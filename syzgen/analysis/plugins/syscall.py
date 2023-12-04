
import logging

from typing import Optional, Set, Tuple, Union
from angr.sim_state import SimState
from claripy.ast.base import Base
from claripy.ast.bv import Reverse, Extract
from syzgen.analysis.plugins.constraints import ConstraintReason, add_one_constraint
from syzgen.analysis.plugins.record_alloc import RecordInputSymAllocation
from syzgen.executor import ExecutionMode
from syzgen.models import MAX_MEMORY_SIZE, brkAlloc
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import ALL_KNOWN_TYPES, ConstType, Context, FlagType, KnownType, PtrDir, PtrType, RangeType, ResourceType, StructType, Type

import syzgen.analysis.plugins as Plugins

logger = logging.getLogger(__name__)


class SyscallPlugin(
    RecordInputSymAllocation,
):
    """Plugin to store the syscall to be analyzed.
    Also use it to concretize input based on the given syscall.
    """

    def __init__(self, syscall: Syscall, **kwargs) -> None:
        self.syscall: Syscall = syscall
        self.input_prefix: Set[str] = syscall.get_input_arg_names() | {"inp"}
        self.input_pointee_prefix: Set[str] = syscall.get_input_pointer_arg_names() | {
            "inp"}
        logger.debug("detect input arguments %s", ", ".join(self.input_prefix))

        super().__init__(**kwargs)

    def reload(self, syscall: Syscall, **kwargs) -> None:
        super().reload(**kwargs)

        self.syscall = syscall

    def pre_execute(self, state: SimState) -> None:
        super().pre_execute(state)

        self.concretize_input(state)

    def gen_constraint_range(self, state: SimState, typ: RangeType, sym: Base, val: Optional[int] = None):
        ret = [typ.min <= sym, typ.max >= sym]
        if typ.stride != 1:
            ret.append((sym % typ.stride) == 0)
        return ret

    def gen_constraint_flag(self, state: SimState, typ: FlagType, sym: Base, val: Optional[int] = None):
        constraints = [sym == v for v in typ.values]
        return [state.solver.Or(*constraints)]

    def gen_constraint_const(self, state: SimState, typ: ConstType, sym: Base, val: Optional[int] = None):
        return [sym == typ.getData()]

    def gen_constraint_struct(self, state: SimState, typ: StructType, sym: Base, val: Optional[int] = None):
        ret = []
        for field in typ.fields:
            # note the endness. This should be only called by alloc_argument and thus
            # the endess is different from those in @concretize_input.
            l, r = (field.offset+field.size)*8-1, field.offset*8
            # l, r = sym.length-1-field.offset*8, sym.length-(field.offset+field.size)*8
            field_sym = Extract(l, r, sym)
            # FIXME: val should be a pointer, but currently we only pass its actual value from alloc_argument.
            # We don't parse pointer actually yet.
            concrete_val = (val >> (field.offset * 8)) & ((1 << (field.size * 8)) - 1) if val is not None else None
            self.on_concretize_input(state, sym, l, r, field)
            gen_constraints = getattr(self, f"gen_constraint_{field.type.lower()}", None)
            if gen_constraints:
                ret.extend(gen_constraints(state, field, field_sym, val=concrete_val))
        return ret

    def gen_constraint_resource(self, state: SimState, typ: ResourceType, sym: Base, val: Optional[int] = None):
        """Note it is only called by alloc_argument or gen_constraint_struct.
        concretize_input would call concretize_source."""
        if self.MODE is ExecutionMode.DYNAMIC:
            # change the data upon new execution
            assert(val is not None)
            logger.debug("resource should be %s %x", sym, val)
            return [sym == val]
        return []

    def assign_symbolic_tag(self, state: SimState, name: str, concrete_addr: int, size: int) -> Base:
        sym = state.solver.BVS(
            name, size*8,
            key=(name, size),
            eternal=True,
        )
        add_one_constraint(
            self, state,
            sym == concrete_addr,
            reason=ConstraintReason.SYMBOLIZATION
        )
        return sym

    def alloc_argument(self, state: SimState, name: str, addr: int = 0, val: Optional[int] = None, track_boundary: bool = False) -> Tuple[int, Union[Base, int]]:
        """Allocate symbolic memory for top-level arguments"""
        for arg in self.syscall.args:
            if name == arg.typename:
                if isinstance(arg, PtrType):
                    # if arg.dir & PtrDir.DirIn == 0:
                    #     raise RuntimeError(
                    #         "no need to symbolize output %s", name)
                    length = arg.ref.size
                    addr = addr or brkAlloc(state, MAX_MEMORY_SIZE + 512) # reserve more space in case we need to re-alloc it.
                    # addr = self.global_alloctor.alloc(length=length)
                    sym = state.solver.BVS(
                        name, length*8, key=(name, addr), eternal=True)
                    self.record_sym_alloc(state, addr, sym, track_boundary=track_boundary, direction=arg.dir)
                    break
                elif isinstance(arg, ConstType):
                    return 0, arg.getData()
                else:
                    # FIXME: what about other types?
                    sym = state.solver.BVS(
                        name, arg.size*8, key=(name, arg.size*8), eternal=True)
                    self.on_concretize_input(state, sym, sym.length-1, 0, arg)
                    gen_constraints = getattr(
                        self, f"gen_constraint_{arg.type.lower()}", None)
                    if gen_constraints:
                        for constraint in gen_constraints(state, arg, sym, val=val):
                            add_one_constraint(
                                self, state, constraint,
                                reason=ConstraintReason.INPUT
                            )
                    return 0, sym
        else:
            length = MAX_MEMORY_SIZE
            addr = addr or brkAlloc(state, length)
            # addr = self.global_alloctor.alloc(length=length)
            sym = state.solver.BVS(
                name, length*8, key=(name, length), eternal=True)

        state.memory.store(addr, sym, inspect=False)
        logger.debug("_alloc_arguments %s: 0x%x", name, addr)
        return addr, sym

    def alloc_input_sym(self, state: SimState, addr: int, size: int) -> Tuple[int, Base]:
        """Allocate symbolic memory for nested pointer"""
        if addr == 0:
            addr = brkAlloc(state, MAX_MEMORY_SIZE + 512) # reserve more space in case we need to re-alloc it.
            # addr = self.global_alloctor.alloc(size)
        sym_cont = state.solver.BVS(
            "inp_%x" % addr, size*8, key=("inp", addr), eternal=True)
        state.memory.store(addr, sym_cont, inspect=False)
        logger.debug("alloc_input_sym: 0x%x", addr)
        return addr, sym_cont

    def on_concretize_input(self, state: SimState, sym: Base, l: int, r: int, typ: Type):
        """examine input and associated symbolic memory/type"""
        pass

    def concretize_resource(self, state: SimState, addr: int, sym: Base, typ: ResourceType) -> None:
        if self.MODE is ExecutionMode.DYNAMIC:
            # if we have a concrete context, we should use the original
            # value directly.
            concrete = state.memory.load(
                addr+typ.offset, typ.size, inspect=False)
            add_one_constraint(
                self, state,
                sym == concrete,
                reason=ConstraintReason.INPUT
            )
            logger.debug(
                "read resource %d from memory for %s", concrete, sym)

    def concretize_known_type(self, state: SimState, addr: int, symbol: Base, sym: Base, typ: KnownType) -> None:
        if self.MODE is ExecutionMode.DYNAMIC:
            concrete = state.memory.load(
                addr+typ.offset, typ.size, inspect=False)
            add_one_constraint(
                self, state,
                sym == concrete,
                reason=ConstraintReason.INPUT
            )
            logger.debug("read %s from memory for %s", typ.name, sym)
        else:
            t = self.get_target().target.name.lower()
            if t not in ALL_KNOWN_TYPES:
                return
            for struct in ALL_KNOWN_TYPES[t][typ.name]:
                for field in struct.fields:
                    offset = typ.offset + field.offset
                    l, r = symbol.length-1-offset*8, symbol.length-(offset+field.size)*8
                    sym = Extract(l, r, symbol)
                    if field.type in {"range", "flag", "const"}:
                        self.concretize_primitives(state, sym, field)
                # FIXME: nested types? multiple structs
                break

    def concretize_primitives(self, state: SimState, sym: Base, typ: Type) -> None:
        logger.debug("concretize %s with %s", sym, typ.type)
        gen_constraints = getattr(self, f"gen_constraint_{typ.type.lower()}")
        for constraint in gen_constraints(state, typ, Reverse(sym)):
            add_one_constraint(
                self, state,
                constraint,
                reason=ConstraintReason.INPUT
            )

    def concretize_input(self, state: SimState) -> None:
        """Concretize inputs based on its type.
        Call this after top-level argument initialization.
        ctx.ret should store all symbolic memory for inputs as follows:
        ctx.ret: Dict[Tuple[str, str], Dict]
        e.g., ("inputStruct", "[4]"): {"addr": 0xDEADBEEF, "symbol": sym_mem}
        """

        context = Context()
        context.ret = {}
        for addr, sym in self._alloc_sym_input.items():
            for i, arg in enumerate(self.syscall.args):
                name = sym.args[0].split("_")[0]
                if name == arg.typename:
                    context.ret[(arg.typename, str([i]))] = {
                        "addr": addr, "symbol": sym}

        def concretize(ctx: Context, typ: Type):
            if ctx.dir & PtrDir.DirIn == 0:
                return

            # FIXME: add weight for known types
            if typ.type in ("struct", "buffer", ):
                return

            # concretize following types
            if typ.type in ("ptr", "resource", "const", "range", "flag", "known"):
                path = list(ctx.path)
                data = None
                while len(path) > 0:
                    path = path[:-1]
                    key = (ctx.arg, str(path))
                    if key in ctx.ret:
                        data = ctx.ret[key]
                        break
                if data is None:
                    return

                # concretize pointer, constant, and dependence
                logger.debug("%s", data)
                logger.debug("concretize %s: %d %d",
                             typ.type, typ.offset, typ.size)
                symbol = data["symbol"]
                l, r = symbol.length-1-typ.offset*8, symbol.length-(typ.offset+typ.size)*8
                sym = Extract(l, r, symbol)
                self.on_concretize_input(state, symbol, l, r, typ)

                if isinstance(typ, ResourceType):
                    self.concretize_resource(state, data["addr"], sym, typ)
                elif isinstance(typ, KnownType):
                    self.concretize_known_type(state, data["addr"], symbol, sym, typ)
                elif isinstance(typ, PtrType):
                    ptr = state.memory.load(
                        data["addr"]+typ.offset, typ.size, inspect=False)
                    if state.solver.unique(ptr):
                        p = state.solver.eval(ptr)
                        if p == 0:
                            raise RuntimeError("NULL pointer?")
                        _, sym_cont = self.alloc_input_sym(
                            state, p, typ.ref.size)
                    else:
                        p, sym_cont = self.alloc_input_sym(
                            state, 0, typ.ref.size)

                    # note little endianness
                    add_one_constraint(
                        self, state,
                        Reverse(sym) == p,
                        reason=ConstraintReason.INPUT
                    )
                    self.record_sym_alloc(state, p, sym_cont, track_boundary=True, direction=typ.dir)
                    ctx.ret[(ctx.arg, str(ctx.path))] = {
                        "addr": p, "symbol": sym_cont}

                    # To be able to track back from the pointer to the
                    # user input, we need to record the access path.
                    Plugins.dependency.record_access_path(self, state, p, sym)
                else:
                    self.concretize_primitives(state, sym, typ)
            else:
                raise RuntimeError("unsupported type %s", typ.type)

        self.syscall.visit(context, concretize)
