
import logging
import typing
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from claripy.ast.base import Base
from typing import Callable, Dict, List, Optional, Set, Tuple
from syzgen.analysis.access_path import AccessNode, access_tree_write2
from syzgen.analysis.plugins.constraints import ConstraintManagementPlugin, ConstraintReason
from syzgen.analysis.plugins.syscall import SyscallPlugin
from syzgen.config import Options
from syzgen.executor import KEY_TRACE, PluginMixin, PriorityList
from syzgen.models import FindObjectException, HeapAllocator, isAllocObject, isHeapObject
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import PtrType
from syzgen.utils import extractVariables

import syzgen.analysis.plugins as Plugins

logger = logging.getLogger(__name__)
options = Options()


class RecordAccessPathPlugin(
    ConstraintManagementPlugin,
    SyscallPlugin,
):
    """Record access path for every memory read and write, as well as constraints."""

    def __init__(
        self,
        constraint_filter: Optional[Callable[[int], bool]] = None,
        **kwargs
    ) -> None:
        super().__init__(**kwargs)
        self.constraint_filter = constraint_filter

        logger.debug("init RecordAccessPathPlugin")
        self._read_expr_cache = set()
        self._write_expr_cache = set()
        self._write_objects: Dict[int, Tuple[int, Base]] = {}

        self.write_access_paths: Set[AccessNode] = set()
        self.read_access_paths: Dict[AccessNode, Tuple[List[int], int]] = {}

        self._register_callback_dependency()

    def _register_callback_dependency(self) -> None:
        if not options.infer_dependence:
            return

        self.register_memory_read(
            self.infer_dependence_read, PriorityList.LOW_PRIORITY)
        self.register_memory_write(
            self.infer_dependence_write, PriorityList.LOW_PRIORITY)
        self.register_constraint_callback(
            self.infer_dependence_constraint, PriorityList.LOW_PRIORITY)

    def reload(self, **kwargs) -> None:
        super().reload(**kwargs)

        self.write_access_paths.clear()
        self.read_access_paths.clear()
        self._write_objects.clear()

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if not self.is_enabled(RecordAccessPathPlugin):
            self.unregister_memory_read(self.infer_dependence_read)
            self.unregister_memory_write(self.infer_dependence_write)
            self.unregister_constraint_callback(
                self.infer_dependence_constraint)

    def enable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().enable_plugin(clazz)

        if self.is_enabled(RecordAccessPathPlugin):
            self._register_callback_dependency()

    def _is_seen(self, expr, is_read: bool):
        # FIXME: what key we should use?
        k = expr.shallow_repr()
        cache = self._read_expr_cache if is_read else self._write_expr_cache
        if k not in cache:
            cache.add(k)
            return False
        return True

    def get_pointer_source(self, state, addr):
        """Retrieve its source pointer.
        Addr might be calculated from another pointer.
        addr = *source + off"""
        for leaf in addr.leaf_asts():
            if leaf.op == "BVS":
                names = leaf.args[0].split('_')
                if names[0] in {"tmp", "mem"}:
                    # FIXME: check it is a pointer?
                    return int(names[1], 16)
        return None

    def record_access_path(self, state: SimState, p: int, addr: Base) -> None:
        logger.debug("trace: %#x, %s", p, addr)
        state.locals[KEY_TRACE][p] = (None, addr)

    def infer_dependence_read(self, state, addr, size):
        concrete_addr = state.solver.min(addr)
        if state.solver.symbolic(addr):
            # var = self.get_pointer_source(state, addr)  # get_tmp_var(addr)
            # state.locals[KEY_TRACE][concrete_addr] = (var, addr)
            # logger.debug("trace: %#x", concrete_addr)
            self.record_access_path(state, concrete_addr, addr)
        else:
            _, rel = self.getBaseAddr(concrete_addr)
            if rel and concrete_addr not in state.locals[KEY_TRACE]:
                state.locals[KEY_TRACE][concrete_addr] = (
                    rel, state.solver.BVV(rel, 64))
                logger.debug("trace: %#x %#x", concrete_addr, rel)

        if state.solver.eval(size) == 8:
            # We may read a pointer. Since we need to match it to a write pattern later,
            # which is guaranteed to have a pointer, we don't need to ensure it is a pointer
            # at this point. That said, enforce some minimum check could reduce the overhead.
            if self._is_seen(addr, True):
                return
            variables = extractVariables(addr, includes=self.input_prefix)
            if len(variables) == 1:  # Only involves one user input
                # deps = state.globals.get("deps", dict())
                # r = access_tree(addr, deps, state.globals["trace"], state.globals["trace_cache"])
                r = access_tree_write2(
                    self,
                    state, addr,
                    state.locals[KEY_TRACE],
                    self.input_prefix,
                    self._write_objects,
                    cache=state.locals["trace_cache"],
                )
                if r and r.qualify():
                    logger.debug("access tree read: %s", r)
                    logger.debug("%s", variables[0])
                    self.read_access_paths[r] = (
                        # state.globals["read_path"][r] = (
                        get_access_path(self.syscall, state, variables[0]),
                        variables[0].length//8
                    )
                    # reserve this variable as a whole
                    Plugins.recovery.reserve_field_from_input(self, state, variables[0])
                    if options.hook_point == "access":
                        from IPython import embed
                        embed()

    def infer_dependence_write(self, state, addr, expr: Base, size: Optional[Base]):
        if (
            not state.solver.symbolic(expr) and
            expr.length == 64
        ):
            cont = state.solver.eval(expr)
            if isHeapObject(cont):    # HEAP OBJECT
                if state.solver.symbolic(addr):
                    if self._is_seen(addr, False):
                        return
                else:
                    concrete_addr = state.solver.eval(addr)
                    if self.is_stack_pointer(state, concrete_addr):
                        return
                    if (
                        not self.is_valid_pointer(concrete_addr, state)
                        and not isAllocObject(concrete_addr)
                    ):
                        return

                if cont not in self._write_objects:
                    try:
                        allocator: HeapAllocator = options.heap_allocator
                        base_addr, _ = allocator.get_object(cont)
                        self._write_objects[base_addr] = (cont, addr)
                    except FindObjectException:
                        return

                r = access_tree_write2(
                    self,
                    state, addr,
                    state.locals[KEY_TRACE],
                    self.input_prefix,
                    self._write_objects,
                    cache=state.locals["trace_cache"],
                )
                if r and r.qualify():
                    logger.debug("access tree write: %s", r)
                    self.write_access_paths.add(r)
                    if options.hook_point == "access":
                        from IPython import embed
                        embed()

    def infer_dependence_constraint(self, state, constraints, reason):
        if reason != ConstraintReason.NORMAL:
            return

        # Note: for block followed by switch jump, the address can be symbolic and thus cannot be accessed
        # by state.addr.
        addr = state.solver.eval(state.regs.ip)
        if self.constraint_filter and self.constraint_filter(addr):
            return
        constraint = constraints[0]
        if constraint.op == '__eq__' or constraint.op == '__ne__':
            if constraint.args[1].op == 'BVV' or constraint.args[0].op == 'BVV':
                return
            left = extractVariables(
                constraint.args[0], includes=self.input_prefix)
            right = extractVariables(
                constraint.args[1], includes=self.input_prefix)
            if len(left) == 0 and len(right) == 1:  # Only involves one user input
                expr, sym_inp = constraint.args[0], right[0]
            elif len(right) == 0 and len(left) == 1:
                expr, sym_inp = constraint.args[1], left[0]
            else:
                return
            if self._is_seen(expr, True):
                return

            r = access_tree_write2(
                self,
                state, expr,
                state.locals[KEY_TRACE],
                self.input_prefix,
                self._write_objects,
                cache=state.locals["trace_cache"],
            )
            if r and r.qualify():
                logger.debug("access path: %s", r)
                logger.debug("%s", sym_inp)
                self.read_access_paths[r] = (
                    # state.globals["read_path"][r] = (
                    get_access_path(self.syscall, state, sym_inp),
                    sym_inp.length//8
                )
                if options.hook_point == "access":
                    from IPython import embed
                    embed()

    def init(self, state: SimState) -> None:
        if self.is_enabled(RecordAccessPathPlugin):
            options.record_access_path = True

        state.locals[KEY_TRACE] = dict()
        state.locals["trace_cache"] = dict()
        return super().init(state)

    def post_execute(self, simgr: SimulationManager) -> None:
        options.record_access_path = False

        if self.is_enabled(RecordAccessPathPlugin):
            logger.debug("All write access path: %d",
                         len(self.write_access_paths))
            for each in self.write_access_paths:
                logger.debug("%s", each)
            logger.debug("All read access path: %d",
                         len(self.read_access_paths))
            for p, (path, size) in self.read_access_paths.items():
                logger.debug("%s: %s %d", p, path, size)

        return super().post_execute(simgr)


def get_access_path(syscall: Syscall, state: SimState, expr):
    """get the offsets to access the field"""
    if expr.op == "BVS":
        names = expr.args[0].split("_")
        if names[0] == 'inp':
            addr = int(names[1], 16)
            _, e = state.locals[KEY_TRACE][addr]
            return get_access_path(syscall, state, e) + [0]

        # all inputs are pointers, add one more 0 to indicate dereference.
        if names[0] not in syscall.arg_names:
            from IPython import embed
            embed()
        idx = syscall.arg_names.index(names[0])
        arg = syscall.args[idx]
        if isinstance(arg, PtrType):
            return [idx, 0]
        return [idx]
    if expr.op == "Extract":
        ret = get_access_path(syscall, state, expr.args[2])
        if ret[-1] == 0 and len(ret) >= 2:
            # it is a pointer
            # FIXME: endness
            offset = expr.args[2].length - expr.args[0] - 1
        else:
            offset = expr.args[1]
        return ret + [offset//8]
    if expr.op == "Reverse":
        return get_access_path(syscall, state, expr.args[0])
    if expr.op == "Concat":
        new_args = list(reversed(expr.args))
        new_expr = expr.make_like(expr.op, new_args, simplify=True)
        if new_expr.op != "Concat":
            return get_access_path(syscall, state, new_expr)

        # compact ptr: <BV64 0x0 .. arg_84548_64[31:0]>
        if len(expr.args) == 2 and expr.args[0].op == "BVV":
            return get_access_path(syscall, state, expr.args[1])

    logger.error("get_access_path: %s", expr)
    from IPython import embed
    embed()
    raise NotImplementedError(f"access_path {expr}")


def record_access_path(executor, state: SimState, p: int, addr: Base):
    if isinstance(executor, RecordAccessPathPlugin):
        executor.record_access_path(state, p, addr)
