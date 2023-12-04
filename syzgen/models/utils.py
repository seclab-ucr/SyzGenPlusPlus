
import logging

from typing import Callable, Optional, Tuple

from angr.sim_state import SimState
from claripy.ast.bv import Extract, Reverse
from claripy.ast.base import Base
from angr.errors import SimUnsatError
from syzgen.analysis.plugins.constraints import ConstraintReason, add_one_constraint
from syzgen.analysis.plugins.dependency import RecordAccessPathPlugin
from syzgen.analysis.plugins.record_alloc import RecordInputSymAllocation, record_sym_alloc
from syzgen.analysis.plugins.recovery import InputRecoveryPlugin

from syzgen.config import Options
from syzgen.executor import BaseExecutor
from syzgen.models import MAX_MEMORY_SIZE, HeapAllocator, brkAlloc, is_stack_pointer, isAllocObject
from syzgen.parser.types import PtrDir, TypeWeight
from syzgen.utils import extractSymbol

logger = logging.getLogger(__name__)
options = Options()

PointerInitializer = Callable[[SimState, int, int], Base]


def track_length(state, addr: Base, length: Base):
    """If length is symbolic, we need to record the relationship."""
    # from IPython import embed; embed()

    if length.op == "__add__":
        # not supported yet
        logger.info("do not support length with addition")
        return

    # Mapping from len to ptr
    len_sym, len_l, len_r = extractSymbol(length, merge=True)
    if len_sym is None:
        return

    if addr.op in {"__add__"} or not state.solver.symbolic(addr):
        # <BV64 0x8 + arg_1_64> or 0xd001008
        ptr = state.solver.eval(addr)
        allocator: HeapAllocator = options.heap_allocator
        p, _ = allocator.get_closest_object(ptr)
        if ptr - p >= MAX_MEMORY_SIZE or p > ptr:
            return
        addr_sym = None
        for (k, sym) in state.solver.get_variables():
            if len(k) > 1 and k[1] == p:
                addr_sym = sym
                break
        if addr_sym is None:
            return
        off = ptr - p
        addr_l, addr_r = addr_sym.length - off*8 - 1, 0
    else:
        addr_sym, addr_l, addr_r = extractSymbol(addr)
    if addr_sym is None:
        return
    if len_sym.args[0] == addr_sym.args[0] and len_l == addr_l:
        return

    # byte aligned
    len_r = (len_r//8) * 8
    len_l = (len_l//8) * 8 + 7
    # FIXME
    var = Reverse(Extract(len_l, len_r, len_sym))
    try:
        concrete_vars = state.solver.eval_upto(
            var, 1,
            extra_constraints=[var != 0]
        )
    except (AttributeError, SimUnsatError) as e:
        return

    if concrete_vars:
        concrete_var = concrete_vars[0]
        concrete_lens = state.solver.eval_upto(
            length, 1,
            extra_constraints=[var == concrete_var]
        )
        if concrete_lens:
            concrete_len = concrete_lens[0]

        if concrete_len % concrete_var != 0:
            logger.warning("length is not a muliplier of the input: %d %d",
                            concrete_len, concrete_var)

        logger.debug("trackLength %s %s", concrete_var, concrete_len)
        lens = state.locals.get("lens", {})
        lens[(len_sym.args[0], len_l, len_r)] = (
            addr_sym.args[0],
            addr_l, addr_r,
            max(concrete_len//concrete_var, 1),
        )
        state.locals["lens"] = lens

        executor = state.globals.get("executor", None)
        if isinstance(executor, InputRecoveryPlugin):
            # len should be a separate field
            executor.extract_variable(state, len_sym, len_l, len_r, weight=TypeWeight.Input)


def concretize_pointer(state: SimState, addr, length, initialize: Optional[PointerInitializer] = None) -> Tuple[int, int, Optional[Base]]:
    """The addr must be a symbolic expression"""
    size = state.solver.max_int(length)
    # FIXME: 1024??
    # Add a hard constraint here.
    if size > MAX_MEMORY_SIZE:
        size = MAX_MEMORY_SIZE
        # state.solver.add(length <= MAX_MEMORY_SIZE)

    solutions = state.solver.eval_upto(addr, 2)
    sym = None
    if len(solutions) > 1:
        if isinstance(addr, Base):
            rep = addr.__repr__(inner=True)
        else:  # SimActionObject
            rep = addr.ast.__repr__(inner=True)
        ptr = None

        # Find out if we have assigned a pointer before
        for k, v in state.solver.get_variables('ptr', rep):
            p = state.solver.eval(v)
            if k[1] == rep:
                ptr = p
                break
        else:
            # If we didn't concretize this to a concrete pointer, assign one here.
            if not state.solver.solution(addr, options.heap_allocator.base):
                # Don't add infeasible constraint
                return state.solver.eval(addr), size, None
            ptr = brkAlloc(state, size)
        if state.locals.get("trace", None):
            state.locals["trace"][ptr] = (-1, addr)

        # make sure the pointer has a concrete solution
        ptr_bv = state.solver.BVV(ptr, 64)
        logger.debug("%s == %#x", addr.shallow_repr(max_depth=4), ptr)
        # register this pointer to make sure the assignment is consistent across all states
        state.solver.register_variable(ptr_bv, ('ptr', rep), eternal=True)

        executor = state.globals.get("executor", None)
        add_one_constraint(
            executor, state,
            addr == ptr_bv,
            reason=ConstraintReason.INPUT,
        )

        if initialize:
            logger.debug(
                "create a new symbolic memory for ptr %#x with size %d", ptr, size)
            # alloc larger memory in case we didn't get a smaller size
            sym = initialize(state, ptr, MAX_MEMORY_SIZE)
            state.memory.store(ptr, sym, inspect=False)
    else:
        ptr = solutions[0]
        # We have concretized this pointer before, thus the corresponding memory region is already
        # created. Fix the size to stick to previous value.
        # FIXME: have separate memory?
        for prefix in ["inp", "tmp"]:
            for _, sym in state.solver.get_variables(prefix, ptr):
                size = min(size, sym.length//8)
                return ptr, size, None

    return ptr, size, sym


def track_boundary(state: SimState, addr: int, size: int, direction=PtrDir.DirIn):
    """Data transferred from userspace to kernel must go through certain
    functions. We could track the boundaries by checking the size arguments.
    """
    if not options.struct_recovery:
        return
    if size == 0:
        return

    executor = state.globals.get("executor", None)
    if isinstance(executor, RecordInputSymAllocation):
        executor.track_input_boundary(state, addr, size, direction=direction)


def concretize_user_pointer(state: SimState, addr: Base, size: int, direction=PtrDir.DirIn) -> Tuple[int, int]:
    """Read/Write data from/to user-provided pointer. Thus, we need to make sure we concretize
    this probably arbitrary pointer if necessary. We also track the boundary of user input.
    """
    logger.debug("concretize_user_pointer with size: %d", size)
    if state.solver.symbolic(addr):
        executor = state.globals.get("executor", None)
        if isinstance(executor, InputRecoveryPlugin):
            # a pointer must be a separate field
            executor._extract_variables(state, addr, weight=TypeWeight.Input)

        p, size, sym = concretize_pointer(
            state,
            addr,
            size,
            # we may allocate larger memory than required as different paths
            # may ask for different sizes. Hence, we always choose the max size.
            initialize=lambda s, p, l: s.solver.BVS(
                f'inp_{p:x}', l*8, key=("inp", p), eternal=True),
        )
        if sym is not None:
            # To be able to track the input boundary, we need to
            # record every symbolic memory for input.
            record_sym_alloc(executor, state, p, sym)
            if isinstance(executor, RecordAccessPathPlugin):
                # To be able to track back from the pointer to the
                # user input, we need to record the access path.
                executor.record_access_path(state, p, addr)
    else:
        p = state.solver.eval(addr)

    track_boundary(state, p, size, direction=direction)
    return p, size


def check_pointer(state: SimState, addr) -> bool:
    """Check whether addr is a valid pointer"""
    if not state.solver.unique(addr):
        return True

    addr = state.solver.eval(addr)
    executor: BaseExecutor = state.globals["executor"]
    if (
        not executor.is_valid_pointer(addr, state) and
        not isAllocObject(addr) and
        not is_stack_pointer(state, addr)
    ):
        executor = state.globals["executor"]
        executor.terminate_state(state)
        return False

    return True


def memcpy(state, dst, src, src_len):
    if not state.solver.symbolic(dst):
        c_dst = state.solver.eval(dst)
        if not check_pointer(state, c_dst):
            logger.error("invalid dst %#x pointer for memcpy", c_dst)
            return dst
    if not state.solver.symbolic(src):
        c_src = state.solver.eval(src)
        if not check_pointer(state, c_src):
            logger.error("invalid src %#x pointer for memcpy", c_src)
            return dst

    if not state.solver.symbolic(src_len):
        conditional_size = state.solver.eval(src_len)
        conditional_size = min(MAX_MEMORY_SIZE, conditional_size)
    else:
        max_limit = state.solver.max_int(src_len)
        min_limit = state.solver.min_int(src_len)
        conditional_size = min(MAX_MEMORY_SIZE, max(min_limit, max_limit))
    if conditional_size > 0:
        logger.debug("memcpy with size %d", conditional_size)
        src_mem = state.memory.load(src, conditional_size)
        state.memory.store(dst, src_mem, size=conditional_size)

    return dst
