
import logging
from angr.sim_state import SimState
from syzgen.analysis.plugins.constraints import ConstraintReason, add_one_constraint
from syzgen.executor import PluginMixin, PriorityList
from syzgen.models import GlobalAllocator, isGlobalObject, isAllocObject

logger = logging.getLogger(__name__)


class PointerConcretizationPlugin(PluginMixin):
    """Concretize symbolic pointers (which may have arbitrary values).
    Symbolic pointer may come from symbolized user input or global variables.
    (@SymbolizationPlugin may symbolize some global memory).
    Make them concrete to allow further progress."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init PointerConcretizationPlugin")
        # Set new allocator
        self.global_alloctor = GlobalAllocator()

        self.register_memory_read(
            self.concretize_pointer_on_read, PriorityList.FIRST_PRIORITY)
        self.register_memory_write(
            self.concretize_pointer_on_write, PriorityList.FIRST_PRIORITY)

    def reload(self, **kwargs) -> None:
        super().reload(**kwargs)

        self.global_alloctor = GlobalAllocator()

    def _concretize_unallocated_pointer(self, state: SimState, addr) -> None:
        # concretize the memory address if necessary
        if state.solver.symbolic(addr):
            try:
                concrete_addr = state.solver.eval(addr)
            except ValueError:
                # Angr bug?
                state.solver.reload_solver()
                concrete_addr = state.solver.eval(addr)

            if not state.solver.unique(addr):
                if not isGlobalObject(concrete_addr):
                    if state.solver.solution(addr, self.global_alloctor.base):
                        # Looks like it can be an arbitrary value. That said, we
                        # still prefer a valid pointer instead of the one we assign.
                        for candidate in state.solver.eval_upto(addr, 4):
                            if self.is_valid_pointer(candidate, state=state):
                                concrete_addr = candidate
                                break
                        else:
                            concrete_addr = self.global_alloctor.alloc()
                        logger.debug("concretize %s to %#x",
                                     addr.shallow_repr(max_depth=4),
                                     concrete_addr
                                    )
                        add_one_constraint(
                            self, state,
                            addr == concrete_addr,
                            reason=ConstraintReason.CONCRETIZATION
                        )

            if (
                not isAllocObject(concrete_addr) and
                not self.is_valid_pointer(concrete_addr, state) and
                not self.is_stack_pointer(state, concrete_addr)
            ):
                logger.debug("detect invalid pointer %#x", concrete_addr)
                self.terminate_state(state)
        else:
            concrete_addr = state.solver.eval(addr)

        if state.project and state.project.concrete_target:
            # It might directly read memory from backers which are unintialized data
            pageno, _ = state.memory._divide_addr(concrete_addr)
            if pageno not in state.memory._pages:
                start_addr = pageno * state.memory.page_size
                mem = state.project.concrete_target.read_memory(start_addr, state.memory.page_size)
                bvv = state.solver.BVV(mem)
                state.memory.store(start_addr, bvv, inspect=False)

    def concretize_pointer_on_read(self, state: SimState, addr, size):
        self._concretize_unallocated_pointer(state, addr)

    def concretize_pointer_on_write(self, state: SimState, addr, expr, size):
        self._concretize_unallocated_pointer(state, addr)
