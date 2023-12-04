
import angr
import logging
from angr.sim_state import SimState

from syzgen.executor import PluginMixin, PriorityList
from syzgen.models import isAllocObject

logger = logging.getLogger(__name__)


class StaticSymbolizationPlugin(PluginMixin):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init StaticSymbolizationPlugin")
        # FIXME: do we need these?
        # self.register_memory_read(self._static_symbolize_memory, PriorityList.HIGH_PRIORITY)
        # self.register_memory_write(self._static_record_memory, PriorityList.LOW_PRIORITY)

    def is_concrete_section(self, addr: int) -> bool:
        if isAllocObject(addr):
            return False

        sec = self.find_section_by_addr(addr)
        if sec and sec.name in {".data", ".rodata"}:
            return True
        return False

    def pre_execute(self, state: SimState) -> None:
        state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        # state.locals['mem'] = {}
        return super().pre_execute(state)

    def _static_symbolize_memory(self, state: SimState, addr, size):
        if self.is_stack_pointer(state, addr):
            return

        concrete_addr = state.solver.min(addr)
        if isAllocObject(concrete_addr):
            return

        cont = state.memory.load(addr, size, inspect=False)
        if not state.solver.symbolic(cont):
            # make extra symbolization
            if concrete_addr in state.locals['mem']:
                logger.debug("write before read it!")
                from IPython import embed
                embed()

    def _static_record_memory(self, state: SimState, addr, expr, size):
        concrete_addr = state.solver.min(addr)
        for i in range(expr.length//8):
            state.locals['mem'][concrete_addr+i] = True
