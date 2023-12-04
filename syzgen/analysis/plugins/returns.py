

import logging
from typing import Callable
from angr import BP_AFTER
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState

from syzgen.executor import PluginMixin, PriorityList

ReturnCallback = Callable[[SimState], None]
logger = logging.getLogger(__name__)


class ReturnManagementPlugin(PluginMixin):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init ReturnManagementPlugin")
        self.return_callbacks = PriorityList[ReturnCallback]()

    def register_return_callback(self, func: ReturnCallback, priority: int) -> None:
        self.return_callbacks.insert(priority, func)

    def unregister_return_callback(self, func: ReturnCallback) -> None:
        self.return_callbacks.remove(func)

    def _return_management(self, state: SimState):
        logger.debug("onReturn %s", state.regs.ip)

        for func in self.return_callbacks.items():
            func(state)

    def pre_execute(self, state: SimState) -> None:
        if self.return_callbacks:
            state.inspect.b("return", when=BP_AFTER,
                            action=self._return_management)
        return super().pre_execute(state)

    def post_execute(self, simgr: SimulationManager) -> None:
        if "deadended" in simgr.stashes and self.is_enabled(ReturnManagementPlugin):
            for state in simgr.deadended:
                # For state that exits completely, it won't trigger the callback on return
                # and thus we have to check them here.
                if state.addr == state.project.simos.return_deadend:
                    self._return_management(state)

        return super().post_execute(simgr)
