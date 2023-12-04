
from collections import defaultdict
import logging
from typing import Callable, Dict, List, Optional, Set
from angr import BP_AFTER
from angr.sim_state import SimState
from syzgen.executor import PluginMixin, PriorityList
from syzgen.utils import OrderedKeyDict

CallCallback = Callable[[SimState], None]
logger = logging.getLogger(__name__)


class CallManagementPlugin(PluginMixin):
    def __init__(self, first_call: bool = True, **kwargs) -> None:
        """When we set up a call state with an entry function, it does not trigger
        the callback as there is no call instruction involved. We, however, may want
        to record this event (as indicated by the @param `first_call`."""
        super().__init__(**kwargs)

        logger.debug("init CallManagementPlugin")
        self._first_call = first_call
        self.call_callbacks = PriorityList[CallCallback]()

        # record call targets
        self.call_targets: Dict[int, Set[int]] = defaultdict(set)
        self._all_functions = OrderedKeyDict()

    def register_function_call(self, func: CallCallback, priority: int) -> None:
        self.call_callbacks.insert(priority, func)

    def unregister_function_call(self, func: CallCallback) -> None:
        self.call_callbacks.remove(func)

    def get_func_addr(self, addr: int) -> Optional[int]:
        return self._all_functions.floor(addr)

    def _call_management(self, state: SimState, first_call: bool = False):
        # TODO: it typically means it jumps to a symbolic address due to unresolved
        # function pointer. Maybe we can return a symbolic value to make it proceed.
        if state.solver.symbolic(state.regs.ip):
            if not state.solver.unique(state.regs.ip):
                return

        if state.addr == 0:
            self.discard_state(state)
            return

        self._all_functions.add(state.addr, None)

        if not first_call:
            logger.debug("call %#x from %#x", state.addr, state.callstack.call_site_addr)
            self.call_targets[state.callstack.call_site_addr].add(state.addr)

        for func in self.call_callbacks.items():
            func(state)

    def pre_execute(self, state: SimState) -> None:
        if self.call_callbacks:
            state.inspect.b("call", when=BP_AFTER,
                            action=self._call_management)
        super().pre_execute(state)

        if self._first_call:
            self._call_management(state, first_call=True)
