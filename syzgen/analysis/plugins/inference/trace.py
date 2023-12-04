
from angr.sim_state import SimState
from syzgen.analysis.plugins.call import CallManagementPlugin
from syzgen.executor import PriorityList


class TraceExecutionPlugin(CallManagementPlugin):
    """Given an input, we monitor all function calls to see whether
    some inputs (ie, taint source) are used in certain functions (ie, taint
    sink), which can be later used to discover dependency, particular types, etc.
    """

    def __init__(self, first_call: bool = True, **kwargs) -> None:
        super().__init__(first_call, **kwargs)

        self.register_function_call(self._trace_function_call, PriorityList.LOW_PRIORITY)

    def _trace_function_call(self, state: SimState):
        pass
