
import logging

from angr.sim_state import SimState
from syzgen.analysis.plugins.call import CallManagementPlugin
from syzgen.executor import PriorityList

logger = logging.getLogger(__name__)


class DependencyGeneralizationPlugin(CallManagementPlugin):
    """ Dependency inference by looking at functions' arguments
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init DependencyGeneralizationPlugin")
        self.register_function_call(
            self._check_dependency_onCall, PriorityList.LOW_PRIORITY)

    def _check_dependency_onCall(self, state: SimState):
        pass
