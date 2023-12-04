import logging

from angr.sim_manager import SimulationManager
from syzgen.executor import PluginMixin

logger = logging.getLogger(__name__)

class PathLimiterPlugin(PluginMixin):
    def __init__(self, path_limit: int = 512, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init PathLimiterPlugin")
        self._path_limit = path_limit

    def on_execute(self, simgr: SimulationManager) -> None:
        if len(simgr.active) > self._path_limit:
            logger.debug("too many states (%d), yield every other one", len(simgr.active))
            for i in range(0, len(simgr.active), 2):
                self.yield_state(simgr.active[i])
        return super().on_execute(simgr)
