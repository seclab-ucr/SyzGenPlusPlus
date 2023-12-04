
import logging
from collections import defaultdict
import typing

from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from syzgen.analysis.plugins.fork_manager import ForkManagementPlugin
from syzgen.config import Options
from syzgen.executor import PluginMixin, PriorityList

logger = logging.getLogger(__name__)
options = Options()


class ForkProfilePlugin(ForkManagementPlugin):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.enable_fork_profile: bool = options.fork_profile
        self.fork_addrs = defaultdict(int)
        if self.enable_fork_profile:
            logger.debug("init ForkProfilePlugin")
            self.register_fork_callback(
                self._on_fork_profile, PriorityList.LOW_PRIORITY)

    def reload(self, **kwargs) -> None:
        self.fork_addrs.clear()
        return super().reload(**kwargs)

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if not self.is_enabled(ForkProfilePlugin):
            self.unregister_fork_callback(self._on_fork_profile)

    def _on_fork_profile(self, state: SimState, src: int, dst: int) -> None:
        source = state.history.jump_source
        self.fork_addrs[source] += 1

    def post_execute(self, simgr: SimulationManager) -> None:
        if self.enable_fork_profile and self.is_enabled(ForkProfilePlugin):
            logger.info("forked at the following addresses")
            for each in sorted(self.fork_addrs.keys(), key=lambda x: self.fork_addrs[x], reverse=True):
                logger.info(
                    "%d %#x: %s", self.fork_addrs[each], each, self.get_debug_info(each))
        return super().post_execute(simgr)
