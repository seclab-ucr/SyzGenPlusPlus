
import logging

from collections import defaultdict
from typing import Dict
import typing
from angr.sim_state import SimState
from angr.sim_state_options import SimStateOptions
from angr.sim_manager import SimulationManager
from syzgen.analysis.plugins.call import CallManagementPlugin
from syzgen.analysis.plugins.fork_manager import ForkManagementPlugin
from syzgen.analysis.plugins.returns import ReturnManagementPlugin
from syzgen.analysis.plugins.symbolization import SymbolizationPlugin
from syzgen.executor import KEY_EXECUTE_LIMITS, KEY_FORK_LIMITS, PluginMixin, PriorityList

logger = logging.getLogger(__name__)


class LoopLimiterPlugin(
    CallManagementPlugin,
    ReturnManagementPlugin,
    ForkManagementPlugin,
):
    """Record the number of iterations for each loop.
    Note this plugin does not detect loops. Instead, it track the number
    of forks at the same address with the same calling context."""

    ALLOW_FORK = "SYZGEN_ALLOW_FORK"

    def __init__(self, loop_limit: int = 8, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init LoopLimiterPlugin")
        self._loop_limit = loop_limit
        self._forked_states: Dict[int, int] = {}

        self._register_callback_for_looplimiter()

    def _register_callback_for_looplimiter(self):
        self.register_fork_callback(
            self._loop_limit_fork, PriorityList.LOW_PRIORITY)
        self.register_function_call(
            self._loop_limit_push, PriorityList.LOW_PRIORITY)
        self.register_return_callback(
            self._loop_limit_pop, PriorityList.LOW_PRIORITY)

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if not self.is_enabled(LoopLimiterPlugin):
            self.unregister_fork_callback(self._loop_limit_fork)
            self.unregister_function_call(self._loop_limit_push)
            self.unregister_return_callback(self._loop_limit_pop)

    def enable_plugin(self, clazz: typing.Type["PluginMixin"]) -> None:
        super().enable_plugin(clazz)

        if self.is_enabled(LoopLimiterPlugin):
            self._register_callback_for_looplimiter()

    def _loop_limit_push(self, state):
        # logger.debug("state %d call %#x", state.locals.get("id", -1), state.addr)
        state.locals[KEY_FORK_LIMITS].append(defaultdict(int))
        state.locals[KEY_EXECUTE_LIMITS].append(defaultdict(int))

    def _loop_limit_pop(self, state):
        # logger.debug("state %d return", state.locals.get("id", -1))
        if len(state.locals[KEY_FORK_LIMITS]) > 1:
            state.locals[KEY_FORK_LIMITS].pop()
            state.locals[KEY_EXECUTE_LIMITS].pop()
        else:
            logger.error("no callstack left for state %d!", state.locals.get("id", -1))

    def _loop_limit_fork(self, state: SimState, src: int, dst: int) -> None:
        source = state.history.jump_source
        self._forked_states[src] = source
        state.locals[KEY_FORK_LIMITS][-1][source] += 1
        if state.locals[KEY_FORK_LIMITS][-1][source] >= self._loop_limit:
            logger.debug("fork too many times at %#x, halt!", source)
            # discard newly-created paths
            self.discard_state(state)

    def on_execute(self, simgr: SimulationManager) -> None:
        if self._forked_states:
            for state in simgr.active:
                _id = self.get_state_id(state)
                if _id in self._forked_states:
                    source = self._forked_states[_id]
                    state.locals[KEY_FORK_LIMITS][-1][source] += 1
                    if state.locals[KEY_FORK_LIMITS][-1][source] >= self._loop_limit:
                        # TODO: re-enable it later?
                        logger.debug(
                            "disable forking for state at %#x", source)
                        state.options.discard(
                            SymbolizationPlugin.SYMBOLIZE_CONTENT)
                        state.options.discard(LoopLimiterPlugin.ALLOW_FORK)

            self._forked_states.clear()

        if self.is_enabled(LoopLimiterPlugin):
            num = len(simgr.active) + len(simgr.stashes["deferred"])
            for state in simgr.active:
                state.locals[KEY_EXECUTE_LIMITS][-1][state.addr] += 1
                if num > 1 and state.locals[KEY_EXECUTE_LIMITS][-1][state.addr] >= self._loop_limit:
                    logger.debug("yield state at %#x", state.addr)
                    self.yield_state(state)

        return super().on_execute(simgr)

    def init(self, state: SimState) -> None:
        # a dummy dict that should never be useds
        state.locals[KEY_FORK_LIMITS] = [defaultdict(int), defaultdict(int)]
        state.locals[KEY_EXECUTE_LIMITS] = [defaultdict(int), defaultdict(int)]
        return super().init(state)

SimStateOptions.register_bool_option(
    LoopLimiterPlugin.ALLOW_FORK, description="allow it to fork")
