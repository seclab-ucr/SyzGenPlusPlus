
import logging
from typing import Callable

from angr import BP_AFTER
from angr.sim_state import SimState
from syzgen.executor import KEY_STATE_ID, PluginMixin, PriorityList

logger = logging.getLogger(__name__)

ForkCallback = Callable[[SimState, int, int], None]


class ForkManagementPlugin(PluginMixin):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init ForkManagementPlugin")
        self._global_id = 0
        self.fork_callbacks = PriorityList[ForkCallback]()

    def reload(self, **kwargs) -> None:
        super().reload(**kwargs)

        self._global_id = 0

    def register_fork_callback(self, func: ForkCallback, priority: int) -> None:
        self.fork_callbacks.insert(priority, func)

    def unregister_fork_callback(self, func: ForkCallback) -> None:
        self.fork_callbacks.remove(func)

    def get_state_id(self, state: SimState) -> int:
        return state.locals[KEY_STATE_ID]

    def _fork_profile_onFork(self, state):
        if state.history.jumpkind == 'Ijk_Boring':
            if state.solver.is_false(state.history.jump_guard):
                return

            if not state.solver.satisfiable(extra_constraints=(state.history.jump_guard, )):
                return

            logger.debug("onFork at %#x with %s", state.addr,
                         state.history.jump_guard.shallow_repr(max_depth=4))
            src_id, dst_id = state.locals[KEY_STATE_ID], self._global_id
            state.locals[KEY_STATE_ID] = dst_id
            self._global_id += 1
            logger.debug("fork from %d to %d at %#x", src_id,
                         dst_id, state.history.jump_source)
            for func in self.fork_callbacks.items():
                func(state, src_id, dst_id)
        else:
            # FIXME: Testing code
            logger.debug("jumpkind %s", state.history.jump_source)
            from IPython import embed
            embed()

    def init(self, state: SimState) -> None:
        state.locals[KEY_STATE_ID] = self._global_id
        self._global_id += 1
        return super().init(state)

    def pre_execute(self, state: SimState) -> None:
        if self.fork_callbacks:
            state.inspect.b('fork', when=BP_AFTER,
                            action=self._fork_profile_onFork)
        return super().pre_execute(state)
