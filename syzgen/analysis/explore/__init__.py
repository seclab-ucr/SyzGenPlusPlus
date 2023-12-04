
import logging
import random
import time
import traceback
from typing import Callable, List, Optional, Set
import angr

from angr.sim_manager import SimulationManager
from z3.z3types import Z3Exception
from syzgen.executor import BaseExecutor, ExitCode

logger = logging.getLogger(__name__)


class TargetException(Exception):
    pass


class ExplorePluginBP(angr.BP):
    """Same as BP but it allows us to distinguish it from other BPs"""

    def __init__(self, bp_name, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.bp_name = bp_name


class ExplorePlugin:
    def __init__(self) -> None:
        self.event_types: Set[str] = set()

    def add_breakpoint(self, state: angr.SimState, event_type, *args, **kwargs):
        """equivalent to state.inspect.b(...)"""
        self.event_types.add(event_type)
        bp = ExplorePluginBP(type(self).__name__, *args, **kwargs)
        state.inspect.add_breakpoint(event_type, bp)

    def execute(self, simgr: SimulationManager):
        raise NotImplementedError()

    def post_execute(self, simgr: SimulationManager) -> None:
        pass

    def remove_breakpoints(self, simgr: SimulationManager) -> None:
        bp_name = type(self).__name__
        for _, states in simgr.stashes.items():
            for state in states:
                for event_type in self.event_types:
                    state.inspect.remove_breakpoint(
                        event_type,
                        filter_func=lambda bp: getattr(
                            bp, "bp_name", "") == bp_name,
                    )


class BaseExplore:
    """Base abstract class for exploration strategy"""

    def __init__(self, executor: BaseExecutor, verbose=False) -> None:
        self.executor: BaseExecutor = executor
        self.verbose: bool = verbose

        self.plugins: List[ExplorePlugin] = []

    def add_plugin(self, plugin: ExplorePlugin) -> None:
        self.plugins.append(plugin)

    def remove_plugin(self, plugin: ExplorePlugin, simgr: SimulationManager) -> None:
        plugin.remove_breakpoints(simgr)
        self.plugins.remove(plugin)

    def remove_plugins(self, simgr: SimulationManager) -> None:
        for plugin in self.plugins:
            plugin.remove_breakpoints(simgr)
        self.plugins.clear()

    def step(self, simgr: SimulationManager) -> SimulationManager:
        """Make one step forward"""
        return simgr.step()

    def stop(self, simgr: SimulationManager) -> bool:
        return self.executor.should_abort

    def explore(
        self,
        simgr: SimulationManager,
        timeout: int = 0,
        callback: Optional[Callable[[SimulationManager], bool]] = None
    ):
        # TODO: use timeout signal to avoid calling time.time in every step.
        start_time = time.time()
        self.executor.exit_code = ExitCode.UNKNOWN
        while not self.stop(simgr):
            if self.verbose:
                for idx, each in enumerate(simgr.active):
                    logger.debug("state %d at %#x (%d)", idx,
                                 each.addr, each.locals.get("id", 0))
                logger.debug("-----------------------------------")

            for plugin in self.plugins:
                plugin.execute(simgr)

            if callback:
                if callback(simgr):
                    self.executor.exit_code = ExitCode.USER_FORCE
                    break

            if timeout and time.time() - start_time > timeout:
                self.executor.exit_code = ExitCode.TIMEOUT
                break

            try:
                simgr = self.step(simgr)
            except Z3Exception:
                logger.error("z3 error probably due to running out of memory")
                logger.error("see https://github.com/Z3Prover/z3/issues/1251 for more details")
                self.executor.exit_code = ExitCode.Z3_ERROR
                break
            except Exception as e:
                retry = False
                if simgr.errored:
                    for i in reversed(range(len(simgr.errored))):
                        if isinstance(simgr.errored[i].error, angr.errors.SimUnsatError):
                            logger.error("Got an Unsat state, remove it from the stash")
                            del simgr.errored[i]
                            retry = True

                if not retry:
                    traceback.print_exc()
                    from IPython import embed; embed()
                    raise e
            # Note it must be called first before we invoke all plugins
            # as some plugins relies on the executor.
            self.executor.on_execute(simgr)

        # Set exit code
        if self.executor.exit_code == ExitCode.UNKNOWN:
            if self.executor.should_abort:
                self.executor.exit_code = ExitCode.USER_FORCE
            elif not simgr.active:
                self.executor.exit_code = ExitCode.NO_STATE

        logger.debug("time elapsed: %ds", time.time() - start_time)
        simgr.move(from_stash="deferred", to_stash="active")
        for plugin in self.plugins:
            plugin.post_execute(simgr)
        return simgr


class DFSExplore(BaseExplore):
    """Depth-First exploration
    See @angr.exploration_techniques.dfs.DFS
    """

    def __init__(self, executor: BaseExecutor, verbose=False) -> None:
        super().__init__(executor, verbose)

        self._random = random.Random()
        self._random.seed(10)

    def step(self, simgr: SimulationManager) -> SimulationManager:
        # manipulate the stashes before actual execution so that
        # other plugins can see the new states.
        if len(simgr.active) > 1:
            self._random.shuffle(simgr.active)
            simgr.split(from_stash="active", to_stash="deferred", limit=1)

        if len(simgr.active) == 0:
            if len(simgr.deferred) == 0:
                return simgr
            simgr.active.append(simgr.deferred.pop())
        return simgr.step()

    def stop(self, simgr: SimulationManager) -> bool:
        res = (
            len(simgr.stashes["active"]) == 0 and
            len(simgr.stashes["deferred"]) == 0
        )
        return res or super().stop(simgr)


class BFSExplore(BaseExplore):
    """Breath-First exploration strategy"""

    def step(self, simgr: SimulationManager) -> SimulationManager:
        if len(simgr.active) == 0:
            if len(simgr.deferred) == 0:
                return simgr
            simgr.move(from_stash="deferred", to_stash="active")

        return simgr.step()

    def stop(self, simgr: SimulationManager) -> bool:
        res = (
            len(simgr.stashes["active"]) == 0 and
            len(simgr.stashes["deferred"]) == 0
        )
        return res or super().stop(simgr)


class CoverageExplore(DFSExplore):
    """Strive for coverage, ie, pick unseen block.
    1. Pick next state to explore by walking the tree of already explored
    states from the root and randomly take branches until a leaf
    2. Pick next state that covers unseen instructions.
    """

    def __init__(self, executor: BaseExecutor, verbose=False) -> None:
        super().__init__(executor, verbose)

        self._visited_blocks = set()

    def step(self, simgr: SimulationManager) -> SimulationManager:
        if len(simgr.active) > 1:
            self._random.shuffle(simgr.active)
            simgr.split(from_stash="active", to_stash="deferred", limit=1)

        if len(simgr.active) == 0:
            if len(simgr.deferred) == 0:
                return simgr
            for i in range(len(simgr.deferred)-1, -1, -1):
                state = simgr.deferred[i]
                if state.addr not in self._visited_blocks:
                    simgr.deferred.pop(i)
                    simgr.active.append(state)
                    break
            else:
                self._random.shuffle(simgr.deferred)
                simgr.active.append(simgr.deferred.pop())

        # about to execute it
        self._visited_blocks.add(simgr.active[0].addr)
        return simgr.step()


class CombinedExplore(CoverageExplore):
    def __init__(self, executor: BaseExecutor, verbose=False) -> None:
        super().__init__(executor, verbose)

        self._steps = 100

    def step(self, simgr: SimulationManager) -> SimulationManager:
        if self._steps > 0:
            self._steps -= 1
            if len(simgr.active) > 64:
                self._steps = 0
            return simgr.step()
        return super().step(simgr)
