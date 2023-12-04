
import logging
from typing import Dict, List, Set
import typing
from angr.sim_state import SimState
from angr.analyses.loopfinder import Loop

from syzgen.analysis.plugins.cfg import CFGRecoveryPlugin
from syzgen.executor import PluginMixin, PriorityList
from syzgen.parser.models import TargetAddress

logger = logging.getLogger(__name__)


class LoopRecoveryPlugin(CFGRecoveryPlugin):
    """On-demand loop recovery upon function call"""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.register_plugin_needs_dependents(LoopRecoveryPlugin)

        logger.debug("init LoopRecoveryPlugin")
        self._all_loops: Dict[TargetAddress, List[Loop]] = {}
        self._all_break_edges: Set[TargetAddress] = set()
        self._register_callback_for_loop()

    def _register_callback_for_loop(self) -> None:
        if not self.has_dependent(LoopRecoveryPlugin):
            return

        self.register_function_call(
            self._recover_loop_on_call, PriorityList.LOW_PRIORITY)

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if (
            not self.is_enabled(LoopRecoveryPlugin) or
            not self.has_dependent(LoopRecoveryPlugin)
        ):
            self.unregister_function_call(self._recover_loop_on_call)

    def enable_plugin(self, clazz: typing.Type["PluginMixin"]) -> None:
        super().enable_plugin(clazz)

        if self.is_enabled(LoopRecoveryPlugin):
            self._register_callback_for_loop()

    def get_loop_by_addr(self, addr: int) -> List[Loop]:
        return self._all_loops[addr]

    def _recover_loop_on_call(self, state: SimState):
        if state.addr not in self._all_loops:
            func = self.get_func_by_addr(state.addr)
            if func is None:
                return
            module, _, proj = self.load_project_by_addr(state.addr)
            res = proj.analyses.LoopFinder(functions=(func, ))
            self._all_loops[state.addr] = res.loops

            for loop in res.loops:
                for src, _ in loop.break_edges:
                    block = proj.factory.block(src.addr)
                    addr = self.getTargetAddr(block.instruction_addrs[-1], module)
                    self._all_break_edges.add(addr)
