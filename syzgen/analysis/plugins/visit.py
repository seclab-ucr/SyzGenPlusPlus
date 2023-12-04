
from collections import deque
import logging

from typing import Set, Tuple
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from syzgen.analysis.plugins.call import CallManagementPlugin
from syzgen.analysis.plugins.cfg import CFGRecoveryPlugin
from syzgen.config import Options
from syzgen.executor import PluginMixin, PriorityList
from syzgen.parser.models import TargetAddress

logger = logging.getLogger(__name__)
options = Options()


class VisitedFunctionsPlugin(CallManagementPlugin):

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        self.show_function = options.print_function
        self.visited_functions: Set[int] = set()
        if self.show_function:
            logger.debug("init VisitedFunctionsPlugin")
            self.register_function_call(
                self.visit_function_logger, PriorityList.LOW_PRIORITY)

    def reload(self, **kwargs) -> None:
        super().reload(**kwargs)

        self.visited_functions.clear()

    def visit_function_logger(self, state):
        """log all visited functions for debug purpose"""
        self.visited_functions.add(state.addr)

    def post_execute(self, simgr: SimulationManager) -> None:
        if self.show_function:
            logger.info("called following functions:")
            for addr in self.visited_functions:
                if addr in self.hooks:
                    continue
                logger.info("%#x: %s", addr, self.get_debug_info(addr))

        return super().post_execute(simgr)


class VisitedBlocksPlugin(PluginMixin):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        self.visited_blocks: Set[int] = set()
        logger.debug("init VisitedBlocksPlugin")

    def reload(self, **kwargs) -> None:
        self.visited_blocks.clear()
        return super().reload(**kwargs)

    def on_execute(self, simgr: SimulationManager) -> None:
        for state in simgr.active:
            self.visited_blocks.add(state.addr)
        return super().on_execute(simgr)

    def post_execute(self, simgr: SimulationManager) -> None:
        if options.cover:
            with open("cover.csv", "w") as fp:
                for addr in self.visited_blocks:
                    fp.write(f"{addr:#x}\n")

        return super().post_execute(simgr)


class InterfaceBlocksPlugin(
    VisitedBlocksPlugin,
    CFGRecoveryPlugin,
):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        # All potential blocks belonging to one particular interface
        self._interface_blocks: Set[int] = set()
        logger.debug("init InterfaceBlocksPlugin")

    def _traverse_cfg(self, func_addr: TargetAddress, cur_addr: TargetAddress, cache: Set[Tuple[int, int]], depth: int = 5):
        def get_node(nodes, addr):
            for node in nodes:
                if node.addr == addr:
                    return node
            return None

        if depth == 0:
            return
        if (func_addr, cur_addr) in cache:
            return
        cache.add((func_addr, cur_addr))
        logger.debug("checking %x - %x", func_addr, cur_addr)

        func = self.get_func_by_addr(func_addr)
        if func is None or func.addr == 0:
            return

        module, base_addr = self.getBaseAddr(cur_addr)
        if not base_addr:
            return

        graph = func.transition_graph
        start_node = get_node(graph.nodes, base_addr)
        if start_node is None:
            return
        queue = deque()
        queue.append(start_node)
        visited = set()

        while queue:
            node = queue.popleft()
            if node is None:
                continue
            if node.addr in visited:
                continue
            visited.add(node.addr)
            self._interface_blocks.add(self.getTargetAddr(node.addr, module))

            succs = list(graph.successors(node))
            if (len(succs)) == 0:
                # it could be a jump target which does not have any successors in this func
                self._recover_cfg(node.addr, check=True)
                self._traverse_cfg(node.addr, node.addr, cache, depth-1)

            for succ in succs:
                if succ is None:
                    continue
                if isinstance(succ, BlockNode):
                    queue.append(succ)
                elif isinstance(succ, Function): # Function Call
                    # check the validity of the func
                    if succ.name == "dummy_target":
                        continue
                    self._recover_cfg(succ.addr)
                    self._traverse_cfg(succ.addr, succ.addr, cache, depth-1)

    def _unwind_backtrace(self, state: SimState, cache: Set[Tuple[int, int]]):
        cur_addr = state.addr
        for _, f in enumerate(state.callstack):
            func_addr = f.func_addr
            logger.debug("unwind func %#x from %#x", func_addr, cur_addr)
            self._traverse_cfg(func_addr, cur_addr, cache)

            cur_addr = f.call_site_addr

    def post_execute(self, simgr: SimulationManager) -> None:
        if self.is_enabled(InterfaceBlocksPlugin):
            self._interface_blocks.clear()
            self._interface_blocks |= self.visited_blocks

            cache = set()
            for state in simgr.active:
                # collect all addresses that are reachable from this state
                self._unwind_backtrace(state, cache)

        return super().post_execute(simgr)
