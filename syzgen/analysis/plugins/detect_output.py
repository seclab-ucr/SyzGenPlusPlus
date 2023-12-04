
from collections import deque
import logging
from typing import List, Set

from angr.block import Block
from angr.knowledge_plugins.functions.function import Function
import pyvex
from syzgen.analysis.plugins.cfg import CFGRecoveryPlugin
from syzgen.analysis.plugins.visit import InterfaceBlocksPlugin, VisitedBlocksPlugin
from syzgen.parser.models import Address, BaseAddress, TargetAddress

logger = logging.getLogger(__name__)

OUTPUT_FUNCTIONS = {
    "linux": [
        "__put_user_1",
        "__put_user_2",
        "__put_user_4",
        "__put_user_8",
        "_copy_to_user",
    ],
}

FD_FUNCTIONS = {
    "linux": [
        "get_unused_fd_flags",
    ]
}

class OutputDetectorPlugin(
    InterfaceBlocksPlugin,
):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init OutputDetectorPlugin")

    def get_output_funcs(self) -> List[str]:
        return OUTPUT_FUNCTIONS.get(self.get_target().get_os(), [])

    def get_fd_funcs(self) -> List[str]:
        return FD_FUNCTIONS.get(self.get_target().get_os(), [])

    def _contain_func_call(self, module: str, block: Block, targets: Set[TargetAddress]) -> bool:
        if block.vex.jumpkind == "Ijk_Call" and isinstance(block.vex.next, pyvex.expr.Const):
            addr = block.vex.next.con.value
            if self.getTargetAddr(addr, module) in targets:
                return True
        return False

    def contain_func_call(self, module: str, func: Function, targets: Set[TargetAddress]) -> bool:
        return any(
            self._contain_func_call(module, block, targets)
            for block in func.blocks
            if self.getTargetAddr(block.addr, module) in self._interface_blocks
        )

    def detect(self, output_funcs: Set[TargetAddress], excludes: List[Address] = []) -> TargetAddress:
        """Detect whether we have output functions that we failed to cover
        Return the function that contains any of our targets"""
        for addr in output_funcs:
            if addr in self.visited_blocks:
                return addr

        for addr, func in self.functions():
            m, _ = self.getBaseAddr(addr)
            if not m:
                logger.debug("checking invalid function %#x", addr)
                # raise RuntimeError("unknown module")
                continue

            if self.contain_func_call(m, func, output_funcs):
            #     continue
            # logger.debug("func %s contain a target function", repr(func))
            # if self.may_visit_func(addr, func, output_funcs, excludes):
                logger.debug("find a path to a target function")
                return addr
        return 0
