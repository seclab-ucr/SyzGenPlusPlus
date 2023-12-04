
import logging

from angr.sim_state import SimState
from typing import List
from syzgen.analysis.plugins.recovery import ArgAnnotation, BaseAnnotation
from syzgen.executor import KEY_VARIABLES
from syzgen.parser.types import TypeWeight
from syzgen.target import TargetOS

logger = logging.getLogger(__name__)

# https://elixir.bootlin.com/linux/v5.15/source/include/linux/socket.h#L179
class RdmaAddrSizeAnnotation(BaseAnnotation):
    TARGETS = [TargetOS.LINUX, TargetOS.ANDROID]
    ARGS: List[ArgAnnotation] = [(0, True, "sockaddr_storage", 16)]
    FUNCTION = "rdma_addr_size"

    def _extract_type(self, expr, sym, l: int, r: int, state: SimState, name: str, size: int) -> None:
        key = (sym.args[0], l, l-16+1)
        state.locals[KEY_VARIABLES][key] += TypeWeight.KnownType
        return super()._extract_type(expr, sym, l-16, r, state, "sockaddr_storage_internal", size-2)

class RdmaAddrSizeIn6(RdmaAddrSizeAnnotation):
    TARGETS = [TargetOS.LINUX, TargetOS.ANDROID]
    ARGS: List[ArgAnnotation] = [(0, True, "sockaddr_storage", 16)]
    FUNCTION = "rdma_addr_size_in6"
