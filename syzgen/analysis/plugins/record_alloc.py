
import bisect
import logging
from typing import Dict, List, Optional, Tuple

from angr.sim_state import SimState
from claripy.ast.base import Base
from claripy.ast.bv import Extract
from syzgen.analysis.plugins.constraints import ConstraintReason, add_one_constraint
from syzgen.executor import PluginMixin
from syzgen.models import MAX_MEMORY_SIZE
from syzgen.parser.types import PtrDir

logger = logging.getLogger(__name__)


class RecordInputSymAllocation(PluginMixin):
    """record all allocated symbolic memory for input and it can be used to track
    the boundary of input and output"""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init RecordInputSymAllocation")
        self._alloc_input: List[int] = []
        self._alloc_sym_input: Dict[int, Base] = {}

    def reload(self, **kwargs) -> None:
        super().reload(**kwargs)

        self._alloc_input.clear()
        self._alloc_sym_input.clear()

    def init(self, state: SimState) -> None:
        state.globals["read_boundary"] = {}
        state.globals["write_boundary"] = {}
        return super().init(state)

    def record_sym_alloc(self, state: SimState, addr: int, sym: Base, track_boundary: bool = False, direction=PtrDir.DirIn) -> None:
        """record input related symbolic variables so that later on
        we can retrieve the corresponding symbolic object based on the
        concrete address. For input that is not copied through certain
        function like copy_from_user (eg, macos iokit inputs), you may want
        to mark the boundary conservatively."""
        if addr in self._alloc_sym_input:
            logger.debug(
                "alloc symbolic memory for the same address %#x", addr)
            if id(sym) != id(self._alloc_sym_input[addr]):
                raise RuntimeError()
            return
        logger.debug("record allocation for %#x: %s", addr, sym)
        bisect.insort(self._alloc_input, addr)
        self._alloc_sym_input[addr] = sym

        if track_boundary:
            self.track_boundary(state, sym, 0, direction=direction)

    def realloc_sym(self, state: SimState, index: int, addr: int):
        orig_addr = self._alloc_input[index]
        orig_sym = self._alloc_sym_input[orig_addr]
        # assert orig_sym.length == MAX_MEMORY_SIZE*8
        if addr < orig_addr:
            diff = orig_addr - addr
            sym = state.solver.BVS(
                f'inp_{addr:x}',
                min(MAX_MEMORY_SIZE, orig_sym.length//8+diff)*8,
                key=("inp", addr),
                eternal=True
            )
            state.memory.store(addr, Extract(sym.length-1, sym.length-8*diff, sym), inspect=False)
            add_one_constraint(
                self,
                state,
                Extract(sym.length-diff*8-1, 0, sym) == Extract(orig_sym.length-1, diff*8,  orig_sym),
                ConstraintReason.INPUT,
            )

            # move boundaries
            for boundaries in [state.globals["read_boundary"], state.globals["write_boundary"]]:
                if orig_sym.args[0] in boundaries:
                    boundaries[sym.args[0]] = max(0, boundaries[orig_sym.args[0]] - diff*8)
        else:
            # re-register this
            sym = state.solver.BVS(f'inp_{orig_addr:x}', MAX_MEMORY_SIZE*8)
            state.solver.register_variable(sym, ("inp", orig_addr), eternal=True)
            part = Extract(sym.length-orig_sym.length-1, 0, sym)
            state.memory.store(orig_addr+orig_sym.length//8, part, inspect=False)
            addr = orig_addr

            # move boundaries
            for boundaries in [state.globals["read_boundary"], state.globals["write_boundary"]]:
                if orig_sym.args[0] in boundaries:
                    boundaries[sym.args[0]] = boundaries[orig_sym.args[0]]

        del self._alloc_input[index]
        del self._alloc_sym_input[orig_addr]
        self.record_sym_alloc(state, addr, sym)
        return addr, sym

    def get_alloc_sym(self, state: SimState, addr: int) -> Tuple[int, Optional[Base]]:
        index = bisect.bisect_right(self._alloc_input, addr)
        if index == 0:
            logger.info(
                "alloc_input: %s but got %#x",
                ", ".join(f"{each:#x}" for each in self._alloc_input),
                addr,
            )
            if self._alloc_input:
                # need to adjust the input
                return self.realloc_sym(state, 0, addr)
            else:
                logger.error("invalid address %#x", addr)
            return 0, None

        b = self._alloc_input[index-1]
        sym = self._alloc_sym_input[b]
        if addr > b + sym.length//8:
            logger.info(
                "alloc_input: %s but got %#x",
                ", ".join(f"{each:#x}" for each in self._alloc_input),
                addr,
            )
            if addr - b > MAX_MEMORY_SIZE:
                self.discard_state(state)
                return 0, None
            return self.realloc_sym(state, index-1, addr)
            # logger.error("invalid address %#x", addr)
            # return 0, None
            # raise NotImplementedError()

        if index < len(self._alloc_input):
            if self._alloc_input[index] - addr <= 64:
                logger.warning(
                    "invalid address %#x (%#x)?",
                    addr,
                    self._alloc_input[index],
                )

        return b, sym

    def track_boundary(self, state: SimState, sym: Base, offset: int = 0, direction=PtrDir.DirIn) -> None:
        """See track_input_boundary"""
        logger.debug("track_boundary: %s %d %d", sym, offset, direction)
        if offset == sym.length:
            # zero size
            return

        if direction&PtrDir.DirIn:
            self._track_boundary(state, sym, offset, PtrDir.DirIn)
        if direction&PtrDir.DirOut:
            self._track_boundary(state, sym, offset, PtrDir.DirOut)

    def _track_boundary(self, state: SimState, sym: Base, offset: int, direction: PtrDir) -> None:
        boundaries = (
            state.globals["read_boundary"]
            if direction == PtrDir.DirIn
            else state.globals["write_boundary"]
        )
        name = sym.args[0]
        if name not in boundaries or offset < boundaries[name]:
            boundaries[name] = offset

    def track_input_boundary(self, state: SimState, addr, size, direction=PtrDir.DirIn) -> None:
        """Data transferred from userspace to kernel must go through certain
        functions. We could track the boundaries by checking the size arguments.
        """
        if state.solver.symbolic(addr):
            logger.error("track boundary get symbolic address")
            raise RuntimeError()

        addr = state.solver.eval(addr)
        b, sym = self.get_alloc_sym(state, addr)
        if sym is None:
            return

        if state.solver.symbolic(size):
            size = min(state.solver.max_int(size), sym.length//8)
        else:
            size = state.solver.eval(size)
        offset = max(0, sym.length - (addr - b + size) * 8)

        self.track_boundary(state, sym, offset, direction=direction)


def record_sym_alloc(executor: PluginMixin, state: SimState, addr: int, sym: Base, track_boundary: bool = False):
    """Call RecordInputSymAllocation.record_sym_alloc if available"""
    if isinstance(executor, RecordInputSymAllocation):
        executor.record_sym_alloc(state, addr, sym, track_boundary=track_boundary)
