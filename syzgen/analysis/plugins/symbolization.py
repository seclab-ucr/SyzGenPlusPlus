import logging
import typing

from angr.sim_state import SimState
from angr.sim_state_options import SimStateOptions
from cle.backends.elf.regions import ELFSection
from syzgen.analysis.plugins.constraints import ConstraintReason, add_one_constraint
from syzgen.config import Options

from syzgen.executor import PluginMixin, PriorityList
from syzgen.models import isAllocObject, isHeapObject

logger = logging.getLogger(__name__)
options = Options()

class SymbolizationPlugin(PluginMixin):
    """Assign a symbolic tag to each pointer derived from global variables which lays
    the foundation for generating access path. We also symbolize some content to overcome
    the under-constraint challenge caused by in-vivo symbolic execution."""

    CONCRETE_SECTIONS = {
        # macOS
        "__text", "__const", "__common", "__os_log", "__cstring", "__got",
        # Linux
        ".text", ".rodata", ".init.text", ".comment",
    }
    SYMBOLIZE_CONTENT = "SYZGEN_SYMBOLIZE_CONTENT"

    def __init__(self, check_kernel: bool, **kwargs) -> None:
        super().__init__(**kwargs)
        self._check_kernel = check_kernel

        if not options.no_symbolization:
            logger.debug("init SymbolizationPlugin")
            self.register_memory_read(
                self.symbolize_memory, PriorityList.HIGH_PRIORITY)
            self.register_memory_write(
                self.record_write_on_symbolic_memory, PriorityList.LOW_PRIORITY)

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if not self.is_enabled(SymbolizationPlugin):
            self.unregister_memory_read(self.symbolize_memory)
            self.unregister_memory_write(self.record_write_on_symbolic_memory)

    def init(self, state: SimState) -> None:
        state.locals['mem'] = {}
        state.options.add(SymbolizationPlugin.SYMBOLIZE_CONTENT)
        return super().init(state)

    def update_memory(self, state, addr, size=1):
        # FIXME: use interval to optimize the space
        for i in range(size):
            state.locals['mem'][addr+i] = True

    def has_memory(self, state, addr, size=1) -> bool:
        try:
            # for i in range(size):
            #     _ = state.locals['mem'][addr+i]
            # FIXME: how to handle partially symbolic content
            _ = state.locals['mem'][addr]
            return True
        except KeyError:
            return False

    def is_concrete_section(self, addr: int) -> bool:
        if isAllocObject(addr):
            return False
        sec = self.find_section_by_addr(addr)
        # FIXME: __common contains external unintialized global variables
        # e.g., __ZN8OSObject10gMetaClassE
        if sec:
            name = sec.name if isinstance(sec, ELFSection) else sec.sectname
            if name in SymbolizationPlugin.CONCRETE_SECTIONS:
                return True
        return False

    def record_write_on_symbolic_memory(self, state: SimState, addr, expr, size):
        concrete_addr = state.solver.eval(addr)
        if isAllocObject(concrete_addr):
            return
        if self.is_stack_pointer(state, concrete_addr):
            return
        self.update_memory(state, concrete_addr, len(expr)//8)

    def symbolize_memory(self, state: SimState, addr, size):
        concrete_addr = state.solver.min(addr)
        if isHeapObject(concrete_addr):
            return
        if self.is_stack_pointer(state, concrete_addr):
            return
        if SymbolizationPlugin.SYMBOLIZE_CONTENT not in state.options:
            # symbolize it?
            self.update_memory(state, concrete_addr)
            return
        # if not state.solver.unique(addr):
        #     return

        if self.is_concrete_section(concrete_addr):
            logger.debug("do not symbolize %#x", concrete_addr)
            return

        cont = state.memory.load(
            concrete_addr, size,
            endness=state.arch.memory_endness,
            disable_actions=True,
            inspect=False,
        )

        # If it is symbolic, we must have wriiten data at the address.
        # Only symbolize it at our first sight
        if state.solver.symbolic(cont):
            return
        concrete_cont = state.solver.eval(cont)

        sym_cont = state.solver.BVS(
            'tmp_%x' % concrete_addr,
            size * 8,
            key=('tmp', concrete_addr),
        )

        if (
            (size == 8 and self.is_valid_pointer(concrete_cont, state)) or
            self.has_memory(state, concrete_addr, size)
        ):
            # it is a pointer or we have updated it
            add_one_constraint(
                self, state,
                sym_cont == concrete_cont,
                reason=ConstraintReason.SYMBOLIZATION
            )
        else:
            if not state.solver.symbolic(addr):
                # global address?
                m, rel = self.getBaseAddr(concrete_addr)
                if m == "kernel" and not self._check_kernel:
                    return
                if not rel:
                    return

            # For directly accessed global variables, we only symbolize certain
            # variables, including NULL pointer and bool value.
            if concrete_cont >= 2:
                return

            logger.debug("symbolize content %s %s", cont, concrete_cont)

        state.memory.store(concrete_addr, sym_cont,
                           endness=state.arch.memory_endness, inspect=False)


SimStateOptions.register_bool_option(
    SymbolizationPlugin.SYMBOLIZE_CONTENT, description="symbolize some global memory")
