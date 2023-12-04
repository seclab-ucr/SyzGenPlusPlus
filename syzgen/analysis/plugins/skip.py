
import logging
from typing import Optional
import typing

from angr import SimProcedure
from angr.calling_conventions import DefaultCC
from angr.sim_state import SimState
from angr.sim_type import SimTypePointer, SimTypeFunction, SimTypeBottom
from syzgen.analysis.plugins.call import CallManagementPlugin
from syzgen.analysis.plugins.signature import FunctionSignaturePlugin
from syzgen.analysis.plugins.syscall import SyscallPlugin
from syzgen.executor import PluginMixin, PriorityList
from syzgen.models import ReturnUnconstrained, isAllocObject
from syzgen.utils import contain_inputs

logger = logging.getLogger(__name__)


class ReturnDirectly(SimProcedure):
    def run(self):
        return

class SkipFunctionPlugin(
    CallManagementPlugin,
    FunctionSignaturePlugin,
    SyscallPlugin,
):
    """Detect functions that does not process output, ie, they do not have an
    output pointer as their parameters"""
    def __init__(self, skip_all_functions=False, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init SkipFunctionPlugin")
        self._skip_all_functions = skip_all_functions
        self._function_skip = set()
        arch = self.get_default_project().arch
        self._cc = DefaultCC[arch.name](arch)

        proj = self.get_default_project()
        self._return_unconstrained_addr = proj.loader.extern_object.make_extern("return_unconstrained")
        self._return_addr = proj.loader.extern_object.make_extern("return_directly")
        proj.hook(self._return_unconstrained_addr.rebased_addr, ReturnUnconstrained())
        proj.hook(self._return_addr.rebased_addr, ReturnDirectly())

        self.register_function_call(self._check_function_to_skip, PriorityList.LOW_PRIORITY)

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if not self.is_enabled(SkipFunctionPlugin):
            self.unregister_function_call(self._check_function_to_skip)

    def enable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().enable_plugin(clazz)

        if self.is_enabled(SkipFunctionPlugin):
            self.register_function_call(self._check_function_to_skip, PriorityList.LOW_PRIORITY)

    def _skip_this_function(self, state: SimState, prototype: Optional[SimTypeFunction]=None) -> None:
        logger.debug("skip function at %#x", state.addr)
        if prototype is None:
            prototype = self.get_prototype_by_addr(state.addr)

        if (
            prototype is None or
            not isinstance(prototype.returnty, SimTypeBottom)
        ):
            state.regs.ip = self._return_unconstrained_addr.rebased_addr
        else:
            state.regs.ip = self._return_addr.rebased_addr

    def _check_function_to_skip(self, state: SimState) -> None:
        if state.project.is_hooked(state.addr):
            return
        if self._skip_all_functions or state.addr in self._function_skip:
            self._skip_this_function(state)

        protocol = self.get_prototype_by_addr(state.addr)
        if protocol is None:
            return

        # if protocol._arch is None:
        #     protocol = protocol.with_arch(self._cc.arch)

        for reg, arg in zip(self._cc.ARG_REGS, protocol.args):
            val = state.registers.load(reg, inspect=False)
            concrete_val = state.solver.eval(val)
            if (
                isinstance(arg, SimTypePointer) or
                isAllocObject(concrete_val) # unsigned long arg for ioctl
            ):
                if state.solver.symbolic(val):
                    if contain_inputs(val, inputs=self.input_pointee_prefix):
                        break
                first_byte = state.memory.load(state.solver.eval(val), size=1, inspect=False)
                if state.solver.symbolic(first_byte):
                    if contain_inputs(first_byte, inputs=self.input_pointee_prefix):
                        break
        else:
            self._function_skip.add(state.addr)
            self._skip_this_function(state, protocol)

        # from IPython import embed; embed()
