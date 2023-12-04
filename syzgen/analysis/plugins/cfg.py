
import logging
from typing import Optional
import typing
from angr.analyses.cfg.indirect_jump_resolvers.resolver import IndirectJumpResolver
from angr.knowledge_plugins.functions.function import Function
from angr.sim_state import SimState
from syzgen.analysis.plugins.call import CallManagementPlugin
from syzgen.executor import PluginMixin, PriorityList
from syzgen.parser.models import TargetAddress

logger = logging.getLogger(__name__)


class DummyIndirectJumpResolver(IndirectJumpResolver):
    """Provide dummy jump target when default resolver fails to address it, which
    ensure our transition graph contains edge for indirect jumps.
    We assume all indirect calls would return."""

    def __init__(self, project, timeless=False, base_state=None):
        super().__init__(project, timeless, base_state)

        self.unresolved_target = project.loader.extern_object.make_extern(
            "dummy_target")
        # project.hook(self.unresolved_target.rebased_addr, angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())

    def filter(self, cfg, addr, func_addr, block, jumpkind):
        # print(cfg, addr, func_addr, block, jumpkind)
        return jumpkind == "Ijk_Call"

    def resolve(self, cfg, addr, func_addr, block, jumpkind):
        return True, [self.unresolved_target.rebased_addr]


class CFGRecoveryPlugin(CallManagementPlugin):
    """On-demand cfg recovery upon function call"""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.register_plugin_needs_dependents(CFGRecoveryPlugin)

        logger.debug("init CFGRecoveryPlugin")
        self._functions_cfg = {}
        self._register_callback_for_cfg()

    def _register_callback_for_cfg(self) -> None:
        # CFG recovery is the foundation for some other plugins, make sure we call it early.
        if not self.has_dependent(CFGRecoveryPlugin):
            return

        self.register_function_call(
            self._recovery_on_function_call, PriorityList.HIGH_PRIORITY)

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if (
            not self.is_enabled(CFGRecoveryPlugin) or
            not self.has_dependent(CFGRecoveryPlugin)
        ):
            self.unregister_function_call(self._recovery_on_function_call)

    def enable_plugin(self, clazz: typing.Type["PluginMixin"]) -> None:
        super().enable_plugin(clazz)

        if (
            self.is_enabled(CFGRecoveryPlugin) and
            self.has_dependent(CFGRecoveryPlugin)
        ):
            self._register_callback_for_cfg()

    def get_func_by_addr(self, addr: int) -> Optional[Function]:
        if addr not in self._functions_cfg:
            return None
        return self._functions_cfg[addr]

    def functions(self):
        return self._functions_cfg.items()

    def _get_cfg(self, proj, off: int):
        cfg = proj.analyses.CFGEmulated(
            context_sensitivity_level=0,
            starts=(off,),
            call_depth=0,
            normalize=True,
            no_construct=True,
        )
        cfg.indirect_jump_resolvers.append(DummyIndirectJumpResolver(proj))
        cfg._initialize_cfg()
        cfg._analyze()
        return cfg

    def _recover_cfg(self, addr: TargetAddress, check: bool = False):
        if addr in self._functions_cfg:
            return
        proj = self.get_default_project()
        if proj.is_hooked(addr):
            return

        _, off, proj = self.load_project_by_addr(addr)
        if proj:
            if check:
                sym = proj.loader.find_symbol(off, fuzzy=True)
                if sym is None or sym.relative_addr != off:
                    return

            cfg = self._get_cfg(proj, off)
            func = cfg.functions.get_by_addr(off)
            self._functions_cfg[addr] = func
            # for addr, func in cfg.functions._function_map.items():
            #     self._functions_cfg[self.getTargetAddr(addr, module)] = func

    def _recovery_on_function_call(self, state: SimState):
        """Called whenever we have a function call"""
        self._recover_cfg(state.addr)
