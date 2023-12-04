
import logging
from typing import Optional, Set
import typing

from angr import BP_AFTER
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from syzgen.analysis.plugins.constraints import ConstraintManagementPlugin, ConstraintReason
from syzgen.analysis.plugins.loop import LoopRecoveryPlugin

from syzgen.executor import KEY_REDUCED_CONSTRAINTS, PluginMixin, PriorityList

logger = logging.getLogger(__name__)


class ConstraintRelaxationPlugin(
    ConstraintManagementPlugin,
    LoopRecoveryPlugin,
):
    """Eliminate undesired constraints introduced by memory concretization and loops.
    Make sure it is put after @InputRecoveryPlugin"""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._all_concretization_addrs: Set[int] = set()
        self._collect_constraint_filter = None

        logger.debug("init ConstraintRelaxationPlugin")
        self.register_constraint_callback(
            self._collect_constraints, PriorityList.LOW_PRIORITY)

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if not self.is_enabled(ConstraintRelaxationPlugin):
            self.unregister_constraint_callback(self._collect_constraints)

    def init(self, state: SimState) -> None:
        state.locals[KEY_REDUCED_CONSTRAINTS] = []
        return super().init(state)

    def pre_execute(self, state: SimState) -> None:
        if self.is_enabled(ConstraintRelaxationPlugin):
            state.inspect.b("address_concretization", when=BP_AFTER,
                            action=self._on_address_concretization)
        return super().pre_execute(state)

    def _on_address_concretization(self, state: SimState):
        logger.debug("concretize address at %#x", state.addr)
        self._all_concretization_addrs.add(state.addr)

    def reload_solver(self, src: SimState, dst: SimState) -> None:
        dst.solver.reload_solver(
            constraints=src.locals[KEY_REDUCED_CONSTRAINTS])

    def post_execute(self, simgr: SimulationManager) -> None:
        if self.is_enabled(ConstraintRelaxationPlugin):
            for state in simgr.stashes["deadended"] + simgr.stashes["active"]:
                self.reload_solver(state, state)
        return super().post_execute(simgr)

    def set_collect_constraint_filter(self, func) -> None:
        self._collect_constraint_filter = func

    def _collect_constraints(self, state, constraints, reason):
        # In SimConcretizationStrategyMinWrite, we record all address where we concretize symbolic addrs.
        if state.addr in self._all_concretization_addrs:
            return
        if state.addr in self._all_break_edges:
            return

        if (
            self._collect_constraint_filter and
            self._collect_constraint_filter(constraints, reason)
        ):
            return

        state.locals[KEY_REDUCED_CONSTRAINTS].extend(
            const for const in constraints if not const.is_true())
