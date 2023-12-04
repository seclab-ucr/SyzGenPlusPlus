import logging

from enum import Enum
from typing import Any, Callable
from angr import BP_BEFORE
from angr.sim_state import SimState
from claripy.ast.bool import true as BoolTrue
from claripy.ast.bool import false as BoolFalse

from syzgen.executor import PluginMixin, PriorityList

import syzgen.analysis.plugins as Plugins

logger = logging.getLogger(__name__)
ConstraintCallback = Callable[[SimState, Any, "ConstraintReason"], None]


class ConstraintReason(Enum):
    INPUT = 1
    CONCRETIZATION = 2
    SYMBOLIZATION = 3
    NORMAL = 4


class ConstraintManagementPlugin(PluginMixin):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init ConstraintManagementPlugin")
        self.constraint_callbacks = PriorityList[ConstraintCallback]()

    def register_constraint_callback(self, func: ConstraintCallback, priority: int) -> None:
        self.constraint_callbacks.insert(priority, func)

    def unregister_constraint_callback(self, func: ConstraintCallback) -> None:
        self.constraint_callbacks.remove(func)

    def add_one_constraint(self, state: SimState, constraint, reason=ConstraintReason.NORMAL):
        """Add one constraint to the state.
        Note manually added constraints won't trigger angr's breakpoints,
        and thus we need to invoke the callback directly to avoid lost of
        constraints in relaxation phase.
        """
        if reason not in {
            ConstraintReason.CONCRETIZATION,
            ConstraintReason.SYMBOLIZATION,
        }:
            # no need to trigger the callback
            self._onConstraint(state, [constraint], reason)
        state.solver.add(constraint)

    def _onConstraint(self, state, constraints, reason):
        if constraints[0] is BoolTrue or constraints[0] is BoolFalse:
            return

        logger.debug("onConstraint %s %s", state.regs.ip,
                     constraints[0].shallow_repr(max_depth=4))
        # FIXME: do we need it?
        if state.solver.symbolic(state.regs.ip):
            return
        for func in self.constraint_callbacks.items():
            func(state, constraints, reason)

    def onConstraint(self, state):
        constraints = state.inspect.added_constraints
        self._onConstraint(state, constraints, ConstraintReason.NORMAL)

    def pre_execute(self, state: SimState) -> None:
        if self.constraint_callbacks:
            state.inspect.b('constraints', when=BP_BEFORE,
                            action=self.onConstraint)

        super().pre_execute(state)


def add_one_constraint(executor, state, constraint, reason=ConstraintReason.NORMAL):
    """Allow plugins process this constraint before adding it"""
    if isinstance(executor, ConstraintManagementPlugin):
        executor.add_one_constraint(state, constraint, reason)
    else:
        state.solver.add(constraint)

    if reason == ConstraintReason.INPUT:
        Plugins.recovery.reserve_fields_from_input(executor, state, [constraint])
