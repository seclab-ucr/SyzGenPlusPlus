
import logging

from angr.concretization_strategies import SimConcretizationStrategy


logger = logging.getLogger(__name__)


class SimConcretizationStrategyMin(SimConcretizationStrategy):
    """
    Concretization strategy that returns the minimum address.
    """

    def _concretize(self, memory, addr,  **kwargs):
        return [self._min(memory, addr,  **kwargs)]
