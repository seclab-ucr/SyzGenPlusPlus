
import unittest

from syzgen.analysis.access_path import AccessNode
from syzgen.utils import get_blank_state


class TestAccessPath(unittest.TestCase):
    Tests = [
        "<__add__ <read <__add__ <read <__add__ <read <__add__ <read <__add__ <read <__add__ <read <BVV 18446744071641728584>>, <BVV 64>>>, <BVV 400>>>, <BVV 2904>>>, <BVV 0>>>, <BVV 8>>>, <__lshift__ <__add__ <ZeroExt <BVV 32>, <__and__ <Extract <BVV 31>, <BVV 0>, <LShR <Concat <BVV 0, 16>, <__invert__ <__or__ <__invert__ <Extract <BVV 1807>, <BVV 1800>, <BVS data, 2240>>>, <__invert__ <Extract <BVV 1743>, <BVV 1736>, <BVS data, 2240>>>>>, <__invert__ <__or__ <__invert__ <Extract <BVV 1799>, <BVV 1792>, <BVS data, 2240>>>, <__invert__ <Extract <BVV 1735>, <BVV 1728>, <BVS data, 2240>>>>>>, <BVV 1>>>, <BVV 63>>>, <BVV 4>>, <BVV 3>>, <BVV 6>>",
        "<__add__ <read <__add__ <read <__add__ <read <__add__ <read <__add__ <read <__add__ <read <__add__ <read <BVV 18446744071641728584, 64>>, <BVV 64, 0>>>, <BVV 400, 0>>>, <BVV 856, 0>>>, <BVV 2040, 0>>>, <BVV 40, 0>>>, <BVV 8, 0>>>, <__lshift__ <Concat <BVV 0, 32>, <Extract <BVV 31, 0>, <BVV 0, 0>, <LShR <Concat <BVV 0, 32>, <__xor__ <BVV 0, 32>, <__or__ <Concat <Extract <BVV 2015, 0>, <BVV 2008, 0>, <BVS data, 2240>>, <BVV 0, 24>>, <Concat <BVV 0, 8>, <Extract <BVV 2007, 0>, <BVV 2000, 0>, <BVS data, 2240>>, <BVV 0, 16>>, <Concat <BVV 0, 16>, <Extract <BVV 1999, 0>, <BVV 1992, 0>, <BVS data, 2240>>, <BVV 0, 8>>, <Concat <BVV 0, 24>, <Extract <BVV 1991, 0>, <BVV 1984, 0>, <BVS data, 2240>>>>>>, <BVV 0, 64>>>>, <BVV 3, 64>>, <BVV 8, 64>>",
    ]

    def test_access_path(self):
        state = get_blank_state()
        for test in self.Tests:
            AccessNode.create(test).to_claripy(state)
