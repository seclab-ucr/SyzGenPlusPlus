
import unittest
from syzgen.executor import KEY_VARIABLES
from syzgen.executor.locals import SimStateLocals  # DON'T REMOVE: register locals
from syzgen.parser.symtype import SymType
from syzgen.parser.types import Constant

from syzgen.utils import get_blank_state


class TestType(unittest.TestCase):
    ranges = [
        {
            "size": 32,
            "ranges": [(31, 0, 0), (7, 0, 103), (31, 24, 100), (31, 0, 1), (15, 8, 1)],
            "result": [(31, 24, 100), (23, 16, 1), (15, 8, 1), (7, 0, 103)],
        },
        {
            "size": 32,
            "ranges": [(31, 0, 0), (7, 0, 103), (15, 8, 101), (31, 24, 201), (29, 16, 8), (31, 0, 1), (23, 16, 2), (29, 24, 1), (19, 16, 1)],
            "result": [(31, 24, 201), (23, 16, 8), (15, 8, 101), (7, 0, 103)]
        },
        {
            "size": 32,
            "ranges": [(31, 0, 0), (7, 0, 101), (15, 8, 101), (29, 16, 7), (29, 24, 1), (23, 16, 1)],
            "result": [(31, 16, 7), (15, 8, 101), (7, 0, 101)]
        },
    ]
    def test_get_ranges(self):
        state = get_blank_state()
        for test in self.ranges:
            with self.subTest(test=test):
                new_state = state.copy()
                sym = new_state.solver.BVS("arg", size=test["size"])
                new_state.locals[KEY_VARIABLES] = {}
                for r in test["ranges"]:
                    new_state.locals[KEY_VARIABLES][(sym.args[0], r[0], r[1])] = r[2]

                arg = SymType(sym)
                result = arg.get_ranges(new_state)
                print(result)
                self.assertEqual(result, test["result"])

    def test_separate(self):
        const = Constant(0xdeadbeefdeadbeef, 8, None)
        self.assertTrue(const.separable(4))
        fields = const.separate(4)
        self.assertTrue(fields[0].getData() == 0xdeadbeef)
        self.assertTrue(fields[1].getData() == 0xdeadbeef)
