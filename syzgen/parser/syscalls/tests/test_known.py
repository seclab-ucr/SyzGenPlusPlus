
import unittest

from syzgen.parser.types import ALL_KNOWN_TYPES, StructType


class TestKnownTypes(unittest.TestCase):
    def test_known_types_linux(self):
        for name, types in ALL_KNOWN_TYPES["linux"].items():
            print(f"{name}:")
            for each in types:
                self.assertTrue(isinstance(each, StructType))
                print(each.repr())
