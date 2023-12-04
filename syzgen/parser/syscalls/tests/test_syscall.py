
import os
import json
import unittest
from syzgen.parser.syscalls import Syscall

cur_dir = os.path.dirname(os.path.abspath(__file__))

class TestSyscall(unittest.TestCase):
    def test_syscall_to_json(self):
        data_path = os.path.join(cur_dir, "data", "syscalls.json")
        with open(data_path, "r") as fp:
            tests = json.load(fp)

        for test in tests:
            with self.subTest(test=test):
                syscall = Syscall.load(test)
                print(syscall.toJson())
                print(test)
                self.assertTrue(syscall.toJson() == test)
