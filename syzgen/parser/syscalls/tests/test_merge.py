
import json
import os
from syzgen.config import Options
from syzgen.parser.optimize import reduce_syscall, reduce_syscalls

from syzgen.parser.syscalls import Syscall
from syzgen.test import BaseTestUnit

cur_dir = os.path.dirname(os.path.abspath(__file__))
options = Options()


class TestMergeSyscall(BaseTestUnit):
    def test_reduce_syscall_to_one(self):
        data_path = os.path.join(cur_dir, "data", "merge_syscalls.json")
        with open(data_path, "r") as fp:
            tests = json.load(fp)

        for test in tests:
            with self.subTest(test=test):
                syscalls = [Syscall.load(each) for each in test["syscalls"]]
                res = syscalls[0]
                print(res.repr())
                for syscall in syscalls[1:]:
                    print(syscall.repr())
                    res, changes = reduce_syscall(res, syscall, enforce=test["enfore"])
                print("result: %d" % changes)
                print(res.repr())
                # print(json.dumps(res.toJson()))
                result = Syscall.load(test["result"])
                self.assertTrue(res.equal(result))

    def test_reduce_syscalls(self):
        data_path = os.path.join(cur_dir, "data", "merge_multi_syscalls.json")
        with open(data_path, "r") as fp:
            tests = json.load(fp)

        for test in tests:
            with self.subTest(test=test):
                syscalls = [Syscall.load(each) for each in test["syscalls"]]
                for each in syscalls:
                    print(each.repr())
                syscalls = reduce_syscalls(syscalls)
                print("results:")
                for each in syscalls:
                    print(each.repr())
                    print(each.toJsonStr())
                self.assertEqual(len(syscalls), len(test["results"]))
                for i, each in enumerate(syscalls):
                    self.assertTrue(each.equal(Syscall.load(test["results"][i])))
