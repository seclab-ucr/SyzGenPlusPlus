
import json
import os
from typing import List
import unittest
from syzgen.analysis.plugins.recovery import ALL_INFERENCE_RULES, InferenceRule

from syzgen.parser.syscalls import Syscall

cur_dir = os.path.dirname(os.path.abspath(__file__))

class TestInference(unittest.TestCase):
    def test_inference_rules(self):
        data_path = os.path.join(cur_dir, "data", "syscalls.json")
        with open(data_path, "r") as fp:
            tests = json.load(fp)

        all_rules: List[InferenceRule] = []
        for t, rules in ALL_INFERENCE_RULES.items():
            for rule in rules:
                all_rules.append(rule(target=t))
        print(all_rules)

        for test in tests:
            with self.subTest(test=test):
                syscall = Syscall.load(test["syscall"])
                print(syscall.repr())
                for rule in all_rules:
                    rule.optimize(syscall)
                print(syscall.repr())
                print(syscall.toJson())
                result = Syscall.load(test["result"])
                self.assertTrue(syscall.equal(result))
