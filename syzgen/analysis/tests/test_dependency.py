
import os
import json

from syzgen.analysis.access_path import AccessNode
from syzgen.analysis.dependence import generate_valid_testcase, match_array_with_index, match_multiple_access, merge_read_access_paths
from syzgen.analysis.tests import TestExecutor
from syzgen.utils import get_blank_state

cur_dir = os.path.dirname(os.path.abspath(__file__))

class TestDependence(TestExecutor):
    def test_dependency_type(self):
        data_path = os.path.join(cur_dir, "data", "access_paths.json")
        with open(data_path, "r") as fp:
            tests = json.load(fp)

        state = get_blank_state()
        for test in tests:
            with self.subTest(test=test):
                writes = set(AccessNode.create(each) for each in test["write"])
                for each in writes:
                    print("write: ", str(each))
                    print(each.to_claripy(state))
                # print(writes)
                reads = {}
                for p, t in test["read"].items():
                    reads[AccessNode.create(p)] = tuple(t)
                for each in reads:
                    print("read: ", str(each))
                    print(each.to_claripy(state))
                # print(reads)
                merges = merge_read_access_paths(reads)
                found = False
                for (path, size), read_patterns in merges.items():
                    for i, func in enumerate([
                        match_multiple_access,
                        match_array_with_index,
                    ]):
                        matched_writes = func(read_patterns, writes)
                        if matched_writes:
                            print(f"[Type {i}] matched!")
                            found = True
                            break
                self.assertEqual(found, test["result"])

    def test_generate_testcase(self):
        module = "dev_dri"
        generate_valid_testcase(
            self.target,
            "ioctl$DRM_IOCTL_PRIME_FD_TO_HANDLE",
            f"cfg_{module}.json",
            "poc.syz",
            timeout=30*60
        )
