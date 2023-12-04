import unittest
from syzgen.analysis.tests import TestExecutor
from syzgen.config import Options


options = Options()

# @unittest.skipIf(options.getConfigKey("target") != "android", "requires Android")
class TestAndroidExecutor(TestExecutor):
    SYSCALLS = [
        {
            "module": "ipc",
            "name": "write",
            "dynamic": False,
            "syscall": {'CallName': 'write', 'SubName': 'ipc_Group0_0_syzgen', 'status': 0, 'args': [{'type': 'resource', 'offset': 0, 'size': 4, 'typename': 'fd', 'data': [0, 0, 0, 0], 'access': True, 'name': 'ipc_fd', 'parent': 'fd'}, {'type': 'ptr', 'offset': 0, 'size': 8, 'typename': 'data', 'optional': False, 'dir': 1, 'ref': {'type': 'buffer', 'offset': 0, 'size': 4096, 'access': True}}, {'type': 'buffer', 'offset': 0, 'size': 8, 'typename': 'size', 'data': [0, 16, 0, 0, 0, 0, 0, 0], 'access': True, 'path': [1], 'bitSize': 8}]}
        },
    ]

    def setUp(self, debug: bool = True) -> None:
        return super().setUp(debug, config="pixel_config")

    def test_syscalls(self):
        for test in self.SYSCALLS:
            timeout = 600 if "timeout" not in test else test["timeout"]
            syscall, model, interface = self.prepare_executor(
                test["module"],
                test["name"],
                syscall_json=test["syscall"],
                timeout=timeout,
                dynamic=test["dynamic"]
            )
            interface.execute_syscall(syscall, model, cmd=interface.cmd)

            print("result:")
            for each in model.methods[interface.cmd]:
                print(each.repr())
