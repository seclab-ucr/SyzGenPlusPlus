
import logging
import os
import unittest
from syzgen.analysis.tests import TestExecutor

from syzgen.config import Options

options = Options()
logger = logging.getLogger(__name__)
cur_dir = os.path.dirname(os.path.abspath(__file__))

@unittest.skipIf(options.getConfigKey("target") != "linux", "requires Linux")
class TestLinuxExecutor(TestExecutor):

    def test_syscalls(self):
        options.fork_profile = True
        for test in self.load_data(os.path.join(cur_dir, "data", "linux_executor.json")):
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
