
import os
from syzgen.config import Options
from syzgen.target.tests import TestTarget

options = Options()

class TestTestCase(TestTarget):
    def test_prepare_testcase(self):
        module_name = "card0"
        with self.target:
            poc = "poc.syz"
            while True:
                self.target.generate_poc(
                    "ioctl$card0_Group0_0",
                    os.path.join(
                        options.getConfigKey("syzkaller"),
                        "workdir",
                        f"cfg_{module_name}.json"
                    ),
                    poc,
                )
                if self.target.check_testcase(poc):
                    break
