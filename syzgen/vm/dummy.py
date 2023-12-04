

import os
import subprocess
from typing import Any, Dict
from syzgen.config import Options
from syzgen.vm import VMInstance


options = Options()


class DummyInstance(VMInstance):
    """In case we do not have dynamic environment, use pure static solution
    with dummy vm instance."""

    def __init__(self, kernel_dir, user="root") -> None:
        super().__init__(kernel_dir, user)

    def get_type(self) -> str:
        return "dummy"

    @staticmethod
    def initialize(*args, **kwargs) -> "DummyInstance":
        return DummyInstance(
            kwargs.pop("kernel", "") or options.getConfigKey("kernel", ""),
        )

    def copy(self) -> "DummyInstance":
        return self

    def wait_for_ssh(self, timeout=5):
        return

    def is_running(self) -> bool:
        return True

    def run_cmd(self, cmds, check=True, enable_stdout=False, enable_stderr=False, timeout=None):
        return subprocess.run(
            ["echo"],
            check=check,
            stdout=subprocess.PIPE if enable_stdout else None,
            stderr=subprocess.PIPE if enable_stderr else None,
            timeout=timeout,
        )

    def genSyzConfig(self, **kwargs) -> Dict[str, Any]:
        return {}

    def get_kernel(self) -> str:
        if self.kernel_dir:
            return os.path.join(self.kernel_dir, "vmlinux")
        return ""
