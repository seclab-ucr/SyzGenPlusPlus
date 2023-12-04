
import logging
import subprocess
import time
import re
from typing import Any, Dict, List
from syzgen.config import Options

from syzgen.vm import VMInstance

logger = logging.getLogger(__name__)
options = Options()


class ADBInstance(VMInstance):
    """Connect Android via adb"""

    def __init__(self, kernel_dir, adb_bin, device=None, has_root=False) -> None:
        super().__init__(kernel_dir, user="shell")

        self.adb_bin = adb_bin
        self.device = device
        self.has_root = has_root

        if not self.device:
            devices = self.get_devices()
            if len(devices) != 1:
                logger.error("find %d devices", len(devices))
                raise RuntimeError()
            self.device = devices[0]

    def run(self):
        logger.debug("start adb...")
        cmds = [
            *self.get_ssh_cmd(),
            *self.get_log_cmd(),
        ]
        self._process = subprocess.Popen(cmds)
        self._process.communicate()

    def get_log_cmd(self):
        if self.has_root:
            return ["su", "root", "dmesg", "w"]
        return ["logcat", "–v", "time", "*:F"]

    def get_scp_cmd(self, src, dst) -> List[str]:
        return [
            self.adb_bin,
            "-s",
            self.device,
            "push",
            src,
            dst,
        ]

    def get_ssh_cmd(self) -> List[str]:
        return [
            self.adb_bin,
            "-s",
            self.device,
            "shell",
        ]

    def get_devices(self):
        cmds = [self.adb_bin, "devices"]
        ret = subprocess.run(cmds, check=True, stdout=subprocess.PIPE)
        regex = re.compile(r"^([\w\d-]+)[ \t]+(\w+)$")
        devices = []
        for line in ret.stdout.split(b"\n"):
            line = line.decode("utf-8")
            if line.startswith("List of devices"):
                continue
            res = regex.match(line)
            if res:
                devices.append(res.group(1))
        return devices

    @staticmethod
    def initialize(**kwargs):
        device = kwargs.pop("device", "") or options.getConfigKey("device", default="")
        user = kwargs.pop("user", "") or options.getConfigKey("user", default="")
        return ADBInstance(
            # right now we don't have the kernel for Android
            kwargs.pop("kernel", ""),
            kwargs.pop("adb", "") or options.getConfigKey("adb"),
            device=device,
            has_root=(user == "root"),
        )

    def copy(self) -> "VMInstance":
        return ADBInstance(
            self.kernel_dir,
            self.adb_bin,
            device=self.device,
            has_root=self.has_root,
        )

    def get_type(self) -> str:
        return "adb"

    def genSyzConfig(self, **kwargs) -> Dict[str, Any]:
        return {}

    def get_kernel(self) -> str:
        return os.path.join(self.kernel_dir, "vmlinux")

def TestADBInstance():
    inst = ADBInstance(
        "",
        "adb",
        options.getConfigKey("device", default=""),
        has_root=False
    )
    with inst:
        time.sleep(1)
        inst.wait_for_ssh()

        inst.run_cmd(["ls", "-al", "/dev"])
