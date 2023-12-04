
import logging
import os
import subprocess
import re
import time

from typing import Any, Dict, List
from syzgen.config import Options

from syzgen.debugger import Debugger
from syzgen.debugger.proxy import Proxy

from syzgen.vm import VMInstance

logger = logging.getLogger(__name__)
options = Options()


class VmwareInstance(VMInstance):
    def __init__(self, kernel_dir, vmxpath, ip="", user="root") -> None:
        super().__init__(kernel_dir, user=user)

        self._kernel = os.path.join(kernel_dir, "kernel.development")
        self._vmxpath = vmxpath
        self._ip = ip

    def get_type(self) -> str:
        return "vmware"

    def get_kernel(self) -> str:
        return self._kernel

    def copy(self) -> "VmwareInstance":
        return VmwareInstance(
            self.kernel_dir,
            self._vmxpath,
            ip=self._ip,
            user=self.user
        )

    def run(self):
        attempts = 2
        while True:
            try:
                subprocess.run(["vmrun", "start", self._vmxpath, "nogui"], check=True)
                break
            except subprocess.CalledProcessError as e:
                if attempts > 0:
                    attempts -= 1
                    time.sleep(5)
                    logger.info("failed to launch vmware, let us try one more time!")
                    continue

                raise e

        # Call this regardless to make sure we successfully boot the vm
        ret = subprocess.run(
            ["vmrun", "getGuestIPAddress", self._vmxpath, "-wait"],
            timeout=5*60,
            check=True,
            stdout=subprocess.PIPE,
        )
        ip = ret.stdout.decode("utf-8").strip()
        logger.debug("get vm ip %s", ip)
        if not re.match(r"(\d+\.){3}(\d+)", ip):
            raise RuntimeError("invalid ip")
        if self._ip and self._ip != ip:
            raise RuntimeError(f"the given ip does not match vmxpath {ip}")
        self._ip = ip

        self._process = subprocess.Popen(self.get_ssh_cmd())
        self._process.wait()

    def isConnected(self) -> bool:
        if not self._ip:
            # Wait until we get the ip via vmrun getGuestIPAddress
            return False
        return super().isConnected()

    def terminate(self):
        cmds = ["vmrun", "stop", self._vmxpath]
        while True:
            logger.debug("%s", " ".join(cmds))
            subprocess.run(cmds, check=False)
            time.sleep(1)
            ret = subprocess.run(
                ["vmrun", "list"], stdout=subprocess.PIPE, check=True)
            if self._vmxpath not in ret.stdout.decode("utf-8"):
                break
            if cmds[-1] != "hard":
                cmds.append("hard")
        return super().terminate()

    def get_ip(self) -> str:
        if not self._ip:
            raise RuntimeError("ip is None")
        return self._ip

    def get_ssh_cmd(self) -> List[str]:
        return [
            "ssh",
            f"{self.user}@{self._ip}",
        ]

    def get_scp_cmd(self, src, dst) -> List[str]:
        return [
            "scp",
            src,
            f"{self.user}@{self._ip}:{dst}",
        ]

    def wait_for_ssh(self, timeout=180):
        time.sleep(60)
        return super().wait_for_ssh(timeout=timeout)

    def suspend(self):
        self.run_cmd(
            ["sudo dtrace -w -n \"BEGIN { breakpoint(); }\""], check=False)
        # time.sleep(10)  # wait a few seconds to make it taking effect

    def genSyzConfig(self, **kwargs) -> Dict[str, Any]:
        return {
            "sshkey": options.getConfigKey("sshkey"),
            "ssh_user": self.user,
            "vm": {
                "count": 1,
                "base_vmx": options.getConfigKey("vmxpath"),
                "serial": options.getConfigKey("serial"),
            }
        }

    @staticmethod
    def initialize(*args, **kwargs) -> "VmwareInstance":
        kernel = kwargs.pop("kernel", "") or options.getConfigKey("kernel")
        user = kwargs.pop("user", "") or options.getConfigKey("user")
        vmpath = kwargs.pop("vmxpath", "") or options.getConfigKey("vmxpath")
        ip = kwargs.pop("ip", "") or options.getConfigKey("ip", "")
        return VmwareInstance(kernel, vmpath, user=user, ip=ip)


def TestVmwareInstance():
    inst = VmwareInstance.initialize("vmware")
    with inst:
        inst.wait_for_ssh()

        inst.run_cmd(["ls", "/"])
