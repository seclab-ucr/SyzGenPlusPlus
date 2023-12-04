
import logging
import subprocess
from threading import Thread
import time
from typing import Any, Callable, Dict, List, Optional

from syzgen.debugger import Debugger
from syzgen.debugger.proxy import Proxy

logger = logging.getLogger(__name__)
Instances: Dict[str, Callable[[], "VMInstance"]] = {}


class VMFailure(Exception):
    pass


class VMInstance(Thread):
    """Base class for VM instance"""

    def __init__(self, kernel_dir, user="root") -> None:
        super().__init__()

        self.kernel_dir: str = kernel_dir
        self.user: str = user
        self._process: Optional[subprocess.Popen] = None
        self._debugger: Optional[Debugger] = None

    @staticmethod
    def register(typ: str, ctor: Callable[[], "VMInstance"]) -> None:
        Instances[typ] = ctor

    @staticmethod
    def initialize(typ: str, *args, **kwargs) -> "VMInstance":
        return Instances[typ](*args, **kwargs)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, typ, value, tb):
        self.terminate()

    def is_running(self) -> bool:
        """Different from is_alive, this ensures the vm has been connected"""
        return self._process and self._process.poll() is None

    def terminate(self):
        if self._process:
            self._process.terminate()
            self._process.wait()
            self._process = None
            logger.debug("terminate vm")
        if self._debugger:
            try:
                if self._debugger.proxy.is_alive():
                    self._debugger.proxy.output(self._debugger.get_broken_string())
            except ConnectionResetError:
                # the debugger exited already
                pass
            self._debugger.terminate()
            self._debugger = None
            logger.debug("terminated debugger")

    def isConnected(self) -> bool:
        # To avoid indefinite loop, do not use run_cmd
        new_cmds = [
            *self.get_ssh_cmd(),
            "pwd",
        ]
        # logger.debug("run %s", new_cmds)
        return subprocess.run(
            new_cmds,
            check=False,
        ).returncode == 0

    def wait_for_ssh(self, timeout=5):
        """Wait until we can connect to the instance.
        Overwrite this method to set pre-defined timeout for different VM
        """
        start = time.time()
        while time.time() - start < timeout:
            logger.debug("waiting for connection")
            if self.isConnected():
                return
            time.sleep(1)
        raise VMFailure()

    def copy_file(self, src: str, dst: str) -> str:
        cmds = self.get_scp_cmd(src, dst)
        subprocess.run(cmds, check=True)
        return dst

    def run_cmd(self, cmds, check=True, enable_stdout=False, enable_stderr=False, timeout=None):
        if not self.isConnected():
            raise RuntimeError("vm is not connected!")

        new_cmds = [
            *self.get_ssh_cmd(),
            # *cmds,
            " ".join(cmds),
        ]
        logger.debug("run %s", new_cmds)
        try:
            return subprocess.run(
                new_cmds,
                check=check,
                stdout=subprocess.PIPE if enable_stdout else None,
                stderr=subprocess.PIPE if enable_stderr else None,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            if check:
                raise e
            return None

    def attach_debugger(self, debugger: Debugger) -> Proxy:
        if not self.isConnected():
            raise RuntimeError("vm is not connected!")

        self._debugger = debugger
        self.suspend()
        debugger.start()
        debugger.proxy.serve()
        debugger.proxy.slide = debugger.get_slide()
        return debugger.proxy

    def copy(self) -> "VMInstance":
        raise NotImplementedError()

    def suspend(self):
        raise NotImplementedError()

    def get_ssh_cmd(self) -> List[str]:
        """Command to run shell commands"""
        raise NotImplementedError()

    def get_scp_cmd(self, src, dst) -> List[str]:
        """Command to upload files"""
        raise NotImplementedError()

    def get_type(self) -> str:
        raise NotImplementedError()

    def get_kernel(self) -> str:
        """return the kernel binary"""
        raise NotImplementedError()

    def get_ip(self) -> str:
        raise NotImplementedError()

    def get_debug_port(self) -> int:
        raise NotImplementedError()

    def get_ssh_port(self) -> int:
        raise NotImplementedError()

    def genSyzConfig(self, **kwargs) -> Dict[str, Any]:
        raise NotImplementedError

# fmt: off
from .adb import ADBInstance
from .vmware import VmwareInstance
from .qemu import QEMUInstance
from .dummy import DummyInstance
VMInstance.register("adb", ADBInstance.initialize)
VMInstance.register("qemu", QEMUInstance.initialize)
VMInstance.register("vmware", VmwareInstance.initialize)
VMInstance.register("dummy", DummyInstance.initialize)
# fmt: on
