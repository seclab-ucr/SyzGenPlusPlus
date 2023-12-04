
import logging
import os
from typing import Optional
import pexpect

from threading import Thread, Lock

from syzgen.debugger.proxy import Proxy

logger = logging.getLogger(__name__)


class Debugger(Thread):
    """Abstract debugger for VM"""

    def __init__(self, kernel, proxy: Proxy, ip: str):
        super().__init__()

        self._ip = ip
        self.kernel = kernel
        self.proxy: Proxy = proxy
        self.lock = Lock()

        if not os.path.exists(kernel):
            raise FileNotFoundError(kernel)

    def get_slide(self) -> int:
        raise NotImplementedError()

    def get_debugger(self) -> str:
        raise NotImplementedError()

    def communicate(self, debugger: pexpect.spawn):
        raise NotImplementedError()

    def get_broken_string(self) -> str:
        raise NotImplementedError()

    def run(self):
        debugger = None
        try:
            if not self.lock.acquire(blocking=False):
                # already call terminate
                return

            cmd = f"{self.get_debugger()} {self.kernel}"
            logger.debug("run %s", cmd)
            c = os.environ.copy()
            c["PROXY_PORT"] = f"{self.proxy.port}"
            debugger = pexpect.spawn(cmd, timeout=60, env=c)
            self.communicate(debugger)
            # wait indefinitely until the connection is terminated,
            # connection is broken if we close proxy.
            debugger.expect(self.get_broken_string(), timeout=None)
            # print(debugger.before)
            logger.debug("return from proxy -c")
        except pexpect.exceptions.TIMEOUT as e:
            logger.debug("debugger timeout")
            if debugger:
                logger.debug("%s", debugger.before)
        finally:
            if debugger:
                try:
                    debugger.close()
                    debugger.terminate(force=True)
                except pexpect.exceptions.ExceptionPexpect:
                    pass
            self.lock.release()

    def terminate(self):
        logger.debug("terminate debugger...")
        self.proxy.exit()
        # make sure our debugger exit
        self.lock.acquire()

    def fieldOffset(
        fieldName: str,
        structName: str,
        object_path: Optional[str] = None
    ) -> int:
        """use debugger to calculate offsetof"""
        raise NotImplementedError()


class DummyDebugger(Debugger):
    def run(self):
        pass

    def get_slide(self) -> int:
        return 0
