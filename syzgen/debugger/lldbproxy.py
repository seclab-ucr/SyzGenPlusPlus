
import logging
from typing import Optional
import os
import subprocess
import re

from functools import lru_cache
from syzgen.config import Options

from syzgen.debugger import Debugger

from syzgen.debugger.proxy import Proxy

logger = logging.getLogger(__name__)
options = Options()

FIELD_OFFSET_REG = re.compile(
    r"^\((?P<type>.+)\) \$0 = (?P<value>0x[\da-f]+)$")


class LLDBProxy(Proxy):
    '''LLDB Proxy used by angr to retrieve code and data.
    '''

    def __init__(self, port=None, timeout=120):
        super().__init__(port=port, timeout=timeout)

    def read_memory(self, addr, size, task=None):
        request = {
            "cmd": "read mem",
            "addr": addr,
            "size": size
        }
        if task is not None:
            request["task"] = task
        return self.request(request, fmt="binary")

    def find_symbols_addr(self, names):
        request = {
            "cmd": "find symbol",
            "names": names,
        }
        reply = self.request(request)
        return reply["symbols"]

    @lru_cache()
    def find_symbol_name(self, addr) -> str:
        request = {
            "cmd": "find name",
            "addr": addr
        }
        reply = self.request(request)
        return reply["name"]

    @lru_cache()
    def find_section_name(self, addr):
        request = {
            "cmd": "find section",
            "addr": addr,
        }
        reply = self.request(request)
        return reply["name"]

    def find_global_variable(self, name):
        request = {
            "cmd": "find var",
            "name": name
        }
        reply = self.request(request)
        return reply["addr"]

    def read_kext_mapping(self):
        request = {
            "cmd": "showallkexts"
        }
        reply = self.request(request)
        ret = reply["kexts"]
        return sorted(ret, key=lambda x: x[0])

    def read_task(self, name):
        request = {
            "cmd": "showtask",
            "name": name
        }
        reply = self.request(request)
        return reply["task"]

    def set_task(self, name):
        request = {
            "cmd": "set target",
            "target": name
        }
        self.request(request)

    def step(self):
        request = {
            "cmd": "step"
        }
        self.request(request)

    def set_breakpoint(self, addr, **kwargs):
        """
        set breakpoint
        addr: address 
        kext: kext
        target: the program to trigger the breakpoint
        """
        request = {
            "cmd": "set bp",
            "kext": kwargs.pop("kext"),
            "target": kwargs.pop("target", "poc"),
            "addr": addr
        }
        self.request(request)


class LLDBDebugger(Debugger):
    '''LLDB debugger used to communicate with debugger and send commands.
    '''

    def __init__(self, kernel, ip):
        super().__init__(kernel, LLDBProxy(), ip)

        self._slide = 0

    def get_debugger(self) -> str:
        return "lldb"

    def get_slide(self) -> int:
        return self._slide

    def get_broken_string(self) -> str:
        return "connection is broken"

    def communicate(self, debugger):
        # logger.debug("spawn lldb")
        # lldb = pexpect.spawn("lldb %s" % self.kernel, timeout=30)
        debugger.expect("\\(lldb\\)")
        # lldb.expect("\\(lldb\\)")
        outs = debugger.before
        logger.debug(outs)

        # For unknown reason, we have to invoke 'script' in advance.
        debugger.sendline("script")
        debugger.expect(">>>")
        outs = debugger.before
        logger.debug(outs)

        debugger.sendline("quit()")
        debugger.expect("\\(lldb\\)")
        logger.debug(debugger.before)
        # lldb.expect("\\(lldb\\)")
        # print(lldb.before)

        debugger.sendline("command script import %s" %
                          os.path.join(os.getcwd(), "debug.py"))
        debugger.expect("\\(lldb\\)")
        logger.debug(debugger.before)
        # lldb.expect("\\(lldb\\)")
        # print(lldb.before)

        logger.debug("kdp-remote %s", self._ip)
        debugger.sendline(f"kdp-remote {self._ip}")
        debugger.expect("stopped")
        logger.debug(debugger.before)
        # Kernel slid 0x14000000 in memory.
        # Alternative: p vm_kernel_slide
        m = re.search(
            r"Kernel slid (?P<slide>0x[0-9a-f]+) in memory.", debugger.before.decode("utf-8"))
        if m:
            self._slide = int(m.group("slide"), 16)
            logger.debug("kernel slide 0x%x", self._slide)
        else:
            logger.error("failed to get the kernel slide")
            raise RuntimeError()

        logger.debug("proxy -c")
        debugger.sendline("proxy -c")

        # while not self.stop:
        #     lldb.expect([pexpect.TIMEOUT, pexpect.EOF], timeout=1)
        # logger.debug("return from proxy -c")

    @staticmethod
    @lru_cache(maxsize=None)
    def fieldOffset(
        fieldName: str,
        structName: str,
        object_path: Optional[str] = None
    ) -> int:
        if object_path is None:
            # FIXME: refactor this
            object_path = os.path.join(
                options.getConfigKey("kernel"), "kernel.development")
        cmds = [
            "lldb",
            object_path,
            "-o",
            f"p &((({structName}*)0)->{fieldName})",
            "--batch",
        ]
        ret = subprocess.run(cmds, stdout=subprocess.PIPE)
        for line in ret.stdout.split(b'\n'):
            line = line.decode('utf-8')
            if "$0" in line:
                print(line)
                m = FIELD_OFFSET_REG.match(line)
                if m:
                    return int(m.group("value"), 16)
        raise Exception(
            f"Failed to get the offset of {fieldName} from {structName}")


def TestLLDBDebugger():
    print(LLDBDebugger.fieldOffset(
        "structureOutputSize",
        "IOExternalMethodArguments",
        "/Library/Developer/KDKs/KDK_10.15.4_19E287.kdk/System/Library/Kernels/kernel.development",
    ))
