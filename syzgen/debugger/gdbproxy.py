
from functools import lru_cache
import logging
import os
import re
import subprocess
from typing import Optional

import pexpect
from syzgen.config import Options
from syzgen.debugger import Debugger

from syzgen.debugger.proxy import Proxy

logger = logging.getLogger(__name__)
options = Options()

FIELD_OFFSET_REG = re.compile(r"^\$1 = \((?P<type>.+)\) (?P<value>0x[\da-f]+)")
STRUCT_SIZE_REG = re.compile(r"^\$1 = (?P<value>\d+)$")


class GDBProxy(Proxy):
    '''GDB Proxy used by angr to retrieve code and data
    '''

    def __init__(self, port=None):
        super().__init__(port=port)

    def read_memory(self, addr, size):
        request = {
            "cmd": "read mem",
            "addr": addr,
            "size": size
        }
        return self.request(request, fmt="binary")

    def set_breakpoint(self, addr, **kwargs):
        """
        set breakpoint
        addr: address
        target: the program to trigger the breakpoint
        """
        request = {
            "cmd": "set bp",
            "target": kwargs.pop("target", "poc"),
            "addr": addr
        }
        self.request(request)

    def wait_breakpoint(self, timeout=None):
        super().wait_breakpoint(timeout=15)


class GDBDebugger(Debugger):

    def __init__(self, kernel, ip: str, gdb_port: int):
        super().__init__(kernel, GDBProxy(), ip)

        self._gdb_port = gdb_port

    def get_debugger(self) -> str:
        return "gdb"

    def get_broken_string(self) -> str:
        return "Remote connection closed"

    def get_slide(self) -> int:
        return 0

    def communicate(self, debugger: pexpect.spawn):
        debugger.expect("\\(gdb\\)")

        debugger.sendline("set pagination off")
        # debugger.sendline("set target-async on")
        debugger.sendline("source " + os.path.join(os.getcwd(), "proxy.py"))
        debugger.sendline("source " + os.path.join(os.getcwd(), "gdb_debug.py"))
        logger.debug(debugger.before)

        debugger.sendline(f"target remote {self._ip}:{self._gdb_port}")
        debugger.expect("Remote debugging using")
        logger.debug(debugger.before)
        logger.debug("proxy -c")
        debugger.sendline("proxy -c")

    @staticmethod
    @lru_cache(maxsize=None)
    def structSize(
        structName: str,
        object_path: Optional[str] = None,
    ) -> int:
        if object_path is None:
            # FIXME: refactor this
            object_path = os.path.join(
                options.getConfigKey("binary"), "vmlinux")
        cmds = [
            "gdb",
            object_path,
            "-ex", f"p sizeof({structName})",
            "-q", "--batch",
        ]
        ret = subprocess.run(cmds, stdout=subprocess.PIPE)
        for line in ret.stdout.split(b'\n'):
            line = line.decode('utf-8')
            if "$1" in line:
                print(line)
                m = STRUCT_SIZE_REG.match(line)
                if m:
                    return int(m.group("value"))
        raise Exception(f"Failed to get the size of {structName}")

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
                options.getConfigKey("binary"), "vmlinux")
        cmds = [
            "gdb",
            object_path,
            "-ex", f"p &((({structName}*)0)->{fieldName})",
            "-q", "--batch",
        ]
        ret = subprocess.run(cmds, stdout=subprocess.PIPE)
        for line in ret.stdout.split(b'\n'):
            line = line.decode('utf-8')
            if "$1" in line:
                print(line)
                m = FIELD_OFFSET_REG.search(line)
                if m:
                    return int(m.group("value"), 16)
        raise Exception(
            f"Failed to get the offset of {fieldName} from {structName}")


def TestGDBDebugger():
    print("Offset:", GDBDebugger.fieldOffset(
        "refcount",
        "struct kmem_cache",
        "/home/wchen130/workplace/SyzGen_setup/linux-5.15-raw/vmlinux",
    ))
    print("Size:", GDBDebugger.structSize(
        "struct kmem_cache",
        "/home/wchen130/workplace/SyzGen_setup/linux-5.15-raw/vmlinux",
    ))
