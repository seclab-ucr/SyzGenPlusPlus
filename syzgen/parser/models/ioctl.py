
from typing import Dict, List
from syzgen.parser.models import Address, BaseModel, MethodInfo, SyscallModel
from syzgen.parser.syscalls import Syscall
from syzgen.parser.syscalls.ioctl import IOCTLMethod, IOCTLOpen
from syzgen.parser.syscalls.mmap import Mmap
from syzgen.parser.syscalls.read import SysRead
from syzgen.parser.syscalls.write import SysWrite
from syzgen.parser.types import ResourceType, int2bytes


class IOCTLModel(SyscallModel[IOCTLMethod, MethodInfo]):
    def init_syscall(self, cmd: int, method: MethodInfo) -> IOCTLMethod:
        subname = Syscall.SUBNAME_FORMAT.format(self.name, cmd, 0)
        fd = ResourceType(
            {"name": f"{self.name}_fd", "parent": "fd",
                "data": int2bytes(0, 4)},
            typename="fd",
        )
        syscall = IOCTLMethod(subname, fd=fd)
        if method:
            syscall.getCmdHandler(self.dispatcher.selector, cmd)
        return syscall


class WriteModel(SyscallModel[SysWrite, MethodInfo]):
    def init_syscall(self, cmd: int, method: MethodInfo) -> SysWrite:
        subname = Syscall.SUBNAME_FORMAT.format(self.name, cmd, 0)
        fd = ResourceType(
            {"name": f"{self.name}_fd", "parent": "fd",
                "data": int2bytes(0, 4)},
            typename="fd",
        )
        syscall = SysWrite(subname, fd=fd)
        if method:
            syscall.getCmdHandler(self.dispatcher.selector, cmd)
        return syscall


class LinuxDriverModel(BaseModel):
    """Model for Linux Kernel Driver"""

    def initialize(
        self,
        ops: Dict[str, int],
        dev_path: str = ""
    ) -> None:
        if dev_path == "":
            raise RuntimeError("empty dev file path")

        self.add_syscall(IOCTLOpen(self.name, dev_path))
        if "read" in ops and ops["read"]:
            self.add_syscall(SysRead(self.name))
        if "mmap" in ops and ops["mmap"]:
            self.add_syscall(Mmap(self.name))
        if "unlocked_ioctl" in ops and ops["unlocked_ioctl"]:
            ioctl = IOCTLModel(self.name, Address("kernel", ops["unlocked_ioctl"]))
            self.add_syscall(ioctl)
        if "write" in ops and ops["write"]:
            write = WriteModel(self.name, Address("kernel", ops["write"]))
            self.add_syscall(write)

        super().initialize()

    def get_extra_syscalls(self) -> List[str]:
        ret = super().get_extra_syscalls()
        ret.append("close")
        return ret
