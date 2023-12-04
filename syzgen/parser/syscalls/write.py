
from typing import Optional
from syzgen.parser.syscalls import Syscall
from syzgen.parser.syscalls.read import SysRead
from syzgen.parser.types import PtrDir, PtrType, ResourceType, StructType


class SysWrite(SysRead):
    """Syscall Write
    write(fd, data ptr, size bytesize[data])
    """
    NAME = "write"

    def __init__(self, subName, fd: Optional[ResourceType] = None):
        super().__init__(subName, fd)

    def validate(self):
        Syscall.validate(self)

        if isinstance(self.data, PtrType):
            self.data.dir |= PtrDir.DirIn
            self.size.path = [1]

        if isinstance(self.size, StructType):
            if self.size.fields[0].size <= 4:
                self.size = self.size.fields[0]
                self.size.path = [1]
