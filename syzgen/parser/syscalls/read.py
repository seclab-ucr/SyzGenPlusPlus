
from typing import Optional
from syzgen.models import MAX_MEMORY_SIZE
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import BufferType, PtrDir, PtrType, ResourceType, int2bytes


class SysRead(Syscall):
    """Syscall Read
    read(fd, data ptr, size bytesize[data])
    """
    NAME = "read"
    ARG_FD = "fd"
    ARG_DATA = "data"
    ARG_SIZE = "size"

    def __init__(self, subName, fd: Optional[ResourceType] = None):
        super().__init__(f"{subName}_syzgen")

        self.args.append(fd if fd else ResourceType(
            {"name": f"{subName}_fd", "parent": "fd", "data": int2bytes(0, 4)},
            typename="fd"
        ))
        self.args.append(
            PtrType({"ref": BufferType({"data": [0xff]*MAX_MEMORY_SIZE}).toJson()},
                    typename="data")
        )
        self.args.append(BufferType(
            {"data": int2bytes(MAX_MEMORY_SIZE, 8)},
            typename="size"),
        )

        self.validate()

    def validate(self):
        super().validate()

        if isinstance(self.data, PtrType):
            self.data.dir = PtrDir.DirOut
            self.size.path = [1]

    @property
    def data(self):
        return self.args[1]

    @data.setter
    def data(self, val):
        self.args[1] = val

    @property
    def size(self):
        return self.args[2]

    @size.setter
    def size(self, val):
        self.args[2] = val
