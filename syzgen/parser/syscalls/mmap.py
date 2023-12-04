
from syzgen.models import MAX_MEMORY_SIZE
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import BufferType, Constant, KnownType, LenType, ResourceType, int2bytes


class Mmap(Syscall):
    """void *mmap(void *addr, size_t length, int prot, int flags,
    int fd, off_t offset);"""
    NAME = "mmap"
    ARG_ADDR = "addr"
    ARG_LEN = "len"
    ARG_PROT = "prot"
    ARG_FLAGS = "flags"
    ARG_FD = "fd"
    ARG_OFFSET = "offset"

    def __init__(self, subName, fd=None):
        super().__init__(subName)

        self.args.append(KnownType({"name": "vma", "size": 8}))
        self.args.append(LenType({
            "lenField": "addr",
            "bitSize": 8,
            "min": 0,
            "max": 0,
            "size": 8,
            "path": [0],
        }))
        self.args.append(KnownType({"name": "flags[mmap_prot]", "size": 4}))
        self.args.append(KnownType({"name": "flags[mmap_flags]", "size": 4}))
        self.args.append(fd if fd else ResourceType(
            {"name": f"{subName}_fd", "parent": "fd", "data": int2bytes(0, 4)},
        ))
        self.args.append(Constant(0, 4, None))

        self.validate()

    @property
    def size(self):
        return self.args[1]

    @size.setter
    def size(self, val):
        self.args[1] = val

    def validate(self):
        super().validate()

        self.size.path = [0]
