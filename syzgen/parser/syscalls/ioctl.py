
import logging

from typing import Optional, Tuple, Union
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import Buffer, BufferType, ConstType, FlagType, LenType, PtrDir, PtrType, RangeType, ResourceType, StringType, StructType, Type, int2bytes


logger = logging.getLogger(__name__)


class IOCTLOpen(Syscall):
    """openat to open dev
    e.g., openat$ptmx(fd const[AT_FDCWD], file ptr[in, string["/dev/ptmx"]],
    flags flags[open_flags], mode const[0]) fd_tty
    """
    NAME = "openat"
    ARG_FD = "fd"
    ARG_FILE = "file"
    ARG_FLAGS = "flags"
    ARG_MODE = "mode"

    def __init__(self, subName, dev_file = ""):
        super().__init__(f"{subName}_syzgen")

        self.ret = ResourceType(
            {"name": f"{subName}_fd", "parent": "fd", "data": int2bytes(0, 4)},
            typename="fd",
        )
        self.args.append(
            ConstType({"data": int2bytes(0xffffffffffffff9c, 8)}, typename="fd"))
        self.args.append(PtrType({
            "ref": StringType({"values": [dev_file], "data": [0]}).toJson(), "dir": PtrDir.DirIn},
            typename="file"
        ))
        # dummy flags
        self.args.append(
            FlagType({"values": [0], "data": [0]}, typename="flags"))
        self.args.append(ConstType({"data": int2bytes(0, 4)}, typename="mode"))

        self.validate()

    def generateTemplate(self, f):
        values = ", ".join(f"\"{each}\""for each in self.file.ref.values)
        args = [
            "fd const[AT_FDCWD]",
            f'file ptr[in, string[{values}]]',
            "flags flags[open_flags]",
            "mode const[0]",
        ]
        # syscallname "(" [arg ["," arg]*] ")" [type]
        f.write(
            f'{self.Name}({", ".join(args)}) {self.ret.name if self.ret else ""}\n')

    @property
    def file(self):
        return self.args[1]


class IOCTLMethod(Syscall):
    """Syscall template for ioctl in Linux
    long ioctl(fd fd, unsigned int cmd, unsigned long arg)
    """
    NAME = "ioctl"
    ARG_FD = "fd"
    ARG_CMD = "cmd"
    ARG_ARG = "arg"

    def __init__(
        self,
        subname,
        fd: Optional[ResourceType] = None,
        cmd: Optional[Union[int, Type]] = None,
        arg: Optional[Type] = None,
    ):
        super().__init__(subname)

        self.args.append(fd if fd else ResourceType(
            {"name": "fd", "data": int2bytes(0, 4)},
            typename="fd",
        ))
        if cmd is not None:
            if isinstance(cmd, int):
                self.args.append(
                    ConstType({"data": int2bytes(cmd, 4)}, typename="cmd"))
            else:
                self.args.append(cmd)
        else:
            self.args.append(BufferType(
                {"data": int2bytes(0, 4)}))
        if arg is None:
            self.args.append(Buffer(8, None))
        else:
            self.args.append(arg)

        self.validate()

    @property
    def arg(self) -> Type:
        return self.args[2]

    @arg.setter
    def arg(self, val):
        self.args[2] = val

    @property
    def cmd(self) -> Type:
        return self.args[1]

    @cmd.setter
    def cmd(self, val):
        self.args[1] = val

    @property
    def fd(self) -> Type:
        return self.args[0]

    @fd.setter
    def fd(self, val):
        self.args[0] = val

    def generateTemplateArg(self, f, index: int, arg: Type) ->Tuple[str, str]:
        arg_name = self.arg_names[index]
        if arg_name == IOCTLMethod.ARG_ARG:
            # intptr, if it is not a pointer, its size must be 4
            if isinstance(arg, StructType):
                # FIXME: compact ptr with size of 8
                if arg.fields[0].size <= 4 or isinstance(arg.fields[0], PtrType):
                    c = arg.fields[0].copy()
                    if isinstance(arg.fields[0], RangeType):
                        c.size = 4
                    return self.generateTemplateArg(f, index, c)
                if arg.fields[0].separable(4):
                    arg.split(0, 4)
                    return self.generateTemplateArg(f, index, arg)

                logger.info("syscall: \n%s\n", self.repr())
                raise NotImplementedError()

            if arg.size > 4:
                if isinstance(arg, RangeType):
                    new_arg: RangeType = arg.copy()
                    new_arg.size = 4
                    new_arg.data = new_arg.data[:4]
                    new_arg.min = arg.min&0xffffffff
                    new_arg.max = 0xffffffff if arg.max&0xffffffff00000000 else arg.max&0xffffffff
                    return self.generateTemplateArg(f, index, new_arg)
            else:
                typ, name = super().generateTemplateArg(f, index, arg)
                if typ.startswith("int32"):
                    typ = "intptr" + typ[5:]
                return typ, name
        elif arg_name == IOCTLMethod.ARG_CMD:
            if isinstance(arg, StructType):
                value = 0
                for field in arg.fields:
                    off = field.offset * 8
                    if isinstance(field, ConstType):
                        value += (field.getData() << off)
                    elif isinstance(field, FlagType):
                        value += (max(*field.values) << off)
                    elif isinstance(field, RangeType):
                        value += (field.max << off)
                    elif isinstance(field, LenType):
                        if field.max:
                            value += (field.max << off)
                        else:
                            value += ((1 << field.size*8) - 1) << off
                    elif field.type == "buffer":
                        value += ((1 << field.size*8) - 1) << off
                    else:
                        raise NotImplementedError(f"unknown type: {field.type}")
                return "const[%s]" % hex(value), arg_name

        return super().generateTemplateArg(f, index, arg)

    def check_return_value(self) -> bool:
        return True
