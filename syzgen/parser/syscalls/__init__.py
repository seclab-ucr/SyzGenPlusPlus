
import copy
from enum import Enum
import importlib
import json
import os
import tempfile
# import logging

from typing import Dict, Generator, List, Optional, Set, Tuple, TypeVar
import typing
from claripy.ast.base import Base
from syzgen.parser.types import ConstType, Constant, Context, PtrDir, PtrType, ResourceType, StructType, SyscallNamespace, SyscallTypeRefineCallback, SyscallVisitCallback, Type, int2bytes

SyscallType = TypeVar("SyscallType", bound="Syscall")
# logger = logging.getLogger(__name__)


class SyscallStatus(Enum):
    INIT = 0
    REINIT = 1
    INCOMPLETE = 2
    FINISHED = 3

    OUTPUT = 4


class Syscall(SyscallNamespace):
    NAME = "syscall"
    SUBNAME_FORMAT = "{}_Group{:x}_{}"

    def __init__(self, subName):
        self.SubName: str = subName

        self.args: List[Type] = []
        # It seems that we only care about returned resource
        self.ret: Optional[ResourceType] = None
        self.arg_names: List[str] = self.collect_arg_names()

        self._counter = 0
        self.status: SyscallStatus = SyscallStatus.INIT

    @property
    def CallName(self) -> str:
        return self.NAME

    @property
    def Name(self) -> str:
        if self.SubName and len(self.SubName) > 0:
            return f"{self.CallName}${self.SubName}"
        return self.CallName

    def check_return_value(self) -> bool:
        # whether we need to check return value (cause it might be a resource)
        return False

    def collect_arg_names(self) -> List[str]:
        base = self.__class__
        if base is Syscall:
            return []

        arg_names = []
        while True:
            for k, v in vars(base).items():
                if k.startswith("ARG_"):
                    arg_names.append(v)
                    assert type(v) is str

            if arg_names:
                break
            base = base.__base__
            if base is object:
                raise RuntimeError(
                    "syscall %s does not specify arguments", self.CallName)
        return arg_names

    def assignNewName(self, prefix: str) -> str:
        # Note: the rule for generating names is critical as we rely on the pattern to distinguish
        # special flags.
        self._counter += 1
        return f"{self.SubName}_{prefix}_{self._counter}"

    def is_unique(self, name: str) -> bool:
        return name.startswith(self.SubName)

    def resetName(self):
        """All self-assigned name should be reset as we may want to re-name the syscall.
        """
        self._counter = 0
        for arg in self.args:
            arg.resetName(self.SubName)

    def set_subname(self, model_name: str, cmd: int, index: int) -> None:
        self.SubName = self.SUBNAME_FORMAT.format(model_name, cmd, index)

    def validate(self):
        assert len(self.arg_names) == len(self.args)
        # if self.arg_names and len(self.arg_names) == len(self.args):
        for i, arg in enumerate(self.args):
            arg.typename = self.arg_names[i]
        return True

    def visit(self, ctx: Context, func: SyscallVisitCallback, isOffset=False):
        """ Visitor to traverse all arguments in a DFS manner.
        func return True if it wants to stop the traversal.
        """
        ctx.syscall = self
        if self.ret:
            ctx.arg = self.ret.typename
            ctx.path.append(-1)
            ctx.dir = PtrDir.DirOut
            ctx.parent = None
            self.ret.visit(ctx, func, isOffset=isOffset)
            ctx.path.pop()

        for i, arg in enumerate(self.args):
            ctx.arg = arg.typename
            ctx.path.append(i)
            ctx.parent = None
            ctx.dir = PtrDir.DirIn
            if arg.visit(ctx, func, isOffset=isOffset):
                break
            ctx.path.pop()

    def refine(self, other) -> None:
        """Refine the current type according to the given one"""
        for i in range(len(self.args)):
            self.args[i] = self.args[i].refine(other.args[i])
        self.validate()

    def refine_type(
        self,
        ctx: Context,
        func: SyscallTypeRefineCallback,
        isOffset: bool = False
    ):
        """ Visitor to traverse all arguments and allow modification of them.
        func should return a refined type based on the original type passed as
        the second parameter. You can also return a list of types if you split
        the original type.
        """
        ctx.syscall = self
        for i, arg in enumerate(self.args):
            ctx.arg = arg.typename
            ctx.path.append(i)
            ret = arg.refine_type(ctx, func, isOffset=isOffset)
            if isinstance(ret, list):
                # We split the original field into multiple fields
                fields = [each.toJson() for each in ret]
                ret = StructType({"fields": fields})
            elif not isinstance(ret, Type):
                raise Exception(f"unknown type {type(ret)}")
            self.args[i] = ret
            ctx.path.pop()
        self.validate()

    def simplify(self, other):
        """Refine current model according to passed model
        """
        self.CallName = other.CallName
        self.SubName = other.SubName
        for i, arg in enumerate(self.args):
            self.args[i] = arg.simplify(other.args[i])
        self.validate()

    def equal(self, other: "Syscall"):
        if self.CallName != other.CallName:
            return False
        for i, arg in enumerate(self.args):
            if not arg.equal(other.args[i]):
                return False
        return True

    def generateTemplateArg(self, f, index: int, arg: Type) ->Tuple[str, str]:
        # Note syzkaller assume the size for syscalls' argument is fixed.
        # Therefore, no need for const to specify the size.
        if isinstance(arg, StructType):
            # not suppose to have a struct for a syscall argument usually,
            # in some rare cases, we may need to construct a struct just
            # for an int
            if arg.size > 8 or self.NAME == "syz_convert_to_int":
                raise RuntimeError(f"argument size {arg.size} is too large for {self.NAME}")
            # in case we need to convert multiple args, add a suffix to generate unique names
            convert = SyzConvert2Int.Create(f"{self.SubName}_{index}", arg)
            f.write(f"resource {convert.ret.name}[{convert.ret.parent}]\n")
            convert.generateTemplate(f)
            return convert.ret.name, arg.typename

        return arg.generateTemplate(self, PtrDir.DirIn, f, top=True)

    def generateTemplate(self, f):
        args = []
        for i, arg in enumerate(self.args):
            typ, name = self.generateTemplateArg(f, i, arg)
            args.append(f"{name} {typ}")
        # syscallname "(" [arg ["," arg]*] ")" [type]
        resc = ""
        if self.ret and isinstance(self.ret, ResourceType):
            resc = self.ret.name
        f.write(
            f'{self.Name}({", ".join(args)}) {resc}\n'
        )

    def get_extra_syscalls(self) -> Generator[Optional["Syscall"], None, None]:
        """Extra syscalls generated when we produce the template (see @generateTemplate)"""
        for index, arg in enumerate(self.args):
            if isinstance(arg, StructType):
                with tempfile.TemporaryFile("w") as fp:
                    typ, _ = self.generateTemplateArg(fp, index, arg)
                    if typ.endswith("_ret"):
                        convert = SyzConvert2Int.Create(f"{self.SubName}_{index}", arg)
                        yield convert

    def repr(self):
        ret = self.Name + "\n"
        ret += f"status: {self.status}\n"
        for arg in self.args:
            ret += f"{arg.typename}:\n"
            ret += arg.repr()
        if self.ret:
            ret += "return:\n"
            ret += self.ret.repr()
        return ret

    def toArgs(self):
        # Convert it data that can be later transformed into testcase by syzkaller
        args = []
        for each in self.args:
            args.append(each.toJson())
        return {"group": self.Name, "args": args}

    def toJson(self):
        ret = {
            "CallName": self.CallName,
            "SubName": self.SubName,
            "status": self.status.value,
            "args": [each.toJson() for each in self.args],
        }
        if self.ret:
            ret["ret"] = self.ret.toJson()
        return ret

    def toJsonStr(self):
        return json.dumps(self.toJson())

    def copy(self):
        # obj = pickle.loads(pickle.dumps(self))
        obj = copy.deepcopy(self)
        obj.resetName()
        obj.validate()
        return obj

    @staticmethod
    def register_syscall(name: str, syscall_class: typing.Type["Syscall"]) -> None:
        # FIXME: how to register all syscalls
        SYSCALLS[name] = syscall_class

    @staticmethod
    def load(data):
        if data["CallName"] not in SYSCALLS:
            raise Exception("Unknown syscall name %s" % data["CallName"])

        syscall = SYSCALLS[data["CallName"]](data["SubName"])
        syscall.status = SyscallStatus(data["status"])
        syscall.SubName = data["SubName"]
        for i in range(len(data["args"])):
            syscall.args[i] = Type.construct(data["args"][i])
        syscall.validate()
        return syscall

    def get_input_arg_names(self) -> Set[str]:
        ret = set()
        for arg in self.args:
            if isinstance(arg, (ResourceType, ConstType)):
                continue
            if isinstance(arg, PtrType):
                if arg.dir & PtrDir.DirIn:
                    ret.add(arg.typename)
            else:
                ret.add(arg.typename)
        return ret

    def get_input_pointer_arg_names(self) -> Set[str]:
        ret = set()
        for arg in self.args:
            if isinstance(arg, PtrType) and arg.dir & PtrDir.DirIn:
                ret.add(arg.typename)
        return ret

    def refine_cmd(self, arg: Type, offset: int, size: int, cmd: Optional[int] = None) -> int:
        """ If we know which field is used as the command handler, we could further refine the
        model by concretizing it.
        """
        def concretize(ctx: Context, typ: Type):
            if ctx.arg != arg.typename:
                return typ

            # only analyze the first layer
            if (
                len(ctx.path) == 1 or
                (len(ctx.path) == 2 and ctx.parent.type == "ptr") or
                (len(ctx.path) == 3 and ctx.parent.type == "struct")
            ):
                # ptr->buffer or ptr->struct->buffer
                if typ.offset <= offset and typ.offset + typ.size >= offset + size:
                    if typ.size == size and typ.type == "const":
                        ctx.ret = typ.getData()
                        return typ
                    if typ.type != "buffer":
                        return typ

                    # split the buffer
                    fields = []
                    off = offset - typ.offset
                    for i, (start, end) in enumerate([(0, off), (off, off+size), (off+size, typ.size)]):
                        if start == end:
                            continue
                        data = typ.toJson()
                        data["data"] = typ.data[start:end]
                        data["offset"] = start + typ.offset
                        # reset the typename as it may split into multiple objs.
                        data["typename"] = None
                        if i == 1:
                            data["type"] = "const"
                            if cmd is not None:
                                data["data"] = int2bytes(cmd, size)
                            ctx.ret = int.from_bytes(data["data"], "little")
                        fields.append(Type.construct(data))
                    if len(fields) == 1:
                        fields[0] = typ.typename  # inherit parent's name
                        return fields[0]
                    return fields

            return typ

        ctx = Context()
        self.refine_type(ctx, concretize)
        if cmd is not None and ctx.ret != cmd:
            print(cmd, ctx.ret)
            raise Exception("incorrect cmd handler")
        return ctx.ret

    def getCmdHandler(self, sym: Base, cmd: Optional[int] = None) -> int:
        """Refine the syscall to make the command/selector concrete.
        It can also get back the concrete command value if the syscall
        has one (ie., it has gone through this process before), in which
        case pass None for cmd."""
        for i, arg in enumerate(self.args):
            if sym.op == "BVS":
                names = sym.args[0].split('_', 1)
                if names[0] == arg.typename:
                    if not isinstance(arg, ConstType):
                        if cmd is None:
                            raise RuntimeError("cmd is None")
                        self.args[i] = Constant(cmd, arg.size, arg.typename)
                    return self.args[i].getData()
            elif sym.op == "Extract" and sym.args[2].op == 'BVS':
                if isinstance(arg, PtrType):
                    left, right = (
                        (sym.args[2].length-sym.args[0]-1)//8,
                        (sym.args[2].length-sym.args[1])//8
                    )
                else:
                    left, right = sym.args[1]//8, (sym.args[0]+1)//8
                names = sym.args[2].args[0].split('_', 1)
                if names[0] == arg.typename:
                    return self.refine_cmd(arg, left, right-left, cmd=cmd)
            else:
                raise NotImplementedError("getCmdHandler for %s", sym)

        raise RuntimeError("failed to get cmd handler")


SYSCALLS: Dict[str, typing.Type[Syscall]] = {}

path = os.path.dirname(os.path.abspath(__file__))
for file_name in os.listdir(path):
    if not file_name.endswith(".py"):
        continue
    if file_name == "__init__.py":
        continue
    module_name = file_name[:-3]
    m = importlib.import_module(
        f".{module_name}",
        "syzgen.parser.syscalls",
    )
    for attr_name in dir(m):
        attr = getattr(m, attr_name)
        if (
            isinstance(attr, type) and
            issubclass(attr, Syscall) and
            attr_name != "Syscall"
        ):
            Syscall.register_syscall(attr.NAME, attr)

# fmt: off
from syzgen.parser.syscalls.syz_convert import SyzConvert2Int
# fmt: on
