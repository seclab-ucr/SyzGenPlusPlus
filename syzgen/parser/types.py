
from collections import defaultdict
import copy
from enum import IntFlag
import json
import logging
import os
from typing import Callable, Dict, List, Optional, Union

from syzgen.config import Options

logger = logging.getLogger(__name__)
options = Options()

#
#  Types for constructing structures
#


def Constant(val, size, name): return ConstType(
    {"data": int2bytes(val, size)}, typename=name)


def ConstantOffset(val, size, off, name): return ConstType(
    {"data": int2bytes(val, size)}, offset=off, typename=name)


def Buffer(size, name): return BufferType({"data": [0xff]*size}, typename=name)


def BufferOffset(size, off, name): return BufferType(
    {"data": [0xff]*size}, offset=off, typename=name)


def Pointer(ref, name): return PtrType({"ref": ref}, offset=0, typename=name)


def PointerOffset(ref, off, name): return PtrType(
    {"ref": ref}, offset=off, typename=name)


def NullPointer(off, name): return ConstantOffset(0, 8, off, name)


class TypeWeight:
    KnownType = 1000
    Input     = 100

class SimplifyError(Exception):
    """Testcase does not comply with given model"""

class SyscallNamespace:
    def assignNewName(self, prefix: str) -> str:
        raise NotImplementedError()

    def is_unique(self, name: str) -> bool:
        raise NotImplementedError()


def int2bytes(value, size):
    ret = []
    for _ in range(size):
        ret.append((value & 0xff))
        value = value >> 8
    return ret


def Size2Type(size):
    if size <= 1:
        return "int8"
    if size == 2:
        return "int16"
    if size == 4:
        return "int32"
    if size == 8:
        return "int64"
    return f"array[int8, {size}]"


def Const2Type(value, typename):
    size = len(value)
    types = {
        1: "const[0x%x, int8]",
        2: "const[0x%x, int16]",
        4: "const[0x%x, int32]",
        8: "const[0x%x, int64]"
    }
    if size in types:
        return types[size] % int.from_bytes(value, "little"), None

    definition = "%s {\n" % typename
    index = 0
    while len(value) > 0:
        size = len(value)
        if size >= 8:
            size = 8
        elif size >= 4:
            size = 4
        elif size >= 2:
            size = 2
        else:
            size = 1

        definition += "    field%d  %s\n" % (
            index, types[size] % int.from_bytes(value[:size], "little"))
        index += 1
        value = value[size:]
    definition += "} [packed]"
    return typename, definition


class Context:
    def __init__(self):
        self.syscall = None
        self.path: List[int] = []
        # name of the top level argument
        self.arg: str = None
        self.ret = None
        self.parent: Optional[Type] = None
        # PtrType.DirIn ...
        self.dir: PtrDir = 0


SyscallVisitCallback = Callable[[Context, "Type"], bool]
SyscallTypeRefineCallback = Callable[
    [Context, "Type"],
    Union["Type", List["Type"]]
]

ALL_TYPES = {}


class Type:
    """Base type for specs"""
    NAME = "type"

    def __init__(self, offset=0, size=0, typename=None):
        self.offset: int = offset
        self.size: int = size
        self.access: bool = True
        self.typename: str = typename   # name of this field
        self.path: Optional[List[int]] = None           # path to another field
        self.isArray: bool = False

    @property
    def type(self) -> str:
        return self.NAME

    def visit(self, ctx: Context, func: SyscallVisitCallback, isOffset: bool = False):
        return func(ctx, self)

    def refine_type(self, ctx: Context, func: SyscallTypeRefineCallback, isOffset: bool = False):
        return func(ctx, self)

    def refine(self, other: "Type") -> "Type":
        """Refine the current type according to the given one"""
        return self

    def resetName(self, prefix):
        if self.typename and self.typename.startswith(prefix):
            self.typename = None

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size) + "\n"
        return ret

    def getTypeName(self, syscall: SyscallNamespace):
        if self.typename is None:
            self.typename = syscall.assignNewName(self.type)
        return self.typename

    def equal(self, other: "Type") -> bool:
        raise Exception("Not implemented")

    @staticmethod
    def register_type(key: str, clazz) -> None:
        if key in ALL_TYPES:
            raise RuntimeError("%s is already registered for %s", key, clazz)
        ALL_TYPES[key] = clazz

    @staticmethod
    def construct(data, offset=0, isPtr=True) -> "Type":
        if "offset" in data:  # it is a pre-loaded model
            offset = data["offset"]
        type = data["type"]
        typename = data["typename"] if "typename" in data else None
        if type == "none":
            return None
        if type == "ptr" or (isPtr and "ptr" in data):
            return PtrType(data, offset, typename=typename)
        if type not in ALL_TYPES:
            raise Exception("unknown type %s" % type)
        return ALL_TYPES[type](data, offset, typename=typename)

    def getData(self):
        return None

    def getRawData(self):
        return []

    def copy(self) -> "Type":
        return copy.deepcopy(self)

    def toJson(self):
        ret = {
            "type": self.type,
            "offset": self.offset,
            "size": self.size,
        }
        if self.typename:
            ret["typename"] = self.typename
        return ret

    def generateTemplate(self, syscall: SyscallNamespace, dir: "PtrDir", f, top=False):
        raise NotImplementedError()

    def separable(self, size: int) -> bool:
        return False

    def separate(self, size: int) -> List["Type"]:
        raise NotImplementedError()


class PtrDir(IntFlag):
    UNKNOWN  = 0
    DirIn    = 1
    DirOut   = 2
    DirInOut = 3


class PtrType(Type):
    NAME = "ptr"
    DirStr = ["in", "in", "out", "inout"]  # default: in

    def __init__(self, data, offset=0, typename=None):
        super().__init__(offset=offset, size=8, typename=typename)
        self.data: Optional[List] = None
        self.dir: PtrDir = PtrDir.UNKNOWN if "dir" not in data else PtrDir(data["dir"])

        if "ref" in data:
            self.ref = Type.construct(data["ref"], 0, isPtr=False)
        elif data["type"] == "ptr":
            # A pointer type without ref
            self.ref = None
        else:
            self.ref = Type.construct(data, 0, isPtr=False)
            self.data = data["ptr"]

        if "optional" in data:
            self.optional = data["optional"]
        else:
            self.optional = False

    def equal(self, other):
        if other.type == "ptr":
            if self.ref and other.ref and self.ref.equal(other.ref):
                return True
        return False

    def refine(self, other):
        if other.type == "struct":
            raise Exception("incorrect struct type")
        if other.type != "ptr":
            ret = other.refine(self)
            ret.typename = self.typename or ret.typename
            return self
            # if other.size < self.size or len(other.fields) <= 1:
            #     raise Exception("incorrect struct type")
            # other = other.fields[0]  # due to alignment, the size must be larger than 8
            # return self.refine(other)
        # refine reference
        if self.ref is not None:
            self.dir |= other.dir
            self.ref = self.ref.refine(other.ref)
        return self

    def simplify(self, model):
        if model.type == "ptr":
            if self.ref is not None:
                self.ref = self.ref.simplify(model.ref)
            return self
        if model.type == "buffer" or model.type == "resource":
            if model.size != self.size:
                raise Exception("simplify ptr with wrong size")
            ret = model.toJson()
            ret["data"] = self.getData()
            return Type.construct(ret, offset=self.offset)

        # ERROR
        logger.debug("self:\n%s\n", self.repr())
        logger.debug("model:\n%s\n", model.repr())
        raise Exception("simplify ptr with struct")

    def visit(self, ctx, func, isOffset=False):
        if func(ctx, self):
            return True  # stop
        if self.ref:
            old_dir = ctx.dir
            # change the dir only if it is specified.
            ctx.dir = self.dir if self.dir else ctx.dir
            ctx.parent = self
            ctx.path.append(0)
            ret = self.ref.visit(ctx, func, isOffset=isOffset)
            ctx.path.pop()
            ctx.parent = None
            ctx.dir = old_dir
            return ret

    def refine_type(self, ctx, func, isOffset=False):
        old_parent = ctx.parent  # We must save the parent as callback is invoked at last
        old_dir = ctx.dir
        if self.ref:
            ctx.path.append(0)
            ctx.parent = self
            ctx.dir = self.dir if self.dir else ctx.dir
            typename = self.ref.typename
            ret = self.ref.refine_type(ctx, func, isOffset=isOffset)
            if isinstance(ret, Type):
                self.ref = ret
            elif isinstance(ret, list):
                # We split the original field into multiple fields
                fields = [each.toJson() for each in ret]
                self.ref = StructType(
                    {"fields": fields}, offset=0, typename=typename)
            else:
                raise Exception(f"unknown type {type(ret)}")
            ctx.path.pop()

        ctx.parent, ctx.dir = old_parent, old_dir
        return func(ctx, self)

    def resetName(self, prefix):
        super(PtrType, self).resetName(prefix)
        if self.ref:
            self.ref.resetName(prefix)

    def generateTemplate(self, syscall, dir, f, top=False):
        dir = self.dir if self.dir else dir
        typ, _ = self.ref.generateTemplate(syscall, dir, f, top=False)
        dir = PtrType.DirStr[dir]
        if self.optional:
            unionName = syscall.assignNewName("union")
            definition = f"{unionName} [\n"
            definition += f'    {syscall.assignNewName("field")}  const[0, intptr]\n'
            definition += f'    {syscall.assignNewName("field")}  {typ}\n'
            definition += "] [varlen]"
            f.write(definition + "\n")
            typ = f"ptr[{dir}, {unionName}]"
        else:
            typ = f"ptr[{dir}, {typ}]"

        return typ, self.getTypeName(syscall)

    def getData(self):
        if self.data:
            return int2bytes(self.data, 8)
        return int2bytes(0, 8)

    def repr(self, indent=0):
        ret = " "*indent + self.type + \
            f" {self.size} {PtrType.DirStr[self.dir]}"
        if self.optional:
            ret += " optional"
        ret += "\n"
        if self.ref:
            ret += self.ref.repr(indent+2)
        return ret

    def toJson(self):
        ret = super(PtrType, self).toJson()
        ret["optional"] = self.optional
        ret["dir"] = self.dir.value
        if self.ref:
            ret["ref"] = self.ref.toJson()
        return ret


class BufferType(Type):
    NAME = "buffer"

    def __init__(self, data, offset=0, typename=None):
        size = 0
        if "data" in data:
            self.data = data["data"]
            size = len(self.data)
        elif "size" in data:
            size = data["size"]
            self.data = [0] * size
        if size == 0:
            raise Exception()

        super().__init__(offset=offset, size=size, typename=typename)
        if "access" in data:
            self.access = data["access"]
        # Attributes for LenType
        self.path = None if "path" not in data else data["path"]
        self.bitSize = 8 if "bitSize" not in data else data["bitSize"]

    def equal(self, other):
        if other.type == "buffer":
            if self.size == other.size and self.path == other.path and self.bitSize == other.bitSize:
                return True
        return False

    def separable(self, size: int) -> bool:
        if self.NAME == "buffer":
            # derived class needs to call the default func
            return True
        return super().separable(size)

    def separate(self, size: int) -> List[Type]:
        ret = [self]
        rest = self.data[size:]
        self.data = self.data[:size]
        self.size = len(self.data)

        if len(rest) != 0:
            data = self.toJson()
            data["data"] = rest
            new_field = Type.construct(data, self.offset+self.size)
            ret.append(new_field)

        return ret

    def refine(self, other):
        # pointer can be optional
        if other.type == "ptr":
            if self.isNull():
                other.optional = True
            return other.copy()

        # Prefer more fine-grained type
        # if other.type == "struct":
        #     if self.path:
        #         # Len should be considered as a whole.
        #         # we probably only want one field
        #         data = other.fields[0].toJson()
        #         data["size"] = self.size
        #         data["data"] = int2bytes(int.from_bytes(
        #             data["data"], "little"), self.size)
        #         data["path"] = self.path
        #         data["bitSize"] = self.bitSize
        #         return Type.construct(data, self.offset)
        #     else:
        #         new_type = StructType({"fields": [self.toJson()]}, 0)
        #         return new_type.refine(other)

        if other.type in {"known", "resource", "struct", "const"}:
            return other
        # if other.type in ["const", "resource", "flag", "range", "string"]:
        #     if self.path:
        #         other.path = self.path
        #         other.bitSize = self.bitSize
        #     return other

        if other.type != "buffer":
            raise RuntimeError("refine buffer with type: %s" % other.type)

        # mark access flag
        # if not other.access:
        #     self.access = False

        # # Expand or split it to struct
        # # FIXME: should we reserve other attributes
        # if self.size < other.size:
        #     field1 = BufferType({"data": self.data})
        #     field2 = BufferType({"data": other.data[self.size:]}, self.size)
        #     return StructType({"fields": [field1.toJson(), field2.toJson()]})

        return self

    def simplify(self, model):
        if model.type == "ptr":
            if int.from_bytes(self.getData(), "little") != 0:
                raise SimplifyError("Cannot simplify buffer to pointer")
            return ConstantOffset(0, self.size, self.offset, self.typename)

        if model.type == "const" and int.from_bytes(self.getRawData(), "little") != model.getData():
            raise SimplifyError("Cannot simplify buffer to const")
        if model.type == "range" and not model.min <= int.from_bytes(self.getRawData(), "little") <= model.max:
            raise SimplifyError("Cannot simplify buffer to range")
        if model.type == "flag" and int.from_bytes(self.getRawData(), "little") not in model.values:
            raise SimplifyError("Cannot simplify buffer to flag")

        if model.type == "struct":
            new_type = StructType({"fields": [self.toJson()]}, self.offset)
            return new_type.simplify(model)
        if model.type != "buffer":
            # Be consistent with more fine-grained type
            ret = model.toJson()
            ret["data"] = self.data[:model.size]
            return Type.construct(ret, self.offset)

        self.data = self.data[:model.size]
        self.size = len(self.data)
        return self

    def generateTemplate(self, syscall, dir, f, top=False):
        name = self.getTypeName(syscall)
        if top and self.size == 8:
            return "intptr", name

        if self.size == 0:
            return "array[int8]", name
        if options.zero_unused and not self.access:
            if self.size in [1, 2, 4, 8]:
                return "const[0, %s]" % Size2Type(self.size), name
            return "array[const[0, int8], %d]" % self.size, name
        return Size2Type(self.size), name

    def isNull(self):
        if len(self.data) != 8:
            return False
        for each in self.data:
            if each != 0:
                return False
        return True

    def getData(self):
        '''
        This function can be overrided as opposed to getRawData
        '''
        return self.data

    def getRawData(self):
        return self.data

    def repr(self, indent=0):
        ret = " "*indent + self.type + ("+" if self.access else "-") + \
            " " + str(self.size) + " "
        data = self.getData()
        if isinstance(data, list):
            if len(data) <= 128:
                ret += str(self.getData())
            else:
                def int2str(x): return str(x)
                ret += "["
                ret += (", ".join(map(int2str, data[:16])) +
                        " ... " + ", ".join(map(int2str, data[-16:])))
                ret += "]"
        else:
            ret += str(data)
        if self.path:
            ret += " Sizeof %s with bitSize %d" % (
                str(self.path), self.bitSize)
        ret += "\n"
        return ret

    def toJson(self):
        ret = super(BufferType, self).toJson()
        if self.size <= 64:
            ret["data"] = self.data
        ret["access"] = self.access
        if self.path:
            ret["path"] = self.path
            ret["bitSize"] = self.bitSize  # if hasattr(self, "bitSize") else 8
        return ret


class LenType(Type):
    NAME = "len"

    '''
    LenType is only used when generating templates, it is not persistent, meaning
    no field is stored as LenType. Instead, we use other types with attribute 'path'.
    '''

    def __init__(self, data, offset=0, typename=None):
        super().__init__(offset=offset, size=data["size"], typename=typename)
        self.lenField = data["lenField"]
        self.bitSize = data["bitSize"]
        self.max = data["max"]
        self.min = data["min"]
        self.path = None if "path" not in data else data["path"]

    def equal(self, other):
        if isinstance(other, LenType):
            if self.lenField == other.lenField and self.bitSize == other.bitSize:
                return True
        return False

    def generateTemplate(self, syscall, dir, f, top=False):
        prefix = "len"
        if self.bitSize in [16, 32, 64]:
            prefix = "bytesize%d" % (self.bitSize//8)
        elif self.bitSize == 1:
            prefix = "bitsize"
        # Note: For bitSize of 8 and others, we could directly use lenType because we would convert struct
        # into array.
        # elif self.bitSize != 8:
        #     raise Exception("bitSize of %d" % self.bitSize)

        # if self.max == 0:
        #     return "const[0]" if top else "const[0, %s]" % Size2Type(self.size), self.getTypeName(syscall)

        if top:
            return "%s[%s]" % (prefix, self.lenField), self.getTypeName(syscall)
        return "%s[%s, %s]" % (prefix, self.lenField, Size2Type(self.size)), self.getTypeName(syscall)

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size) + " "
        ret += " Sizeof %s with bitSize %d [%d:%d]" % (
            str(self.path), self.bitSize, self.min, self.max)
        ret += "\n"
        return ret

    def toJson(self):
        ret = super(LenType, self).toJson()
        ret["lenField"] = self.lenField
        ret["bitSize"] = self.bitSize
        ret["max"] = self.max
        ret["min"] = self.min
        return ret


class ResourceType(BufferType):
    NAME = "resource"

    def __init__(self, data, offset=0, typename=None):
        super().__init__(data, offset, typename=typename)
        self.name = data["name"] if "name" in data else None
        self.parent = data["parent"] if "parent" in data else None

    def equal(self, other):
        if isinstance(other, ResourceType):
            if self.name == other.name and self.parent == other.parent:
                return True
        return False

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size) + \
            " " + (" " if self.name is None else self.name) + "\n"
        return ret

    def refine(self, other):
        return self

    def toJson(self):
        ret = super(ResourceType, self).toJson()
        if self.name:
            ret["name"] = self.name
        if self.parent:
            ret["parent"] = self.parent
        return ret

    def generateTemplate(self, syscall, dir, f, top=False):
        return self.name, self.getTypeName(syscall)


class ConstType(BufferType):
    NAME = "const"

    def __init__(self, data, offset=0, typename=None):
        super().__init__(data, offset, typename=typename)

    def equal(self, other):
        if isinstance(other, ConstType):
            if self.size == other.size and self.getData() == other.getData():
                return True
        return False

    def generateTemplate(self, syscall, dir, f, top=False):
        if self.size <= 8:
            if top:
                return "const[%d]" % self.getData(), self.getTypeName(syscall)
            return "const[%d, %s]" % (self.getData(), Size2Type(self.size)), self.getTypeName(syscall)
        raise Exception("Not implemented yet")

    def refine(self, other: Type):
        if other.type == "resource":
            return other

        if other.type == "const":
            if self.getData() != other.getData():  # Multiple constant values
                res = self.toJson()
                res["type"] = "flag"
                res["values"] = [self.getData(), other.getData()]
                return FlagType(res, offset=self.offset)
        elif other.type == "flag":
            return other.copy().refine(self)

        return self

    def separable(self, size: int) -> bool:
        return True

    def getData(self):
        raw_data = BufferType.getData(self)
        return int.from_bytes(raw_data, "little")

    def toJson(self):
        return super(ConstType, self).toJson()


class FlagType(BufferType):
    NAME = "flag"

    def __init__(self, data, offset=0, typename=None):
        super(FlagType, self).__init__(data, offset, typename=typename)
        self.values = set() if "values" not in data else set(data["values"])

    def equal(self, other):
        if other.type == "flag":
            if self.size == other.size and self.values == other.values:
                return True
        return False

    def toJson(self):
        ret = super(FlagType, self).toJson()
        ret["values"] = list(self.values)
        return ret

    def refine(self, other):
        if other.type == "resource":
            return other
        elif other.type == "const":
            self.values.add(other.getData())
        elif other.type == "flag":
            self.values = self.values.union(other.values)
        return self

    def generateTemplate(self, syscall: SyscallNamespace, dir, f, top=False):
        typename = self.getTypeName(syscall)
        unique_name = (
            typename if syscall.is_unique(typename)
            else syscall.assignNewName(self.type)
        )
        out = "%s = %s" % (unique_name, ", ".join([str(x) for x in self.values]))
        f.write(out + "\n")
        if top:
            return f"flags[{unique_name}]", typename
        return "flags[%s, %s]" % (unique_name, Size2Type(self.size)), typename

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + \
            str(self.size) + " " + str(list(self.values))
        if self.path:
            ret += " Sizeof %s" % str(self.path)
        ret += "\n"
        return ret


class StringType(FlagType):
    NAME = "string"

    def __init__(self, data, offset=0, typename=None):
        super(StringType, self).__init__(data, offset, typename=typename)
        self.fixLen = 0 if "fixLen" not in data else data["fixLen"]

    def equal(self, other):
        if other.type == "string":
            return self.values == other.values
        return False

    def refine(self, other):
        # TODO
        return self

    def toJson(self):
        ret = super(StringType, self).toJson()
        ret["fixLen"] = self.fixLen if hasattr(self, "fixLen") else 0
        return ret

    def generateTemplate(self, syscall, dir, f, top=False):
        typename = self.getTypeName(syscall)
        if len(self.values) > 1:
            out = "%s = %s" % (typename, ", ".join(
                ["\"%s\"" % x.strip('\x00') for x in self.values]))
            f.write(out + "\n")
            if self.fixLen:
                return "string[%s, %d]" % (typename, self.fixLen), typename
            return "string[%s]" % typename, typename
        elif len(self.values) == 1:
            if self.fixLen:
                return "string[\"%s\", %d]" % (next(iter(self.values)), self.fixLen), typename
            return "string[\"%s\"]" % next(iter(self.values)), typename

        if self.fixLen:
            return "array[int8, %d]" % self.fixLen, typename
        return "string", typename


class RangeType(BufferType):
    NAME = "range"
    SPECIAL_INTS = {0x7fffffff, 0x80000000, 0x7fffffffffffffff, 0x8000000000000000}

    def __init__(self, data, offset=0, typename=None):
        super().__init__(data, offset, typename=typename)
        self.min = data["min"]
        self.max = data["max"]
        self.stride = data["stride"]

    def equal(self, other):
        if isinstance(other, RangeType):
            if (
                self.size == other.size and
                self.min == other.min and
                self.max == other.max and
                self.stride == other.stride
            ):
                return True
        return False

    def toJson(self):
        ret = super(RangeType, self).toJson()
        ret["min"] = self.min
        ret["max"] = self.max
        ret["stride"] = self.stride
        return ret

    def refine(self, other):
        if other.type == "resource":
            return other
        return self

    def generateTemplate(self, syscall, dir, f, top=False):
        ret = ""
        if self.min == 0 and self.max == ((1 << self.size*8)-1):
            ret = "%s" % Size2Type(self.size)
        elif self.size in [3, 5, 7]:
            # FIXME: range 3 --> array[int8, 3][0:12582911]
            ret += Size2Type(self.size)
        else:
            ret += "%s[%d:%d" % (Size2Type(self.size), self.min,
                                 min(self.max, self.min+(1 << 64)-(1 << 32)))
            if self.stride == 1:
                ret += "]"
            else:
                ret += (", %d]" % self.stride)
        return ret, self.getTypeName(syscall)

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size)
        ret += " [%d:%d, %d]" % (self.min, self.max, self.stride)
        if self.path:
            ret += " Sizeof %s with bitSize %d" % (
                str(self.path), self.bitSize)
        ret += "\n"
        return ret


class StructType(Type):
    NAME = "struct"

    def __init__(self, data, offset=0, typename=None):
        super().__init__(offset=offset, typename=typename)
        self.fields: List[Type] = []
        self.isArray = False if "isArray" not in data else data["isArray"]
        for each in data["fields"]:
            struct = Type.construct(each, isPtr=True)
            struct.offset = offset
            self.fields.append(struct)
            offset += struct.size
            self.size += struct.size

    def equal(self, other):
        if other.type == "struct":
            if len(self.fields) == len(other.fields):
                for i in range(len(self.fields)):
                    if not self.fields[i].equal(other.fields[i]):
                        return False
                return True
        return False

    def replace(self, index, replacements: List[Type]):
        """replace subfields starting from the index. Make sure we do not
        need to split any fields"""
        totalSize = sum(each.size for each in replacements)
        for field in self.fields[index:]:
            totalSize -= field.size
            if totalSize <= 0:
                break

        if totalSize:
            raise RuntimeError("unequal size for replacement")

        # fix offsets first
        offset = self.fields[index].offset
        for each in replacements:
            each.offset = offset
            offset += each.size

        totalSize = sum(each.size for each in replacements)
        while totalSize:
            totalSize -= self.fields[index].size
            self.fields.pop(index)

        for i, each in enumerate(replacements):
            self.fields.insert(index+i, each)

    def split(self, index, size):
        field = self.fields[index]
        if not field.separable(size):
            raise Exception(f"split non-separable type {field.type}")

        new_fields = field.separate(size)
        self.fields = self.fields[:index] + new_fields + self.fields[index+1:]

    def merge(self, index, size):
        while True:
            if self.fields[index].size >= size:
                return
            if index+1 >= len(self.fields):
                # raise Exception("no field to be merged")
                left = size - self.fields[index].size
                self.fields.append(BufferType({"size": left}, offset=self.size))
                self.size += left

            data = self.fields[index].toJson()
            data["data"] = (
                (self.fields[index].getRawData() or [0]*self.fields[index].size) +
                (self.fields[index+1].getRawData() or [0]*self.fields[index+1].size)
            )
            data["type"] = "buffer"
            new_field = BufferType(data, self.fields[index].offset)
            self.fields[index] = new_field
            del self.fields[index+1]

    def refine(self, other: Type):
        if other.type == "buffer":
            other = StructType({"fields": [other.toJson()]}, other.offset)
        elif other.type != "struct":
            raise Exception("refine struct with %s" % other.type)

        fields = []
        l = r = 0
        while l < len(self.fields) and r < len(other.fields):
            ltype, rtype = self.fields[l], other.fields[r]
            if ltype.size == rtype.size:
                fields.append(ltype.refine(rtype))
            else:
                if ltype.size > rtype.size:
                    if ltype.separable(rtype.size):
                        self.split(l, rtype.size)
                    else:
                        other.merge(r, ltype.size)
                else:
                    if rtype.separable(ltype.size):
                        other.split(r, ltype.size)
                    else:
                        self.merge(l, rtype.size)
                continue
            l += 1
            r += 1

        fields += self.fields[l:]

        self.fields = fields
        self.size = fields[-1].offset + fields[-1].size
        return self

    def simplify(self, model):
        others = []
        if model.type != "struct":
            others.append(model)
        else:
            others = model.fields

        fields = []
        l = r = 0
        while l < len(self.fields) and r < len(others):
            ltype, rtype = self.fields[l], others[r]
            if ltype.size == rtype.size:
                fields.append(ltype.simplify(rtype))
            else:
                if ltype.size > rtype.size:
                    self.split(l, rtype.size)
                else:
                    if l == len(self.fields) - 1:
                        # if it is the last one, that's okay.
                        l += 1
                        r += 1
                        fields.append(ltype.simplify(rtype))
                        break

                    print(ltype.repr())
                    print(rtype.repr())
                    raise SimplifyError("ltype should has larger size")
                continue
            l += 1
            r += 1

        # Current testcase is shorter than our model, expand it but mark the rest as inaccessible.
        for i in range(r, len(others)):
            each = others[i].toJson()
            each["access"] = False
            fields.append(Type.construct(each))

        self.fields = fields
        self.size = fields[-1].offset + fields[-1].size
        if model.type != "struct":
            if len(self.fields) != 1:
                raise SimplifyError(
                    "Error when simplifying structure to other type")
            return self.fields[0]

        return self

    def visit(self, ctx, func, isOffset=False):
        if func(ctx, self):
            return True  # stop
        offset = 0
        i = 0
        while i < len(self.fields):
            if isOffset:
                ctx.path.append(offset)
            else:
                ctx.path.append(i)
            ctx.parent = self
            ret = self.fields[i].visit(ctx, func, isOffset=isOffset)
            ctx.path.pop()
            ctx.parent = None
            if ret:
                return True  # stop

            offset += self.fields[i].size
            i += 1

    def refine_type(self, ctx, func, isOffset=False):
        old_parent = ctx.parent
        i, fields = 0, []
        while i < len(self.fields):
            # we may change fields in func
            if isOffset:
                ctx.path.append(self.fields[i].offset)
            else:
                ctx.path.append(i)
            ctx.parent = self
            ret = self.fields[i].refine_type(ctx, func, isOffset=isOffset)
            if isinstance(ret, list):
                for field in ret:
                    fields.append(field)
            elif isinstance(ret, Type):
                fields.append(ret)
            else:
                raise Exception("unknown type %s" % type(ret))
            ctx.path.pop()
            i += 1

        offset = 0
        for field in fields:
            field.offset = offset
            offset += field.size

        self.fields = fields
        self.size = offset
        ctx.parent = old_parent
        return func(ctx, self)

    def resetName(self, prefix):
        super(StructType, self).resetName(prefix)
        for field in self.fields:
            field.resetName(prefix)

    def generateTemplate(self, syscall, dir, f, top=False):
        typename = self.getTypeName(syscall)
        definition = "%s {\n" % typename
        for i in range(len(self.fields)):
            typ, name = self.fields[i].generateTemplate(syscall, dir, f)
            definition += "    %s  %s\n" % (name, typ)
        definition += "} [packed]"
        f.write(definition + "\n")
        return typename, typename

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size) + "\n"
        for each in self.fields:
            ret += each.repr(indent+2)
        return ret

    def toJson(self):
        ret = super(StructType, self).toJson()
        ret["fields"] = [each.toJson() for each in self.fields]
        ret["isArray"] = self.isArray if hasattr(self, "isArray") else False
        return ret


class ArrayType(Type):
    '''ArrayType is only used when generating templates'''
    NAME = "array"

    def __init__(self, data, offset=0, typename=None):
        super().__init__(offset=offset, size=data["minLen"], typename=typename)
        self.ref = Type.construct(data["field"], 0)
        self.minLen = data["minLen"]
        self.maxLen = data["maxLen"]

    def equal(self, other):
        if isinstance(other, ArrayType):
            return self.ref.equal(other.ref)
        return False

    def generateTemplate(self, syscall, dir, f, top=False):
        subtype, _ = self.ref.generateTemplate(syscall, dir, f)
        minLen, maxLen = min(self.minLen, 4096), min(self.maxLen, 4096)
        if maxLen != 0:
            if minLen != maxLen:
                return "array[%s, %d:%d]" % (subtype, minLen, maxLen), self.getTypeName(syscall)
            return "array[%s, %d]" % (subtype, maxLen), self.getTypeName(syscall)
        return "array[%s]" % subtype, self.getTypeName(syscall)

    def toJson(self):
        ret = super(ArrayType, self).toJson()
        ret["field"] = self.ref.toJson()
        ret["minLen"] = self.minLen
        ret["maxLen"] = self.maxLen
        return ret

    def repr(self, indent=0):
        ret = " "*indent + self.type + " " + str(self.size)
        ret += " [%d:%d]\n" % (self.minLen, self.maxLen)
        return ret


class KnownType(Type):
    """Pre-defined type like sockaddr_in6"""
    NAME = "known"

    def __init__(self, data, offset=0, typename=None):
        super().__init__(offset, data['size'], typename)

        self.name = data["name"]

    def equal(self, other: "Type"):
        if isinstance(other, KnownType) and self.name == other.name:
            return True
        return False

    def repr(self, indent=0):
        return " "*indent + f"{self.name} {self.size}\n"

    def toJson(self):
        ret = super().toJson()
        ret["name"] = self.name
        return ret

    def generateTemplate(self, syscall: SyscallNamespace, dir: "PtrDir", f, top=False):
        return self.name, self.getTypeName(syscall)

    def refine(self, other: "Type") -> "Type":
        return self

# Register all subclass of Type
for k, v in globals().copy().items():
    try:
        if issubclass(v, Type) and v != Type:
            Type.register_type(v.NAME, v)
    except TypeError:
        pass

# load structures of all pre-defined types
ALL_KNOWN_TYPES: Dict[str, Dict[str, List[StructType]]] = {}
cur_dir = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(cur_dir, "known.json"), "r") as fp:
    data = json.load(fp)
    for each in data:
        for t in each["targets"]:
            if t not in ALL_KNOWN_TYPES:
                ALL_KNOWN_TYPES[t] = defaultdict(list)
            ALL_KNOWN_TYPES[t][each["name"]].append(Type.construct(each["type"]))
