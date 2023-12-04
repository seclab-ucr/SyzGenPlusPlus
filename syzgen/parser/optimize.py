
from syzgen.config import Options
from syzgen.models import MAX_MEMORY_SIZE
from syzgen.parser.types import ALL_TYPES, KnownType, LenType
import logging
import json
from typing import Dict, List, Optional, Tuple
from syzgen.parser.syscalls import Syscall

from syzgen.parser.types import ConstType, Context, FlagType, RangeType, ResourceType, StringType, StructType, Type, PtrType, BufferType, Constant

logger = logging.getLogger(__name__)
options = Options()

class MergeKnownTypeError(Exception):
    pass

class Path(object):
    def __init__(self):
        self.path = []
        self.index = -1
        self.type = None

    def append(self, val):
        self.path.append(val)

    def pop(self):
        self.path.pop()

    def combine(self, path):
        if self.index != path.index:
            return None
        if not self.match(path.path):
            return None

        if self.type.offset+self.type.size == path.type.offset:
            new_path = Path()
            new_path.type = ResourceType(
                {"data": self.type.getData() + path.type.getData()}, self.type.offset)
            new_path.path = list(self.path)
            new_path.index = self.index
            return new_path
        return None

    def overlap(self, path):
        # Path is superset of self
        if self.index != path.index:
            return False
        if not self.match(path.path):
            return False

        if path.type.offset <= self.type.offset and \
                self.type.offset+self.type.size <= path.type.offset+path.type.size:
            return True
        return False

    def match(self, path):
        if isinstance(path, list):
            if len(self.path) != len(path):
                return False
            for i in range(len(self.path)):
                if self.path[i] != path[i]:
                    return False
            return True

        if self.index != path.index:
            return False
        if len(self.path) != len(path.path):
            return False
        for i in range(len(self.path)):
            if self.path[i] != path.path[i]:
                return False
        if self.type.offset != path.type.offset:
            return False
        if self.type.size != path.type.size:
            return False
        return True

    def startswith(self, path):
        if isinstance(path, list):
            if len(self.path) < len(path):
                return False
            for i in range(len(path)):
                if self.path[i] != path[i]:
                    return False
            return True

        return False

    def equal(self, path):
        if not self.match(path):
            return False
        return self.type.getData() == path.type.getData()

    def getData(self):
        return self.type.getData()

    def repr(self):
        ret = "Path:\n"
        ret += "  path: " + str(self.path) + "\n"
        ret += "  index: " + str(self.index) + "\n"
        if self.type:
            ret += self.type.repr(indent=2)
        return ret

    def toJson(self):
        ret = {
            "path": self.path,
            "index": self.index
        }
        if self.type:
            ret["type"] = self.type.toJson()
        return ret

    @staticmethod
    def create(data):
        path = Path()
        path.index = data["index"]
        path.path = data["path"]
        if "type" in data:
            path.type = ResourceType(data["type"], data["type"]["offset"])
        return path

    def __hash__(self):
        return hash((str(self.path), self.index, self.type.offset, self.type.size))

    def __eq__(self, other):
        return self.match(other)


class Dependence(object):
    def __init__(self, outPath, inPath):
        self.outPath = outPath
        self.inPath = inPath

    def contained(self, dependences):
        for dependence in dependences:
            if self.match(dependence):
                return dependence
        return None

    def overlap(self, dependence):
        if not self.outPath.overlap(dependence.outPath):
            return False
        if not self.inPath.overlap(dependence.inPath):
            return False
        return True

    def match(self, dependence):
        if self.outPath.match(dependence.outPath) and \
                self.inPath.match(dependence.inPath):
            return True
        return False

    def combine(self, dependence):
        outP = self.outPath.combine(dependence.outPath)
        if outP is None:
            return None
        inP = self.inPath.combine(dependence.inPath)
        if inP is None:
            return None
        return Dependence(outP, inP)

    def repr(self):
        return "Out " + self.outPath.repr() + "\nIn " + self.inPath.repr() + "\n"

    def __hash__(self):
        return hash(self.outPath) + hash(self.inPath)

    def __eq__(self, other):
        return self.match(other)

def degrade_type(typ: Type) -> Type:
    if isinstance(typ, RangeType):
        if typ.min == 0 and typ.max == (1<<typ.size*8)-1 and typ.stride == 1:
            data = typ.toJson()
            data["type"] = "buffer"
            return Type.construct(data)
    return typ


class MergeRule:
    MESSAGE = ""

    def __init__(self, *args) -> None:
        for each in args:
            assert issubclass(each, Type)
        assert len(args) <= 2
        self._types = args

    def apply(self, this: Type, other: Type, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        """return (succeed, refined type, # of changes, message)"""
        raise NotImplementedError()

    def run(self, this: Type, other: Type, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        if len(self._types) == 2:
            # must be exactly the same type
            if type(this) is self._types[0] and type(other) is self._types[1]:
                return self.apply(this, other, enforce=enforce)
            elif type(this) is self._types[1] and type(other) is self._types[0]:
                return self.apply(other, this, enforce=enforce)
        elif len(self._types) == 1:
            if type(this) is self._types[0] and type(other) is self._types[0]:
                return self.apply(this, other, enforce=enforce)
        else:
            return self.apply(this, other, enforce=enforce)
        return None, 0, ""

class Merge_Ptr_Const(MergeRule):
    MESSAGE = "merge ptr and null"

    def __init__(self) -> None:
        super().__init__(PtrType, ConstType)

    def apply(self, ptr: PtrType, const: ConstType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        # Pointers can have a special value 0.
        if const.getData() == 0 or enforce:
            return ptr, 1, self.MESSAGE
        return None, 0, ""


class Merge_Const_Flag(MergeRule):
    MESSAGE = "merge const and flag"

    def __init__(self) -> None:
        super().__init__(ConstType, FlagType)

    def apply(self, const: ConstType, flag: FlagType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        flag.values.add(const.getData())
        return flag, 1, self.MESSAGE


class Merge_Flag_Range(MergeRule):
    MESSAGE = "merge flag and range"

    def __init__(self) -> None:
        super().__init__(FlagType, RangeType)

    def apply(self, flag: FlagType, range: RangeType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        # flag is included in the range
        if all([range.min <= val <= range.max for val in flag.values]):
            return range, 1, self.MESSAGE
        # flag expands range, ie, flags follows range
        cmin, cmax = range.min, range.max
        while cmax+1 in flag.values:
            cmax += 1
        while cmin-1 in flag.values:
            cmin -= 1
        if all([cmin <= val <= cmax for val in flag.values]):
            range.min, range.max = cmin, cmax
            return range, 1, self.MESSAGE
        if enforce:
            range.min = min(range.min, *flag.values)
            range.max = max(range.max, *flag.values)
            return range, 1, self.MESSAGE
        return None, 0, ""


class Merge_Const_Range(MergeRule):
    MESSAGE = "merge const and range"

    def __init__(self) -> None:
        super().__init__(ConstType, RangeType)

    def apply(self, const: ConstType, range: RangeType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        if range.min <= const.getData() <= range.max:
            return range, 0, self.MESSAGE
        if const.getData() == range.min-1:
            range.min -= 1
            return range, 1, self.MESSAGE
        if const.getData() == range.max+1:
            range.max += 1
            return range, 1, self.MESSAGE
        if enforce:
            range.min = min(range.min, const.getData())
            range.max = max(range.max, const.getData())
            return range, 1, self.MESSAGE
        return None, 0, ""


class Merge_Ptr_Buffer(MergeRule):
    MESSAGE = "merge pointer and non-accessed buffer"

    def __init__(self) -> None:
        super().__init__(PtrType, BufferType)

    def apply(self, ptr: PtrType, buf: BufferType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        """similar to MergeConstFlag"""
        if not buf.access or enforce:
            return ptr, 1, self.MESSAGE
        return None, 0, ""


class Merge_Ptr_Range(MergeRule):
    MESSAGE = "merge pointer and range"

    def __init__(self) -> None:
        super().__init__(PtrType, RangeType)

    def apply(self, this: PtrType, other: RangeType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        return this, 0, self.MESSAGE


class Merge_Range_Buffer(MergeRule):
    MESSAGE = "merge range and buffer"

    def __init__(self) -> None:
        super().__init__(RangeType, BufferType)

    def apply(self, this: RangeType, other: BufferType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        if (
            this.min in RangeType.SPECIAL_INTS or
            this.max in RangeType.SPECIAL_INTS
        ):
            return None, 0, ""

        return other, 1, self.MESSAGE


class Merge_Flag_Buffer(MergeRule):
    MESSAGE = "merge flag and buffer"

    def __init__(self) -> None:
        super().__init__(FlagType, BufferType)

    def apply(self, this: FlagType, other: BufferType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        # if enforce:
        return other, 1, self.MESSAGE
        # return None, 0, ""


class Merge_Const_Buffer(MergeRule):
    MESSAGE = "merge const and buffer"

    def __init__(self) -> None:
        super().__init__(ConstType, BufferType)

    def apply(self, this: ConstType, other: BufferType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        # Fuzzer may easily generate a const of zero for buffer type
        # if enforce or this.getData() == 0:
        # FIXME: do we really read this const?
        return other, 0, self.MESSAGE
        # return None, 0, ""


class Merge_Known_Buffer(MergeRule):
    MESSAGE = "merge known type and buffer"

    def __init__(self) -> None:
        super().__init__(KnownType, BufferType)

    def apply(self, this: KnownType, other: BufferType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        return this, 0, self.MESSAGE


class Merge_Struct_Buffer(MergeRule):
    MESSAGE = "merge struct and buffer"

    def __init__(self) -> None:
        super().__init__(StructType, BufferType)

    def apply(self, this: StructType, other: BufferType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        return this, 0, self.MESSAGE


class Merge_Struct_Const(MergeRule):
    MESSAGE = "merge struct and const"

    def __init__(self) -> None:
        super().__init__(StructType, ConstType)

    def apply(self, this: StructType, other: Type, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        other = StructType({"fields": [other.toJson()]}, other.offset)
        return merge_fields(this, other, enforce)


class Merge_Struct_Range(MergeRule):
    MESSAGE = "merge struct and range"

    def __init__(self) -> None:
        super().__init__(StructType, RangeType)

    def apply(self, this: StructType, other: RangeType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        if enforce:
            # range is more safe to use (sound)
            return other, 0, self.MESSAGE
        return None, 0, ""


class Merge_Ptr(MergeRule):
    def apply(self, this: PtrType, other: PtrType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        ref, changes, msg = merge_fields(this.ref, other.ref, enforce=enforce)
        if ref:
            this.ref = ref
            return this, changes, msg
        return None, 0, ""


class Merge_Struct(MergeRule):
    MESSAGE = "merge structs"

    def apply(self, this: StructType, other: StructType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        fields, changes, msg = [], 0, self.MESSAGE
        l = r = 0
        while l < len(this.fields) and r < len(other.fields):
            ltype, rtype = this.fields[l], other.fields[r]
            # print(ltype.repr(), rtype.repr(), changes)
            if ltype.size == rtype.size:
                res, c, msg = merge_fields(ltype, rtype, enforce=enforce)
                if res is None:
                    return None, 0, msg
                changes += c
                fields.append(res)
            else:
                # always choose the smaller one
                if ltype.size > rtype.size:
                    if ltype.separable(rtype.size):
                        this.split(l, rtype.size)
                    elif not enforce:
                        return None, 0, "fields have different sizes %d and %d" % (ltype.size, rtype.size)
                    else:
                        other.merge(r, ltype.size)
                        changes += 1
                else:
                    if rtype.separable(ltype.size):
                        other.split(r, ltype.size)
                    elif not enforce:
                        return None, 0, "fields have different sizes %d and %d" % (ltype.size, rtype.size)
                    else:
                        this.merge(l, rtype.size)
                        changes += 1
                continue
            l += 1
            r += 1

        fields += this.fields[l:]
        fields += other.fields[r:]
        this.fields = fields
        this.size = fields[-1].offset + fields[-1].size
        return this, changes, msg


class Merge_String(MergeRule):
    MESSAGE = "merge strings"

    def apply(self, this: StringType, other: StringType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        if this.values and other.values:
            this.values.update(other.values)
        elif this.values or other.values:
            return None, 0, "allow string of variable size"
        return this, 0, self.MESSAGE


class Merge_Const(MergeRule):
    MESSAGE = "merge consts"

    def apply(self, this: ConstType, other: ConstType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        if this.getData() != other.getData():
            # merge two consts to flag
            data = this.toJson()
            data["values"] = [this.getData(), other.getData()]
            data["type"] = "flag"
            return Type.construct(data), 1, self.MESSAGE
        return this, 0, ""


class Merge_Range(MergeRule):
    def _merge_range(self, typ1: RangeType, typ2: RangeType) -> None:
        typ1.min = min(typ1.min, typ2.min)
        typ1.max = max(typ1.max, typ2.max)

    def apply(self, typ1: RangeType, typ2: RangeType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        if typ1.min != typ2.min or typ1.max != typ2.max:
            if enforce:
                self._merge_range(typ1, typ2)

            if typ1.max + 1 == typ2.min or typ2.max + 1 == typ1.min:
                boundary = max(typ1.min, typ2.min)
                if boundary in RangeType.SPECIAL_INTS:
                    # do not merge special boundaries that separate positive numbers from negetive
                    return None, 0, "merge ranges with special boundaries"

            # merge consecutive ranges
            if (
                typ1.min <= typ2.max+1 and
                typ2.min <= typ1.max+1 and
                typ1.stride == typ2.stride
            ):
                self._merge_range(typ1, typ2)
                return typ1, 1, "merge ranges"
            return None, 0, "merge ranges failed"
        return typ1, 0, ""


class Merge_Flag(MergeRule):
    MESSAGE = "merge flags"

    def apply(self, this: FlagType, other: FlagType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        if this.values != other.values:
            this.values.update(other.values)
            return this, 1, self.MESSAGE
        return this, 0, ""


class Merge_Known(MergeRule):
    MESSAGE = "merge known types"

    def apply(self, this: KnownType, other: KnownType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        if this.name != other.name:
            if enforce:
                raise MergeKnownTypeError()
            return None, 0, "merge known types failed"
        return this, 0, ""


class Merge_Buffer(MergeRule):
    MESSAGE = "merge buffers"

    def apply(self, this: BufferType, other: BufferType, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
        ret = this if this.size >= other.size else other
        if this.path:
            ret.path, ret.bitSize = this.path, this.bitSize
        elif other.path:
            ret.path, ret.bitSize = other.path, other.bitSize
        return ret, 0, ""


def merge_fields(typ1: Type, typ2: Type, enforce: bool = False) -> Tuple[Optional[Type], int, str]:
    changes, msg = 0, ""
    if typ1.type != typ2.type:
        typ = None
        if (typ1.type, typ2.type) in MERGE_DIFFERENT_TYPES_RULES:
            rule = MERGE_DIFFERENT_TYPES_RULES[(typ1.type, typ2.type)]
            typ, changes, msg = rule.run(typ1, typ2, enforce=enforce)
        elif (typ2.type, typ1.type) in MERGE_DIFFERENT_TYPES_RULES:
            rule = MERGE_DIFFERENT_TYPES_RULES[(typ2.type, typ1.type)]
            typ, changes, msg = rule.run(typ2, typ1, enforce=enforce)

        if typ is not None:
            typ = degrade_type(typ)
            if typ1.path and typ1.path == typ2.path:
                # Special case where we can merge len fields without counting it as a change.
                return typ, 0, msg
            return typ, changes, msg

        if enforce:
            raise NotImplementedError(
                "unsupported merge between %s and %s", typ1.type, typ2.type)
        return None, 0, "different types between %s and %s" % (typ1.type, typ2.type)
    else:
        if typ1.type in MERGE_SAME_TYPE_RULES:
            typ1, changes, msg = MERGE_SAME_TYPE_RULES[typ1.type].apply(
                typ1, typ2, enforce=enforce)
            if typ1 is None:
                if enforce:
                    raise NotImplementedError("failed to merge %s", typ2.type)
                return None, 0, msg
        elif typ1.size != typ2.size:
            if enforce:
                raise NotImplementedError("different size of %s", typ1.type)
            return None, 0, "different size of %s" % typ1.type
        elif not typ1.equal(typ2):
            raise NotImplementedError("unsupported type of %s", typ1.type)
        typ1.access = typ1.access or typ2.access
        return degrade_type(typ1), changes, msg


def findLenByOffset(interface, path):
    def visit(ctx, typ):
        if isinstance(typ, (BufferType, LenType)) and typ.path == path:
            ctx.ret = (ctx.parent, typ)
            return True

    ctx = Context()
    ctx.ret = (None, None)
    interface.visit(ctx, visit)
    return ctx.ret


def findFieldByOffset(interface, path) -> Optional[Type]:
    def visit(ctx, typ):
        if path == ctx.path: # and typ.type == "ptr":
            ctx.ret = typ
            return True

    ctx = Context()
    ctx.ret = None
    interface.visit(ctx, visit, isOffset=True)
    return ctx.ret


def reduce_struct(syscall):
    """ For structure with only one field, we can reduce the struct to its field.
    """
    def simpify(ctx, typ):
        if typ.type == "struct" and len(typ.fields) == 1:
            typ.fields[0].typename = typ.typename
            return typ.fields[0]
        return typ

    ctx = Context()
    syscall.refine_type(ctx, simpify)


def reduce_buffer(syscall, finalize: bool):
    def simpify(_, typ):
        if typ.type == "buffer" and typ.size == MAX_MEMORY_SIZE:
            typ.size = 0
            typ.data = []
        return typ

    if finalize:
        syscall.refine_type(Context(), simpify)


def refine_buffer(syscall):
    '''
    We initially assign a large byte array for any void pointer. After symbolic execution,
    we may refine the type and now let's eliminate irrelevant part from the structure based
    on the 'access' arritute that denotes whether we have accessed some particular field
    during the course.
    '''
    def refine(ctx, typ):
        if ctx.arg not in ["input", "inputStruct"]:
            return typ

        if typ.type == "struct":
            for i in range(len(typ.fields)-1, -1, -1):
                if typ.fields[i].access:
                    # the last accessible field
                    typ.fields = typ.fields[:i+1]
                    typ.size = typ.fields[i].offset + typ.fields[i].size
                    if len(typ.fields) == 1:
                        # reduce struct type if we only have field
                        typ.fields[0].typename = typ.typename
                        return typ.fields[0]
                    return typ

            # all are inaccessible, pick the first one
            typ.fields[0].access = True
            return typ.fields[0]
        elif typ.type == "ptr":
            # Note ref is refined before the ptr itself.
            # Ref only has one child which must be accessed.
            if typ.ref and not typ.ref.access:
                typ.ref.access = True

        return typ

    ctx = Context()
    syscall.refine_type(ctx, refine)


def fix_buffer_access(syscall: Syscall) -> None:
    """Unaccessed field might be mistakenly converted into constant zero to reduce
    the input space. If we know the correct size of a struct/buffer, we should mark
    the entire field as accessed."""
    def fix_access(ctx: Context, typ: Type):
        if ctx.parent and isinstance(ctx.parent, PtrType):
            _, lenType = findLenByOffset(syscall, ctx.path[:-1])
            if lenType:
                typ.access = True
                if isinstance(typ, StructType):
                    for field in typ.fields:
                        field.access = True

    syscall.visit(Context(), fix_access, isOffset=True)


def reduce_length(syscall: Syscall) -> None:
    """ For types with lenType, we reduce its size accordingly.
    The given syscall would be modified in place.
    """
    def refine(ctx, typ: Type):
        if ctx.parent and ctx.parent.type == "ptr":
            _, lenType = findLenByOffset(syscall, ctx.path[:-1])
            if lenType:
                maximum = typ.size
                if lenType.type == "const":
                    maximum = lenType.getData()*lenType.bitSize//8
                elif lenType.type == "flag":  # and typ.type == "buffer":
                    maximum = max(lenType.values)*lenType.bitSize//8
                elif lenType.type == "range":  # and typ.type == "buffer":
                    # FIXME: add size constraints
                    maximum = min(lenType.max*lenType.bitSize//8, typ.size)

                if maximum > typ.size:
                    # Add padding
                    data = {"type": "buffer", "data": [0xff]*(maximum-typ.size)}
                    padding = BufferType(data, typ.size)
                    # print("add padding to:%s\n%s\n" % (interface.Name, ctx.parent.repr()))
                    # print(ctx.path)
                    if typ.type == "struct":
                        typ.fields.append(padding)
                        return typ
                    else:
                        return [typ, padding]
                elif maximum < typ.size:
                    # cut off
                    # print("cutting off buffer:%s\n%s\n" % (interface.Name, ctx.parent.repr()))
                    # print(ctx.path, maximum)
                    if maximum == 0:
                        return Constant(0, 1, None)

                    if typ.type == "buffer":
                        data = typ.toJson()
                        data["data"] = typ.getRawData()[:maximum]
                        return BufferType(data, typ.offset)
                    elif typ.type == "struct":
                        size = 0
                        for i in range(len(typ.fields)):
                            size += typ.fields[i].size
                            if size >= maximum:
                                typ.fields = typ.fields[:i+1]
                                typ.size = size
                                if len(typ.fields) == 1:
                                    return typ.fields[0]
                                return typ
                    elif typ.type == "string":
                        # For string, we only modify len.
                        return typ

                    print(typ.repr())
                    print(lenType.repr())
                    raise Exception(
                        "cutting off %s is not implemented!" % typ.type)

        return typ

    ctx = Context()
    syscall.refine_type(ctx, refine, isOffset=True)

def reduce_syscall(syscall1: Syscall, syscall2: Syscall, enforce: bool = False, max_diff: int = 1):
    if syscall1.CallName != syscall2.CallName:
        return None, 0
    if syscall1.status != syscall2.status:
        return None, 0

    base = syscall1.copy()
    target = syscall2.copy()

    changes = 0
    for i in range(len(base.args)):
        arg, c, msg = merge_fields(
            base.args[i], target.args[i], enforce=enforce)
        changes += c
        if msg:
            logger.debug("%s", msg)
        if enforce:
            if arg is None:
                from IPython import embed
                embed()
                raise RuntimeError()
        else:
            if arg is None or changes > max_diff:
                return None, changes
        base.args[i] = arg
    base.validate()
    return base, changes


def existSyscall(sys, calls):
    for each in calls:
        if sys.equal(each):
            return True
    return False


def reduce_syscalls_preprocess(syscalls, max_diff: int = 1):
    ret = []
    merged = set()
    for i in range(len(syscalls)):
        if i in merged:
            continue
        if existSyscall(syscalls[i], syscalls[i+1:]):
            continue

        found = False
        for j in range(i+1, len(syscalls)):
            new_syscall, num = reduce_syscall(syscalls[i], syscalls[j], max_diff=max_diff)
            if new_syscall:
                if existSyscall(new_syscall, syscalls[i:i+1]):
                    merged.add(j)
                elif existSyscall(new_syscall, syscalls[j:j+1]):
                    found = True
                    break
        if not found:
            ret.append(syscalls[i])
    logger.debug("reduce_syscalls_preprocess from %d to %d",
                 len(syscalls), len(ret))
    return ret


def reduce_syscalls_fast(syscalls, max_diff: int):
    logger.debug("reduce_syscalls_fast %d", len(syscalls))

    changed = True
    while changed:
        changed = False
        tmp = []
        merged = set()
        for i in range(len(syscalls)):
            if i in merged:
                continue
            for j in range(i+1, len(syscalls)):
                if j in merged:
                    continue
                new_syscall, num = reduce_syscall(syscalls[i], syscalls[j], max_diff=max_diff)
                if new_syscall and not existSyscall(new_syscall, tmp):
                    logger.debug("merge %d %d", i, j)
                    tmp.append(new_syscall)
                    merged.add(i)
                    merged.add(j)
                    changed = True
            if i not in merged:
                merged.add(i)
                if not existSyscall(syscalls[i], tmp):
                    tmp.append(syscalls[i])
        syscalls = tmp
    return syscalls


def reduce_syscalls(syscalls: List[Syscall]) -> List[Syscall]:
    try:
        syscalls = reduce_syscalls_preprocess(syscalls, max_diff=options.min_diff)
        if len(syscalls) >= options.max_specs:
            return reduce_syscalls_fast(syscalls, max_diff=options.max_diff)

        changed = True
        while changed:
            changed = False
            tmp = []
            merged = set()
            # Check every pair
            for i in range(len(syscalls)):
                for j in range(i+1, len(syscalls)):
                    new_syscall, _ = reduce_syscall(syscalls[i], syscalls[j], max_diff=options.min_diff)
                    if new_syscall:
                        if not existSyscall(new_syscall, tmp):
                            tmp.append(new_syscall)
                            changed = True
                        merged.add(i)
                        merged.add(j)
                if i not in merged:
                    merged.add(i)
                    if not existSyscall(syscalls[i], tmp):
                        tmp.append(syscalls[i])
            if len(tmp) > len(syscalls)*2:
                return reduce_syscalls_fast(syscalls, max_diff=options.max_diff)
            syscalls = tmp

        return syscalls
    except Exception as e:
        logger.info("please fix the following:")
        for syscall in syscalls:
            logger.info(json.dumps(syscall.toJson()))
        raise e


def reduce_syscalls_to_one(syscalls: List[Syscall]) -> List[Syscall]:
    try:
        ret = []
        while syscalls:
            t = syscalls[0]
            remaining = []
            for syscall in syscalls[1:]:
                try:
                    t, _ = reduce_syscall(t, syscall, enforce=True)
                except MergeKnownTypeError:
                    remaining.append(syscall)
            ret.append(t)
            syscalls = remaining
        return ret
    except Exception as e:
        logger.info("please fix the following:")
        for syscall in syscalls:
            logger.info(json.dumps(syscall.toJson()))
        raise e


MERGE_DIFFERENT_TYPES_RULES: Dict[Tuple[str, str], MergeRule] = {}
MERGE_SAME_TYPE_RULES: Dict[str, MergeRule] = {}
for k, v in globals().copy().items():
    try:
        if issubclass(v, MergeRule) and v != MergeRule:
            names = [each.lower() for each in k.split("_")]
            if names[0] != "merge" or len(names) > 3:
                raise RuntimeError("unconventional name %s", names[0])
            if len(names) == 2:
                if names[1] not in ALL_TYPES:
                    raise RuntimeError("unknown type %s", names[1])
                MERGE_SAME_TYPE_RULES[names[1]] = v()
            elif len(names) == 3:
                if names[1] not in ALL_TYPES or names[2] not in ALL_TYPES:
                    raise RuntimeError(
                        "unknown type %s or %s", names[1], names[2])
                MERGE_DIFFERENT_TYPES_RULES[(names[1], names[2])] = v()
    except TypeError:
        pass
