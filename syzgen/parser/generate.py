
import os
import subprocess
import logging
import shutil
import json
from typing import Tuple, Union
from syzgen.config import Options
from syzgen.models import MAX_MEMORY_SIZE

from syzgen.parser.models import BaseModel
from syzgen.parser.syscalls import Syscall
from syzgen.parser.syscalls.iokit import ServiceClose, ServiceOpen

from syzgen.utils import loads
from syzgen.parser.types import BufferType, Context, PtrDir, PtrType, int2bytes, \
    Constant, StructType, Size2Type, Const2Type, SimplifyError, LenType, ArrayType, Type
from syzgen.parser.optimize import reduce_buffer, reduce_struct, findLenByOffset, findFieldByOffset

logger = logging.getLogger(__name__)
options = Options()


def genServicePoc(serviceName: str, client_type: int, path: str):
    """
    IOServiceOpen(serviceName, type, &connection)
    kern_return_t IOConnectCallMethod(mach_port_t connection, uint32_t selector, 
        const uint64_t *input, uint32_t inputCnt, const void *inputStruct, 
        size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, 
        void *outputStruct, size_t *outputStructCnt);
    """
    with open(path, "w") as fp:
        fp.write(
            f'syz_IOServiceOpen(&(0x7f0000000000)=\'{serviceName}\\x00\', '
            f'{client_type:#x}, &(0x7f0000000000)=<r0=>0x0)\n'
        )
        fp.write(
            "syz_IOConnectCallMethod(r0, 0, &(0x7f0000001000), 0x10, "
            "&(0x7f0000002000), 0x400, &(0x7f0000003000), &(0x7f0000004000)=0x10,"
            " &(0x7f0000005000), &(0x7f0000006000)=0x400)\n"
        )
        fp.write("syz_IOServiceClose(r0)")


def _adjust_type_size(lenType: Type, finalize: bool) -> Tuple[int, int]:
    # Note: if it is not finalized, we use a large buffer as the initial length
    # (min = max = MAX_MEMORY_SIZE).
    minLen, maxLen = (0, MAX_MEMORY_SIZE) if finalize else (
        MAX_MEMORY_SIZE, MAX_MEMORY_SIZE)
    if lenType.type == "len" or lenType.type == "range":
        if lenType.max == 0:
            return 0, 0

        if finalize:
            minLen, maxLen = lenType.min, lenType.max
        else:
            # Provide the maximum length if it is not finalized (We also set a threshold MAX_MEMORY_SIZE).
            v = min(lenType.max, MAX_MEMORY_SIZE *
                    8//lenType.bitSize)
            minLen, maxLen = v, v
    elif lenType.type == "flag":
        if max(lenType.values) == 0:
            return 0, 0

        if finalize:
            minLen, maxLen = min(
                lenType.values), max(lenType.values)
        else:
            v = min(max(lenType.values),
                    MAX_MEMORY_SIZE*8//lenType.bitSize)
            minLen, maxLen = v, v
    elif lenType.type == "const":
        v = lenType.getData()
        minLen, maxLen = v, v

    return minLen, maxLen


def _adjust_type_with_lenType(ctx: Context, typ: Type, lenType: Union[BufferType, LenType], finalize: bool) -> Type:
    if lenType.type not in ["len", "range", "flag", "buffer", "const"]:
        return typ

    assert isinstance(ctx.parent, StructType)
    minLen, maxLen = _adjust_type_size(lenType, finalize)
    if maxLen == 0:
        return typ

    if lenType.bitSize > 8:
        # It might be an array of structure or scalarInput
        fields = []
        totalSize = 0
        idx = ctx.parent.fields.index(typ)
        for field in ctx.parent.fields[idx:]:
            if field.offset + field.size <= lenType.bitSize//8:
                fields.append(field.toJson())
                totalSize += field.size

        if totalSize < lenType.bitSize//8:
            buf = BufferType(
                {"access": True, "data": [0xff]*(lenType.bitSize//8-totalSize)})
            fields.append(buf.toJson())

        length = 0 if maxLen > MAX_MEMORY_SIZE else maxLen
        if len(fields) == 1:
            typ = ArrayType({"field": fields[0], "size": typ.size, "minLen": minLen,
                                "maxLen": length}, typ.offset, typ.typename)
        else:
            new_struct = StructType({"fields": fields})
            typ = ArrayType({"field": new_struct.toJson(), "size": typ.size, "minLen": minLen,
                                "maxLen": length}, typ.offset, typ.typename)
        # merge all remaining fields into one array and thus delete them
        del ctx.parent.fields[idx+1:]

    return typ


def _adjust_struct_with_lenType(ctx: Context, typ: StructType, lenType: Union[BufferType, LenType], finalize: bool, resize: bool) -> Type:
    # FIXME: do not hardcode max size
    if typ.type == "buffer" and typ.size == MAX_MEMORY_SIZE and finalize:
        typ.size = 0
        typ.data = []

    # It must be of variable length.
    minLen, maxLen = _adjust_type_size(lenType, finalize)
    if maxLen == 0:
        return Constant(0, 4, typ.typename)

    # if minLen == maxLen we do not use array.
    if finalize and minLen == maxLen and not all(each.equal(typ.fields[0]) for each in typ.fields[1:]):
        return typ
    # and lenType.bitSize not in [16, 32, 64]:
    elif lenType.bitSize > 8:
        # It might be an array of structure or scalarInput
        fields = []
        totalSize = 0
        repeat = typ.fields[0].size == lenType.bitSize//8
        if repeat:
            # If the first field has the same size as the bitSize, we probably have a case same
            # as scalarInput.
            fields.append(typ.fields[0].toJson())
            totalSize += typ.fields[0].size
            for field in typ.fields[1:]:
                if field.offset + field.size <= minLen*lenType.bitSize//8:
                    fields.append(field.toJson())
                    totalSize += field.size
        else:
            for field in typ.fields:
                if field.offset + field.size <= lenType.bitSize//8:
                    fields.append(field.toJson())
                    totalSize += field.size

            if len(fields) == 0:
                print(lenType.repr())
                print("min: %d, max: %d" % (minLen, maxLen))
                print(typ.repr())
                raise Exception("unexpected struct and len")

        if repeat:
            if all([each.equal(typ.fields[0]) for each in typ.fields[1:]]):
                length = 0 if maxLen > MAX_MEMORY_SIZE else maxLen
                return ArrayType({"field": typ.fields[0].toJson(), "size": typ.size, "minLen": minLen,
                                    "maxLen": length}, typ.offset)

            if totalSize < minLen*lenType.bitSize//8:
                # Add padding
                buf = BufferType(
                    {"access": True, "data": [0xff]*(lenType.bitSize//8)}, 0)
                if maxLen >= MAX_MEMORY_SIZE:
                    # Unlimited buffer
                    arr = ArrayType({"field": buf.toJson(), "minLen": minLen-totalSize//(lenType.bitSize//8),
                                        "maxLen": 0}, totalSize)
                else:
                    arr = ArrayType({"field": buf.toJson(), "minLen": minLen-totalSize//(lenType.bitSize//8),
                                        "maxLen": maxLen-totalSize//(lenType.bitSize//8)}, totalSize)
                fields.append(arr.toJson())
                typ = StructType({"fields": fields})
            # else: keep the original one
        elif ctx.dir & PtrDir.DirOut == 0:
            # Do not optimize the structure for output
            if totalSize < lenType.bitSize//8:
                buf = BufferType(
                    {"access": True, "data": [0xff]*(lenType.bitSize//8-totalSize)})
                fields.append(buf.toJson())

            length = 0 if maxLen > MAX_MEMORY_SIZE else maxLen
            if len(fields) == 1:
                typ = ArrayType({"field": fields[0], "size": typ.size, "minLen": minLen,
                                    "maxLen": length}, typ.offset)
            else:
                new_struct = StructType({"fields": fields})
                typ = ArrayType({"field": new_struct.toJson(), "size": typ.size, "minLen": minLen,
                                    "maxLen": length}, typ.offset)
    elif resize or typ.size == MAX_MEMORY_SIZE:
        # Normal struct or buffer, followed by an buffer with variable size.
        # We can not trust both minLen and maxLen. MinLen can be smaller than expected,
        # and maxLen is larger than expected.
        fields = []
        totalSize = 0
        for i, field in enumerate(typ.fields):
            if (
                field.offset + field.size <= minLen*lenType.bitSize//8 or
                # include all but last fields
                i != len(typ.fields)-1 or
                field.type != "buffer"  # include all non-buffer fields
            ):
                fields.append(field.toJson())
                totalSize += field.size

        if totalSize < minLen*lenType.bitSize//8:
            # Add padding
            buf = BufferType(
                {"access": True, "data": [0xff]}, 0)
            arr = ArrayType({"field": buf.toJson(), "minLen": (minLen*lenType.bitSize//8-totalSize),
                                "maxLen": maxLen*lenType.bitSize//8-totalSize}, totalSize)
            fields.append(arr.toJson())
        else:
            # TODO:
            if totalSize <= maxLen*lenType.bitSize//8:
                # Add padding
                buf = BufferType(
                    {"access": True, "data": [0xff]}, 0)
                if maxLen >= MAX_MEMORY_SIZE:
                    # Unlimited buffer
                    arr = ArrayType(
                        {"field": buf.toJson(), "minLen": 0, "maxLen": 0}, totalSize)
                else:
                    arr = ArrayType({
                        "field": buf.toJson(),
                        "minLen": 0,
                        "maxLen": maxLen*lenType.bitSize//8-totalSize
                    }, totalSize)
                fields.append(arr.toJson())
            else:
                print(lenType.repr())
                print(typ.repr())
                raise Exception("unexpected size")

        if len(fields) == 1:
            typ = Type.construct(fields[0])
        typ = StructType({"fields": fields})

    return typ


def reduce_lenType(interface: Syscall, finalize: bool, resize: bool = False):
    def refine(ctx, typ: Type):
        if isinstance(typ, BufferType) and typ.path is not None:
            # convert buffer with path to lenType
            # ptr could be a ptr or array (which might be a buf at this point)
            ptr = findFieldByOffset(interface, typ.path)
            if ptr and ptr.typename:
                ref = ptr
                if isinstance(ptr, PtrType):
                    assert ptr.ref is not None
                    ref = ptr.ref

                data = typ.toJson()
                data["lenField"] = ptr.typename
                if typ.type == "const":
                    size = typ.getData()
                    if size == 0:
                        return typ
                    # if not ptr.ref.isArray:
                    #     if size != ptr.ref.size:
                    #         print(interface.repr())
                    #         print(typ.repr())
                    #         print(ptr.repr())
                    if ref.type == "string":
                        print("find a lenType")
                        print(typ.repr())
                        print(ptr.repr())
                        data["max"] = data["min"] = 0
                        return LenType(data, typ.offset, typename=typ.typename)
                elif typ.type == "buffer":
                    data["max"] = data["min"] = 0
                    return LenType(data, typ.offset, typename=typ.typename)
                elif typ.type == "range":
                    if ref.type == "string" and typ.min < MAX_MEMORY_SIZE:
                        # Since we cannot have limits on the string, let's keep using range.
                        return typ

                    data["max"] = typ.max
                    data["min"] = typ.min
                    return LenType(data, typ.offset, typename=typ.typename)
                elif typ.type == "flag":
                    data["max"] = max(typ.values)
                    data["min"] = min(typ.values)
                    return LenType(data, typ.offset, typename=typ.typename)
                # if ptr.optional: # union has different sizes
                #     return LenType({"size": typ.size, "lenField": ptr.typename}, typ.offset)
        elif ctx.parent:
            if ctx.parent.type == "ptr":
                _, lenType = findLenByOffset(interface, ctx.path[:-1])
                if lenType and isinstance(typ, StructType):
                    typ = _adjust_struct_with_lenType(ctx, typ, lenType, finalize, resize)
            elif ctx.parent.type == "struct":
                _, lenType = findLenByOffset(interface, ctx.path)
                if lenType:
                    typ = _adjust_type_with_lenType(ctx, typ, lenType, finalize)

        if isinstance(typ, StructType):
            typ.fields[0].access = True  # First field must be accessed.
            for i in reversed(range(len(typ.fields)-1)):
                if (
                    typ.fields[i].path and
                    typ.fields[i+1].path and
                    typ.fields[i].path == typ.fields[i+1].path
                ):
                    # we may mistakenly separate a 8-byte len field into two 4-byte fields.
                    if typ.fields[i].size + typ.fields[i+1].size <= 8:
                        typ.fields[i].size += typ.fields[i+1].size
                        if isinstance(typ.fields[i], BufferType):
                            typ.fields[i].data.extend(typ.fields[i+1].getRawData() or [0] * typ.fields[i+1].size)
                        del typ.fields[i+1]

            for i in range(len(typ.fields)):
                # If string is not the last field, we assume it has fixed length.
                if typ.fields[i].type == "string" and i != len(typ.fields)-1:
                    typ.fields[i].fixLen = typ.fields[i].size

            if typ.size == MAX_MEMORY_SIZE:
                if typ.fields[-1].type == "buffer" and typ.fields[-1].size >= 1024:
                    typ.fields[-1].size = 0
                    typ.fields[-1].data = []

        return typ

    ctx = Context()
    interface.refine_type(ctx, refine, isOffset=True)


class TemplateGenerator:
    """Note: make a copy before you pass the model as it would modify the given one."""

    def __init__(self, model: BaseModel) -> None:
        self.model = model

    def refine(self, syscall: Syscall, finalize: bool):
        reduce_lenType(syscall, finalize, resize=False)
        reduce_struct(syscall)
        reduce_buffer(syscall, finalize)

    def run(self, outfile: str, finalize: bool, build: bool = False):

        f = open(outfile, "w")

        resources = dict()
        out_resources = dict()

        def search(ctx, typ):
            if typ.type == "resource":
                if ctx.dir & PtrDir.DirOut:
                    out_resources[typ.name] = typ

                if typ.name not in resources:
                    resources[typ.name] = typ

        for syscall in self.model.syscalls():
            syscall.visit(Context(), search)

        for name, typ in resources.items():
            if name in out_resources:
                # if name in {"fd"}: # existing resource
                #     continue
                f.write("resource %s[%s]\n" % (
                    name, typ.parent if typ.parent else Size2Type(typ.size)))
            else:
                # We use const instead of resource
                typename, definition = Const2Type(typ.getData(), typename=name)
                if definition is None:
                    f.write("type %s %s\n" % (name, typename))
                else:
                    f.write("%s\n" % definition)
        f.write("\n")

        # Simplify to ArrayType
        # def refine_array(ctx, typ):
        #     if typ.type == "struct":
        #         tgt = typ.fields[0]
        #         if all([each.equal(tgt) for each in typ.fields]):
        #             typ = ArrayType({"field": tgt.toJson(), "minLen": len(typ.fields), \
        #                 "maxLen": len(typ.fields), "size": typ.size}, typ.offset)
        #     return typ

        # for group, interfaces in model.methods.items():
        #     for interface in interfaces:
        #         interface.refine_type(Context(), refine_array)
        # for group, interfaces in model.async_methods.items():
        #     for interface in interfaces:
        #         interface.refine_type(Context(), refine_array)

        def write2file(fp, model: BaseModel):
            for syscall in model.syscalls():
                syscall.generateTemplate(fp)

        # At this point, fields may not have been assigned a name and thus we can not refine LenType.
        # We do generation before and after LenType refinement.
        with open(os.devnull, "w") as null:
            write2file(null, self.model)

        # Refine LenType
        for syscall in self.model.syscalls():
            # reduce_lenType(syscall, finalize)
            self.refine(syscall, finalize)

        # sys_Open.generateTemplate(f)
        write2file(f, self.model)

        f.close()

        if build:
            # Hack for macos where it requries kernel source code.
            subprocess.run(["make", "SOURCEDIR=tmp"], check=True,
                           cwd=options.getConfigKey("syzkaller"))

        return outfile


class IOKitTemplateGenerator(TemplateGenerator):
    def refine(self, syscall: Syscall, finalize: bool):
        # For iokit drivers, it uses pre-allocated buffer to store some input
        # and thus we may not figure out the boundary precisely. Instead, usse
        # Len field to guess the boundary.
        reduce_lenType(syscall, finalize, resize=True)
        reduce_struct(syscall)
        reduce_buffer(syscall, finalize)

# Give a certain input, find the first output on which it depends.


def find_dependence(interfaces, index):
    itfCall = interfaces[index]

    ret = index
    # Check known dependence

    def get_resource(ctx, typ):
        if ctx.dir & PtrDir.DirIn == 0:
            return

        if typ.type == "resource":
            # If this input has a dependence
            resource = typ.name
            data = typ.getData()
            # print("found input resource", resource, data)

            # Find the cloest ouput corresponding to the dependence
            last = index - 1
            while last >= 0:
                itf = interfaces[last]

                def find_resource(c, t):
                    if c.dir & PtrDir.DirOut == 0:
                        return

                    if t.type == "resource" and t.name == resource and \
                            t.getData() == data:
                        c.ret = True
                        return True

                c = Context()
                itf.visit(c, find_resource)
                if c.ret:
                    break
                last -= 1

            if last != -1 and last < ctx.ret:
                # We may have multiple dependence, record the first one.
                ctx.ret = last
                # print("found output resource at ", last)

    ctx = Context()
    ctx.ret = index
    itfCall.visit(ctx, get_resource)

    return ret if ret < ctx.ret else ctx.ret


def get_testcase(interfaces, start, end):
    index = end
    while index >= start:
        # print(index, start, end)
        last = find_dependence(interfaces, index)
        if last != -1 and last < start:
            start = last
        index -= 1
    return start, end


def generateTestcases(logdir, model, serviceName, client):
    all_inputs = {}
    for name in os.listdir(logdir):
        if name.endswith(".log") and name.startswith("out_kernel_hook"):
            logger.debug("loading %s..." % name)
            syscalls = loads(os.path.join(logdir, name))
            refined = []
            for i, syscall in enumerate(syscalls):
                # print("parsing %d" % i)
                cmd = syscall.getCmdHandler(model.selector)
                test = syscall.copy()
                succeed = False
                for each in model.methods[cmd]:
                    try:
                        # print("before")
                        # print(test.repr())
                        test.simplify(each)
                        # print("after")
                        # print(test.repr())
                        refined.append(test)
                        succeed = True
                        break
                    except SimplifyError as e:
                        print(e)
                if not succeed:
                    print(syscall.repr())
                    print(model.methods[cmd][0].repr())
                    logger.error("Failed to simplify testcases")
            all_inputs[name] = refined

    path = os.path.join("workdir", "progs")
    shutil.rmtree(path, ignore_errors=True)
    try:
        os.mkdir(path)
    except:
        pass

    sysOpen = ServiceOpen.create(serviceName, client.type, model.name)
    sysClose = ServiceClose()

    num = 0
    for filename, inputs in all_inputs.items():
        print("parsing %s" % filename)
        if len(inputs) < 10:  # no need to split the testcase
            with open(os.path.join(path, "%d.prog" % num), "w") as f:
                port_num = inputs[-1].connection.getData()
                port = port_num if isinstance(
                    port_num, list) else int2bytes(port_num, 8)
                sysOpen.port.ref.data = port
                sysClose.port.data = port
                json.dump(sysOpen.toArgs(), f)
                f.write("\n")
                for syscall in inputs:
                    syscall.connection.data = port
                    json.dump(syscall.toArgs(), f)
                    f.write("\n")
                json.dump(sysClose.toArgs(), f)
            num += 1
        else:
            last = len(inputs) - 1
            while last >= 0:
                start, end = get_testcase(inputs, last, last)
                logger.debug("find a testcase from %d to %d: %d" %
                             (start, end, num))
                with open(os.path.join(path, "%d.prog" % num), "w") as f:
                    port_num = inputs[end].connection.getData()
                    port = port_num if isinstance(
                        port_num, list) else int2bytes(port_num, 8)
                    sysOpen.port.ref.data = port
                    sysClose.port.data = port
                    json.dump(sysOpen.toArgs(), f)
                    f.write("\n")
                    for i in range(start, end+1):
                        # Note syscalls with different ports sometimes have dependence and thus we can not
                        # separate these calls by their ports. To reduce the number of calls, we use the
                        # same ports here.
                        inputs[i].connection.data = port
                        json.dump(inputs[i].toArgs(), f)
                        f.write("\n")
                    json.dump(sysClose.toArgs(), f)
                num += 1
                last = start - 1

    return os.path.abspath(path)


def instrument_testcase_with_hook(prog_file: str, outfile: str):
    syzkaller = options.getConfigKey("syzkaller")
    cmds = [
        os.path.join(syzkaller, "bin", "syz-syzgen"),
        "-command=hook",
        f"-output={outfile}",
        prog_file,
    ]
    logger.debug("%s", cmds)
    subprocess.run(cmds, check=True)
