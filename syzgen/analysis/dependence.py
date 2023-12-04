
from collections import defaultdict
import json
import logging
import os
import re
import subprocess
import time
from typing import Dict, List, Optional, Set, Tuple, Union

from syzgen.analysis.access_path import AccessNode
from syzgen.models import BASE_HEAP_LOCATION
from syzgen.parser.models import READ_ACCESS_PATHS, WRITE_ACCESS_PATHS
from syzgen.parser.syscalls import Syscall
from syzgen.target import Target

from syzgen.parser.optimize import Context, reduce_syscalls

from syzgen.parser.types import BufferType, PtrDir, PtrType, ResourceType, StructType, Type, int2bytes
from syzgen.parser.generate import BaseModel

from syzgen.config import Options
from syzgen.utils import UnusedTempFileName, get_blank_state
from syzgen.vm.dummy import DummyInstance

RESOURCE_INIT = re.compile(r'uint64_t r\[(?P<NUM>\d+)\] = {.+};', re.MULTILINE|re.DOTALL)

logger = logging.getLogger(__name__)
options = Options()


class InvalidTestCaseException(Exception):
    pass


class RefineReadDependencyException(Exception):
    pass


def access_path_filter(path: str) -> bool:
    # Must derived from global variables
    global_variables = ["glb", "gs", "file"]
    if not any(each in path for each in global_variables):
        return True
    # Must have at least one dereference
    if "*" not in path:
        return True
    return False


def verify_dependency(
    target: Target,
    resource: ResourceType,
    cmd: int,
    model: BaseModel,
    prog_file: str,
):
    options = Options()
    target.generate_template(
        model, True, True,
        options.getConfigKey("cover", False)
    )
    # Heuristic 1: Invoke the syscall multiple times to see if we can get contiguous
    # values in outputs
    syzkaller = options.getConfigKey("syzkaller")
    output_prog = UnusedTempFileName(".syz")
    # cfg_path = os.path.join(syzkaller, "workdir", f"cfg_{model.name}.json")

    for options in [[], ["-repeat"], ["-mutate"]]:
        cmds = [
            os.path.join(syzkaller, "bin", "syz-syzgen"),
            "-command=infer",
            f"-resource={resource.name}",
            f"-output={output_prog}",
            *options,
            prog_file,
        ]
        logger.debug("%s", " ".join(cmds))
        ret = subprocess.run(cmds, stderr=subprocess.PIPE)
        if ret.returncode != 0:
            output = ret.stderr.decode("utf-8")
            if "failed to find the resource in output" in output:
                # weird cases where the output buffer is NULL.
                # FIXME: re-generate it through fuzzing?
                logger.info("failed to get a correct testcase")
                # raise InvalidTestCaseException()
                return True
            # other unknown errors
            raise NotImplementedError(output)

        def init_resource(content):
            res = RESOURCE_INIT.search(content)
            if res is None:
                logger.error("prog:\n%s", content)
                raise RuntimeError("no resources")

            num = int(res.group("NUM"), 10)
            replace = "uint64_t r[%d] = {%s};" % (num, ", ".join(["-1"] * num))
            return content[:res.start()] + replace + content[res.end():]

        executable = UnusedTempFileName("_poc")
        target.build_poc(output_prog, executable, func=init_resource, initresc=True)
        poc = target.copy_file(executable)
        os.unlink(executable)
        os.unlink(output_prog)

        ret = target.inst.run_cmd([poc], check=True, enable_stdout=True)
        regex = re.compile(r"syzgen: res (?P<resource>-?\d+)")
        resources = []
        for line in ret.stdout.split(b"\n"):
            line = line.decode("utf-8")
            m = regex.search(line)
            if m:
                resources.append(int(m.group("resource")))
        if len(resources) > 3:
            logger.debug("resources: %s", resources)
            if (
                all(each in {0, 0xffffffff, 0xffffffffffffffff, -1} for each in resources)
                and all(each == resources[0] for each in resources)
            ):
                # either no output or it is not a resource since we require
                # that each call should produce a different resource
                continue
            delta = resources[1] - resources[0]
            if (
                delta and
                all(delta == resources[i] - resources[i-1]
                    for i in range(2, len(resources)))
            ):
                logger.info(
                    "[Verify Dependency 1] Find contiguous resources in output")
                return True

    # Heuristic 2: compare coverage
    # from IPython import embed; embed()
    # if options.getConfigKey("cover", False):
    #     # applicable if it supports coverage
    #     # FIXME: pick a random syscall
    #     use_syscall: Syscall = list(model.methods(cmd))[-1]
    #     cfg_path = os.path.join(syzkaller, "workdir", f"cfg_{model.name}.json")
    #     # Insert new syscalls with valid and invalid resources
    #     output_prog = UnusedTempFileName(".syz")
    #     basename = os.path.basename(output_prog)
    #     cmds = [
    #         os.path.join(syzkaller, "bin", "syz-syzgen"),
    #         "-command=insert",
    #         f"-syscall={use_syscall.Name}",
    #         f"-resource={resource.name}",
    #         f"-config={cfg_path}",
    #         f"-output={basename}",
    #         prog_file,
    #     ]
    #     logger.debug("%s", " ".join(cmds))
    #     subprocess.run(cmds, check=True)

    #     invalid_test = target.copy_file(f"invalid_{basename}")
    #     valid_test = target.copy_file(f"valid_{basename}")
    #     syz_run = target.copy_file(os.path.join(
    #         syzkaller,
    #         "bin",
    #         target.get_target().replace("/", "_"),
    #         "syz-run"
    #     ))
    #     syz_executor = target.copy_file(os.path.join(
    #         syzkaller,
    #         "bin",
    #         target.get_target().replace("/", "_"),
    #         "syz-executor",
    #     ))
    #     escaped_syscall_name = use_syscall.Name.replace("$", "\$")
    #     try:
    #         ret = target.inst.run_cmd([
    #             syz_run,
    #             f'-executor={syz_executor}',
    #             # "-vv=100",
    #             "-cover",
    #             "-collide=false",
    #             "-threaded=false",
    #             "-output=true",
    #             "-command=verify",
    #             # "-debug",
    #             # "-coverfile=1",
    #             f'-syscall={escaped_syscall_name}',
    #             invalid_test,
    #             valid_test,
    #         ], enable_stderr=True)
    #         logger.debug("test cover: %s", ret.stderr.decode("utf-8"))
    #     except Exception as e:
    #         from IPython import embed; embed()
    #         raise e

    #     # clean up
    #     os.unlink(f"invalid_{basename}")
    #     os.unlink(f"valid_{basename}")
    #     os.unlink(output_prog)
    #     if b"sys-run: Succeed!" in ret.stderr:
    #         logger.info("[Verify Dependency 2] Cover more blocks with valid resources")
    #         return True

    return False


def generate_valid_testcase(
    target: Target,
    syscall: str,
    config_file: str,
    outfile: str,
    timeout: Optional[int] = None,  # in seconds
):
    """
    syscall: prefix of the syscall name
    config_file: name of the config file
    """
    syzkaller = options.getConfigKey("syzkaller")
    cfg_path = os.path.join(syzkaller, "workdir", config_file)
    cmds = [
        os.path.join(syzkaller, "bin", "syz-manager"),
        f"-config={cfg_path}",
        f"-command=TargetSyscall={syscall}",
        f"-output={outfile}",
    ]
    if target.get_os() == "darwin":
        kcov = os.path.join(target.kcov_path, "kcov")
        if not os.path.exists(kcov):
            raise RuntimeError("%s does not exist", kcov)
        cmds.extend(["-kcov", kcov])
    if timeout:
        cmds.extend(["-timeout", str(timeout)])
    logger.debug("run syzkaller to generate a valid testcase %s",
                 " ".join(cmds))
    subprocess.run(cmds, check=True)
    if timeout:
        if not os.path.exists(outfile) or os.path.getsize(outfile) == 0:
            raise TimeoutError()
    return outfile


def apply_write_dependency(target: Target, model: BaseModel, base: Syscall, write_cmd: int, resource: ResourceType):
    def get_path_to_resource(ctx: Context, typ: Type):
        if ctx.dir&PtrDir.DirOut and typ == resource:
            ctx.ret = list(ctx.path)
            return True
    ctx = Context()
    base.visit(ctx, get_path_to_resource, isOffset=True)
    path = ctx.ret
    if path is None:
        raise RuntimeError("failed to find the resource")

    def apply_resource(ctx: Context, typ: Type):
        # TODO: different structures?
        if ctx.path == path:
            return resource
        return typ

    for each in model.methods(write_cmd):
        if each != base:
            each.refine_type(Context(), apply_resource, isOffset=True)

    syscalls, _cmd = model.model(write_cmd)
    syscalls.methods[_cmd] = reduce_syscalls(syscalls.methods[_cmd])
    for i, each in enumerate(syscalls.get_syscalls(_cmd)):
        each.set_subname(model.name, _cmd, i)
        logger.debug(each.repr())
    target.generate_template(
        model, True, True, options.getConfigKey("cover", False))


def count_output_bytes(syscall: Syscall) -> int:
    def count(ctx: Context, typ: Type):
        if (
            ctx.dir & PtrDir.DirOut and
            typ.type != "ptr" and
            typ.type != "struct"
        ):
            ctx.ret += typ.size

    ctx = Context()
    ctx.ret = 0
    syscall.visit(ctx, count)
    return ctx.ret

def rewrite(model: BaseModel, src: ResourceType, dst: ResourceType):
    def visit(_: Context, typ: Type):
        if isinstance(typ, ResourceType) and typ.name == src.name:
            typ.name = dst.name

    for syscall in model.syscalls():
        syscall.visit(Context(), visit)

def overwrite_resource(model: BaseModel, arg: Type, resource: ResourceType):
    if isinstance(arg, ResourceType) and arg.name != resource.name:
        n1 = int(arg.name.split("_")[-1])
        n2 = int(resource.name.split("_")[-1])
        if n1 < n2:
            rewrite(model, resource, arg)
            resource.name = arg.name
        else:
            rewrite(model, arg, resource)
            arg.name = resource.name

def refine_write_dependency_fast(target: Target, model: BaseModel, write_cmd: int, resource: ResourceType) -> bool:
    def find_resource(ctx: Context, typ: Type):
        if ctx.dir & PtrDir.DirOut and isinstance(typ, ResourceType):
            if typ.name == resource.name:
                ctx.ret = True
                return True

    def visit(ctx: Context, typ: Type):
        if (
            ctx.dir & PtrDir.DirOut and
            typ.type != "ptr" and
            typ.type != "struct"
        ):
            logger.debug("visit: %s", ctx.path)
            if ctx.parent is None:
                idx = ctx.path[-1]
                if idx == -1:
                    overwrite_resource(model, ctx.syscall.ret, resource)
                    ctx.syscall.ret = resource
                else:
                    overwrite_resource(model, ctx.syscall.args[idx], resource)
                    ctx.syscall.args[idx] = resource
                ctx.ret = True
                return True
            elif isinstance(ctx.parent, PtrType):
                ctx.parent.ref = resource
                ctx.ret = True
                return True
            elif isinstance(ctx.parent, StructType):
                index = ctx.path[-1]
                ctx.parent.fields[index:] = [resource]
                ctx.ret = True
                return True

    # Check if there is only one possible location for the resource
    succeed = False
    found_new = False
    for syscall in model.methods(write_cmd):
        # Check if the syscall already has this resource in the output
        ctx = Context()
        syscall.visit(ctx, find_resource)
        if ctx.ret:
            succeed = True
            continue

        size = count_output_bytes(syscall)
        if size == resource.size:
            ctx = Context()
            ctx.ret = False
            syscall.visit(ctx, visit)
            if ctx.ret:
                succeed = True
                found_new = True

    if found_new:
        logger.info("[Verify Dependency 0] refine dependency cause only one candidate exists")
        model.reduce(write_cmd)
        target.generate_template(model, True, True, options.getConfigKey("cover", False))

    return succeed


def refine_write_dependency_no_verifier(target: Target, model: BaseModel, write_cmd: int, resource: ResourceType):
    for syscall in model.methods(write_cmd):
        def search(ctx, typ):
            if (
                ctx.dir & PtrDir.DirOut and
                typ.type != "ptr" and
                typ.type != "struct" and
                typ.size >= resource.size
            ):
                if ctx.parent is None:
                    # arg or return value
                    idx = ctx.path[-1]
                    if idx == -1:
                        ctx.syscall.ret = resource
                    else:
                        ctx.syscall.args[idx] = resource
                elif isinstance(ctx.parent, PtrType):
                    if typ.size == resource.size:
                        ctx.parent.ref = resource
                    else:
                        if typ.type != "buffer":
                            return
                        copied = typ.toJson()
                        copied["data"] = typ.data[resource.size:]
                        new_field = BufferType(
                            copied, offset=resource.size)
                        ctx.parent.ref = StructType(
                            {"fields": [resource.toJson(), new_field.toJson()]})
                elif ctx.parent.type == "struct":
                    index = ctx.path[-1]
                    if typ.size == resource.size:
                        ctx.parent.fields[index] = resource
                    else:
                        # split and gen struct
                        # TODO: enumerate all possible positions
                        if typ.type != "buffer":
                            return
                        copied = typ.toJson()
                        copied["data"] = typ.data[resource.size:]
                        new_field = BufferType(
                            copied, offset=typ.offset+resource.size)
                        ctx.parent.fields[index] = resource
                        ctx.parent.fields.insert(index+1, new_field)

                return True

        syscall.visit(Context(), search)
        # syscall.arg.visit(ctx, search)
        if len(list(model.methods(write_cmd))) > 1:
            # Also apply it to other syscalls?
            apply_write_dependency(
                target, model, syscall, write_cmd, resource)
        break


def refine_write_dependency(target: Target, model: BaseModel, write_cmd: int, read_cmd: int, resource: ResourceType):
    # First make sure we have not refined it.
    def check_resouce(ctx: Context, typ: Type):
        if ctx.dir & PtrDir.DirOut and isinstance(typ, ResourceType):
            if typ.name == resource.name:
                ctx.ret = True
                return True

    for each in model.methods(write_cmd):
        ctx = Context()
        each.visit(ctx, check_resouce)
        if ctx.ret:
            # we already refined it
            logger.info("already refine it for write as %s", resource.name)
            return True

    if isinstance(target.inst, DummyInstance):
        refine_write_dependency_no_verifier(target, model, write_cmd, resource)
        return True

    # 1. Generate a valid testcase
    gen_syscalls = model.methods(write_cmd)
    prefix = "_".join(next(gen_syscalls, None).Name.split("_")[:-1])
    # FIXME: proper timeout?
    prog_file = UnusedTempFileName(".syz")
    start_time = time.time()
    try:
        prog_file = generate_valid_testcase(
            target, prefix,
            f"cfg_{model.name}.json",
            prog_file,
            timeout=30*60
        )
    except TimeoutError:
        logger.info(f"[Verify Dependency] Failed to generate testcase for {prefix}")
        if refine_write_dependency_fast(target, model, write_cmd, resource):
            return True

        # refine_write_dependency_no_verifier(target, model, write_cmd, resource)
        return False
    finally:
        end_time = time.time()
        logger.info(f"[Verify Dependency] It took {end_time - start_time} to "
                    f"generate testcase for {prefix}")

    with target:
        # get the target syscall name
        name = None
        with open(prog_file, "r") as fp:
            for line in reversed(fp.readlines()):
                try:
                    index = line.index("(")
                    if index != -1:
                        name = line[:index]
                        break
                except ValueError:
                    pass
        logger.debug("find a valid testcase for %s", name)

        target.infer_output(prog_file, write_cmd, name, model)

        # Enable coverage: for macos, we need to manually enable it.
        target.enable_kcov()

        print("debug: ", write_cmd, name)
        for each in model.methods(write_cmd):
            print(each.repr())

        # Heuristics
        # Trial and error
        resource = resource.copy()
        for syscall in model.methods(write_cmd):
            if syscall.Name == name:
                def search(ctx: Context, typ: Type):
                    if (
                        ctx.dir & PtrDir.DirOut and
                        isinstance(typ, StructType) and
                        all(field.size < resource.size for field in typ.fields)
                    ):
                        # no subfield we can use to convert;
                        # merge fields
                        for i, field in enumerate(typ.fields):
                            if field.offset % resource.size != 0:
                                # FIXME: use alignment to reduce number of attempts
                                continue

                            old_fields = []
                            old_size = 0
                            for each in typ.fields[i:]:
                                old_fields.append(each)
                                old_size += each.size
                                if old_size >= resource.size:
                                    break

                            if old_size == resource.size:
                                typ.replace(i, [resource])
                                if verify_dependency(target, resource, read_cmd, model, prog_file):
                                    ctx.ret = True
                                    return True

                                typ.replace(i, old_fields)


                    # replace subfield with resource      
                    if (
                        ctx.dir & PtrDir.DirOut and
                        typ.type != "ptr" and
                        typ.type != "struct" and
                        typ.size >= resource.size
                    ):
                        if ctx.parent is None:
                            # arg or return value
                            idx = ctx.path[-1]
                            if idx == -1:
                                ctx.syscall.ret = resource
                            else:
                                ctx.syscall.args[idx] = resource

                            if verify_dependency(target, resource, read_cmd, model, prog_file):
                                ctx.ret = True
                                return True

                            # undo
                            if idx == -1:
                                ctx.syscall.ret = typ
                            else:
                                ctx.syscall.args[idx] = typ
                            # target.generate_template(
                            #         model, True, True, options.getConfigKey("cover", False))
                        elif isinstance(ctx.parent, PtrType):
                            if typ.size == resource.size:
                                ctx.parent.ref = resource
                            else:
                                # split and gen struct
                                # TODO: enumerate all possible positions
                                if typ.type != "buffer":
                                    return
                                copied = typ.toJson()
                                copied["data"] = typ.data[resource.size:]
                                new_field = BufferType(
                                    copied, offset=resource.size)
                                ctx.parent.ref = StructType(
                                    {"fields": [resource.toJson(), new_field.toJson()]})

                            if verify_dependency(target, resource, read_cmd, model, prog_file):
                                ctx.ret = True
                                return True
                            # undo
                            ctx.parent.ref = typ
                        elif isinstance(ctx.parent, StructType):
                            index = ctx.path[-1]
                            if typ.size == resource.size:
                                # ctx.parent.fields[index] = resource
                                ctx.parent.replace(index, [resource])
                                if verify_dependency(target, resource, read_cmd, model, prog_file):
                                    ctx.ret = True
                                    return True
                                # undo
                                ctx.parent.replace(index, [typ])
                            else:
                                # split and gen struct
                                # TODO: enumerate all possible positions
                                if typ.type != "buffer":
                                    return
                                copied = typ.toJson()
                                copied["data"] = typ.data[resource.size:]
                                new_field = BufferType(
                                    copied, offset=typ.offset+resource.size)
                                ctx.parent.replace(index, [resource, new_field])

                                if verify_dependency(target, resource, read_cmd, model, prog_file):
                                    ctx.ret = True
                                    return True
                                # undo
                                ctx.parent.replace(index, [typ])

                ctx = Context()
                ctx.ret = False
                syscall.visit(ctx, search)
                # syscall.arg.visit(ctx, search)
                if ctx.ret and len(list(model.methods(write_cmd))) > 1:
                    # Also apply it to other syscalls?
                    apply_write_dependency(
                        target, model, syscall, write_cmd, resource)

                os.unlink(prog_file)
                return ctx.ret


def refine_read_dependency(
    target: Target,
    model: BaseModel,
    cmd: int,
    resource: ResourceType,
    path: List[int]
) -> ResourceType:
    """refine the syscall based on the dependency we found"""

    def callback(ctx: Context, typ: Type) -> Type:
        # FIXME: when we get offset path from @get_access_path, we may assume some
        # fields are of type struct instead of primitives and thus append one extra
        # zero to the end.
        _path = ctx.path
        if (
            isinstance(ctx.parent, PtrType) and
            not isinstance(typ, StructType)
        ):
            _path = _path + [0]
        if ctx.path == path or _path == path:
            if typ.size == resource.size:
                logger.debug("find target type %s", typ.repr())
                if typ.type != "resource":  # we may already refine it
                    ctx.ret = resource
                    return resource
                ctx.ret = typ

        if isinstance(typ, StructType) and ctx.ret is None:
            if ctx.path == path[:-1]:
                for i, field in enumerate(typ.fields):
                    if field.offset == path[-1] and field.size < resource.size:
                        typ.merge(i, resource.size)
                        typ.fields[i] = resource
                        ctx.ret = resource
                        break

        return typ

    new_syscalls = []
    for syscall in model.methods(cmd):
        ctx = Context()
        syscall.refine_type(ctx, callback, isOffset=True)
        if ctx.ret and ctx.ret != resource:
            return ctx.ret
        if ctx.ret:
            # if a syscall does not have the resource, we ignore this one.
            new_syscalls.append(syscall)
    if len(new_syscalls) == 0:
        raise RefineReadDependencyException("cannot refine read dependency")

    syscalls, _cmd = model.model(cmd)
    syscalls.methods[_cmd] = reduce_syscalls(new_syscalls)
    for i, syscall in enumerate(model.methods(cmd)):
        syscall.set_subname(model.name, _cmd, i)
        logger.debug(syscall.repr())
    return resource


def merge_read_access_paths(read_access_paths: READ_ACCESS_PATHS) -> Dict[Tuple[Tuple, int], List[AccessNode]]:
    merges: defaultdict[Tuple[Tuple, int],
                        List[AccessNode]] = defaultdict(list)
    for pat, (path, size) in read_access_paths.items():
        for _path, _size in merges:
            # Detect conflicts
            if (
                len(_path) == len(path) and
                _path[:-1] == path[:-1]
            ):
                if _path[-1] != path[-1]:
                    if path[-1] > _path[-1] + _size and path[-1] + size < _path[-1]:
                        raise RuntimeError(
                            "overlapping and different resources")
                elif size != _size:
                    raise RuntimeError(
                        "same resource but with different sizes")

        merges[(tuple(path), size)].append(pat)

    return merges


def _infer_dependency(target: Target, modelOrName: Union[str, BaseModel]):
    if isinstance(modelOrName, BaseModel):
        model = modelOrName
    else:
        model: BaseModel = target.load_model(modelOrName)
        if model is None:
            raise FileNotFoundError(f"no model for {modelOrName}")

    resource_patterns: List[Set[AccessNode]] = []
    resources: List[ResourceType] = []

    # Count how many connections we already have so that new connection won't have conflict.
    existings = set()

    def count(_, typ: Type):
        if isinstance(typ, ResourceType) and "_connection_" in typ.name:
            existings.add(typ.name)
    for syscall in model.syscalls():
        syscall.visit(Context(), count)

    def verify_hypothesis(matched_writes: Set[AccessNode], model: BaseModel, write_cmd, read_cmd) -> Tuple[bool, BaseModel]:
        """Verify whether these two have dependency and return the new model, which might be
        unmodified if the hypothesis does not hold."""
        # if we match the same write patterns, we don't need to create a new resource
        for i, _patterns in enumerate(resource_patterns):
            # FIXME: partial match instead of exact match, eg, use the first one
            if _patterns == matched_writes:
                resource = resources[i]
                break
            elif _patterns & matched_writes:
                logger.error("found partial match!")
                logger.debug("%s", _patterns)
                logger.debug("%s", matched_writes)
                raise RuntimeError()
        else:
            resource = ResourceType({
                "name": f"{model.name}_connection_{len(resources)+len(existings)}",
                "data": int2bytes(0, size),
            })
            resource_patterns.append(matched_writes)
            resources.append(resource)

        while True:
            try:
                # make a copy before we made any changes
                copied_model = model.copy()
                old_resource = refine_read_dependency(
                    target, copied_model, read_cmd, resource, list(path))
                if old_resource != resource:
                    logger.info("already refine it for read as %s", old_resource.name)
                    resources[-1] = old_resource

                if refine_write_dependency(target, copied_model, write_cmd, read_cmd, old_resource):
                    logger.info("Successfully verified the dependency!")
                    return True, copied_model
                else:
                    resource_patterns.pop()
                    resources.pop()
            except InvalidTestCaseException:
                continue
            except RefineReadDependencyException:
                pass

            break

        # We failed, reset it before we return
        target.generate_template(
            model, True, True, options.getConfigKey("cover", False))
        return False, model

    for cmd, write_patterns in model.get_write_access_paths():
        if not write_patterns:
            continue

        for syscall in model.methods(cmd):
            if count_output_bytes(syscall) != 0:
                break
        else:
            # if all the syscalls have no output, we don't need to check the dependency
            logger.debug("skip %d as it has no output", cmd)
            continue

        # copied_model = model.copy()
        for cmd2, read_access_paths in model.get_read_access_paths():
            if cmd == cmd2:
                continue
            merges = merge_read_access_paths(read_access_paths)

            for (path, size), read_patterns in merges.items():
                for i, func in enumerate([
                    match_multiple_access,
                    match_array_with_index,
                ]):
                    matched_writes = func(read_patterns, write_patterns)
                    if not matched_writes:
                        logger.info(
                            "[Type %d] %s read pattern does not match with write patterns %s",
                            i,
                            model.get_idx_repr(cmd2),
                            model.get_idx_repr(cmd),
                        )
                    else:
                        # for each pattern, we always found a match
                        logger.info(
                            "[Type %d] find a dependency between %s and %s at %s %d",
                            i,
                            model.get_idx_repr(cmd),
                            model.get_idx_repr(cmd2),
                            path, size,
                        )
                        p = os.path.join(target.tmp_path, f"{model.name}.dependency")
                        if os.path.exists(p):
                            with open(p) as fp:
                                records = json.load(fp)
                        else:
                            records = {}
                        if model.get_idx_repr(cmd) in options.getConfigKey("dependencies", []):
                            logger.info("ignore this one")
                            continue
                        if model.get_idx_repr(cmd) in records:
                            if model.get_idx_repr(cmd2) in records[model.get_idx_repr(cmd)]:
                                logger.info("ignore this one")
                                continue

                        succeed, model = verify_hypothesis(
                            matched_writes, model, cmd, cmd2)
                        if succeed:
                            break

                        logger.info(f"[Verify Dependency] Failed to verify the dependency between {cmd} and {cmd2}")
                        if model.is_complete(cmd) and model.is_complete(cmd2):
                            if model.get_idx_repr(cmd) not in records:
                                records[model.get_idx_repr(cmd)] = []
                            records[model.get_idx_repr(cmd)].append(model.get_idx_repr(cmd2))
                            with open(p, "w") as fp:
                                json.dump(records, fp)

    return model


def match_multiple_access(read_patterns: List[AccessNode], write_patterns: WRITE_ACCESS_PATHS) -> Set[AccessNode]:
    # Look for pattern of type 1:
    # Write: *address = object
    # Read: *address.id == input
    # Linked List
    # Write 1: <__add__ <read <__add__ <BVS userClient>, <BVV 264>>>, <BVV 8>>
    # Read 1: <read <__add__ <read <__add__ <read <__add__ <BVS userClient>, <BVV 264>>>, <BVV 8>>>, <BVV 8>>>
    # Read 2: <read <__add__ <read <__add__ <read <__add__ <read <__add__ <BVS userClient>, <BVV 264>>>, <BVV 8>>>, <BVV 16>>>, <BVV 8>>>
    # Array (AppleUSBHostInterfaceUserClient)
    # Write 1: <read <__add__ <read <__add__ <read <__add__ <BVS userClient>, <BVV 304>>>, <BVV 24>>>, <BVV 24>>>
    # Write 2: <__add__ <read <__add__ <read <__add__ <read <__add__ <BVS userClient>, <BVV 304>>>, <BVV 24>>>, <BVV 24>>>, <BVV 8>>
    # Write 3: <__add__ <read <__add__ <read <__add__ <read <__add__ <BVS userClient>, <BVV 304>>>, <BVV 24>>>, <BVV 24>>>, <BVV 16>>
    # Read 1: <read <__add__ <read <read <__add__ <read <__add__ <read <__add__ <BVS userClient>, <BVV 304>>>, <BVV 24>>>, <BVV 24>>>>, <BVV 40>>>
    # Read 2: <read <add <read <add <read <add <read <add <read <add <BVS userClient>, <BVV 304>>>, <BVV 24>>>, <BVV 24>>>, <BVV 8>>>, <BVV 40>>>
    # Read 3: <read <add <read <add <read <add <read <add <read <add <BVS userClient>, <BVV 304>>>, <BVV 24>>>, <BVV 24>>>, <BVV 16>>>, <BVV 40>>>
    state = get_blank_state()
    _offset = None
    matched_writes = set()
    # from IPython import embed; embed()
    for read in read_patterns:
        if read.op != "read":
            continue
        for pat in write_patterns:
            source = read.args[0].get_source()
            if source and source.args[0] == pat:
                addr = state.solver.eval(read.args[0].to_claripy(state))
                offset = addr - BASE_HEAP_LOCATION
                if _offset is not None and _offset != offset:
                    logger.debug(
                        "inconsistent offset between %d and %d", _offset, offset)
                    continue
                _offset = offset
                matched_writes.add(pat)
                break

    if len(matched_writes) < 3:
        return set()
    return matched_writes


def _match_array_with_index(read: AccessNode, writes: Set[AccessNode]) -> Optional[AccessNode]:
    # read: *(base + offset + index)
    # write: *(base + offset)
    # read and write have the same base + offset
    # return the base to group future matches
    if read.op != '__add__':
        return None

    state = get_blank_state()
    # logger.debug("%s", read)
    left = read.to_claripy(state)
    for write in writes:
        right = write.to_claripy(state)
        if state.solver.satisfiable((left == right,)):
            if read.get_source() == write.get_source():
                return write

    return None

def match_array_with_index(read_patterns: List[AccessNode], write_patterns: WRITE_ACCESS_PATHS) -> Set[AccessNode]:
    # Detect type 2
    # Write: *(base + count) = object
    # Read: *(base + input)
    # Read: <add <read <add <read <add <BVS userClient>, <BVV 232>>>, <BVV 24>>>,
    #       <lshift <ZeroExt <BVV 32>, <Concat <Extract <BVS input_5_1024>>, <Extract <BVS input_5_1024>>, <Extract <BVS input_5_1024>>,
    #       <Extract <BVS input_5_1024>>>>, <BVV 3>>>: [2, 0, 0] 4
    # Write: <add <read <add <read <add <BVS userClient>, <BVV 232>>>, <BVV 24>>>,
    #        <lshift <ZeroExt <BVV 32>, <read <add <read <add <BVS userClient>, <BVV 232>>>, <BVV 32>>>>, <BVV 3>>>
    matched_writes = set()
    for read in read_patterns:
        if not read.hasInput():
            continue
        base = _match_array_with_index(read, write_patterns)
        if base:
            matched_writes.add(base)
            break

    return matched_writes

def infer_dependency(target: Target, modelOrName: Union[str, BaseModel], save: bool=True) -> BaseModel:
    if isinstance(modelOrName, BaseModel):
        model = modelOrName
    else:
        model: BaseModel = target.load_model(modelOrName)
        if model is None:
            raise FileNotFoundError(f"no model for {modelOrName}")

    model.save(target.model_path)
    target.generate_template(
        model, True, True, options.getConfigKey("cover", False))
    logger.debug("start to infer dependencies...")
    # For dependency verification, we need to collect coverage and thus make sure
    # we use the correct kernel.
    model = _infer_dependency(target.get_target_for_fuzzing(), model)
    if save:
        model.save(target.model_path)

    return model
