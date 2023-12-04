
import json
import logging
import os
import subprocess
import time

from typing import Callable, Dict, List, Optional
from syzgen.analysis.dependence import generate_valid_testcase, infer_dependency
from syzgen.analysis.explore import BFSExplore, CoverageExplore
from syzgen.analysis.plugins.dependency import RecordAccessPathPlugin
from syzgen.analysis.plugins.detect_output import OutputDetectorPlugin
from syzgen.analysis.plugins.error_path import DetectErrorPathPlugin
from syzgen.analysis.plugins.recovery import InputRecoveryPlugin, reduce_states
from syzgen.config import AnalysisType, Options
from syzgen.debugger.proxy import ProxyException
from syzgen.executor import BaseExecutor, ExitCode
from syzgen.executor.executor import TestCase

from syzgen.parser.models import Address, BaseModel, SyscallModel
from syzgen.parser.optimize import reduce_syscalls, reduce_syscalls_to_one
from syzgen.parser.syscalls import Syscall, SyscallStatus
from syzgen.parser.types import Buffer, BufferType, Context, PtrDir, PtrType, ResourceType, int2bytes
from syzgen.target import Target, UnresolvedModelException
from syzgen.utils import UnusedTempFileName
from syzgen.vm import VMFailure

logger = logging.getLogger(__name__)
options = Options()


SyscallStatusOrder = {
    SyscallStatus.INIT: 0,
    SyscallStatus.REINIT: 1,
    SyscallStatus.OUTPUT: 2,
    SyscallStatus.INCOMPLETE: 3,
    SyscallStatus.FINISHED: 4,
}

class InvalidTestcaseError(Exception):
    pass

class BaseModelAnalysis:
    def __init__(self, target: Target, model: BaseModel, dynamic: bool, binary: str, **kwargs) -> None:
        logger.info("initializing %s......" % self.__class__.__name__)
        self.target = target.get_target_for_analysis()
        self.model = model
        self.dynamic = dynamic
        self.binary = binary
        self.kwargs = kwargs

    def prepare_testcase(self, syscall: Syscall, isVMRunning: bool, **kwargs) -> Optional[TestCase]:
        if not isVMRunning:
            return None

        poc = UnusedTempFileName(".syz")
        while True:
            self.target.generate_poc(
                syscall.Name,
                os.path.join(
                    options.getConfigKey("syzkaller"),
                    "workdir",
                    f"cfg_{self.model.name}.json"
                ),
                poc,
            )
            # make sure the testcase we generated can generate all resources correctly.
            if self.target.check_testcase(poc):
                break

        executable = UnusedTempFileName("_poc")
        self.target.build_poc(poc, executable)

        with open(poc, "r") as fp:
            content = fp.read()
        # delete syz
        os.unlink(poc)
        return TestCase(executable, ["sudo", executable], syzprog=content)

    def run(self) -> None:
        for module_num, model in self.model._syscall_models():
            if model.entry.address == 0:
                logger.info("try python main.py --target %s --find_drivers", self.model.name)
                if options.step and options.step is AnalysisType.ALL:
                    # only do it when we need to retry
                    raise UnresolvedModelException("new model: %s" % model.name)
            self._run(module_num, model)
            self.model.save(self.target.model_path)

    def _run(self, model_num: int, model: SyscallModel) -> None:
        raise NotImplementedError()

    def execute_syscall(
        self,
        syscall: Syscall,
        model: SyscallModel,
        testcase: Optional[TestCase]=None,
        func: Optional[Callable[[Syscall, SyscallModel, Optional[TestCase]], None]]=None,
        **kwargs
    ) -> None:
        logger.debug("execute following syscall:")
        logger.debug("%s", syscall.repr())
        logger.debug("%s", json.dumps(syscall.toJson()))

        call = func or self._execute_syscall
        if self.dynamic:
            testcase = testcase or self.prepare_testcase(syscall, False)
            attempts = 0
            while True:
                attempts += 1
                if attempts > 3:
                    logger.error(
                        "VM was not working probably due to invalid testcase: \n%s\n%s",
                        testcase.syzprog if testcase else "",
                        syscall.repr(),
                    )
                    raise InvalidTestcaseError()
                try:
                    with self.target:
                        if testcase is None:
                            testcase = self.prepare_testcase(syscall, True)
                        assert testcase is not None

                        t = testcase
                        if testcase.need_copy:
                            dst = self.target.copy_file(testcase.proc_path)
                            logger.debug("copy poc to guest")
                            t = testcase.replace(dst)
                        call(syscall, model, testcase=t, **kwargs, **self.kwargs)
                    break
                except ProxyException as e1:
                    logger.debug("exception %s", e1)
                    logger.error("proxy error occurs! retrying...")
                except VMFailure as e2:
                    logger.debug("exception %s", e2)
                    logger.error("vm failure occurs! retrying...")

            testcase.unlink()
        else:
            call(syscall, model, **kwargs, **self.kwargs)

    def _execute_syscall(self, syscall: Syscall, model: SyscallModel, testcase: Optional[TestCase] = None, **kwargs) -> None:
        raise NotImplementedError()

    def get_executor(self, syscall: Syscall, model: SyscallModel, **kwargs) -> BaseExecutor:
        raise NotImplementedError()


class InterfaceRecovery(BaseModelAnalysis):
    def __init__(
        self,
        target: Target,
        binary: str,
        cmd: int,
        model: BaseModel,
        dynamic: bool,
        **kwargs,
    ) -> None:
        assert model is not None
        assert target is not None

        self.cmd = cmd

        self._cmds_with_fd: Dict[int, Address] = {}

        super().__init__(target, model, dynamic, binary, **kwargs)

    def handle_new_fd(self) -> None:
        raise NotImplementedError()

    def get_struct_executor(self, syscall: Syscall, model: SyscallModel, **kwargs) -> Optional[BaseExecutor]:
        return None

    def _need_refinement(self, syscall: Syscall) -> bool:
        for arg in syscall.args:
            if isinstance(arg, PtrType) and arg.dir&PtrDir.DirIn:
                if arg.ref and arg.ref.type not in {"resource", "const", "known"}:
                    return True
            elif isinstance(arg, BufferType):
                return True
        return False

    def _need_initialize(self, syscall: Syscall) -> bool:
        return (
            syscall.status == SyscallStatus.INIT or
            syscall.status == SyscallStatus.REINIT
        )

    def _execute_syscall(
        self,
        syscall: Syscall,
        model: SyscallModel,
        testcase: Optional[TestCase] = None,
        cmd: int=0,
        index: int=0,
        **kwargs
    ) -> None:
        func = getattr(self, f"process_{syscall.status.name.lower()}_syscall")
        executor = self.get_executor(syscall, model, testcase=testcase, **kwargs)
        func(executor, cmd, index, syscall, model)

        if isinstance(executor, RecordAccessPathPlugin):
            model.write_patterns[cmd].update(executor.write_access_paths)
            model.read_patterns[cmd].update(executor.read_access_paths)

    def process_syscalls(self, cmd: int, model_num: int) -> None:
        while True:
            # we may change the model when inferring dependency and thus need to reload it
            model: SyscallModel = self.model.get_syscall_model(model_num)
            candidates = []
            for i, syscall in enumerate(model.get_syscalls(cmd)):
                if syscall.status == SyscallStatus.FINISHED:
                    continue
                if not self._need_refinement(syscall):
                    syscall.status = SyscallStatus.FINISHED
                    continue

                candidates.append((i, syscall))

            if candidates:
                # order = SyscallStatusOrder[SyscallStatus.INCOMPLETE]
                # if (
                #     all(
                #         SyscallStatusOrder[call.status] >= order
                #         for _, call in candidates
                #     ) and len(candidates) > 12
                # ):
                #     break

                candidates = sorted(
                    candidates,
                    key=lambda x: SyscallStatusOrder[x[1].status]
                )
                i, syscall = candidates[0]

                try:
                    self.execute_syscall(syscall, model, cmd=cmd, index=i)
                except subprocess.TimeoutExpired:
                    logger.error("failed to generate a testcase, skip this")
                    syscall.status = SyscallStatus.FINISHED
                    continue
                except InvalidTestcaseError:
                    logger.info("Switch to static executor for this syscall")
                    self.dynamic = False
                    self.execute_syscall(syscall, model, cmd=cmd, index=i)
                    self.dynamic = True

                model.reduce(cmd)
                if options.infer_dependence:
                    start_time = time.time()
                    self.model = infer_dependency(self.target, self.model)
                    stop_time = time.time()
                    logger.info("infer dependency took %s", stop_time - start_time)

                self.target.generate_template(
                    self.model, False, True,
                    options.getConfigKey("cover", False)
                )
                self.model.save(self.target.model_path)

                if options.process_once:
                    break
            else:
                # no process at all
                break

    def fix_alloc_fd(self, syscalls: List[Syscall], fd: ResourceType) -> bool:
        """replace alloc_fd with its real name"""
        def visit(ctx, typ):
            if ctx.dir&PtrDir.DirOut == 0:
                return
            if isinstance(typ, ResourceType) and typ.name == "alloc_fd":
                typ.name = fd.name
                typ.parent = fd.parent
                ctx.ret = True

        res = False
        for syscall in syscalls:
            ctx = Context()
            syscall.visit(ctx, visit)
            if ctx.ret:
                res = True
        return res

    def process_init_syscall(self, executor: BaseExecutor, cmd: int, index: int, syscall: Syscall, model: SyscallModel) -> bool:
        # Explore all possible paths (BFS)
        executor.explorer = BFSExplore
        assert isinstance(executor, InputRecoveryPlugin)

        executor.register_state_reduction(reduce_states)
        executor.register_syscall_reduction(reduce_syscalls)
        executor.run()

        syscalls = list(executor.recovered_syscalls)
        orig_syscall: Syscall = model.methods[cmd].pop(index)
        if len(syscalls) == 0 and options.non_empty:
            orig_syscall.status = SyscallStatus.FINISHED
            syscalls.append(orig_syscall)
        model.methods[cmd].extend(syscalls)

        status = SyscallStatus.INCOMPLETE
        if executor.exit_code != ExitCode.NO_STATE and isinstance(executor, OutputDetectorPlugin):
            # OutputDetectorPlugin should be used in conjunction with BFSExplore
            output_funcs = executor.get_output_funcs()
            if output_funcs:
                targets = set(
                    addr for _, addr in executor.getFuncAddrs(*output_funcs)
                )
                excludes = [model.entry]
                if model.dispatcher is not None and cmd in model.dispatcher.methods:
                    excludes.append(model.dispatcher.methods[cmd].addr)
                if executor.detect(targets, excludes=excludes):
                    status = SyscallStatus.OUTPUT

        if orig_syscall.check_return_value():
            assert isinstance(executor, DetectErrorPathPlugin)
            entry_addr = executor.getTargetAddr(model.entry.address, model.entry.module)
            targets = set()
            alloc_fd = False
            fd_funcs = executor.get_fd_funcs()
            if fd_funcs:
                targets = set(
                    addr for _, addr in executor.getFuncAddrs(*fd_funcs)
                )
                # note static analysis is not path sensitive and thus we need to make sure
                # this command can lead to fd allocation.
                if executor.detect(targets):
                    alloc_fd = True

            # assume it only generate one fd
            new_module_name = f"{model.name}_Group{cmd:x}"
            fd = ResourceType({
                "name": f"{new_module_name}_fd",
                "parent": "fd",
                "data": int2bytes(0, 4)
                }, typename="fd",
            )
            if self.fix_alloc_fd(syscalls, fd):
                # out fd in the output buffer
                alloc_fd = False
                # new fd should be associated with new ioctl commands
                self.handle_new_fd(self.model, new_module_name)

            num = len(targets)
            if not executor.always_return_error_code(entry_addr, targets=targets):
                logger.debug("syscall has non-error-code return values")
                ret_buf = Buffer(4, None)
                if alloc_fd and len(targets) < num:
                    logger.debug("assume fd functions return fd as return value")
                    ret_buf = fd
                    # new fd should be associated with new ioctl commands
                    self.handle_new_fd(self.model, new_module_name)
                for syscall in syscalls:
                    syscall.ret = ret_buf

        for syscall in syscalls:
            if syscall.status == SyscallStatus.INIT:
                syscall.status = status

        return False

    def process_output_syscall(self, executor: BaseExecutor, cmd: int, index: int, syscall: Syscall, model: SyscallModel) -> bool:
        # refine structure in case we miss some out pointer
        orig_timeout = options.timeout
        options.timeout = 300

        if executor is not None:
            executor.run()
            assert isinstance(executor, InputRecoveryPlugin)
            for each in executor.recovered_syscalls:
                syscall.refine(each)
            logger.debug("refine structures: \n%s\n", syscall.repr())

        options.timeout = orig_timeout
        syscall.status = SyscallStatus.INCOMPLETE
        return False

    def process_incomplete_syscall(self, executor: BaseExecutor, cmd: int, index: int, syscall: Syscall, model: SyscallModel) -> bool:
        # Explore some paths (DFS)
        # executor.reload(syscall=syscall)
        executor.explorer = CoverageExplore
        assert isinstance(executor, InputRecoveryPlugin)
        executor.register_syscall_reduction(reduce_syscalls_to_one)
        executor.run()

        syscalls = list(executor.recovered_syscalls)
        if len(syscalls) == 0:
            syscall.status = SyscallStatus.FINISHED
        else:
            orig_syscall: Syscall = model.methods[cmd].pop(index)
            for syscall in syscalls:
                new_syscall = orig_syscall.copy()
                new_syscall.refine(syscall)
                new_syscall.status = SyscallStatus.FINISHED
                model.methods[cmd].append(new_syscall)

        return False

    def interface_recovery(self, cmd: int, model_num: int):
        model: SyscallModel = self.model.get_syscall_model(model_num)
        if cmd not in model.methods:
            # logger.debug("unknown cmd %#x", cmd)
            return

        self.process_syscalls(cmd, model_num)
        # self.model = infer_dependency(self.target, self.model)
        model = self.model.get_syscall_model(model_num)

        logger.info("final results:")
        for i, call in enumerate(model.get_syscalls(cmd)):
            call.set_subname(model.name, cmd, i)
            logger.info("%s", call.repr())

    def _run(self, model_num: int, model: SyscallModel) -> None:
        if self.cmd != -1:
            logger.info("start to analyze cmd 0x%x", self.cmd)
            self.interface_recovery(self.cmd, model_num)
        else:
            for cmd in sorted(model.methods.keys()):
                logger.info("start to analyze cmd 0x%x", cmd)
                self.interface_recovery(cmd, model_num)


class InterfaceDiscovery(BaseModelAnalysis):
    def __init__(self, target: Target, model: BaseModel, **kwargs) -> None:
        super().__init__(target, model, False, "", **kwargs)

    def add_syscalls(self, model: SyscallModel, ops: Dict[str, int]):
        raise NotImplementedError()

    def run(self) -> None:
        indices = []
        for num, _ in self.model._syscall_models():
            indices.append(num)

        for num in reversed(indices):
            model = self.model.get_syscall_model(num)
            if model.entry.address != 0:
                continue

            self.model.remove_syscall(num)
            self._run(model)

        BaseModel.initialize(self.model)
        self.model.save(self.target.model_path)

    def _run(self, model: SyscallModel) -> None:
        fd: Optional[ResourceType] = None
        syscall = model.get_any_syscall()
        for arg in syscall.args:
            if isinstance(arg, ResourceType) and arg.parent == "fd":
                fd = syscall.args[0]
                break
        assert fd

        def search(ctx: Context, typ):
            if ctx.dir&PtrDir.DirOut and isinstance(typ, ResourceType):
                if typ.name == fd.name:
                    ctx.ret = True
                    return True

        for each in self.model.syscalls():
            ctx = Context()
            each.visit(ctx, search)
            if ctx.ret:
                start_time = time.time()
                poc = UnusedTempFileName(".syz")
                prefix = "_".join(each.Name.split("_")[:-1])
                poc = generate_valid_testcase(
                    self.target,
                    prefix,
                    os.path.join(
                        options.getConfigKey("syzkaller"),
                        "workdir",
                        f"cfg_{self.model.name}.json"
                    ),
                    poc,
                    timeout=30*60,
                )
                logger.info(f"[Verify Dependency fd] It took {time.time() - start_time} to "
                    f"generate testcase for {prefix}")
                with self.target:
                    ops = self.target.check_fd(poc)
                    self.add_syscalls(model, ops)

                os.unlink(poc)
                break
