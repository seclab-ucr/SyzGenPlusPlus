
import logging
import os
from typing import Optional

from angr import SimProcedure
from angr.sim_state import SimState
from claripy.ast.base import Base
from claripy.ast.bv import Extract
from syzgen.parser.models import CommandExtractInterface, MethodTable
from syzgen.analysis.interface import BaseModelAnalysis, InvalidTestcaseError

from syzgen.analysis.iokit import ExternalMethodExecutor, GetTargetAndMethodExecutor
from syzgen.analysis.plugins.commands import CommandIdentificationPlugin, LinuxCommandIdentificationPlugin
from syzgen.config import Options
from syzgen.executor import BaseExecutor
from syzgen.executor.executor import TestCase
from syzgen.executor.linux import LinuxDyanmicSyscallExecutor, LinuxStaticSyscallExecutor
from syzgen.kext.macho import DispatchTable, ExternalMethodDispatch, Method, Service, UserClient
from syzgen.parser.generate import genServicePoc
from syzgen.parser.models import Address, BaseModel, SyscallModel, TargetAddress
from syzgen.parser.syscalls import Syscall
from syzgen.parser.syscalls.ioctl import IOCTLMethod
from syzgen.parser.syscalls.iokit import IOConnectCallMethod
from syzgen.parser.syscalls.write import SysWrite
from syzgen.target import Target
from syzgen.utils import UnusedTempFileName


logger = logging.getLogger(__name__)
options = Options()


class SuperExternalMethod(SimProcedure):
    def __init__(self, executor, **kwargs):
        super().__init__(**kwargs)

        self.executor: ExternalMethodCommand = executor

    def run(self, this, selector, args, dispatch, object, reference):
        """IOUserClient::externalMethod(unsigned int, IOExternalMethodArguments*,
        IOExternalMethodDispatch*, OSObject*, void*)
        """
        logger.debug("call IOUserClient::externalMethod %s", dispatch)
        if not self.state.solver.symbolic(dispatch):
            # probably only one dispatch function
            cmd = Extract(31, 0, selector.to_claripy())
            ptr = self.state.solver.eval(dispatch)
            if ptr == 0:  # It will invoke getTargetAndMethodForIndex
                # TODO: combine two dispatch tables!!
                return

            logger.debug("cmd: %s (%#x)", cmd, self.state.solver.eval(cmd))
            table = self.executor.new_method_table(cmd)
            i = self.state.solver.min(cmd)
            succeed, m = self.executor.get_method(self.state, ptr, i, isCustom=False)
            if succeed:
                table.addMethod(m)
                self.executor._func_table = table
                self.executor.abort()
        else:
            self.executor._identify_dispatch_table(self.state, dispatch, 8, isCustom=False)


class ExternalMethodCommand(
    ExternalMethodExecutor,
    CommandIdentificationPlugin,
):
    def __init__(self, target, syscall: IOConnectCallMethod, binary, kext, service, client, entry=0, **kwargs):
        super().__init__(
            target, syscall, binary,
            kext, service, client,
            entry=entry,
            command_keys=(IOConnectCallMethod.ARG_SELECTOR, 32),
            # check_kernel=False, # SymbolizationPlugin
            **kwargs,
        )

    def new_method_table(self, selector: Base) -> DispatchTable:
        return DispatchTable(selector)

    def new_method(self, state: Optional[SimState], ptr: TargetAddress, addr: Address, cmd: int, isCustom: bool) -> Method:
        """ Conventions in IOKit development: If it calls default externalMethod,
        we could extract the argument according to its type (IOExternalMethodDispatch).
        Otherwise, we only retrieve the pointer.
        struct IOExternalMethodDispatch {
            IOExternalMethodAction function;
            uint32_t               checkScalarInputCount;
            uint32_t               checkStructureInputSize;
            uint32_t               checkScalarOutputCount;
            uint32_t               checkStructureOutputSize;
        };
        """
        if isCustom:
            return Method(addr.module, addr.address, cmd)

        scalarInputCount = state.solver.eval(
            state.mem[ptr+0x8].uint32_t.resolved)
        structInputSize = state.solver.eval(
            state.mem[ptr+0xc].uint32_t.resolved)
        scalarOutputCount = state.solver.eval(
            state.mem[ptr+0x10].uint32_t.resolved)
        structOutputSize = state.solver.eval(
            state.mem[ptr+0x14].uint32_t.resolved)
        return ExternalMethodDispatch(
            addr.module, addr.address, cmd,
            # TODO: get the symbol name?
            # sym = executor.proj.loader.find_symbol(offset)
            None,
            scalarInputCount=scalarInputCount,
            structInputSize=structInputSize,
            scalarOutputCount=scalarOutputCount,
            structOutputSize=structOutputSize
        )

    def pre_execute(self, state):
        super().pre_execute(state)

        addr = self.getFuncAddr("IOUserClient::externalMethod")
        state.project.hook(addr, SuperExternalMethod(self), length=0)


class IOCTLCommandExecutor(
    LinuxStaticSyscallExecutor,
    LinuxCommandIdentificationPlugin,
):
    """Executor to extract all valid values for command identifier"""

    def __init__(self, target, syscall: IOCTLMethod, binary, entry: Address, **kwargs):
        super().__init__(
            target,
            binary,
            entry,
            syscall=syscall,
            command_keys=(IOCTLMethod.ARG_CMD, 32),
            **kwargs
        )


class IOCTLDynamicCommandExecutor(
    LinuxDyanmicSyscallExecutor,
    LinuxCommandIdentificationPlugin,
):
    def __init__(self, target, syscall: IOCTLMethod, binary, entry, **kwargs):
        super().__init__(
            target, binary, entry,
            syscall=syscall,
            command_keys=(IOCTLMethod.ARG_CMD, 32),
            **kwargs
        )


class LinuxWriteCommandExtractor(
    LinuxStaticSyscallExecutor,
    LinuxCommandIdentificationPlugin,
):
    def __init__(self, target, syscall: SysWrite, binary, entry: Address, **kwargs):
        super().__init__(
            target,
            binary,
            entry,
            syscall=syscall,
            **kwargs,
        )


class LinuxWriteDynamicCommandExtractor(
    LinuxDyanmicSyscallExecutor,
    LinuxCommandIdentificationPlugin,
):
    def __init__(self, target, syscall: SysWrite, binary, entry, **kwargs):
        super().__init__(
            target, binary, entry,
            syscall=syscall,
            **kwargs
        )


class CommandExtractor(BaseModelAnalysis):
    def default_dispatcher(self, executor: CommandIdentificationPlugin):
        dispatcher: MethodTable = executor.new_method_table(None)
        return dispatcher

    def _execute_syscall(self, syscall: Syscall, model: SyscallModel, testcase: Optional[TestCase] = None, **kwargs) -> None:
        executor = self.get_executor(syscall, model, testcase=testcase, **kwargs)
        executor.run()

        assert isinstance(executor, CommandExtractInterface)
        model.dispatcher = executor.get_method_table() or self.default_dispatcher(executor)
        model.initialize()

        self.model.reset_mapping()

    def _run(self, model_num: int, model: SyscallModel) -> None:
        syscall = model.get_any_syscall()
        if not model.initialized():
            logger.info("Start to extract commands")
            try:
                self.execute_syscall(syscall, model)
            except InvalidTestcaseError:
                logger.info("Switch to static executor for this syscall")
                self.dynamic = False
                self.execute_syscall(syscall, model)


class LinuxCommandExtractor(CommandExtractor):
    def get_executor(self, syscall: Syscall, model: SyscallModel, **kwargs) -> BaseExecutor:
        if syscall.CallName == "ioctl":
            executor_clazz = IOCTLDynamicCommandExecutor if self.dynamic else IOCTLCommandExecutor
        elif syscall.CallName == "write":
            executor_clazz = LinuxWriteDynamicCommandExtractor if self.dynamic else LinuxWriteCommandExtractor
        else:
            raise NotImplementedError()

        executor = executor_clazz(
            self.target,
            syscall,
            self.binary,
            model.entry,
            check_kernel=True,
            # debug=True,
            **kwargs,
        )
        return executor


class IOKitCommandExtractor(CommandExtractor):
    def __init__(self, target: Target, model: BaseModel, binary: str, service: Service, client: UserClient, **kwargs) -> None:
        super().__init__(target, model, client.externalMethod != 0, binary, **kwargs)

        self.service = service
        self.client = client

    def prepare_testcase(self, syscall: Syscall, isVMRunning: bool, **kwargs) -> Optional[TestCase]:
        # Generate testcase that will trigger externalMethod
        poc = UnusedTempFileName(".syz")
        genServicePoc(self.service.metaClass, self.client.type, poc)
        executable = UnusedTempFileName("_poc")
        self.target.build_poc(poc, executable)

        with open(poc, "r") as fp:
            content = fp.read()
        os.unlink(poc)
        return TestCase(executable, ["sudo", executable], syzprog=content)

    def get_executor(self, syscall: Syscall, model: SyscallModel, **kwargs) -> BaseExecutor:
        if not self.client.externalMethod:
            # use static analysis to get dispatch table from getTargetAndMethodForIndex
            executor = GetTargetAndMethodExecutor(
                self,
                self.binary,
                self.service,
                self.client,
            )
        else:
            executor = ExternalMethodCommand(
                self.target,
                syscall,
                self.binary,
                model.entry.module,
                self.service,
                self.client,
                model.entry.address,
                **kwargs,
            )
        return executor
