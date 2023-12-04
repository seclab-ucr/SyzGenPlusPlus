
import logging
from typing import Dict

from angr.sim_state import SimState
from claripy.ast.base import Base

from syzgen.analysis.interface import InterfaceDiscovery, InterfaceRecovery
from syzgen.analysis.plugins.constraints import add_one_constraint
from syzgen.analysis.plugins.dependency import RecordAccessPathPlugin
from syzgen.analysis.plugins.detect_output import OutputDetectorPlugin
from syzgen.analysis.plugins.error_path import DetectErrorPathPlugin
from syzgen.analysis.plugins.loop_limiter import LoopLimiterPlugin
from syzgen.analysis.plugins.path_limiter import PathLimiterPlugin
from syzgen.analysis.plugins.recovery import InputRecoveryPlugin
from syzgen.analysis.plugins.relaxation import ConstraintRelaxationPlugin
from syzgen.analysis.plugins.skip import SkipFunctionPlugin
from syzgen.analysis.plugins.symbolization import SymbolizationPlugin
from syzgen.analysis.plugins.visit import VisitedFunctionsPlugin
from syzgen.config import Options
from syzgen.executor import BaseExecutor
from syzgen.executor.linux import LinuxDyanmicSyscallExecutor, LinuxStaticSyscallExecutor
from syzgen.parser.models import Address, BaseModel, SyscallModel
from syzgen.parser.models.ioctl import IOCTLModel, WriteModel
from syzgen.parser.syscalls import Syscall, SyscallStatus
from syzgen.parser.syscalls.read import SysRead

logger = logging.getLogger(__name__)
options = Options()


def LinuxErrorCode(val: int) -> bool:
    # /usr/include/asm-generic/errno-base.h and
    # /usr/include/asm-generic/errno.h
    # include/linux/errno.h
    val = val & 0xffffffff
    return 0xffffff7b <= val <= 0xffffffff or 0xfffffded <= val <= 0xfffffe00


def LinuxNotErrorCode(executor: BaseExecutor, state: SimState, ret: Base) -> None:
    val = ret & 0xffffffff
    add_one_constraint(executor, state, 0xfffffded > val)
    add_one_constraint(executor, state, val >= 0)


class LinuxStaticSyscallRecoveryExecutor(
    LinuxStaticSyscallExecutor,
    LoopLimiterPlugin,
    PathLimiterPlugin,
    SymbolizationPlugin,
    OutputDetectorPlugin,
    RecordAccessPathPlugin,
    InputRecoveryPlugin,
    ConstraintRelaxationPlugin,
    DetectErrorPathPlugin,
    VisitedFunctionsPlugin,
):
    def __init__(self, target, binary: str, entry: Address, syscall: Syscall, **kwargs):
        super().__init__(
            target, binary, entry,
            syscall=syscall,
            check_kernel=True,  # SymbolizationPlugin
            **kwargs
        )

    def isErrorCode(self, val: int) -> bool:
        return LinuxErrorCode(val)

    def notErrorCode(self, state: SimState, ret: Base) -> None:
        LinuxNotErrorCode(self, state, ret)


class LinuxDynamicSyscallRecoveryExecutor(
    LinuxDyanmicSyscallExecutor,
    LoopLimiterPlugin,
    PathLimiterPlugin,
    SymbolizationPlugin,
    OutputDetectorPlugin,
    RecordAccessPathPlugin,
    InputRecoveryPlugin,
    ConstraintRelaxationPlugin,
    DetectErrorPathPlugin,
    VisitedFunctionsPlugin,
):
    def __init__(self, target, binary, entry, syscall, **kwargs):
        super().__init__(
            target, binary, entry,
            syscall=syscall,
            check_kernel=True,  # SymbolizationPlugin
            **kwargs
        )

    def isErrorCode(self, val: int) -> bool:
        return LinuxErrorCode(val)

    def notErrorCode(self, state: SimState, ret: Base) -> None:
        LinuxNotErrorCode(self, state, ret)


class LinuxStaticStructRecoveryExecutor(
    LinuxStaticSyscallExecutor,
    SymbolizationPlugin,
    SkipFunctionPlugin,
    InputRecoveryPlugin,
):
    def __init__(self, target, binary, entry: Address, **kwargs):
        super().__init__(
            target, binary, entry,
            check_kernel=True,
            structOnly=True,
            **kwargs
        )


class LinuxDynamicStructRecoveryExecutor(
    LinuxDyanmicSyscallExecutor,
    SymbolizationPlugin,
    SkipFunctionPlugin,
    InputRecoveryPlugin,
):
    def __init__(self, target, binary, entry: Address, **kwargs):
        super().__init__(
            target, binary, entry,
            check_kernel=True,
            structOnly=True,
            **kwargs
        )


class LinuxInterfaceRecovery(InterfaceRecovery):
    def get_struct_executor(self, syscall: Syscall, model: SyscallModel, **kwargs) -> BaseExecutor:
        executor_clazz = LinuxDynamicStructRecoveryExecutor if self.dynamic else LinuxStaticStructRecoveryExecutor
        return executor_clazz(
            self.target,
            self.binary,
            model.entry,
            syscall=syscall,
            **kwargs,
        )

    def get_executor(self, syscall: Syscall, model: SyscallModel, **kwargs):
        if syscall.status == SyscallStatus.OUTPUT:
            # no type recovery and skip certain functions
            return self.get_struct_executor(syscall, model, **kwargs)

        executor_clazz = LinuxDynamicSyscallRecoveryExecutor if self.dynamic else LinuxStaticSyscallRecoveryExecutor
        return executor_clazz(
            self.target,
            self.binary,
            model.entry,
            syscall,
            module_name=self.model.name,
            structOnly=syscall.status == SyscallStatus.INCOMPLETE,
            **kwargs,
        )

    def handle_new_fd(self, model: BaseModel, module_name: str) -> None:
        # placeholder address
        ioctl: IOCTLModel = IOCTLModel(module_name, Address("kernel", 0))
        ioctl = model.add_syscall(ioctl)
        ioctl.initialize()


class LinuxInterfaceDiscovery(InterfaceDiscovery):
    def add_syscalls(self, model: SyscallModel, ops: Dict[str, int]):
        if "read" in ops and ops["read"]:
            self.model.add_syscall(SysRead(model.name))
        if "unlocked_ioctl" in ops and ops["unlocked_ioctl"]:
            ioctl = IOCTLModel(model.name, Address("kernel", ops["unlocked_ioctl"]))
            self.model.add_syscall(ioctl)
        if "write" in ops and ops["write"]:
            write = WriteModel(model.name, Address("kernel", ops["write"]))
            self.model.add_syscall(write)
