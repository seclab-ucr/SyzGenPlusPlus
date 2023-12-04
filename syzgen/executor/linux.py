
from angr.calling_conventions import DefaultCC
from angr.sim_state import SimState
from typing import Dict
from syzgen.analysis.plugins.concretization import PointerConcretizationPlugin
from syzgen.analysis.plugins.constraints import ConstraintReason, add_one_constraint
from syzgen.analysis.plugins.fork_profile import ForkProfilePlugin
from syzgen.analysis.plugins.symbolization import SymbolizationPlugin
from syzgen.analysis.plugins.syscall import SyscallPlugin
from syzgen.analysis.plugins.ud2 import InstructionHandler
from syzgen.config import Options
from syzgen.executor import BaseExecutor
from syzgen.executor.executor import InitStateFunc, LinuxDynamicExecutor, LinuxStaticExecutor
from syzgen.parser.syscalls.ioctl import IOCTLMethod
from syzgen.parser.syscalls.write import SysWrite


options = Options()


def setup_gs(state: SimState, executor: BaseExecutor) -> SimState:
    assert isinstance(executor, SyscallPlugin)
    state.regs.gs = executor.assign_symbolic_tag(state, "gs", state.regs.gs, 8)
    return state


def setup_ioctl_dev_arguments(state: SimState, executor: BaseExecutor) -> SimState:
    assert isinstance(executor, SyscallPlugin)
    cc = DefaultCC[state.arch.name](state.arch)
    # setup arguments
    dev_addr, _ = executor.alloc_argument(state, "dev")
    state.registers.store(cc.ARG_REGS[0], dev_addr)

    file_addr, _ = executor.alloc_argument(state, "file")
    state.registers.store(cc.ARG_REGS[1], file_addr)
    # state.regs.rdi = file_addr

    _, cmd = executor.alloc_argument(state, IOCTLMethod.ARG_CMD)
    state.registers.store(cc.ARG_REGS[2], cmd)
    # state.regs.esi = cmd

    addr, addr_sym = executor.alloc_argument(state, IOCTLMethod.ARG_ARG, track_boundary=True)
    state.registers.store(cc.ARG_REGS[3], addr if addr else addr_sym)
    # state.regs.rdx = addr if addr else addr_sym

    return state


def setup_ioctl_arguments(state: SimState, executor: BaseExecutor) -> SimState:
    assert isinstance(executor, SyscallPlugin)
    cc = DefaultCC[state.arch.name](state.arch)
    # setup arguments
    file_addr, _ = executor.alloc_argument(state, "file")
    state.registers.store(cc.ARG_REGS[0], file_addr)
    # state.regs.rdi = file_addr

    _, cmd = executor.alloc_argument(state, IOCTLMethod.ARG_CMD)
    state.registers.store(cc.ARG_REGS[1], cmd)
    # state.regs.esi = cmd

    addr, addr_sym = executor.alloc_argument(state, IOCTLMethod.ARG_ARG, track_boundary=True)
    state.registers.store(cc.ARG_REGS[2], addr if addr else addr_sym)
    # state.regs.rdx = addr if addr else addr_sym

    return state


def setup_ioctl_arguments_dynamic(state: SimState, executor: SyscallPlugin) -> SimState:
    assert isinstance(executor, SyscallPlugin)
    cc = DefaultCC[state.arch.name](state.arch)
    # assign a tag to the first argument
    # file_addr = state.regs.rdi
    file_addr = state.registers.load(cc.ARG_REGS[0], 8)
    file_sym = executor.assign_symbolic_tag(state, "file", file_addr, 8)
    state.registers.store(cc.ARG_REGS[0], file_sym)
    # state.regs.rdi = file_sym

    _, cmd = executor.alloc_argument(state, IOCTLMethod.ARG_CMD)
    state.registers.store(cc.ARG_REGS[1], cmd)
    # state.regs.esi = cmd

    concrete_arg = state.solver.eval(state.registers.load(cc.ARG_REGS[2], 8, endness=state.arch.memory_endness))
    addr, addr_sym = executor.alloc_argument(state, IOCTLMethod.ARG_ARG, val=concrete_arg, track_boundary=True)
    state.registers.store(cc.ARG_REGS[2], addr if addr else addr_sym)
    # state.regs.rdx = addr if addr else addr_sym

    return state


def setup_write_arguments(state: SimState, executor: BaseExecutor) -> SimState:
    """ssize_t (*write) (struct file *, const char __user *, size_t, loff_t *);"""
    assert isinstance(executor, SyscallPlugin)
    cc = DefaultCC[state.arch.name](state.arch)
    file_addr, _ = executor.alloc_argument(state, "file")
    state.registers.store(cc.ARG_REGS[0], file_addr)
    # state.regs.rdi = file_addr

    addr, _ = executor.alloc_argument(state, SysWrite.ARG_DATA)
    state.registers.store(cc.ARG_REGS[1], addr)
    # state.regs.rsi = addr

    _, size = executor.alloc_argument(state, SysWrite.ARG_SIZE)
    state.registers.store(cc.ARG_REGS[2], size)
    # state.regs.rdx = size

    state.registers.store(cc.ARG_REGS[3], 0)
    # state.regs.rcx = 0

    return state


def setup_write_arguments_dynamic(state: SimState, executor: BaseExecutor) -> SimState:
    assert isinstance(executor, SyscallPlugin)
    # assign a tag to the first argument
    cc = DefaultCC[state.arch.name](state.arch)
    file_addr = state.registers.load(cc.ARG_REGS[0], 8)
    file_sym = executor.assign_symbolic_tag(state, "file", file_addr, 8)
    state.registers.store(cc.ARG_REGS[0], file_sym)
    # state.regs.rdi = file_sym

    addr, _ = executor.alloc_argument(state, SysWrite.ARG_DATA)
    state.registers.store(cc.ARG_REGS[1], addr)
    # state.regs.rsi = addr

    _, size = executor.alloc_argument(state, SysWrite.ARG_SIZE)
    state.registers.store(cc.ARG_REGS[2], size)
    # state.regs.rdx = size

    state.registers.store(cc.ARG_REGS[3], 0)
    # state.regs.rcx = 0

    return state


class LinuxStaticSyscallExecutor(
    LinuxStaticExecutor,
    SyscallPlugin,
):
    """
    Base executor for linux syscall with plugins to setup context
    """

    # FIXME: auto init it
    Initializer: Dict[str, InitStateFunc] = {
        "ioctl": setup_ioctl_arguments,
        "write": setup_write_arguments,
        "ioctl_dev": setup_ioctl_dev_arguments,
    }

    def getInitState(self) -> SimState:
        state = super().getInitState()
        name = self.syscall.NAME + options.syscall_suffix
        if name in LinuxStaticSyscallExecutor.Initializer:
            state = LinuxStaticSyscallExecutor.Initializer[name](state, self)
        else:
            raise NotImplementedError()
        return state


class LinuxDyanmicSyscallExecutor(
    LinuxDynamicExecutor,
    PointerConcretizationPlugin,
    SymbolizationPlugin,
    ForkProfilePlugin,
    InstructionHandler,
    SyscallPlugin,
):
    Initializer: Dict[str, InitStateFunc] = {
        "ioctl": setup_ioctl_arguments_dynamic,
        "write": setup_write_arguments_dynamic,
    }

    def getInitState(self) -> SimState:
        state = super().getInitState()
        if self.syscall.NAME in LinuxDyanmicSyscallExecutor.Initializer:
            state = setup_gs(state, self)
            state = LinuxDyanmicSyscallExecutor.Initializer[self.syscall.NAME](state, self)
        else:
            raise NotImplementedError()
        return state
