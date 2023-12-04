
from functools import lru_cache
import copy
import logging
import os
import subprocess
import angr
from typing import Callable, List, Optional, Tuple

from angr import BP_BEFORE, Project
from angr.errors import SimConcreteRegisterError
from angr.concretization_strategies import SimConcretizationStrategyRange
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from archinfo import ArchAArch64, ArchAMD64
from syzgen.analysis.explore import BFSExplore
from syzgen.analysis.plugins.concretization import PointerConcretizationPlugin
from syzgen.analysis.plugins.constraints import ConstraintReason, add_one_constraint
from syzgen.analysis.plugins.fork_profile import ForkProfilePlugin
from syzgen.analysis.plugins.signature import FunctionSignaturePlugin
from syzgen.analysis.plugins.skip import SkipFunctionPlugin
from syzgen.analysis.plugins.static_symbolization import StaticSymbolizationPlugin
from syzgen.analysis.plugins.ud2 import InstructionHandler

from syzgen.config import Options
from syzgen.executor import BaseExecutor, ExecutionMode
from syzgen.executor.concretize import SimConcretizationStrategyMin
from syzgen.models import FuncModel
from syzgen.models.android import AndroidModel
from syzgen.models.linux import LinuxModel

from syzgen.debugger.proxy import DebuggerConcreteTarget, Proxy, ProxyException
from syzgen.kext.macho import LoadVMLinux
from syzgen.parser.models import Address
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import ConstType, FlagType, PtrDir, PtrType, RangeType, StructType, Type
from syzgen.target import Target
from syzgen.utils import any2int

logger = logging.getLogger(__name__)
options = Options()

InitStateFunc = Callable[[SimState, BaseExecutor], SimState]

#
# in-vivo symbolic execution
#

class TestCase:
    def __init__(self, path: str, cmds: List[str], need_copy: bool=True, syzprog: str="") -> None:
        # path to the program in the local host machine
        self.proc_path = path
        self.proc_name = os.path.basename(path)
        self.cmds = cmds

        # We need to copy the program to the guest machine
        self.need_copy = need_copy
        self.syzprog = syzprog

    def replace(self, dst: str) -> "TestCase":
        """replace the path to the program in the guest machine"""
        t = copy.deepcopy(self)
        for i, each in enumerate(t.cmds):
            if each == self.proc_path:
                t.cmds[i] = dst
        return t

    def unlink(self) -> None:
        if self.proc_path.endswith("_poc"):
            os.unlink(self.proc_path)


class Executor(BaseExecutor):
    """
    Under-context static analysis: perform static analysis after dynamic execution in order to 
    resolve most function pointers.
    Note: Similar to symbolic execution, but we optimize it to cater our purpose.
    """

    MODE = ExecutionMode.DYNAMIC

    def __init__(
        self,
        target,
        binary: str,
        entry: Address,
        syscall: Optional[Syscall] = None,
        model: Optional[FuncModel]=None,
        testcase: Optional[TestCase] = None,
        **kwargs
    ):
        assert syscall
        assert testcase

        self.entry = entry
        self.proxy: Proxy = self.prepare_proxy(target, testcase, syscall, kwargs.pop("debug", False)) 

        super().__init__(
            target,
            binary,
            model=model,
            concrete_target=DebuggerConcreteTarget(self.proxy),
            syscall=syscall,
            **kwargs,
        )

    def onVexLift(self, state):
        # avoid concrete_load in angr.engines.vex.lifter.VEXLifter
        try:
            state.inspect.vex_lift_buff = state.solver.eval(state.memory.load(
                state.inspect.vex_lift_addr,
                state.inspect.vex_lift_size,
                inspect=False,
            ), cast_to=bytes)
        except Exception:
            logger.error("failed to lift code at %s", state.inspect.vex_lift_addr)
            from IPython import embed; embed()

    def getInitState(self) -> SimState:
        # target = DebuggerConcreteTarget(self.proxy)
        state = super().getInitState()
        state.inspect.b('vex_lift', when=BP_BEFORE, action=self.onVexLift)
        # state.memory.mem._memory_backer.set_concrete_target(target)

        # synchronize registers (see state.concrete.sync)
        setattr(state.regs, "cc_ndep", 0)  # special register
        for reg in state.arch.register_list:
            # set default value for all registers
            setattr(state.regs, reg.name, 0)
            if (reg.concrete and reg.general_purpose) or reg.name == "gs":
                try:
                    reg_val = self.proj.concrete_target.read_register(reg.name)
                    setattr(state.regs, reg.name, reg_val)
                    logger.debug("sync %s: 0x%x", reg.name, reg_val)
                except SimConcreteRegisterError as e:
                    logger.debug("Failed to read register: %s", e)
                    raise ProxyException("Failed to sync register")

        # set concretization strategies
        # Taking the max value often leads to invalid address
        state.memory.write_strategies = [
            SimConcretizationStrategyRange(128),
            # SimConcretizationStrategyMax
            SimConcretizationStrategyMin(),
        ]
        state.memory.read_strategies = [
            SimConcretizationStrategyRange(2048),
            # SimConcretizationStrategySolutions(512),
            # SimConcretizationStrategyMax
            SimConcretizationStrategyMin(),
        ]

        state.callstack.func_addr = state.addr
        # ensure it halts when finishing executing the entry function
        self.setDeadEnd(state)
        return state

    def setDeadEnd(self, state):
        # set return address
        ret_addr = self.proj.simos.return_deadend
        # Assume we just run into this function and stack pointer is not tampered.
        # terminate when this function is finished.
        logger.debug("reg rsp: %s", state.regs.sp)
        # print(state.mem[state.regs.sp].uint64_t.resolved)
        state.memory.store(state.regs.sp, state.solver.BVV(
            ret_addr, 64), endness=state.arch.memory_endness, inspect=False)

    def prepare_proxy(self, target: Target, testcase: TestCase, syscall: Syscall, debug_vm: bool):
        """Setup a debugger using the given testcase"""
        def reach(_proxy: Proxy):
            while True:
                logger.debug("hit the breakpoint!")
                if self.isTargetSyscall(_proxy, syscall):
                    break
                _proxy.continue_run()
                logger.debug("It is not the target, continue...")
                _proxy.wait_breakpoint()

        proxy = target.setup_proxy(
            self.entry,
            testcase.proc_name,
            cmds=testcase.cmds,
            func=reach,
            debug=debug_vm,
        )
        return proxy

    def isTargetArgument(self, proxy: Proxy, typ: Type, val: int) -> bool:
        if typ.type in {"resource", "buffer", "known"}:
            return True

        if isinstance(typ, ConstType):
            if val != typ.getData():
                return False
        elif isinstance(typ, PtrType):
            # if not isValidPointer(val):
            #     return False
            if typ.dir&PtrDir.DirOut:
                return True
            if typ.ref:
                if isinstance(typ.ref, StructType):
                    return self.isTargetArgument(proxy, typ.ref, val)
                if typ.ref.size > 8: # FIXME
                    return True
                val = proxy.read_memory(val, typ.ref.size)
                if val is None:
                    return False
                val = any2int(val)
                return self.isTargetArgument(proxy, typ.ref, val)
        elif isinstance(typ, FlagType):
            if val not in typ.values:
                return False
        elif isinstance(typ, RangeType):
            if not typ.min <= val <= typ.max:
                return False
        elif isinstance(typ, StructType):
            for field in typ.fields:
                if field.size > 8:
                    continue
                _val = any2int(proxy.read_memory(val + field.offset, field.size))
                if not self.isTargetArgument(proxy, field, _val):
                    return False
        return True

    def isTargetSyscall(self, proxy: Proxy, syscall: Syscall) -> bool:
        return True


class SingleFunctionExecutor(
    BaseExecutor,
    SkipFunctionPlugin,
):
    def __init__(self, target, binary: str, model = None, concrete_target=None, **kwargs):
        super().__init__(
            target, binary, model, concrete_target,
            skip_all_functions=True,
            first_call=False, # do not skip the initial function
            **kwargs
        )
        self.disable_plugin(FunctionSignaturePlugin)


#
# static symbolic execution
#
# class StaticExecutor(BaseExecutor):
#     """Perform symbolic execution on a single function
#     """

#     def __init__(self, binary, func, start, end=None):
#         super().__init__(binary)
#         self._func = func
#         self._start = start
#         self._end = end if end else self._start + self.getFuncSize(func)
#         self.queue = deque()
#         logger.debug("%s %s", hex(self._start), hex(self._end))

#         # Get vtables for all class
#         self.metaClazz = parse_vtables(self.proj)

#     def getInitState(self):
#         # FIX relocation symbols
#         state = super().getInitState()
#         return self.proj.factory.call_state(self._start, base_state=state)

#     def run(self):
#         state = self.getInitState()
#         self.pre_execute(state)

#         self.queue.append(state)
#         while self.queue and not self.should_abort:
#             cur = self.queue.popleft()
#             for work in self.execute(cur):
#                 logger.debug("add one work 0x%x" % work.addr)
#                 self.queue.append(work)

#         return self.post_execute()

#     def handle_state(self, state, block):
#         raise Exception("handle_state is not implemented")

#     def execute(self, state):
#         ret = []
#         if not self._start <= state.addr < self._end:
#             return ret

#         node = self.proj.factory.block(state.addr)
#         if node is None:
#             return ret

#         num_inst = None if node is None else len(node.instruction_addrs)
#         logger.debug("Executing %#x: %d", state.addr,
#                      len(node.instruction_addrs))
#         sim_successors = self.proj.factory.successors(state, num_inst=num_inst)
#         isCall = False if node is None else node.capstone.insns[-1].mnemonic == 'call'
#         nxt_addr = node.addr + node.size

#         todo = []
#         for succ in sim_successors.flat_successors:
#             if self.handle_state(succ, node):
#                 # stop
#                 continue

#             # Because we did not fix relocatable call target, some call instructions calling
#             # external functions may seem to jump to next instruction.
#             if isCall or not self._start <= succ.addr < self._end:
#                 # jmp can also call other functions but it doesn't return
#                 succ.regs.ip = nxt_addr if isCall else 0
#                 succ.regs.rax = state.solver.BVS("ret_value", 64)

#             todo.append(succ)

#         if isCall and len(todo) > 128:
#             todo = sim_successors[:128]

#         for succ in sim_successors.unconstrained_successors:
#             # deference unknown function ptr results in too many successors
#             if isCall:
#                 succ.regs.ip = nxt_addr  # skip this instruction
#                 succ.regs.rax = state.solver.BVS("ret_value", 64)
#             else:
#                 succ.regs.ip = 0  # no need to continue

#         return todo + sim_successors.unconstrained_successors

#     def pre_execute(self, state):
#         pass

#     def post_execute(self):
#         pass

#     #
#     # Utility
#     #
#     def getFuncSize(self, func):
#         lldb = DbgHelper(self.filename)
#         return lldb.getFuncSize(self.proj, func.name, func.relative_addr)


class LinuxStaticExecutor(
    BaseExecutor,
    PointerConcretizationPlugin,
    ForkProfilePlugin,
    InstructionHandler,
    StaticSymbolizationPlugin,
):
    """Static symbolic execution for ioctl in contrast to in-vivo
    symbolic execution where we use debugger to get concrete memory state.
    """

    def __init__(self, target, binary: str, entry: Address, **kwargs):
        if target.get_os() == "linux":
            model = LinuxModel()
        elif target.get_os() == "android":
            model = AndroidModel()
        else:
            raise NotImplementedError()

        libs = kwargs.pop("libs", [])
        super().__init__(
            target,
            binary,
            model=model,
            libs=libs,
            **kwargs
        )

        self.entry: Address = entry
        self._loaded_project = LoadVMLinux(binary, self._func_model, libs=libs)

    def getInitState(self) -> SimState:
        state = super().getInitState()

        if isinstance(state.arch, ArchAMD64):
            # setup gs
            # current
            # mov    %gs:0x16d00,%rax
            gs_addr = self.global_alloctor.alloc(length=0x20000)
            gs_sym = state.solver.BVS(
                'gs',
                64,
                key=('gs', 8),
                eternal=True,
            )
            add_one_constraint(
                self, state,
                gs_sym == gs_addr,
                reason=ConstraintReason.SYMBOLIZATION
            )
            state.regs.gs = gs_sym

        state.memory.write_strategies = [
            SimConcretizationStrategyMin(),
        ]
        state.memory.read_strategies = [
            SimConcretizationStrategyRange(2048),
            SimConcretizationStrategyMin(),
        ]

        state = self.proj.factory.call_state(
            self.getTargetAddr(self.entry.address, self.entry.module),
            base_state=state
        )
        if isinstance(state.arch, ArchAArch64):
            # not sure why it does not terminate
            state.project.hook(
                state.solver.eval(state.regs.lr),
                angr.SIM_PROCEDURES["stubs"]["PathTerminator"](),
                0,
            )
        return state

    @lru_cache()
    def get_debug_info(self, addr: int) -> str:
        if not addr:
            return ""
        sym = self.proj.loader.find_symbol(addr, fuzzy=True)
        if sym:
            name = os.path.basename(sym.owner.binary)
            if name != "vmlinux":
                return f"{name}:{sym.name}({sym.relative_addr:#x})"
        ret = subprocess.run(
            ["addr2line", hex(addr), "-e", self.filename], stdout=subprocess.PIPE)
        return ret.stdout.decode("utf-8").strip()

    def getBaseAddr(self, ip, target=None) -> Tuple[str, int]:
        # if 0xffffffff80000000 <= ip <= self.proj.loader.main_object.max_addr:
        return "kernel", ip

    def getTargetAddr(self, offset, target="kernel"):
        assert target == "kernel"
        return offset

    def load_project_by_addr(self, addr: int) -> Tuple[str, int, Optional[Project]]:
        module, off = self.getBaseAddr(addr)
        return module, off, self._loaded_project

    def execute(self, simgr: SimulationManager) -> SimulationManager:
        explorer = self.explorer or BFSExplore
        exp = explorer(self, verbose=True)
        # exp = DFSExplore(self, verbose=True)
        # exp = CoverageExplore(self, verbose=True)
        # exp = CombinedExplore(self, verbose=True)
        # /usr/include/asm-generic/errno-base.h
        return exp.explore(simgr, timeout=self.timeout)


class LinuxDynamicExecutor(Executor):
    def __init__(self, target, binary: str, entry: Address, syscall: Syscall = None, **kwargs):
        super().__init__(
            target,
            binary,
            entry,
            syscall=syscall,
            model=LinuxModel(),
            **kwargs
        )

        self._loaded_project = LoadVMLinux(binary, self._func_model)

    @lru_cache()
    def get_debug_info(self, addr: int) -> str:
        if addr == 0:
            return ""
        ret = subprocess.run(
            ["addr2line", hex(addr), "-e", self.filename], stdout=subprocess.PIPE)
        return ret.stdout.decode("utf-8").strip()

    # no kaslr
    def getBaseAddr(self, ip, target=None) -> Tuple[str, int]:
        if 0xffffffff80000000 <= ip <= self.proj.loader.main_object.max_addr:
            return "kernel", ip
        return "", 0

    def getTargetAddr(self, offset, target="kernel"):
        assert target == "kernel"
        return offset

    def load_project_by_addr(self, addr: int) -> Tuple[str, int, Optional[Project]]:
        module, off = self.getBaseAddr(addr)
        return module, off, self._loaded_project

    def execute(self, simgr: SimulationManager) -> SimulationManager:
        explorer = self.explorer or BFSExplore
        exp = explorer(self, verbose=True)
        return exp.explore(simgr, timeout=self.timeout)
