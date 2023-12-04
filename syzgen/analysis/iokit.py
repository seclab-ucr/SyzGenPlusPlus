
import logging
import os
import time
import angr

from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from claripy.ast.base import Base

from typing import Dict, List, Optional, Tuple, Union
from syzgen.analysis.plugins.fork_profile import ForkProfilePlugin
from syzgen.analysis.plugins.path_limiter import PathLimiterPlugin
from syzgen.parser.models import CommandExtractInterface
from syzgen.analysis.explore import BFSExplore
from syzgen.analysis.interface import InterfaceRecovery
from syzgen.analysis.plugins.concretization import PointerConcretizationPlugin
from syzgen.analysis.plugins.constraints import ConstraintReason, add_one_constraint
from syzgen.analysis.plugins.dependency import RecordAccessPathPlugin
from syzgen.analysis.plugins.error_path import DetectErrorPathPlugin
from syzgen.analysis.plugins.loop_limiter import LoopLimiterPlugin
from syzgen.analysis.plugins.recovery import InputRecoveryPlugin
from syzgen.analysis.plugins.relaxation import ConstraintRelaxationPlugin
from syzgen.analysis.plugins.symbolization import SymbolizationPlugin
from syzgen.analysis.plugins.syscall import SyscallPlugin
from syzgen.analysis.static import parse_client
from syzgen.config import MissingKeyInConfigError, Options

from syzgen.debugger.lldbproxy import LLDBDebugger
from syzgen.debugger.proxy import Proxy
from syzgen.executor.executor import SingleFunctionExecutor
from syzgen.executor.macos import MacExecutor, err_get_code, err_get_system
from syzgen.kext.macho import DispatchTable, Method, Service, UserClient, parse_vtables, read_vtables
from syzgen.models import FuncModel, brkAlloc
from syzgen.parser.models import BaseModel, SyscallModel, TargetAddress
from syzgen.parser.syscalls import Syscall, SyscallStatus
from syzgen.parser.syscalls.iokit import IOConnectCallAsyncMethod, IOConnectCallMethod
from syzgen.parser.types import PtrType
from syzgen.target import Target
from syzgen.utils import any2int, demangle

logger = logging.getLogger(__name__)
options = Options()


class NewUserClient(angr.SimProcedure):
    NO_RET = True

    def __init__(self, executor):
        super().__init__()

        self.executor: ClientExecutor = executor

    def run(self, instance, gMetaClass):
        metaClass = self.state.solver.eval(gMetaClass)
        driver, addr, proj = self.executor.load_project_by_addr(metaClass)
        logger.debug("%s: %#x", driver, addr)
        logger.debug("Call IOUserClient at %#x with %#x" %
              (self.state.addr, metaClass))
        if proj:
            # Check class name
            sym = proj.loader.find_symbol(addr)
            if sym and sym.name.endswith("gMetaClassE"):
                clazz = demangle(sym.name)[:-len("::gMetaClass")]
                logger.debug("%s %#x %s", clazz, addr, sym.name)
                self.executor.addUserClient(self.state, driver, clazz)


class ClientExecutor(MacExecutor):
    """symbolically execute Service::newUserClient to find all returned clients.
    """

    def __init__(
        self,
        target: Target,
        binary: str,
        kext: str,
        serviceName: str,
        entry: int = 0,
        **kwargs
    ):
        self.serviceName = serviceName
        self.userClients: Dict[int, UserClient] = {}

        super().__init__(target, None, binary, kext, entry, **kwargs)

    def prepare_testcase(self, target: Target, syscall: Syscall) -> Tuple[str, List[str]]:
        cmds = [
            "sudo",
            os.path.join(target.baseDir, "testService"),
            self.serviceName,
            "0",
        ]
        return "testService", cmds

    def pre_execute(self, state):
        super().pre_execute(state)
        # newUserClient(this, task* owningTask, void* securityID,
        # unsigned int type, IOUserClient** handler)
        typ = state.solver.BVS("type", 32, key=(
            "newUserClient", "type"), eternal=True)
        state.regs.ecx = typ

        addr = self.getFuncAddr("IOUserClient::IOUserClient")
        self.proj.hook(addr, NewUserClient(executor=self), length=0)

        # IOService::NewUserClient
        addr = self.getFuncAddr("IOService::NewUserClient")
        self.proj.hook(addr, angr.SIM_PROCEDURES["stubs"]["PathTerminator"]())

    def addUserClient(self, state, module, userClient):
        for _, uc in self.userClients.items():
            if uc.metaClass == userClient:
                return

        variables = list(state.solver.get_variables("newUserClient", "type"))
        if len(variables) > 0:
            _, sym_cont = variables[0]
            cmin = state.solver.min(sym_cont)
            logger.debug("add one client %s: %d", userClient, cmin)
            if cmin in self.userClients and self.userClients[cmin] != userClient:
                raise Exception("inconsistent userClient between %s and %s" %
                                (userClient, self.userClients[cmin]))
            uc = UserClient(module, userClient, type=cmin)
            parse_client(self._load_project_by_kext(module), uc)
            self.userClients[cmin] = uc

    def execute(self, simgr: angr.SimulationManager) -> angr.SimulationManager:
        explorer = self.explorer or BFSExplore
        exp = explorer(self, verbose=True)
        simgr = exp.explore(simgr, timeout=self.timeout)
        return simgr

class IOExternalMethodArguments:
    def __init__(self, StateOrProxy: Union[SimState, Proxy], client):
        self.args, self.selector = self.get_arguments_selector(StateOrProxy, client)

    def read_memory(self, StateOrProxy: Union[SimState, Proxy], addr: int, size: int) -> int:
        if isinstance(StateOrProxy, SimState):
            return StateOrProxy.solver.eval(StateOrProxy.memory.load(
                addr,
                size=size,
                inspect=False,
                endness=StateOrProxy.arch.memory_endness
            ))
        else:
            return any2int(StateOrProxy.read_memory(addr, size))

    def get_arguments_selector(self, StateOrProxy: Union[SimState, Proxy], client: UserClient) -> Tuple[int, int]:
        """return the registers that store args and selector. It's trivial if we are
        at the entry of externalMethod since we can simply get them by following the
        calling convention."""
        if client.externalMethod:
            # externalMethod(this, uint32_t selector, IOExternalMethodArguments * args,
            #    IOExternalMethodDispatch * dispatch, OSObject * target, void * reference )
            args = (
                StateOrProxy.solver.eval(StateOrProxy.regs.rdx)
                if isinstance(StateOrProxy, SimState) else
                any2int(StateOrProxy.read_register("rdx"))
            )
            selector = (
                StateOrProxy.solver.eval(StateOrProxy.regs.esi)
                if isinstance(StateOrProxy, SimState) else
                # note: though we only need to read esi, lldb only support reading
                # the whole register.
                any2int(StateOrProxy.read_register("rsi"))&0xffffffff
            )
            # TODO: collect all global variables
        elif client.getTargetAndMethodForIndex:
            # IOUserClient::getTargetAndMethodForIndex(IOService **targetP, UInt32 index)
            try:
                reg_args = options.getConfigKey("reg_args")
                args = (
                    StateOrProxy.solver.eval(StateOrProxy.registers.load(
                        reg_args["reg_name"],
                        inspect=False,
                    )) if isinstance(StateOrProxy, SimState) else
                    any2int(StateOrProxy.read_register(reg_args["reg_name"]))
                )
                selector = (
                    StateOrProxy.solver.eval(StateOrProxy.regs.rdx)
                    if isinstance(StateOrProxy, SimState) else
                    any2int(StateOrProxy.read_register("rdx"))
                )
            except MissingKeyInConfigError as e:
                logger.info(
                    "please run scripts/analyze_externalMethod.py first")
                raise e
        else:
            raise Exception("no newUserClient")

        # image lookup -t IOExternalMethodArguments
        inputCntOffset, inputStructCntOffset, outputCntOffset, outputStructCntOffset = [
            LLDBDebugger.fieldOffset(field, "IOExternalMethodArguments")
            for field in [
                "scalarInputCount",
                "structureInputSize",
                "scalarOutputCount",
                "structureOutputSize"
            ]
        ]
        inputOffset, inputStructOffset, outputOffset, outputStructOffset = [
            LLDBDebugger.fieldOffset(field, "IOExternalMethodArguments")
            for field in [
                "scalarInput",
                "structureInput",
                "scalarOutput",
                "structureOutput",
            ]
        ]
        self.inputCntOffset = inputCntOffset
        self.inputStructCntOffset = inputStructCntOffset
        self.outputCntOffset = outputCntOffset
        self.outputStructCntOffset = outputStructCntOffset
        self.inputOffset = inputOffset
        self.inputStructOffset = inputStructOffset
        self.outputOffset = outputOffset
        self.outputStructOffset = outputStructOffset

        scalarInputCount, structInputSize, scalarOutputCount, structOutputSize = [
            self.read_memory(StateOrProxy, args+offset, 4)
            for offset in [
                inputCntOffset,
                inputStructCntOffset,
                outputCntOffset,
                outputStructCntOffset,
            ]
        ]
        scalarInput, structInput, scalarOutput, structOutput = [
            self.read_memory(StateOrProxy, args+offset, 8)
            for offset in [
                inputOffset,
                inputStructOffset,
                outputOffset,
                outputStructOffset,
            ]
        ]

        logger.debug("scalarInput* %#x", scalarInput)
        logger.debug("scalarInputCount %d", scalarInputCount)
        logger.debug("structInput* %#x", structInput)
        logger.debug("structInputSize %d", structInputSize)
        logger.debug("scalarOutput* %#x", scalarOutput)
        logger.debug("scalarOutputCount %d", scalarOutputCount)
        logger.debug("structOutput %#x", structOutput)
        logger.debug("structOutputSize %d", structOutputSize)

        self.scalarInput = scalarInput
        self.scalarInputCnt = scalarInputCount
        self.structInput = structInput
        self.structInputCnt = structInputSize
        self.scalarOutput = scalarOutput
        self.scalarOutputCnt = scalarOutputCount
        self.structOutput = structOutput
        self.structOutputCnt = structOutputSize

        return args, selector


class ExternalMethodExecutor(
    MacExecutor,
    PointerConcretizationPlugin,
    SymbolizationPlugin,
    SyscallPlugin,
):
    """Executor for the interface:
    externalMethod(this, uint32_t selector, IOExternalMethodArguments * args,
        IOExternalMethodDispatch * dispatch, OSObject * target, void * reference )
    """
    def __init__(self, target, syscall, binary, kext, service, client, entry, **kwargs):
        self.service: Service = service
        self.client: UserClient = client

        super().__init__(
            target, syscall,
            binary,
            kext, entry,
            check_kernel=False, # SymbolizationPlugin
            **kwargs
        )

    def getInitState(self) -> SimState:
        state = super().getInitState()

        args = IOExternalMethodArguments(state, self.client)
        base = args.args

        # assign a tag to the first argument
        userClient_addr = state.regs.rdi
        userClient_sym = state.solver.BVS(
            "userClient", 64,
            key=("userClient", 8),
            eternal=True
        )
        add_one_constraint(
            self,
            state,
            userClient_addr == userClient_sym,
            reason=ConstraintReason.SYMBOLIZATION
        )
        state.regs.rdi = userClient_sym
        logger.debug("symbolize userClient %s, %s", userClient_addr, userClient_sym)

        _, selector = self.alloc_argument(state, IOConnectCallMethod.ARG_SELECTOR)
        state.regs.esi = selector
        # selector is also stored in args
        _selectorOff = LLDBDebugger.fieldOffset(
            "selector", "IOExternalMethodArguments")
        state.mem[base+_selectorOff].uint32_t = selector

        _, scalarInputCnt = self.alloc_argument(state, IOConnectCallMethod.ARG_INPUT_CNT)
        state.memory.store(
            base+args.inputCntOffset,
            scalarInputCnt,
            endness=state.arch.memory_endness,
        )

        # For inputs like ARG_INPUT, ARG_INPUTSTRUCT are already copied to some
        # kernel memory and thus no copy_from_user-like function involved to mark
        # the boundary. Hence, we manually specify it by setting track_boundary.
        self.alloc_argument(
            state,
            IOConnectCallMethod.ARG_INPUT,
            addr=args.scalarInput,
            track_boundary=True,
        )

        _, structInputSize = self.alloc_argument(state, IOConnectCallMethod.ARG_INPUTSTRUCT_CNT)
        state.memory.store(
            base+args.inputStructCntOffset,
            structInputSize,
            endness=state.arch.memory_endness,
        )

        self.alloc_argument(
            state,
            IOConnectCallMethod.ARG_INPUTSTRUCT,
            addr=args.structInput,
            track_boundary=True,
        )

        self.alloc_argument(
            state, IOConnectCallMethod.ARG_OUTPUT_CNT,
            addr=state.solver.eval(base+args.outputCntOffset),
            track_boundary=True,
        )
        self.alloc_argument(
            state, IOConnectCallMethod.ARG_OUTPUTSTRUCT_CNT,
            addr=state.solver.eval(base+args.outputStructCntOffset),
            track_boundary=True,
        )
        return state


class GetTargetAndMethodExecutor(
    SingleFunctionExecutor,
    CommandExtractInterface,
):
    """Executor for Method * getTargetAndMethodForIndex(IOService **targetP, UInt32 index);
    Analyzing the above function to get the dispatch table. Since it is usually a
    simple function, we only need to perform a static analysis on a single function.
    """
    def __init__(self, target, binary: str, service: Service, client: UserClient, **kwargs):
        super().__init__(
            target, binary,
            model=FuncModel(),
            syscall=Syscall("dummy"),
            **kwargs
        )

        self.service = service
        self.client = client
        self.table = None

        # Get vtables for all class
        self.metaClazz = parse_vtables(self.proj)

    def get_method_table(self) -> Optional[DispatchTable]:
        if self.table and len(self.table):
            return self.table
        return None

    def getInitState(self) -> SimState:
        state = super().getInitState()

        self.client_addr, _ = self.alloc_argument(state, "client")
        # First field is vtable
        vtables = read_vtables(
            self.proj, self.metaClazz[self.client.metaClass])
        vtable_addr = brkAlloc(state, len(vtables))
        state.memory.store(vtable_addr, state.solver.BVV(vtables, len(vtables)*8))
        state.memory.store(self.client_addr, state.solver.BVV(vtable_addr, 64), endness=state.arch.memory_endness)

        self.target_addr = brkAlloc(state, 8)
        state.memory.store(self.target_addr, state.solver.BVV(0, 64), inspect=False)

        index = state.solver.BVS("selector", 32, key=("getTargetAndMethodForIndex", "selector"))
        self.table = DispatchTable(index)

        return self.proj.factory.call_state(
            self.client.getTargetAndMethodForIndex,
            self.client_addr,
            self.target_addr,
            index,
            base_state=state
        )

    def getService(self, state):
        """getTargetAndMethodForIndex returns the dispatch func and the second argument stores the corresponding
        service object. There are two possible service objects, one is the current client and the other one is
        the corresponding service.
        """
        service = state.mem[self.target_addr].uint64_t.resolved
        if state.solver.is_true(service == self.client_addr):
            return self.client
        # FIXME: it is not guaranteed.
        return self.service

    def getServiceFunc(self, obj, func):
        """
        IOMethod: disassemble -n shim_io_connect_method_scalarI_structureI
        0xffffff801f9f626e <+78>:  movq   0x8(%r15), %r11   ; r11 = func
        0xffffff801f9f6272 <+82>:  movq   0x10(%r15), %rcx  ; rcx = offset
        ... ...
        0xffffff801f9f6286 <+102>: addq   %rcx, %rsi        ; rsi = object + offset
        0xffffff801f9f6289 <+105>: testb  $0x1, %r11b
        0xffffff801f9f628d <+109>: je     0xffffff801f9f6297        ; <+119> at IOUserClient.cpp:5275:10
        0xffffff801f9f628f <+111>: movq   (%rsi), %rax
        0xffffff801f9f6292 <+114>: movq   -0x1(%r11,%rax), %r11
        """
        meta = self.metaClazz[obj.metaClass]
        if func & 0x1:
            func = (func-1)//8
            return meta.vtables[func][1]
        else:
            sym = self.proj.loader.find_symbol(func)
            return sym.name

    def post_execute(self, simgr: SimulationManager) -> None:
        """Return
        struct IOExternalMethod {
            IOService *         object;
            IOMethod            func;
            IOOptionBits        flags;
            IOByteCount         count0;
            IOByteCount         count1;
        };
        """
        super().post_execute(simgr)

        for state in simgr.deadended:
            expr = state.regs.rax
            logger.debug("returned method %s", expr)
            if not state.solver.symbolic(expr):
                # Probably only one dispatch function
                continue

            service = self.getService(state)
            candidates = state.solver.eval_upto(expr, 256)
            for addr in candidates:
                copy_state = state.copy()
                copy_state.solver.add(expr == addr)
                cmd = copy_state.solver.eval(self.table.selector)
                logger.debug("ptr: %#x, cmd: %#x", addr, cmd)

                func = copy_state.solver.eval(
                    copy_state.mem[addr+0x8].uint64_t.resolved)
                flags = copy_state.solver.eval(
                    copy_state.mem[addr+0x18].uint64_t.resolved)
                count0 = copy_state.solver.eval(
                    copy_state.mem[addr+0x20].uint64_t.resolved)
                count1 = copy_state.solver.eval(
                    copy_state.mem[addr+0x28].uint64_t.resolved)
                logger.debug("func: %#x, flags: %#x, count0: %#x, count1: %#x",
                    func, flags, count0, count1)
                self.table.addExternalMethod(service.module, addr, cmd, self.getServiceFunc(
                    service, func), flags, count0, count1)

    def execute(self, simgr: SimulationManager) -> SimulationManager:
        explorer = self.explorer or BFSExplore
        exp = explorer(self, verbose=True)
        return exp.explore(simgr, timeout=self.timeout)


class IOKitExecutor(
    ExternalMethodExecutor,
    LoopLimiterPlugin,
    PathLimiterPlugin,
    RecordAccessPathPlugin,
    InputRecoveryPlugin,
    ConstraintRelaxationPlugin,
    DetectErrorPathPlugin,
    ForkProfilePlugin,
):
    """Execute IOKit interface"""

    def __init__(
        self,
        target,
        binary: str,
        kext: str,  # target kext
        entry: int,
        syscall: Union[IOConnectCallMethod, IOConnectCallAsyncMethod],
        service: Service,
        client: UserClient,
        method: Method,
        **kwargs,
    ):
        super().__init__(
            target, syscall,
            binary, kext,
            service, client,
            entry,
            constraints_filter=lambda addr: addr >= 0xffffff8000000000,
            input_filter=lambda addr: addr >= 0xffffff8000000000,
            **kwargs,
        )

        self._method = method

    # def detect_error_path_filter(self, addr: TargetAddress) -> bool:
    #     return addr >= 0xffffff8000000000

    def isErrorCode(self, val: int) -> bool:
        # see /iokit/IOKit/IOReturn.h
        val = val & 0xffffffff
        return (
            err_get_system(val) == 0x38 and
            0x2bc <= err_get_code(val) <= 0x2f0
        )

    def notErrorCode(self, state: SimState, ret: Base) -> None:
        val = val & 0xffffffff
        constraints = [val < 0xe00002bc, val > 0xe00002f0]
        add_one_constraint(self, state, state.solver.Or(*constraints))

    def setDeadEnd(self, state):
        """Set deadend so that symbolic execution can exit early to avoid
        unnecessary computation"""
        if self.client.externalMethod:
            super().setDeadEnd(state)
        elif self.client.getTargetAndMethodForIndex:
            # We want to continue to execute after this function is returned.
            # Set the dead end when starting executing our target function (see @execute).
            pass
        else:
            raise Exception("not implemented yet!")

    def isTargetSyscall(self, proxy: Proxy, syscall: Union[IOConnectCallMethod, IOConnectCallAsyncMethod]) -> bool:
        args = IOExternalMethodArguments(proxy, self.client)

        # check arguments
        if not self.isTargetArgument(proxy, syscall.selector, args.selector):
            return False
        if not self.isTargetArgument(proxy, syscall.inputCnt, args.scalarInputCnt):
            return False
        if not self.isTargetArgument(proxy, syscall.inputStructCnt, args.structInputCnt):
            return False
        if isinstance(syscall.outputCnt, PtrType) and syscall.outputCnt.ref:
            if not self.isTargetArgument(proxy, syscall.outputCnt.ref, args.scalarOutputCnt):
                return False
        if isinstance(syscall.outputStructCnt, PtrType) and syscall.outputStructCnt.ref:
            if not self.isTargetArgument(proxy, syscall.outputStructCnt.ref, args.structOutputCnt):
                return False

        if not self.isTargetArgument(proxy, syscall.input, args.scalarInput):
            return False
        if not self.isTargetArgument(proxy, syscall.inputStruct, args.structInput):
            return False

        return True

    def execute(self, simgr: SimulationManager) -> SimulationManager:
        # Reach the functionality first then we explore different paths
        tgt = self.getTargetAddr(self._method.addr.address, self._method.addr.module)
        logger.debug("target addr is 0x%x", tgt)
        self.waypoint.add(tgt)
        simgr.stashes["waypoint"] = []

        start = time.time()
        exp = BFSExplore(self, verbose=True)
        simgr = exp.explore(simgr, options.timeout)
        # exp.explore(simgr, callback=callback)
        left = max(1, options.timeout - (time.time() - start)
                   ) if options.timeout else 0

        # clear all states except those that reached the target address
        simgr._clear_states("active")
        simgr.move(from_stash="waypoint", to_stash="active")
        simgr._clear_states("deadended")
        self.waypoint.clear()
        if len(simgr.active) == 0:
            logger.info("You may want to increase the timeout threshold")
            return simgr

        if self.client.externalMethod == 0 and self.client.getTargetAndMethodForIndex:
            # Now that we encouter the target function, we could set the dead end.
            ret_addr = self.proj.simos.return_deadend
            if len(simgr.active) != 1:
                raise Exception(
                    "multiple states when executing the target function")
            state = simgr.active[0]
            logger.debug("reg sp: %s", state.regs.sp)
            logger.debug("return addr: %s", state.mem[state.regs.sp].uint64_t.resolved)
            state.memory.store(
                state.regs.sp,
                state.solver.BVV(ret_addr, 64),
                endness=state.arch.memory_endness,
                inspect=False,
            )

        logger.debug("reached target address")

        # TODO: try state merging?
        simgr.apply(stash_func=self.deduplicate)

        exp = self.explorer(self, verbose=True)
        return exp.explore(simgr, timeout=left)


class IOKitRecovery(InterfaceRecovery):
    """For IOConnectCallMethod and IOConnectCallAsyncMethod only"""

    def __init__(self, target: Target, binary: str, cmd: int, service: Service, client: UserClient, model: BaseModel, **kwargs) -> None:
        self._service = service
        self._client = client

        super().__init__(target, binary, cmd, model, True, **kwargs)

    def get_executor(self, syscall: Syscall, model: SyscallModel, **kwargs):
        structOnly = syscall.status in {SyscallStatus.INCOMPLETE, SyscallStatus.OUTPUT}
        return IOKitExecutor(
            self.target,
            self.binary,
            model.entry.module,
            model.entry.address,
            syscall,
            self._service,
            self._client,
            model.dispatcher.methods[self.cmd],
            structOnly=structOnly,
            **kwargs,
        )
