
from enum import Enum
import logging
import time
import typing
import re
import angr

from typing import Any, Callable, Generator, Generic, List, Optional, Set, Tuple, TypeVar

from angr.sim_manager import SimulationManager
from angr.sim_state import SimState

from syzgen.config import Options
from syzgen.models import DummyModel, FuncModel, HeapAllocator, StateTerminator, interactive_hook, isValidPointer
from syzgen.executor.locals import SimStateLocals  # DON'T REMOVE: register locals
from syzgen.parser.models import BaseAddress, TargetAddress
from syzgen.target import Target

logger = logging.getLogger(__name__)
options = Options()

MemoryReadCallback = Callable[[SimState, Any, Any], None]
MemoryWriteCallback = Callable[[SimState, Any, Any, Any], None]

KEY_REDUCED_CONSTRAINTS = "reduced_constraints"
KEY_DISCARD = "discard"
KEY_YIELD = "yield"
KEY_DEADEND = "deadended"
KEY_VARIABLES = "variables"
KEY_TYPE_ANNOTATION = "type_annotation"
KEY_STATE_ID = "id"
KEY_FORK_LIMITS = "loop_limiter"
KEY_EXECUTE_LIMITS = "execution_limiter"
KEY_TRACE = "trace"

RE_FUNCTION_COPY = re.compile(r"\.\d+")

T = TypeVar("T")

def yield_state(state) -> bool:
    if state.locals.get(KEY_YIELD, False):
        # reset
        state.locals[KEY_YIELD] = False
        return True
    return False

class PriorityList(Generic[T]):
    # reserve some priority
    FIRST_PRIORITY = 0
    SECOND_PRIORITY = 1
    THIRD_PRIORITY = 2

    HIGH_PRIORITY = 1 << 3
    NORMAL_PRIORITY = 1 << 6
    LOW_PRIORITY = 1 << 12

    def __init__(self) -> None:
        self.list: List[Tuple[int, T]] = []

    def insert(self, priority: int, obj: T):
        if self.contain(priority, obj):
            return

        idx = len(self.list)
        for i, (p, _) in enumerate(self.list):
            if priority < p:
                idx = i
                break
        self.list.insert(idx, (priority, obj))

    def remove(self, obj: T):
        for i, (_, v) in enumerate(self.list):
            if v == obj:
                self.list.pop(i)
                break

    def contain(self, priority: int, obj: T):
        for p, v in self.list:
            if priority < p:
                break
            if v is obj:
                return True
        return False

    def items(self) -> Generator[T, None, None]:
        for _, obj in self.list:
            yield obj

    def __bool__(self) -> bool:
        return len(self.list) > 0


class ExecutionMode(Enum):
    DYNAMIC = 0
    STATIC  = 1


class PluginMixin:
    MODE = ExecutionMode.STATIC
    RequireDependents = []

    def __init__(self, **kwargs) -> None:
        self.should_abort = False

        self.memory_read_callbacks = PriorityList[MemoryReadCallback]()
        self.memory_write_callbacks = PriorityList[MemoryWriteCallback]()

    def reload(self, **kwargs) -> None:
        """Re-init the plugins while preserving some immediate results"""
        pass

    def disable_plugin(self, clazz: typing.Type["PluginMixin"]) -> None:
        setattr(self, f"enable_{clazz.__name__}", False)

        # recursively disable its parent if there is no other usage of it.
        for parent in clazz.__bases__:
            if parent in self.RequireDependents and not self.has_dependent(parent):
                self.disable_plugin(parent)

    def enable_plugin(self, clazz: typing.Type["PluginMixin"]) -> None:
        setattr(self, f"enable_{clazz.__name__}", True)

        for parent in clazz.__bases__:
            if issubclass(parent, PluginMixin) and not self.is_enabled(parent):
                self.enable_plugin(parent)

    def is_enabled(self, clazz: typing.Type["PluginMixin"]) -> bool:
        # by default, all plugins are enabled if not specified.
        return getattr(self, f"enable_{clazz.__name__}", True)

    def register_plugin_needs_dependents(self, t: typing.Type["PluginMixin"]) -> None:
        """When we disable a plugin, we might also want to disable its parent if there
        is no other usage of it. However, not all plugins should be disabled in this
        recursive way. We allow users to decide and call this function whenever necessary."""
        self.RequireDependents.append(t)

    def _has_dependent(self, base: typing.Type["PluginMixin"], clazz: typing.Type["PluginMixin"]) -> bool:
        for parent in base.__bases__:
            if parent == clazz:
                if self.is_enabled(base):
                    return True
            elif issubclass(parent, PluginMixin):
                if self._has_dependent(parent, clazz):
                    return True
        return False

    def has_dependent(self, clazz: typing.Type["PluginMixin"]) -> bool:
        """Determine whether there is any enabled plugins that are
        dependent on the given class."""
        return self._has_dependent(self.__class__, clazz)

    def abort(self) -> None:
        self.should_abort = True

    def init(self, state: SimState) -> None:
        """called just after we create a blank state and have not done anything yet.
        This is the place where plugins can add more properties to the state."""
        pass

    def pre_execute(self, state: SimState) -> None:
        """called before we perform the symbolic execution.
        Note all derived class that override it must call super() to support mixin
        """
        pass

    def on_execute(self, simgr: SimulationManager) -> None:
        """Called during the symbolic execution.
        Note all derived class that override it must call super() to support mixin
        """
        simgr.move(
            from_stash="active",
            to_stash=KEY_DISCARD,
            filter_func=lambda s: s.locals.get(KEY_DISCARD, False)
        )
        simgr.move(
            from_stash="active",
            to_stash=KEY_DEADEND,
            filter_func=lambda s: s.locals.get(KEY_DEADEND, False)
        )
        simgr.move(
            from_stash="active",
            to_stash="deferred",
            filter_func=yield_state,
        )

    def discard_state(self, state: SimState) -> None:
        logger.debug("discard state at %#x", state.addr)
        state.locals[KEY_DISCARD] = True

    def yield_state(self, state: SimState) -> None:
        state.locals[KEY_YIELD] = True

    def terminate_state(self, state: SimState) -> None:
        logger.debug("move state at %#x to deadended", state.addr)
        state.locals[KEY_DEADEND] = True

    def post_execute(self, simgr: SimulationManager) -> None:
        """called after we perform the symbolic execution.
        Note all derived class that override it must call super() to support mixin
        """
        # During execution of post_execute, we may discard more states
        # which need to be moved to another stash manually.
        simgr.move(
            from_stash="deadended",
            to_stash=KEY_DISCARD,
            filter_func=lambda s: s.locals.get(KEY_DISCARD, False)
        )

    def register_memory_read(self, func: MemoryReadCallback, priority: int):
        self.memory_read_callbacks.insert(priority, func)

    def unregister_memory_read(self, func: MemoryReadCallback) -> None:
        self.memory_read_callbacks.remove(func)

    def register_memory_write(self, func: MemoryWriteCallback, priority: int):
        self.memory_write_callbacks.insert(priority, func)

    def unregister_memory_write(self, func: MemoryWriteCallback) -> None:
        self.memory_write_callbacks.remove(func)

    def get_debug_info(self, addr: int) -> str:
        """return the debug info for one specific address"""
        raise NotImplementedError()

    def find_section_by_addr(self, addr):
        """find the section that contains this address"""
        return self.proj.loader.find_section_containing(addr)

    def getBaseAddr(self, ip: TargetAddress, target=None) -> Tuple[str, BaseAddress]:
        """Get the relative address of this address in the file"""
        raise NotImplementedError()

    def getTargetAddr(self, offset, target="kernel") -> TargetAddress:
        """Get the resolved address of this offset"""
        raise NotImplementedError()

    def load_project_by_addr(self, addr: TargetAddress) -> Tuple[str, BaseAddress, Optional[angr.Project]]:
        """return the project that contains the address, as well as the module name and offset"""
        raise NotImplementedError()

    def get_default_project(self) -> angr.Project:
        raise NotImplementedError()

    def get_target(self) -> Target:
        raise NotImplementedError()

    def is_stack_pointer(self, state: SimState, addr) -> bool:
        stack_ptr = state.solver.eval(state.regs.sp)
        concrete_addr = state.solver.min(addr)
        if abs(concrete_addr - stack_ptr) <= 8096:
            return True
        return False

    def is_valid_pointer(self, addr: int, state=None) -> bool:
        return isValidPointer(addr, state=state)

    def getFuncAddr(self, name: str) -> Tuple[str, TargetAddress]:
        raise NotImplementedError()

    def getFuncAddrs(self, *funcs) -> List[Tuple[str, TargetAddress]]:
        raise NotImplementedError()

class ExitCode(Enum):
    UNKNOWN = 0
    NO_STATE = 1
    TIMEOUT = 2
    USER_FORCE = 3
    Z3_ERROR = 4


class BaseExecutor(PluginMixin):
    def __init__(
        self,
        target: Target,
        binary: str,
        model: Optional[FuncModel] = None,
        concrete_target=None,
        **kwargs
    ):
        # basics
        self.filename = binary
        self._func_model = model
        self.target: Target = target
        assert target is not None

        self.proj = angr.Project(
            self.filename,
            concrete_target=concrete_target,
            force_load_libs=kwargs.pop("libs", []),
        )
        logger.debug("init BaseExecutor")

        super().__init__(**kwargs)

        self.hooks = {}
        # Allow user to manually set some addresses that needs to be
        # taken care of.
        self.ignore_addrs: Set[int] = set()
        self.waypoint: Set[int] = set()
        self.dead: Set[int] = set()
        self.breakpoints: Set[int] = set()

        # Set the new heap allocator to a shared instance
        options.heap_allocator = HeapAllocator()

        # others
        self.exit_code = ExitCode.UNKNOWN
        self.explorer = None
        self.timeout: int = options.timeout

        self.initialized: bool = False

    def reload(self, **kwargs) -> None:
        super().reload(**kwargs)

        options.heap_allocator = HeapAllocator()
        self.exit_code = ExitCode.UNKNOWN

    def get_default_project(self) -> angr.Project:
        return self.proj

    def get_target(self) -> Target:
        return self.target

    def getInitState(self) -> SimState:
        state = self.proj.factory.blank_state()
        for reg in state.arch.register_list:
            # set default value for all registers
            setattr(state.regs, reg.name, 0)
        self.init(state)
        return state

    def initialize(self):
        """initialization before we generate the initial state. Note if it should only be called once
        across different runs, please check against @self.initialized."""
        # Other initializations executed after we instantiate the executor,
        # which is invoked just before we get the initial state. It is
        # necessary if we want to operate on the @proj so that it can take
        # effect on the all subsequently generated states.
        if self.initialized:
            return
        self.initialized = True

        self.setup_hooks()
        for addr in self.breakpoints:
            self.proj.hook(addr, interactive_hook, length=0)

    def pre_execute(self, state: SimState) -> None:
        """called before we perform the symbolic execution"""
        if options.hook_point == "pre":
            from IPython import embed
            embed()

        if self.memory_read_callbacks:
            state.inspect.b('mem_read', when=angr.BP_BEFORE,
                            action=self.onMemoryRead)
        if self.memory_write_callbacks:
            state.inspect.b('mem_write', when=angr.BP_BEFORE,
                            action=self.onMemoryWrite)

        # set default value for all registers
        state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)

        # set self
        state.globals["executor"] = self
        super().pre_execute(state)

    def post_execute(self, simgr: SimulationManager) -> None:
        """Show error stack backtrace for debugging purpose
        """
        if options.hook_point == "post":
            from IPython import embed
            embed()

        # any state marked with the tag `discard` should be dropped
        simgr.move(
            from_stash="deadended",
            to_stash=KEY_DISCARD,
            filter_func=lambda s: s.locals.get(KEY_DISCARD, False)
        )
        if KEY_DISCARD in simgr.stashes:
            logger.debug("remove %d states", len(simgr.stashes[KEY_DISCARD]))

        if not options.ignore_error and "errored" in simgr.stashes and len(simgr.errored) > 0:
            unknown_addr = False
            for i, each in enumerate(simgr.errored):
                if each.state.addr in self.ignore_addrs:
                    continue
                if each.state.addr&0xffffffff == each.state.project.simos.return_deadend&0xffffffff:
                    # TODO: why it occurs?
                    continue
                unknown_addr = True
                logger.debug("%d state", i)
                self.show_backtrace(each.state)

            if unknown_addr:
                # For debugging purpose
                from IPython import embed
                embed()
                raise Exception("Error state!")

        # call all the plugins after we handle it
        super().post_execute(simgr)
        return

    def execute(self, simgr: SimulationManager) -> SimulationManager:
        raise NotImplementedError()

    def show_backtrace(self, state):
        logger.debug("Show error state stack frames: 0x%x", state.addr)
        for i, f in enumerate(state.callstack):
            logger.info(
                "Frame %d: %#x => %#x", i,
                f.call_site_addr or 0,
                f.func_addr or 0
            )
            logger.info("%s => %s", self.get_debug_info(
                f.call_site_addr), self.get_debug_info(f.func_addr))

    def onMemoryRead(self, state):
        addr = state.inspect.mem_read_address
        size = state.inspect.mem_read_length
        # call [rax + 0x28]
        # state.regs.ip might be symbolic
        logger.debug(
            "on Memory Read, %s, %s, 0x%x",
            hex(addr) if isinstance(addr, int) else addr.shallow_repr(max_depth=4),
            size,
            state.solver.eval(state.regs.ip)
        )

        for func in self.memory_read_callbacks.items():
            func(state, addr, size)

    def onMemoryWrite(self, state):
        addr = state.inspect.mem_write_address
        expr = state.inspect.mem_write_expr
        size = state.inspect.mem_write_length

        logger.debug(
            "on Memory Write, %s, %s, 0x%x",
            hex(addr) if isinstance(addr, int) else addr.shallow_repr(max_depth=4),
            expr.shallow_repr(max_depth=4),
            state.solver.eval(state.regs.ip),
        )
        for func in self.memory_write_callbacks.items():
            func(state, addr, expr, size)

    def run(self) -> None:
        simgr = None
        self.initialize()
        state = self.getInitState()

        time1 = time.time()
        self.pre_execute(state)
        simgr = self.proj.factory.simgr(state)
        time2 = time.time()
        simgr = self.execute(simgr)
        time3 = time.time()
        self.post_execute(simgr)
        time4 = time.time()
        # logger.debug("Time Cost: %s %s %s %s", time1, time2, time3, time4)
        logger.info("pre_execute: %s", time2 - time1)
        logger.info("execute: %s", time3 - time2)
        logger.info("post_execute: %s", time4 - time3)

    def getFuncAddrs(self, *funcs):
        '''
        param funcs: function names
        return a list of tuple <func name, addr>
        '''
        ret = list()
        # for sym in self.proj.loader.find_all_symbols(func):
        # sym = self.proj.loader.find_symbol(func)
        for sym in self.proj.loader.symbols:
            if sym is None:
                continue
            if not sym.is_function and not sym.is_extern:
                continue
            for func in funcs:
                if sym.name == func:
                    ret.append((func, sym.rebased_addr))
                    break
                elif sym.name.startswith(func):
                    # also hook all copies
                    suffix = sym.name[len(func):]
                    if RE_FUNCTION_COPY.match(suffix):
                        ret.append((func, sym.rebased_addr))
                        break
        return ret

    def getFuncAddr(self, name):
        return self.getFuncAddrs(name)[0][1]

    def setup_hooks(self):
        if self._func_model is None:
            return

        # __stack_chk_fail
        self.proj.hook(0, StateTerminator())

        models = self._func_model.getFunc2Model()
        names = list(models)
        for func, addr in self.getFuncAddrs(*names):
            logger.debug("Replace %s at 0x%x", func, addr)
            self.proj.hook(addr, models[func], replace=True)
            self.hooks[addr] = func

        hooks = self._func_model.getFunc2Hook()
        names = list(hooks)
        for func, addr in self.getFuncAddrs(*names):
            logger.debug("Hook %s at 0x%x", func, addr)
            self.proj.hook(addr, hooks[func], length=0)

        funcWithZero = DummyModel("funcWithZero")
        funcWithOne = DummyModel("funcWithOne", ret_value=1)
        # We allow user to define some function hooks
        for addr, real_addr, driver in self.get_relocated_addresses("funcWithZero"):
            logger.debug("hook with funcWithZero: %s %#x %#x",
                         driver, addr, real_addr)
            self.proj.hook(real_addr, funcWithZero)
        for addr, real_addr, driver in self.get_relocated_addresses("funcWithOne"):
            logger.debug("hook with funcWithOne: %s %#x %#x",
                         driver, addr, real_addr)
            self.proj.hook(real_addr, funcWithOne)

        # Sometimes it is difficult to model every possible function in the kernel that is
        # essential for the execution. Thereby, we provide a method to manually configure
        # some waypoints and dead points.
        for addr, real_addr, driver in self.get_relocated_addresses("dead"):
            logger.debug("dead point: %s %#x %#x", driver, addr, real_addr)
            self.dead.add(real_addr)
        for addr, real_addr, driver in self.get_relocated_addresses("waypoint"):
            logger.debug("waypoint: %s %#x %#x", driver, addr, real_addr)
            self.waypoint.add(real_addr)
        for addr, real_addr, driver in self.get_relocated_addresses("ignore"):
            logger.debug("ignore point: %s %#x %#x", driver, addr, real_addr)
            self.ignore_addrs.add(real_addr)
        for addr, real_addr, driver in self.get_relocated_addresses("breakpoint"):
            logger.debug("breakpoint: %s %#x %#x", driver, addr, real_addr)
            self.breakpoints.add(real_addr)

    def on_execute(self, simgr: SimulationManager) -> None:
        """Move states to corresponding stash according to our config"""
        if self.dead or self.waypoint:
            dead_states, waypoint_states, remain = [], [], []
            for state in simgr.active:
                if state.addr in self.dead:
                    dead_states.append(state)
                elif state.addr in self.waypoint:
                    waypoint_states.append(state)
                else:
                    remain.append(state)

            if dead_states or waypoint_states:
                simgr._clear_states("active")
                simgr._store_states("dead", dead_states)
                simgr._store_states("waypoint", waypoint_states)
                simgr._store_states("active", remain)

        return super().on_execute(simgr)

    def get_relocated_addresses(self, key: str) -> Generator[Tuple[str, int, int], None, None]:
        for driver, addrs in options.getConfigKey(key, default={}).items():
            for addr in addrs:
                if isinstance(addr, str):
                    addr = int(addr, 16)
                real_addr = self.getTargetAddr(addr, driver)
                if real_addr:
                    yield (addr, real_addr, driver)

    def find_symbol_by_addr(self, addr, fuzzy=False):
        """find the corresponding symbol for this address"""
        raise NotImplementedError()

    def find_symbol_by_name(self, obj, name, fuzzy=False):
        """find the corresponding symbol by its name"""
        raise NotImplementedError()
