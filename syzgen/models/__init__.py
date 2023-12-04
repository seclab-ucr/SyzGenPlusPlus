
import logging
import angr

from angr.sim_state import SimState
from bisect import bisect
from datetime import datetime
from typing import Tuple, Union

from claripy.ast.bv import Extract
from claripy.ast.base import Base

from syzgen.config import Options

try:
    from time import time_ns
except ImportError:
    # For compatibility with Python 3.6
    def time_ns():
        now = datetime.now()
        return int(now.timestamp() * 1e9)


logger = logging.getLogger(__name__)
options = Options()

MAX_MEMORY_SIZE = 4096
# Region to allocate memory invoked by functions like malloc
BASE_HEAP_LOCATION = 0xd0000000
MAX_HEAP_LOCATION = BASE_HEAP_LOCATION + 0x10000000
# Region to allocate memory for unknown global variables
BASE_GLOBAL_LOCATION = MAX_HEAP_LOCATION
MAX_GLOBAL_LOCATION = MAX_HEAP_LOCATION + 0x10000000

# HEAP_LOCATION = BASE_HEAP_LOCATION + 0x1000
# GLOBAL_LOCATION = BASE_GLOBAL_LOCATION + 0x1000


def isHeapObject(addr): return BASE_HEAP_LOCATION <= addr < MAX_HEAP_LOCATION


def isGlobalObject(
    addr): return BASE_GLOBAL_LOCATION <= addr < MAX_GLOBAL_LOCATION


def isAllocObject(
    addr): return BASE_HEAP_LOCATION <= addr < MAX_GLOBAL_LOCATION

def isValidPointer(addr, state=None):
    if state:
        # FIXME: hard-coded range for pointers
        min_addr = max(state.project.loader.max_addr&0xffff700000000000, 0x1000)
        return min_addr <= addr < state.project.loader.max_addr
    return 0xffff700000000000 <= addr < 0xffffffff90000000


def ALIGN(x, align): return ((x+align-1) & (~(align-1)))


def Arg2Base(arg): return arg if isinstance(arg, Base) else arg.to_claripy()


def is_stack_pointer(state: SimState, addr: int) -> bool:
    stack_ptr = state.solver.eval(state.regs.sp)
    if abs(addr - stack_ptr) <= 8096:
        return True
    return False


def get_monotonic_ns():
    return time_ns()


def get_monitonic_sec():
    return int(datetime.now().timestamp())


class FindObjectException(Exception):
    pass


class BaseAllocator:
    def __init__(self, base, alignment) -> None:
        self.base = base
        self.align = alignment
        self.objects = []

    def _alloc(self, size: int, align: int = 0) -> int:
        addr = self.base
        self.base = ALIGN(self.base+size, align if align else self.align)
        self.objects.append((addr, size))
        logger.debug("alloc: %#x, base: %#x, size: %d", addr, self.base, size)
        return addr

    def get_closest_object(self, addr: int) -> Tuple[int, int]:
        idx = bisect(self.objects, (addr, 0))
        if idx >= len(self.objects):
            return self.objects[-1]
        if idx == 0:
            return self.objects[0]
        obj1 = self.objects[idx-1]
        obj2 = self.objects[idx]
        return obj1 if addr - obj1[0] < obj2[0] - addr else obj2

    def get_object(self, addr: int) -> Tuple[int, int]:
        idx = bisect(self.objects, (addr, 0))
        if idx >= len(self.objects):
            p, s = self.objects[-1]
            if p <= addr < p + s:
                return p, s
            logger.error("failed to find the object %#x", addr)
            # from IPython import embed; embed()
            raise FindObjectException()
        p, s = self.objects[idx]
        if p <= addr < p + s:
            return p, s
        if idx > 0:
            p, s = self.objects[idx-1]
            if p <= addr < p + s:
                return p, s
        logger.error("failed to find the object %#x", addr)
        # from IPython import embed; embed()
        raise FindObjectException()

    def get_object_size(self, addr: int) -> int:
        _, s = self.get_object(addr)
        return s

    def alloc(self, state, length, align: int = 0):
        ptr = None
        if state.solver.symbolic(length):
            size = max(
                min(state.solver.max_int(length), MAX_MEMORY_SIZE),
                state.solver.min(length),
            )
            logger.debug("concretize Malloc size %s %d", length, size)
            ptr = self._alloc(size, align=align)
        else:
            size = state.solver.eval(length)
            if size > 0x20000:
                logger.warning("alloc size of %d larger than %d", size, 0x20000)
                size = MAX_MEMORY_SIZE
                # from IPython import embed; embed()
                # raise Exception("alloc size %d" % size)
            ptr = self._alloc(size, align=align)

        logger.debug("return ptr: 0x%x", ptr)
        # FIXME: Track all heap objects
        # alloc = state.globals.get("alloc", [])
        # bisect.insort(alloc, ptr)
        # state.globals["alloc"] = alloc
        # intialize all allocated memory to avoid symbolization
        state.memory.store(ptr, state.solver.BVV(0, size*8), inspect=False)
        return ptr


class HeapAllocator(BaseAllocator):
    def __init__(self) -> None:
        super().__init__(BASE_HEAP_LOCATION + 0x1000, 0x100)


class GlobalAllocator(BaseAllocator):
    def __init__(self) -> None:
        self.unit = 0x2000

        super().__init__(BASE_GLOBAL_LOCATION + 0x1000, self.unit)

    def alloc(self, length=0x2000, align: int = 0):
        return self._alloc(length, align=align)


def brkAlloc(state, length, align=0, tag: bool = False) -> Union[int, Base]:
    allocator: HeapAllocator = options.heap_allocator
    addr = allocator.alloc(state, length, align=align)
    # Make the execution slow and mostly importantly may trigger a bug in angr/z3?
    # if tag and options.record_access_path:
    #     name = f"alloc_{addr:x}"
    #     addr_sym = state.solver.BVS(name, 64, key=(name, 8), eternal=True)
    #     state.solver.add(addr_sym == addr)
    #     return addr_sym
    return addr


class NamedSimProcedure(angr.SimProcedure):
    def __init__(self, name: str, **kwargs):
        super().__init__(**kwargs)

        self._name = name


class GenericMalloc(NamedSimProcedure):
    def run(self):
        return brkAlloc(self.state, MAX_MEMORY_SIZE)


class Snprintf(angr.SimProcedure):
    def run(self, dst, length, fmt):
        # In the driver we tested, snprintf does not matter
        self.state.memory.store(
            dst, self.state.solver.BVV(0, 8), inspect=False)
        return 0


class Memset(angr.SimProcedure):
    def run(self, dst, char, length):
        if self.state.solver.symbolic(length):
            size = self.state.solver.max_int(length)
            if size > MAX_MEMORY_SIZE:
                size = MAX_MEMORY_SIZE
        else:
            size = self.state.solver.eval(length)
            if size > MAX_MEMORY_SIZE:
                logger.info("size %d exceeds MAX_MEMORY_SIZE", size)
                size = MAX_MEMORY_SIZE
                # from IPython import embed
                # embed()
                # raise RuntimeError(f"size {size} exceeds {MAX_MEMORY_SIZE}")
        ptr = self.state.solver.eval(dst)
        c = Extract(7, 0, char.to_claripy())
        logger.debug("memset 0x%x, %s, %d", ptr, c, size)
        for i in range(size):
            self.state.memory.store(ptr+i, c, inspect=False)


class Strlen(angr.SimProcedure):
    def run(self, src):
        logger.debug("call strlen %s", src)
        src_addr = self.state.solver.eval(src)
        max_size = MAX_MEMORY_SIZE
        min_size = 0
        for i in range(max_size):
            c = self.state.memory.load(src_addr+i, 1, inspect=False)
            if not self.state.solver.symbolic(c):
                if self.state.solver.is_true(c == 0):
                    max_size = i
                    break
                else:
                    min_size = i

        # TODO: Mark the boundary of the string
        logger.debug("max_size: %d, min_size: %d", max_size, min_size)
        if max_size <= min_size + 1:
            return max_size

        ret_len = self.state.solver.BVS(
            "strnlen_ret", 64, inspect=False, events=False)
        self.state.solver.add(ret_len <= max_size)
        self.state.solver.add(ret_len >= min_size)
        return ret_len


class Strcpy(angr.SimProcedure):
    def run(self, dst, src):
        logger.debug("call strcpy %s, %s", dst, src)
        max_size = MAX_MEMORY_SIZE
        src_addr = self.state.solver.eval(src)
        for i in range(max_size):
            c = self.state.memory.load(src_addr+i, 1, inspect=False)
            if not self.state.solver.symbolic(c):
                if self.state.solver.is_true(c == 0):
                    max_size = i
                    break

        src_mem = self.state.memory.load(src, max_size)
        self.state.memory.store(dst, src_mem, size=max_size)
        return dst


class GetMonons(angr.SimProcedure):
    def run(self):
        return get_monotonic_ns()


class CurrentTime(angr.SimProcedure):
    def run(self):
        return get_monitonic_sec()


class DummyModel(NamedSimProcedure):
    def __init__(self, name: str, ret_value: int=0, **kwargs):
        super().__init__(name, **kwargs)
        self.ret_value = ret_value

    def run(self):
        logger.debug("call %s", self._name)
        if self.ret_value is not None:
            return self.ret_value


class StateTerminator(angr.SimProcedure):
    """Terminate the execution and mark it as abandoned"""
    NO_RET = True

    def run(self):
        logger.debug("terminate this state %d",
                     self.state.locals.get("id", -1))
        return


class ReturnUnconstrained(angr.SimProcedure):
    def run(self):
        _, size = self.cc.arch.registers.get(self.cc.RETURN_VAL.reg_name)
        return self.state.solver.BVS("return_val", size=size*8, inspect=False)


def dummyHook(state):
    pass


class FuncModel:
    def __init__(self):
        pass

    def getFunc2Model(self):
        return dict()

    def getFunc2Hook(self):
        return dict()


def interactive_hook(state):
    logger.debug("called interactive hook %s", state.regs.ip)
    from IPython import embed
    embed()
