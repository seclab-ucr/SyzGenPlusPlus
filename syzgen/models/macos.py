
import logging
import angr
import time
import random

from claripy.ast.bv import Extract

from syzgen.config import Options
from syzgen.debugger.lldbproxy import LLDBDebugger
from syzgen.executor import BaseExecutor
from syzgen.models.utils import concretize_user_pointer, memcpy, track_length
from syzgen.utils import demangle, extractFields
from syzgen.models import (
    Arg2Base,
    FuncModel,
    DummyModel,
    MAX_MEMORY_SIZE,
    Snprintf,
    StateTerminator,
    brkAlloc,
    Memset,
)

logger = logging.getLogger(__name__)
options = Options()

#
# General Function Summaries
#


class IOMalloc(angr.SimProcedure):
    def run(self, length):
        logger.debug("call IOMalloc %s", length)
        return brkAlloc(self.state, length, tag=True)


class Zalloc(angr.SimProcedure):
    def run(self, zone):
        # FIXME: how to get the offset: p &(((zone_t)0)->elem_size)
        size_offset = LLDBDebugger.fieldOffset(
            "elem_size",
            "zone_t",
        )
        elem_size = self.state.mem[zone+size_offset].uint64_t.resolved
        logger.debug("call zalloc %s %d", zone, elem_size)
        return brkAlloc(self.state, elem_size, tag=True)


class KallocCanblock(angr.SimProcedure):
    def run(self, psize, canBlock, site):
        length = self.state.mem[psize].uint64_t.resolved
        logger.debug("call kalloc_canblock %s %s %s %s",
                     psize, canBlock, site, length)
        return brkAlloc(self.state, length, tag=True)


class runAction(angr.SimProcedure):
    """IOCommandGate::runAction
    """
    IS_FUNCTION = True
    RET_ERROR = True

    def run(self, this, action, arg0, arg1, arg2, arg3):
        logger.debug("call IOCommandGate::runAction")
        # There is definitely no refs
        # FIXME: do not hardcode the offset (IOCommandGate->owner)
        _owner_offset = LLDBDebugger.fieldOffset(
            "owner",
            "IOCommandGate",
        )
        owner = self.state.mem[this+_owner_offset].uint64_t.resolved
        # TODO: provide prototype
        self.call(
            action,
            [Arg2Base(owner), Arg2Base(arg0), Arg2Base(arg1), Arg2Base(arg2), Arg2Base(arg3)],
            "retFromRunAction"
        )

    def retFromRunAction(self, this, action, arg0, arg1, arg2, arg3):
        logger.debug("return from action")
        self.ret(0)


class IOWorkLoopRunAction(angr.SimProcedure):
    """IOReturn IOWorkLoop::runAction(Action inAction, OSObject *target,
        void *arg0, void *arg1, void *arg2, void *arg3)
    """
    IS_FUNCTION = True
    RET_ERROR = True

    def run(self, this, action, target, arg0, arg1, arg2, arg3):
        logger.debug("call IOWorkLoop::runAction %s %s %s %s %s %s",
                     action, target, arg0, arg1, arg2, arg3)
        return self.call(
            action,
            [Arg2Base(target), Arg2Base(arg0), Arg2Base(arg1), Arg2Base(arg2), Arg2Base(arg3)],
            "retFromRunAction"
        )

    def retFromRunAction(self, this, action, target, arg0, arg1, arg2, arg3):
        return 0


class MemPrepare(angr.SimProcedure):
    def run(self, this, direction):
        logger.debug("call prepare")
        return 0


class MemWriteBytes(angr.SimProcedure):
    def run(self, this, offset, dst, length):
        logger.debug("on WriteBytes %s %s %s %s", this, offset, dst, length)
        return length


class MemReadBytes(angr.SimProcedure):
    """IOByteCount
    IOMemoryDescriptor::readBytes
    (IOByteCount offset, void *bytes, IOByteCount length)
    """

    def run(self, this, offset, dst, length):
        logger.debug("on ReadBytes %s %s %s %s", this, offset, dst, length)
        # p &(((IOMemoryDescriptor*)0)->_length)
        addr = self.state.solver.eval(this)
        if self.state.solver.symbolic(length):
            size = self.state.solver.max_int(length)
            if size > MAX_MEMORY_SIZE:
                size = MAX_MEMORY_SIZE
        else:
            size = self.state.solver.eval(length)

        ptr = self.state.locals.get(('mapping', addr))
        sym_cont = self.state.memory.load(ptr, size, inspect=False)

        concrete_offset = self.state.solver.eval(offset)
        logger.debug("ReadBytes %s %d %d %d", sym_cont, sym_cont.length, concrete_offset, size)
        if concrete_offset*8 >= sym_cont.length:
            raise Exception("offset exceeds")
        left, right, remain = concrete_offset, concrete_offset+size, 0
        if right*8 > sym_cont.length:
            remain = right-(sym_cont.length//8)
            right = sym_cont.length//8

        if left == 0 and right*8 == sym_cont.length:
            self.state.memory.store(dst, sym_cont)
        else:
            self.state.memory.store(dst, Extract(
                sym_cont.length-left*8-1, sym_cont.length-right*8, sym_cont))

        if remain > 0:  # Padding with zero
            self.state.memory.store(
                dst+(sym_cont.length//8), self.state.solver.BVV(0, remain*8))

        # TODO: concrete or symbolic?
        return size


class MakeMapping(angr.SimProcedure):
    """IOMemoryMap *IOMemoryDescriptor::makeMapping(
        IOMemoryDescriptor *    owner,
        task_t                  __intoTask,
        IOVirtualAddress        __address,
        IOOptionBits            options,
        IOByteCount             __offset,
        IOByteCount             __length )
    """

    def run(self, this, owner, task, mapping, options, offset, length):
        logger.debug(
            "call IOMemoryDescriptor::makeMapping %s %s", this, mapping)
        addr = self.state.solver.eval(this)

        _fMemoryOff = LLDBDebugger.fieldOffset("fMemory", "IOMemoryMap")
        self.state.mem[mapping+_fMemoryOff].uint64_t = addr

        ptr = self.state.locals.get(('mapping', addr), None)
        if ptr is None:
            raise Exception("failed to find the mapping 0x%x" % addr)
        _fAddressOff = LLDBDebugger.fieldOffset("fAddress", "IOMemoryMap")
        self.state.mem[mapping+_fAddressOff].uint64_t = ptr

        return mapping


class GetVirtualAddress(angr.SimProcedure):
    """virtual IOVirtualAddress IOMemoryMap::getVirtualAddress(void);
    p &(((IOMemoryMap*)0)->fAddress)
    """

    def run(self, this):
        logger.debug("call IOMemoryMap::getVirtualAddress %s", this)
        _fAddressOff = LLDBDebugger.fieldOffset("fAddress", "IOMemoryMap")
        return self.state.mem[this+_fAddressOff].uint64_t.resolved


class GetMemoryDescriptor(angr.SimProcedure):
    """IOMemoryDescriptor * IOMemoryMap::getMemoryDescriptor()
    """

    def run(self, this):
        logger.debug("call getMemoryDescriptor %s", this)
        pmapping = self.state.solver.eval(this)
        _fMemoryOff = LLDBDebugger.fieldOffset("fMemory", "IOMemoryMap")
        return self.state.mem[pmapping+_fMemoryOff].uint64_t.resolved


def CopyFromUser(state, addr, length):
    if state.solver.symbolic(length):
        track_length(state, addr, length)

        size = state.solver.max_int(length)
        if size > MAX_MEMORY_SIZE:
            size = MAX_MEMORY_SIZE
            state.solver.add(length <= MAX_MEMORY_SIZE)
    else:
        size = state.solver.eval(length)

    # concretize addr
    return concretize_user_pointer(state, addr, size)


class InitWithOptions(angr.SimProcedure):
    """bool
    IOMemoryDescriptor::initWithOptions(void *         buffers,
        UInt32         count,
        UInt32         offset,
        task_t         task,
        IOOptionBits   options,
        IOMapper *     mapper)
    """

    def run(self, this, buffers, count, offset, task, options, mapper):
        logger.debug("call IOGeneralMemoryDescriptor::initWithOptions")
        if self.state.solver.eval(count) != 1:
            logger.error("do not support count != 1")
            raise RuntimeError("count != 1")
        if self.state.solver.eval(offset) != 0:
            logger.error("do not support offset != 0")
            raise RuntimeError("offset != 0")
        # IOAddressRange* buffer
        addr = self.state.mem[buffers].uint64_t.resolved
        length = self.state.mem[buffers+0x8].uint64_t.resolved
        obj = self.state.solver.eval(this)

        ptr, size = CopyFromUser(self.state, addr, length)
        _lengthOffset = LLDBDebugger.fieldOffset(
            "_length",
            "IOBufferMemoryDescriptor",
        )
        self.state.memory.store(
            this + _lengthOffset,
            size,
            endness=self.state.arch.memory_endness,
            inspect=False,
        )
        # store the mapping info
        self.state.locals[('mapping', obj)] = ptr
        return 1


class InitWithPhysicalMask(angr.SimProcedure):
    """bool IOBufferMemoryDescriptor::initWithPhysicalMask(
        task_t            inTask,
        IOOptionBits      options,
        mach_vm_size_t    capacity,
        mach_vm_address_t alignment,
        mach_vm_address_t physicalMask)
    """

    def run(self, this, inTask, options, capacity, alignment, physicalMask):
        logger.debug("call InitWithPhysicalMask: %s, %s, %s, %s, %s, %s",
                     this, inTask, options, capacity, alignment, physicalMask)
        if self.state.solver.max(capacity) == 0:
            return 0
        _capacityOffset = LLDBDebugger.fieldOffset(
            "_capacity",
            "IOBufferMemoryDescriptor",
        )
        self.state.memory.store(
            this+_capacityOffset,
            capacity,
            endness=self.state.arch.memory_endness,
            inspect=False
        )  # _capacity
        ptr = brkAlloc(self.state, capacity, tag=True)
        logger.debug("call InitWithPhysicalMask %#x", ptr)
        _bufferOffset = LLDBDebugger.fieldOffset(
            "_buffer",
            "IOBufferMemoryDescriptor",
        )
        self.state.memory.store(
            this+_bufferOffset,
            ptr,
            endness=self.state.arch.memory_endness,
            inspect=False
        )  # _buffer
        # store the mapping info
        self.state.locals[
            ('mapping', self.state.solver.eval(this))
        ] = ptr
        return 1


class IOBufferSetLength(angr.SimProcedure):
    """void IOBufferMemoryDescriptor::setLength(vm_size_t length)"""

    def run(self, this, length):
        _lengthOffset = LLDBDebugger.fieldOffset(
            "_length",
            "IOBufferMemoryDescriptor",
        )
        self.state.memory.store(
            this+_lengthOffset,
            length,
            endness=self.state.arch.memory_endness,
            inspect=False
        )  # _length


class IOBufferGetBytesNoCopy(angr.SimProcedure):
    def run(self, this):
        """IOBufferMemoryDescriptor::getBytesNoCopy(void)"""
        logger.debug("call getBytesNoCopy %s", this)
        _bufferOffset = LLDBDebugger.fieldOffset(
            "_buffer",
            "IOBufferMemoryDescriptor",
        )
        return self.state.mem[this+_bufferOffset].uint64_t.resolved

# IOBufferMemoryDescriptor::withBytes(const void * inBytes,
#     vm_size_t    inLength,
#     IODirection  inDirection,
#     bool         inContiguous)
# It creates an object, call initWithPhysicalMask and then call appendBytes.


class IOBufferAppendBytes(angr.SimProcedure):
    """IOBufferMemoryDescriptor::appendBytes(const void * bytes, vm_size_t withLength)
    Note we assume it was only called by withBytes and thus _length is 0.
    TODO: check capacity and length
    """

    def run(self, this, addr, length):
        logger.debug(
            "call IOBufferMemoryDescriptor::appendBytes %s %s %s", this, addr, length)
        # Assign a concrete pointer to the symbolic addr
        ptr, size = CopyFromUser(self.state, addr, length)
        if size == 0:
            return 0
        sym_cont = self.state.memory.load(ptr, size, inspect=False)

        _bufferOffset = LLDBDebugger.fieldOffset(
            "_buffer",
            "IOBufferMemoryDescriptor",
        )
        buf = self.state.mem[this+_bufferOffset].uint64_t.concrete  # _buffer
        # We assume the offset is zero.
        self.state.memory.store(buf, sym_cont, inspect=False)

        _lengthOffset = LLDBDebugger.fieldOffset(
            "_length",
            "IOBufferMemoryDescriptor",
        )
        origin_length = self.state.solver.eval(
            self.state.mem[this+_lengthOffset].uint64_t.resolved)
        if origin_length != 0:
            print("original length is %d" % origin_length)
            raise Exception("original is not zero: %d" % origin_length)
        # FIXME: when calling getLength, it returns this concrete length (ie., concretization)
        self.state.memory.store(
            this+_lengthOffset,
            self.state.solver.BVV(size, 64),
            endness=self.state.arch.memory_endness,
        )  # _length
        return 1


class Copyin(angr.SimProcedure):
    def run(self, uaddr, kaddr, length):
        print("Copyin", uaddr, kaddr, length)
        state = self.state
        ptr, size = CopyFromUser(self.state, uaddr, length)
        sym_cont = self.state.memory.load(ptr, size, inspect=False)
        state.memory.store(kaddr, sym_cont, inspect=self.state.solver.symbolic(kaddr))
        return length


class bzero(angr.SimProcedure):
    def run(self, dst, length):
        logger.debug("call bzero %s %s", dst, length)
        if self.state.solver.symbolic(length):
            size = self.state.solver.max_int(length)
            if size > MAX_MEMORY_SIZE:
                size = MAX_MEMORY_SIZE
        else:
            size = self.state.solver.eval(length)
        ptr = self.state.solver.min(dst)
        for i in range(size):
            self.state.memory.store(
                ptr+i, self.state.solver.BVV(0, 8), inspect=False)


class MemmoveChk(angr.SimProcedure):
    def run(self, dst, src, srcLen, dstLen):
        # srcLen <= dstLen
        print("call __memmove_chk", dst, src, srcLen, dstLen)
        if not self.state.solver.symbolic(srcLen):
            conditional_size = self.state.solver.eval(srcLen)
        else:
            max_limit = self.state.solver.max_int(srcLen)
            min_limit = self.state.solver.min_int(srcLen)
            conditional_size = min(MAX_MEMORY_SIZE, max(min_limit, max_limit))
        if not self.state.solver.symbolic(dstLen):
            concrete = self.state.solver.eval(dstLen)
            conditional_size = min(conditional_size, concrete)

        if conditional_size > 0:
            print("__memmove_chk with size %d" % conditional_size)
            src_mem = self.state.memory.load(src, conditional_size)
            self.state.memory.store(dst, src_mem, size=conditional_size)

        return dst


class Memmove(angr.SimProcedure):
    def run(self, dst, src, srcLen):
        logger.debug("call memmove %s %s %s", dst, src, srcLen)
        return memcpy(self.state, dst, src, srcLen)


def addStringVariable(state, sym, left, right):
    if sym is not None:
        variables = state.locals.get("variables", set())
        variables.add((sym, left, right))
        state.locals["variables"] = variables

        strings = state.locals.get("strings", set())
        strings.add((sym, left, right))
        state.locals["strings"] = strings


def strnlen(state, src, limit, annotate=True, ret_size=64):
    if not state.solver.symbolic(limit):
        conditional_size = state.solver.eval(limit)
    else:
        max_limit = state.solver.max_int(limit)
        min_limit = state.solver.min_int(limit)
        conditional_size = min(MAX_MEMORY_SIZE, max(min_limit, max_limit))

    src_addr = state.solver.eval(src)
    max_size = conditional_size
    min_size = 0
    fields = set()
    for i in range(max_size):
        c = state.memory.load(src_addr+i, 1, inspect=False)
        if annotate:
            extractFields(c, fields)
        if not state.solver.symbolic(c):
            if state.solver.is_true(c == 0):
                max_size = i
                break
            else:
                min_size = i + 1
    logger.debug("max_size: %d, min_size: %d", max_size, min_size)

    if annotate:
        # Mark the boundary of the string
        l, r, sym = 0, 0, None
        for (name, left, right) in fields:
            if sym is None and l == 0 and r == 0:
                l, r, sym = left, right, name
            else:
                if left > l:
                    l = left
                if right < r:
                    r = right
                if name != sym:
                    sym = None
        logger.debug("addStringVariable %s %d %d", sym, l, r)
        addStringVariable(state, sym, l, r)

    if min_size == max_size:
        return min_size

    ret_len = state.solver.BVS(
        "strnlen_ret", ret_size, inspect=False, events=False)
    state.solver.add(ret_len <= max_size)
    state.solver.add(ret_len >= min_size)
    return ret_len


class Strnlen(angr.SimProcedure):
    def run(self, src, limit):
        logger.debug("call strnlen %s %s", src, limit)
        return strnlen(self.state, src, limit)


class Strlen(angr.SimProcedure):
    def run(self, src):
        logger.debug("call strlen")
        return strnlen(self.state, src, MAX_MEMORY_SIZE)


class KernelThreadStart(angr.SimProcedure):
    """https://developer.apple.com/documentation/kernel/1429094-kernel_thread_start
    kern_return_t kernel_thread_start(thread_continue_t continuation, void *parameter, thread_t *new_thread);
    """

    def run(self, func, param, thread):
        print("kernel_thread_start", func)
        return 0


class ThreadWakeupThread(angr.SimProcedure):
    def run(self):
        print("call thread_wakeup_thread")


class OSAddAtomic16(angr.SimProcedure):
    """https://developer.apple.com/documentation/kernel/1576475-osaddatomic16?language=objc
    """

    def run(self, amount, addr):
        print("call OSAddAtomic16", amount, addr)
        val = self.state.mem[addr].uint16_t.resolved
        new_val = val + self.state.regs.di
        self.state.memory.store(
            addr, new_val, endness=self.state.arch.memory_endness, inspect=False)
        return val


class OSStringInitWithCString(angr.SimProcedure):
    """bool OSString::initWithCStringNoCopy(char const*)"""

    def run(self, this, cstr):
        logger.debug("call OSString::initWithCStringNoCopy %s %s", this, cstr)
        if self.state.solver.eval(cstr) == 0:
            return 0
        _lengthOff = LLDBDebugger.fieldOffset("length", "OSString")
        _stringOff = LLDBDebugger.fieldOffset("string", "OSString")
        length = strnlen(self.state, cstr, MAX_MEMORY_SIZE,
                         ret_size=32, annotate=False)
        # self.state.mem[this+_lengthOff].uint32_t = length + 1
        self.state.memory.store(this+_lengthOff, length+1, size=4,
                                endness=self.state.arch.memory_endness, inspect=False)

        ptr = brkAlloc(self.state, MAX_MEMORY_SIZE, tag=True)
        # self.state.mem[this+_stringOff].uint64_t = ptr
        self.state.memory.store(this+_stringOff, ptr, size=8,
                                endness=self.state.arch.memory_endness, inspect=False)
        max_size = self.state.solver.max(length)
        src_mem = self.state.memory.load(cstr, max_size, inspect=False)
        self.state.memory.store(ptr, src_mem, size=max_size, inspect=False)
        return 1


class OSStringInitWithCStringNoCopy(angr.SimProcedure):
    """bool OSString::initWithCStringNoCopy(const char *cString)
    inlined strlen causes concretization
    """

    def run(self, this, cstr):
        logger.debug("call OSString::initWithCStringNoCopy %s %s", this, cstr)
        if self.state.solver.eval(cstr) == 0:
            return 0
        _lengthOff = LLDBDebugger.fieldOffset("length", "OSString")
        _stringOff = LLDBDebugger.fieldOffset("string", "OSString")

        length = strnlen(self.state, cstr, MAX_MEMORY_SIZE,
                         ret_size=32, annotate=False)
        self.state.memory.store(this+_lengthOff, length+1, size=4,
                                endness=self.state.arch.memory_endness, inspect=False)
        self.state.memory.store(this+_stringOff, cstr, size=8,
                                endness=self.state.arch.memory_endness, inspect=False)
        # self.state.mem[this+_lengthOff].uint32_t = length + 1
        # self.state.mem[this+_stringOff].uint64_t = cstr
        return 1


class ClockGetTime(angr.SimProcedure):
    def run(self, secp, usecp):
        t = time.time()
        sec = int(t)
        usec = int((t-sec)*1000000)
        self.state.memory.store(
            secp, self.state.solver.BVV(sec, 32), inspect=False)
        self.state.memory.store(
            usecp, self.state.solver.BVV(usec, 32), inspect=False)


def IORecursiveLockLock(state):
    logger.debug("call IORecursiveLockLock")
    # lock = state.solver.eval(state.regs.rdi)
    # IORecursiveLock * _lock->thread = 0;
    # thread = state.memory.load(lock+0x18, 8, endness=state.arch.memory_endness, inspect=False)
    # curThread = state.memory.load(state.regs.gs+0x8, 8, endness=state.arch.memory_endness, inspect=False)
    # print("thread:", thread, curThread)
    # state.memory.store(lock+0x18, state.solver.BVV(0, 64), inspect=False)
    # lock->count = 0
    # count = state.memory.load(lock+0x20, 4, endness=state.arch.memory_endness, inspect=False)
    # print("count:", count)
    # state.memory.store(lock+0x20, state.solver.BVV(0, 32), inspect=False)


class copyClientEntitlement(angr.SimProcedure):
    def run(self, task, entitlement):
        logger.debug("call copyClientEntitlement")
        key = self.state.mem[entitlement].string.concrete.decode("utf8")
        logger.debug("call copyClientEntitlement %s", key)
        logger.debug("return kIOBooleanTrue %s", hex(
            self.state.globals["kIOBooleanTrue"]))
        if key not in options.getConfigKey("entitlements"):
            raise Exception("Unknown entitlement %s" % key)
        return self.state.globals["kIOBooleanTrue"]


class ReadRandom(angr.SimProcedure):
    def run(self, buf, count):
        size = self.state.solver.max_int(count)
        if size > MAX_MEMORY_SIZE:
            size = 1024
        ptr = self.state.solver.eval(buf)
        for i in range(size):
            b = random.randrange(256)
            self.state.memory.store(ptr+i, self.state.solver.BVV(b, 8))
        return count


class OSSymbolPoolFindSymbol(angr.SimProcedure):
    """OSSymbolPool::findSymbol(char const*)"""
    NO_RET = True

    def run(self, this, cstr):
        logger.debug("call OSSymbolPool::findSymbol")
        # if it is symbolic string, we directly return 0 to avoid concretization.
        for i in range(1024):
            c = self.state.memory.load(cstr+i, 1, inspect=False)
            if self.state.solver.symbolic(c):
                self.ret(0)
                return
            elif self.state.solver.is_true(c == 0):
                break

        self.successors.add_successor(
            self.state,
            self.state.addr,
            self.state.solver.true,
            "Ijk_NoHook",
        )


class OSSymbolPoolInsertSymbol(angr.SimProcedure):
    """OSSymbolPool::insertSymbol(OSSymbol*)"""

    def run(self, this, symbol):
        logger.debug("call OSSymbolPool::insertSymbol %s", symbol)
        # return symbol
        # FIXME: how to model different versions
        return 0


class OSDictionaryGetObject(angr.SimProcedure):
    """OSObject *OSDictionary::getObject(const OSSymbol *aKey) const"""

    def run(self, this, key):
        logger.debug("call OSDictionary::getObject")
        if self.state.solver.eval(key) == 0:
            return 0
        _dictOff = LLDBDebugger.fieldOffset("dictionary", "OSDictionary")
        _countOff = LLDBDebugger.fieldOffset("count", "OSDictionary")
        count_max = self.state.solver.max(
            self.state.mem[this+_countOff].uint32_t.resolved
        )
        count_min = self.state.solver.min(
            self.state.mem[this+_countOff].uint32_t.resolved
        )
        logger.debug("max count: %d %d", count_min, count_max)
        count = max(count_min, min(4, count_max))
        dictionary = self.state.solver.eval(
            self.state.mem[this+_dictOff].uint64_t.resolved
        )
        if dictionary == 0:
            return 0

        _stringOff = LLDBDebugger.fieldOffset("string", "OSSymbol")
        _lengthOff = LLDBDebugger.fieldOffset("length", "OSSymbol")
        for i in range(count):
            sym = self.state.solver.eval(
                self.state.mem[dictionary+i*16].uint64_t.resolved
            )
            value = self.state.solver.eval(
                self.state.mem[dictionary+i*16+8].uint64_t.resolved
            )
            if self.state.solver.eval(key) == sym:
                logger.debug("find key!")
                return value
            logger.debug("%d %x %x", i, sym, value)
            if sym == 0 or value == 0:
                break

            # s1 must be concrete while s2 can be symbolic
            s1 = self.state.solver.eval(
                self.state.mem[sym+_stringOff].uint64_t.resolved
            )
            s2 = self.state.mem[key+_stringOff].uint64_t.resolved
            # assume c1 is concrete
            size = self.state.solver.eval(
                self.state.mem[sym+_lengthOff].uint32_t.resolved
            )
            logger.debug("find symbol %s", self.state.mem[s1].string.concrete)
            mem = self.state.memory.load(s1, size, inspect=False)
            mem2 = self.state.memory.load(s2, size)
            if self.state.solver.solution(mem2, mem):
                # if s1 == s2
                new_state = self.state.copy()
                self.state.solver.add(mem2 == mem)
                self.ret(value)
                self.state = new_state

        self.ret(0)


def SafeMetaCast(state):  # self, base, meta):
    base = state.regs.rdi
    meta = state.regs.rsi
    logger.debug("call OSMetaClassBase::safeMetaCast %s, %s", base, meta)
    if not state.solver.symbolic(base):
        return

    # It also triggers concretization of this pointer
    # if it is not done already.
    vtable = state.mem[base].uint64_t.resolved
    if not state.solver.symbolic(vtable):
        return

    executor: BaseExecutor = state.globals.get("executor", None)
    if executor is None:
        return

    meta_addr = state.solver.eval(meta)
    sym = executor.find_symbol_by_addr(meta_addr)
    if sym:
        # e.g., IOUSBHostDevice::gMetaClass
        gMeta = demangle(sym.name)[:-len("::gMetaClass")]
        logger.debug("cast to %s", gMeta)
        # get vtable for it
        k = f"__ZTV{len(gMeta)}{gMeta}"
        vtable = executor.find_symbol_by_name(sym.owner, k)
        if vtable:
            state.mem[base].uint64_t = executor.getTargetAddr(
                vtable.relative_addr + 0x10,
                target=vtable,
            )
            return

    from IPython import embed
    embed()
    raise RuntimeError()
    # from IPython import embed; embed()


class ProcName(angr.SimProcedure):
    def run(self, pid, buf, size):
        # TODO
        self.state.memory.store(buf+1, self.state.solver.BVV(0, 8))
        return


class MacModel(FuncModel):
    def __init__(self):
        pass

    def getFunc2Model(self):
        funcWithZero = DummyModel("funcWithZero")
        funcWithOne = DummyModel("funcWithOne", ret_value=1)
        terminator = StateTerminator()
        models = {
            "IOCommandGate::runAction": runAction(),
            "IOWorkLoop::runAction": IOWorkLoopRunAction(),
            "IOGeneralMemoryDescriptor::prepare": MemPrepare(),
            "IOMemoryDescriptor::writeBytes": MemWriteBytes(),
            "IOMemoryDescriptor::readBytes": MemReadBytes(),
            "IOGeneralMemoryDescriptor::initWithOptions": InitWithOptions(),
            "IOGeneralMemoryDescriptor::complete": funcWithZero,
            "IOMemoryDescriptor::makeMapping": MakeMapping(),
            "IOMemoryMap::getVirtualAddress": GetVirtualAddress(),
            "IOMemoryMap::getMemoryDescriptor": GetMemoryDescriptor(),
            "IOMemoryMap::free()": funcWithZero,
            "lck_mtx_lock": funcWithZero,
            "lck_mtx_lock_spin_always": funcWithZero,
            "lck_mtx_unlock": funcWithZero,
            "lck_spin_lock": funcWithZero,
            "lck_spin_unlock": funcWithZero,
            "lck_mtx_try_lock": funcWithOne,
            "lck_mtx_lock_spin": funcWithZero,
            "IOSimpleLockLock": funcWithZero,
            "IOSimpleLockUnLock": funcWithZero,
            "OSObject::release()": funcWithZero,
            "IOMalloc": IOMalloc(),
            "kalloc_canblock": KallocCanblock(),
            "zalloc": Zalloc(),
            "IOFree": funcWithZero,
            "kfree": funcWithZero,
            "zfree": funcWithZero,
            "bzero": bzero(),
            "memset": Memset(),
            "snprintf": Snprintf(),
            # "IORecursiveLockLock": IORecursiveLockLock,
            # "IORecursiveLockUnlock": funcWithZero,
            "proc_name": ProcName(),

            "__memmove_chk": MemmoveChk(),
            "memmove": Memmove(),
            "memcpy": Memmove(),
            "bcopy": Memmove(),
            "strnlen": Strnlen(),
            "strlen": Strlen(),
            "IOLog": funcWithZero,
            "_os_log_internal": funcWithZero,
            "kprintf": funcWithZero,
            # "OSAddAtomic16": OSAddAtomic16(),
            "kernel_thread_start": KernelThreadStart(),
            "thread_wakeup_thread": ThreadWakeupThread(),
            "IOEventSource::signalWorkAvailable": funcWithOne,
            "IOTimerEventSource::setTimeout(unsigned int, unsigned int)": funcWithZero,
            "IOTimerEventSource::setTimeout(unsigned long long)": funcWithZero,
            "IOTimerEventSource::setTimeout(unsigned int, unsigned long long, unsigned long long)": funcWithZero,
            "IOCommandGate::commandWakeup": funcWithZero,
            "IOCommandGate::commandSleep(void*, unsigned int)": funcWithZero,
            "IOCommandGate::commandSleep(void*, unsigned long long, unsigned int)": funcWithZero,
            "IOWorkLoop::removeEventSource(IOEventSource*)": funcWithZero,
            "mach_msg_send_from_kernel_proper": funcWithZero,

            "IOBufferMemoryDescriptor::initWithPhysicalMask": InitWithPhysicalMask(),
            "IOBufferMemoryDescriptor::setLength": IOBufferSetLength(),
            "IOBufferMemoryDescriptor::getBytesNoCopy()": IOBufferGetBytesNoCopy(),
            "IOBufferMemoryDescriptor::appendBytes": IOBufferAppendBytes(),

            "ml_io_read": funcWithZero,
            "clock_get_system_microtime": ClockGetTime(),
            "IOService::terminate": funcWithZero,

            "IOUserClient::copyClientEntitlement": copyClientEntitlement(),
            "IOUserClient::clientHasPrivilege": funcWithZero,
            "read_random": ReadRandom(),

            # TODO: model OSDictionary properly
            "OSUnserializeXML(char const*, unsigned long, OSString**)": funcWithZero,

            "vnode_authorize": funcWithZero,
            "vprintf": funcWithZero,
            "tsleep": funcWithZero,
            'msleep': funcWithZero,

            "copyin": Copyin(),
            # OSDictionary::getObject(OSString const*)
            "OSSymbolPool::insertSymbol(OSSymbol*)": OSSymbolPoolInsertSymbol(),
            "OSSymbolPool::findSymbol(char const*)": OSSymbolPoolFindSymbol(),
            "OSDictionary::getObject(OSSymbol const*)": OSDictionaryGetObject(),
            "OSString::initWithCStringNoCopy(char const*)": OSStringInitWithCStringNoCopy(),
            "OSString::initWithCString(char const*)": OSStringInitWithCString(),

            "iokit_make_send_right": funcWithZero,
            "IOService::waitQuiet(unsigned long long)": funcWithZero,

            "IORegistryEntry::setProperty(OSSymbol const*, OSObject*)": funcWithOne,
            "IORegistryEntry::setProperty(char const*, OSObject*)": funcWithOne,
            "IORegistryEntry::removeProperty(char const*)": funcWithZero,

            "__stack_chk_fail": terminator,
            "panic": terminator,
            "OSObject::taggedRetain": funcWithZero,
            "OSObject::taggedRelease": funcWithZero,
        }

        return models

    def getFunc2Hook(self):
        # Hook methods without replacing them
        hooks = {
            # "IOMalloc": IOMalloc
            # "OSSymbol::withCStringNoCopy": OSSymbolString,
            # "OSString::withCString": OSStringWithCString,
            # "IORecursiveLockLock": IORecursiveLockLock,
            "OSMetaClassBase::safeMetaCast(OSMetaClassBase const*, OSMetaClass const*)": SafeMetaCast,
        }
        return hooks
