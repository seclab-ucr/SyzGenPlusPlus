
import logging

import angr
from angr.calling_conventions import DefaultCC
from angr.sim_state import SimState
from claripy.ast.bv import Extract
from syzgen.analysis.plugins.record_alloc import RecordInputSymAllocation
from syzgen.analysis.plugins.recovery import reserve_type_from_input
from syzgen.models.utils import check_pointer, concretize_user_pointer, memcpy, track_length

from syzgen.parser.types import PtrDir

from syzgen.config import Options

from syzgen.models import (
    MAX_MEMORY_SIZE,
    CurrentTime,
    FindObjectException,
    FuncModel, DummyModel,
    GenericMalloc,
    GetMonons,
    HeapAllocator, NamedSimProcedure,
    ReturnUnconstrained,
    Snprintf, StateTerminator,
    Strcpy, Strlen,
    brkAlloc, Memset,
)
from syzgen.utils import extractSymbols

logger = logging.getLogger(__name__)
options = Options()


class AllocPages(angr.SimProcedure):
    def run(self, mask, order):
        logger.debug("Call alloc_pages %s", order)
        if self.state.solver.symbolic(order):
            size = 4096 * 8
        else:
            size = 4096 * (2 ** self.state.solver.eval(order))
        return brkAlloc(self.state, size)


class KmallocTrackCaller(angr.SimProcedure):
    def run(self, size, flag, caller):
        logger.debug("Call __kmalloc_track_caller %s", size)
        return brkAlloc(self.state, size, tag=True)


class Vmalloc(angr.SimProcedure):
    def run(self, size, flag):
        logger.debug("Call __vmalloc %s", size)
        return brkAlloc(self.state, size, tag=True)


class AllocPerCPU(angr.SimProcedure):
    def run(self, size, align):
        logger.debug("Call __alloc_percpu %s", size)
        return brkAlloc(self.state, size, tag=True)


class KmemCacheAllocTrace(angr.SimProcedure):
    def run(self, cache, flags, size):
        # void *kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags, size_t size)
        logger.debug("Call kmem_cache_alloc_trace %s", size)
        return brkAlloc(self.state, size, tag=True)


class KmemCacheAlloc(NamedSimProcedure):
    def run(self, cache, flags):
        # kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
        addr = self.state.solver.eval(cache)
        logger.debug("call %s %s %#x", self._name, cache, addr)
        # we do not know the exact size for the cache, fall back to a default size
        return brkAlloc(self.state, MAX_MEMORY_SIZE, tag=True)

        # if self.state.solver.symbolic(cache):
        #     logger.debug("symbolic cache %s", cache)
        #     if not isValidPointer(addr):
        #         return brkAlloc(self.state, MAX_MEMORY_SIZE, tag=True)
        # else:
        #     if addr == 0:
        #         return brkAlloc(self.state, MAX_MEMORY_SIZE, tag=True)

        # from IPython import embed
        # embed()
        # raise RuntimeError(f"Unknown cache 0x{addr:x}")


class KmallocNode(NamedSimProcedure):
    def run(self, size, flags, node):
        # void *kvmalloc_node(size_t size, gfp_t flags, int node)
        logger.debug("Call %s %s", self._name, size)
        return brkAlloc(self.state, size, tag=True)


class Memcpy(angr.SimProcedure):
    def run(self, dst, src, src_len):
        logger.debug("call memcpy %s %s %s", dst, src, src_len)
        return memcpy(self.state, dst, src, src_len)


class Memcmp(angr.SimProcedure):
    def run(self, s1_addr, s2_addr, n):
        logger.debug("call memcmp")
        memcmp = angr.SIM_PROCEDURES['libc']['memcmp']
        res = self.inline_call(memcmp, s1_addr, s2_addr, n).ret_expr
        if res.length < 64:
            res = res.sign_extend(64 - res.length)
        return res


class CopyFromUser(angr.SimProcedure):
    '''_copy_from_user(void *to, const void __user *from, unsigned long n)
    '''

    def run(self, to, addr, length):
        logger.debug("Call _copy_from_user %s %s %s", to, addr, length)
        if not check_pointer(self.state, addr):
            return

        if self.state.solver.symbolic(length):
            track_length(self.state, addr, length)

            size = self.state.solver.max_int(length)
        else:
            size = self.state.solver.eval(length)

        if size > MAX_MEMORY_SIZE:
                size = MAX_MEMORY_SIZE
                # self.state.solver.add(length <= MAX_MEMORY_SIZE)

        addr, size = concretize_user_pointer(self.state, addr, size)
        cont = self.state.memory.load(addr, size, inspect=False)
        self.state.memory.store(to, cont, inspect=self.state.solver.symbolic(to))
        return 0


class GetUser1(angr.SimProcedure):
    def run(self):
        logger.debug("get_user_1: %s", self.state.regs.rax)
        if not check_pointer(self.state, self.state.regs.rax):
            return

        addr, _ = concretize_user_pointer(self.state, self.state.regs.rax, 1)
        cont = self.state.memory.load(
            addr, 1, endness=self.state.arch.memory_endness, inspect=False)
        self.state.regs.edx = cont.zero_extend(32 - 8)
        return 0


class GetUser2(angr.SimProcedure):
    def run(self):
        logger.debug("get_user_2: %s", self.state.regs.rax)
        if not check_pointer(self.state, self.state.regs.rax):
            return

        addr, _ = concretize_user_pointer(self.state, self.state.regs.rax, 2)
        cont = self.state.memory.load(
            addr, 2, endness=self.state.arch.memory_endness, inspect=False)
        self.state.regs.edx = cont.zero_extend(32 - 16)
        return 0


class GetUser4(angr.SimProcedure):
    def run(self):
        # from IPython import embed; embed()
        # read from %rax and store to %edx
        logger.debug("get_user_4: %s", self.state.regs.rax)
        if not check_pointer(self.state, self.state.regs.rax):
            return

        addr, _ = concretize_user_pointer(self.state, self.state.regs.rax, 4)
        cont = self.state.memory.load(
            addr, 4, endness=self.state.arch.memory_endness, inspect=False)
        self.state.regs.edx = cont
        return 0


class GetUser8(angr.SimProcedure):
    def run(self):
        logger.debug("get_user_8: %s", self.state.regs.rax)
        if not check_pointer(self.state, self.state.regs.rax):
            return

        addr, _ = concretize_user_pointer(self.state, self.state.regs.rax, 8)
        cont = self.state.memory.load(
            addr, 8, endness=self.state.arch.memory_endness, inspect=False)
        self.state.regs.rdx = cont
        return 0


class PutUser1(angr.SimProcedure):
    def run(self):
        # movl %eax,(%_ASM_CX)
        # xor %ecx,%ecx
        val = self.state.regs.al
        addr = self.state.regs.rcx
        logger.debug("call __put_user_1 %s %s", val, addr)
        if not check_pointer(self.state, addr):
            return

        addr, _ = concretize_user_pointer(self.state, addr, 1, PtrDir.DirOut)
        self.state.memory.store(addr, val, inspect=False)
        self.state.regs.ecx = 0


class PutUser2(angr.SimProcedure):
    def run(self):
        # movl %eax,(%_ASM_CX)
        # xor %ecx,%ecx
        val = self.state.regs.ax
        addr = self.state.regs.rcx
        logger.debug("call __put_user_2 %s %s", val, addr)
        if not check_pointer(self.state, addr):
            return

        addr, _ = concretize_user_pointer(self.state, addr, 2, PtrDir.DirOut)
        self.state.memory.store(addr, val, inspect=False)
        self.state.regs.ecx = 0


class PutUser4(angr.SimProcedure):
    def run(self):
        # movl %eax,(%_ASM_CX)
        # xor %ecx,%ecx
        val = self.state.regs.eax
        addr = self.state.regs.rcx
        logger.debug("call __put_user_4 %s %s", val, addr)
        if not check_pointer(self.state, addr):
            return

        addr, _ = concretize_user_pointer(self.state, addr, 4, PtrDir.DirOut)
        self.state.memory.store(addr, val, inspect=False)
        self.state.regs.ecx = 0


class PutUser8(angr.SimProcedure):
    def run(self):
        # movl %eax,(%_ASM_CX)
        # xor %ecx,%ecx
        val = self.state.regs.rax
        addr = self.state.regs.rcx
        logger.debug("call __put_user_8 %s %s", val, addr)
        if not check_pointer(self.state, addr):
            return

        addr, _ = concretize_user_pointer(self.state, addr, 8, PtrDir.DirOut)
        self.state.memory.store(addr, val, inspect=False)
        self.state.regs.ecx = 0


class CopyToUser(angr.SimProcedure):
    '''_copy_to_user(void *to, const void __user *from, unsigned long n)
    '''

    def run(self, to, src, length):
        logger.debug("Call _copy_to_user %s %s %s", to, src, length)
        if not check_pointer(self.state, to):
            return

        if self.state.solver.symbolic(length):
            track_length(self.state, to, length)

            size = self.state.solver.max_int(length)
            if size > MAX_MEMORY_SIZE:
                size = MAX_MEMORY_SIZE
                # self.state.solver.add(length <= MAX_MEMORY_SIZE)
        else:
            size = self.state.solver.eval(length)
            if size > MAX_MEMORY_SIZE:
                size = MAX_MEMORY_SIZE

        addr, size = concretize_user_pointer(
            self.state, to, size, direction=PtrDir.DirOut)
        if not check_pointer(self.state, src):
            return

        cont = self.state.memory.load(src, size, inspect=self.state.solver.symbolic(src))
        self.state.memory.store(addr, cont, inspect=False)

        # logger.debug("copied content: %s", cont)
        # from IPython import embed; embed()
        res = extractSymbols(cont, merge=True)
        if any(each.args[0].startswith("alloc_fd") for each in res):
            logger.debug("found alloc_fd in the output")
            for i in range(size):
                b = self.state.memory.load(src+i, 1, inspect=False)
                logger.debug("%d: %s", i, b)
                res = extractSymbols(b, merge=True)
                if any(each.args[0].startswith("alloc_fd") for each in res):
                    # to + i
                    logger.debug("offset: %d", i)
                    executor = self.state.globals["executor"]
                    if isinstance(executor, RecordInputSymAllocation):
                        b, sym = executor.get_alloc_sym(self.state, addr)
                        left = max(0, sym.length - (addr - b + i) * 8 - 1)
                        right = max(0, sym.length - (addr - b + i + 4) * 8)
                        expr = Extract(left, right, sym) if sym.length > 32 else sym
                        reserve_type_from_input(executor, self.state, expr, "alloc_fd", 4)
                    break
        return 0


class ClearUser(angr.SimProcedure):
    def run(self, ptr, length):
        logger.debug("call clear_user %s and %s", ptr, length)
        if not check_pointer(self.state, ptr):
            return

        addr, _ = concretize_user_pointer(self.state, ptr, 4, PtrDir.UNKNOWN)
        size = self.state.solver.max_int(length)
        if size > MAX_MEMORY_SIZE:
            size = MAX_MEMORY_SIZE
        zero = self.state.solver.BVV(0, 8)
        for i in range(size):
            self.state.memory.store(addr + i, zero, inspect=False)


class Ksize(angr.SimProcedure):
    def run(self, ptr):
        logger.debug("call ksize %s", ptr)
        allocator: HeapAllocator = options.heap_allocator
        try:
            return allocator.get_object_size(self.state.solver.eval(ptr))
        except FindObjectException:
            return self.state.solver.BVS("ksize_ret", size=64)


class GetRandomBytes(angr.SimProcedure):
    def run(self, buf, nbytes):
        if self.state.solver.symbolic(nbytes):
            raise NotImplementedError()
        size = self.state.solver.eval(nbytes)
        zero = self.state.solver.BVV(0, 8)
        for i in range(size):
            self.state.memory.store(buf+i, zero, inspect=self.state.solver.symbolic(buf))


class AllocFD(angr.SimProcedure):
    def run(self):
        logger.debug("call alloc_fd")
        return self.state.solver.BVS("alloc_fd", size=64)


def fget(state: SimState):
    cc = DefaultCC[state.arch.name](state.arch)
    fd = state.registers.load(cc.ARG_REGS[0], 4)
    if not state.solver.unique(fd):
        state.solver.add(fd == 0)
        reserve_type_from_input(state.globals["executor"], state, fd, "fd", 4)


class DownSemaphore(NamedSimProcedure):
    """void __sched down_write(struct rw_semaphore *sem)
    (gdb) ptype struct rw_semaphore
    type = struct rw_semaphore {
        atomic_long_t count;
        atomic_long_t owner;
        struct optimistic_spin_queue osq;
        raw_spinlock_t wait_lock;
        struct list_head wait_list;
    }"""

    def run(self, sem):
        count = self.state.memory.load(sem, 8, endness=self.state.arch.memory_endness)
        logger.debug("call %s with count", self._name, count)
        self.state.memory.store(sem, count+1, endness=self.state.arch.memory_endness)
        return 0


class UpSemaphore(NamedSimProcedure):
    """void up_write(struct rw_semaphore *sem)"""

    def run(self, sem):
        count = self.state.memory.load(sem, 8, endness=self.state.arch.memory_endness)
        logger.debug("call %s with count %s", self._name, count)
        self.state.memory.store(sem, count-1, endness=self.state.arch.memory_endness)
        return 0


class LinuxModel(FuncModel):
    def __init__(self):
        super().__init__()

    def getFunc2Model(self):
        retWithZero = DummyModel("retWithZero")
        retWithOne = DummyModel("retWithOne", ret_value=1)
        copy2user = CopyToUser()
        terminator = StateTerminator()
        procedures = {
            "__fentry__": retWithZero,
            "__lock_acquire": retWithZero,
            "lock_release": retWithZero,
            "mutex_lock": retWithZero,
            "mutex_unlock": retWithZero,
            "mutex_lock_nested": retWithZero,
            "_raw_spin_unlock": retWithZero,
            "_raw_spin_lock_bh": retWithZero,
            "_raw_spin_unlock_bh": retWithZero,
            "_raw_spin_lock": retWithZero,
            "_raw_read_lock_bh": retWithZero,
            "_raw_spin_trylock": retWithZero,
            "printk": retWithZero,
            "_printk": retWithZero,
            "vprintk": retWithZero,
            "snprintf": retWithZero,
            "vsnprintf": Snprintf(),
            "vscnprintf": Snprintf(),
            "__warn_printk": retWithZero,
            "__dev_printk": retWithZero,
            "_dev_printk": retWithZero,
            "down_read": DownSemaphore("down_read"),
            "down_write": DownSemaphore("down_write"),
            "up_write": UpSemaphore("up_write"),
            "up_read": UpSemaphore("up_read"),

            "_raw_spin_lock_irqsave": retWithZero,
            "_raw_spin_unlock_irqrestore": retWithZero,
            "_raw_read_lock_irqsave": retWithZero,
            "_raw_read_unlock_irqrestore": retWithZero,
            "_raw_spin_lock_irq": retWithZero,
            "_raw_spin_unlock_irq": retWithZero,
            "rcu_barrier": retWithZero,
            "__rcu_read_lock": retWithZero,
            "__rcu_read_unlock": retWithZero,
            "_raw_write_unlock": retWithZero,
            "_raw_read_unlock": retWithZero,
            "_raw_write_lock_irqsave": retWithZero,
            "_raw_write_unlock_irqrestore": retWithZero,
            "mutex_lock_killable": retWithZero,
            "mutex_lock_interruptible": retWithZero,
            "down_read_trylock": ReturnUnconstrained(),
            "dump_stack": retWithZero,
            "get_random_bytes": GetRandomBytes(),

            "__kmalloc_track_caller": KmallocTrackCaller(),
            "kfree": retWithZero,
            "kvfree": retWithZero,
            "__vmalloc": Vmalloc(),
            "vfree": retWithZero,
            "__kmalloc": Vmalloc(),
            "__alloc_percpu": AllocPerCPU(),
            "pcpu_alloc": AllocPerCPU(),
            "free_percpu": retWithZero,
            "kmem_cache_alloc_trace": KmemCacheAllocTrace(),
            # void *kvmalloc_node(size_t size, gfp_t flags, int node)
            "kvmalloc_node": KmallocNode("kvmalloc_node"),
            "__kmalloc_node": KmallocNode("__kmalloc_node"),
            # void *kmalloc_reserve(size_t size, gfp_t flags, int node, bool *pfmemalloc)
            "kmalloc_reserve": KmallocNode("kmalloc_reserve"),
            "kfree_skb": retWithZero,
            # kmem_cache_alloc(struct kmem_cache *s, gfp_t gfpflags)
            "kmem_cache_alloc": KmemCacheAlloc("kmem_cache_alloc"),
            # void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
            "kmem_cache_alloc_node": KmemCacheAlloc("kmem_cache_alloc_node"),
            "kmem_cache_free": retWithZero,
            "__slab_free": retWithZero,
            "ksize": Ksize(),
            "__check_object_size": retWithZero,
            "mmput": retWithZero,
            "__mmu_notifier_release": retWithZero,
            "mempool_alloc": GenericMalloc("mempool_alloc"),
            "__get_free_pages": AllocPages(),
            "vzalloc": KmallocNode("vzalloc"),

            "memset": Memset(),
            "memcpy": Memcpy(),
            "memcmp": Memcmp(),
            "_copy_from_user": CopyFromUser(),
            "_copy_to_user": copy2user,
            "copy_user_generic_string": copy2user,
            "copy_user_enhanced_fast_string": copy2user,
            "__get_user_1": GetUser1(),
            "__get_user_2": GetUser2(),
            "__get_user_4": GetUser4(),
            "__get_user_8": GetUser8(),
            "__put_user_1": PutUser1(),
            "__put_user_2": PutUser2(),
            "__put_user_4": PutUser4(),
            "__put_user_8": PutUser8(),
            "clear_user": ClearUser(),
            "strlen": Strlen(),
            "strcpy": Strcpy(),

            "queue_work_on": retWithOne,
            "__wake_up": retWithZero,
            "__cond_resched": retWithZero,
            "__schedule": retWithZero,
            "schedule": retWithZero,
            "msleep": retWithZero,
            "usleep_range": retWithZero,
            "do_softirq": retWithZero,
            "panic": terminator,
            "refcount_warn_saturate": terminator,
            "__stack_chk_fail": terminator,
            "on_each_cpu_cond_mask": retWithZero,
            "mm_take_all_locks": retWithZero,
            "mm_drop_all_locks": retWithZero,
            "__kthread_bind_mask": retWithZero,
            "kthread_unpark": retWithZero,
            "preempt_notifier_inc": retWithZero,
            "preempt_notifier_dec": retWithZero,

            # Debugging functions
            "__might_sleep": retWithZero,
            "__might_fault": retWithZero,
            "debug_check_no_locks_freed": retWithZero,
            "_warn_unseeded_randomness": retWithZero,
            "__list_add_valid": retWithOne,
            "__list_del_entry_valid": retWithOne,
            "debug_locks_off": retWithZero,
            "debug_object_activate": retWithZero,
            "debug_object_deactivate": retWithZero,
            "debug_object_init": retWithZero,
            "__debug_object_init": retWithZero,
            "debug_object_init_on_stack": retWithZero,
            "debug_object_destroy": retWithZero,
            "debug_object_free": retWithZero,
            "debug_object_assert_init": retWithZero,
            "debug_object_active_state": retWithZero,
            "debug_check_no_obj_freed": retWithZero,
            "debug_objects_init_debugfs": retWithZero,
            "debug_objects_mem_init": retWithZero,

            # rcu
            "call_rcu": retWithZero,
            "stack_trace_save": retWithZero,
            "kvfree_call_rcu": retWithZero,
            "rcu_init_geometry": retWithZero,
            "init_srcu_struct": retWithZero,
            "synchronize_srcu": retWithZero,
            "synchronize_rcu": retWithZero,
            "synchronize_srcu_expedited": retWithZero,
            "__call_rcu": retWithZero,

            "kobject_put": retWithZero,
            "kthread_stop": retWithZero,
            "__init_work": retWithZero,
            "cancel_work_sync": retWithZero,
            "schedule_timeout": retWithZero,
            "ktime_get_mono_fast_ns": GetMonons(),
            "ktime_get_raw": GetMonons(),
            "current_time": CurrentTime(),
            "ktime_get": GetMonons(),
            "update_rq_clock": retWithZero,
            "set_cpus_allowed_ptr": retWithZero,
            "ktime_get_ts64": retWithZero,

            # file
            "alloc_fd": AllocFD(),
            "d_instantiate": retWithZero,
            "__invalid_creds": retWithZero,
            "dump_invalid_creds": retWithZero,
            "fd_install": retWithZero,
            "fput_many": retWithZero,

            # utility
            "wake_up_process": retWithZero,
            "wait_for_completion": retWithZero,
            "sched_setscheduler_nocheck": retWithZero,
            "__SCT__cond_resched": retWithZero,
            "__SCT__might_resched": retWithZero,
            "cancel_delayed_work_sync": retWithZero,
            "queue_delayed_work_on": retWithOne,

            "__printk_ratelimit": retWithZero,
            "___ratelimit": retWithZero,
            "_printk_deferred": retWithZero,
            "check_preemption_disabled": retWithZero,
            "tracepoint_probe_unregister": retWithZero,
            "rpm_resume": retWithZero,
            "regulator_enable": retWithZero,
            "regulator_disable": retWithZero,
            "input_event": retWithZero,
            "native_smp_send_reschedule": retWithZero,
            "irq_domain_associate": retWithZero,

            "preempt_notifier_register": retWithZero,
            "__restore_fpregs_from_fpstate": retWithZero,
            "__wake_up_sync": retWithZero,
        }

        return procedures

    def getFunc2Hook(self):
        # Hook methods without replacing them
        hooks = {
            "fget": fget,
        }
        return hooks
