
import gdb

# set pagination off
# target remote :1234
# source proxy.py
# source gdb_debug.py

# from scripts/gdb/linux
def get_current_cpu():
    return gdb.selected_thread().num - 1

def per_cpu(var_ptr, cpu):
    if cpu == -1:
        cpu = get_current_cpu()

    try:
        offset = gdb.parse_and_eval(
            "__per_cpu_offset[{0}]".format(str(cpu)))
    except gdb.error:
        # !CONFIG_SMP case
        offset = 0
    pointer = var_ptr.cast(uint64) + offset
    return pointer.cast(var_ptr.type).dereference()


def get_current_task(cpu=-1):
    var_ptr = gdb.parse_and_eval("&current_task")
    return per_cpu(var_ptr, cpu).dereference()


class HitBreakpoint(gdb.Function):
    def __init__(self) -> None:
        super().__init__("is_hit_breakpoint")

    def invoke(self):
        return get_current_task()["comm"].string()

HitBreakpoint()


def lookup_types(*types):
    for type_str in types:
        try:
            return gdb.lookup_type(type_str)
        except Exception as e:
            exc = e
    raise exc

uint64 = lookup_types('unsigned long long', 'ulong', 'u64', 'uint64')
uint   = lookup_types('unsigned int', 'uint', 'u32', 'uint32')
ushort = lookup_types('unsigned short', 'ushort', 'u16', 'uint16')
uchar  = lookup_types('unsigned char', 'ubyte', 'u8', 'uint8')
task_type = lookup_types('struct task_struct')


class GDBDebugger(object):
    def __init__(self):
        pass

    def read_register(self, register, **kwargs):
        print("read register %s" % register)
        if register == "gs":
            return self.get_gs_register()

        # https://github.com/pwndbg/pwndbg/blob/05036defa01d4d47bfad56867f53470a29fcdc89/pwndbg/regs.py#L284
        val = gdb.selected_frame().read_register(register)
        val = val.cast(uint64)
        return int(val)

    def write_register(self, register, value, **kwargs):
        print("write reigster %s" % register, value)
        if type(value) == str:
            gdb.execute("set $%s = %s" % (register, value))
        elif type(value) == int:
            gdb.execute("set $%s = %d" % (register, value))
        else:
            raise Exception("unknown type %s for value" % type(value))

    def read_memory(self, addr, nbytes, **kwargs):
        result = gdb.selected_inferior().read_memory(addr, nbytes)
        return bytearray(result)

    def write_memory(self, addr, data, *args, **kwargs):
        if isinstance(data, str):
            data = bytes(data, 'utf8')
        
        gdb.selected_inferior().write_memory(addr, data)

    def get_gs_register(self, timeout=5):
        # shellcode = b'\x65\x48\x8b\x04\x25\x00\x00\x00\x00' # moveq %gs:0x0, %rax
        # orig_rax = self.read_register("rax")
        # orig_pc = self.read_register("rip")
        # orig_insts = self.read_memory(orig_pc, len(shellcode))
        # print("rax: %s, rip: %s" % (orig_rax, orig_pc))
        # print(orig_insts)

        # self.write_memory(orig_pc, shellcode)

        # self.step(timeout=timeout)

        # # restore
        # self.write_memory(orig_pc, orig_insts)
        # self.write_register("rip", orig_pc)

        # gs = self.read_register("rax")
        # self.write_register("rax", orig_rax)

        # return gs
        offset = gdb.parse_and_eval(
            "__per_cpu_offset[{0}]".format(str(get_current_cpu())))
        return int(offset.cast(uint64))

    def step(self, timeout=5):
        gdb.execute("si")


# class Recall(object):
#     def __call__(self):
#         gdb.write("proxy -r...\n")
#         gdb.execute("proxy -r")

# def handle_signal(sig, frame):
#     print("handle signal %s" % sig)
#     gdb.post_event(Recall())


class GDBProxy(gdb.Command, Proxy):
    """GDB Proxy to execute commands from server or local users
    """

    program = "proxy"

    def __init__(self):
        super(GDBProxy, self).__init__("proxy", gdb.COMMAND_USER)
        Proxy.__init__(self)

        self.debugger = GDBDebugger()

        print('The "{0}" command has been installed, type "help {0}" or "{0} -h"'
            ' for detailed help.'.format(self.program))
        # signal.signal(signal.SIGALRM, handle_signal)

    def invoke(self, arg, from_tty):
        self.dont_repeat()

        Proxy.call_from_debugger(self, arg)

    def handle_command(self, request):
       return Proxy.handle_command(self, request)

    def test(self):
        print("test")

    # def handle_pause(self, timeout=5, **kwargs):
    #     # this is only necessary for GDB in which our command
    #     # may block the entire GDB.
    #     print("set timeout %d" % timeout)
    #     signal.alarm(timeout)
    #     Proxy.handle_pause(self, **kwargs)

    def run_cmd(self, cmd):
        return gdb.execute(cmd, to_string=True)

    def read_register(self, reg_name):
        return self.debugger.read_register(reg_name)

    def read_memory(self, addr=0, size=0, **kwargs):
        return self.debugger.read_memory(addr, size)

    def handle_continue(self, **kwargs):
        if not self.isStop():
            self.send({"errcode": 1, "msg": "not stopped"})
            return

        self.send({"errcode": 0})
        # it blocks until the command is done and thus we send reply first
        gdb.execute("continue") # run in background

    def handle_wait(self, timeout=15, **kwargs):
        # continue would block the entire GDB, thus as long as we get here,
        # the thread is stopped.
        return

    def handle_set_bp(self, addr=0, target="", **kwargs):
        # set conditional breakpoint
        cmd = 'b *0x%x if $_streq($is_hit_breakpoint(), "%s")' % (addr, target)
        # cmd = 'b *0x%x' % (addr)
        self.handle_output(cmd)
        gdb.execute(cmd)

    def handle_rm_bp(self, **kwargs):
        gdb.execute("delete")

    def isStop(self):
        thread = gdb.selected_thread()
        if not thread.is_valid():
            return False
        return thread.is_stopped()

    def find_function_addr(self, name):
        val = gdb.parse_and_eval("&%s" % name)
        val = val.cast(uint64)
        return int(val)

    def handle_output(self, msg="", **kwargs):
        gdb.write(msg)

GDBProxy()
