
import socket
import struct
import json
import logging

from angr_targets.concrete import ConcreteTarget
from angr.errors import SimConcreteMemoryError, SimConcreteRegisterError

from syzgen.models import isAllocObject
from syzgen.utils import UnusedTcpPort

logger = logging.getLogger(__name__)


class ProxyException(Exception):
    pass


def check_error(f):
    def wrapper(*args, **kwargs):
        reply = f(*args, **kwargs)
        if isinstance(reply, dict):
            if reply["errcode"] != 0:
                raise ProxyException(
                    f'receive err: {str(reply)} '
                    f' for {" ".join(map(str, args))}'
                )
        return reply

    return wrapper


class Proxy:
    def __init__(self, port=None, timeout=120):
        self.sock = None
        self.port = port or UnusedTcpPort()
        self.slide = 0
        self.timeout = timeout

        self.serv: socket.socket = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM)
        self.serv.bind(('localhost', self.port))
        logger.debug("set up debugger server on port %d", self.port)
        self.serv.listen(1)

    def __enter__(self):
        self.serve()
        return self

    def __exit__(self, type, value, tb):
        self.pause()
        if self.sock:
            # only close the connection rather than terminating the server as `exit` does.
            self.sock.close()
            self.sock = None
        logger.info("please disconnect the debugger on the other side...")

    def is_alive(self):
        return self.sock is not None

    def serve(self):
        logger.info("start server, waiting for debugger to connect...")
        try:
            self.serv.settimeout(self.timeout)
            conn, _ = self.serv.accept()
            self.serv.settimeout(None)
            self.sock = conn
            logger.debug("connect to client")
        except socket.timeout:
            logger.error("failed to connect to debugger")
            raise ProxyException("accept timeout")

    def exit(self):
        if self.sock:
            self.sock.close()
            # self.sock = None
        if self.serv:
            self.serv.close()
            # self.serv = None

    def send(self, data):
        request = json.dumps(data).encode()
        self.sock.sendall(struct.pack("<I", len(request)))
        self.sock.sendall(request)

    def recvn(self, nbytes):
        remain = nbytes
        ret = b''
        while remain > 0:
            data = self.sock.recv(remain)
            if not data:
                raise ConnectionResetError("connection is broken")
            ret += data
            remain -= len(data)
        return ret

    def recv_reply(self, fmt="json"):
        size = self.recvn(4)
        size = struct.unpack("<I", size)[0]
        logger.debug("receive size: %d", size)
        if size == 0:
            return None

        data = self.recvn(size)
        if fmt == "json":
            return json.loads(data)
        return data

    @check_error
    def request(self, request, fmt="json", timeout=None):
        self.send(request)
        try:
            self.sock.settimeout(timeout)
            ret = self.recv_reply(fmt=fmt)
            self.sock.settimeout(None)
            return ret
        except socket.timeout:
            raise ProxyException("timeout for request %s" % request)

    def pause(self, timeout=10):
        """Allow our debugger's proxy to yield the control back to the debugger"""
        request = {
            "cmd": "pause",
        }
        self.request(request)

    def read_register(self, reg_name):
        request = {
            "cmd": "read reg",
            "reg": reg_name
        }
        reply = self.request(request)
        return reply["val"]

    def read_memory(self, address, nbytes, **kwargs):
        raise NotImplementedError

    def set_breakpoint(self, addr, **kwargs):
        raise NotImplementedError()

    def wait_breakpoint(self, timeout=None):
        """Wait until a breakpoint is hit"""
        request = {
            "cmd": "wait",
        }
        self.request(request, timeout=timeout)

    def remove_breakpoints(self):
        """Remove all breakpoints"""
        request = {
            "cmd": "rm bp"
        }
        self.request(request)

    def find_section_name(self, addr) -> str:
        """Get the name of the section containning this addr.
        Note it may only work for sections in the main object loaded by the debugger"""
        raise NotImplementedError()

    def find_symbol_name(self, addr) -> str:
        """Get the name of the symbol at this addr.
        Note it may only work for symbols in the main object loaded by the debugger"""
        raise NotImplementedError()

    def continue_run(self):
        """Continue. Note for GDB, this will block until the breakpoint is hit"""
        request = {
            "cmd": "continue"
        }
        self.request(request)

    def find_functions_addr(self, names):
        """Find the addresses of the functions given their names"""
        request = {
            "cmd": "find func",
            "names": names
        }
        reply = self.request(request)
        return reply["funcs"]

    def output(self, msg):
        """Print a message to the console"""
        request = {
            "cmd": "output",
            "msg": msg
        }
        self.request(request)


class DebuggerConcreteTarget(ConcreteTarget):
    def __init__(self, proxy):
        super(DebuggerConcreteTarget, self).__init__()
        self.proxy: Proxy = proxy

    def read_register(self, register, **kwargs):
        try:
            val = self.proxy.read_register(register)
            if isinstance(val, str):
                if val.startswith("0x"):
                    return int(val, 16)
                return int(val)
            else:
                return val
        except:
            logger.debug("failed to register %s", register)
            raise SimConcreteRegisterError("reg: %s" % register)

    def read_memory(self, address, nbytes, **kwargs):
        try:
            logger.debug("read %d from %#x", nbytes, address)
            if isAllocObject(address):  # special region for allocation
                return b'\x00'*nbytes
            res = self.proxy.read_memory(address, nbytes, **kwargs)
            if res is None:
                logger.error("failed to read %#x", address)
                return b'\x00'*nbytes
            return res
        except:
            raise SimConcreteMemoryError(
                "read mem addr: %x %d" % (address, nbytes))

    def exit(self):
        # self.sock.close()
        pass
