import os
import time
import socket
import struct
import json
import argparse
import shlex
import traceback

def catch_exception(f):
    def wrapper(*args, **kwargs):
        ret = {}
        try:
            data = f(*args, **kwargs)
            if data:
                ret.update(data)
            ret["errcode"] = 0
        except Exception as e:
            print(e)
            ret["errcode"] = 1
        return ret

    return wrapper

class Proxy(object):
    '''Generic proxy base'''

    def __init__(self):
        self.parser = self.create_options()
        self.sock = None
        self.port = int(os.getenv("PROXY_PORT"))
        assert self.port, "PORT is not set"

    def create_options(self):
        parser = argparse.ArgumentParser(prog=self.program, add_help=False)
        parser.add_argument("-c", "--connect", action="store_true", default=False, help="connect to client")
        parser.add_argument("-e", "--exit", action="store_true", default=False, help="quit")
        parser.add_argument("-r", "--restart", action="store_true", default=False, help="restart after pause")
        parser.add_argument("-t", "--test", action="store_true", default=False, help="testing")
        parser.add_argument("-f", "--find", action="store_true", default=False, help="helping function")
        parser.add_argument("-i", "--ip", default="localhost", help="ip address of client, default localhost")
        parser.add_argument("-h", "--help", action="store_true", default=False, help="show this help message")
        return parser

    def call_from_debugger(self, arg):
        command_args = shlex.split(arg)
        args = self.parser.parse_args(command_args)
        if args.connect:
            self.connect(args.ip)
        elif args.restart:
            self.serve_forever()
        elif args.exit:
            self.disconnect()
        elif args.test:
            self.test()
        elif args.find:
            self.set_breakpoint()
        elif args.help:
            self.parser.print_help()

    def test(self):
        raise NotImplementedError

    def run_cmd(self, cmd):
        raise NotImplementedError

    def connect(self, ip):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ip, self.port))
        print("successfully connect to the server")
        self.serve_forever()

    def disconnect(self):
        if self.sock:
            print("disconnect...")
            self.sock.close()
            self.sock = None

    def recvn(self, nbytes):
        remain = nbytes
        ret = b''
        while remain > 0:
            data = self.sock.recv(remain)
            if not data:
                raise Exception("connection is broken")
            ret += data
            remain -= len(data)
        return ret
    
    def send(self, data):
        # print("send data: ", data)
        if data is None:
            self.sock.sendall(struct.pack("<I", 0))
        else:
            if isinstance(data, dict):
                data = json.dumps(data).encode()
            self.sock.sendall(struct.pack("<I", len(data)))
            self.sock.sendall(data)

    def serve_forever(self):
        if self.sock is None: return
        print("start listening")
        while True:
            size = self.recvn(4)
            size = struct.unpack("<I", size)[0]
            data = self.recvn(size)
            request = json.loads(data)
            if self.handle_command(request):
                break

    def handle_command(self, request):
        '''
        return: True to exit the loop
        '''
        # print("receive command: ", request)
        cmd = request["cmd"]
        if cmd == "pause":
            self.handle_pause(**request)
            return True
        elif cmd == "exit":
            self.disconnect()
            return True
        elif cmd == "read mem":
            try:
                val = self.read_memory(**request)
                if val and len(val) > 0:
                    self.send(val)
                    return False
            except:
                pass
            self.send(None)
            return False
        elif cmd == "continue":
            self.handle_continue(**request)
            return False

        func = getattr(self, "handle_" + cmd.replace(' ', '_'), None)
        if func:
            try:
                ret = func(**request)
                if ret is None:
                    ret = {}
                ret["errcode"] = 0
                self.send(ret)
            except Exception as e:
                print(traceback.format_exc())
                self.send({"errcode": 1, **request})
        else:
            print("unsupported command %s" % cmd)
            self.send({"errcode": 2})

        return False

    def handle_pause(self, **kwargs):
        """yield the control back to the debugger"""
        self.send({"errcode": 0})

    def read_register(self, reg, **kwargs):
        raise NotImplementedError()

    def read_memory(self, addr=0, size=0, **kwargs):
        raise NotImplementedError()

    def handle_read_reg(self, reg = "", **kwargs):
        ret = {}
        reg_name = str(reg)  # FIXME: python2 style
        val = self.read_register(reg_name)
        print("read register %s: %s" % (reg_name, val))
        ret["val"] = val
        return ret

    def handle_continue(self, **kwargs):
        """Continue the process"""
        raise NotImplementedError()

    def handle_set_bp(self, addr=0, target="", **kwargs):
        """Set breakpoint for a specific process"""
        raise NotImplementedError()

    def handle_rm_bp(self, **kwargs):
        """Remove all breakpoints"""
        raise NotImplementedError()

    def isStop(self):
        """Check if the process is stopped"""
        raise NotImplementedError()

    def handle_wait(self, timeout=15, **kwargs):
        """wait until the process stops or timeout"""
        elapsed = 0
        while elapsed <= timeout:
            if self.isStop():
                break
            time.sleep(1)
            elapsed += 1

        if elapsed > timeout:
            raise Exception("timeout while waiting for breakpoint")

    def find_function_addr(self, name):
        raise NotImplementedError()

    def handle_find_func(self, names=[], **kwargs):
        """Find the function address"""
        funcs = dict()
        for name in names:
            try:
                name = str(name)  # FIXME: python2 style
                ret = self.find_function_addr(name)
                funcs[name] = ret
            except Exception as e:
                print(e)
        return {"errcode": 0, "funcs": funcs}

    def handle_output(self, msg="", **kwargs):
        """Output the debug information"""
        raise NotImplementedError()
