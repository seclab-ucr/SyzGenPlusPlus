
import argparse
import os
import time
from base import Command
from syzgen.config import Options
from syzgen.debugger import DummyDebugger
from syzgen.debugger.gdbproxy import GDBDebugger, GDBProxy
from syzgen.debugger.lldbproxy import LLDBDebugger, LLDBProxy
from syzgen.target import Target

options = Options()

class RunVM(Command):
    """Set up vm for interactive debugging"""

    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("-i", "--input", default="",
                            help="input file to run in vm")
        parser.add_argument("--attach", default=False,
                            action="store_true", help="attach a real debugger")
        return super().init_parser(parser)

    def run(self, args, target: Target):
        outfile = args.input
        if outfile and outfile.endswith(".syz"):
            outfile = "poc"
            target.compile_poc(args.input, outfile)

        target = target.get_target_for_analysis()

        with target:
            if outfile:
                dest = target.copy_file(outfile)
            if target.get_os() == "darwin":
                print("run the following commands:")
                print(f"lldb {target.inst.get_kernel()}")
                print("script")
                print("command script import %s" %
                      os.path.join(os.getcwd(), "debug.py"))
                print(f"kdp-remote {target.inst.get_ip()}")
                print("fuzz -a addr -d kext")
                proxy = target.inst.attach_debugger(
                    LLDBDebugger(target.inst.get_kernel(), target.inst.get_ip()) if args.attach else
                    DummyDebugger(target.inst.get_kernel(), LLDBProxy(timeout=None), target.inst.get_ip())
                )
                if outfile:
                    target.inst.run_cmd(["sudo", dest], check=False)
                proxy.pause()
            elif target.get_os() == "linux":
                print("remote port: %d" % target.inst.get_debug_port())
                proxy = target.inst.attach_debugger(
                    GDBDebugger(target.inst.get_kernel(), target.inst.get_ip(), target.inst.get_debug_port())
                    if args.attach else
                    DummyDebugger(target.inst.get_kernel(), GDBProxy(), target.inst.get_ip())
                )
                if outfile:
                    addr = proxy.find_functions_addr(["drm_ioctl"])["drm_ioctl"]
                    print("addr:", hex(addr))
                    proxy.set_breakpoint(addr, target=os.path.basename(dest))
                    print("set bp at %s" % hex(addr))
                    proxy.continue_run()
                    print("continue")
                    target.inst.run_cmd([dest], check=False, timeout=10)
                    print("run cmd sudo %s" % dest)

                    # from IPython import embed; embed()

                    proxy.wait_breakpoint()
                    print("breakpoint hit")
                    val = proxy.read_register("gs")
                    print("gs:", val)
                    # proxy.pause()
                # from IPython import embed; embed()
            else:
                raise NotImplementedError("unsupported os %s", target.get_os())
            try:
                while True:
                    time.sleep(2)
            except KeyboardInterrupt:
                pass


if __name__ == '__main__':
    RunVM().start()
