
import json
from json.decoder import JSONDecodeError
import logging
import os
import re
import subprocess
import angr

from typing import Any, Dict, Generator, List, Optional, Set, Tuple
from syzgen.analysis.command import LinuxCommandExtractor
from syzgen.analysis.ioctl import LinuxInterfaceDiscovery, LinuxInterfaceRecovery
from syzgen.config import Options
from syzgen.debugger import DummyDebugger
from syzgen.debugger.gdbproxy import GDBDebugger, GDBProxy
from syzgen.debugger.proxy import Proxy
from syzgen.parser.models import Address
from syzgen.parser.models.ioctl import LinuxDriverModel
from syzgen.parser.syscalls.ioctl import IOCTLMethod
from syzgen.parser.syscalls.write import SysWrite

from syzgen.parser.types import Type
from syzgen.target import NoDriverException, Target
from syzgen.utils import UnusedTempFileName

logger = logging.getLogger(__name__)
options = Options()


class LinuxTarget(Target):
    NAME = "linux"

    def __init__(self, target, typ, name, **kwargs) -> None:
        super().__init__(target, typ, name, base_dir="/", **kwargs)

    def get_target(self) -> str:
        return "linux/amd64"

    def get_target_for_fuzzing(self) -> "Target":
        fuzz_kernel = options.getConfigKey("kernel")
        if fuzz_kernel != self.inst.kernel_dir:
            return self.copy(kernel=fuzz_kernel)
        return self

    def get_target_for_analysis(self) -> "Target":
        raw_kernel = options.getConfigKey("binary")
        if raw_kernel != self.inst.kernel_dir:
            return self.copy(kernel=raw_kernel)
        return self

    def setup(self, **kwargs):
        super().setup(**kwargs)

        # hook.ko must be compiled with the target kernel
        cwd = os.path.join(os.getcwd(), "hooks", "linux")
        subprocess.run(
            ["make"],
            cwd=cwd,
            env={**os.environ, "KERNEL": self.inst.kernel_dir, "PWD": cwd},
            check=True,
        )
        self.copy_file("hooks/linux/client/getfd")
        module = self.copy_file(os.path.join("hooks", "linux", "hook.ko"))
        self.inst.run_cmd(["insmod", module])

    def genProjectConfig(self, project_name: str, config: str = "config", **kwargs) -> Dict[str, Any]:
        version = kwargs.pop("version")
        image = kwargs.pop("image")

        config = super().genProjectConfig(project_name, config, **kwargs)
        config["user"] = "root"
        config["ip"] = "localhost"
        if version:
            config["kernel"] = os.path.join(
                os.getcwd(), "linux-distro", f"linux-{version}-fuzz")
            config["binary"] = os.path.join(
                os.getcwd(), "linux-distro", f"linux-{version}-raw")
        if image:
            config["image"] = os.path.abspath(
                os.path.join(image, "stretch.img"))
            config["sshkey"] = os.path.abspath(
                os.path.join(image, "stretch.id_rsa"))
        return config

    def init_model(self, module_name: str, path: str, ops: Dict[str, int]) -> LinuxDriverModel:
        model: Optional[LinuxDriverModel] = self.load_model(module_name)
        if model is None:
            model = LinuxDriverModel(module_name)

        model.initialize(
            ops,
            dev_path=path,
        )
        model.save(self.model_path)
        logger.info("successfully generate init model")
        self.generate_template(model, False, True)
        return model

    def generate_model(self, target: str, **kwargs):
        services = self.load_services()
        if services is None:
            logger.error("please run python main.py --find_drivers first")
            return

        for device, items in services.items():
            if target == device:
                if "ops" in items:
                    ops = items["ops"]
                    self.init_model(target, items["path"], ops)
                else:
                    logger.error("no ops found in services.json")
                break
        else:
            logger.error("failed to find the target %s", target)

    def find_device(self, dirPath: str = "/dev", cache: Optional[Set]=None) -> Generator[Tuple[str, int, int, str], None, None]:
        dirPath = os.path.normpath(dirPath)
        if cache is None:
            cache = set()
        if dirPath in cache:
            return
        cache.add(dirPath)

        ret = self.inst.run_cmd(["ls", "-al", dirPath], check=False, enable_stdout=True)
        regex = re.compile(
            r"(?P<mode>.[rwx-]{9}).?\W+\d+\W+\w+\W+\w+(\W+)?(?P<major>\d+,)?(\W+)(?P<minor>\d+)"
            r" (\d{4}-\d{1,2}-\d{1,2}|[a-zA-Z]{3,4}\W+\d{1,2}) \d{2}:\d{2} (?P<name>.+)"
        )
        for line in ret.stdout.split(b"\n"):
            line = line.decode("utf-8")
            res = regex.match(line)
            if res:
                logger.debug("match %s", line)
                mode, name = res.group("mode"), res.group("name")
                # print(res.group(0))
                if mode[0] == 'd':
                    if name in {"char", ".", ".."}:
                        continue
                    yield from self.find_device(os.path.join(dirPath, name), cache=cache)
                elif mode[0] == 'l':
                    name = name.split("->")[-1].strip()
                    if not name.startswith("/"):
                        name = os.path.join(dirPath, name)
                    # print(name)
                    if not name.startswith("/proc"):
                        yield from self.find_device(name, cache=cache)
                elif mode[0] in ['c', 'b']:
                    if not name.startswith("/"):
                        name = os.path.join(dirPath, name)
                    yield (mode, int(res.group("major")[:-1]), int(res.group("minor")), name)
            else:
                logger.debug("failed to match %s", line)

    def find_device_interface(self, cmds: List[str]):
        ret = self.inst.run_cmd(cmds, enable_stdout=True)
        regex = re.compile(
            r"(read|write|unlocked_ioctl|compat_ioctl|open): (0x[0-9a-f]+)")
        ops = {}
        for line in ret.stdout.split(b"\n"):
            line = line.decode("utf-8")
            res = regex.match(line)
            if res:
                print(res.group(1), res.group(2))
                ops[res.group(1)] = int(res.group(2), 16)
        return ops

    def check_fd(self, prog_file: str):
        syzkaller = options.getConfigKey("syzkaller")
        output = UnusedTempFileName(".syz")

        cmds = [
            os.path.join(syzkaller, "bin", "syz-syzgen"),
            "-command=check_fd",
            f"-output={output}",
            prog_file,
        ]
        logger.debug("%s", " ".join(cmds))
        subprocess.run(cmds, check=True)
        executable = UnusedTempFileName("_poc")
        self.build_poc(output, executable)

        poc = self.copy_file(executable)
        os.unlink(output)
        os.unlink(executable)
        return self.find_device_interface([poc])

    def scan_devices(self):
        res = {}
        for mode, major, minor, p in self.find_device():
            module_name = os.path.basename(p)
            logger.debug("%s %d %d %s %s", mode, major, minor, p, module_name)

            ops = None
            cmds = [os.path.join(self.baseDir, "getfd"), p]
            try:
                ops = self.find_device_interface(cmds)
            except subprocess.CalledProcessError:
                pass

            module_name = module_name.replace("-", "_")
            res[module_name] = {
                "mode": mode,
                "name": module_name,
                "major": major,
                "minor": minor,
                "path": p,
            }
            if ops:
                res[module_name]["ops"] = ops
                # infer_open(target, module_name, ops)
                # self.init_model(module_name, p, ops)

        self.save_resources(res)

    def setup_proxy(
        self,
        entry: Address,
        executable: str,
        cmds: List[str],
        func=None,
        debug: bool = False,
    ) -> Proxy:
        name = os.path.basename(executable)
        proxy = self.inst.attach_debugger(
            DummyDebugger(self.inst.get_kernel(), GDBProxy(), self.inst.get_ip())
            if debug else
            GDBDebugger(self.inst.get_kernel(), self.inst.get_ip(), self.inst.get_debug_port())
        )
        # no kaslr
        proxy.set_breakpoint(entry.address, target=name)
        logger.debug("set breakpoint for %s", entry)
        # resume the VM
        proxy.continue_run()

        logger.debug("running %s...", executable)
        self.inst.run_cmd(cmds, check=False, timeout=10)
        logger.debug("execute the program in guest to hit the breakpoint")
        proxy.wait_breakpoint()

        if func:
            func(proxy)

        proxy.remove_breakpoints()
        return proxy

    def find_drivers(self, target: str = None):
        # We may have two versions of kernel
        kernel: LinuxTarget = self.get_target_for_analysis()
        if not target:
            with kernel:
                kernel.scan_devices()
            return

        services = self.load_services()
        if services is None:
            logger.info("run python main.py --find_drivers without %s first", target)
            raise NoDriverException("no drivers found")

        model = self.load_model(target)
        if model is None:
            self.generate_model(target)
            model = self.load_model(target)
            assert model
        LinuxInterfaceDiscovery(self, model).run()

    def _fix_ops(self, ops, libs, binary) -> Dict[str, int]:
        if any(isinstance(v, str) for _, v in ops.items()):
            p = angr.Project(self.get_main_object(binary=binary), force_load_libs=libs)
            for k, v in ops.items():
                if isinstance(v, str):
                    sym = p.loader.find_symbol(v)
                    if sym is None:
                        raise RuntimeError()
                    ops[k] = sym.rebased_addr
        return ops

    def find_cmds(self, target: str):
        services = self.load_services()
        if services is None:
            return

        if target in services:
            items = services[target]
            ops = items["ops"]
            binary = items["binary"] if "binary" in items else None
            libs = [] if "libs" not in items else items["libs"]
            ops = self._fix_ops(ops, libs, binary)
            model = self.init_model(target, items["path"], ops)

            t = self.get_target_for_analysis()
            LinuxCommandExtractor(
                # use the minimum kernel for analysis
                t,
                model,
                options.dynamic,
                t.get_main_object(binary=binary),
                libs=libs,
            ).run()

            # save the model
            model.save(self.model_path)
            self.generate_template(model, False, True)
        else:
            logger.error("failed to find the device %s", target)

    def infer_type(self, target: str, cmd: int = -1, **kwargs):
        services = self.load_services()
        if services is None:
            return

        if target in services:
            items = services[target]
            libs = [] if "libs" not in items else items["libs"]
            binary = items["binary"] if "binary" in items else None
            model = self.load_model(target)
            t = self.get_target_for_analysis()
            LinuxInterfaceRecovery(
                self,
                t.get_main_object(binary=binary),
                # os.path.join(options.getConfigKey("binary"), "vmlinux"),
                cmd,
                model,
                options.dynamic,
                debug=options.debug_vm,
                libs=libs,
            ).run()
        else:
            logger.error("failed to find the target %s", target)

    def showcase(self, target: str, cmd: int):
        services = self.load_services()
        if services is None:
            return

        if target in services:
            items = services[target]
            logger.debug("%s", json.dumps(items, indent=2))
            model = self.load_model(target)
            if model is not None:
                model.debug_repr(cmd=cmd)
        else:
            logger.error("failed to find the target %s", target)

    def infer_output(self, prog_file: str, cmd: int, syscall: str, model: LinuxDriverModel) -> None:
        # 2. Add instrumentaion
        instrumented = UnusedTempFileName(".syz")
        syzkaller = options.getConfigKey("syzkaller")
        cmds = [
            os.path.join(syzkaller, "bin", "syz-syzgen"),
            "-command=hook",
            f"-output={instrumented}",
            prog_file,
        ]
        logger.debug("%s", cmds)
        subprocess.run(cmds, check=True)
        # 3. Convert the testcase to C code and compile it
        executable = UnusedTempFileName("_poc")
        self.compile_poc(instrumented, executable, ["-Ihooks/linux/lib"])

        # 4. Refine the layout for output
        poc = self.copy_file(executable)
        res = self.inst.run_cmd([poc], enable_stdout=True)
        logger.debug("output: %s", res.stdout)
        for line in reversed(res.stdout.decode("utf-8").split("\n")):
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    ptr = Type.construct(data)
                    logger.debug("ptr:\n%s\n", ptr.repr())
                    for each in model.methods(cmd):
                        # FIXME: refine all syscalls?
                        if isinstance(each, SysWrite):
                            each.data.refine(ptr)
                        elif isinstance(each, IOCTLMethod):
                            each.arg.refine(ptr)
                        else:
                            raise NotImplementedError(
                                "unsupported syscall %s", each.NAME)
                        logger.debug("syscall:\n%s\n", each.repr())
                    break
                except JSONDecodeError:
                    pass
        # clean up
        os.unlink(instrumented)
        os.unlink(executable)
