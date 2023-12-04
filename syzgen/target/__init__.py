
import enum
import importlib
import logging
import json
import os
import re
import subprocess
import time

from typing import Any, Callable, Dict, List, Optional, Union
import typing

from syzgen.config import WORKDIR, Options
from syzgen.debugger.proxy import Proxy
from syzgen.parser.generate import BaseModel, TemplateGenerator
from syzgen.parser.models import Address
from syzgen.utils import UnusedTcpPort, UnusedTempFileName

from syzgen.vm import VMInstance

logger = logging.getLogger(__name__)
options = Options()

TARGETS: Dict[str, typing.Type["Target"]] = {}

class UnresolvedModelException(Exception):
    pass

class NoDriverException(Exception):
    pass

class TargetOS(enum.Enum):
    LINUX = 1
    ANDROID = 2
    DARWIN = 3

    @classmethod
    def from_value(cls, name: str):
        for e in cls:
            if e.name.lower() == name.lower():
                return e
        raise RuntimeError(f"unknown OS type {name}")

    @staticmethod
    def Register(typ: str, clazz: typing.Type["Target"]):
        assert typ != ""
        TARGETS[typ] = clazz

    def Create(self, typ: str, name: str, **kwargs):
        return TARGETS[self.name.lower()](
            self,
            typ,
            name,
            **kwargs,
        )


class Target:
    """Class to abstract the environment for one specific target"""
    initialized = False
    NAME = ""

    def __init__(
        self,
        target: TargetOS,
        typ: str,
        name: str,
        base_dir: str = "/",
        **kwargs
    ) -> None:
        self.target: TargetOS = target
        self.inst: VMInstance = VMInstance.initialize(typ, **kwargs)
        self.name = name  # unique project name
        self.baseDir = base_dir

        for p in [self.model_path, self.testcase_path, self.tmp_path]:
            if not os.path.exists(p):
                os.makedirs(p)

        self.setup_functions = []

    def register_setup(self, func, *args, **kwargs):
        """We may have different setup functions for the same target in
        different situations."""
        self.setup_functions.append((func, args, kwargs))

    def __enter__(self):
        # Each instance is a thread which only allows to be executed once.
        # We make a copy every time we run it.
        try:
            self.inst = self.inst.copy()
            self.inst.start()
            self.inst.wait_for_ssh()
            self.setup()
            for func, args, kwargs in self.setup_functions:
                func(*args, **kwargs)
            # make sure inst starts completely before we return
            while not self.inst.is_running():
                logger.debug("wait for vm")
                time.sleep(1)
        except Exception as e:
            self.inst.terminate()
            raise e
        return self

    def __exit__(self, typ, value, tb):
        self.inst.terminate()

    @staticmethod
    def Create(target: Optional[str] = None, typ: Optional[str] = None, **kwargs) -> "Target":
        if not Target.initialized:
            # Avoid circular dependency
            Target._load_all_targets()
            Target.initialized = True

        target = target or options.getConfigKey("target")
        vm = typ or options.getConfigKey("type")
        project_name = kwargs.pop(
            "project_name", "") or options.getConfigKey("project_name")
        t = TargetOS.from_value(target)
        logger.info("loading %s with %s for project %s",
                    target, vm, project_name)
        return t.Create(vm, project_name, **kwargs)

    def copy(self, **kwargs) -> "Target":
        target = kwargs.pop("target", self.target.name)
        vm = kwargs.pop("type", self.inst.get_type())
        project = kwargs.pop("project_name", self.name)
        t = TargetOS.from_value(target)
        return t.Create(vm, project, **kwargs)

    @property
    def workdir(self) -> str:
        return os.path.join(WORKDIR, self.name)

    @property
    def model_path(self) -> str:
        return os.path.join(self.workdir, "model")

    @property
    def testcase_path(self) -> str:
        return os.path.join(self.workdir, "testcases")

    @property
    def tmp_path(self) -> str:
        return os.path.join(self.workdir, "tmp")

    def load_services(self) -> Optional[Dict[str, Any]]:
        service_path = os.path.join(self.model_path, "services.json")
        if not os.path.exists(service_path):
            logger.error("file %s does not exist", service_path)
            logger.info("please run python main.py --find_drivers first")
            return None
        with open(service_path, "r") as fp:
            return json.load(fp)

    def save_resources(self, services):
        with open(os.path.join(self.model_path, "services.json"), "w", encoding="utf-8") as fp:
            json.dump(services, fp, indent=2)

    def load_model(self, module_name: str) -> Optional[BaseModel]:
        return BaseModel.load(self.model_path, module_name)

    def genProjectConfig(self, project_name: str, config: str = "config", **kwargs) -> Dict[str, Any]:
        """Generate basic config for SyzGen to run. This is called in the script
        scripts/genConfig.py"""
        items: Dict[str, Any] = {}
        if os.path.exists(config):
            with open(config, "r") as fp:
                items = json.load(fp)

        syzkaller = os.path.join("src", "github.com", "google", "syzkaller")
        items.update({
            "target": self.get_os(),
            "type": self.inst.get_type(),
            "syzkaller": os.path.join(os.getenv("GOPATH"), syzkaller),
            "project_name": project_name,
            "cover": True,
            "dead": {},
            "funcWithZero": {},
            "funcWithOne": {},
            "breakpoint": {}
        })
        return items

    def genSyzConfig(
        self,
        enabled_syscalls: List[str],
        outfile: str,
        enable_coverage: bool = True,
        workdir: str = None,
        num_procs: int=1,
        num_cpu: int=2,
        num_vm: int=1,
    ):
        """Generate config for syzkaller to fuzz the given syscalls"""
        workdir = workdir or os.path.join(options.getConfigKey("syzkaller"), "workdir")
        item = {
            "target": self.get_target(),
            "http": f"127.0.0.1:{UnusedTcpPort()}",
            "workdir": workdir,
            "syzkaller": options.getConfigKey("syzkaller"),
            "reproduce": False,
            "cover": enable_coverage,
            "procs": num_procs,
            "type": self.inst.get_type(),
        }
        item.update(self.inst.genSyzConfig(num_cpu=num_cpu, num_vm=num_vm))
        item["enable_syscalls"] = enabled_syscalls

        if not os.path.exists(workdir):
            os.mkdir(workdir)

        cfg_path = os.path.join(workdir, outfile)
        logger.debug("generating config at %s", cfg_path)
        with open(cfg_path, "w") as f:
            json.dump(item, f, indent=2)

    def genSyzConfigWithModel(self, model: BaseModel, enable_cov: bool, num_procs: int = 1):
        """Generate config for syzkaller to fuzz the given model"""
        enabled_syscalls = [each.Name for each in model.syscalls()]
        enabled_syscalls.extend(model.get_extra_syscalls())
        self.genSyzConfig(
            enabled_syscalls,
            os.path.join(options.getConfigKey("syzkaller"),
                         "workdir", f"cfg_{model.name}.json"),
            enable_coverage=enable_cov,
            num_procs=num_procs,
        )

    def get_template_generator(self, model: BaseModel) -> TemplateGenerator:
        return TemplateGenerator(model)

    def generate_template(
        self,
        nameOrModel: Union[str, BaseModel],
        finalize: bool,
        build: bool,
        enable_cov: bool = True,
        **kwargs,
    ):
        """Generate syzlang templates based on the given model."""
        if isinstance(nameOrModel, BaseModel):
            model = nameOrModel
        else:
            model = self.load_model(nameOrModel)
        if model is None:
            logger.error("model is None")
            return

        self.get_template_generator(model.copy()).run(
            os.path.join(options.getConfigKey("syzkaller"), "sys",
                         self.get_os(), f"{model.name}_gen.txt"),
            finalize,
            build=build,
        )
        self.genSyzConfigWithModel(model, enable_cov)

    def check_fd(self, prog_file: str):
        raise NotImplementedError()

    def check_testcase(self, prog_file: str) -> bool:
        """Note the vm must be running."""
        syzkaller = options.getConfigKey("syzkaller")
        output = UnusedTempFileName(".syz")
        # cfg_path = os.path.join(syzkaller, "workdir", f"cfg_{model.name}.json")
        cmds = [
            os.path.join(syzkaller, "bin", "syz-syzgen"),
            "-command=check",
            f"-output={output}",
            prog_file,
        ]
        logger.debug("%s", " ".join(cmds))
        subprocess.run(cmds, check=True)
        executable = UnusedTempFileName("_poc")
        self.build_poc(output, executable, func=lambda x: x.replace("if (res != -1)", ""))
        os.unlink(output)

        poc = self.copy_file(executable)
        os.unlink(executable)

        ret = self.inst.run_cmd([poc], check=True, enable_stdout=True)
        regex = re.compile(r"syzgen: res (?P<resource>-?\d+)")
        resources = []
        for line in ret.stdout.split(b"\n"):
            line = line.decode("utf-8")
            m = regex.search(line)
            if m:
                resources.append(int(m.group("resource")))
        logger.debug("resources: %s", ", ".join(map(str, resources)))
        for each in resources:
            if each == -1:
                return False
        return True

    def generate_poc(self, sysname: str, config: str, outfile: str):
        """Generate a testcase that exercise the given syscall with respect
        to dependencies."""
        cmds = [
            os.path.join(options.getConfigKey(
                "syzkaller"), "bin", "syz-syzgen"),
            "-command", "generate",
            "-syscall", sysname,
            "-config", config,
            "-output", outfile,
        ]
        logger.debug("run %s", cmds)
        subprocess.run(cmds, check=True, timeout=3*60)

    def build_poc(
        self, filepath: str, outfile: str,
        func: Optional[Callable[[str], str]]=None,
        **kwargs,
    ):
        """build binary from syz program with default options"""
        self.compile_poc(filepath, outfile, ["-Ilibs"], func=func, **kwargs)

    def csource(
        self,
        prog_file: str, outfile: str,
        func: Optional[Callable[[str], str]]=None,
        **kwargs,
    ):
        """Convert syz prog to c code"""
        syzkaller = options.getConfigKey("syzkaller")
        cmds = [
            os.path.join(syzkaller, "bin", "syz-prog2c"),
            f"-prog={prog_file}"
        ]
        if kwargs.pop("initresc", False):
            cmds.append("-initresc=True")
        logger.debug("%s", cmds)
        with open(outfile, "w") as fp:
            subprocess.run(cmds, stdout=fp, check=True)

        # instrument the source code
        if func:
            with open(outfile, "r") as fp:
                content = "\n".join(fp.readlines())
            content = func(content)
            logger.debug("new program:\n%s", content)
            with open(outfile, "w") as fp:
                fp.write(content)

    def compile_poc(
        self,
        filepath: str,
        outfile: str,
        extra_flags: List[str] = [],
        func: Optional[Callable[[str], str]]=None,
        **kwargs,
    ):
        """Advanced version of build_poc, which allows more flexibilities.
        1. Allow extra flags for compilation
        2. allow source code instrumentation
        """

        # firstly convert it to c file
        target = UnusedTempFileName(".c")
        self.csource(filepath, target, func=func, **kwargs)

        # compile the c code
        cmds = [
            "gcc", "-o", outfile, target,
            *extra_flags, *self.get_cflags(),
        ]
        logger.debug("%s", cmds)
        subprocess.run(cmds, check=True)
        # clean up
        os.unlink(target)

    def copy_file(self, src: str) -> str:
        """Handy utility to copy file from host to pre-defined destination"""
        if not os.path.exists(src):
            raise FileNotFoundError(src)

        name = os.path.basename(src)
        return self.inst.copy_file(src, os.path.join(self.baseDir, name))

    def get_os(self) -> str:
        return self.get_target().split("/")[0]

    def get_arch(self) -> str:
        return self.get_target().split("/")[1]

    def get_target(self) -> str:
        """return string composed by os/arch"""
        raise NotImplementedError()

    def setup(self, **kwargs):
        """Call this function when the instance is initialized"""
        if not self.inst.is_alive:
            raise RuntimeError("Must call setup after the inst is initialized")

    def setup_proxy(
        self,
        entry: Address,
        executable: str,
        cmds: List[str],
        func=None,
        debug: bool = False,
    ) -> Proxy:
        """set up a proxy for communication between angr and VM.
        Note it assumes the VM is already booted at this point."""
        raise NotImplementedError()

    def analyze(self, target: str=None, **kwargs):
        while True:
            try:
                self.find_drivers(target=target, **kwargs)
                self.find_cmds(target=target, **kwargs)
                self.infer_type(target=target, **kwargs)
            except UnresolvedModelException:
                continue

            break

    def find_drivers(self, target: str = None):
        """Find all interfaces"""
        raise NotImplementedError()

    def find_cmds(self, target: str):
        """Identify valid command values"""
        raise NotImplementedError()

    def infer_type(self, target: str, **kwargs):
        """Interface recovery"""
        raise NotImplementedError()

    def showcase(self, target: str, cmd: int):
        """Show info for the given target"""
        raise NotImplementedError()

    def generate_model(self, target: str, **kwargs):
        """init model"""
        raise NotImplementedError()

    def infer_output(self, prog_file: str, cmd: int, syscall: str, model: BaseModel) -> None:
        raise NotImplementedError()

    def get_cflags(self) -> List[str]:
        return []

    def enable_kcov(self) -> None:
        """For some kernel, we may need to manually enable kcov"""
        return

    @staticmethod
    def _load_all_targets():
        assert Target.initialized is False
        path = os.path.dirname(os.path.abspath(__file__))
        for file_name in os.listdir(path):
            if not file_name.endswith(".py"):
                continue
            module_name = file_name[:-3]
            # try:
            m = importlib.import_module(
                f".{module_name}",
                "syzgen.target",
            )
            # except ImportError:
            #     logger.warning("Unable to import procedure %s", module_name)
            #     continue

            for attr_name in dir(m):
                attr = getattr(m, attr_name)
                if (
                    isinstance(attr, type) and
                    issubclass(attr, Target) and
                    attr_name != "Target"
                ):
                    TargetOS.Register(attr.NAME, attr)

    # We maintain two kernels, one for fuzzing with kcov enabled and the other one
    # with minimum config for analysis. To make it explicit, call the following API
    # get the correct target.
    def get_target_for_analysis(self) -> "Target":
        return self

    def get_target_for_fuzzing(self) -> "Target":
        return self

    def get_main_object(self, binary: Optional[str] = None) -> str:
        return self.inst.get_kernel() or binary
