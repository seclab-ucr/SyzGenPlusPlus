
import logging
from typing import Tuple
from syzgen.analysis.interface import InterfaceRecovery
from syzgen.analysis.ioctl import LinuxInterfaceRecovery
from syzgen.analysis.iokit import IOKitRecovery

from syzgen.config import Options
from syzgen.parser.models import BaseModel, SyscallModel
from syzgen.parser.syscalls import Syscall
from syzgen.target.macos import MacOSTarget
from syzgen.test import BaseTestUnit

logging.basicConfig()
logger = logging.getLogger("syzgen")
options = Options()


class TestExecutor(BaseTestUnit):
    def prepare_executor(
        self,
        module_name: str,
        call_name: str,
        syscall_json: str = "",
        timeout: int=600,
        dynamic: bool=False
    ) -> Tuple[Syscall, SyscallModel, InterfaceRecovery]:
        if isinstance(self.target, MacOSTarget):
            service_name, module_name = self.target._parse_target(module_name)
            s, c = self.target.get_service_client_clazz(service_name, module_name)
            if s is None or c is None:
                assert False
            binary = self.target.find_kext_path(s.module)
            self.target.register_setup(self.target.wait_for_client, s.metaClass, c.type, root=True)
        else:
            services = self.target.load_services()
            items = services[module_name]
            libs = [] if "libs" not in items else items["libs"]

        model: BaseModel = self.target.load_model(module_name)
        model_name = f"{call_name}${module_name}" if "$" not in call_name else call_name
        _model: SyscallModel = model.get_syscall_model_by_name(model_name)
        target = self.target.get_target_for_analysis()

        options.timeout = timeout
        syscall = _model.get_any_syscall() if syscall_json == "" else Syscall.load(syscall_json)
        syscall.validate()
        logger.debug(syscall.repr())

        cmd = (
            syscall.getCmdHandler(_model.dispatcher.selector)
            if _model.dispatcher is not None
            else 0
        )
        t = options.getConfigKey("target")
        if t in {"linux", "android"}:
            interface = LinuxInterfaceRecovery(
                target,
                target.inst.get_kernel(),
                cmd,
                model,
                dynamic,
                libs=libs,
            )
        elif t == "darwin":
            interface = IOKitRecovery(
                target,
                binary,
                cmd,
                s, c,
                model,
            )
        return syscall, _model, interface
