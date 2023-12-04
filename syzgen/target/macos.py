
import re
import angr
import logging
import json
import os
import subprocess
import time
import xml.etree.ElementTree as ET

from typing import Any, Callable, Dict, Generator, List, Optional, Tuple, Union
from syzgen.analysis.command import IOKitCommandExtractor

from syzgen.analysis.iokit import ClientExecutor, IOKitRecovery
from syzgen.analysis.static import parse_client
from syzgen.config import Options
from syzgen.debugger import DummyDebugger
from syzgen.debugger.lldbproxy import LLDBDebugger, LLDBProxy
from syzgen.debugger.proxy import Proxy, ProxyException
from syzgen.kext.helper import iterate_kext, parse_signature
from syzgen.kext.macho import Service, UserClient, find, isDefinedFunc
from syzgen.parser.generate import BaseModel, IOKitTemplateGenerator
from syzgen.parser.models import Address
from syzgen.parser.models.iokit import IOKitModel
from syzgen.parser.types import Constant
from syzgen.utils import addEntitlement, demangle
from syzgen.target import Target, TargetOS

logger = logging.getLogger(__name__)
options = Options()


class MacOSTarget(Target):
    NAME = "darwin"

    def __init__(self, target: TargetOS, typ: str, name: str, **kwargs) -> None:
        super().__init__(target, typ, name, base_dir="/private/tmp", **kwargs)

        if not os.path.exists(self.kcov_path):
            os.makedirs(self.kcov_path)

    def get_target(self) -> str:
        return "darwin/amd64"

    def get_cflags(self) -> List[str]:
        res = super().get_cflags()
        res.extend(["-framework", "IOKit"])
        return res

    def setup(self, **kwargs):
        super().setup(**kwargs)

        self.copy_file("libs/testService")
        self.copy_file("libs/registry")

    @property
    def kcov_path(self) -> str:
        """dir to store all kcov json files.
        We also store the binary kcov file for actual fuzzing"""
        return os.path.join(self.workdir, "kcov")

    def enable_kcov(self) -> None:
        # copy kcov file
        self.copy_file(os.path.join(self.kcov_path, "kcov"))

        # Load our pre-installed kcov driver
        self.inst.run_cmd(["sudo", "kextload", "kcov.kext"])

    def get_all_entitlements(self):
        ret = []
        tree = ET.parse("libs/ent.plist")
        root = tree.getroot()
        assert root.tag == "plist"
        for child in root[0]:
            if child.tag == "key":
                ret.append(child.text)
        return ret

    def genProjectConfig(self, project_name: str, config: str = "config", **kwargs) -> Dict[str, Any]:
        config = super().genProjectConfig(project_name, config, **kwargs)
        config["vmxpath"] = "please provide path to vmx (via vmrun list)"
        config["serial"] = "path to VM serial file"
        config["user"] = "user name to the VM"
        config["sshkey"] = "path to your ssh key for the VM"
        config["kernel"] = "dir to the install kdk kernel"
        config["driver_dir"] = "dir to all the kexts"
        config["entitlements"] = self.get_all_entitlements()
        return config

    def find_kext_path(self, kext: str) -> str:
        with open(os.path.join(self.model_path, "kexts.json"), "r") as fp:
            kext_paths = json.load(fp)
            return kext_paths[kext]

    def build_poc(self, filepath: str, outfile: str, func: Optional[Callable[[str], str]] = None, **kwargs):
        super().build_poc(filepath, outfile, func, **kwargs)
        addEntitlement(outfile)

    def check_service_property(self, service, key):
        cmds = [os.path.join(self.baseDir, "registry"), service, key]
        err = self.inst.run_cmd(cmds, enable_stderr=True, check=False).stderr
        return err.strip().decode('utf8')

    def _run_test_service(self, clazz: str, type: int, root=False) -> int:
        cmds = [os.path.join(self.baseDir, "testService"), clazz, str(type)]
        if root:
            cmds = ["sudo"] + cmds
        return self.inst.run_cmd(cmds, check=False).returncode

    def check_effect_service(self, clazz: str, root=False):
        """testService returns -1 if it fails to find the service"""
        return self._run_test_service(clazz, 0, root=root) != 255

    def check_effect_client(self, clazz: str, typ: int, root=False):
        """testService returns 0 if it successfully open the service"""
        return self._run_test_service(clazz, typ, root=root) == 0

    def wait_for_client(self, clazz: str, typ: int, root=False, timeout: int = 60):
        """Even after the system is booted, some services are not ready.
        Wait until we can get the service!
        """
        start = time.time()
        while not timeout or time.time() - start <= timeout:
            if self.check_effect_client(clazz, typ, root=root):
                return
            time.sleep(1)
        raise TimeoutError()

    def _parse_target(self, target: str) -> Tuple[str, str]:
        """For some user clients, it may have multiple services
        We allow users to provide the target name combined with its service
        name in the format of service::client.
        """
        service_name, client_name = "", target
        if "::" in target:
            service_name, client_name = target.split("::")
        return service_name, client_name

    def get_service_client(self, service_name: Optional[str], client_name: str):
        services = self.load_services()
        if not services:
            logger.error("please run python main.py --find_drivers first")
            return None, None

        if service_name:
            items = services[service_name]
            items["clazz"] = service_name
            for client in items["clients"]:
                if client["clazz"] == client_name:
                    return items, client
            return items, None

        for service_name, items in services.items():
            for client in items["clients"]:
                if client["clazz"] == client_name:
                    items["clazz"] = service_name
                    return items, client
        return None, None

    def get_service_client_clazz(self, service_name, client_name) -> Tuple[Optional[Service], Optional[UserClient]]:
        s, c = None, None
        service, client = self.get_service_client(service_name, client_name)
        if service:
            s = Service.Create(service["kext"], service["clazz"], service["newUserClient"])
        if client:
            c = UserClient.Create(client["kext"], client["clazz"], client["type"], client["ops"])
        return s, c

    def _find_all_service_names(self, binary) -> Generator[str, None, None]:
        checked = set()
        proj = angr.Project(binary)
        for sym in proj.loader.main_object.symbols:
            if "getMetaClass" not in sym.name:
                continue
            clazz, func = parse_signature(demangle(sym.name))
            if func == "getMetaClass" and clazz not in checked:
                checked.add(clazz)
                # ignore those are not loaded in the system
                if self.check_effect_service(clazz, root=False):
                    yield clazz
                elif self.check_effect_service(clazz, root=True):
                    yield clazz

    def parse_service(self, binary: str, clazz: str) -> Service:
        """
        virtual IOReturn newUserClient( task_t owningTask, void * securityID,
            UInt32 type, OSDictionary * properties,
            LIBKERN_RETURNS_RETAINED IOUserClient ** handler );

        virtual IOReturn newUserClient( task_t owningTask, void * securityID,
            UInt32 type,
            LIBKERN_RETURNS_RETAINED IOUserClient ** handler );

        The second function is called first, if it is not overriden, the former one will be invoked.
        """
        proj = angr.Project(binary)
        service = Service(clazz)
        if self.check_effect_service(clazz, root=False):
            service.access = True
        elif self.check_effect_service(clazz, root=True):
            service.access = False
        else:
            logger.debug("Cannot access service: %s" % clazz)

        symbols = []
        for sym in find(proj, "newUserClient"):
            if isDefinedFunc(sym):  # and sym.is_external:
                symbols.append(sym)

        for sym in symbols:
            demangled = demangle(sym.name)
            metaClass, funcName = parse_signature(demangled)
            if funcName != "newUserClient" or metaClass != service.metaClass:
                continue

            if service.newUserClient != 0:
                # multiple newUserClient seen
                # check signature
                signature = demangled[demangled.index("(")+1:-1]
                if len(signature.split(",")) == 4:
                    continue

            service.newUserClient = sym.relative_addr

        return service

    def find_default_client(self, binary, kext, service_name, driver_dir):
        userClient = self.check_service_property(
            service_name, "IOUserClientClass")
        if userClient:
            client = UserClient(kext, className=userClient, type=0)
            if self.check_effect_client(service_name, 0, root=False):
                client.access = True
            elif self.check_effect_client(service_name, 0, root=True):
                client.access = False
            else:
                logger.info("We cannot access: %s:%s with default selector 0",
                    service_name, userClient)
                return False

            # the client might reside in a different binary
            # TODO: it is extremely inefficient, fix it later
            proj = angr.Project(binary)
            if not parse_client(proj, client):
                def find_class(binary, kext):
                    proj = angr.Project(binary)
                    if parse_client(proj, client):
                        client.module = kext
                        return True
                iterate_kext(driver_dir, find_class)

            return client

        return None

    def find_client(self, binary, kext, entry, serviceName) -> List[UserClient]:
        with self:
            executor = ClientExecutor(self, binary, kext, serviceName, entry)
            executor.run()
            return [uc for _, uc in executor.userClients.items()]

    def find_drivers(self, target=None):
        # TODO: how to pass the arguments properly?
        driver_dir = options.getConfigKey("driver_dir")
        service_path = os.path.join(self.model_path, "services.json")
        services = {}
        skip_service_scan = False
        if os.path.exists(service_path):
            skip_service_scan = True
            with open(service_path, "r") as fp:
                services = json.load(fp)

        binaries = {}

        def analysis(binary, kext):
            binaries[kext] = binary

            for clazz in self._find_all_service_names(binary):
                if clazz in services:
                    continue

                service = self.parse_service(binary, clazz)
                client = self.find_default_client(binary, kext, service.metaClass, driver_dir)

                services[clazz] = {
                    "binary": binary,
                    "kext": kext,
                    "newUserClient": service.newUserClient,
                    "clients": [],
                }
                if client:
                    services[clazz]["clients"].append({
                        "clazz": client.metaClass,
                        "ops": client.toJson(),
                        "type": client.type,
                    })

        def save_result():
            with open(service_path, "w", encoding="utf-8") as fp:
                json.dump(services, fp, indent=2)

        if not skip_service_scan:
            with self:
                iterate_kext(driver_dir, analysis)

            save_result()
            with open(os.path.join(self.model_path, "kexts.json"), "w") as fp:
                json.dump(binaries, fp, indent=2)

        # FIXME: it is time consuming and thus we do it on demand.
        if not target:
            return

        # wait for some drivers to be loaded
        self.register_setup(time.sleep, 30)
        for clazz, items in services.items():
            if target and clazz != target:
                continue

            if items["newUserClient"] != 0 and len(items["clients"]) == 0:
                logger.debug("start to analyze %s", clazz)
                while True:
                    try:
                        clients: List[UserClient] = self.find_client(
                            items["binary"],
                            items["kext"],
                            items["newUserClient"],
                            clazz,
                        )
                        items["clients"].extend([
                            {
                                "kext": client.module,
                                "clazz": client.metaClass,
                                "type": client.type,
                                "ops": client.toJson(),
                            } for client in clients
                        ])
                        for client in clients:
                            logger.debug("find one UserClient %s",
                                         client.metaClass)
                        save_result()
                        break
                    except ProxyException as e:
                        logger.error("proxy error occurs! retrying...")

    def setup_proxy(
        self,
        entry: Address,
        executable: str,
        cmds: List[str],
        func=None,
        debug: bool = False,
    ) -> Proxy:
        # dst = self.copy_file(executable)
        # logger.debug("copy %s to guest", executable)
        name = os.path.basename(executable)

        proxy = self.inst.attach_debugger(
            DummyDebugger(self.inst.get_kernel(), LLDBProxy())
            if debug else
            LLDBDebugger(self.inst.get_kernel(), self.inst.get_ip())
        )
        proxy.set_breakpoint(entry.address, kext=entry.module, target=name)
        logger.debug("set breakpoint for %s", entry)
        # resume the vm
        proxy.continue_run()

        logger.debug("running %s...", executable)
        self.inst.run_cmd(cmds, check=False)
        logger.debug("execute the program in guest to hit the breakpoint")
        # Set the task so that accessing userspace memory becomes feasible.
        proxy.set_task(name)
        proxy.wait_breakpoint()

        if func:
            func(proxy)

        proxy.remove_breakpoints()
        return proxy

    def can_access_userclient(self, service: Service, client: UserClient) -> bool:
        if self.check_effect_client(service.metaClass, client.type, root=True):
            return True
        else:
            logger.info(
                "We cannot access %s:%s with selector %d",
                service.metaClass, client.metaClass, client.type
            )
            return False

    def init_model(
        self,
        service: Service,
        client: UserClient,
    ):
        model: Optional[IOKitModel] = self.load_model(client.metaClass)
        if model is None:
            model = IOKitModel(client.metaClass)

        model.initialize(service=service, client=client)

        # infer dependencies from logs
        # testcases = os.path.join(self.testcase_path, client.metaClass)
        # if os.path.exists(testcases):
        #     # If we have collected some traces, we could infer input structure from them.
        #     # Refine default model
        #     refine_model_with_log(testcases, model, client)
        model.save(self.model_path)
        logger.info("successfully generate init model")
        self.generate_template(model, False, True)
        return model

    def generate_model(self, target: str, **kwargs):
        service_name, client_name = self._parse_target(target)
        service, client = self.get_service_client_clazz(service_name, client_name)
        if client is None:
            logger.error("failed to find the target %s", target)
            return

        self.init_model(service, client)

    def generate_template(
        self,
        nameOrModel: Union[str, BaseModel],
        finalize: bool,
        build: bool,
        enable_cov: bool = False,
        **kwargs,
    ):
        """
        Other arguments:
        is_async: bool
        """
        if isinstance(nameOrModel, str):
            _, client_name = self._parse_target(nameOrModel)
            model = self.load_model(client_name)
        elif isinstance(nameOrModel, BaseModel):
            model = nameOrModel
        else:
            raise RuntimeError("invalid model")

        super().generate_template(model, finalize, build,
                                  options.getConfigKey("cover", False))
        addEntitlement(os.path.join(
            options.getConfigKey("syzkaller"),
            "bin",
            f"{self.get_os()}_{self.get_arch()}",
            "syz-executor"
        ))

    def find_cmds(self, name: str):
        service_name, client_name = self._parse_target(name)
        s, c = self.get_service_client_clazz(service_name, client_name)
        if c is None:
            logger.error("failed to find the target %s", name)
            return

        self.register_setup(time.sleep, 30)
        # Make sure the driver is loaded!
        self.register_setup(
            self.wait_for_client,
            s.metaClass, c.type,
            root=True
        )

        model = self.init_model(s, c)
        binary = self.find_kext_path(c.module)
        IOKitCommandExtractor(
            self, model,
            binary,
            s, c,
        ).run()

        # if table is None:
        #     logger.debug(
        #         "[Dynamic] failed to find functionalities for %s:%s" % (service, name))
        #     # try to use static analysis, which is less precise and uses heuristics.
        #     table = analyze_externalMethod(items["binary"], s, c)
        # init model and generate templates
        model.save(self.model_path)
        self.generate_template(model, False, True)

    def _gen_kcov(self, kcov: Optional[List[str]], binary: str) -> None:
        kcov = set() if kcov is None else set(kcov)
        p = os.path.join(self.kcov_path, f"{os.path.basename(binary)}.json")
        if os.path.exists(p):
            kcov.add(p)
        else:
            logger.debug("cannot find %s", p)
        if len(kcov) != 1:
            # FIXME: support multiple binaries
            logger.error("receive %d kcov", len(kcov))
            raise RuntimeError("error for kcov")
        subprocess.run([
            "python",
            "kcov/scripts/gen_cov.py",
            "-o", os.path.join(self.kcov_path, "kcov"),
            *[each for each in kcov],
        ],
            check=True,
        )

    def infer_type(self, target: str, cmd: int = -1, **kwargs):
        service_name, client_name = self._parse_target(target)
        s, c = self.get_service_client_clazz(service_name, client_name)
        if c is None:
            logger.error("failed to find the target %s", target)
            return

        kcov = kwargs.pop("kcov")
        binary = self.find_kext_path(s.module)

        self._gen_kcov(kcov, binary)
        model: IOKitModel = self.load_model(client_name)
        if model is None:
            logger.error(
                "please run python main.py --gen_model --target %s", client_name)
            return
        # Make sure the driver is loaded!
        self.register_setup(
            self.wait_for_client, s.metaClass, c.type, root=True)
        IOKitRecovery(
            self,
            binary,
            cmd,
            s,
            c,
            model,
            debug=False,
        ).run()

    def showcase(self, target: str, cmd: int):
        service_name, client_name = self._parse_target(target)
        _, c = self.get_service_client_clazz(service_name, client_name)
        if c is None:
            logger.error("failed to find the target %s", target)
            return

        model: IOKitModel = self.load_model(client_name)
        if model is not None:
            model.debug_repr(cmd=cmd)

    def infer_output(self, prog_file: str, cmd: int, syscall: str, model: IOKitModel) -> None:
        syz_run = self.copy_file(
            os.path.join(options.getConfigKey("syzkaller"),
                         "bin", "darwin_amd64", "syz-run"),
        )
        syz_executor = self.copy_file(
            os.path.join(options.getConfigKey("syzkaller"),
                         "bin", "darwin_amd64", "syz-executor"),
        )
        testcase = self.copy_file(prog_file)
        escaped_syscall = syscall.replace("$", "\$")
        ret = self.inst.run_cmd([
            syz_run,
            f'-executor={syz_executor}',
            "-collide=false",
            "-threaded=false",
            "-command=refine",
            f'-syscall={escaped_syscall}',
            testcase,
        ], enable_stderr=True)
        regex = re.compile(r"syz-run: (?P<num>\d+) is okay")
        lines = [line.decode("utf-8") for line in ret.stderr.split(b"\n")]
        for line in lines:
            m = regex.match(line)
            if m:
                num = int(m.group("num"))
                logger.debug("scalar_outputCnt is %d", num)
                for each in model.methods[cmd]:
                    # FIXME: refine all syscalls
                    each.outputCnt.ref = Constant(
                        num, each.outputCnt.ref.size, None)
                    each.validate()
                break
        for i, line in enumerate(lines):
            if "refined program:" in line:
                logger.debug("find refined program!")
                new_prog = lines[i+1:]
                with open(prog_file, "w") as fp:
                    for each in new_prog:
                        fp.write(each)
                        fp.write("\n")
                break

    def get_template_generator(self, model: BaseModel) -> IOKitTemplateGenerator:
        return IOKitTemplateGenerator(model)
