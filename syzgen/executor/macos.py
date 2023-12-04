
import json
import logging
import os
import angr

from cle.utils import key_bisect_floor_key
from typing import Optional, Tuple
from syzgen.analysis.explore import BFSExplore
from syzgen.config import Options
from syzgen.debugger.lldbproxy import LLDBProxy
from syzgen.executor.executor import Executor
from syzgen.kext.macho import LoadMachoDriver
from syzgen.models.macos import MacModel
from syzgen.parser.models import Address, BaseAddress, TargetAddress
from syzgen.parser.syscalls import Syscall
from syzgen.target import Target

logger = logging.getLogger(__name__)
options = Options()

#
#  error number layout as follows:
#  hi		                       lo
#  | system(6) | subsystem(12) | code(14) |
#
def err_get_system(err): return ((err)>>26)&0x3f

def err_get_sub(err): return ((err)>>14)&0xfff

def err_get_code(err): return (err)&0x3fff

class MacExecutor(
    Executor,
):
    def __init__(
        self,
        target: Target,
        syscall: Syscall,
        binary: str,
        kext: str,  # target kext
        entry: int = 0,
        **kwargs,
    ):
        self.kexts = []
        self.kext_paths = []
        self._path_to_kext = {}
        self.kext_projects = {}

        self.target_kext: str = kext
        self.target_base = 0

        super().__init__(
            target, binary,
            Address(kext, entry),
            syscall=syscall,
            model=MacModel(),
            **kwargs
        )

        self.first_inst = None
        if entry:
            block = self.proj.factory.block(entry)
            self.first_inst = block.capstone.insns[0]

    def initialize(self):
        if not self.initialized:
            # load all kext modules, it has to be called before we do anything else.
            self.load_module(self.proxy, self.target.workdir)
        return super().initialize()

    def load_module(self, proxy: LLDBProxy, workdir: str):
        self.kexts = proxy.read_kext_mapping()
        for (addr, size, name) in self.kexts:
            logger.debug("Load %#x, %#x, %s", addr, size, name)
            if name == self.target_kext:
                self.target_base = addr

        with open(os.path.join(workdir, "model", "kexts.json"), "r") as fp:
            self.kext_paths = json.load(fp)
        for k, p in self.kext_paths.items():
            self._path_to_kext[p] = k

    def is_valid_pointer(self, addr: int, state=None) -> bool:
        # FIXME: hard-coded range for pointers
        return 0xffffff7000000000 <= addr < 0xffffffff90000000

    def getBaseAddr(self, ip, target=None) -> Tuple[str, int]:
        res = key_bisect_floor_key(self.kexts, ip, keyfunc=lambda x: x[0])
        if res:
            start, size, name = res
            if ip < start + size:
                if target and name != target:
                    return "", 0
                return name, ip - start
        if target is None and ip >= 0xffffff8000000000:
            return "kernel", ip - self.proxy.slide
        return "", 0

    def getTargetAddr(self, offset, target="kernel"):
        if not isinstance(target, str):
            binary = target.owner.binary
            if binary.endswith("kernel.development"):
                target = "kernel"
            else:
                target = self._path_to_kext[binary]

        if target == "kernel":
            return offset + self.proxy.slide
        # FIXME: optimize it
        for (addr, size, name) in self.kexts:
            if name == target:
                if offset < size:
                    return addr+offset
        return 0

    def _load_project_by_kext(self, kext: str) -> Optional[angr.Project]:
        if kext == "kernel" and kext not in self.kext_projects:
            self.kext_projects[kext] = angr.Project(os.path.join(
                options.getConfigKey("kernel"),
                "kernel.development"
            ))
        elif kext and kext not in self.kext_projects:
            self.kext_projects[kext] = LoadMachoDriver(self.kext_paths[kext])

        return self.kext_projects[kext] if kext in self.kext_projects else None

    def load_project_by_addr(self, addr: TargetAddress) -> Tuple[str, BaseAddress, Optional[angr.Project]]:
        kext, off = self.getBaseAddr(addr)
        return kext, off, self._load_project_by_kext(kext)

    def find_section_by_addr(self, addr):
        _, off, proj = self.load_project_by_addr(addr)
        if proj:
            return proj.loader.find_section_containing(off)
        return None

    def find_symbol_by_addr(self, addr: int, fuzzy: bool = False):
        _, off, proj = self.load_project_by_addr(addr)
        if proj:
            return proj.loader.find_symbol(off, fuzzy=fuzzy)
        return None

    def find_symbol_by_name(self, obj, name, fuzzy=False):
        if fuzzy:
            raise NotImplementedError()

        res = obj.get_symbol(name)
        if res:
            return res[0]
        return None

    def getFuncAddrs(self, *funcs):
        ret = []
        res = self.proxy.find_functions_addr(list(funcs))
        for name, ents in res.items():
            for ent in ents:
                if not ent["inlined"]:
                    ret.append((name, ent["addr"]))
                    break
        return ret

    def getInitState(self) -> angr.SimState:
        state = super().getInitState()

        # Get some global variables necessary for procedure modeling.
        pkIOBooleanTrue = self.proxy.find_global_variable("kOSBooleanTrue")
        kIOBooleanTrue = state.solver.eval(
            state.mem[pkIOBooleanTrue].uint64_t.resolved)
        state.globals["kIOBooleanTrue"] = kIOBooleanTrue

        # Fix first instruction that is set to int3
        # Note it must be set before we execute any instruction, otherwise the old one will be cachced.
        # int3 only has one bytes and thus any instruction would be sufficient to overwrite it.
        if self.entry:
            state.memory.store(
                # self.entry+self.target_base,
                self.getTargetAddr(self.entry.address, self.entry.module),
                state.solver.BVV(self.first_inst.bytes),
                inspect=False,
            )

        return state

    def get_debug_info(self, addr: int) -> str:
        if addr > 0xffffff8000000000:
            name = self.proxy.find_symbol_name(addr)
            return f"{name}(0x{addr-self.proxy.slide:x})"
        else:
            driver, addr = self.getBaseAddr(addr)
            return f"{driver}(+0x{addr:x})"

    def execute(self, simgr: angr.SimulationManager) -> angr.SimulationManager:
        explorer = self.explorer or BFSExplore
        exp = explorer(self, verbose=True)
        return exp.explore(simgr, timeout=self.timeout)
