
import angr
import logging

from typing import List, Optional
from syzgen.models import StateTerminator
from syzgen.models.linux import LinuxModel
from syzgen.parser.models import BaseAddress, MethodInfo, MethodTable

from syzgen.utils import demangle
from syzgen.kext.helper import parse_signature

logger = logging.getLogger(__name__)


def LoadMachoDriver(path: str):
    """Load IOKit driver and patch relocations"""
    proj = angr.Project(path)

    X86_64_RELOC_BRANCH = 2

    stack_chk_fail = proj.loader.extern_object.make_extern("___stack_chk_fail")
    proj.hook(stack_chk_fail.rebased_addr,
              angr.SIM_PROCEDURES["stubs"]["PathTerminator"]())
    dummy_target = proj.loader.extern_object.make_extern("dummy_target")
    proj.hook(dummy_target.rebased_addr,
              angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]())
    # proj.loader.perform_irelative_relocs
    # hacky way to fix branch/jump relocations
    for _, sym in proj.loader.main_object.extreltab.items():
        if sym.is_external and sym.r_type == X86_64_RELOC_BRANCH:
            # print(sym.addr, sym.symbol)
            if sym.symbol.name in proj.loader.extern_object._symbol_cache:
                target_addr = proj.loader.extern_object._symbol_cache[sym.symbol.name].rebased_addr
            else:
                target_addr = dummy_target.rebased_addr

            proj.loader.main_object.memory.pack_word(
                sym.addr,
                target_addr-(sym.addr+sym.size),
                size=sym.size
            )
    return proj


def LoadVMLinux(path: str, model: Optional[LinuxModel] = None, libs: List[str] = []) -> angr.Project:
    proj = angr.Project(path, force_load_libs=libs)
    model = model or LinuxModel()
    for name, func in model.getFunc2Model().items():
        if not isinstance(func, StateTerminator):
            continue
        sym = proj.loader.find_symbol(name)
        if name and sym is not None:
            # Patch project so that we can get correct CFG
            proj.hook(sym.rebased_addr, func)
    return proj

def find(proj, name, fuzzy=True):
    """
    fuzzy search if str is given, otherwise we perform precise search.
    """
    ret = []
    if isinstance(name, str):
        for sym in proj.loader.main_object.symbols:
            if fuzzy:
                if name in sym.name:
                    ret.append(sym)
            else:
                if name == sym.name:
                    return [sym]
    elif isinstance(name, int):
        for sym in proj.loader.main_object.symbols:
            if fuzzy:
                raise Exception("fuzzy find not implemented yet")
            else:
                if sym.relative_addr == name:
                    return [sym]
    return ret


def getClassFunctions(proj, className, hasDefault=False):
    ret = []
    defaults = {
        className, "~"+className, "getMetaClass"
    }
    for sym in find(proj, className):
        clazz, func = parse_signature(demangle(sym.name))
        if clazz != className:
            continue

        if func in defaults and not hasDefault:
            continue

        ret.append(sym)

    return ret


def getAllClassFunctions(proj, hasDefault=False):
    ret = []
    for sym in proj.loader.main_object.symbols:
        if sym.section_name == "__text":
            demangled = demangle(sym.name)
            clazz, func = parse_signature(demangled)
            if clazz:
                if not hasDefault:
                    if func in ["MetaClass", "~MetaClass", "getMetaClass"]:
                        continue
                    if clazz.endswith("::MetaClass"):
                        continue
                    if clazz == func or "~"+clazz == func:
                        continue
                ret.append(sym)
    return ret


def isDefinedFunc(sym):
    if sym.n_type & 0xe == 0xe and sym.section_name == "__text":
        return True
    return False


class Method(MethodInfo):
    def __init__(self, module: str, addr: int, cmd: int, name: Optional[str] = None) -> None:
        super().__init__(module, addr, cmd, name)

    def repr(self):
        ret = "Method %d at %s %s\n" % (
            self.cmd, self.addr, self.method_name or "")
        ret += "\tscalarInputCount: %d, structInputSize: %d, scalarOutputCount: %d, structOutputSize: %d\n" % \
            (self.getScalarInputCount(), self.getStructInputSize(),
             self.getScalarOutputCount(), self.getStructOutputSize())
        return ret

    def debug_repr(self):
        logger.info("Method %d at %s %s", self.cmd,
                    self.addr, self.method_name or "")
        logger.info(
            "\tscalarInputCount: %d, structInputSize: %d, "
            "scalarOutputCount: %d, structOutputSize: %d\n",
            self.getScalarInputCount(),
            self.getStructInputSize(),
            self.getScalarOutputCount(),
            self.getStructOutputSize()
        )

    def getScalarInputCount(self):
        return -1

    def getStructInputSize(self):
        return -1

    def getScalarOutputCount(self):
        return -1

    def getStructOutputSize(self):
        return -1

    def isCustom(self):
        return True


class ExternalMethod(Method):
    # From IOUserClient.h
    kIOUCTypeMask = 0x0000000f
    kIOUCScalarIScalarO = 0
    kIOUCScalarIStructO = 2
    kIOUCStructIStructO = 3
    kIOUCScalarIStructI = 4

    kIOUCForegroundOnly = 0x00000010
    kIOUCVariableStructureSize = 0xffffffff

    def __init__(self, module, addr, cmd, method, flags, count0, count1):
        """Check iokit/kernel/IOUserClient.cpp
        switch (method->flags & kIOUCTypeMask) {
        case kIOUCScalarIStructI:
            args->scalarInput, args->scalarInputCount == count0,
            args->structureInput, args->structureInputSize == count1 or count1 == kIOUCVariableStructureSize
        case kIOUCScalarIScalarO:
            args->scalarInput, args->scalarInputCount == count0,
            args->scalarOutput, &args->scalarOutputCount == count1
        case kIOUCScalarIStructO:
            args->scalarInput, args->scalarInputCount == count0,
            args->structureOutput, &structureOutputSize == count1 or count1 == kIOUCVariableStructureSize
        case kIOUCStructIStructO:
            args->structureInput, args->structureInputSize == count0 or count0 == kIOUCVariableStructureSize
            args->structureOutput, &structureOutputSize == count1 or count1 == kIOUCVariableStructureSize
        """
        super(ExternalMethod, self).__init__(module, addr, cmd, method)

        self.flags = flags
        self.count0 = count0
        self.count1 = count1

    def getScalarInputCount(self):
        if self.flags & ExternalMethod.kIOUCTypeMask in [ExternalMethod.kIOUCScalarIStructI,
                                                         ExternalMethod.kIOUCScalarIScalarO, ExternalMethod.kIOUCScalarIStructO]:
            return self.count0
        return 0

    def getStructInputSize(self):
        t = self.flags & ExternalMethod.kIOUCTypeMask
        if t == ExternalMethod.kIOUCScalarIStructI:
            return self.count1
        elif t == ExternalMethod.kIOUCStructIStructO:
            return self.count0
        return 0

    def getScalarOutputCount(self):
        if self.flags & ExternalMethod.kIOUCTypeMask == ExternalMethod.kIOUCScalarIScalarO:
            return self.count1
        return 0

    def getStructOutputSize(self):
        if self.flags & ExternalMethod.kIOUCTypeMask in [ExternalMethod.kIOUCScalarIStructO,
                                                         ExternalMethod.kIOUCStructIStructO]:
            return self.count1
        return 0

    def isCustom(self):
        return False


class ExternalMethodDispatch(Method):
    def __init__(self, module, addr, cmd, method, scalarInputCount, structInputSize, scalarOutputCount, structOutputSize):
        super().__init__(module, addr, cmd, method)

        self.scalarInputCount = scalarInputCount
        self.structInputSize = structInputSize
        self.scalarOutputCount = scalarOutputCount
        self.structOutputSize = structOutputSize

    def getScalarInputCount(self):
        return self.scalarInputCount

    def getStructInputSize(self):
        return self.structInputSize

    def getScalarOutputCount(self):
        return self.scalarOutputCount

    def getStructOutputSize(self):
        return self.structOutputSize

    def isCustom(self):
        return False


class DispatchTable(MethodTable[Method]):
    def addCustomMethod(self, module, addr, cmd, method):
        m = Method(module, addr, cmd, method)
        self.methods[cmd] = m

    def addExternalMethod(self, module, addr, cmd, method, flags, count0, count1):
        m = ExternalMethod(module, addr, cmd, method, flags, count0, count1)
        self.methods[cmd] = m

    def addExternalMethodDispatch(self, module, addr, cmd, method, scalarInputCount=0,
                                  structInputSize=0, scalarOutputCount=0, structOutputSize=0):
        m = ExternalMethodDispatch(
            module, addr, cmd, method, scalarInputCount, structInputSize, scalarOutputCount, structOutputSize)
        self.methods[cmd] = m

    # def addMethod(self, cmd, method):
    #     if cmd in self.methods:
    #         logger.debug("cmd %d is already present with addr 0x%x" %
    #                      (cmd, self.methods[cmd].addr))
    #         logger.debug("new method addr 0x%x" % method.addr)
    #     self.methods[cmd] = method


class MetaClass:
    def __init__(self, metaClass=""):
        self.metaClass = metaClass
        self.parent = None
        self.size = 0
        self.vtables = []
        self.vtables_addr = 0

    def repr(self):
        ret = "%s 0x%x\n" % (self.metaClass, self.vtables_addr)
        for off, name in self.vtables:
            if off:
                ret += "\t%s at 0x%x\n" % (name, off)
            else:
                ret += "\t%s\n" % name
        return ret


class BaseClass:
    def __init__(self, module, className, meta=None):
        self.module = module
        self.metaClass = className
        self.meta = meta


class Service(BaseClass):
    """
    get the addr for the following functions:
        1): ****::newUserClient()
        2): ****::getTargetAndMethodForIndex()
        3): ****::getAsyncTargetAndMethodForIndex()
        4): ****::getTargetAndTrapForIndex()
        5): ****::externalMethod()
    """

    def __init__(self, module, className):
        super().__init__(module, className)
        self.newUserClient: int = 0
        self.userClients: List[UserClient] = []
        self.access = False

    def getUserClient(self, metaClass):
        for client in self.userClients:
            if client.metaClass == metaClass:
                return client
        return None

    def repr(self):
        access = True if not hasattr(self, "access") else self.access
        ret = "Service: %s %s\n" % (
            self.metaClass, "user" if access else "root")
        ret += "func newUserClient: 0x%x\n" % self.newUserClient
        for each in self.userClients:
            ret += "\t%s\n" % each.repr()
        return ret

    @staticmethod
    def Create(module: str, clazz: str, newUserClient: BaseAddress) -> "Service":
        ret = Service(module, clazz)
        ret.newUserClient = newUserClient
        return ret


class UserClient(BaseClass):
    def __init__(self, module, className, type=None):
        super().__init__(module, className)
        self.type = type
        self.access = False

        self.getTargetAndMethodForIndex = 0
        self.getAsyncTargetAndMethodForIndex = 0
        self.externalMethod = 0
        # self.dispatchMethodsSym = None
        # self.dispatchMethods = dict()
        # self.dispatchMethodsType = ""

    def repr(self):
        ret = "%s: %d %s\n" % (self.metaClass, self.type,
                               "user" if self.access else "root")
        if self.externalMethod:
            ret += "\texternalMethod: 0x%x\n" % self.externalMethod
        if self.getTargetAndMethodForIndex:
            ret += "\tgetTargetAndMethodForIndex: 0x%x\n" % self.getTargetAndMethodForIndex
        if self.getAsyncTargetAndMethodForIndex:
            ret += "\tgetAsyncTargetAndMethodForIndex: 0x%x\n" % self.getAsyncTargetAndMethodForIndex
        # if len(self.dispatchMethods):
        #     ret += "\tDispatch Table:"
        #     if self.dispatchMethodsSym:
        #         ret += " %s 0x%x %s\n" % (demangle(self.dispatchMethodsSym.name).strip(),
        #             self.dispatchMethodsSym.relative_addr, self.dispatchMethodsType)
        #     for selector, methods in self.dispatchMethods.items():
        #         ret += "\t%d: %s at 0x%x\n" % (selector, methods[0], methods[1])
        return ret

    def toJson(self):
        return {
            "externalMethod": self.externalMethod,
            "getTargetAndMethodForIndex": self.getTargetAndMethodForIndex,
            "getAsyncTargetAndMethodForIndex": self.getAsyncTargetAndMethodForIndex,
        }

    @staticmethod
    def Create(module: str, clazz: str, typ: int, ops) -> "UserClient":
        ret = UserClient(module, clazz, typ)
        ret.externalMethod = ops["externalMethod"]
        ret.getTargetAndMethodForIndex = ops["getTargetAndMethodForIndex"]
        ret.getAsyncTargetAndMethodForIndex = ops["getAsyncTargetAndMethodForIndex"]
        return ret


def read_vtables(proj, clazz):
    with open(proj.filename, "rb") as fp:
        fp.seek(clazz.vtables_addr)
        size = len(clazz.vtables)
        return fp.read(size*8)


def getVtables(proj, metaClass, addr):
    logger.debug("get vtables for %s" % metaClass)
    clazz = MetaClass(metaClass)
    clazz.vtables_addr = addr
    with open(proj.filename, "rb") as fp:
        end = addr
        while True:
            if end in proj.loader.main_object.extreltab:
                idx = proj.loader.main_object.extreltab[end].referenced_symbol_index
                sym = proj.loader.main_object.get_symbol_by_insertion_order(
                    idx)
                offset = 0
            else:
                offset = proj.loader.main_object._unpack("Q", fp, end, 8)[0]
                if offset == 0:
                    break
                syms = find(proj, offset, fuzzy=False)
                sym = syms[0] if syms else None
            if sym:
                clazz.vtables.append((offset, sym.name))
            else:
                clazz.vtables.append((offset, ""))
            end += 8
    return clazz


def findVtableOffset(meta, name):
    for i, each in enumerate(meta.vtables):
        if name == each[1]:
            return meta.vtables_addr + i*8
    return 0


def parse_vtables(proj, target=""):
    metaClazz = {}
    for sym in find(proj, "__ZTV"):  # vtables
        demangledname = demangle(sym.name).strip()
    #     print(demangledname)
        if demangledname.startswith("vtable for " + target):
            metaClass = demangledname[len("vtable for "):]
            if sym.value != 0:
                # proj.loader.main_object.min_addr is zero in most cases
                # but has non-zero value if the given binary is kernel
                clazz = getVtables(
                    proj,
                    metaClass,
                    sym.value+0x10-proj.loader.main_object.min_addr
                )
                metaClazz[metaClass] = clazz
    return metaClazz

# def parse_registered_clazz(proj):
#     # Patch relocation to data reference first
#     relocations = defaultdict(list)
#     for offset, extrel in proj.loader.main_object.extreltab.items():
#         if extrel.is_reference_undefined_data and not extrel.is_relative_pc:
#             relocations[(extrel.symbol.name, extrel.size)].append(offset)

#     base_state = proj.factory.blank_state()
#     for key, addrs in relocations.items():
#         syn_name = demangle(key[0])
#         v = base_state.solver.BVS(syn_name, key[1]*8)
#         # Patch reference
#         for relc in addrs:
#             # print(relc, v)
#             base_state.memory.store(relc, v)

#     ret = []
#     for addr in proj.loader.main_object.mod_init_func_pointers:
#         state = proj.factory.call_state(addr, base_state=base_state.copy())
#         # print(state.mem.types)
#         simgr = proj.factory.simgr(state)
#         simgr.step()

#         if len(simgr.active) != 1:
#             raise Exception(
#                 "parse_registered_clazz error: expect 1 state but get %d states" % len(simgr.active))
#         state = simgr.active[0]

#         parent = state.regs.rdx
#         if state.solver.symbolic(parent):
#             name, _, _ = extractField(parent)
#             # print(name, type(name))
#             name = extractName(name)
#         else:
#             parent = state.solver.eval(parent)
#             sym = proj.loader.find_symbol(parent)
#             # if sym is None:
#             #     continue

#             name = sym.name
#             name = demangle(name)

#         className = state.mem[state.regs.rsi].string.concrete.decode()
#         size = state.solver.eval(state.regs.rcx)
#         print("addr: 0x%x" % addr)
#         print("name:", className)
#         # TODO: detect userClient class
#         print("parent:", name)
#         print("size:", size)
#         clazz = MetaClass()
#         clazz.metaClass = className
#         clazz.parent = name
#         clazz.size = size
#         ret.append(clazz)

#     return ret
