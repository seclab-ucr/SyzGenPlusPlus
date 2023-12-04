
from collections import OrderedDict
import logging
import os
import pickle
import re
import subprocess
from angr.sim_manager import SimulationManager
from angr.sim_type import *

from syzgen.executor import PluginMixin
from syzgen.parser.models import TargetAddress

logger = logging.getLogger(__name__)

NM_Function_Expr = re.compile(r"(?P<addr>[a-f0-9]+) T (?P<name>.+)")
Function_Name_Expr = re.compile(
    r"^(\d+:)?\s*(static )?(?P<return>.+ \**)(?P<name>\w+)\((?P<params>.+)\);?")
Function_Ret_Expr = re.compile(
    r"^(\d+:)?\s*(static )?(?P<return>.+ \**)\((?P<stars>\*+)(?P<name>\w+)\((?P<params2>.+)\)\)\((?P<params>.+)\);?")
Arg_Function_Expr = re.compile(
    r"^(?P<return>[^,]+)\((?P<stars>\*+)( const)?\)\(")
Array_Expr = re.compile(
    r"(?P<type>.+)\((?P<stars>\*+)( const)?\)\[(?P<size>\d*)\]")

types = {
    "u64": SimTypeNum(64, False),
    "u32": SimTypeNum(32, False),
    "u16": SimTypeNum(16, False),
    "u8":  SimTypeNum(8, False),
}
register_types(types)


def parse_type(typ: str):
    if typ in ALL_TYPES:
        return ALL_TYPES[typ]
    m = Arg_Function_Expr.match(typ)
    if m:
        ret, stars = m.group("return"), len(m.group("stars"))
        params = FunctionSignaturePlugin.split_parameters(
            typ[len(m.group(0)):-1])
        f = SimTypeFunction(params, parse_type(ret.strip()))
        for _ in range(stars):
            f = SimTypePointer(f)
        return f
    for prefix in {"const ", "volatile "}:
        if typ.startswith(prefix):
            return parse_type(typ[len(prefix):])
    for suffix in {" const", " restrict"}:
        if typ.endswith(suffix):
            return parse_type(typ[:-len(suffix)])

    if typ[-1] == "*":
        ret = SimTypePointer(parse_type(typ[:-1].rstrip()))
    elif typ[-1] == ']':
        m = Array_Expr.match(typ)
        assert m is not None
        t, stars, size = m.group("type"), m.group("stars"), m.group("size")
        if size:
            f = SimTypeFixedSizeArray(parse_type(t.strip()), int(size, 10))
        else:
            f = SimTypeArray(parse_type(t.strip()))
        if stars:
            for _ in range(len(stars)):
                f = SimTypePointer(f)
        return f
    elif typ.startswith("struct "):
        ret = SimStruct(OrderedDict(), name=typ[len("struct "):])
    elif typ.startswith("union "):
        ret = SimUnion({}, name=typ[len("union "):])
    elif typ.startswith("enum "):
        ret = ALL_TYPES["int"]
    elif len(typ.split()) == 1:
        ret = SimTypeTop(label=typ)
    else:
        raise NotImplementedError("unsupported type", typ)

    register_types({typ: ret})
    return ret


class FunctionSignaturePlugin(PluginMixin):
    """Managing function signature"""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init FunctionSignaturePlugin")
        self._prototypes_path = os.path.join(self.get_target().workdir, "prototypes.pickle")
        self._prototypes: Dict[TargetAddress, SimTypeFunction] = {}

    def get_prototype_by_addr(self, addr: TargetAddress) -> Optional[SimTypeFunction]:
        return self._prototypes.get(addr, None)

    def pre_execute(self, state: SimState) -> None:
        if self.is_enabled(FunctionSignaturePlugin):
            self.load_prototypes()

        return super().pre_execute(state)

    def post_execute(self, simgr: SimulationManager) -> None:
        if self.is_enabled(FunctionSignaturePlugin):
            self.save_prototypes_to_file()

        return super().post_execute(simgr)

    def _execute_command(self, cmds, func):
        p = subprocess.Popen(cmds, stdout=subprocess.PIPE)
        for line in p.stdout:
            func(line.decode().rstrip())
        p.stdout.close()
        p.wait()

    # def _nm_get_all_functions(self, binary):
    #     all_functions = {}

    #     def collect(line: str):
    #         m = NM_Function_Expr.match(line)
    #         if m:
    #             addr, name = int(m.group("addr"), 16), m.group("name")
    #             all_functions[name] = addr

    #     self._execute_command(["nm", binary], collect)
    #     return all_functions

    def _gdb_info_functions(self, binary):
        prototypes = {}

        def collect(line: str):
            if not line.endswith(";"):
                return

            # logger.debug("parse %s", line)
            name, prototype = FunctionSignaturePlugin.parse_signature(line)
            prototypes[name] = prototype

        cmds = ["gdb", binary, "-ex", "info functions", "-q", "--batch"]
        self._execute_command(cmds, collect)
        return prototypes

    @staticmethod
    def split_parameters(params: str):
        _params = []
        while params:
            m = Arg_Function_Expr.search(params)
            if m:
                p = m.group(0)
                c = 1
                for i in range(len(p), len(params)):
                    if params[i] == '(':
                        c += 1
                    elif params[i] == ')':
                        c -= 1
                        if c == 0:
                            p = params[:i+1]
                            _params.append(parse_type(p))
                            params = params[i+1:].lstrip(", ")
                            break
            else:
                res = params.split(",", 1)
                if len(res) == 1:
                    p, params = res[0], ""
                else:
                    p, params = res
                _params.append(parse_type(p))
                params = params.lstrip()
        return _params

    @staticmethod
    def parse_signature(line: str):
        m = Function_Name_Expr.match(line)
        if m is not None:
            ret, name, params = (
                m.group("return"),
                m.group("name"),
                m.group("params"),
            )
        else:
            m = Function_Ret_Expr.match(line)
            if m is not None:
                ret, name, params = (
                    f'{m.group("return")} ({m.group("stars")})({m.group("params2")})',
                    m.group("name"),
                    m.group("params")
                )
        if m is None:
            raise RuntimeError("failed to parse %s" % line)
        # function pointer in params
        _params = FunctionSignaturePlugin.split_parameters(params)
        # protocol: SimTypeFunction = parse_signature(line)
        prototype = SimTypeFunction(
            _params, parse_type(ret.strip()), label=name)
        return name, prototype

    def _get_function_signature_from_symbols(self, module, binary):
        logger.debug("trying to get function signatures from debug info...")
        prototypes = self._gdb_info_functions(binary)
        # FIXME: get proj based on the module
        _, _, proj = self.load_project_by_addr(0)
        for name, prototype in prototypes.items():
            sym = proj.loader.find_symbol(name)
            if sym:
                t = self.getTargetAddr(sym.relative_addr, module)
                self._prototypes[t] = prototype

    def load_prototypes_from_file(self) -> None:
        if os.path.exists(self._prototypes_path):
            with open(self._prototypes_path, "rb") as fp:
                prototypes = pickle.load(fp)
                for (module, addr), obj in prototypes.items():
                    t = self.getTargetAddr(addr, module)
                    self._prototypes[t] = obj

    def save_prototypes_to_file(self) -> None:
        with open(self._prototypes_path, "wb") as fp:
            res = {}
            for addr, obj in self._prototypes.items():
                m, t = self.getBaseAddr(addr)
                res[(m, t)] = obj
            pickle.dump(res, fp)

    def load_prototypes(self):
        if os.path.exists(self._prototypes_path):
            self.load_prototypes_from_file()
        else:
            if not self.is_enabled(FunctionSignaturePlugin):
                return

            # FIXME
            self._get_function_signature_from_symbols("kernel", self.get_default_project().filename)
