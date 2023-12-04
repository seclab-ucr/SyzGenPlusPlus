
import logging
import pyvex
import typing

from typing import Dict, Optional, Tuple
from angr import Project
from angr.calling_conventions import DefaultCC, SimRegArg
from angr.sim_state import SimState
from claripy.ast.base import Base
from syzgen.analysis.plugins.call import CallManagementPlugin
from syzgen.analysis.plugins.returns import ReturnManagementPlugin
from syzgen.config import Options
from syzgen.executor import PluginMixin, PriorityList

logger = logging.getLogger(__name__)
options = Options()

def get_return_register(proj: Project) -> Tuple[str, int, int]:
    cc = DefaultCC[proj.arch.name](proj.arch)
    if cc.RETURN_VAL is not None and isinstance(cc.RETURN_VAL, SimRegArg):
        reg_name = cc.RETURN_VAL.reg_name
        reg_offset, reg_size = proj.arch.registers.get(reg_name)
        return reg_name, reg_offset, reg_size
    raise RuntimeError("failed to get the return register")

class DetectErrorCodePlugin(
    CallManagementPlugin,
    ReturnManagementPlugin,
):
    """Detect error path by recognizing returned error code
    We read return value from register eax by default."""

    def __init__(
        self,
        **kwargs
    ) -> None:
        super().__init__(**kwargs)
        logger.debug("init DetectErrorCodePlugin")

        (
            self._ret_reg,
            self._ret_reg_offset,
            self._ret_reg_size
        ) = get_return_register(self.get_default_project())

        self._return_addr = self.get_default_project().simos.return_deadend
        # whether the caller uses the return value. If not, the return value cannot
        # be an error code.
        self._handled: Dict[int, bool] = {}
        # For the initial function we called, there is no caller for us to check.
        self._handled[self._return_addr] = True

        self._error_code_funcs = {}

        self._error_code_counter = 0

        self.register_return_callback(self._detect_error_code, PriorityList.LOW_PRIORITY)

    def isErrorCode(self, val: int) -> bool:
        return False

    def notErrorCode(self, state: SimState, ret: Base) -> None:
        return None

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if not self.is_enabled(DetectErrorCodePlugin):
            self.unregister_return_callback(self._detect_error_code)

    def enable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().enable_plugin(clazz)

        if self.is_enabled(DetectErrorCodePlugin):
            self.register_return_callback(self._detect_error_code, PriorityList.LOW_PRIORITY)

    def pre_execute(self, state: SimState) -> None:
        for item in options.getConfigKey("error_code", default=[]):
            addr = item["addr"]
            if isinstance(addr, str):
                addr = int(addr, 16)
            addr = self.getTargetAddr(addr, item["module"])
            func = eval(item["func"])
            func(0)
            self._error_code_funcs[addr] = func

        return super().pre_execute(state)

    def post_execute(self, simgr) -> None:
        logger.info("eliminate %d states due to error code detection", self._error_code_counter)
        return super().post_execute(simgr)

    def _return_value(self, state: SimState, addr: int) -> bool:
        """Make sure the return value is used. Otherwise the function may not have
        any return statements."""
        if addr in self._handled:
            return self._handled[addr]

        if state.project.is_hooked(addr):
            p = state.project.hooked_by(addr)
            res = getattr(p, "RET_ERROR", False)
            self._handled[addr] = res
            return res

        def use_register(data: Optional[pyvex.expr.IRExpr]) -> bool:
            if data is None:
                return False
            if type(data).__name__ in {"RdTmp", "Const"}:
                return False
            if isinstance(data, pyvex.expr.Get):
                if data.offset == self._ret_reg_offset:
                    return True
            elif isinstance(data, (pyvex.expr.Binop, pyvex.expr.Unop, pyvex.expr.CCall)):
                for arg in data.args:
                    if use_register(arg):
                        return True
            elif isinstance(data, pyvex.expr.Load):
                return use_register(data.addr)
            elif isinstance(data, pyvex.expr.ITE):
                for arg in [data.cond, data.iffalse, data.iftrue]:
                    if use_register(arg):
                        return True
            else:
                raise NotImplementedError("unsupported data %s", data)

        res = False
        _, off, proj = self.load_project_by_addr(addr)
        if off:
            block = proj.factory.block(off)
            for stmt in block.vex.statements:
                if type(stmt).__name__ in {"IMark", "AbiHint", "MBE", "LLSC"}:
                    continue
                if type(stmt).__name__ in {"Dirty"}:
                    # it might use or kill it, e.g., rdtsc
                    break
                if isinstance(stmt, pyvex.stmt.WrTmp):
                    # use
                    if use_register(stmt.data):
                        res = True
                        break
                elif isinstance(stmt, pyvex.stmt.Put):
                    if use_register(stmt.data):
                        res = True
                        break
                    # kill
                    if stmt.offset == self._ret_reg_offset:
                        break
                elif isinstance(stmt, pyvex.stmt.Store):
                    if use_register(stmt.data):
                        res = True
                        break
                elif isinstance(stmt, pyvex.stmt.Exit):
                    if use_register(stmt.guard):
                        res = True
                        break
                elif isinstance(stmt, pyvex.stmt.CAS):
                    if (
                        use_register(stmt.expdHi) or
                        use_register(stmt.expdLo) or
                        use_register(stmt.dataLo) or
                        use_register(stmt.dataHi)
                    ):
                        res = True
                        break
                else:
                    raise NotImplementedError(
                        "do not support %s at %#x", stmt, addr)
        self._handled[addr] = res
        return res

    def _detect_error_code(self, state: SimState):
        val = state.registers.load(self._ret_reg, inspect=False)
        if state.solver.symbolic(val):
            if state.addr == self._return_addr:
                self.notErrorCode(state, val)
        else:
            if state.solver.symbolic(state.regs.ip):
                if not state.solver.unique(state.regs.ip):
                    return
                addr = state.solver.eval(state.regs.ip)
            else:
                addr = state.addr

            ret = state.solver.eval(val)
            # if addr&0xfff == 0x22c:
            #     from IPython import embed; embed()

            if self._error_code_funcs:
                # Some functions have user-defined error code
                src_addr = state.history.jump_source
                if src_addr:
                    start_addr = self.get_func_addr(src_addr)
                    if start_addr in self._error_code_funcs:
                        isErrorCode = self._error_code_funcs[start_addr]
                        if isErrorCode(ret):
                            logger.debug("return an error code %#x", ret)
                            self._error_code_counter += 1
                            self.discard_state(state)
                        return

            if self.isErrorCode(ret) and self._return_value(state, addr):
                logger.debug("return an error code %#x", ret)
                self._error_code_counter += 1
                self.discard_state(state)
