
import logging

from typing import Callable, Dict, Optional, Tuple
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from claripy.ast.base import Base
from claripy.ast.bv import Reverse
from syzgen.parser.models import CommandExtractInterface
from syzgen.analysis.plugins.relaxation import ConstraintRelaxationPlugin
from syzgen.analysis.plugins.syscall import SyscallPlugin
from syzgen.executor import PriorityList
from syzgen.kext.macho import Method
from syzgen.parser.models import Address, MethodInfo, MethodTable, SimpleMethodTable, TargetAddress
from syzgen.utils import extractVariables

logger = logging.getLogger(__name__)


class CommandIdentificationPlugin(
    ConstraintRelaxationPlugin,
    SyscallPlugin,
    CommandExtractInterface,
):
    """Identify valid command values and their corresponding functionalities.
    To the end, we moniter every memory read to find any function tables and then
    the index is the command code. Sometimes if the command argument is known in priori,
    e.g., the second argument of ioctl, we also monitor its possible values."""

    MINIMUM_FUNCTIONALITY = 8

    def __init__(
        self,
        functable_filter: Optional[Callable[[int], bool]] = None,
        command_keys: Optional[Tuple] = None,
        **kwargs
    ) -> None:
        super().__init__(**kwargs)

        logger.debug("init CommandIdentificationPlugin")
        self._function_table_filter = functable_filter
        self._command_keys = command_keys
        self._func_table: Optional[MethodTable] = None
        self._cmd_table: Optional[MethodTable] = None
        self._cmd_candidates: Dict[int, int] = {}
        self.register_memory_read(
            self._identify_dispatch_table,
            PriorityList.LOW_PRIORITY
        )

        self._cmd_allowlist = self.input_prefix - {"size", "file"}

    def get_method_table(self) -> Optional[MethodTable]:
        ret: Optional[MethodTable] = None
        if self._func_table is None:
            ret = self._cmd_table
        elif self._cmd_table is None:
            ret = self._func_table
        else:
            ret = (
                self._func_table
                if len(self._func_table) > len(self._cmd_table) else
                self._cmd_table
            )
        if ret is not None and len(ret.methods) == 0:
            ret = None
        return ret

    def new_method_table(self, selector: Base) -> MethodTable[MethodInfo]:
        raise NotImplementedError()

    def new_method(
        self,
        state: Optional[SimState],
        ptr: TargetAddress,
        addr: Address,
        cmd: int,
        isCustom: bool
    ) -> MethodInfo:
        """
        @param ptr: the pointer that points to the addr
        @param addr: the base address of the functionality
        """
        raise NotImplementedError()

    def get_method(self, state: SimState, ptr: TargetAddress, cmd: int, isCustom: bool) -> Tuple[bool, Optional[Method]]:
        addr = state.memory.load(
            ptr, 8, endness=state.arch.memory_endness, inspect=False)
        concrete_addr = state.solver.eval(addr)
        if concrete_addr == 0:
            # it is possible we have a null pointer.
            return True, None
        module, offset = self.getBaseAddr(concrete_addr)
        if not offset:
            # not a valid pointer
            return False, None

        sec = self.find_section_by_addr(concrete_addr)
        if not sec or sec.name not in {".text", "__text"}:
            return False, None
        return True, self.new_method(state, ptr, Address(module, offset), cmd, isCustom)

    def _parse_function_table(self, state: SimState, cmd: Base, expr, isCustom: bool = False):
        if (
            self._func_table is None or
            self._func_table.selector.shallow_repr() != cmd.shallow_repr()
        ):
            table = self.new_method_table(cmd)
        else:
            table = self._func_table

        # for arguments like selector/cmd, we directly assign values to their corresponding registers
        # and thus have different endianness
        isLittleEndian = (
            cmd.op == "BVS" and
            cmd.args[0].startswith(tuple(self.input_prefix))
        )
        cmd = cmd if isLittleEndian or cmd.length <= 8 else Reverse(cmd)

        # Due to concretization, we may have some unnecessary constraints.
        # Use reduced constraints to make sure we can get the correct max value.
        new_state = state.copy()
        self.reload_solver(state, new_state)
        # if isLittleEndian else state.solver.max(Reverse(cmd))
        # FIXME:
        # <SAO <BV64 if 0x5 <= selector_0_32 then 0x0 else 0xffffff7f90833470 +
        # ((0x0 .. selector_0_32) + (0x0 .. selector_0_32 .. 0) .. 0)>>
        total = new_state.solver.max(cmd)
        logger.debug("cmd max: %d", total)
        if total > 1024:
            logger.debug("cmd cannot be larger than 1024")
            return None

        # from IPython import embed; embed()

        i = new_state.solver.min(cmd)
        while i <= total:
            if (
                i not in table.methods and
                new_state.solver.satisfiable(extra_constraints=(cmd == i,))
            ):
                blank_state = new_state.copy()
                blank_state.solver.add(cmd == i)
                ptr = blank_state.solver.eval(expr)
                succeed, m = self.get_method(new_state, ptr, i, isCustom)
                if not succeed:
                    return None

                if m:
                    logger.debug("[1] %s", m)
                    table.addMethod(m)

            i += 1

        # while True:
        #     # Due to concretization, we may have some unnecessary constraints.
        #     # We allow it to continue to search forward and halt if we cannot find more functions.
        #     # Typically the function table is followed by some null bytes.
        #     blank_state: SimState = state.project.factory.blank_state()
        #     # if isLittleEndian:
        #     blank_state.solver.add(cmd == i)
        #     # else:
        #     #     blank_state.solver.add(Reverse(cmd) == i)
        #     ptr = blank_state.solver.eval(expr)
        #     succeed, m = self.get_method(state, ptr, i, isCustom)
        #     if not succeed or not m:
        #         break
        #     logger.debug("[2] %s", m)
        #     table.addMethod(m)
        #     i += 1

        table.debug_repr()
        if self._func_table is None or len(table) > len(self._func_table):
            # replace it
            self._func_table = table
        return table

    def _identify_dispatch_table(self, state: SimState, addr, size, isCustom=True):
        if self._function_table_filter and self._function_table_filter(state.addr):
            return

        if not state.solver.is_true(size == 8):
            # not read a pointer
            return

        # TODO: do we really need this?
        # base, offset = extractBaseOffset(state, addr)
        # if base is None or offset is None:
        #     return

        cmds = extractVariables(addr, includes=self._cmd_allowlist)
        if len(cmds) == 1:
            cmd = cmds[0]
            logger.debug("extract cmd from mem access: %s", cmd)
            table = self._parse_function_table(state, cmd, addr, isCustom=isCustom)
            if table and len(table) > 1:
                # self.abort()
                self.discard_state(state)

    def pre_execute(self, state: SimState) -> None:
        if self._command_keys is not None:
            k = next(state.solver.get_variables(*self._command_keys), None)
            self._cmd_table = self.new_method_table(k[1] if k else None)
        return super().pre_execute(state)

    def on_execute(self, simgr: SimulationManager) -> None:
        if self._func_table and len(self._func_table) >= self.MINIMUM_FUNCTIONALITY:
            return super().on_execute(simgr)

        if self._command_keys is not None:
            for state in simgr.active:
                cmd = next(state.solver.get_variables(
                    *self._command_keys), None)
                # (('cmd', 32), <BV32 cmd_1_32>)
                solutions = state.solver.eval_upto(cmd[1], 3)
                if len(solutions) == 1:
                    if solutions[0] not in self._cmd_table.methods:
                        logger.debug(
                            "Cmd only has one value: %d", solutions[0])
                        self._cmd_table.addMethod(self.new_method(
                            state,
                            0,
                            Address(*self.getBaseAddr(state.addr)),
                            solutions[0],
                            True,
                        ))
                        # self.cmds[solutions[0]] = state.addr
                    # Allow it to continue to execute
                    # e.g., selector is not command identifier but there is an constraint on it.
                    if len(self._cmd_table) >= self.MINIMUM_FUNCTIONALITY:
                        state.regs.ip = state.project.simos.return_deadend
                        self.unregister_memory_read(self._identify_dispatch_table)
                elif len(solutions) == 2:
                    for each in solutions:
                        if each not in self._cmd_candidates:
                            self._cmd_candidates[each] = state.addr

        return super().on_execute(simgr)

    def post_execute(self, simgr: SimulationManager) -> None:
        for cmd, addr in self._cmd_candidates.items():
            if cmd not in self._cmd_table.methods:
                self._cmd_table.addMethod(self.new_method(
                    None,
                    0,
                    Address(*self.getBaseAddr(addr)),
                    cmd,
                    True,
                ))

        return super().post_execute(simgr)


class LinuxCommandIdentificationPlugin(CommandIdentificationPlugin):
    def new_method_table(self, selector: Base) -> MethodTable[MethodInfo]:
        return SimpleMethodTable(selector)

    def new_method(self, state: Optional[SimState], ptr: TargetAddress, addr: Address, cmd: int, isCustom: bool) -> MethodInfo:
        return MethodInfo(addr.module, addr.address, cmd)
