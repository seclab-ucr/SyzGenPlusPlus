
import logging
import time
from typing import Dict, Set

from angr import BP_BEFORE
from angr.block import Block, CapstoneInsn
from angr.sim_state import SimState
from angr.sim_manager import SimulationManager
from archinfo import ArchAArch64, ArchAMD64
from syzgen.executor import PluginMixin

logger = logging.getLogger(__name__)


def terminater(state):
    plugin: PluginMixin = state.globals["executor"]
    plugin.terminate_state(state)


def nop(state):
    pass


def rdmsr(state):
    ecx = state.regs.ecx
    val = state.solver.eval(ecx)
    edx = state.solver.BVS(f"rdmsr_edx_{val:#x}", 32, key=("rdmsr_edx", val), eternal=True)
    eax = state.solver.BVS(f"rdmsr_eax_{val:#x}", 32, key=("rdmsr_eax", val), eternal=True)
    state.regs.edx = edx
    state.regs.eax = eax


class InstructionHandler(PluginMixin):
    """Terminate states that encounter special instruction, e.g., ud2 or rdmsr
    cause angr does not handle it properly:
    IRSB {
        t0:Ity_I64
        00 | ------ IMark(0xffffffff814215cd, 2, 0) ------
        NEXT: PUT(rip) = 0xffffffff814215cd; Ijk_NoDecode
    }
    """

    SPECIAL_INSTUCTIONS = {
        "ud2": terminater,
        "trap": terminater,
        "nop": nop,
        "hint": nop,
        "mrs": nop,
        "stac": nop,
        "rdmsr":rdmsr,
        "vmwrite": nop,
    }

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)

        logger.debug("init InstructionHandler")
        self._special_instructions: Dict[str, Set[int]] = {}

        for k in InstructionHandler.SPECIAL_INSTUCTIONS:
            self._special_instructions[k] = set()

    def _disassemble(self, state: SimState, block: Block, addr: int):
        """See angr.block.Block.capstone"""
        cs = block.arch.capstone if not block.thumb else block.arch.capstone_thumb
        try:
            data = state.memory.load(addr, 8, inspect=False)
            bs = state.solver.eval(data).to_bytes(8, "big")
            for cs_insn in cs.disasm(bs, addr):
                return CapstoneInsn(cs_insn)
        except:
            pass
        return None

    def _undecoded_instruction(self, state: SimState, block: Block, addr: int):
        # VEX fails to handle certain instructions (e.g., vmcall)
        insn = self._disassemble(state, block, addr)
        if insn is None or insn.mnemonic not in self.SPECIAL_INSTUCTIONS:
            # give up
            logger.debug("reach block with no code, discard it")
            self.terminate_state(state)
            self._special_instructions["trap"].add(addr)
            return

        state.project.hook(
            addr,
            self.SPECIAL_INSTUCTIONS[insn.mnemonic],
            insn.size,
        )
        self._special_instructions[insn.mnemonic].add(addr)

    def onTranslateBlock(self, state):
        # The state we got is actually a copy. The original state is moved to
        # the deadended stash if it has no successors.
        block = state.project.factory.block(state.inspect.vex_lift_addr)
        logger.debug("onTranslateBlock at %#x with size: %d", state.inspect.vex_lift_addr, block.vex.size)
        if block.vex.size == 0 or not block.capstone.insns:
            self._undecoded_instruction(state, block, block.addr)
            # avoid Empty IRSB passed to HeavyVEXMixin.
            nop = None
            if isinstance(state.arch, ArchAArch64):
                nop = b'\x1f\x20\x03\xd5' # NOP
            elif isinstance(state.arch, ArchAMD64):
                nop = b'\x90'

            if nop is None:
                raise NotImplementedError("need to provide NOP")
            state.inspect.vex_lift_buff = nop
            state.inspect.vex_lift_size = len(nop)
        elif block.vex.jumpkind == 'Ijk_NoDecode':
            logger.debug("hook no decoded instruction at %#x",
                         state.inspect.vex_lift_addr)
            if block.capstone.insns[-1].mnemonic == "ud2":
                state.project.hook(
                    state.inspect.vex_lift_addr,
                    self.SPECIAL_INSTUCTIONS["ud2"],
                    block.vex.size,
                )
                self._special_instructions["ud2"].add(state.inspect.vex_lift_addr)
            elif block.capstone.insns[-1].mnemonic in {"hint", "mrs"}:
                # bti
                mnemonic = block.capstone.insns[-1].mnemonic
                state.project.hook(
                    block.vex.instruction_addresses[-1],
                    self.SPECIAL_INSTUCTIONS[mnemonic],
                    block.size,
                )
                self._special_instructions[mnemonic].add(block.vex.instruction_addresses[-1])
            else:
                self._undecoded_instruction(state, block, block.addr + block.size)
        elif block.vex.jumpkind == 'Ijk_SigTRAP':
            logger.debug("hook trap instruction at %#x", state.inspect.vex_lift_addr)
            state.project.hook(
                state.inspect.vex_lift_addr,
                self.SPECIAL_INSTUCTIONS["trap"],
                block.size,
            )
            self.discard_state(state)
            self._special_instructions["trap"].add(state.inspect.vex_lift_addr)

    def handle_special_instructions(self, state: SimState):
        for k, addrs in self._special_instructions.items():
            for addr in addrs:
                size = 0
                if k == "rdmsr":
                    size = 2
                else:
                    block = state.project.factory.block(addr)
                    assert block.size
                    size = block.size

                state.project.hook(addr, self.SPECIAL_INSTUCTIONS[k], size)

    def handle_dirty_call(self, state: SimState):
        func_name = state.inspect.dirty_name
        if func_name == "amd64g_dirtyhelper_RDTSCP":
            # unknown bugs from angr??
            # from angr.engines.vex.heavy.dirty.amd64g_dirtyhelper_RDTSC
            logger.debug("handle_dirty_call %s at %#x", func_name, state.addr)
            retval = state.solver.BVV(int(time.process_time() * 1000000) + 12345678, 64)
            state.inspect.dirty_result = retval

    def pre_execute(self, state: SimState) -> None:
        state.inspect.b('vex_lift', when=BP_BEFORE, action=self.onTranslateBlock)
        state.inspect.b('dirty', when=BP_BEFORE, action=self.handle_dirty_call)
        self.handle_special_instructions(state)
        return super().pre_execute(state)
