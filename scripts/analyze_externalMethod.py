#
# If the driver does not override IOUserClient::externalMethod but has
# IOUserClient::getTargetAndMethodForIndex, we set getTargetAndMethodForIndex
# as the entry where we can start to analyze because we need to set the breakpoint
# and then retrieve the concrete memory values from debugger. Thus, we cannot
# breakpoint at the core kernel, which might be hit by other processes/drivers.
# Setting breakpoint at the driver code is preferrable but also introduce the
# problem where we do not have the address of inputs. By reverse engineer, we
# can easily find which register the input args is store at and this script is
# trying to automate the process.
#

import angr
from angr.sim_manager import SimulationManager

from angr.sim_state import SimState
from base import Command, logger
from syzgen.analysis.explore import BFSExplore
from syzgen.config import Options
from syzgen.executor.executor import BaseExecutor
from syzgen.kext.helper import parse_signature
from syzgen.kext.macho import find, parse_vtables, read_vtables
from syzgen.target import Target
from syzgen.utils import demangle

# See xnu-6153.81.5/iokit/Kernel/IOUserClient.cpp
# IOReturn
# IOUserClient::externalMethod( uint32_t selector, IOExternalMethodArguments * args,
#     IOExternalMethodDispatch * dispatch, OSObject * target, void * reference )


class TargetHook(angr.SimProcedure):
    def run(self, this, object, selector, executor=None):
        logger.debug("call IOUserClient::getTargetAndMethodForIndex")
        # logger.debug("r12: %s", self.state.regs.r12)
        # TODO: enumerate all registers
        for reg in self.state.arch.register_list:
            if reg.concrete and reg.general_purpose:
                val = self.state.registers.load(
                    reg.name, inspect=False, disable_actions=True)
                if (
                    not self.state.solver.symbolic(val) and
                    self.state.solver.eval(val) == 0xb0004000
                ):
                    # find the register that points to args
                    executor.reg = {
                        "type": "SimRegArg",
                        "reg_name": reg.name,
                        "size": reg.size,
                    }
                    break

        if executor:
            executor.abort()


class ExternalMethodExecutor(BaseExecutor):
    def __init__(self, binary, entry, target, model=None):
        super().__init__(binary, model=model)

        self._start = entry
        self._target = target
        self.metaClazz = parse_vtables(self.proj, target="IOUserClient")
        self.reg = None

    def pre_execute(self, state):
        logger.debug("hook getTargetAndMethodForIndex at %#x", self._target)
        self.proj.hook(self._target, TargetHook(executor=self), length=0)

    def getInitState(self):
        state: SimState = self.proj.factory.blank_state(addr=self._start)

        vtable = read_vtables(self.proj, self.metaClazz["IOUserClient"])
        args = state.solver.BVV(0, 0x1000)
        # client = state.solver.BVS("client", 0x1000*8)

        # First field is vtable
        state.memory.store(0xb0000000, state.solver.BVV(
            0xb0001000, 64), endness=state.arch.memory_endness)
        # state.memory.store(0xb0000008, client)
        state.memory.store(0xb0001000, state.solver.BVV(vtable, len(vtable)*8))
        state.memory.store(0xb0004000, args)
        return self.proj.factory.call_state(
            state.addr,
            0xb0000000,  # this
            0,  # selector
            0xb0004000,  # args
            0,  # dispath
            0,  # target
            0,  # reference,
            base_state=state,
        )

    def execute(self, simgr: SimulationManager) -> SimulationManager:
        exp = BFSExplore(verbose=True)

        def callback(simgr):
            return self.should_abort

        exp.explore(simgr, 60, callback)

        return simgr


class Analyzer(Command):
    def find_func(self, proj, meta, name):
        for sym in find(proj, name):
            if sym.section_name != "__text":
                continue
            metaClass, func = parse_signature(demangle(sym.name))
            if func != name or metaClass != meta:
                continue
            return sym
        return None

    def run(self, args, target: Target):
        binary = target.inst.get_kernel()
        proj = angr.Project(binary)

        externalMethod = self.find_func(proj, "IOUserClient", "externalMethod")
        getTargetAndMethodForIndex = self.find_func(
            proj, "IOUserClient", "getTargetAndMethodForIndex")
        executor = ExternalMethodExecutor(
            binary,
            externalMethod.relative_addr,
            getTargetAndMethodForIndex.relative_addr
        )
        executor.run()
        if executor.reg:
            logger.debug("find the register that points to args %s",
                         executor.reg["reg_name"])
            options = Options()
            options.setConfigKey("reg_args", executor.reg)
            logger.debug("successfully save the result in the config file")
        else:
            logger.debug("failed to find the register!")


if __name__ == '__main__':
    Analyzer().start()
