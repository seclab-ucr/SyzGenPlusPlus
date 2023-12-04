
from collections import deque
from typing import List
import logging

from syzgen.kext.macho import UserClient, find, isDefinedFunc
from syzgen.kext.helper import parse_signature
from syzgen.utils import demangle, demangle
# from syzgen.executor.executor import StaticExecutor

logger = logging.getLogger(__name__)


# class EntitlementExecutor(StaticExecutor):
#     """IOUserClient::copyClientEntitlement(task, const char*)
#     """

#     MAXIMUM_TIMES = 5

#     def __init__(self, binary, func, start):
#         super(EntitlementExecutor, self).__init__(binary, func, start)

#         self.entitlement = ""
#         self.counters = dict()

#     def execute(self, state):
#         """ Record the excution times of each basic block to avoid running indefinitely.
#         """
#         if state.addr not in self.counters:
#             self.counters[state.addr] = 1
#         else:
#             self.counters[state.addr] += 1
#         if self.counters[state.addr] > self.MAXIMUM_TIMES:
#             return []

#         return super(EntitlementExecutor, self).execute(state)

#     def handle_state(self, state, block):
#         print(hex(state.addr), hex(block.addr))
#         if block.capstone.insns[-1].mnemonic == 'call':
#             addr = block.capstone.insns[-1].address + 1
#             if addr in self.proj.loader.main_object.extreltab:
#                 idx = self.proj.loader.main_object.extreltab[addr].referenced_symbol_index
#                 sym = self.proj.loader.main_object.get_symbol_by_insertion_order(
#                     idx)
#                 print("call %s" % sym.name)
#                 metaClass, func = parse_signature(demangle(sym.name))
#                 if metaClass == "IOUserClient" and func == "copyClientEntitlement":
#                     entitlement = state.mem[state.regs.rsi].string.concrete.decode(
#                         "utf8")
#                     print("require entitlement: %s" % entitlement)
#                     self.entitlement = entitlement
#                     self.abort()


# def find_entitlement(binary):
#     entitlements = set()
#     proj = angr.Project(binary)
#     # possible functions that will check entitlements
#     targets = ["initWithTask", "newUserClient"]
#     for tgt in targets:
#         for sym in find(proj, tgt):
#             if sym.section_name != "__text":
#                 continue
#             metaClass, func = parse_signature(demangle(sym.name))
#             if func != tgt:
#                 continue

#             print(metaClass, func, sym.name, sym.relative_addr)
#             executor = EntitlementExecutor(binary, sym, sym.relative_addr)
#             executor.run()
#             if executor.entitlement:
#                 entitlements.add(executor.entitlement)

#     return entitlements


def parse_client(proj, client: UserClient):
    symbols = []
    for sym in find(proj, client.metaClass):
        if isDefinedFunc(sym):  # and sym.is_external:
            symbols.append(sym)

    founded = 0
    for sym in symbols:
        demangled = demangle(sym.name)
        metaClass, funcName = parse_signature(demangled)
        if metaClass != client.metaClass:
            continue
        founded += 1
        if funcName == "externalMethod":
            client.externalMethod = sym.relative_addr
        elif funcName == "getTargetAndMethodForIndex":
            client.getTargetAndMethodForIndex = sym.relative_addr
        elif funcName == "getAsyncTargetAndMethodForIndex":
            client.getAsyncTargetAndMethodForIndex = sym.relative_addr
        elif funcName == "getTargetAndTrapForIndex":
            client.getTargetAndTrapForIndex = sym.relative_addr
    return founded > 0
