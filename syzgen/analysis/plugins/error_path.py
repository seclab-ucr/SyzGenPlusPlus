
from collections import deque
import logging
import typing
import pyvex

from typing import Dict, List, Optional, Set, Tuple, Union
from angr import Project
from angr.codenode import BlockNode
from angr.errors import SimMemoryMissingError, SimEngineError
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from syzgen.analysis.plugins.cfg import CFGRecoveryPlugin
from syzgen.analysis.plugins.error_code import DetectErrorCodePlugin
from angr.knowledge_plugins.key_definitions.atoms import Register, Atom, Tmp
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.definition import Definition
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.reaching_definitions import ReachingDefinitionsAnalysis
from angr.knowledge_plugins.functions.function import Function
from syzgen.executor import PluginMixin, PriorityList
from syzgen.models import DummyModel
from syzgen.parser.models import TargetAddress

logger = logging.getLogger(__name__)


def _get_source(data: pyvex.IRExpr, node: pyvex.block.IRSB) -> Optional[Union[int, Atom]]:
    """Get the source from a move-like instruction"""
    if isinstance(data, pyvex.expr.RdTmp):
        return Tmp(data.tmp, data.result_size(node.tyenv)//8)
    if isinstance(data, pyvex.expr.Unop):
        if data.op in {"Iop_32Uto64", "Iop_64to32", "Iop_32Sto64"}:
            return _get_source(data.args[0], node)
    if isinstance(data, pyvex.expr.Get):
        return Register(data.offset, data.result_size(node.tyenv)//8)
    if isinstance(data, pyvex.expr.Const):
        return data.con.value
    return None


def get_source(definition: Definition, node: pyvex.block.IRSB, source: Atom) -> Optional[Union[int, Atom]]:
    """Get the source from the node (recursively track back its source until we
    reach the top of node). Note we only consider direct assignment."""
    # if isinstance(stmt, pyvex.stmt.Put):
    #     source = Register(stmt.offset, stmt.data.result_size(node.block.vex.tyenv))
    for stmt in reversed(node.statements[:definition.codeloc.stmt_idx+1]):
        if isinstance(stmt, pyvex.stmt.Put):
            if isinstance(source, Register) and stmt.offset == source.reg_offset:
                source = _get_source(stmt.data, node)
        elif isinstance(stmt, pyvex.stmt.WrTmp):
            if isinstance(source, Tmp) and stmt.tmp == source.tmp_idx:
                source = _get_source(stmt.data, node)

        if isinstance(source, int) or source is None:
            break

    return source


class RDFunctionHandler(FunctionHandler):
    def handle_local_function(
        self,
        state: "ReachingDefinitionsState",
        function_address: int, call_stack: Optional[List], maximum_local_call_depth: int, visited_blocks: Set[int], dep_graph: "DepGraph", src_ins_addr: Optional[int] = None, codeloc: Optional['CodeLocation'] = None
    ) -> Tuple[bool, "ReachingDefinitionsState", Set[int], "DepGraph"]:
        return False, state, visited_blocks, dep_graph

    def handle_indirect_call(self, state: 'ReachingDefinitionsState', src_codeloc: Optional['CodeLocation'] = None) -> Tuple[bool, 'ReachingDefinitionsState']:
        return False, state

class DetectErrorPathPlugin(
    CFGRecoveryPlugin,
    DetectErrorCodePlugin,
):
    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        logger.debug("init DetectErrorPathPlugin")

        self._checked_error_funcs: typing.Set[int] = set()
        self._error_blocks: typing.Set[int] = set()
        self._error_path_counter = 0
        self.register_function_call(self._detect_error_path_on_call, PriorityList.LOW_PRIORITY)

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if not self.is_enabled(DetectErrorPathPlugin):
            self.unregister_function_call(self._detect_error_path_on_call)

    def enable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().enable_plugin(clazz)

        if self.is_enabled(DetectErrorCodePlugin):
            self.register_function_call(self._detect_error_path_on_call, PriorityList.LOW_PRIORITY)

    def detect_error_path_filter(self, addr: TargetAddress) -> bool:
        return False

    def isErrorCode(self, val: int) -> bool:
        """Derived class needs to override this function"""
        return False

    def _check_all_values(self, module: str, values, rd: ReachingDefinitionsAnalysis, source: Register, defs: LiveDefinitions, addr: int, target_func: Function, visited: Dict, targets) -> bool:
        # if addr == 0xffffffff81f6cba0:
        #     from IPython import embed; embed()
        # logger.debug("values: %s", values)
        res = True
        for value in values:
            if value.op == "BVV":
                val = value.args[0]
                if not self.isErrorCode(val) and val != 0:
                    res = False
                continue

            has_def = False
            # logger.debug("check value: %s", value)
            for definition in defs.extract_defs(value):
                # logger.debug("check definition: %s", definition)
                # First check if we get the value from a function call.
                # if so, it is unresolved since we do not perform inter-
                # procedure analysis.
                if definition.tags:
                    is_ret = False
                    for tag in definition.tags:
                        if isinstance(tag, ReturnValueTag):
                            is_ret = True
                            func_addr = tag.function
                            if tag.function is None:
                                # statically unresolved targets
                                if addr in self.call_targets:
                                    func_addrs = self.call_targets[addr]
                                else:
                                    logger.debug("unknown call target at %#x", addr)
                                    break
                            else:
                                func_addrs = [tag.function]
                                # from IPython import embed; embed()
                            # logger.debug("error code from function %#x", func_addr)
                            # FIXME: it is not a target address
                            for func_addr in func_addrs:
                                if not self.always_return_error_code(self.getTargetAddr(func_addr, module), visited, targets):
                                    res = False
                                    break
                            break
                    if is_ret:
                        continue

                has_def = True
                if isinstance(definition.codeloc, ExternalCodeLocation):
                    continue

                node = target_func.project.factory.block(definition.codeloc.block_addr)
                # node = target_func.get_node(definition.codeloc.block_addr)
                res = get_source(definition, node.vex, source)
                if res is None:
                    # unresolved source
                    # blocks[node.addr] = False
                    logger.debug("failed to get its source")
                    continue
                if res == source:
                    if value.op == "BVV":
                        # Due to optimization (ie, const unfolding), we may not be
                        # able to get the source from those opted out instructions.
                        val = value.args[0]
                        if not self.isErrorCode(val) and val != 0:
                            res = False
                        continue
                if isinstance(res, int):
                    logger.debug(
                        "find one error code %#x at %#x", res, node.addr)
                    # print(f"find one error code {res:#x} at {node.addr:#x}")
                    # from IPython import embed; embed()
                    if not self.isErrorCode(res) and res != 0:
                        res = False
                    continue
                assert(isinstance(res, Register))
                if not self.reg_is_error_code(module, rd, res, rd.get_reaching_definitions_by_node(node.addr, OP_BEFORE), node.addr, target_func, visited, OP_BEFORE, targets):
                    res = False
                # logger.debug("add node %#x", node.addr)
            if defs.is_top(value) and not has_def:
                # no use-def chain for this source in this node because it is
                # directly passed from predecessors. Traverse each predecessor
                # to get the error code.
                node = target_func.get_node(addr)
                for pred in node.predecessors():
                    if not self.reg_is_error_code(module, rd, source, rd.get_reaching_definitions_by_node(pred.addr, OP_AFTER), pred.addr, target_func, visited, OP_AFTER, targets):
                        res = False
                # all predecessors return an error code
                # return True
        return res

    def reg_is_error_code(self, module: str, rd: ReachingDefinitionsAnalysis, source: Register, defs: LiveDefinitions, addr: int, target_func: Function, visited: Dict, t, targets) -> bool:
        # logger.debug(f"looking for {source} from {addr:#x}")
        # visited.add((source.reg_offset, addr))
        if (source.reg_offset, addr, t) in visited:
            return visited[(source.reg_offset, addr, t)]
        visited[(source.reg_offset, addr, t)] = True # to avoid infinite loop

        res = True
        try:
            for values in defs.register_definitions.load(source.reg_offset, source.size).values.values():
                if not self._check_all_values(module, values, rd, source, defs, addr, target_func, visited, targets):
                    visited[(source.reg_offset, addr, t)] = False
                    res = False
        except SimMemoryMissingError:
            # no def chain for this source, we lost track...
            # probably because of some unresolved function call
            # conservatively assume it does not set an error code.
            logger.debug("failed to get rd for %s from %#x", source, addr)
        #     # FIXME: aggressive
        #     return True

        visited[(source.reg_offset, addr, t)] = res
        return res

    def backward(self, rd: ReachingDefinitionsAnalysis, exit_addr: int, target_func: Function) -> typing.Dict[int, bool]:
        """conduct recursive backward analysis to find the block that set the error code.
        Two types of blocks: 1. blocks that definitely set the error code and 2. others
        with unresolved source or non-error-code source"""
        defs = rd.get_reaching_definitions_by_node(exit_addr, OP_AFTER)
        source = Register(self._ret_reg_offset, self._ret_reg_size)

        queue = deque()
        # register to track
        # reaching definition for the tracked register
        # location where we get the defs
        queue.append((source, defs, exit_addr))
        visited = set()
        blocks = {}

        def mark(addr, val):
            if addr not in blocks or blocks[addr]:
                blocks[addr] = self.isErrorCode(val)

        while queue:
            source, defs, addr = queue.pop()
            # print(f"looking for {source} from {addr:#x}")
            if (source.reg_offset, addr) in visited:
                continue
            visited.add((source.reg_offset, addr))
            # if addr == 0xffffffff8284002f:
            #     from IPython import embed; embed()
            try:
                for values in defs.register_definitions.load(source.reg_offset, source.size).values.values():
                    for value in values:
                        has_def = False
                        for definition in defs.extract_defs(value):
                            # First check if we get the value from a function call.
                            # if so, it is unresolved since we do not perform inter-
                            # procedure analysis.
                            if definition.tags:
                                for tag in definition.tags:
                                    if isinstance(tag, ReturnValueTag):
                                        blocks[addr] = False
                                        break
                                if addr in blocks:
                                    break

                            has_def = True
                            if isinstance(definition.codeloc, ExternalCodeLocation):
                                continue

                            node = target_func.project.factory.block(definition.codeloc.block_addr)
                            # node = target_func.get_node(definition.codeloc.block_addr)
                            res = get_source(definition, node.vex, source)
                            if res is None:
                                # unresolved source
                                blocks[node.addr] = False
                                continue
                            if res == source:
                                if value.op == "BVV":
                                    # Due to optimization (ie, const unfolding), we may not be
                                    # able to get the source from those opted out instructions.
                                    mark(node.addr, value.args[0])
                                else:
                                    # eax = eax + 1
                                    blocks[node.addr] = False
                                continue
                            if isinstance(res, int):
                                logger.debug(
                                    "find one error code %#x at %#x", res, node.addr)
                                # print(f"find one error code {res:#x} at {node.addr:#x}")
                                mark(node.addr, res)
                                continue
                            if isinstance(res, Tmp):
                                blocks[node.addr] = False
                                continue
                            assert(isinstance(res, Register))
                            queue.append((
                                res,
                                rd.get_reaching_definitions_by_node(
                                    node.addr, OP_BEFORE),
                                node.addr,
                            ))
                            # logger.debug("add node %#x", node.addr)
                        if defs.is_top(value) and not has_def:
                            # no use-def chain for this source in this node because it is
                            # directly passed from predecessors. Traverse each predecessor
                            # to get the error code.
                            node = target_func.get_node(addr)
                            for pred in node.predecessors():
                                queue.append((
                                    source,
                                    rd.get_reaching_definitions_by_node(
                                        pred.addr, OP_AFTER),
                                    pred.addr,
                                ))
                                # logger.debug("add pred node %#x", pred.addr)
                            continue
            except SimMemoryMissingError:
                # no def chain for this source, we lost track...
                # probably because of some unresolved function call
                # conservatively assume it does not set an error code.
                logger.debug("failed to get rd for %s from %#x", source, addr)
                blocks[addr] = False
                pass
        return blocks

    def funcMayReturnError(self, func: Function, proj: Project) -> bool:
        for node in func.graph.nodes():
            # print(hex(node.addr))
            block = proj.factory.block(node.addr)
            for stmt in block.vex.statements:
                if isinstance(stmt, pyvex.IRStmt.Put) and isinstance(stmt.data, pyvex.IRExpr.Const):
                    const = stmt.data.con.value
                    if self.isErrorCode(const):
                        # if 0xe00002bc <= const <= 0xe00002f0:
                        # print("may return error code %#x" % node.addr)
                        return True

        return False

    def always_return_error_code(self, entry: TargetAddress, visited: Optional[Dict]=None, targets: Optional[Set]=None) -> bool:
        # TODO: interface-aware
        def nodeOnly(typ, **kwargs):
            return typ == "node"

        if visited is None:
            visited = {}
        if entry in visited:
            return visited[entry]

        # logger.debug("check return values for %#x", entry)
        if targets and entry in targets:
            targets.remove(entry)

        self._recover_cfg(entry)
        target_func = self.get_func_by_addr(entry)
        if target_func is None:
            proj = self.get_default_project()
            res = True
            if proj.is_hooked(entry):
                proc = proj._sim_procedures[entry]
                if isinstance(proc, DummyModel):
                    # modeled functions do not return error code,
                    ret_error = proc.ret_value is None or proc.ret_value == 0
                    if not ret_error:
                        res = False
            visited[entry] = res
            return res

        module, _, proj = self.load_project_by_addr(entry)
        try:
            rd: ReachingDefinitionsAnalysis = proj.analyses.ReachingDefinitions(
                subject=target_func,
                func_graph=target_func.graph,
                cc=target_func.calling_convention,
                observe_callback=nodeOnly,
                function_handler=RDFunctionHandler(),
            )
        except SimEngineError:
            logger.info("ReachingDefinitionsAnalysis failed")
            return False

        # 1. Find all exit nodes
        exit_nodes = []
        for node in target_func.graph.nodes():
            block = proj.factory.block(node.addr)
            if block.vex.jumpkind == 'Ijk_Ret':
                exit_nodes.append(node)

        res = True
        source = Register(self._ret_reg_offset, self._ret_reg_size)
        for each in exit_nodes:
            defs = rd.get_reaching_definitions_by_node(each.addr, OP_AFTER)
            if not self.reg_is_error_code(module, rd, source, defs, each.addr, target_func, visited, OP_AFTER, targets):
            # if not self._always_return_error_code(module, rd, each.addr, target_func):
                res = False
        visited[entry] = res
        return res

    def detect_error_paths(self, entry: TargetAddress, target_func: Function):
        logger.debug("detect_error_paths for %#x", entry)

        def nodeOnly(typ, **kwargs):
            return typ == "node"

        _, _, proj = self.load_project_by_addr(entry)
        if not self.funcMayReturnError(target_func, proj):
            return set()

        rd: ReachingDefinitionsAnalysis = proj.analyses.ReachingDefinitions(
            subject=target_func,
            func_graph=target_func.graph,
            cc=target_func.calling_convention,
            observe_callback=nodeOnly,
            function_handler=RDFunctionHandler(),
        )

        # 1. Find all exit nodes
        exit_nodes = []
        for node in target_func.graph.nodes():
            block = proj.factory.block(node.addr)
            if block.vex.jumpkind == 'Ijk_Ret':
                exit_nodes.append(node)
        # print("exit_nodes", exit_nodes)

        # 2. Find all frontiers that set return value
        errorBlocks = {}
        for each in exit_nodes:
            blocks = self.backward(rd, each.addr, target_func)
            for addr, res in blocks.items():
                if addr not in errorBlocks:
                    errorBlocks[addr] = res
                else:  # merge two results
                    errorBlocks[addr] = errorBlocks[addr] and res
        # print("errorBlocks:")
        # for k, v in errorBlocks.items():
        #     print(f"{k:#x}:{v}")

        # 3. expand frontiers
        # the block setting error code follows a call/jmp block (We can perceive them as one block)
        # we need to work on the transition_graph as it correctly handles edges with function call
        func_cfg = target_func.transition_graph

        def get_node(nodes, addr) -> typing.Optional[BlockNode]:
            for node in nodes:
                if node.addr == addr:
                    return node
            return None

        queue = deque()
        visited = set()
        for addr, res in errorBlocks.items():
            node = get_node(func_cfg.nodes, addr)
            queue.append((node, res))
        while queue:
            node, res = queue.pop()
            if node.addr in visited:
                continue
            visited.add(node.addr)

            for pred in func_cfg.predecessors(node):
                for succ in func_cfg.successors(pred):
                    if (
                        target_func.addr <= succ.addr < target_func.addr + target_func.size and
                        succ.addr != node.addr
                    ):  # ignore function call
                        break
                else:
                    # pred has function call and/or this node.
                    errorBlocks[pred.addr] = res
                    queue.append((pred, res))

        # print("find error blocks")
        # for addr, res in errorBlocks.items():
        #     print(f"{addr:#x}: {res}")

        # 4. Construct whitelist with forward and backward traversal
        # 4.1 backward: all predecessors of non-error blocks are also non-error blocks
        queue = deque()
        visited = set()
        whitelist = set()
        for addr, res in errorBlocks.items():
            if not res:
                whitelist.add(addr)
                node = get_node(func_cfg.nodes, addr)
                assert node is not None
                queue.append(node)
        while queue:
            node = queue.pop()
            if node.addr in visited:
                continue
            visited.add(node.addr)

            # if node.addr == 0x11c67:
            #     from IPython import embed; embed()

            for pred in func_cfg.predecessors(node):
                # print(f"add {pred.addr:#x} due to succ {node.addr:#x}")
                whitelist.add(pred.addr)
                queue.append(pred)

        # print("init whitelist")
        # print(", ".join(map(hex, whitelist)))
        if not whitelist:
            logger.info("got empty whitelist, something might be wrong...")
            return set()

        # 4.2 forward: all successors of non-error blocks are also non-error block unless
        # we encounter an error block
        queue = deque()
        visited = set()
        for addr, res in errorBlocks.items():
            if not res:
                node = get_node(func_cfg.nodes, addr)
                assert node is not None
                queue.append(node)
        while queue:
            node = queue.pop()
            if node.addr in visited:
                continue
            visited.add(node.addr)
            # print(f"analyzing {node.addr:#x}")
            for pred in func_cfg.successors(node):
                if pred.addr not in errorBlocks:
                    # print(f"add {pred.addr:#x} due to pred {node.addr:#x}")
                    whitelist.add(pred.addr)
                    queue.append(pred)

        # print("final whitelist")
        # print(", ".join(map(hex, whitelist)))

        # 5. blocks not marked as non-error blocks are error blocks
        results = []
        for node in func_cfg.nodes:
            if (
                node.addr not in whitelist and
                target_func.addr <= node.addr < target_func.addr + target_func.size
            ):
                results.append(node)

        # 6. prune unnecessary blocks (reserve top blocks)
        blacklist = set([each.addr for each in results])
        pruned = set()
        for node in results:
            for pred in func_cfg.predecessors(node):
                if pred.addr not in blacklist:
                    break
            else:
                # all its predecessors in blacklist already
                pruned.add(node.addr)

        return blacklist - pruned

    def on_execute(self, simgr: SimulationManager) -> None:
        for state in simgr.active:
            if state.addr in self._error_blocks:
                logger.debug("discard state at %#x", state.addr)
                self._error_path_counter += 1
                self.discard_state(state)

        return super().on_execute(simgr)

    def post_execute(self, simgr: SimulationManager) -> None:
        logger.info("eliminate %d states due to error path detection", self._error_path_counter)
        return super().post_execute(simgr)

    def _detect_error_path_on_call(self, state: SimState):
        if state.addr in self._checked_error_funcs:
            return
        self._checked_error_funcs.add(state.addr)
        if state.project.is_hooked(state.addr):
            return
        if self.detect_error_path_filter(state.addr):
            return
        
        ret_addr = state.callstack.current_return_target & 0xffffffffffffffff
        if not self._return_value(state, ret_addr):
            return

        target_func = self.get_func_by_addr(state.addr)
        if target_func is None:
            return

        module, _ = self.getBaseAddr(state.addr)
        blocks = self.detect_error_paths(state.addr, target_func)
        for off in blocks:
            logger.debug("found an error block %#x", off)
            self._error_blocks.add(self.getTargetAddr(off, module))
