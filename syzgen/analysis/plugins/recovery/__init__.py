
from collections import defaultdict
import importlib
import logging
import os

from typing import Callable, DefaultDict, Dict, List, Optional, Tuple, Union
import typing
from archinfo import Arch
from angr.calling_conventions import DefaultCC
from angr.sim_manager import SimulationManager
from angr.sim_state import SimState
from claripy.ast.base import Base
from syzgen.analysis.plugins.syscall import SyscallPlugin

from syzgen.analysis.reduce import HAClustering
from syzgen.calling_convention import Argument
from syzgen.config import Options
from syzgen.executor import KEY_TYPE_ANNOTATION, KEY_VARIABLES, PluginMixin, PriorityList
from syzgen.parser.models import TargetAddress
from syzgen.parser.optimize import fix_buffer_access, reduce_length
from syzgen.parser.symtype import SymScalarType, SymType
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import Context, KnownType, PtrDir, PtrType, ResourceType, Type, TypeWeight
from syzgen.target import TargetOS
from syzgen.utils import extractFields, extractSymbol, extractSymbols

logger = logging.getLogger(__name__)
ReduceStatesFunc = Callable[[List[SimState]], List[SimState]]
ReduceSyscallsFunc = Callable[[List[Syscall]], List[Syscall]]
ReduceSyscallFunc = Callable[[Syscall], None]
AnnotationCallback = Callable[["InputRecoveryPlugin", SimState], None]

options = Options()


def reduce_states(states: List[SimState]) -> List[SimState]:
    # cannot use it if it is dfs
    active_state = None
    active_states = []
    remains = []
    for state in states:
        if state.locals["stash"] != "deadended": # do not remove active states
            if active_state is None:
                active_state = state
            elif state.history.block_count > active_state.history.block_count:
                active_states.append(active_state)
                active_state = state
            else:
                active_states.append(state)
        else:
            remains.append(state)

    if active_state:
        remains.append(active_state)
    points = [(each, each.history.block_count) for each in remains]
    results = HAClustering(points)
    results.extend(active_states)
    return results


class InputRecoveryPlugin(SyscallPlugin):
    """Plugin for input struct recovery
    @param enable_input_recovery: bool
    @param input_filter: filter function
    @param syscall: Syscall
    """

    def __init__(
        self,
        input_filter: Optional[Callable[[int], bool]] = None,
        structOnly: bool = False,
        **kwargs
    ) -> None:
        """:param input_filter is used to confine the scope where we can recover the input struct."""
        super().__init__(**kwargs)

        self.input_filter = input_filter
        self._structOnly = structOnly
        self.recovered_syscalls: List[Syscall] = []

        self._reduce_states_funcs: List[ReduceStatesFunc] = []
        self._reduce_syscalls_funcs: List[ReduceSyscallsFunc] = []
        self._reduce_syscall_funcs: List[ReduceSyscallFunc] = []

        self._annotation_funcs: DefaultDict[TargetAddress,
                                            List[BaseAnnotation]] = defaultdict(list)
        self._inference_rules: List[InferenceRule] = []

        logger.debug("init InputRecoveryPlugin")
        self.register_memory_read(
            self._extract_varialbes_from_read,
            PriorityList.LOW_PRIORITY,
        )
        # self.register_constraint_callback(self._extract_variables_from_constraints, PriorityList.LOW_PRIORITY)
        # Error paths that exit early may invoke some uncovered functions. If we want to
        # reserve them, we can uncomment the following line.
        # self.register_function_call(self.log_function_call_per_state, PriorityList.LOW_PRIORITY)

    def reload(self, **kwargs) -> None:
        super().reload(**kwargs)

        self.recovered_syscalls.clear()
        self._reduce_states_funcs.clear()
        self._reduce_syscalls_funcs.clear()
        self._reduce_syscall_funcs.clear()

    def disable_plugin(self, clazz: typing.Type[PluginMixin]) -> None:
        super().disable_plugin(clazz)

        if not self.is_enabled(InputRecoveryPlugin):
            self.unregister_memory_read(self._extract_varialbes_from_read)

    def register_state_reduction(self, func: ReduceStatesFunc) -> None:
        self._reduce_states_funcs.append(func)

    def register_syscall_reduction(self, func: ReduceSyscallsFunc) -> None:
        self._reduce_syscalls_funcs.append(func)

    def register_single_syscall_reduction(self, func: ReduceSyscallFunc) -> None:
        self._reduce_syscall_funcs.append(func)

    def init(self, state: SimState) -> None:
        state.locals[KEY_VARIABLES] = defaultdict(int)
        state.locals[KEY_TYPE_ANNOTATION] = {}
        state.locals["visited"] = set()
        return super().init(state)

    def pre_execute(self, state: SimState) -> None:
        if self.is_enabled(InputRecoveryPlugin):
            t = self.get_target().target
            to_hook: Dict[str, BaseAnnotation] = {}
            # TODO: also load them from config files
            for handler in ALL_ANNOTATIONS[t]:
                to_hook[handler.FUNCTION] = handler(state.project.arch)

            names = [each for each in to_hook if each]
            for name, addr in self.getFuncAddrs(*names):
                logger.debug("Annotate %s at %#x", name, addr)
                state.project.hook(addr, self.annotate, length=0)
                self._annotation_funcs[addr].append(to_hook[name])

            for rule in ALL_INFERENCE_RULES[t]:
                self._inference_rules.append(rule(target=t))

        return super().pre_execute(state)

    def post_execute(self, simgr: SimulationManager) -> None:
        if self.is_enabled(InputRecoveryPlugin):
            # extract fields first before we reload the solver and constraints
            # note we extract it afterwards because the constraints is now simplified.
            for state in simgr.stashes["deadended"] + simgr.stashes["active"]:
                for constraint in state.solver.constraints:
                    self._extract_variables(state, constraint)

        super().post_execute(simgr)

        if self.is_enabled(InputRecoveryPlugin):
            self.recovered_syscalls = self.recover(simgr)

    def log_function_call_per_state(self, state):
        """Record all functions one state has visited"""
        state.locals["visited"].add(state.addr)

    def on_concretize_input(self, state: SimState, symbol: Base, l: int, r: int, typ: Type):
        if isinstance(typ, (KnownType, ResourceType)):
            self.extract_variable(
                state, symbol, l ,r,
                TypeWeight.KnownType + TypeWeight.Input,
            )
            logger.debug("find known type %s %d-%d (%s)", symbol, l, r, typ.name)
            state.locals[KEY_TYPE_ANNOTATION][(symbol.args[0], l, r)] = typ.name

        return super().on_concretize_input(state, symbol, l, r, typ)

    def extract_variable(self, state: SimState, expr: Union[str, Base], left: int, right: int, weight: int) -> None:
        if isinstance(expr, Base):
            if expr.op != "BVS":
                raise RuntimeError()
            key = (expr.args[0], left, right)
        else:
            key = (expr, left, right)
        state.locals[KEY_VARIABLES][key] += weight

    def _extract_variables(self, state: SimState, expr, weight: int = 1):
        fields = set()
        # only structure needs field recovery
        extractFields(expr, fields, includes=self.input_prefix)
        for each in fields:
            # logger.debug("field: %s", each)
            state.locals[KEY_VARIABLES][each] += weight

    # def _extract_ptr(self, state: SimState, expr):
    #     fields = set()
    #     extractFields(expr, fields, includes=self.input_prefix)
    #     if len(fields) == 1:
    #         for sym, l, r in fields:
    #             state.locals[KEY_TYPE_ANNOTATION][(sym, l, r)] = "ptr"
    #             # logger.debug("ptr field: %s %d %d", sym, l, r)
    #             # if l - r != 63:
    #             #     logger.info("Got a pointer whose size is %d, adjusting it...", (l-r+1)//8)
    #             #     r = l - 63
    #             # state.locals[KEY_VARIABLES][(sym, l, r)] += TypeWeight.KnownType
    #     else:
    #         logger.error("failed to extract the pointer %s", fields)

    def _extract_varialbes_from_read(self, state, addr, size):
        if state.solver.symbolic(state.regs.ip):
            return
        if state.solver.eval(size) > 8:
            # it does not help identify fields
            return

        # if state.addr <= 0xffffff8000000000:
        if self.input_filter and self.input_filter(state.addr):
            # some lib call like bcopy will access single byte
            # we only care about the code in driver
            # Extract accessed fields
            return

        cont = state.memory.load(
            addr, size,
            endness=state.arch.memory_endness,
            # disable_actions=True,
            inspect=False,
        )
        self._extract_variables(state, cont)

    def _extract_variables_from_constraints(self, state, constraints):
        if self.input_filter and self.input_filter(state.addr):
            return

        for constraint in constraints:
            logger.debug("search constraint")
            self._extract_variables(state, constraint)

    def fix_resources(self, orig: Syscall, syscall: Syscall) -> None:
        """We may mark resources as known type during the process and thus
        need to change it back according to their names which are unique."""
        resources: Dict[str, ResourceType] = {}
        def collect_resource(_, typ):
            if isinstance(typ, ResourceType):
                resources[typ.name] = typ
        orig.visit(Context(), collect_resource)

        def fix_resource(_, typ):
            if isinstance(typ, KnownType) and typ.name in resources:
                return resources[typ.name].copy()
            return typ
        syscall.refine_type(Context(), fix_resource)

    def evaluate_one(self, state: SimState) -> Syscall:
        """ convert one state to one specification"""
        syscall = self.syscall.copy()
        for i, arg in enumerate(syscall.args):
            if arg.type in {"resource", "const"}:
                continue
            if isinstance(arg, PtrType):
                if arg.dir == PtrDir.DirOut:
                    # no need to recover struct for output
                    continue
                new_arg = SymType(arg.typename, structOnly=self._structOnly)
                new_arg.initialize(state, state)
            else:
                v = next(state.solver.get_variables(arg.typename), None)
                if v is None:
                    continue
                sym = v[1]
                new_arg = SymScalarType(sym, structOnly=self._structOnly)
                new_arg.initialize(state, state)
            # find length fields
            new_arg.refineLen([i])

            logger.debug("%s: \n%s\n", arg.typename, new_arg.repr())
            arg = Type.construct(new_arg.toJson())
            logger.debug(arg.repr())
            syscall.args[i] = arg

        self.fix_resources(self.syscall, syscall)

        for rule in self._inference_rules:
            rule.optimize(syscall)
        for func in self._reduce_syscall_funcs:
            func(syscall)

        syscall.validate()
        return syscall

    def evaluate(self, states: List[SimState]) -> List[Syscall]:
        syscalls: List[Syscall] = []
        for state in states:
            if not state.solver.satisfiable():
                continue
            try:
                syscalls.append(self.evaluate_one(state))
            except Exception as e:
                logger.error("got exception %s", e)
                # from IPython import embed; embed()
                # raise e
        return syscalls

    def recover(self, simgr: SimulationManager) -> List[Syscall]:
        for name, states in simgr.stashes.items():
            for state in states:
                state.locals["stash"] = name

        # FIXME: errored states?
        states = simgr.stashes["deadended"] + simgr.stashes["active"] + simgr.stashes["unconstrained"]
        states = self.deduplicate(states)
        if len(states) == 0:
            return []

        for func in self._reduce_states_funcs:
            states = func(states)
        if len(states) == 0:
            return []
        # one simple heuristic to reduce the overhead
        # we assume that adjacent paths look similar
        while len(states) >= options.max_syscalls:
            logger.info("having %s states, reduce by half...", len(states))
            states = states[::2]

        # from IPython import embed; embed()
        # simgr._store_states("merge", states)
        # simgr.merge(stash="merge")
        # syscalls = self.evaluate(simgr.stashes["merge"])
        syscalls = self.evaluate(states)
        orig_size = len(syscalls)
        if orig_size == 0:
            return []

        for func in self._reduce_syscalls_funcs:
            syscalls = func(syscalls)
        if len(syscalls) < orig_size:
            logger.debug("reduce syscalls from %d to %d",
                         orig_size, len(syscalls))
        for syscall in syscalls:
            logger.debug("%s", syscall.repr())

        for each in syscalls:
            reduce_length(each)
            fix_buffer_access(each)

        return syscalls

    def _reduce_constraints(self, state) -> List[str]:
        reduced_constraints: List[str] = []
        for constraint in state.solver.constraints:
            # if self._is_concretization_expr(constraint):
            #     continue
            symbols = extractSymbols(
                constraint, includes=self.input_prefix, merge=True)
            if len(symbols) == 0:
                continue
            reduced_constraints.append(constraint.shallow_repr(max_depth=4))
        return reduced_constraints

    def deduplicate(self, states: List[SimState]) -> List[SimState]:
        """Heuristic-based deduplication of states. Same constraint sets should
        result in same specifications"""
        size = len(states)
        results = {}
        # constraints = []
        for state in states:
            k = frozenset(self._reduce_constraints(state))
            if (
                k not in results or
                state.history.block_count > results[k].history.block_count
            ):
                results[k] = state

        logger.debug("deduplicate states from %d to %d", size, len(results))
        return [state for _, state in results.items()]

    def annotate(self, state) -> None:
        if state.addr not in self._annotation_funcs:
            raise RuntimeError()

        for annotation in self._annotation_funcs[state.addr]:
            annotation.annotate(self, state)


# index of the parameters, is pointer, name, size
ArgAnnotation = Tuple[int, bool, str, int]
class BaseAnnotation:
    TARGETS = []
    FUNCTION = ""
    ARGS: List[ArgAnnotation] = []

    def __init__(
        self,
        arch: Arch,
        function: str = "",
        targets: List[TargetOS]=[],
        args: List[ArgAnnotation] = []
    ) -> None:
        self._cc = DefaultCC[arch.name](arch)
        self.function = self.FUNCTION or function
        self.targets = self.TARGETS or targets
        self.args: List[ArgAnnotation] = self.ARGS or args
        self.eval_args: List[Argument] = []

        for idx, is_pointer, _, size in self.args:
            if idx >= len(self._cc.ARG_REGS):
                raise NotImplementedError("trying to get %dth parameter", idx)
            reg = self._cc.ARG_REGS[idx]
            _, reg_size = arch.registers.get(reg)
            self.eval_args.append(Argument.create_reg(
                reg,
                reg_size if is_pointer else size,
                is_pointer)
            )

    def _annotate_variable(self, ptr, executor: InputRecoveryPlugin, state: SimState, name: str) -> None:
        first_byte = state.memory.load(ptr, 1, inspect=False)
        if not state.solver.symbolic(first_byte):
            return

        sym, l, _ = extractSymbol(
            first_byte, includes=executor.input_pointee_prefix)
        if sym is None:
            return

        # FIXME: mark the entire symbolic input
        self._extract_type(first_byte, sym, l, 0, state, name, 0)

    def annotate(self, executor: InputRecoveryPlugin, state: SimState) -> None:
        if not self.args:
            return

        for i, (_, is_pointer, name, size) in enumerate(self.args):
            arg = self.eval_args[i]
            v = arg.get_value(state)
            if is_pointer:
                if size == 0:
                    # field with variable length like string
                    return self._annotate_variable(v, executor, state, name)

                cont = state.memory.load(v, size=size)
                self.extract_type(executor, state, cont, name, size)
            else:
                self.extract_type(executor, state, v, name, size)

    def extract_type(
        self,
        executor: InputRecoveryPlugin,
        state: SimState,
        expr: Base,
        name: str,
        size: int,
    ):
        sym, l, r = extractSymbol(expr, includes=executor.input_prefix)
        if sym is None:
            return

        self._extract_type(expr, sym, l, r, state, name, size)

    def _extract_type(self, expr, sym, l: int, r: int, state: SimState, name: str, size: int) -> None:
        logger.debug(
            "annotate %s with %s at %s",
            expr.shallow_repr(max_depth=4),
            name,
            self.FUNCTION or hex(state.addr)
        )
        key = (sym.args[0], l, r)
        if size != 0 and (l-r+1)//8 != size:
            logger.info("failed to extract the field for %s", name)
            return

        logger.debug("key: %s", key)
        state.locals[KEY_VARIABLES][key] += TypeWeight.KnownType

        if (
            key in state.locals[KEY_TYPE_ANNOTATION] and
            name != state.locals[KEY_TYPE_ANNOTATION][key]
        ):
            if name in {"alloc_fd", }: # tentative names
                return

            raise RuntimeError(
                "conflicting types: %s and %s" % (
                    name,
                    state.locals[KEY_TYPE_ANNOTATION][key]
                )
            )
        state.locals[KEY_TYPE_ANNOTATION][key] = name

    @staticmethod
    def register_annotation(target: TargetOS, handler: typing.Type["BaseAnnotation"]) -> None:
        ALL_ANNOTATIONS[target].append(handler)


class InferenceRule:
    TARGETS = []

    def __init__(self, target: TargetOS) -> None:
        self.target = target

    def optimize(self, syscall: Syscall) -> None:
        """Optimize the syscall specification"""
        pass

    @staticmethod
    def register_inference_rule(target: TargetOS, rule: typing.Type["InferenceRule"]):
        ALL_INFERENCE_RULES[target].append(rule)


ALL_ANNOTATIONS: Dict[TargetOS,
                      List[typing.Type[BaseAnnotation]]] = defaultdict(list)
ALL_INFERENCE_RULES: Dict[TargetOS, List[typing.Type[InferenceRule]]] = defaultdict(list)

# import all classes under the current directory
path = os.path.dirname(os.path.abspath(__file__))
skip_procs = ['__init__']
for proc_file_name in os.listdir(path):
    if not proc_file_name.endswith('.py'):
        continue
    proc_module_name = proc_file_name[:-3]
    if proc_module_name in skip_procs:
        continue

    try:
        proc_module = importlib.import_module(
            f".{proc_module_name}",
            'syzgen.analysis.plugins.recovery',
        )
    except ImportError:
        logger.warning("Unable to import procedure %s", proc_module_name)
        continue

    for attr_name in dir(proc_module):
        attr = getattr(proc_module, attr_name)
        if isinstance(attr, type):
            if (
                issubclass(attr, BaseAnnotation) and
                attr_name != "BaseAnnotation"
            ):
                for t in attr.TARGETS:
                    BaseAnnotation.register_annotation(t, attr)
            elif (
                issubclass(attr, InferenceRule) and
                attr_name != "InferenceRule"
            ):
                for t in attr.TARGETS:
                    InferenceRule.register_inference_rule(t, attr)


def reserve_fields_from_input(executor, state, constrains):
    """reserve the fields we already identify"""
    if isinstance(executor, InputRecoveryPlugin):
        for each in constrains:
            executor._extract_variables(state, each, weight=TypeWeight.Input)

def reserve_field_from_input(executor, state, expr):
    if isinstance(executor, InputRecoveryPlugin):
        executor._extract_variables(state, expr, weight=TypeWeight.Input)


def reserve_type_from_input(executor, state: SimState, expr: Base, name: str, size: int) -> None:
    if isinstance(executor, InputRecoveryPlugin):
        inst = BaseAnnotation(state.project.arch)
        inst.extract_type(executor, state, expr, name, size)

# def reserve_ptr_from_input(executor, state: SimState, expr: Base):
#     if isinstance(executor, InputRecoveryPlugin):
#         executor._extract_ptr(state, expr)
