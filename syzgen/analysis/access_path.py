
import logging
import re

from typing import Dict, List, Optional, Tuple, Union
from claripy.ast.bv import Reverse, BV, ZeroExt, SignExt
from claripy.ast.base import Base
from syzgen.config import Options

from syzgen.utils import catch_error, contain_inputs, extractVariables
from syzgen.models import BASE_HEAP_LOCATION, FindObjectException, HeapAllocator, isAllocObject, isHeapObject

logger = logging.getLogger(__name__)
options = Options()

AP_REGEX = re.compile(r"^<(?P<op>\w+) (?P<args>.+)>$")

# https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function#:~:text=Fowler%E2%80%93Noll%E2%80%93Vo%20is%20a,and%20Phong%20Vo%20in%201991.
def fnv64(data):
    hash_ = 0xcbf29ce484222325
    for b in data:
        hash_ *= 0x100000001b3
        hash_ &= 0xffffffffffffffff
        hash_ ^= ord(b)
    return hash_


class AccessNode:
    OPPOSITE = {
        "__eq__": "__ne__",
        "__ne__": "__eq__",
        "__lt__": "__ge__",
        "__ge__": "__lt__",
        "__le__": "__gt__",
        "__gt__": "__le__",
    }
    OPS = {
        "ZeroExt": ZeroExt,
        "SignExt": SignExt,
    }

    def __init__(self, op, args):
        self.op = op
        self.args: List[Union["AccessNode", int, str]] = args
        self._hash = fnv64(repr(self))
        self._has_input = None
        # If it is composed of symbolic input, we also need to have its concrete
        # value (usually its minimum value) to perform the comparision.
        # e.g., base + (offset + 4) << 3 + 8 == base + 40 + offset << 3
        # in which offset is derived from user input.
        # self.value: Optional[int] = None

    def hasInput(self, input_names: List[str] = []):
        if self._has_input is None:
            self._has_input = self._hasInput(input_names)
        return self._has_input

    def _hasInput(self, input_names):
        if self.op == "BVS":
            if not input_names:
                return True
            names = self.args[0].split("_", 1)
            if names[0] in input_names:
                return True
            return False
        if self.op == "BVV":
            return False
        if any(arg.hasInput(input_names) for arg in self.args):
            return True
        return False

    def match(self, other, depth=0):
        """
        Examples:
        <__eq__ <read <__add__ <read <__add__ <read <__add__ <BVS userClient>,
        <BVV 264>>>, <BVV 8>>>, <BVV 8>>>, <Reverse <Extract
        <BVS AppleUpstreamUserClient_connection_0>>>>
        <__ne__ <read <__add__ <read <__add__ <read <__add__ <BVS userClient>,
        <BVV 264>>>, <BVV 8>>>, <BVV 8>>>, <Reverse <Extract <BVS input_223_1024>>>>
        """
        if self.op != other.op:
            if depth != 0:
                return False
            if self.op not in AccessNode.OPPOSITE:
                return False
            if AccessNode.OPPOSITE[self.op] != other.op:
                return False

        if self.op == "BVS":
            # We assume there is only one variable, and thus we only have one pair.
            return True
        if self.op == "BVV":
            return self.args[0] == other.args[0]
        if self.op == "Extract":
            if self.args[2].op == "BVS":
                return self.args[2].match(other.args[2], depth+1)
            else:
                return self.args[0] == other.args[0] and self.args[1] == other.args[1] and \
                    self.args[2].match(other.args[2], depth+1)

        for i, arg in enumerate(self.args):
            if not arg.match(other.args[i], depth+1):
                return False
        return True

    def qualify(self):
        # At least we should have one read
        if self.op == "read":
            return True

        for arg in self.args:
            if isinstance(arg, AccessNode) and arg.qualify():
                return True
        return False

    @staticmethod
    def create(s) -> "AccessNode":
        def parse_args(args):
            ret = []
            counter = 0
            start = 0
            for i, c in enumerate(args):
                if c == '<':
                    counter += 1
                elif c == '>':
                    counter -= 1
                    if counter == 0:
                        ret.append(args[start:i+1])
                        start = i+2 # skip comma
            return ret

        m = AP_REGEX.match(s)
        if m:
            op = m.group("op")
            args = m.group("args")
            # print(op, args)
            if op == "BVV":
                args = args.split(",")
                return AccessNode(op, [
                    int(args[0]),
                    0 if len(args) == 1 else int(args[1])
                ])
            if op == "BVS":
                args = args.split(",")
                return AccessNode(op, [args[0], int(args[1])])

            args = parse_args(args)
            return AccessNode(op, [AccessNode.create(each.strip()) for each in args])

        raise RuntimeError()

    def get_source(self) -> Optional["AccessNode"]:
        if self.op == "read":
            return self
        for each in self.args:
            if isinstance(each, AccessNode):
                ret = each.get_source()
                if ret:
                    return ret
        return None

    def to_claripy(self, state) -> Union[int, Base]:
        if self.op == "BVV":
            if len(self.args) == 2 and self.args[1]:
                return state.solver.BVV(self.args[0], self.args[1])
            return self.args[0]
        if self.op == "BVS":
            return state.solver.BVS(self.args[0], size=self.args[1], key=tuple(self.args), eternal=True)
        if self.op == "read":
            return state.solver.BVV(BASE_HEAP_LOCATION + 0x1000, 64)
        func = getattr(BV, self.op) if self.op not in self.OPS else self.OPS[self.op]
        if self.op in {"__add__", "__or__"}:
            ret = func(self.args[0].to_claripy(state), self.args[1].to_claripy(state))
            for each in self.args[2:]:
                ret = func(ret, each.to_claripy(state))
        elif self.op == "Extract":
            ret = func(
                state.solver.eval(self.args[0].to_claripy(state)),
                state.solver.eval(self.args[1].to_claripy(state)),
                self.args[2].to_claripy(state),
            )
        else:
            args = [each.to_claripy(state) for each in self.args]
            # print(self.op, " || ".join(map(str, self.args)))
            ret = func(*args)
        # print(self.op, ret)
        return ret

    def __str__(self) -> str:
        return "<{} {}>".format(self.op, ", ".join(map(str, self.args)))

    def __repr__(self) -> str:
        if self.op == "BVV":
            return f"<{self.op} {self.args[0]}>"
        return "<{} {}>".format(self.op, ", ".join(map(repr, self.args)))

    def __hash__(self):
        return self._hash

    def __eq__(self, other):
        return self.op == other.op and self._hash == other._hash


COMPLEX_ACCESS_PATH = 1
NO_POINTER = 2
EXCEED_DEPTH = 3
NO_OBJECT = 4

@catch_error
def access_tree_write2(
    executor,
    state,
    expr,
    trace,
    input_names,
    objects: Dict[int, Tuple[int, Base]],
    cache=None,
    is_ptr=True
) -> Optional[AccessNode]:
    ret, error = _access_tree_write(
        executor,
        state, expr,
        trace, input_names,
        objects,
        cache=cache,
        is_ptr=is_ptr
    )
    if ret is None and error == 0:
        logger.error("failed to handle %s", expr)
        # raise RuntimeError()
    return ret


def _access_tree_write(
    executor,
    state,
    expr,
    trace,
    input_names,
    objects: Dict[int, Tuple[int, Base]],
    cache=None,
    is_ptr=True,
    max_depth=32,
) -> Tuple[Optional[AccessNode], int]:
    """get the access path to the accessed variables"""
    if cache and expr in cache:
        return cache[expr], 0

    if isinstance(expr, int):
        return AccessNode("BVV", [expr, 0]), 0

    if max_depth == 0:
        if is_ptr:
            return None, EXCEED_DEPTH
        return AccessNode("BVV", [state.solver.min(expr), expr.length]), 0

    ret, error = None, 0
    if expr.op == 'BVS':
        names = expr.args[0].split("_")
        if not is_ptr:
            if names[0] not in input_names:
                ret = AccessNode("BVV", [state.solver.min(expr), expr.length])
            else:
                # no need to go further cause we do not match this later if it
                # is not a pointer, but we need a symbolic variable to compute
                # the target address.
                ret = AccessNode("BVS", ["_".join(names[:2]), expr.length])
        elif names[0] in {'tmp', 'mem', 'inp'}:
            addr = int(names[1], 16)
            if addr in trace:
                _, parent_expr = trace[addr]
                ret, error = _access_tree_write(
                    executor,
                    state, parent_expr, trace, input_names, objects,
                    cache=cache,
                    is_ptr=is_ptr,
                    max_depth=max_depth-1,
                )
                if ret is not None:
                    ret = AccessNode("read", [ret])
        else:
            ret = AccessNode("BVS", [names[0], expr.length])
        # if ret is None:
        #     ret = AccessNode("BVS", [expr.args[0]])
    elif expr.op == 'BVV':
        val = expr.args[0]
        if expr.length == 64 and isHeapObject(val):
            try:
                allocator: HeapAllocator = options.heap_allocator
                base_addr, _ = allocator.get_object(val)
                if base_addr in objects:
                    parent_addr, parent_expr = objects[base_addr]
                    base, error = _access_tree_write(
                        executor,
                        state, parent_expr, trace, input_names, objects,
                        cache=cache,
                        is_ptr=is_ptr,
                        max_depth=max_depth-1,
                    )
                    if base is None:
                        return None, error
                    ret = AccessNode(
                        '__add__',
                        [
                            AccessNode("read", [base]),
                            AccessNode("BVV", [val - parent_addr, 0]),
                        ],
                    )
            except FindObjectException:
                return None, NO_OBJECT

        if ret is None:
            ret = AccessNode("BVV", [val, expr.length])
    elif expr.op == 'If':
        # FIXME: pick anyone?
        ret, error = _access_tree_write(
            executor,
            state, expr.args[1], trace, input_names, objects,
            cache=cache,
            is_ptr=is_ptr,
            max_depth=max_depth-1,
        )
    elif is_ptr:
        if expr.op == 'Extract':
            # Similar to add
            ret, error = _access_tree_write(
                executor,
                state, expr.args[2], trace, input_names, objects,
                cache=cache,
                is_ptr=True,
                max_depth=max_depth-1,
            )
            if ret and ret.op == 'read':
                offset = expr.args[2].length - expr.args[0] - 1
                if offset:
                    ret = AccessNode('read', [AccessNode('__add__', [
                        ret.args[0], AccessNode('BVV', [offset//8, 0])
                    ])])
                    logger.info("extract %s with offset %d", expr, offset)
                    # from IPython import embed; embed()
                    # ret = AccessNode('__add__', [
                    #     ret,
                    #     AccessNode("BVV", [offset//8, 0])
                    # ])
            # FIXME: non-pointer
            # else:
            #     # <BV32 (0x0 .. tmp_ffffff800ebc0138_93_32[23:20])[31:0]>
            #     # not all bits come from one memory object
            #     ret, error = _access_tree_write(state, expr.args[2], trace, input_names, cache=cache, is_ptr=True)
        elif expr.op == 'Concat':
            # <BV64 tmp_c000a100_25_32768[32647:32640] .. tmp_c000a100_25_32768[32655:32648] ..
            # tmp_c000a100_25_32768[32663:32656] .. tmp_c000a100_25_32768[32671:32664] ..
            # tmp_c000a100_25_32768[32679:32672] .. tmp_c000a100_25_32768[32687:32680] ..
            # tmp_c000a100_25_32768[32695:32688] .. tmp_c000a100_25_32768[32703:32698] ..
            # 0 .. tmp_c000a100_25_32768[32696:32696]>
            # [<BV57 tmp_c000a100_25_32768[32696:32640]>, <BV6 tmp_c000a100_25_32768[32703:32698]>]
            # Try fields without merging first
            candidates = extractVariables(expr) + extractVariables(expr, merge=True)
            for candidate in candidates:
                if candidate.length != 64:
                    continue
                base_addr = state.solver.eval(
                    candidate
                    if candidate.op == "BVS" else
                    Reverse(candidate)
                )  # 0xc000bcb2
                # base_addr = state.solver.eval(candidate)
                concrete_addr = state.solver.eval(expr)  # 0xc000bcb0
                offset = concrete_addr - base_addr
                ret, error = _access_tree_write(
                    executor,
                    state, candidate, trace, input_names, objects,
                    cache=cache,
                    is_ptr=True,
                    max_depth=max_depth-1,
                )
                if ret is None:
                    return None, error
                if offset:
                    ret = AccessNode(
                        '__add__', [ret, AccessNode('BVV', [offset, 0])])
                break
            if ret is None:
                # <BV64 0x0 .. tmp_ffffff8011062898_93_32[23:20]>
                # If it is not a pointer, it should be a value derived from a pointer.
                # <BV64 (mem_d0043ff8_1842_64{UNINITIALIZED}[63:2] .. 0) + 0x8>
                candidates = sorted(
                    extractVariables(expr, merge=True),
                    key=lambda x: x.length,
                    reverse=True
                )
                if candidates:
                    ret, error = _access_tree_write(
                        executor,
                        state, candidates[0], trace, input_names, objects,
                        cache=cache,
                        is_ptr=True,
                        max_depth=max_depth-1,
                    )
                else:
                    return None, NO_POINTER
        else:
            for i, each in enumerate(expr.args):
                val = state.solver.eval(each)
                if (
                    # heap/global address
                    executor.is_valid_pointer(val, state) or
                    # allocated by us
                    isAllocObject(val) or
                    # concretize <BV64 mem_d002c000_1119_64{UNINITIALIZED} +
                    # ((0#32 .. tmp_ffffffff84e15730_1118_32) << 0x3)> to 0xd002e000
                    # both mem_d002c000_1119_64 and tmp_ffffffff84e15730_1118_32 are
                    # unconstrained before.
                    (
                        isinstance(each, Base) and
                        each.op == "BVS" and
                        each.args[0].startswith("mem_")
                    )
                ):
                    base, error = _access_tree_write(
                        executor,
                        state, each, trace, input_names, objects,
                        cache=cache,
                        is_ptr=True,
                        max_depth=max_depth-1,
                    )
                    if base is None:
                        continue

                    if len(expr.args) == 1:
                        ret = base
                    elif all(
                        not contain_inputs(each, input_names)
                        for j, each in enumerate(expr.args) if i != j
                    ):
                        # Convert it to add formula if no inputs invovled
                        concrete_addr = state.solver.eval(expr)
                        offset = concrete_addr - val
                        ret = AccessNode(
                            '__add__', [base, AccessNode('BVV', [offset, 0])])
                    elif base.hasInput(input_names):
                        # Skip complex access paths like *(base + index) + index
                        ret, error = None, COMPLEX_ACCESS_PATH
                    else:
                        new_args = []
                        for j, arg in enumerate(expr.args):
                            if i == j:
                                # FIXME: should we reorder it
                                new_args.append(base)
                                continue
                            if not contain_inputs(arg, input_names):
                                v = state.solver.min(arg)
                                if v:
                                    new_args.append(AccessNode("BVV", [v, arg.length]))
                            else:
                                node, error = _access_tree_write(
                                    executor,
                                    state, arg, trace, input_names, objects,
                                    cache=cache,
                                    is_ptr=False,
                                    max_depth=max_depth-1,
                                )
                                if node is None:
                                    return None, error
                                new_args.append(node)

                        if len(new_args) == 1:
                            ret = new_args[0]
                        else:
                            ret = AccessNode(expr.op, new_args)

                    break
            else:
                # no pointer: <BV32 0#24 .. tmp_ffff8880454968a8_19739_8>
                # fall back to pick the first one
                for i, each in enumerate(expr.args):
                    if (
                        isinstance(each, Base) and
                        each.op == "BVS" and
                        each.args[0].startswith("tmp_")
                    ):
                        base, error = _access_tree_write(
                            executor,
                            state, each, trace, input_names, objects,
                            cache=cache,
                            is_ptr=True,
                            max_depth=max_depth-1,
                        )
                        if base is None:
                            continue

                        new_args = []
                        for j, arg in enumerate(expr.args):
                            if i == j:
                                new_args.append(base)
                                continue

                            v = state.solver.min(arg)
                            l = arg.length if isinstance(arg, Base) else 0
                            new_args.append(AccessNode("BVV", [v, l]))
                        ret = AccessNode(expr.op, new_args)
                        break
                else:
                    return None, NO_POINTER
    else:
        if not contain_inputs(expr, input_names):
            ret = AccessNode("BVV", [state.solver.min(expr), expr.length])
        else:
            new_args = []
            for each in expr.args:
                arg, error = _access_tree_write(
                    executor,
                    state, each, trace, input_names, objects,
                    cache=cache,
                    is_ptr=False,
                    max_depth=max_depth-1,
                )
                if arg is None:
                    return None, error
                new_args.append(arg)
            ret = AccessNode(expr.op, new_args)

    if cache:
        cache[expr] = ret
    return ret, error

# def extract(state, base):
#     alloc = state.globals.get("alloc", [])
#     var, sym_ptr = state.globals["trace"][base]  # var == 0xc0009cb0
#     if var is None:
#         # logger.debug("%#x, None, %s", base, sym_ptr)
#         # <BV64 Reverse(gs_b0019d00_10_64)>
#         # the second last number might be different
#         return access_repr(sym_ptr)
#     # logger.debug("%#x, %#x, %s", base, var, sym_ptr)

#     # <BV64 tmp_c000a100_25_32768[32647:32640] .. tmp_c000a100_25_32768[32655:32648] ..
#     # tmp_c000a100_25_32768[32663:32656] .. tmp_c000a100_25_32768[32671:32664] ..
#     # tmp_c000a100_25_32768[32679:32672] .. tmp_c000a100_25_32768[32687:32680] ..
#     # tmp_c000a100_25_32768[32695:32688] .. tmp_c000a100_25_32768[32703:32698] ..
#     # 0 .. tmp_c000a100_25_32768[32696:32696]>
#     # [<BV57 tmp_c000a100_25_32768[32696:32640]>, <BV6 tmp_c000a100_25_32768[32703:32698]>]
#     # Try fields without merging first
#     candidates = extractVariables(sym_ptr) + extractVariables(sym_ptr, merge=True)
#     # logger.debug("candidates %s", candidates)
#     for candidate in candidates:
#         if candidate.length != 64:
#             # Cannot be a pointer
#             continue
#         concrete_addr = state.solver.eval(Reverse(candidate))  # 0xc000bcb2
#         offset = concrete_addr - base
#         index = bisect.bisect_right(alloc, concrete_addr)
#         if index > 0 and alloc[index-1] == base:
#             off = (candidate.args[-1].length - candidate.args[0] - 1) // 8
#             # *(var + off) - offset
#             ret = f"*({extract(state, var)} + {off})" if off else f"*({extract(state, var)})"
#             if offset:
#                 return f"({ret} - {offset})"
#             else:
#                 return f"({ret})"

# @catch_error
# def access_tree_write(state, expr):
#     # FIXME: eval or min?
#     addr = state.solver.eval(expr)  # 0xc000bcd8
#     # For the case of containner_of, we don't have the base pointer.
#     # Try to get the base from the expression first, and then check the alloc array.
#     base = extractBase(state, expr, addr=addr) or addr
#     alloc = state.globals.get("alloc", [])
#     index = bisect.bisect_right(alloc, base)
#     if index == 0:
#         return None
#     base = alloc[index-1] # 0xc000bcb0
#     if base + 8192 <= addr:
#         return None
#     offset = addr - base  # 0x28
#     # return base + offset

#     res = f'{extract(state, base)} + {offset}' if offset else f"{extract(state, base)}"
#     if "None" in res:
#         return None
#     return res

