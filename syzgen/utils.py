
import bisect
import errno
import random
import socket
import subprocess
import os
import re
import logging
import pickle
import tempfile
import angr
from typing import Dict, Iterable, List, Set, Tuple, Union

from claripy.ast.base import Base
from claripy.ast.bv import Extract, Reverse
from collections import defaultdict

logger = logging.getLogger(__name__)
# sys.setrecursionlimit(3000)  # for extractFields

TMP_PATTERN = re.compile(r"^tmp_([\da-f]+)_")


def any2int(num):
    if isinstance(num, str):
        if num.startswith("0x"):
            return int(num, 16)
    elif isinstance(num, list):
        return int.from_bytes(num, "little")
    elif isinstance(num, bytes):
        return int.from_bytes(num, "little")
    return num


def catch_error(func):
    def inner(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            from IPython import embed
            embed()
            raise e
    return inner


def dumps(path, obj):
    with open(path, "wb") as fp:
        pickle.dump(obj, fp)


def loads(path, default=None):
    if not os.path.exists(path):
        return default

    with open(path, "rb") as fp:
        return pickle.load(fp)


def demangle(name):
    # https://github.com/nico/demumble
    output = subprocess.run(
        ["./libs/demumble", name],
        check=True,
        cwd=os.getcwd(),
        stdout=subprocess.PIPE
    ).stdout
    return output.decode().strip()


def addEntitlement(filepath):
    # Give entitlement
    cmds = ["sh", "./autosign.sh", os.path.abspath(filepath)]
    logger.debug("%s", " ".join(cmds))
    subprocess.run(cmds, check=True, cwd=os.path.join(os.getcwd(), "libs"))


def extractFields(expr: Base,
                  data: Set[Tuple[Union[Base, str], int, int]],
                  depth: int = 0,
                  keep_sym: bool = False,
                  excludes: Iterable[str] = [],
                  includes: Iterable[str] = [],
                  reverse: bool = False,
                  ):
    """Extract all fields in the expression. Note one expression may contain
    multiple disjoint or joint fields. Consecutive fields are separate if they
    are not accessed in the same operation (e.g., concat)."""
    if depth > 16:
        return

    if expr.op == 'Extract' and expr.args[2].op == 'BVS':
        names = expr.args[2].args[0].split('_', 1)
        if names[0] in excludes:
            return
        if includes and names[0] not in includes:
            return
        # Note the endian
        data.add((
            expr.args[-1] if keep_sym else expr.args[-1].args[0],
            expr.args[0],
            expr.args[1]
        ))
        return

    if expr.op == "Concat" and not reverse:
        # Reverse the list to simplify it. If it is only simpified, this
        # operation has no effect.
        new_args = list(reversed(expr.args))
        new_expr = expr.make_like(expr.op, new_args, simplify=True)
        extractFields(new_expr, data, depth+1, keep_sym=keep_sym,
                      excludes=excludes, includes=includes, reverse=True)
        return

    if expr.op == 'BVS':
        names = expr.args[0].split('_', 1)
        if names[0] in excludes:
            return
        if includes and names[0] not in includes:
            return
        data.add((
            expr if keep_sym else expr.args[0],
            expr.length-1, 0
        ))
        return

    args = expr.args[1:] if expr.op == 'If' else expr.args
    for each in args:
        if isinstance(each, Base):
            extractFields(each, data, depth+1, keep_sym=keep_sym,
                          excludes=excludes, includes=includes)


def extractField(expr):
    # e.g., Reverse(structInput_2_928[479:416])
    if expr.op == 'Extract' and expr.args[2].op == 'BVS':
        return expr.args[2].args[0], expr.args[0], expr.args[1]
    if expr.op == 'Reverse':
        return extractField(expr.args[0])
    if expr.op == 'BVS':
        return expr.args[0], expr.length-1, 0
    return None, 0, 0


def extractVariablesWithField(expr, excludes=[]):
    candidates = set()
    if isinstance(expr, list):
        for each in expr:
            extractFields(each, candidates, keep_sym=True, excludes=excludes)
    else:
        extractFields(expr, candidates, keep_sym=True)

    cmds = []
    for sym, left, right in candidates:
        cmds.append(Extract(left, right, sym))
    return cmds


def extractName(name):
    if type(name) is bytes:
        name = name.decode()
    m = re.search(r'(.+)_[\d]+_[\d]', name)
    if m:
        return m.group(1)
    return None


def extractSymbols(expr, excludes=[], includes=[], maxDepth=16, merge=False) -> Dict[Base, List[Tuple[int, int]]]:
    """Extract all accessed symbols in the expression regardless how they are used.
    Disjoint fields would be merged if indicated."""
    symbols = defaultdict(list)
    _extractSymbols(expr, symbols, excludes=excludes,
                    includes=includes, maxDepth=maxDepth, merge=merge)
    return symbols


def _extractSymbols(expr, data, excludes=[], includes=[], maxDepth=16, merge=False):
    if maxDepth < 0:
        return
    if expr.op == 'Extract' and expr.args[-1].op == 'BVS':
        names = expr.args[2].args[0].split('_', 1)
        if names[0] in excludes:
            return
        if includes and names[0] not in includes:
            return

        # Note the endian
        if merge:
            data[expr.args[-1]] = [[
                max(expr.args[0], expr.args[0], *
                    [r for r, _ in data[expr.args[-1]]]),
                min(expr.args[1], expr.args[1], *
                    [l for _, l in data[expr.args[-1]]]),
            ]]
        elif expr.args[-1] not in data:
            data[expr.args[-1]].append([expr.args[0], expr.args[1]])
        else:
            res = []
            for i, ele in enumerate(data[expr.args[-1]]):
                if ele[1] > expr.args[0] + 1:
                    res.append(ele)
                elif ele[0] + 1 < expr.args[1]:
                    res.append([expr.args[0], expr.args[1]])
                    res.extend(data[expr.args[-1]][i:])
                    break
                else:
                    merged = [max(ele[0], expr.args[0]),
                              min(ele[1], expr.args[1])]
                    for j in range(i+1, len(data[expr.args[-1]])):
                        r, l = data[expr.args[-1]][j]
                        if r + 1 < merged[1]:
                            res.append(merged)
                            res.extend(data[expr.args[-1]][j:])
                            break
                        merged = [max(merged[0], r), min(merged[1], l)]
                    else:
                        res.append(merged)
                    break

            data[expr.args[-1]] = res
        return

    if expr.op == 'BVS':
        names = expr.args[0].split('_', 1)
        if names[0] in excludes:
            return
        if includes and names[0] not in includes:
            return
        data[expr] = []
        data[expr].append([expr.length-1, 0])
        return

    args = expr.args[1:] if expr.op == 'If' else expr.args
    for each in args:
        if isinstance(each, Base):
            _extractSymbols(each, data, excludes=excludes,
                            includes=includes, maxDepth=maxDepth-1, merge=merge)


def extractSymbol(expr, merge=False, excludes=[], includes=[]):
    symbols = extractSymbols(expr, merge=merge, excludes=excludes, includes=includes)
    if len(symbols) > 1:
        return None, 0, 0
    for sym, arr in symbols.items():
        if len(arr) > 1:
            return None, 0, 0
        for l, r in arr:
            return sym, l, r
    return None, 0, 0


def extractVariables(expr, excludes: Union[List, Set] = [], includes: Union[List, Set] = [], merge=False):
    symbols = defaultdict(list)
    if isinstance(expr, list):
        for each in expr:
            _extractSymbols(each, symbols, excludes=excludes,
                            includes=includes, merge=merge)
    else:
        _extractSymbols(expr, symbols, excludes=excludes,
                        includes=includes, merge=merge)

    cmds = []
    for sym, arr in symbols.items():
        for left, right in arr:
            cmds.append(Extract(left, right, sym))
    return cmds


def extractBaseOffset(state, expr):
    if expr.op != '__add__':
        return None, None

    # It must be in the form of base + index * constant
    # base + (rax+rax<<1)<<8

    if expr.args[0].op == 'BVV':
        return state.solver.eval(expr.args[0]), expr.args[1]
    elif expr.args[1].op == 'BVV':
        return state.solver.eval(expr.args[1]), expr.args[0]
    else:
        return None, None


def extractBase(state, expr, addr=0):
    if addr == 0:
        addr = state.solver.eval(expr)
    candidates = extractVariablesWithField(expr)
    for candidate in candidates:
        if candidate.length != 64:
            # Cannot be a pointer
            continue
        concrete_addr = state.solver.eval(Reverse(candidate))
        if abs(addr - concrete_addr) < 4096:
            return concrete_addr
    return 0


def contain_inputs(expr: Base, inputs: Set[str], max_depth: int=16) -> bool:
    if max_depth < 0:
        return False

    if isinstance(expr, int):
        return False

    if expr.op == 'BVS':
        names = expr.args[0].split('_', 1)
        return names[0] in inputs

    for arg in expr.args:
        if isinstance(arg, Base):
            if contain_inputs(arg, inputs, max_depth=max_depth-1):
                return True

    return False


DUMMY_PROJECT = None
def get_blank_state() -> angr.SimState:
    global DUMMY_PROJECT
    if DUMMY_PROJECT is None:
        DUMMY_PROJECT = angr.Project(
            "libs/hello",
            auto_load_libs=False,
            main_opts={'base_addr': 0x400000}
        )
    return DUMMY_PROJECT.factory.blank_state()


def random_port():
    return random.randrange((64 << 10)-(1 << 10)) + (1 << 10)


def UnusedTcpPort():
    while True:
        port = random_port()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            logger.debug("test port %d", port)
            s.bind(("localhost", port))
            s.close()
            return port
        except socket.error as e:
            if e.errno != errno.EADDRINUSE:
                raise e

def UnusedTempFileName(suffix: str):
    fd, filename = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return filename


class OrderedKeyDict:
    def __init__(self) -> None:
        self._keys: List = []
        self._dict = {}

    def __contains__(self, k):
        return k in self._dict

    def __getitem__(self, k):
        return self._dict[k]

    def items(self):
        return self._dict.items()

    def add(self, key, val) -> None:
        if key in self:
            return

        self._dict[key] = val
        # FIXME: it is still O(n) time complexity.
        bisect.insort(self._keys, key)

    def floor(self, key):
        idx = bisect.bisect_right(self._keys, key)
        if idx > 0:
            return self._keys[idx-1]
        return None
