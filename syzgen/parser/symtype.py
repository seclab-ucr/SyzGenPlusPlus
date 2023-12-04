
from ctypes import Union
import json
import logging
import math

from functools import reduce
import re
from typing import List, Tuple
from archinfo import Endness

from claripy.ast.base import Base
from claripy.ast.bv import Reverse, Extract
from syzgen.executor import KEY_TYPE_ANNOTATION, KEY_VARIABLES
from syzgen.parser.types import PtrDir, int2bytes

logger = logging.getLogger(__name__)


class SymType(object):
    """
    Re-construct structure given the final state and the top-level symbol.
    """

    ENDNESS = Endness.BE

    def __init__(self, symbol, fuzzy=False, structOnly=False):  # size in bits
        self.symbol: Union[str, Base] = symbol
        # FIXME: remote it
        # We didn't reach the final state, hence some info is not accurate.
        self.fuzzy = fuzzy
        self.fields = None
        self.dir = 0
        self.structOnly = structOnly

    def get_symbolic_variable(self, state, *key):
        v = list(state.solver.get_variables(*key))
        if len(v) > 0:
            return v[0][1]
        return None

    def get_ranges(self, state) -> List[Tuple[int, int, int]]:
        ret = []
        for (name, left, right), count in state.locals[KEY_VARIABLES].items():
            if right == left:
                continue
            if name == self.symbol.args[0]:
                ret.append((left, right, count))
        logger.debug("variables: %s", ret)

        # 1. Prefer fields that were accessed more frequently
        # 2. Prefer field with smaller size because it is easier to associate it with constraints.
        ranges = sorted(ret, reverse=True)
        non_overlapped = []
        for l, r, c in ranges:
            # print("[2]: ", l, r, c, non_overlapped)
            for i in range(len(non_overlapped)-1, -1, -1):
                l2, r2, c2 = non_overlapped[i]
                if l2 >= l and r2 <= r:
                    # it contains the current
                    if c2 > c:
                        break
                    # split it
                    new_ranges = []
                    if l2 > l:
                        new_ranges.append((l2, l+1, c2))
                    new_ranges.append((l, r, c))
                    if r2 < r:
                        new_ranges.append((r-1, r2, c2))
                    del non_overlapped[i]
                    for j, field in enumerate(new_ranges):
                        non_overlapped.insert(i+j, field)
                    break
                elif l >= l2 and r <= r2:
                    # current contains it
                    if c >= c2:
                        del non_overlapped[i]
                        continue
                    if r2 > r:
                        non_overlapped.insert(i+1, (r2-1, r, c))
                    r = l2 + 1
                    if l < r:
                        break
                elif l2 >= r and l >= r2:
                    # overlapped
                    if l2 >= l:
                        if c2 >= c:
                            non_overlapped.insert(i+1, (r2-1, r, c))
                        else:
                            non_overlapped[i] = (l2, l+1, c2)
                            non_overlapped.insert(i+1, (l, r, c))
                        break
                    else:
                        if c2 >= c:
                            r = l2 + 1
                        else:
                            non_overlapped[i] = (r-1, r2, c2)
            else:
                # insert
                for i in range(len(non_overlapped)-1, -1, -1):
                    if non_overlapped[i][0] > l:
                        non_overlapped.insert(i+1, (l, r, c))
                        break
                else:
                    non_overlapped.append((l, r, c))

        # print("[1]: ", non_overlapped)
        # merge bits into bytes
        res = []
        bits, cur_l, cur_r, cur_c = 0, 0, 0, 0
        for (l, r, c) in non_overlapped:
            bits += l - r + 1
            cur_l = max(cur_l, l)
            cur_r = r
            cur_c = max(cur_c, c)
            if bits % 8 == 0:
                if cur_r % 8:
                    raise NotImplementedError("unaligned bits")
                res.append((cur_l, cur_r, cur_c))
                bits = cur_l = cur_r = cur_c = 0
        if cur_l:
            # expand bits to byte
            cur_l = (cur_l+8)//8*8-1
            cur_r = cur_r//8*8
            res.append((cur_l, cur_r, cur_c))
        non_overlapped = res

        for i in range(len(non_overlapped)-1, -1, -1):
            l, r, c = non_overlapped[i]
            if r % 8 or (l+1) % 8:
                raise NotImplementedError(
                    "do not support bit level separation")
            size = (l - r + 1) // 8
            if size in {1, 2, 4, 8}:
                continue
            # uncanonical types: split them based on address alignment
            offset = (self.symbol.length - l - 1) // 8
            if size == 3 or size == 5:
                non_overlapped[i] = (l, l-7 if offset % 2 else l-size*8+9, c)
                non_overlapped.insert(
                    i+1, (l-8 if offset % 2 else l-size*8+8, r, c))
            # elif size < 8:
            #     raise NotImplementedError("uncanonical size %d" % size)

        logger.debug("refined variables: %s", non_overlapped)
        return non_overlapped

    def initialize(self, state, solver_state):
        if isinstance(self.symbol, str):
            # FIXME: default direction for pointer
            self.fields = [{"type": "ptr", "size": 8}]
        else:
            read_boundaries = state.globals["read_boundary"]
            write_boundaries = state.globals["write_boundary"]
            right = self.symbol.length
            if self.symbol.args[0] in read_boundaries:
                right = min(right, read_boundaries[self.symbol.args[0]])
                self.dir |= PtrDir.DirIn
            if self.symbol.args[0] in write_boundaries:
                right = min(right, write_boundaries[self.symbol.args[0]])
                self.dir |= PtrDir.DirOut
            if right == self.symbol.length:
                # no boundary found, make it a const (no mutation allowed)
                self.fields = [{
                    "type": "const",
                    "left": 31,
                    "right": 0,
                    "access": True,
                    "data": int2bytes(0, 4),
                    "size": 4,
                }]
            else:
                self.fields = [{
                    "type": "buffer",
                    "left": self.symbol.length-1,
                    "right": right,
                }]  # big-endian

        if self.fields[0]["type"] == "const":
            pass
        elif isinstance(self.symbol, str):
            ptr_sym = self.get_symbolic_variable(state, self.symbol)
            if ptr_sym is not None:
                self.fields[0]["ref"] = SymType(ptr_sym, fuzzy=self.fuzzy, structOnly=self.structOnly)
                self.fields[0]["ref"].initialize(state, solver_state)
                self.fields[0]["dir"] = self.fields[0]["ref"].dir or PtrDir.DirIn
            else:
                raise Exception(f"unknown variable {self.symbol}")
        else:
            ranges = self.get_ranges(state)
            for left, right, _ in ranges:
                self.refine(left, right)

            self.evaluate(state, solver_state)

        # for field in self.fields:
        #     if field["type"] == "ptr":
        #         self.dir |= field["dir"]

    def refine(self, left, right):
        """Split existing field if we find its subfield has been accessed,
        and merge consecutive fields if they are assessed as a whole.
        Note: left boundary is larger than the right.
        """
        for index, each in enumerate(self.fields):
            if each["left"] >= left and each["right"] <= right:
                # if "access" in each and each["access"]:
                #     continue

                new_fields = []
                if each["left"] > left:
                    new_fields.append({
                        "type": "buffer",
                        "left": each["left"],
                        "right": left+1,
                    })
                new_fields.append({
                    "type": "buffer",
                    "left": left,
                    "right": right,
                    "access": True
                })
                if each["right"] < right:
                    new_fields.append({
                        "type": "buffer",
                        "left": right-1,
                        "right": each["right"]
                    })
                del self.fields[index]
                for i, field in enumerate(new_fields):
                    self.fields.insert(index+i, field)
                break
            elif each["left"] >= right and left >= each["right"]:
                # overlapping
                if "access" in each and each["access"]:
                    continue
                new_fields = []
                if each["left"] >= left:
                    if each["left"] > left:
                        new_fields.append({
                            "type": "buffer",
                            "left": each["left"],
                            "right": left+1
                        })
                    new_fields.append({
                        "type": "buffer",
                        "left": left,
                        "right": each["right"],
                        "access": True
                    })
                else:
                    new_fields.append({
                        "type": "buffer",
                        "left": each["left"],
                        "right": max(right, each["right"]),
                        "access": True
                    })
                    if each["right"] < right:
                        new_fields.append({
                            "type": "buffer",
                            "left": right-1,
                            "right": each["right"]
                        })
                del self.fields[index]
                for i in range(len(new_fields)):
                    self.fields.insert(index+i, new_fields[i])
                break

        new_field = {"type": "buffer", "left": 0,
                     "right": float('inf'), "access": True}
        indices = []
        for index, each in enumerate(self.fields):
            # find all interval covered by (left, right)
            if each["left"] <= left and each["right"] >= right:
                new_field["left"] = max(each["left"], new_field["left"])
                new_field["right"] = min(each["right"], new_field["right"])
                indices.append(index)

        if new_field["left"] != left or new_field["right"] != right:
            # from IPython import embed; embed()
            logger.warning("one access overlaps multiple fields")
        if len(indices) > 1:
            for index in reversed(indices):
                del self.fields[index]
            self.fields.insert(indices[0], new_field)

    def evaluate(self, state, solver_state):
        # We may find out new dependence through type inference
        sym_name = self.symbol.args[0]
        type_annotations = state.locals.get(KEY_TYPE_ANNOTATION, {})
        lens = state.locals.get("lens", {})

        for i, field in enumerate(self.fields):
            size = (field["left"] - field["right"] + 1) // 8
            field["size"] = size

            if "access" not in field:
                if self.fuzzy:
                    # We may miss some field because we didn't execute all the way through.
                    field["access"] = True
                continue

            logger.debug("%s, %s, %s", sym_name, field["left"], field["right"])
            k = (sym_name, field["left"], field["right"])
            if k in type_annotations:
                logger.debug("find a %s", type_annotations[k])
                if type_annotations[k] == "string":
                    field["type"] = "string"
                    # test if it is a constant string
                    string_value = ""
                    for i in range(size):
                        c = Extract(
                            field["left"]-8*i,
                            field["left"]-8*i-8+1,
                            self.symbol
                        )
                        vals = state.solver.eval_upto(c, 2)
                        if len(vals) == 1:
                            string_value += chr(vals[0])
                            if vals[0] == 0:
                                break
                        else:
                            break
                    if len(string_value) >= 4:
                        field["values"] = [string_value]
                elif (
                    re.match(r".+_connection_[\d]+$", type_annotations[k]) or
                    type_annotations[k] in {"alloc_fd"}
                ):
                    field["type"] = "resource"
                    field["name"] = type_annotations[k]
                else:
                    field["type"] = "known"
                    field["name"] = type_annotations[k]

            sym = Extract(field["left"], field["right"], self.symbol)
            sym_LE = Reverse(sym) if self.ENDNESS == Endness.BE else sym
            logger.debug("sym_LE: %s", sym_LE)
            if size in {4, 8} and field["type"] == "buffer":  # it could be a pointer
                # TODO: use type annotation instead of evalution
                concrete = state.solver.eval(sym_LE)
                logger.debug("evaluate %s, %s", sym, concrete)
                ptr_sym = self.get_symbolic_variable(state, "inp", concrete)
                # print(concrete, ptr_sym)
                if ptr_sym is not None:
                    field["type"] = "ptr"
                    field["ref"] = SymType(ptr_sym, fuzzy=self.fuzzy, structOnly=self.structOnly)
                    field["ref"].initialize(state, solver_state)
                    field["dir"] = field["ref"].dir or PtrDir.DirIn

            if (
                not self.structOnly and
                field["type"] not in ["ptr", "resource", "known"] and
                size in {1, 2, 4, 8} and not self.fuzzy and i < 64
            ):
                try:
                    field["min"] = solver_state.solver.min(sym_LE)
                    field["max"] = solver_state.solver.max(sym_LE)
                except:
                    logger.error("failed to eval min")
                    field["min"] = solver_state.solver.min(sym_LE)
                    field["max"] = solver_state.solver.max(sym_LE)

                if field["min"] == field["max"]:
                    # detect constant
                    field["type"] = "const"
                elif field["min"] != 0 or field["max"] != ((1 << size*8)-1):
                    # Flag or Range value
                    # Check if it is range: use simple heuristics
                    # FIXME: 1. XXXX00 the LSB is zero and XXXX is not zero.
                    res1 = solver_state.solver.satisfiable(extra_constraints=(
                        sym_LE == field["min"]+1,
                    ))
                    res2 = solver_state.solver.satisfiable(extra_constraints=(
                        sym_LE == field["max"]-1,
                    ))
                    if res1 and res2:
                        field["type"] = "range"
                        field["stride"] = 1
                        # TODO: check range with stride
                    else:
                        # Binary search to find out maximum number of possible values
                        num = 4
                        while num < 256:
                            solutions = solver_state.solver.eval_upto(
                                sym_LE, num)
                            if len(solutions) < num:
                                break
                            num = num*2
                        if num == 256:
                            # Too many possible values
                            logger.debug("%s, %s", sym, field)
                            logger.debug("%s", solutions)
                            logger.warning("Too many possible values")
                            field["type"] = "range"
                            field["stride"] = reduce(math.gcd, solutions) or 1
                        else:
                            field["type"] = "flag"
                            field["values"] = solutions

            # FIXME: refactor this
            for key, val in lens.items():
                if key[0] != sym_name:
                    continue
                if field["left"] >= key[1] and field["right"] <= key[2]:
                    logger.debug("find a length %s, %s", key, val)
                    if "attrs" not in field:
                        field["attrs"] = {}
                    field["attrs"]["len"] = val
                    break

            field["data"] = int2bytes(solver_state.solver.eval(sym_LE), size)

    def refineLen(self, path, ptrs={}):
        if not isinstance(self.symbol, str):
            ptrs[self.symbol.args[0]] = {
                "path": list(path),
                "length": self.symbol.length
            }

        # FIXME: the order is critical.
        offset = 0
        for field in self.fields:
            path.append(offset)
            if field["type"] == "ptr":
                field["ref"].refineLen(list(path), ptrs)
            offset += field["size"]
            path.pop()

        for field in self.fields:
            if "attrs" in field and "len" in field["attrs"]:
                sym, l, _, scale = field["attrs"]["len"]
                if sym not in ptrs:
                    raise Exception("Can not find %s" % sym)
                offset = (ptrs[sym]["length"]-l-1) // 8
                field["path"] = list(ptrs[sym]["path"]) + [offset]
                field["bitSize"] = scale*8

    def toJson(self):
        struct = []
        offset = 0
        fields = self.fields if self.ENDNESS is Endness.BE else reversed(self.fields)
        for field in fields:
            new_field = dict(field)
            new_field["offset"] = offset

            if "access" not in field:
                new_field["access"] = False  # default

            if field["type"] == "ptr":
                new_field["ref"] = field["ref"].toJson()
                new_field["size"] = 8
            elif field["type"] in {"buffer", "resource", "const", "range", "flag", "string", "known"}:
                new_field["size"] = (field["left"] - field["right"] + 1) // 8
                if "data" not in field:
                    new_field["data"] = [0xff] * \
                        new_field["size"]  # dummy data
            else:
                raise Exception("unknown type: %s" % field["type"])
            offset += new_field["size"]
            struct.append(new_field)

        if len(struct) == 1:
            return struct[0]
        return {"type": "struct", "fields": struct, "offset": 0, "size": offset}

    def repr(self):
        ret = {
            "fields": []
        }
        for field in self.fields:
            each = dict()
            for k, v in field.items():
                if k == "ref":
                    each["ref"] = v.repr()
                elif k != "attrs":
                    each[k] = v
            ret["fields"].append(each)
        return json.dumps(ret)
        # return json.dumps(self.toJson())


class SymScalarType(SymType):
    ENDNESS = Endness.LE

    def initialize(self, state, solver_state):
        self.fields = [{
            "type": "buffer",
            "left": self.symbol.length-1,
            "right": 0,
            "access": True,  # FIXME?
        }]  # big-endian

        # the entire input should be accessed, add a dummy one for padding
        k = (self.symbol.args[0], self.symbol.length-1, 0)
        if k not in state.locals[KEY_VARIABLES]:
            state.locals[KEY_VARIABLES][k] = 0
        ranges = self.get_ranges(state)
        for left, right, _ in ranges:
            self.refine(left, right)
        self.evaluate(state, solver_state)
