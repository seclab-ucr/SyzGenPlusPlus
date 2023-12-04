
from collections import defaultdict
from typing import List, Set, Tuple
from syzgen.analysis.plugins.recovery import InferenceRule
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import ALL_KNOWN_TYPES, Buffer, BufferType, ConstType, Context, KnownType, StructType, Type
from syzgen.target import TargetOS


class AutoInference(InferenceRule):
    TARGETS = [e for e in TargetOS]

    def __init__(self, target: TargetOS) -> None:
        super().__init__(target)

        name = target.name.lower()
        self.all_known_types = ALL_KNOWN_TYPES[name] if name in ALL_KNOWN_TYPES else {}

    def get_known_types(self, fields: List[Type]):
        ret = set()
        for field in fields:
            if isinstance(field, KnownType):
                ret.add(field.name)
            elif isinstance(field, ConstType):
                ret.add(field.getData())
        return ret

    def _match(self, target: StructType, fields: List[Type], key_fields: Set[str]) -> Tuple[bool, int]:
        keys = self.get_known_types(fields)
        if key_fields - keys:
            return False, 0

        fields = list(fields)
        l, r, score = 0, 0, 0
        while l < len(target.fields) and r < len(fields):
            ltype, rtype = target.fields[l], fields[r]
            if isinstance(ltype, KnownType):
                if not isinstance(rtype, KnownType) or ltype.name != rtype.name:
                    return False, 0
                score += 1
            elif isinstance(ltype, ConstType):
                if not isinstance(rtype, ConstType) or ltype.getData() != rtype.getData():
                    return False, 0
                score += 1
            elif ltype.size != rtype.size:
                if ltype.size < rtype.size:
                    # split rtype
                    fields[r] = Buffer(ltype.size, None)
                    fields.insert(r+1, Buffer(rtype.size - ltype.size, None))
                else:
                    fields[r] = Buffer(rtype.size+fields[r+1].size, None)
                    del fields[r+1]
                continue

            l += 1
            r += 1

        return l == len(target.fields), score

    def match(self, target: StructType, syscall: Syscall) -> Tuple[bool, int, int]:
        key_fields = self.get_known_types(target.fields)

        def visit(ctx: Context, typ: Type):
            if isinstance(typ, StructType):
                if target.size > typ.size:
                    return

                fields: List[Type] = []
                size = 0
                for field in typ.fields:
                    fields.append(field)
                    size += field.size

                    while size >= target.size:
                        succeed, score = self._match(target, fields, key_fields)
                        if succeed:
                            ctx.ret = (score, fields[0].offset)
                            return True
                        size -= fields[0].size
                        fields = fields[1:]

        ctx = Context()
        syscall.visit(ctx, visit)
        if ctx.ret:
            score, offset = ctx.ret
            return True, score, offset
        return False, 0, 0

    def _optimize(self, name: str, offset: int, target: StructType, syscall: Syscall) -> bool:
        t = KnownType({"name": name, "size": target.size})
        key_fields = self.get_known_types(target.fields)

        def refine(_, typ: Type):
            if isinstance(typ, StructType):
                if typ.size < target.size:
                    return typ

                for i, field in enumerate(typ.fields):
                    if field.offset == offset:
                        fields = [field]
                        j, size = i+1, field.size
                        while j < len(typ.fields):
                            if size >= target.size:
                                break
                            fields.append(typ.fields[j])
                            size += typ.fields[j].size
                            j += 1
                        if size < target.size:
                            break
                        succeed, _ = self._match(target, fields, key_fields)
                        if succeed:
                            t.offset = offset
                            typ.fields = typ.fields[:i] + [t] + typ.fields[j:]
                            rest = size - target.size
                            if rest:
                                typ.fields.insert(i+1, BufferType({"size": rest}, offset=offset+t.size))

                        break
            return typ

        syscall.refine_type(Context(), refine)

    def optimize(self, syscall: Syscall) -> None:
        cur = self.all_known_types
        nxt = defaultdict(list)
        while cur:
            target, target_name, target_offset, max_score = None, None, 0, 0
            for name, structs in cur.items():
                for typ in structs:
                    succeed, _score, _offset = self.match(typ, syscall)
                    if succeed:
                        nxt[name].append(typ)
                        if _score > max_score:
                            max_score = _score
                            target, target_name, target_offset = typ, name, _offset

            if not target:
                return

            self._optimize(target_name, target_offset, target, syscall)

            cur = nxt
            nxt = defaultdict(list)
