
from typing import Optional
from syzgen.parser.syscalls import Syscall
from syzgen.parser.types import ConstType, PtrDir, PtrType, ResourceType, StructType, Type, int2bytes


class SyzConvert2Int(Syscall):
    NAME = "syz_convert_to_int"
    ARG_ARG = "arg"
    ARG_SIZE = "size"

    def __init__(
        self,
        subName: str,
        ret: Optional[ResourceType]=None,
        arg: Optional[Type]=None,
        size: Optional[Type]=None,
    ):
        super().__init__(subName)

        self.ret: ResourceType = ResourceType({
            "name": f"{subName}_ret",
            "parent": "int32",
            "data": int2bytes(0, 4)
        }) if ret is None else ret

        self.args.append(
            ConstType({"data": int2bytes(0, 8)})
            if arg is None else arg
        )
        self.args.append(
            ConstType({"data": int2bytes(4, 4)})
            if size is None else size
        )

        self.validate()

    @staticmethod
    def Create(subName: str, arg: StructType) -> "SyzConvert2Int":
        size = arg.size
        resc = ResourceType({
            "name": f"{subName}_ret",
            "parent": "int16" if size <= 2 else ("int32" if size <= 4 else "int64"),
            "data": int2bytes(0, size),
        })
        # reset the typename and then it can regenerate a unique one
        ref = arg.toJson()
        ref["typename"] = None
        ptr = PtrType({
            "ref": ref,
            "dir": PtrDir.DirIn,
        })
        size = ConstType({"data": int2bytes(size, 4)})
        return SyzConvert2Int(subName, ret=resc, arg=ptr, size=size)
