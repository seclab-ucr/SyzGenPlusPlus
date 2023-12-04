
import json
import os

from angr.calling_conventions import SimRegArg, SimStackArg
from archinfo import RegisterName


class SimRegRet(SimRegArg):
    def __init__(self, reg_name: RegisterName, size: int, alt_offsets=None):
        SimRegArg.__init__(self, reg_name, size, alt_offsets)


class Argument:
    """A wrapper for SimRegArg or SimStackArg"""

    def __init__(self, data):
        if data["type"] == "SimRegArg":
            arg = SimRegArg(data["reg_name"], data["size"])
        elif data["type"] == "SimStackArg":
            arg = SimStackArg(data["stack_offset"], data["size"])
        elif data["type"] == "SimRegRet":
            arg = SimRegRet(data["reg_name"], data["size"])
        self.arg = arg
        self.is_ptr = data["is_ptr"]

    def get_value(self, state):
        return self.arg.get_value(state)

    @staticmethod
    def create_reg(reg_name: str, size: int, is_ptr: bool) -> "Argument":
        return Argument({
            "type": "SimRegArg",
            "reg_name": reg_name,
            "size": size,
            "is_ptr": is_ptr,
        })

def load_calling_conventions(filepath, slide=0, include_ret=False):
    """ Get calling conventions for all functions
    """
    if not os.path.exists(filepath):
        raise Exception("calling convention does not exists: %s" % filepath)

    ret = dict()
    with open(filepath, "r") as fp:
        for k, v in json.load(fp).items():
            args = [
                Argument(each)
                for each in v
                if include_ret or each["type"] != "SimRegRet"
            ]
            # adjust the address for every function
            ret[slide + int(k)] = args
    return ret
