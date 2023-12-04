
import argparse
import importlib
from typing import List
import angr
import inspect

from base import Command, logger
from syzgen.config import Options
from syzgen.kext.macho import find
from syzgen.target import Target
from syzgen.target.macos import MacOSTarget

# python scripts/error_code.py -m IOBluetoothHCIUserClient --address 0x11a16 -f "lambda x: x&0xff == 0"
# python scripts/error_code.py -m IOBluetoothHCIUserClient --address ValidParameters -f "lambda x: x&0xff == 0"

class ErrorCodeConvertor(Command):
    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("-m", "--module", required=True, help="target module")
        parser.add_argument("-f", "--function", required=True, help="validator functions")
        parser.add_argument("--address", required=True, help="function name of address")
        return super().init_parser(parser)

    def run(self, args, target: Target) -> None:
        if isinstance(target, MacOSTarget):
            service_name, client_name = target._parse_target(args.module)
            s, c = target.get_service_client_clazz(service_name, client_name)
            if c is None:
                logger.error("failed to find the target %s", target)
                return
            module = c.module
            binary = target.find_kext_path(module)
            proj = angr.Project(binary)
            if args.address.startswith("0x"):
                addr = int(args.address, 16)
            else:
                syms = find(proj, args.address, fuzzy=True)
                if not syms:
                    raise RuntimeError("No symbol found")
                if len(syms) > 1:
                    for sym in syms:
                        print(sym.name)
                    raise RuntimeError("Found multiple symbols")
                logger.debug("found symbol: %s", syms[0].name)
                addr = syms[0].relative_addr
        else:
            raise NotImplementedError()

        if args.function.endswith(".py"):
            filepath = args.function[:-3]
            m = importlib.import_module(filepath.replace("/", "."))
            raise NotImplementedError()
        else:
            func = eval(args.function)
            func(0)
            function = args.function

        options = Options()
        f: List = options.getConfigKey("error_code", default=[])
        f.append({
            "addr": hex(addr),
            "module": module,
            "func": function,
        })
        options.setConfigKey("error_code", f)


ErrorCodeConvertor().start()