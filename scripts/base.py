
import angr
import argparse
import logging
import os
import sys
from pathlib import Path

# fmt: off
currentdir = Path(os.path.abspath(__file__)).parent.parent
sys.path.append(str(currentdir))

import syzgen.config as Config
from syzgen.target import Target
# fmt: on

logging.basicConfig()
logger = logging.getLogger("syzgen")
logger.setLevel(logging.DEBUG)

handler = logging.FileHandler("output.log", "w+")
handler.setFormatter(logging.Formatter())
logger.addHandler(handler)


options = Config.Options()
def str2int(x): return int(x, 16) if x.startswith("0x") else int(x)


class Command:
    def __init__(self, description=None) -> None:
        self.parser = argparse.ArgumentParser(
            prog="main", description=description)
        self.init_parser(self.parser)

    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("-t", "--target", choices=[
                            "linux", "android", "macos"], help="target platform (linux/android/macos)")
        parser.add_argument(
            "--type", choices=["qemu", "adb", "vmware"], help="VM type (qemu/adb/vmware)")
        parser.add_argument('-c', '--config', default="config",
                            help="path to the config file")
        options.add_options(parser)

    def start(self):
        args = self.parser.parse_args()
        options.set_options(args)
        Config.CONFIG_PATH = args.config
        if args.debug:
            handler = logging.FileHandler("output.log", "w+")
            handler.setFormatter(logging.Formatter())
            logging.getLogger().addHandler(handler)
            logger.setLevel(logging.DEBUG)

        target = Target.Create(
            args.target,
            args.type,
        )

        self.run(args, target)

    def run(self, args, target: Target) -> None:
        raise NotImplementedError()
