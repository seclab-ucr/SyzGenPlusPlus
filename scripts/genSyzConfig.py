
import argparse
import os
import re
from typing import List
from base import Command

from syzgen.target import Target


class GenSyzConfig(Command):
    """Generate config for syzkaller with a specified syscall specifications"""

    def __init__(self) -> None:
        super().__init__(description="generate a config for syzkaller given particular syzlang files")

    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("file", nargs="+",
                            help="syscall specifications files")
        parser.add_argument("--merge", default="", help="merge configs into one")
        return super().init_parser(parser)

    def run(self, args, target: Target):
        syscalls = []
        for each in args.file:
            if os.path.isdir(each):
                assert(args.merge != "")
                for file in os.listdir(each):
                    if file.endswith("_gen.txt"):
                        self.genSyzConfig(os.path.join(each, file), syscalls)
            else:
                if args.merge == "":
                    syscalls.clear()

                self.genSyzConfig(each, syscalls)
                syscalls = sorted(syscalls)

                if args.merge == "":
                    name = os.path.basename(each)[:-4]
                    target.genSyzConfig(syscalls, f"cfg_{name}.json")

        if args.merge:
            syscalls = sorted(syscalls)
            target.genSyzConfig(syscalls, f"cfg_{args.merge}.json")

    def genSyzConfig(self, filepath, syscalls: List[str]):
        with open(filepath, "r") as fp:
            for line in fp:
                m = re.search(r'^([\w$]+)\(', line)
                if m:
                    call = m.group(0)[:-1]
                    syscalls.append(call)


if __name__ == '__main__':
    GenSyzConfig().start()
