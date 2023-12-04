
import os
import argparse

from base import Command
from syzgen.parser.generate import BaseModel
from syzgen.target import Target
from syzgen.utils import loads


class RunModel(Command):
    """Load Model for interactive debugging"""

    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("-m", "--module", required=True,
                            help="target module")
        return super().init_parser(parser)

    def run(self, args, target: Target):
        model: BaseModel = target.load_model(args.module)
        from IPython import embed
        embed()


if __name__ == '__main__':
    RunModel().start()
