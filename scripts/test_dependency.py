
import argparse
from base import Command
from syzgen.analysis.dependence import infer_dependency
from syzgen.config import Options
from syzgen.parser.generate import BaseModel

from syzgen.target import Target

options = Options()


class TestDependency(Command):
    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("-m", "--module", required=True,
                            help="target module")
        return super().init_parser(parser)

    def run(self, args, target: Target) -> None:
        model: BaseModel = target.load_model(args.module)
        model = infer_dependency(target, model, save=False)
        # model.debug_repr()


if __name__ == '__main__':
    TestDependency().start()
