
import argparse
import os
from base import Command
from syzgen.config import Options
from syzgen.executor import BaseExecutor
from syzgen.target import Target

options = Options()


class TestProject(Command):
    """Test angr.Project"""

    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("-m", "--module", required=True,
                            help="target module")
        return super().init_parser(parser)

    def run(self, args, target: Target) -> None:
        if target.get_os() == "linux":
            binary = os.path.join(options.getConfigKey("binary"), "vmlinux")
        elif target.get_os() == "darwin":
            binary = os.path.join(options.getConfigKey("kernel"), "kernel.development")
        else:
            raise NotImplementedError()
        executor = BaseExecutor(target, binary)
        from IPython import embed
        embed()


if __name__ == '__main__':
    TestProject().start()
