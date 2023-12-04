
from argparse import ArgumentParser
from base import Command, logger
from pathlib import Path
from collections import defaultdict

from concurrent.futures import ThreadPoolExecutor

from syzgen.target import Target

results = defaultdict(set)


def grep(filepath, names):
    global results
    logger.debug("analyzing %s", filepath)
    with open(filepath, "r") as fp:
        for line in fp:
            for name in names:
                if name in line:
                    results[name].add(filepath)


class SearchCommand(Command):
    """Find the source files corresponding to a device name.
    We use a simple string match to do it
    """

    def __init__(self) -> None:
        super().__init__()
        self.executor = ThreadPoolExecutor(max_workers=32)

    def init_parser(self, parser: ArgumentParser):
        parser.add_argument("--source", required=True,
                            help="source dir to the kernel")
        return super().init_parser(parser)

    def run(self, args, target: Target):
        services = target.load_services()
        names = [each for each in services]
        logger.debug("total devices: %d", len(names))

        # print(names)
        for filepath in Path(args.source).glob("**/*.c"):
            self.executor.submit(grep, filepath, names)

        self.executor.shutdown(wait=True)

        unknown = []
        for name in names:
            logger.debug("device: %s", name)
            for each in results[name]:
                logger.debug("\t%s", each)
            if len(results[name]) == 0:
                unknown.append(name)

        logger.debug("\nunknown devices: %d\n", len(unknown))
        for each in unknown:
            logger.debug("device: %s", each)


if __name__ == '__main__':
    cmd = SearchCommand()
    cmd.start()
