
import argparse
import os
import json
import time

from base import Command, logger
from syzgen.target import Target


class TestService(Command):
    """Check whether the specified UserClient can be accessed!
    """

    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("--clazz", required=True)
        return super().init_parser(parser)

    def run(self, args, target: Target):
        # wait for some drivers to be loaded
        target.register_setup(time.sleep, 30)
        service_path = os.path.join(target.model_path, "services.json")
        with open(service_path, "r") as fp:
            services = json.load(fp)

        for clazz, items in services.items():
            if clazz == args.clazz:
                with target:
                    for client in items["clients"]:
                        if target.check_effect_client(clazz, client["type"], root=True):
                            logger.debug("%s with type %d is okay!",
                                         client["clazz"], client["type"])
                break


if __name__ == '__main__':
    TestService().start()
