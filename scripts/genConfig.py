
import argparse
import json
from base import Command
from syzgen.config import Options

from syzgen.target import Target

options = Options()

class GenConfig(Command):
    """Generate a config for syzgen"""

    def __init__(self) -> None:
        super().__init__(description="generate a config for SyzGen")

    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("-n", "--name", required=True, help="project name")
        parser.add_argument("-t", "--target", choices=[
                            "linux", "android", "darwin"], required=True, help="target platform (linux/android/macos)")
        parser.add_argument(
            "--type", choices=["qemu", "adb", "vmware", "dummy"], required=True, help="VM type (qemu/adb/vmware)")
        parser.add_argument('-c', '--config', default="config",
                            help="path to the config file")
        parser.add_argument(
            "--image", help="dir to the debian image for linux")
        parser.add_argument(
            "--version", help="version of the linux (assume the source code is at linux-distro/linux-version-")
        parser.add_argument("--adb", help="path to adb")
        
        options.add_options(parser)

    def start(self):
        args = self.parser.parse_args()
        options.set_options(args)
        dummy_args = [
            "user", "vmxpath", "ip", "kernel",
            "image", "sshkey", "adb", "device",
            "user",
        ]
        dummy_args = {each: "dummy" for each in dummy_args}
        target = Target.Create(
            args.target,
            args.type,
            project_name=args.name,
            **dummy_args,
        )

        self.run(args, target)

    def run(self, args, target: Target):
        config = target.genProjectConfig(
            args.name, args.config,
            image=args.image,
            version=args.version,
            adb=args.adb,
        )
        with open(args.config, "w") as fp:
            json.dump(config, fp, indent=2)
            print(f"generate config file at: {args.config}")


if __name__ == '__main__':
    GenConfig().start()
