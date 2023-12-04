
import argparse
import json
import os
import re
import subprocess
import time

from base import Command
from syzgen.config import Options
from syzgen.target import Target
from syzgen.target.macos import MacOSTarget


options = Options()

class SyzkallerFuzzBaseline(Command):
    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("file", nargs="*",
                            help="syscall specifications files")
        parser.add_argument("--cfg", help="existing syz config to get all enabled syscalls")
        parser.add_argument("--prefix", default="", help="prefix for workdir")
        parser.add_argument("--kcov", help="path to kcov json file")
        parser.add_argument("--nospec", default=False, action="store_true", help="test autogen specs")
        return super().init_parser(parser)

    def mkdir(self, path):
        try:
            os.mkdir(path)
        except:
            pass

    def get_syscalls(self, filepath):
        syscalls = []
        with open(filepath, "r") as fp:
            for line in fp:
                m = re.search(r'^([\w$]+)\(', line)
                if m:
                    call = m.group(0)[:-1]
                    syscalls.append(call)
        return syscalls

    def collect_all_gen_specs(self, target: Target):
        syscalls = []
        syzkaller = options.getConfigKey("syzkaller")
        specs = os.path.join(syzkaller, "sys", target.get_os())
        for file in os.listdir(specs):
            if file.endswith("_gen.txt"):
                syscalls.extend(self.get_syscalls(os.path.join(specs, file)))

        if "close" not in syscalls:
            syscalls.append("close")
        return syscalls

    def run(self, args, target: Target):
        syscalls = []
        num_vm = 2
        if args.cfg:
            assert args.cfg.endswith(".json")
            name = os.path.basename(args.cfg)[:-5]
            if name.startswith("cfg_"):
                name = name[4:]
            with open(args.cfg, "r") as fp:
                data = json.load(fp)
                syscalls = data["enable_syscalls"]
        elif args.nospec:
            name, syscalls = "nospec", self.collect_all_gen_specs(target)
            num_vm = 4
        else:
            name = os.path.basename(args.file[0])[:-4]
            for each in args.file:
                assert each.endswith(".txt")
                syscalls.extend(self.get_syscalls(each))
            if "close" not in syscalls:
                syscalls.append("close")

        print("enabled syscalls:")
        for each in syscalls:
            print(each)
        syscalls = sorted(syscalls)
        syzkaller = options.getConfigKey("syzkaller")

        self.mkdir("results")
        prefix = f"{args.prefix}_{name}" if args.prefix else f"{name}"
        if name != "nospec":
            # reuse the same workdir for nospec
            prefix += "."
            prefix += time.strftime("%Y%m%d-%H%M%S")
        workdir = os.path.join(
            os.getcwd(),
            "results",
            prefix,
        )
        self.mkdir(workdir)

        num_procs = 4
        if target.get_os() == "darwin":
            num_procs = 1

        cfg_path = os.path.join(workdir, f"cfg_{name}.json")
        target.genSyzConfig(
            syscalls,
            f"cfg_{name}.json",
            workdir=workdir,
            num_procs=num_procs,
            num_cpu=2,
            num_vm=num_vm,
        )
        # 24 hours = 86400 sec
        cmds = [
            os.path.join(syzkaller, "bin", "syz-manager"),
            f"-config={cfg_path}",
            f"-timeout={args.timeout}",
        ]
        if isinstance(target, MacOSTarget):
            assert args.kcov and args.kcov.endswith(".json")
            kcov_file = os.path.join(workdir, "kcov")
            subprocess.run([
                "python",
                "kcov/scripts/gen_cov.py",
                "-o", kcov_file,
                args.kcov,
            ], check=True)
            cmds.extend(["-kcov", kcov_file])
        print(" ".join(cmds))

        with open(os.path.join(workdir, "log.txt"), "w") as fp:
            subprocess.run(cmds, stdout=fp, stderr=fp)

if __name__ == '__main__':
    SyzkallerFuzzBaseline().start()
