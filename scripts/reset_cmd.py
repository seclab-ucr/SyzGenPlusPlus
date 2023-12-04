
import argparse
from base import Command, str2int
from syzgen.parser.models import BaseModel, SyscallModel
from syzgen.parser.optimize import reduce_syscalls_to_one
from syzgen.parser.syscalls import SyscallStatus
from syzgen.target import Target


class ResetCmd(Command):
    """Reset the method and access path for certain cmd"""

    def init_parser(self, parser: argparse.ArgumentParser):
        parser.add_argument("-m", "--module", required=True,
                            help="target module")
        parser.add_argument("--cmd", type=str2int, required=True, help="cmd value")
        parser.add_argument("--delete", default=False, action="store_true", help="delete one command")
        parser.add_argument("--merge", default=False, action="store_true", help="merge rest syscalls")
        parser.add_argument("--skip", default=False, action="store_true", help="skip one command")
        return super().init_parser(parser)

    def skip_syscalls(self, model: SyscallModel, cmd: int):
        for each in model.methods[cmd]:
            each.status = SyscallStatus.FINISHED
        model.reduce(cmd)

    def merge_syscalls(self, model: SyscallModel, cmd: int):
        syscalls = model.methods[cmd]
        incompletes = []
        outputs = []
        results = []
        for each in syscalls:
            if each.status == SyscallStatus.INCOMPLETE:
                incompletes.append(each)
            elif each.status == SyscallStatus.OUTPUT:
                outputs.append(each)
            else:
                results.append(each)

        results.append(reduce_syscalls_to_one(incompletes)[0])
        results.append(reduce_syscalls_to_one(outputs)[0])
        model.methods[cmd] = results
        model.reduce(cmd)

    def run(self, args, target: Target) -> None:
        model: BaseModel = target.load_model(args.module)
        if model is None:
            print("no model found")
            return

        for _, m in model._syscall_models():
            if m.dispatcher is not None:
                for cmd, method in m.dispatcher.methods.items():
                    if cmd == args.cmd:
                        if args.delete:
                            del m.methods[cmd]
                        elif args.merge:
                            self.merge_syscalls(m, cmd)
                        elif args.skip:
                            self.skip_syscalls(m, cmd)
                        else:
                            m.methods[cmd] = [m.init_syscall(cmd, method)]
            elif args.cmd == 0:
                m.methods[0] = [m.init_syscall(0, None)]

            if args.cmd in m.read_patterns:
                del m.read_patterns[args.cmd]
            if args.cmd in m.write_patterns:
                del m.write_patterns[args.cmd]

        model.save(target.model_path)
        target.generate_template(model, True, True)

if __name__ == '__main__':
    ResetCmd().start()