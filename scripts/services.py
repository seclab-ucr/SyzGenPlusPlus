
from collections import defaultdict
from typing import Dict
from base import Command
from syzgen.target import Target

class TestServices(Command):

    def run(self, args, target: Target):
        services = target.load_services()
        if target.get_os() == "linux":
            self.run_linux(target, services)

    def run_linux(self, target: Target, services: Dict):
        ioctls = defaultdict(list)
        writes = defaultdict(list)
        for _, items in services.items():
            if "ops" not in items:
                continue
            ops = items["ops"]
            if "unlocked_ioctl" in ops and ops["unlocked_ioctl"]:
                ioctl_addr = ops["unlocked_ioctl"]
                ioctls[ioctl_addr].append(items["path"])
                continue
            if "write" in ops and ops["write"]:
                write_addr = ops["write"]
                writes[write_addr].append(items["path"])
                continue

        for addr, paths in ioctls.items():
            print("ioctl entry: %#x" % addr)
            for each in sorted(paths):
                print("\t%s" % each)

        for addr, paths in writes.items():
            print("write entry: %#x" % addr)
            for each in sorted(paths):
                print("\t%s" % each)

if __name__ == '__main__':
    TestServices().start()
