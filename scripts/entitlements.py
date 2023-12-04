
from base import Command

from syzgen.analysis.static import find_entitlement

from syzgen.target import Target


class Entitlement(Command):
    def run(self, args, target: Target):
        entitlements = set()
        services = target.load_services()
        if not services:
            exit(1)

        checked = set()
        for _, items in services.items():
            binary = items["binary"]
            if binary in checked:
                continue
            checked.add(binary)
            entitlements.update(find_entitlement(binary))

        for each in entitlements:
            print(each)


if __name__ == '__main__':
    Entitlement().start()
