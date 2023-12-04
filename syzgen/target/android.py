
import logging
import os
from typing import Any, Dict
from syzgen.target import Target
from syzgen.target.linux import LinuxTarget
from syzgen.vm.adb import ADBInstance


logger = logging.getLogger(__name__)

class AndroidTarget(LinuxTarget):
    NAME = "android"

    def __init__(self, target, typ, name, **kwargs) -> None:
        super().__init__(target, typ, name, **kwargs)

    def get_target(self) -> str:
        return "android/arm64"

    def setup(self, **kwargs):
        Target.setup(self, **kwargs)

    def find_device_interface(self, path: str):
        return None

    def get_target_for_analysis(self) -> "Target":
        return self

    def get_target_for_fuzzing(self) -> "Target":
        return self

    def genProjectConfig(self, project_name: str, config: str = "config", **kwargs) -> Dict[str, Any]:
        config = Target.genProjectConfig(self, project_name, config, **kwargs)
        config["kernel"] = os.path.join(os.getcwd(), "android-kernel")

        if isinstance(self.inst, ADBInstance):
            adb = kwargs.pop("adb", None)
            if adb is None:
                logger.error("adb path is None")
                raise RuntimeError()

            config["adb"] = adb
            self.inst.adb_bin = adb
            devices = self.inst.get_devices()
            if len(devices) == 1:
                config["device"] = devices[0]
            elif devices:
                logger.info("found multiple device, please select one:")
                for each in devices:
                    logger.info(each)
                config["device"] = "please select one device: %s" % ",".join(devices)
            else:
                logger.info("no android device found")
                config["device"] = "use adb device to get the device id"

        return config
