
import os
import tempfile
from unittest.mock import Mock, patch
from syzgen.analysis.ioctl import LinuxErrorCode

from syzgen.analysis.plugins.error_path import DetectErrorPathPlugin
from syzgen.analysis.tests import TestExecutor
from syzgen.config import Options
from syzgen.executor.macos import err_get_code, err_get_system
from syzgen.kext.macho import LoadMachoDriver, LoadVMLinux
from syzgen.target.linux import LinuxTarget
from syzgen.target.macos import MacOSTarget

options = Options()

def macOS_isErrorCode(val):
    val = val & 0xffffffff
    return (
        err_get_system(val) == 0x38 and
        0x2bc <= err_get_code(val) <= 0x2f0
    )


def ValidParameter_isErrorCode(val):
    return val&0xff == 0


MACOS_TARGETS = [
    {
        "module": "com.apple.iokit.IOAudioFamily",
        "addr": 0xcbca,
        "results": {0xcdc7, 0xcde7, 0xce07, 0xcda7},
        "isErrorCode": macOS_isErrorCode,
    },
    {
        "module": "com.apple.iokit.IOBluetoothFamily",
        "addr": 0x11a16,
        "results": {},
        "isErrorCode": ValidParameter_isErrorCode,
    }
]
LINUX_TARGETS = [
    (0xffffffff81d43700, set()),
    (0xffffffff8283ffe0, {0xffffffff8284001c, 0xffffffff82840078}),
    (0xffffffff82a9d780, {0xffffffff82a9da06, 0xffffffff82a9da26}),
    (0xffffffff82563520, set()),
]

class TesstErrorPath(TestExecutor):
    def setUp(self) -> None:
        self.mock_target = Mock()
        return super().setUp()

    @patch("syzgen.analysis.plugins.error_path.DetectErrorPathPlugin.isErrorCode")
    @patch("syzgen.executor.PluginMixin.load_project_by_addr")
    @patch("syzgen.executor.PluginMixin.get_default_project")
    @patch("syzgen.executor.PluginMixin.getTargetAddr")
    def test_detect_error_paths(
        self,
        mock_get_target_addr,
        mock_get_default_project,
        mock_load_project_by_addr,
        mock_isErrorCode,
    ):
        if isinstance(self.target, MacOSTarget):
            targets = MACOS_TARGETS
        elif isinstance(self.target, LinuxTarget):
            targets = LINUX_TARGETS
        else:
            raise NotImplementedError()


        with tempfile.TemporaryDirectory() as test_dir:
            # mock target
            self.mock_target.workdir = test_dir
            # mock getTargetAddr
            mock_get_target_addr.side_effect = lambda off, _ : off

            for testcase in targets:
                if isinstance(self.target, MacOSTarget):
                    binary = self.target.find_kext_path(testcase["module"])
                    proj = LoadMachoDriver(binary)
                    # mock isErrorCode
                    mock_isErrorCode.side_effect = testcase["isErrorCode"]
                elif isinstance(self.target, LinuxTarget):
                    binary = os.path.join(options.getConfigKey("binary"), "vmlinux")
                    proj = LoadVMLinux(binary)
                    # mock isErrorCode
                    mock_isErrorCode.side_effect = LinuxErrorCode

                # mock get_default_project
                mock_get_default_project.return_value = proj
                # mock load_project_by_addr
                mock_load_project_by_addr.return_value = ("", 0, proj)

                plugin = DetectErrorPathPlugin()
                entry = testcase["addr"]
                cfg = plugin._get_cfg(proj, entry)
                # from IPython import embed; embed()
                blocks = plugin.detect_error_paths(entry, cfg.functions[entry])
                for block in blocks:
                    print(f"{block:#x}")
                self.assertEqual(blocks, testcase["results"])

    ERROR_CODE_TESTS = {
        "linux": [
            {
                "module": "ppp",
                "name": "ioctl",
                "dynamic": False,
                "result": True,
            },
            {
                "module": "loop_control",
                "name": "ioctl",
                "dynamic": False,
                "result": False,
            },
            {
                "module": "kvm",
                "name": "ioctl",
                "dynamic": False,
                "result": False,
            },
            {
                "module": "ptmx",
                "name": "ioctl",
                "dynamic": False,
                "result": False,
            },
        ]
    }

    def test_error_code(self):
        for test in self.ERROR_CODE_TESTS[self.target.get_os()]:
            syscall, model, interface = self.prepare_executor(
                test["module"],
                test["name"],
                dynamic=test["dynamic"]
            )

            def _execute(_syscall, m, testcase=None, **kwargs):
                executor = interface.get_executor(_syscall, m, testcase=testcase, **kwargs)
                executor.initialize()
                state = executor.getInitState()
                executor.pre_execute(state)
                assert isinstance(executor, DetectErrorPathPlugin)

                res = executor.always_return_error_code(state.addr)
                self.assertEqual(res, test["result"])

            interface.execute_syscall(syscall, model, func=_execute)
