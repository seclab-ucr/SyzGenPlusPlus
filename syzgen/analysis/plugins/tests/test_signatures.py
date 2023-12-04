
import json
import os
import tempfile
from unittest.mock import Mock, patch
from syzgen.analysis.plugins.signature import FunctionSignaturePlugin
from syzgen.analysis.tests import TestExecutor
from syzgen.config import Options

options = Options()
cur_dir = os.path.dirname(os.path.abspath(__file__))


class SingatureTestCase(TestExecutor):
    def setUp(self) -> None:
        self.mock_target = Mock()
        self.mock_project = Mock()
        return super().setUp()

    def test_parsing_signature(self):
        data_path = os.path.join(cur_dir, "data", "signatures.json")
        with open(data_path, "r") as fp:
            tests = json.load(fp)

        for sig, (name, res) in tests.items():
            _name, protocol = FunctionSignaturePlugin.parse_signature(sig)
            self.assertEqual(_name, name)
            self.assertEqual(str(protocol), res)

    @patch("syzgen.executor.PluginMixin.getTargetAddr")
    @patch("syzgen.executor.PluginMixin.get_default_project")
    @patch("syzgen.executor.PluginMixin.get_target")
    def test_get_signature_from_gdb(
        self,
        mock_get_target,
        mock_default_project,
        mock_get_target_addr,
    ):
        target = options.getConfigKey("target")
        if target == "linux":
            binary = os.path.join(options.getConfigKey("binary"), "vmlinux")
        else:
            raise NotImplementedError()

        with tempfile.TemporaryDirectory() as test_dir:
            # mock target
            self.mock_target.workdir = test_dir
            mock_get_target.return_value = self.mock_target
            # mock proj
            self.mock_project.filename = binary
            mock_default_project.return_value = self.mock_project
            # mock getTagetAddr
            mock_get_target_addr.side_effect = lambda off, _: off

            FunctionSignaturePlugin().load_prototypes()
