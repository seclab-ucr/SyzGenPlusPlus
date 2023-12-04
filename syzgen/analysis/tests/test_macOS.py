
import logging
import time
from typing import Tuple
import unittest
from syzgen.analysis.iokit import GetTargetAndMethodExecutor

from syzgen.analysis.tests import TestExecutor
from syzgen.config import Options
from syzgen.kext.macho import Service, UserClient
from syzgen.target.macos import MacOSTarget

logger = logging.getLogger(__name__)
options = Options()

@unittest.skipIf(options.getConfigKey("target") != "darwin", "requires macOS")
class TestMacOSExecutor(TestExecutor):
    TARGETS = [
        ("AudioAUUCDriver", "AudioAUUC", {0, 1, 2, 3, 4, 5, 6}),
        ("IOAudioEngine", "IOAudioEngineUserClient", {0, 1, 2, 3, 4, 5}),
        ("AppleImage4", "AppleImage4UserClient", {0, 1, 2, 3}),
        ("AppleMCCSControlModule", "AppleMCCSUserClient", {i for i in range(24576, 24586)}),
        ("AppleSSE", "AppleSSEUserClient", {0}),
        ("AppleCredentialManager", "AppleCredentialManagerUserClient", {0, 2}),
        ("IOAHCIBlockStorageDevice", "AHCISMARTUserClient", {i for i in range(9)}),
        ("AppleFDEKeyStore", "AppleFDEKeyStoreUserClient",
        {0, 1, 2, 3, 4, 5, 6, 12, 13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}),
        ("IOBluetoothHCIController", "IOBluetoothHCIUserClient", {i for i in range(213)}),
        ("IOAVBNub", "IOAVBNubUserClient", {i for i in range(2, 0x19)} - {0x10, 0x11}),
        ("IOUSBHostInterface", "AppleUSBHostInterfaceUserClient", {i for i in range(0x22)}),
    ]
    TARGETS_WITH_METHODS = [
        ("ACPI_SMC_PlatformPlugin", "ACPI_SMC_PluginUserClient", {0, 1, 2, 3}),
        ("IOHDIXController", "IOHDIXControllerUserClient", {0, 1}),
    ]
    SERVICES = [
        ("ACPI_SMC_PlatformPlugin", {"ACPI_SMC_PluginUserClient"}),
        ("AppleUpstreamUserClientDriver", {"AppleUpstreamUserClient"}),
        ("AudioAUUCDriver", {"AudioAUUC"}),
        ("IOBluetoothHCIController", {"IOBluetoothHCIUserClient"}),
        ("IONetworkInterface", {"IONetworkUserClient"}),
        ("IOAHCIBlockStorageDriver", {"AHCISMARTUserClient"}),
        ("IOAudioEngine", {"AppleHDAEngineUserClient", "DspFuncUserClient", "IOAudioEngineUserClient"}),
        ("IOHDACodecDevice", {"IOHDACodecDeviceUserClient"}),
        ("AppleHDAController", {"AppleHDAControllerUserClient"}),
        ("AppleHDADriver", {"AppleHDADriverUserClient"}),
        ("AppleHDAEngine", {"AppleHDAEngineUserClient", "DspFuncUserClient"}),
        ("IOUSBHostInterface", {"AppleUSBHostInterfaceUserClient", "AppleUSBHostFrameworkInterfaceClient"}),
        ("IOUSBHostDevice", {"AppleUSBHostDeviceUserClient", "AppleUSBHostFrameworkDeviceClient"}),
    ]
    DEFAULT_SERVICES = [
        ("AppleAPFSContainer", "AppleAPFSUserClient"),
        ("AppleFDEKeyStore", "AppleFDEKeyStoreUserClient"),
        ("AppleImage4", "AppleImage4UserClient"),
        ("IOHDIXController", "IOHDIXControllerUserClient"),
        ("AppleMCCSControlModule", "AppleMCCSUserClient"),
        ("AppleSSEInterface", "AppleSSEUserClient"),
        ("AppleCredentialManager", "AppleCredentialManagerUserClient"),
        ("IOAVBNub", "IOAVBNubUserClient"),
        ("IOReportHub", "IOReportUserClient"),
        ("IOUSBDevice", "AppleUSBLegacyDeviceUserClient"),
    ]

    SYSCALLS = [
        {
            "module": "IOBluetoothHCIUserClient",
            "timeout": 1000,
            "name": "syz_IOConnectCallMethod",
            "syscall": {'CallName': 'syz_IOConnectCallMethod', 'SubName': 'IOBluetoothHCIUserClient_Group0_1', 'status': 2, 'args': [{'type': 'resource', 'offset': 0, 'size': 8, 'typename': 'connection', 'data': [0, 0, 0, 0, 0, 0, 0, 0], 'access': True, 'name': 'IOBluetoothHCIUserClient_port', 'parent': 'io_connect_t'}, {'type': 'const', 'offset': 0, 'size': 4, 'typename': 'selector', 'data': [0, 0, 0, 0], 'access': True}, {'type': 'ptr', 'offset': 0, 'size': 8, 'typename': 'input', 'optional': False, 'dir': 1, 'ref': {'type': 'buffer', 'offset': 0, 'size': 128, 'access': True}}, {'type': 'range', 'offset': 0, 'size': 4, 'typename': 'inputCnt', 'data': [0, 0, 0, 0], 'access': True, 'path': [2], 'bitSize': 64, 'min': 0, 'max': 16, 'stride': 1}, {'type': 'ptr', 'offset': 0, 'size': 8, 'typename': 'inputStruct', 'optional': False, 'dir': 1, 'ref': {'type': 'struct', 'offset': 0, 'size': 116, 'fields': [{'type': 'ptr', 'offset': 0, 'size': 8, 'optional': False, 'dir': 1, 'ref': {'type': 'struct', 'offset': 0, 'size': 4096, 'fields': [{'type': 'buffer', 'offset': 0, 'size': 4, 'data': [0, 1, 1, 253], 'access': True}, {'type': 'buffer', 'offset': 4, 'size': 4092, 'access': True}], 'isArray': False}}, {'type': 'ptr', 'offset': 8, 'size': 8, 'optional': False, 'dir': 1, 'ref': {'type': 'struct', 'offset': 0, 'size': 4096, 'fields': [{'type': 'const', 'offset': 0, 'size': 1, 'data': [0], 'access': True}, {'type': 'buffer', 'offset': 1, 'size': 1, 'data': [252], 'access': True}, {'type': 'buffer', 'offset': 2, 'size': 2, 'data': [0, 254], 'access': True}, {'type': 'buffer', 'offset': 4, 'size': 4092, 'access': True}], 'isArray': False}}, {'type': 'const', 'offset': 16, 'size': 8, 'data': [0, 0, 0, 0, 0, 0, 0, 0], 'access': True}, {'type': 'const', 'offset': 24, 'size': 8, 'data': [0, 0, 0, 0, 0, 0, 0, 0], 'access': True}, {'type': 'buffer', 'offset': 32, 'size': 24, 'data': [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'range', 'offset': 56, 'size': 8, 'data': [1, 0, 0, 0, 0, 0, 0, 0], 'access': True, 'path': [4, 0, 0], 'bitSize': 8, 'min': 1, 'max': 8, 'stride': 1}, {'type': 'range', 'offset': 64, 'size': 8, 'data': [2, 0, 0, 0, 0, 0, 0, 0], 'access': True, 'path': [4, 0, 8], 'bitSize': 8, 'min': 1, 'max': 8, 'stride': 1}, {'type': 'range', 'offset': 72, 'size': 8, 'data': [255, 255, 0, 0, 0, 0, 0, 0], 'access': True, 'min': 1, 'max': 65535, 'stride': 1}, {'type': 'range', 'offset': 80, 'size': 8, 'data': [1, 128, 0, 0, 0, 0, 0, 0], 'access': True, 'min': 1, 'max': 65535, 'stride': 1}, {'type': 'buffer', 'offset': 88, 'size': 24, 'data': [255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'const', 'offset': 112, 'size': 4, 'data': [0, 0, 0, 0], 'access': True}], 'isArray': False}}, {'type': 'const', 'offset': 0, 'size': 4, 'typename': 'inputStructCnt', 'data': [116, 0, 0, 0], 'access': True, 'path': [4], 'bitSize': 8}, {'type': 'ptr', 'offset': 0, 'size': 8, 'typename': 'output', 'optional': False, 'dir': 2, 'ref': {'type': 'struct', 'offset': 0, 'size': 128, 'fields': [{'type': 'buffer', 'offset': 0, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 8, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 16, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 24, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 32, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 40, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 48, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 56, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 64, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 72, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 80, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 88, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 96, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 104, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 112, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}, {'type': 'buffer', 'offset': 120, 'size': 8, 'data': [255, 255, 255, 255, 255, 255, 255, 255], 'access': True}], 'isArray': True}}, {'type': 'ptr', 'offset': 0, 'size': 8, 'typename': 'outputCnt', 'optional': False, 'dir': 1, 'ref': {'type': 'range', 'offset': 0, 'size': 4, 'data': [15, 0, 0, 0], 'access': True, 'path': [6], 'bitSize': 64, 'min': 0, 'max': 16, 'stride': 1}}, {'type': 'ptr', 'offset': 0, 'size': 8, 'typename': 'outputStruct', 'optional': False, 'dir': 2, 'ref': {'type': 'buffer', 'offset': 0, 'size': 4, 'data': [0, 0, 0, 0], 'access': True}}, {'type': 'ptr', 'offset': 0, 'size': 8, 'typename': 'outputStructCnt', 'optional': False, 'dir': 1, 'ref': {'type': 'const', 'offset': 0, 'size': 4, 'data': [4, 0, 0, 0], 'access': True, 'path': [8], 'bitSize': 8}}]}
        }
    ]

    def setUp(self) -> None:
        super().setUp(debug=True)

        # wait for some drivers to be loaded
        self.target.register_setup(time.sleep, 30)

    def test_default_client_discovery(self):
        assert isinstance(self.target, MacOSTarget)
        with self.target:
            for service_name, client_name in self.DEFAULT_SERVICES:
                service, _ = self.target.get_service_client(service_name, None)
                client = self.target.find_default_client(
                    service["binary"],
                    service["kext"],
                    service_name,
                    options.getConfigKey("driver_dir"),
                )
                self.assertEqual(client.metaClass, client_name)

    def test_client_discovery(self):
        assert isinstance(self.target, MacOSTarget)
        for service_name, clients in self.SERVICES:
            with self.subTest(service_name=service_name):
                service, _ = self.target.get_service_client(service_name, None)
                self.assertIsNotNone(service)
                userClients = self.target.find_client(
                    service["binary"],
                    service["kext"],
                    service["newUserClient"],
                    service_name,
                    options.getConfigKey("driver_dir"),
                )
                names = set(client.metaClass for client in userClients)
                logger.debug("found clients: %s", names)
                self.assertEqual(clients, names)

    def test_cmd_extraction(self):
        assert isinstance(self.target, MacOSTarget)
        options.timeout = 300
        for service_name, client_name, result in self.TARGETS:
            with self.subTest(service_name=service_name, client_name=client_name):
                s, c = self.target.get_service_client_clazz(service_name, client_name)
                self.assertIsNotNone(c)
                table = self.target._find_cmds(s, c)
                logger.debug(table.debug_repr())
                cmds = set(each for each in table.methods)
                self.assertEqual(cmds, result)

    def test_cmd_extraction_table(self):
        assert isinstance(self.target, MacOSTarget)
        for service_name, client_name, result in self.TARGETS_WITH_METHODS:
            with self.subTest(service_name=service_name, client_name=client_name):
                s, c = self.target.get_service_client_clazz(service_name, client_name)
                self.assertIsNotNone(c)
                binary = self.target.find_kext_path(c.module)
                executor = GetTargetAndMethodExecutor(self.target, binary, s, c)
                executor.run()
                cmds = set(each for each in executor.table.methods)
                self.assertEqual(cmds, result)

    def test_syscalls(self):
        for test in self.SYSCALLS:
            timeout = 600 if "timeout" not in test else test["timeout"]
            syscall, model, interface = self.prepare_executor(
                test["module"],
                test["name"],
                syscall_json=test["syscall"],
                timeout=timeout,
                dynamic=True,
            )
            interface.execute_syscall(syscall, model, cmd=interface.cmd)

            print("result:")
            for each in model.methods[interface.cmd]:
                print(each.repr())
