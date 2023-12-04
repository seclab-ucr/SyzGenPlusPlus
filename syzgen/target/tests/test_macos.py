
import unittest
from syzgen.config import Options
from syzgen.target.macos import MacOSTarget
from syzgen.target.tests import TestTarget

options = Options()

@unittest.skipIf(options.getConfigKey("target") != "darwin", "requires macOS")
class TestMacOS(TestTarget):
    ENTITLEMENTS = [
        'com.apple.private.iowatchdog.user-access',
        'com.apple.private.applehda.user-access',
        'com.apple.private.audio.driver-host',
        'com.apple.hid.system.user-access-service',
        'com.apple.hid.system.server-access',
        'com.apple.iokit.CoreAnalytics.user',
        'com.apple.private.applegraphicsdevicecontrol',
        'com.apple.private.gpuwrangler',
        'com.apple.hid.manager.user-access-device',
        'com.apple.developer.hid.virtual.device',
        'com.apple.private.KextAudit.user-access',
        'com.apple.private.security.AppleImage4.user-client',
        'com.apple.private.applecredentialmanager.allow',
        'com.apple.private.diskimages.kext.user-client-access',
        'com.apple.private.applesse.allow',
        'com.apple.private.timesync.clock-testing',
        'com.apple.hid.system.user-access-fast-path',
        'com.apple.private.applesmc.user-access',
        'com.apple.private.timesync.edge-generate',
        'com.apple.private.timesync.edge-capture',
        'com.apple.hid.manager.user-access-protected',
        'com.apple.private.applefdekeystore.readpassphrase',
        'com.apple.private.securityd.stash',
        'com.apple.private.securityd.keychain',
        'com.apple.private.applefdekeystore.deletepassphrase',
        'com.apple.private.storage.revoke-access',
        'com.apple.keystore.filevault',
        'com.apple.bluetooth.iokit-user-access',
        'com.apple.vm.device-access',
        'com.apple.developer.endpoint-security.client',
        'com.apple.private.endpoint-security.manager'
    ]

    def test_entitlements(self):
        assert isinstance(self.target, MacOSTarget)
        entitlements = self.target.get_all_entitlements()
        self.assertEqual(set(self.ENTITLEMENTS), set(entitlements))
