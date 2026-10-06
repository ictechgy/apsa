import unittest
from datetime import date

from quaygate.checks import (
    HIGH, INFO, LOW, MEDIUM, check_adb_enabled, check_android_version,
    check_backup, check_crypto_state, check_dev_options, check_flash_locked,
    check_install_unknown, check_lock_screen, check_oem_unlock,
    check_patch_level, check_selinux, check_verifier, check_wireless_debug,
    parse_getprop, run_device_checks,
)

TODAY = date(2026, 10, 4)


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = dict(responses or {})
        self.calls = []

    def shell(self, *args):
        key = " ".join(args)
        self.calls.append(key)
        value = self.responses.get(key)
        if isinstance(value, Exception):
            raise value
        if value is not None:
            return value
        if args and args[0] == "settings":
            return "null\n"
        return ""

    def get_state(self):
        return "device"


def props(**kw):
    return dict(kw)


class GetpropTest(unittest.TestCase):
    def test_parse(self):
        text = "[ro.build.version.release]: [15]\n[ro.product.model]: [SM-S928N]\n"
        self.assertEqual(parse_getprop(text), {
            "ro.build.version.release": "15",
            "ro.product.model": "SM-S928N",
        })

    def test_parse_empty(self):
        self.assertEqual(parse_getprop(""), {})


class PatchLevelTest(unittest.TestCase):
    def test_fresh(self):
        f = check_patch_level(props(**{"ro.build.version.security_patch": "2026-09-05"}), TODAY)
        self.assertEqual((f.status, f.severity), ("pass", None))

    def test_stale_warn(self):
        f = check_patch_level(props(**{"ro.build.version.security_patch": "2026-02-01"}), TODAY)
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_stale_fail(self):
        f = check_patch_level(props(**{"ro.build.version.security_patch": "2025-07-01"}), TODAY)
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_future_patch_date_na(self):
        f = check_patch_level(props(**{"ro.build.version.security_patch": "2099-01-01"}), TODAY)
        self.assertEqual(f.status, "na")
        self.assertIn("미래", f.detail)

    def test_garbage(self):
        f = check_patch_level(props(**{"ro.build.version.security_patch": "ro.build"}), TODAY)
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_missing(self):
        f = check_patch_level(props(), TODAY)
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))


class AndroidVersionTest(unittest.TestCase):
    def test_old(self):
        f = check_android_version(props(**{"ro.build.version.release": "12"}))
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_current(self):
        f = check_android_version(props(**{"ro.build.version.release": "16"}))
        self.assertEqual(f.status, "pass")

    def test_unknown(self):
        self.assertEqual(check_android_version(props()).status, "na")


class CryptoTest(unittest.TestCase):
    def test_encrypted(self):
        self.assertEqual(check_crypto_state(props(**{"ro.crypto.state": "encrypted"})).status, "pass")

    def test_unsupported(self):
        f = check_crypto_state(props(**{"ro.crypto.state": "unsupported"}))
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_missing(self):
        self.assertEqual(check_crypto_state(props()).status, "na")


class SelinuxTest(unittest.TestCase):
    def test_enforcing(self):
        self.assertEqual(check_selinux(FakeRunner({"getenforce": "Enforcing\n"})).status, "pass")

    def test_permissive(self):
        f = check_selinux(FakeRunner({"getenforce": "Permissive\n"}))
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_disabled(self):
        f = check_selinux(FakeRunner({"getenforce": "Disabled\n"}))
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_empty(self):
        self.assertEqual(check_selinux(FakeRunner()).status, "na")


class LockScreenTest(unittest.TestCase):
    def test_enabled(self):
        self.assertEqual(check_lock_screen(FakeRunner({"locksettings get-disabled": "false\n"})).status, "pass")

    def test_disabled(self):
        f = check_lock_screen(FakeRunner({"locksettings get-disabled": "true\n"}))
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_unparsable(self):
        f = check_lock_screen(FakeRunner({"locksettings get-disabled": "Error: unknown\n"}))
        self.assertEqual(f.status, "na")


class PropertyFlagTests(unittest.TestCase):
    def test_oem_allowed(self):
        f = check_oem_unlock(props(**{"sys.oem_unlock_allowed": "1"}))
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_oem_blocked(self):
        self.assertEqual(check_oem_unlock(props(**{"sys.oem_unlock_allowed": "0"})).status, "pass")

    def test_flash_unlocked(self):
        f = check_flash_locked(props(**{"ro.boot.flash.locked": "0"}))
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_flash_locked(self):
        self.assertEqual(check_flash_locked(props(**{"ro.boot.flash.locked": "1"})).status, "pass")


class SettingsTests(unittest.TestCase):
    def test_dev_options_on(self):
        runner = FakeRunner({"settings get global development_settings_enabled": "1\n"})
        f = check_dev_options(runner)
        self.assertEqual((f.status, f.severity), ("warn", LOW))

    def test_dev_options_default(self):
        self.assertEqual(check_dev_options(FakeRunner()).status, "pass")

    def test_adb_on_is_info(self):
        runner = FakeRunner({"settings get global adb_enabled": "1\n"})
        f = check_adb_enabled(runner)
        self.assertEqual((f.status, f.severity), ("info", INFO))

    def test_wireless_on(self):
        runner = FakeRunner({"settings get global adb_wifi_enabled": "1\n"})
        f = check_wireless_debug(runner)
        self.assertEqual((f.status, f.severity), ("warn", LOW))

    def test_verifier_off(self):
        runner = FakeRunner({"settings get global package_verifier_enable": "0\n"})
        f = check_verifier(runner)
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_verifier_on(self):
        runner = FakeRunner({"settings get global package_verifier_enable": "1\n"})
        self.assertEqual(check_verifier(runner).status, "pass")

    def test_verifier_unknown(self):
        self.assertEqual(check_verifier(FakeRunner()).status, "na")


class InstallUnknownTest(unittest.TestCase):
    KEY = "appops query-op REQUEST_INSTALL_PACKAGES allow"

    def test_allowed_apps(self):
        f = check_install_unknown(FakeRunner({self.KEY: "Package: com.foo\nPackage: com.bar.baz\n"}))
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("com.foo", f.detail)
        self.assertIn("com.bar.baz", f.detail)

    def test_none(self):
        self.assertEqual(check_install_unknown(FakeRunner()).status, "pass")


class BackupTest(unittest.TestCase):
    def test_enabled(self):
        f = check_backup(FakeRunner({"bmgr enabled": "Backup Manager currently enabled\n"}))
        self.assertEqual((f.status, f.severity), ("warn", LOW))

    def test_disabled(self):
        f = check_backup(FakeRunner({"bmgr enabled": "Backup Manager currently disabled\n"}))
        self.assertEqual(f.status, "pass")

    def test_unknown(self):
        self.assertEqual(check_backup(FakeRunner()).status, "na")


class RunDeviceChecksTest(unittest.TestCase):
    GOOD_PROPS = {
        "ro.build.version.release": "16",
        "ro.build.version.security_patch": "2026-09-05",
        "ro.crypto.state": "encrypted",
        "sys.oem_unlock_allowed": "0",
        "ro.boot.flash.locked": "1",
    }

    def test_all_checks_run(self):
        runner = FakeRunner({
            "getenforce": "Enforcing\n",
            "locksettings get-disabled": "false\n",
            "bmgr enabled": "Backup Manager currently disabled\n",
        })
        findings = run_device_checks(runner, self.GOOD_PROPS, TODAY)
        self.assertEqual(len(findings), 13)
        statuses = {f.status for f in findings}
        self.assertNotIn("fail", statuses)
        self.assertNotIn("error", statuses)

    def test_command_failure_becomes_na(self):
        from quaygate.adb import AdbError

        runner = FakeRunner({"getenforce": AdbError("boom")})
        findings = run_device_checks(runner, self.GOOD_PROPS, TODAY)
        selinux = next(f for f in findings if f.check_id == "selinux")
        self.assertEqual(selinux.status, "na")
        self.assertIn("boom", selinux.detail)


if __name__ == "__main__":
    unittest.main()
