import unittest

from quaygate.adb import AdbError
from quaygate.apps import (
    HIGH, INFO, LOW, MEDIUM, AppInfo, audit_apps, collect_apps,
    list_third_party, parse_package_dump,
)


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = dict(responses or {})

    def shell(self, *args):
        key = " ".join(args)
        value = self.responses.get(key)
        if isinstance(value, Exception):
            raise value
        return value if value is not None else ""


DUMP_NORMAL = """Package [com.example.app] (10301):
  userId=10301
  pkg=Package{abc com.example.app}
  codePath=/data/app/~~x==/com.example.app-y==
  versionCode=101 minSdk=24 targetSdk=34
  firstInstallTime=2026-01-02 00:00:00
  installerPackageName=com.android.vending
  pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]
  privateFlags=[ PRIVATE_FLAG_RESIZEABLE_ACTIVITIES ]
"""
DUMP_DEBUG_OLD = DUMP_NORMAL.replace("targetSdk=34", "targetSdk=22") \
    .replace("pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]",
             "pkgFlags=[ HAS_CODE DEBUGGABLE ]") \
    .replace("installerPackageName=com.android.vending", "installerPackageName=null")
DUMP_LEGACY = DUMP_NORMAL.replace("targetSdk=34", "targetSdk=27") \
    .replace("installerPackageName=com.android.vending", "installerPackageName=null")
DUMP_LOW_TIER = DUMP_NORMAL.replace("targetSdk=34", "targetSdk=29")
DUMP_OLD_FORMAT = DUMP_NORMAL.replace("targetSdk=34", "targetSdkVersion=28")


class ListTest(unittest.TestCase):
    def test_parse_sorted_unique(self):
        runner = FakeRunner({"pm list packages -3": "package:com.b\npackage:com.a\npackage:com.b\n"})
        self.assertEqual(list_third_party(runner), ["com.a", "com.b"])


class ParseTest(unittest.TestCase):
    def test_normal(self):
        app = parse_package_dump("com.example.app", DUMP_NORMAL)
        self.assertEqual(app.name, "com.example.app")
        self.assertEqual(app.target_sdk, 34)
        self.assertFalse(app.debuggable)
        self.assertEqual(app.installer, "com.android.vending")

    def test_old_field_name(self):
        self.assertEqual(parse_package_dump("x", DUMP_OLD_FORMAT).target_sdk, 28)

    def test_debuggable_and_null_installer(self):
        app = parse_package_dump("com.example.app", DUMP_DEBUG_OLD)
        self.assertTrue(app.debuggable)
        self.assertEqual(app.target_sdk, 22)
        self.assertIsNone(app.installer)

    def test_installer_field_absent_not_sideloaded(self):
        """installerPackageName 필드 자체가 없으면(미매칭) sideload로 단언하지 않음."""
        app = parse_package_dump("com.empty", "installerPackageName is not here\n")
        self.assertFalse(app.installer_present)
        findings = audit_apps([app], [])
        f = next(x for x in findings if x.check_id == "apps-sideloaded")
        self.assertEqual(f.status, "pass")

    def test_missing_everything(self):
        app = parse_package_dump("com.empty", "")
        self.assertEqual((app.target_sdk, app.debuggable, app.installer), (None, False, None))


class CollectTest(unittest.TestCase):
    def test_partial_failure(self):
        runner = FakeRunner({
            "dumpsys package com.good": DUMP_NORMAL,
            "dumpsys package com.bad": AdbError("boom"),
        })
        infos, errors = collect_apps(runner, ["com.bad", "com.good"])
        self.assertEqual([a.name for a in infos], ["com.good"])
        self.assertEqual(errors, ["com.bad"])


class AuditTest(unittest.TestCase):
    def _one(self, **kw):
        base = dict(name="com.t", target_sdk=34, debuggable=False, installer="com.android.vending")
        base.update(kw)
        return AppInfo(**base)

    def test_debuggable_fails(self):
        findings = audit_apps([self._one(debuggable=True)], [])
        f = next(x for x in findings if x.check_id == "apps-debuggable")
        self.assertEqual((f.status, f.severity), ("fail", HIGH))
        self.assertIn("com.t", f.detail)

    def test_target_tier_fail(self):
        f = next(x for x in audit_apps([self._one(target_sdk=22)], []) if x.check_id == "apps-target-sdk")
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_target_tier_medium(self):
        f = next(x for x in audit_apps([self._one(target_sdk=27)], []) if x.check_id == "apps-target-sdk")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_target_tier_low(self):
        f = next(x for x in audit_apps([self._one(target_sdk=29)], []) if x.check_id == "apps-target-sdk")
        self.assertEqual((f.status, f.severity), ("warn", LOW))

    def test_target_tier_pass_with_unknown_note(self):
        findings = audit_apps([self._one(), self._one(target_sdk=None)], [])
        f = next(x for x in findings if x.check_id == "apps-target-sdk")
        self.assertEqual(f.status, "pass")
        self.assertIn("확인 불가 1개", f.detail)

    def test_sideloaded_info(self):
        f = next(x for x in audit_apps([self._one(installer=None)], []) if x.check_id == "apps-sideloaded")
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("com.t", f.detail)

    def test_clean_pass(self):
        findings = audit_apps([self._one()], [])
        self.assertTrue(all(f.status == "pass" for f in findings))

    def test_errors_reported(self):
        f = next(x for x in audit_apps([], ["com.x"]) if x.check_id == "apps-errors")
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("com.x", f.detail)


if __name__ == "__main__":
    unittest.main()
