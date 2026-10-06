import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date

from quaygate import cli
from quaygate.adb import AdbError
from quaygate.checks import HIGH, Finding
from quaygate.report import exit_code, render_json, render_text, summarize
from tests.helpers import temp_apk, temp_ipa


def make_getprop_text():
    month = f"{date.today().month:02d}"
    patch = f"{date.today().year}-{month}-01"
    return "\n".join([
        "[ro.build.version.release]: [16]",
        "[ro.build.version.sdk]: [36]",
        f"[ro.build.version.security_patch]: [{patch}]",
        "[ro.product.manufacturer]: [Google]",
        "[ro.product.model]: [Pixel Test]",
        "[ro.crypto.state]: [encrypted]",
        "[sys.oem_unlock_allowed]: [0]",
        "[ro.boot.flash.locked]: [1]",
    ]) + "\n"


GOOD_RESPONSES = {
    "getprop": make_getprop_text(),
    "getenforce": "Enforcing\n",
    "locksettings get-disabled": "false\n",
    "bmgr enabled": "Backup Manager currently disabled\n",
    "pm list packages -3": "package:com.example.app\n",
    "dumpsys package com.example.app": (
        "versionCode=101 minSdk=24 targetSdk=34\n"
        "installerPackageName=com.android.vending\n"
        "pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]\n"
    ),
}


class FakeRunner:
    def __init__(self, responses=None, state="device"):
        self.responses = dict(responses or {})
        self.state = state

    def shell(self, *args):
        key = " ".join(args)
        value = self.responses.get(key)
        if isinstance(value, Exception):
            raise value
        if value is not None:
            return value
        if args and args[0] == "settings":
            return "null\n"
        return ""

    def get_state(self):
        if isinstance(self.state, Exception):
            raise self.state
        return self.state


def run_main(argv, runner):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(argv, runner=runner)
    return code, out.getvalue(), err.getvalue()


class ReportTest(unittest.TestCase):
    def test_fail_sorts_before_pass(self):
        findings = [
            Finding("b", "통과항목", "pass", None),
            Finding("a", "심각항목", "fail", HIGH, "심각 내용"),
        ]
        text = render_text("테스트기기", findings)
        self.assertLess(text.index("심각항목"), text.index("통과항목"))
        self.assertIn("심각 내용", text)
        self.assertIn("요약:", text)

    def test_summarize(self):
        findings = [
            Finding("a", "t", "fail", HIGH),
            Finding("b", "t", "warn", HIGH),
            Finding("c", "t", "warn", HIGH),
            Finding("d", "t", "pass", None),
        ]
        self.assertEqual(summarize(findings), {"fail": 1, "warn": 2, "info": 0, "na": 0, "error": 0, "pass": 1})

    def test_exit_code(self):
        self.assertEqual(exit_code([Finding("a", "t", "warn", HIGH)]), 0)
        self.assertEqual(exit_code([Finding("a", "t", "fail", HIGH)]), 1)

    def test_render_json(self):
        findings = [Finding("a", "t", "fail", HIGH, "d", "r"), Finding("b", "t", "pass", None)]
        payload = json.loads(render_json({"model": "Pixel Test"}, findings))
        self.assertEqual(payload["tool"], "apsa")
        self.assertEqual(payload["target"]["model"], "Pixel Test")
        self.assertEqual(payload["summary"]["fail"], 1)
        self.assertEqual([f["check_id"] for f in payload["findings"]], ["a", "b"])


class DeviceCliTest(unittest.TestCase):
    def test_good_run_json(self):
        code, out, err = run_main(["device", "--json"], FakeRunner(GOOD_RESPONSES))
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["target"]["model"], "Pixel Test")
        self.assertEqual(payload["summary"]["fail"], 0)
        ids = {f["check_id"] for f in payload["findings"]}
        self.assertIn("patch-level", ids)
        self.assertIn("apps-debuggable", ids)

    def test_fail_run_exit_1(self):
        responses = dict(GOOD_RESPONSES, **{"locksettings get-disabled": "true\n"})
        code, out, err = run_main(["device"], FakeRunner(responses))
        self.assertEqual(code, 1)
        self.assertIn("잠금 화면", out)

    def test_skip_apps(self):
        responses = dict(GOOD_RESPONSES)
        responses.pop("pm list packages -3")
        code, out, err = run_main(["device", "--skip-apps"], FakeRunner(responses))
        self.assertEqual(code, 0)
        self.assertNotIn("apps-debuggable", out)

    def test_unauthorized_device(self):
        code, out, err = run_main(["device"], FakeRunner(GOOD_RESPONSES, state="unauthorized"))
        self.assertEqual(code, 2)
        self.assertIn("기기가 준비되지 않았습니다", err)

    def test_adb_error(self):
        code, out, err = run_main(["device"], FakeRunner({"getprop": AdbError("boom")}))
        self.assertEqual(code, 2)
        self.assertIn("adb 오류", err)


class AppCliTest(unittest.TestCase):
    def test_apk_cli_json(self):
        with temp_apk(v2=True) as path:
            code, out, err = run_main(["apk", path, "--json"], None)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["target"]["package"], "com.example")
        self.assertEqual(payload["summary"]["fail"], 0)

    def test_apk_cli_text_fail(self):
        with temp_apk(app_over={"debuggable": "true"}, v1=False) as path:
            code, out, err = run_main(["apk", path], None)
        self.assertEqual(code, 1)
        self.assertIn("디버그 모드", out)

    def test_apk_cli_corrupted_zip_exit_2(self):
        """CRC/압축 손상 — traceback 대신 exit 2와 한 줄 오류(P2-8 회귀)."""
        import tempfile, os, zipfile
        from tests.helpers import axml_document, manifest_tree
        fd, path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            import random
            random.seed(42)
            blob = bytes(random.randrange(256) for _ in range(8192))  # 난수 — 압축 안 됨
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("AndroidManifest.xml", blob[:2048])
                z.writestr("classes.dex", blob)
            raw = bytearray(open(path, "rb").read())
            for i in range(400, min(3000, len(raw) - 100), 7):  # deflate 훼손
                raw[i] ^= 0xFF
            open(path, "wb").write(bytes(raw))
            code, out, err = run_main(["apk", path], None)
            self.assertEqual(code, 2)
            self.assertNotIn("Traceback", err)
            self.assertTrue(err.strip())
        finally:
            os.unlink(path)

    def test_apk_cli_bad_file(self):
        code, out, err = run_main(["apk", "/nonexistent.apk"], None)
        self.assertEqual(code, 2)
        self.assertIn("APK 점검 실패", err)

    def test_ipa_cli(self):
        with temp_ipa() as path:
            code, out, err = run_main(["ipa", path, "--json"], None)
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["target"]["bundle_id"], "com.example.app")

    def test_ipa_cli_bad_file(self):
        code, out, err = run_main(["ipa", "/nonexistent.ipa"], None)
        self.assertEqual(code, 2)
        self.assertIn("IPA 점검 실패", err)


class SarifCliTest(unittest.TestCase):
    def test_apk_sarif(self):
        with temp_apk(app_over={"debuggable": "true"}, v1=False) as path:
            code, out, err = run_main(["apk", path, "--sarif"], None)
        self.assertEqual(code, 1)
        payload = json.loads(out)
        self.assertEqual(payload["version"], "2.1.0")
        results = payload["runs"][0]["results"]
        self.assertTrue(results)
        self.assertTrue(all(r["level"] in ("error", "warning", "note") for r in results))
        rule_ids = {r["ruleId"] for r in results}
        self.assertIn("app-debuggable", rule_ids)
        rules = payload["runs"][0]["tool"]["driver"]["rules"]
        self.assertIn("app-debuggable", {r["id"] for r in rules})
        uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        import os.path
        self.assertEqual(uri, os.path.basename(path))  # 절대 경로 노출 방지(basename)

    def test_device_sarif(self):
        responses = dict(GOOD_RESPONSES, **{"bmgr enabled": "Backup Manager currently enabled\n"})
        code, out, err = run_main(["device", "--sarif"], FakeRunner(responses))
        self.assertEqual(code, 0)
        payload = json.loads(out)
        results = payload["runs"][0]["results"]
        self.assertTrue(results)
        self.assertEqual(results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "device")

    def test_sarif_excludes_pass_and_na(self):
        from quaygate.checks import Finding
        from quaygate.report import render_sarif
        out = render_sarif("x.apk", [
            Finding("a", "통과", "pass", None),
            Finding("b", "경고", "warn", "LOW", "d"),
        ])
        payload = json.loads(out)
        self.assertEqual([r["ruleId"] for r in payload["runs"][0]["results"]], ["b"])


if __name__ == "__main__":
    unittest.main()
