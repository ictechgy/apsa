import unittest

from quaygate.apk import Apk
from quaygate.checks import HIGH, INFO, LOW, MEDIUM, Finding
from quaygate.ipa import Ipa, audit_ipa, macho_cryptid
from quaygate.report import render_sarif, render_text, _sanitize
from tests.helpers import build_arsc, build_elf64, build_fat64, build_macho, temp_apk, temp_ipa


def finding(findings, check_id):
    return next(f for f in findings if f.check_id == check_id)


class SarifWarnVisibilityTest(unittest.TestCase):
    """P2-1 — warn/info가 GitHub Code Scanning에서 숨겨지지 않아야 한다."""

    def test_warn_level(self):
        import json
        out = render_sarif("a.apk", [Finding("app-cleartext", "평문", "warn", "MEDIUM", "d")])
        r = json.loads(out)["runs"][0]["results"][0]
        self.assertEqual((r["level"], r["kind"]), ("warning", "fail"))

    def test_info_level(self):
        import json
        out = render_sarif("a.apk", [Finding("x", "정보", "info", "INFO", "d")])
        r = json.loads(out)["runs"][0]["results"][0]
        self.assertEqual((r["level"], r["kind"]), ("note", "fail"))

    def test_fail_level(self):
        import json
        out = render_sarif("a.apk", [Finding("y", "심각", "fail", "HIGH", "d")])
        r = json.loads(out)["runs"][0]["results"][0]
        self.assertEqual((r["level"], r["kind"]), ("error", "fail"))


class LogForgeryTest(unittest.TestCase):
    """P2-8 — APK 유래 문자열로 리포트 줄을 위조할 수 없어야 한다."""

    def test_sanitize_strips_newline_ansi(self):
        cleaned = _sanitize("Evil\n\x1b[32m[통과]\x1b[0m\r")
        self.assertNotIn("\n", cleaned)
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("[32m", cleaned)
        self.assertNotIn("\r", cleaned)

    def test_render_text_single_line(self):
        evil = Finding("app-exported", "외부 공개", "warn", MEDIUM,
                       "activity com.x.Evil\n\x1b[32m[통과] app-debuggable\x1b[0m · 요약: 심각 0")
        text = render_text("t", [evil])
        for line in text.splitlines():
            if "Evil" in line:
                self.assertIn("com.x.Evil", line)
                # 위조 문구가 같은 줄에 평문으로만 남고, 별도 줄/색 코드로 위조되지 않음
                self.assertNotIn("\x1b", line)


class Fat64Test(unittest.TestCase):
    """P2-6 — FAT64(0xCAFEBABF) 슬라이스의 cryptid를 감지해야 한다."""

    def test_fat64_cryptid_detected(self):
        self.assertEqual(macho_cryptid(build_fat64(cryptid=1)), 1)
        self.assertEqual(macho_cryptid(build_fat64(cryptid=0)), 0)

    def test_fat64_ipa_marks_bin_na(self):
        binary = build_fat64(cryptid=1)
        with temp_ipa(binary=binary) as path:
            f = finding(audit_ipa(Ipa(path))[1], "bin-scan")
        self.assertEqual(f.status, "na")
        self.assertIn("FairPlay", f.detail)


class AbiOrderTest(unittest.TestCase):
    """P2-7 — ZIP 엔트리 순서와 무관하게 전 ABI를 검사해야 한다."""

    def test_vulnerable_second_abi_caught(self):
        import os, tempfile, zipfile
        from tests.helpers import axml_document, manifest_tree
        for order in (["armeabi-v7a", "arm64-v8a"], ["arm64-v8a", "armeabi-v7a"]):
            fd, path = tempfile.mkstemp(suffix=".apk")
            os.close(fd)
            try:
                with zipfile.ZipFile(path, "w") as z:
                    z.writestr("AndroidManifest.xml", axml_document(manifest_tree()))
                    for abi in order:
                        blob = build_elf64(execstack=True) if abi == "arm64-v8a" else build_elf64()
                        z.writestr(f"lib/{abi}/libtest.so", blob)
                f = finding(audit_apk(Apk(path))[1], "native-hardening")
                self.assertEqual((f.status, f.severity), ("warn", MEDIUM), order)
                self.assertIn("arm64-v8a", f.detail)
            finally:
                os.unlink(path)


class NscReferenceCleartextTest(unittest.TestCase):
    """P2-3 — NSC cleartextTrafficPermitted 참조값 해석."""

    NSC_TRUE = [("network-security-config", {}, [
        ("base-config", {"cleartextTrafficPermitted": "@2130837504"}, []),
    ])]

    def test_reference_true_flags(self):
        import os, tempfile, zipfile
        from tests.helpers import axml_document, manifest_tree
        fd, path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("AndroidManifest.xml", axml_document(
                    manifest_tree({"networkSecurityConfig": "@xml/network_security_config"})))
                # (0x7F<<24)|(2<<16)|0 = 2130837504 — bool 타입 2번
                z.writestr("resources.arsc",
                           build_arsc([("xml", ["network_security_config"]), ("bool", ["cleartext"])],
                                      bool_true_refs=("cleartext",)))
                z.writestr("res/xml/network_security_config.xml",
                           axml_document(self.NSC_TRUE))
            f = finding(audit_apk(Apk(path))[1], "app-cleartext")
            self.assertEqual((f.status, f.severity), ("warn", MEDIUM))
        finally:
            os.unlink(path)

    def test_reference_unresolvable_is_na(self):
        nsc = [("network-security-config", {}, [
            ("base-config", {"cleartextTrafficPermitted": "@999999999"}, []),
        ])]
        with temp_apk(app_over={"networkSecurityConfig": "@xml/network_security_config"},
                      nsc=nsc) as path:
            f = finding(audit_apk(Apk(path))[1], "app-cleartext")
        self.assertEqual(f.status, "na")


class AtsDomainsTest(unittest.TestCase):
    """P2-9 — ATS 도메인 평문 예외와 iOS10+ 범위 한정."""

    def test_insecure_domain_warns(self):
        over = {"NSAppTransportSecurity": {"NSExceptionDomains": {
            "legacy.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}}}}
        with temp_ipa(plist_over=over) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-ats-domains")
        self.assertEqual((f.status, f.severity), ("warn", LOW))
        self.assertIn("legacy.example.com", f.detail)

    def test_web_content_scope_limited(self):
        over = {"NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True, "NSAllowsArbitraryLoadsInWebContent": True}}
        with temp_ipa(plist_over=over) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-ats")
        self.assertEqual((f.status, f.severity), ("warn", LOW))
        self.assertIn("무시", f.detail)


class MultidexPartialFailureTest(unittest.TestCase):
    """P2-2 — 일부 DEX CRC 손상이 전체 크래시가 아닌 부분 실패여야 한다."""

    def test_partial_dex_failure(self):
        import os, random, tempfile, zipfile
        from tests.helpers import axml_document, build_dex, manifest_tree
        random.seed(7)
        fd, path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            blob = bytes(random.randrange(256) for _ in range(4096))
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("AndroidManifest.xml", axml_document(manifest_tree()))
                z.writestr("classes.dex", build_dex(["com.example.A"]))
                z.writestr("classes2.dex", blob)
            with open(path, "rb") as fh:
                raw = bytearray(fh.read())
            quarter = len(raw) // 4
            for i in range(quarter, quarter + 300, 5):  # 데이터 영역 — CD/EOCD는 보존
                raw[i] ^= 0xFF
            open(path, "wb").write(bytes(raw))
            meta, findings = audit_apk(Apk(path))
            self.assertTrue(findings)  # 전체 크래시 아님
            scan = [f for f in findings if f.check_id == "dex-scan"]
            self.assertTrue(any(f.status in ("na", "info") for f in scan))
        finally:
            os.unlink(path)


class GetTaskAllowTest(unittest.TestCase):
    """P3-9 — 개발 서명(get-task-allow) 감지."""

    def test_dev_signature_fails(self):
        import plistlib as _pl
        prov = (b"garbage-prefix" + _pl.dumps({"Entitlements": {"get-task-allow": True}})
                + b"suffix")
        with temp_ipa(binary=build_macho(), provisioning=prov) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-get-task-allow")
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_absent_profile_cannot_establish_release_entitlements(self):
        with temp_ipa(binary=build_macho()) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-get-task-allow")
        self.assertEqual(f.status, "na")


from quaygate.appchecks import audit_apk  # noqa: E402  (테스트 파일 내 늦은 import)

if __name__ == "__main__":
    unittest.main()
