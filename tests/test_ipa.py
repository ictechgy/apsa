import unittest

from quaygate.checks import HIGH, INFO, LOW, MEDIUM
from quaygate.ipa import Ipa, audit_ipa, macho_cryptid
from tests.helpers import build_macho, temp_ipa


def finding(findings, check_id):
    return next(f for f in findings if f.check_id == check_id)


class MachoCryptidTest(unittest.TestCase):
    def test_thin_plain(self):
        self.assertEqual(macho_cryptid(build_macho()), 0)

    def test_thin_encrypted(self):
        self.assertEqual(macho_cryptid(build_macho(cryptid=1)), 1)

    def test_fat_plain(self):
        self.assertEqual(macho_cryptid(build_macho(cryptid=0, fat=True)), 0)

    def test_fat_encrypted(self):
        self.assertEqual(macho_cryptid(build_macho(cryptid=1, fat=True)), 1)

    def test_not_macho(self):
        self.assertIsNone(macho_cryptid(b"\x00" * 64))

    def test_short(self):
        self.assertIsNone(macho_cryptid(b"\xca\xfe\xba"))


class IpaAuditTest(unittest.TestCase):
    def test_clean_ipa(self):
        with temp_ipa() as path:
            meta, findings = audit_ipa(Ipa(path))
        self.assertEqual(meta["bundle_id"], "com.example.app")
        self.assertNotIn("fail", {f.status for f in findings})

    def test_ats_disabled(self):
        with temp_ipa(plist_over={"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-ats")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_min_os_old(self):
        with temp_ipa(plist_over={"MinimumOSVersion": "13.0"}) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-min-os")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_file_sharing(self):
        with temp_ipa(plist_over={"UIFileSharingEnabled": True}) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-file-sharing")
        self.assertEqual((f.status, f.severity), ("info", INFO))

    def test_url_schemes(self):
        with temp_ipa(plist_over={"CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}]}) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-url-schemes")
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("myapp", f.detail)

    def test_binary_indicators(self):
        binary = b"\x00http://plain.example/x\x00AKIAIOSFODNN7EXAMPLE\x00https://ok.example\x00"
        with temp_ipa(binary=binary) as path:
            findings = audit_ipa(Ipa(path))[1]
        f = finding(findings, "bin-secrets")
        self.assertEqual((f.status, f.severity), ("fail", HIGH))
        f = finding(findings, "bin-cleartext-urls")
        self.assertEqual((f.status, f.severity), ("warn", LOW))
        self.assertIn("plain.example", f.detail)

    def test_hardening_pass(self):
        from tests.helpers import build_macho
        with temp_ipa(binary=build_macho()) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-binary-hardening")
        self.assertEqual(f.status, "pass")

    def test_hardening_no_pie(self):
        from tests.helpers import build_macho
        with temp_ipa(binary=build_macho(pie=False)) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-binary-hardening")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_hardening_no_canary(self):
        from tests.helpers import build_macho
        with temp_ipa(binary=build_macho(canary=False)) as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-binary-hardening")
        self.assertEqual((f.status, f.severity), ("warn", LOW))

    def test_hardening_not_macho_na(self):
        with temp_ipa(binary=b"\x00plain bytes\x00") as path:
            f = finding(audit_ipa(Ipa(path))[1], "ipa-binary-hardening")
        self.assertEqual(f.status, "na")

    def test_streaming_beyond_limit(self):
        """상한 뒤의 시크릿/카나리도 스트리밍으로 검출(P2-5 회귀)."""
        import quaygate.ipa as ipa_mod
        old_limit = ipa_mod.BINARY_SCAN_LIMIT
        ipa_mod.BINARY_SCAN_LIMIT = 64 * 1024
        try:
            binary = (b"\x00" * 100_000 + b"AKIAIOSFODNN7EXAMPLE\x00"
                      + b"\x00" * 50_000 + b"___stack_chk_fail\x00")
            with temp_ipa(binary=binary) as path:
                findings = audit_ipa(Ipa(path))[1]
        finally:
            ipa_mod.BINARY_SCAN_LIMIT = old_limit
        self.assertEqual(finding(findings, "bin-secrets").status, "fail")
        self.assertIn("스트리밍", finding(findings, "bin-secrets").detail)  # 스캔 범위 표기

    def test_binary_clean(self):
        binary = b"\x00https://ok.example/api\x00com.example.Model\x00"
        with temp_ipa(binary=binary) as path:
            findings = audit_ipa(Ipa(path))[1]
        self.assertEqual(finding(findings, "bin-secrets").status, "pass")

    def test_encrypted_binary_skips_scan(self):
        binary = build_macho(cryptid=1) + b"http://plain.example\x00AKIAIOSFODNN7EXAMPLE\x00"
        with temp_ipa(binary=binary) as path:
            findings = audit_ipa(Ipa(path))[1]
        ids = {f.check_id for f in findings}
        self.assertIn("bin-scan", ids)
        self.assertNotIn("bin-secrets", ids)
        self.assertNotIn("bin-cleartext-urls", ids)
        self.assertEqual(finding(findings, "bin-scan").status, "na")


if __name__ == "__main__":
    unittest.main()
