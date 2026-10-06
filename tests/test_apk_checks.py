import unittest

from quaygate.apk import Apk, ApkError
from quaygate.appchecks import audit_apk, load_manifest
from quaygate.checks import HIGH, INFO, LOW, MEDIUM
from tests.helpers import temp_apk


def finding(findings, check_id):
    return next(f for f in findings if f.check_id == check_id)


class ApkAuditTest(unittest.TestCase):
    def test_clean_apk(self):
        with temp_apk(v1=True, v2=True) as path:
            meta, findings = audit_apk(Apk(path))
        self.assertEqual(meta["package"], "com.example")
        self.assertEqual(meta["targetSdk"], "34")
        self.assertNotIn("fail", {f.status for f in findings})
        ids = {f.check_id for f in findings}
        self.assertIn("app-debuggable", ids)
        self.assertIn("app-signature", ids)

    def test_debuggable(self):
        with temp_apk(app_over={"debuggable": "true"}) as path:
            f = finding(audit_apk(Apk(path))[1], "app-debuggable")
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_allowbackup(self):
        with temp_apk(app_over={"allowBackup": "true"}) as path:
            f = finding(audit_apk(Apk(path))[1], "app-allowbackup")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_cleartext_explicit(self):
        with temp_apk(app_over={"usesCleartextTraffic": "true"}) as path:
            f = finding(audit_apk(Apk(path))[1], "app-cleartext")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_cleartext_legacy_default(self):
        with temp_apk(app_over={"usesCleartextTraffic": None},
                      sdk_over={"targetSdkVersion": "27"}) as path:
            f = finding(audit_apk(Apk(path))[1], "app-cleartext")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))
        self.assertIn("기본값이 평문 허용", f.detail)

    def test_exported_unprotected(self):
        components = [("service", {"name": "com.example.Open", "exported": "true"}, [])]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-exported")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))
        self.assertIn("com.example.Open", f.detail)

    def test_exported_implicit_intent_filter(self):
        components = [
            ("activity", {"name": "com.example.Main"}, [
                ("intent-filter", {}, [("action", {"name": "android.intent.action.MAIN"}, [])]),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-exported")
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("com.example.Main", f.detail)

    def test_launcher_implicit_is_normal(self):
        components = [
            ("activity", {"name": "com.example.Main"}, [
                ("intent-filter", {}, [
                    ("action", {"name": "android.intent.action.MAIN"}, []),
                    ("category", {"name": "android.intent.category.LAUNCHER"}, []),
                ]),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-exported")
        self.assertEqual(f.status, "pass")
        self.assertIn("정상 공개", f.detail)

    def test_boot_receiver_implicit_is_normal(self):
        components = [
            ("receiver", {"name": "com.example.Boot"}, [
                ("intent-filter", {}, [
                    ("action", {"name": "android.intent.action.BOOT_COMPLETED"}, []),
                ]),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-exported")
        self.assertEqual(f.status, "pass")

    def test_action_view_receiver_not_exempted(self):
        """android.* 액션이라도 보호 브로드캐스트 목록 밖이면 도달 가능으로 분류."""
        components = [
            ("receiver", {"name": "com.example.Viewer"}, [
                ("intent-filter", {}, [("action", {"name": "android.intent.action.VIEW"}, [])]),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-exported")
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("com.example.Viewer", f.detail)

    def test_duplicate_application_flagged(self):
        """중복 <application> — 첫 선언(false)이 승리해 pass + 비정상 구조 경고."""
        tree = [
            ("manifest", {"package": "com.example"}, [
                ("application", {"debuggable": "false"}, []),
                ("application", {"debuggable": "true"}, []),
            ]),
        ]
        from tests.helpers import axml_document, build_apk
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            build_apk(path, axml_document(tree), v1=False)
            findings = audit_apk(Apk(path))[1]
            anomaly = finding(findings, "app-manifest-anomaly")
            self.assertEqual((anomaly.status, anomaly.severity), ("warn", MEDIUM))
            self.assertIn("중복 <application>", anomaly.detail)
            # 첫 선언(false) 승리 → pass (반대 순서는 test_duplicate_application_first_wins)
            self.assertEqual(finding(findings, "app-debuggable").status, "pass")
        finally:
            os.unlink(path)

    def test_custom_action_receiver_reachable(self):
        components = [
            ("receiver", {"name": "com.example.Push"}, [
                ("intent-filter", {}, [("action", {"name": "com.example.CUSTOM_PUSH"}, [])]),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-exported")
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("com.example.Push", f.detail)

    def test_deeplink_custom_scheme(self):
        components = [
            ("activity", {"name": "com.example.Link"}, [
                ("intent-filter", {"autoVerify": "false"}, [
                    ("action", {"name": "android.intent.action.VIEW"}, []),
                    ("category", {"name": "android.intent.category.BROWSABLE"}, []),
                    ("category", {"name": "android.intent.category.DEFAULT"}, []),
                    ("data", {"scheme": "myapp"}, []),
                ]),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-deeplink")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))
        self.assertIn("myapp", f.detail)

    def test_deeplink_http_unverified(self):
        components = [
            ("activity", {"name": "com.example.Link"}, [
                ("intent-filter", {}, [
                    ("action", {"name": "android.intent.action.VIEW"}, []),
                    ("category", {"name": "android.intent.category.BROWSABLE"}, []),
                    ("data", {"scheme": "https", "host": "example.com"}, []),
                ]),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-deeplink")
        self.assertEqual((f.status, f.severity), ("warn", LOW))

    def test_deeplink_verified_passes(self):
        components = [
            ("activity", {"name": "com.example.Link"}, [
                ("intent-filter", {"autoVerify": "true"}, [
                    ("action", {"name": "android.intent.action.VIEW"}, []),
                    ("category", {"name": "android.intent.category.BROWSABLE"}, []),
                    ("data", {"scheme": "https"}, []),
                ]),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-deeplink")
        self.assertEqual(f.status, "pass")
        self.assertIn("autoVerify", f.detail)

    def test_deeplink_absent(self):
        with temp_apk() as path:
            f = finding(audit_apk(Apk(path))[1], "app-deeplink")
        self.assertEqual(f.status, "pass")

    def test_provider_path_permission_naked_path(self):
        components = [
            ("provider", {"name": "com.example.P", "authorities": "ex", "exported": "true",
                          "permission": "com.example.perm"}, [
                ("path-permission", {"path": "/open"}, []),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-provider-paths")
        # 권한 없는 path-permission은 프레임워크가 무시 → '무보호' 단정 없이 정보
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("/open", f.detail)
        self.assertNotIn("무보호로 열립니다", f.detail)

    def test_provider_partial_protection(self):
        components = [
            ("provider", {"name": "com.example.P", "authorities": "ex", "exported": "true"}, [
                ("path-permission", {"pathPrefix": "/private",
                                     "readPermission": "com.example.perm"}, []),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-provider-paths")
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("com.example.P", f.detail)

    def test_provider_grant_via_child_element(self):
        components = [
            ("provider", {"name": "com.example.P", "authorities": "ex", "exported": "true"}, [
                ("grant-uri-permissions", {"pathPattern": ".*"}, []),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-provider-grant")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_provider_grant_uri_permissions(self):
        components = [
            ("provider", {"name": "com.example.OpenProvider", "authorities": "ex.auth",
                          "exported": "true", "grantUriPermissions": "true"}, []),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-provider-grant")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))
        self.assertIn("com.example.OpenProvider", f.detail)

    def test_dangerous_permissions(self):
        with temp_apk(perms=["android.permission.READ_SMS", "android.permission.CAMERA"]) as path:
            f = finding(audit_apk(Apk(path))[1], "app-permissions-dangerous")
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("READ_SMS", f.detail)

    def test_signature_v1_only(self):
        with temp_apk(v1=True, v2=False) as path:
            f = finding(audit_apk(Apk(path))[1], "app-signature")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_signature_v2_detected(self):
        with temp_apk(v1=True, v2=True) as path:
            f = finding(audit_apk(Apk(path))[1], "app-signature")
        self.assertEqual(f.status, "pass")

    def test_signature_missing(self):
        with temp_apk(v1=False, v2=False) as path:
            f = finding(audit_apk(Apk(path))[1], "app-signature")
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_target_sdk_tiers(self):
        with temp_apk(sdk_over={"targetSdkVersion": "22"}) as path:
            f = finding(audit_apk(Apk(path))[1], "app-target-sdk")
        self.assertEqual((f.status, f.severity), ("fail", HIGH))
        with temp_apk(sdk_over={"targetSdkVersion": "27"}) as path:
            f = finding(audit_apk(Apk(path))[1], "app-target-sdk")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))
        with temp_apk(sdk_over={"targetSdkVersion": "29"}) as path:
            f = finding(audit_apk(Apk(path))[1], "app-target-sdk")
        self.assertEqual((f.status, f.severity), ("warn", LOW))

    def test_dex_secret(self):
        with temp_apk(dex=["AKIAIOSFODNN7EXAMPLE"]) as path:
            f = finding(audit_apk(Apk(path))[1], "dex-secrets")
        self.assertEqual((f.status, f.severity), ("fail", HIGH))

    def test_dex_weak_crypto(self):
        with temp_apk(dex=["AES/ECB/PKCS5Padding"]) as path:
            f = finding(audit_apk(Apk(path))[1], "dex-weak-crypto")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_dex_http_url(self):
        with temp_apk(dex=["http://api.example.com/v1"]) as path:
            f = finding(audit_apk(Apk(path))[1], "dex-cleartext-urls")
        self.assertEqual((f.status, f.severity), ("warn", LOW))
        self.assertIn("api.example.com", f.detail)

    def test_dex_https_only_passes(self):
        with temp_apk(dex=["https://secure.example.com/v1"]) as path:
            f = finding(audit_apk(Apk(path))[1], "dex-cleartext-urls")
        self.assertEqual(f.status, "pass")

    def test_dex_tracker(self):
        with temp_apk(dex=["com.facebook.appevents.AppEventsLogger"]) as path:
            f = finding(audit_apk(Apk(path))[1], "dex-trackers")
        self.assertEqual((f.status, f.severity), ("info", INFO))

    def test_dex_code_precise_weak_crypto(self):
        from tests.helpers import build_code_dex
        code = build_code_dex([("Lcom/t/A;", "m0", "Ljava/security/MessageDigest;",
                                "getInstance", "MD5")])
        with temp_apk(files={"classes.dex": code}) as path:
            f = finding(audit_apk(Apk(path))[1], "dex-weak-crypto")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))
        self.assertIn("com.t.A", f.detail)
        self.assertIn("MD5", f.detail)
        self.assertIn("바이트코드", f.detail)

    def test_dex_code_safe_algo_passes(self):
        from tests.helpers import build_code_dex
        code = build_code_dex([("Lcom/t/B;", "m", "Ljava/security/MessageDigest;",
                                "getInstance", "SHA-256")])
        with temp_apk(files={"classes.dex": code}) as path:
            f = finding(audit_apk(Apk(path))[1], "dex-weak-crypto")
        self.assertEqual(f.status, "pass")

    def test_dex_dynamic_code_finding(self):
        from tests.helpers import build_code_dex
        code = build_code_dex([("Lcom/t/D;", "m", "Ldalvik/system/DexClassLoader;",
                                "<init>", None)])
        with temp_apk(files={"classes.dex": code}) as path:
            findings = audit_apk(Apk(path))[1]
        f = finding(findings, "dex-dynamic-code")
        self.assertEqual((f.status, f.severity), ("info", INFO))
        self.assertIn("DexClassLoader", f.detail)

    def test_native_hardening_execstack(self):
        from tests.helpers import build_elf64
        blob = build_elf64(execstack=True)
        with temp_apk(files={"lib/arm64-v8a/libtest.so": blob}) as path:
            f = finding(audit_apk(Apk(path))[1], "native-hardening")
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))
        self.assertIn("libtest.so", f.detail)

    def test_native_hardening_hardened_pass(self):
        from tests.helpers import build_elf64
        blob = build_elf64()
        with temp_apk(files={"lib/arm64-v8a/libtest.so": blob}) as path:
            f = finding(audit_apk(Apk(path))[1], "native-hardening")
        self.assertEqual(f.status, "pass")
        self.assertIn("RELRO full", f.detail)

    def test_native_absent(self):
        with temp_apk() as path:
            f = finding(audit_apk(Apk(path))[1], "native-hardening")
        self.assertEqual(f.status, "pass")
        self.assertIn("네이티브 라이브러리 없음", f.detail)

    def test_bool_reference_debuggable(self):
        """debuggable=\"@bool/dbg\" 참조 — arsc bool로 해석해 fail."""
        arsc = [("bool", ["dbg"])]
        with temp_apk(app_over={"debuggable": "@2130706432"},
                      arsc_types=[("xml", ["unused"]), ("bool", ["dbg"])],
                      files=None) as path:
            pass
        # 위 방식은 bool이 type 2가 되어 id가 다름 — 전용 플래그 조립
        from tests.helpers import build_arsc, manifest_tree, build_apk, axml_document
        import tempfile, os, zipfile
        # @<id>: (0x7F<<24)|(2<<16)|0 = 2130837504 — xml 타입을 앞에 두어 bool=2번
        fd, apk_path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        with zipfile.ZipFile(apk_path, "w") as z:
            z.writestr("AndroidManifest.xml", axml_document(
                manifest_tree({"debuggable": "@2130837504"})))
            z.writestr("resources.arsc",
                       build_arsc([("xml", ["unused"]), ("bool", ["dbg"])],
                                  bool_true_refs=("dbg",)))
        try:
            findings = audit_apk(Apk(apk_path))[1]
            self.assertEqual(finding(findings, "app-debuggable").status, "fail")
        finally:
            os.unlink(apk_path)

    def test_bool_reference_unresolvable_is_na(self):
        with temp_apk(app_over={"debuggable": "@999999999"}) as path:
            f = finding(audit_apk(Apk(path))[1], "app-debuggable")
        self.assertEqual(f.status, "na")
        self.assertIn("참조값", f.detail)

    def test_duplicate_application_first_wins(self):
        """첫 application debuggable=true + 둘째 false — 플랫폼 규칙대로 첫 선언 승리."""
        tree = [
            ("manifest", {"package": "com.example"}, [
                ("application", {"debuggable": "true"}, []),
                ("application", {"debuggable": "false"}, []),
            ]),
        ]
        from tests.helpers import axml_document, build_apk
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            build_apk(path, axml_document(tree), v1=False)
            findings = audit_apk(Apk(path))[1]
            self.assertEqual(finding(findings, "app-debuggable").status, "fail")
            self.assertIn("첫 선언 기준", finding(findings, "app-manifest-anomaly").detail)
        finally:
            os.unlink(path)

    def test_v2_only_cert_is_na(self):
        with temp_apk(v1=False, v2=True) as path:
            f = finding(audit_apk(Apk(path))[1], "app-cert")
        self.assertEqual(f.status, "na")
        self.assertIn("v2/v3 전용", f.detail)

    def test_corrupted_dex_all_fail_is_na(self):
        import tempfile, os, zipfile
        from tests.helpers import axml_document, manifest_tree
        fd, path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("AndroidManifest.xml",
                           axml_document(manifest_tree()))
                z.writestr("classes.dex", b"\x00\x00not a dex")
            findings = audit_apk(Apk(path))[1]
            self.assertEqual(finding(findings, "dex-scan").status, "na")
        finally:
            os.unlink(path)

    def test_aiza_is_embedded_key_not_secret(self):
        with temp_apk(dex=["AIza" + "A" * 35]) as path:
            findings = audit_apk(Apk(path))[1]
        self.assertEqual(finding(findings, "dex-secrets").status, "pass")
        emb = finding(findings, "dex-embedded-keys")
        self.assertEqual((emb.status, emb.severity), ("warn", MEDIUM))

    def test_explicit_exported_launcher_passes(self):
        components = [
            ("activity", {"name": "com.example.Main", "exported": "true"}, [
                ("intent-filter", {}, [
                    ("action", {"name": "android.intent.action.MAIN"}, []),
                    ("category", {"name": "android.intent.category.LAUNCHER"}, []),
                ]),
            ]),
        ]
        with temp_apk(components=components) as path:
            f = finding(audit_apk(Apk(path))[1], "app-exported")
        self.assertEqual(f.status, "pass")
        self.assertIn("정상 공개", f.detail)

    def test_protection_level_numeric(self):
        components = []
        from tests.helpers import axml_document, build_apk, manifest_tree
        import tempfile, os
        tree = [
            ("manifest", {"package": "com.t"}, [
                ("permission", {"name": "com.t.P0", "protectionLevel": "0"}, []),
                ("permission", {"name": "com.t.P1", "protectionLevel": "1"}, []),
                ("permission", {"name": "com.t.P2", "protectionLevel": "2"}, []),
                ("application", {}, components),
            ]),
        ]
        fd, path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            build_apk(path, axml_document(tree), v1=False)
            findings = audit_apk(Apk(path))[1]
            f = finding(findings, "app-custom-permissions")
            self.assertEqual((f.status, f.severity), ("info", INFO))
            self.assertIn("com.t.P0", f.detail)
            self.assertIn("com.t.P1", f.detail)
            self.assertNotIn("com.t.P2", f.detail)
        finally:
            os.unlink(path)

    def test_cert_runner_injection(self):
        """openssl 없이도 cert 판정 분기가 돌도록 러너 주입(호스트 의존 제거)."""
        from quaygate.checks import HIGH as _HIGH, LOW as _LOW

        def make_runner(out):
            def runner(args, data=None):
                if args[0] == "pkcs7":
                    return (0, "", "")
                return (0, out, "")
            return runner

        debug_runner = make_runner(
            "subject=CN = Android Debug, O = Android, C = US\nnotAfter=Jul 29 12:00:00 2048 GMT\n")
        with temp_apk() as path:
            f = finding(audit_apk(Apk(path), cert_runner=debug_runner)[1], "app-cert")
        self.assertEqual((f.status, f.severity), ("fail", _HIGH))

        expired_runner = make_runner(
            "subject=CN = old\nnotAfter=Jul 29 12:00:00 2020 GMT\n")
        with temp_apk() as path:
            f = finding(audit_apk(Apk(path), cert_runner=expired_runner)[1], "app-cert")
        self.assertEqual((f.status, f.severity), ("warn", _LOW))

        ok_runner = make_runner(
            "subject=CN = release@example.com\nnotAfter=Jul 29 12:00:00 2048 GMT\n")
        with temp_apk() as path:
            f = finding(audit_apk(Apk(path), cert_runner=ok_runner)[1], "app-cert")
        self.assertEqual(f.status, "pass")

    def test_missing_manifest(self):
        import tempfile
        import os
        import zipfile

        fd, path = tempfile.mkstemp(suffix=".apk")
        os.close(fd)
        try:
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("README", "empty")
            with self.assertRaises(ApkError):
                load_manifest(Apk(path))
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
