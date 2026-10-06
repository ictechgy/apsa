import unittest

from quaygate.apk import Apk
from quaygate.appchecks import audit_apk
from quaygate.axml import parse_axml
from quaygate.network_security import analyze, load
from tests.helpers import axml_document, temp_apk


def finding(findings, check_id):
    return next(f for f in findings if f.check_id == check_id)


def nsc_tree(base_attrs=None, domain_configs=None, debug_overrides=False, user_anchor=False):
    base_children = [("trust-anchors", {}, [
        ("certificates", {"src": "user" if user_anchor else "system"}, []),
    ])]
    base = ("base-config", base_attrs or {}, base_children)
    children = [base] + (domain_configs or [])
    if debug_overrides:
        children.append(("debug-overrides", {}, [
            ("trust-anchors", {}, [("certificates", {"src": "user"}, [])]),
        ]))
    return [("network-security-config", {}, children)]


def with_ref(app_extra=None):
    attrs = {"networkSecurityConfig": "@xml/network_security_config"}
    attrs.update(app_extra or {})
    return attrs


class AnalyzeTest(unittest.TestCase):
    def test_base_false_domain_exception(self):
        tree = nsc_tree({"cleartextTrafficPermitted": "false"}, [
            ("domain-config", {"cleartextTrafficPermitted": "true"}, [
                ("domain", {"includeSubdomains": "true"}, ["mirror.example.com"]),
                ("domain", {}, ["dl.example.com"]),
            ]),
        ])
        result = analyze(parse_axml(axml_document(tree)))
        self.assertIs(result["base_cleartext"], False)
        self.assertEqual(result["cleartext_domains"], ["mirror.example.com", "dl.example.com"])
        self.assertFalse(result["user_trust"])
        self.assertFalse(result["debug_overrides"])

    def test_base_true(self):
        result = analyze(parse_axml(axml_document(
            nsc_tree({"cleartextTrafficPermitted": "true"}))))
        self.assertIs(result["base_cleartext"], True)
        self.assertEqual(result["cleartext_domains"], [])

    def test_base_undeclared(self):
        result = analyze(parse_axml(axml_document(nsc_tree())))
        self.assertIsNone(result["base_cleartext"])

    def test_user_anchor_and_debug_overrides(self):
        tree = nsc_tree({"cleartextTrafficPermitted": "false"},
                        debug_overrides=True, user_anchor=True)
        result = analyze(parse_axml(axml_document(tree)))
        self.assertTrue(result["user_trust"])
        self.assertTrue(result["debug_overrides"])

    def test_user_anchor_inside_debug_only_not_flagged(self):
        tree = nsc_tree({"cleartextTrafficPermitted": "false"}, debug_overrides=True)
        result = analyze(parse_axml(axml_document(tree)))
        self.assertFalse(result["user_trust"])
        self.assertTrue(result["debug_overrides"])


class LoadTest(unittest.TestCase):
    def test_resolves_and_parses(self):
        tree = nsc_tree({"cleartextTrafficPermitted": "false"})
        with temp_apk(app_over=with_ref(), nsc=tree) as path:
            events, error = load(Apk(path), with_ref())
        self.assertIsNone(error)
        self.assertTrue(events)

    def test_missing_entry(self):
        with temp_apk(app_over=with_ref()) as path:
            events, error = load(Apk(path), with_ref())
        self.assertIsNone(events)
        self.assertIn("엔트리 없음", error)

    def test_resource_id_form_unresolved(self):
        with temp_apk() as path:
            events, error = load(Apk(path), {"networkSecurityConfig": "@2131951691"})
        self.assertIsNone(events)
        self.assertIn("리소스 ID", error)

    def test_resource_id_resolved_via_arsc(self):
        tree = nsc_tree({"cleartextTrafficPermitted": "false"})
        # 0x7F010000 = (0x7F<<24)|(1<<16)|0 = 2130771968 → 패키지 0x7F, 타입 1(xml), 엔트리 0
        with temp_apk(app_over={"networkSecurityConfig": "@2130771968"},
                      arsc_types=[("xml", ["network_security_config"])], nsc=tree) as path:
            events, error = load(Apk(path), {"networkSecurityConfig": "@2130771968"})
        self.assertIsNone(error)
        self.assertTrue(events)

    def test_obfuscated_path_via_value(self):
        """경로 난독화 재현 — res/qK.xml로 저장하고 arsc 값에 실제 경로를 둔다."""
        tree = nsc_tree({"cleartextTrafficPermitted": "false"})
        with temp_apk(app_over={"networkSecurityConfig": "@2130771968"},
                      arsc_types=[("xml", ["network_security_config"])],
                      arsc_paths={"network_security_config": "res/qK.xml"},
                      files={"res/qK.xml": axml_document(tree)}) as path:
            events, error = load(Apk(path), {"networkSecurityConfig": "@2130771968"})
        self.assertIsNone(error)
        self.assertTrue(events)

    def test_resource_id_non_xml_type(self):
        # 0x7F020000 = 2130837504 → 타입 2(string)
        with temp_apk(app_over={"networkSecurityConfig": "@2130837504"},
                      arsc_types=[("xml", ["unused"]), ("string", ["oops"])]) as path:
            events, error = load(Apk(path), {"networkSecurityConfig": "@2130837504"})
        self.assertIsNone(events)
        self.assertIn("xml 타입이 아님", error)


class IntegrationTest(unittest.TestCase):
    def test_cleartext_overridden_by_policy(self):
        # manifest는 true지만 정책 파일이 차단 — 정책 파일이 이긴다
        tree = nsc_tree({"cleartextTrafficPermitted": "false"})
        with temp_apk(app_over=with_ref({"usesCleartextTraffic": "true"}), nsc=tree) as path:
            f = finding(audit_apk(Apk(path))[1], "app-cleartext")
        self.assertEqual(f.status, "pass")
        self.assertIn("networkSecurityConfig", f.detail)

    def test_domain_exception_low_severity(self):
        tree = nsc_tree({"cleartextTrafficPermitted": "false"}, [
            ("domain-config", {"cleartextTrafficPermitted": "true"}, [
                ("domain", {}, ["legacy.example.com"]),
            ]),
        ])
        with temp_apk(app_over=with_ref(), nsc=tree) as path:
            f = finding(audit_apk(Apk(path))[1], "app-cleartext")
        from quaygate.checks import INFO, LOW
        self.assertEqual((f.status, f.severity), ("warn", LOW))
        self.assertIn("legacy.example.com", f.detail)

    def test_user_trust_finding(self):
        tree = nsc_tree({"cleartextTrafficPermitted": "false"}, user_anchor=True)
        with temp_apk(app_over=with_ref(), nsc=tree) as path:
            f = finding(audit_apk(Apk(path))[1], "app-nsc-user-trust")
        from quaygate.checks import MEDIUM
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_debug_overrides_finding(self):
        tree = nsc_tree({"cleartextTrafficPermitted": "false"}, debug_overrides=True)
        with temp_apk(app_over=with_ref(), nsc=tree) as path:
            f = finding(audit_apk(Apk(path))[1], "app-nsc-debug-overrides")
        from quaygate.checks import INFO as _INFO
        self.assertEqual((f.status, f.severity), ("info", _INFO))  # debuggable 아님 → 릴리스 무시
        with temp_apk(app_over=with_ref({"debuggable": "true"}), nsc=tree) as path:
            f = finding(audit_apk(Apk(path))[1], "app-nsc-debug-overrides")
        from quaygate.checks import MEDIUM
        self.assertEqual((f.status, f.severity), ("warn", MEDIUM))

    def test_no_ref_uses_manifest_logic(self):
        with temp_apk(app_over={"usesCleartextTraffic": "true"}) as path:
            findings = audit_apk(Apk(path))[1]
        ids = {f.check_id for f in findings}
        self.assertNotIn("app-nsc-user-trust", ids)
        self.assertNotIn("app-nsc-debug-overrides", ids)


if __name__ == "__main__":
    unittest.main()
