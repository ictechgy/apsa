from __future__ import annotations

import json

import pytest

from mobile_audit import hybrid_analysis
from mobile_audit.hybrid_analysis import _bindings, _tokens, analyze_hybrid
from mobile_audit.platform_checks import _network_security_config, _secrets
from mobile_audit.rules import static_checks
from mobile_audit.sensitive_logging import sensitive_log_matches

URL = "HYBRID-UNTRUSTED-URL"
LOG = "STORAGE-SENSITIVE-LOG"
TRUST = "SOURCE-TRUST-ALL-CERTS"
INVENTORY = {"input_kind": "source", "platforms": ["android", "ios"], "android_config": [], "ios_config": []}


def matches(findings: list[dict], rule: str) -> list[dict]:
    return [item for item in findings if item["rule_id"] == rule]


def test_summary_exhaustion_cannot_starve_direct_hybrid_emission():
    sources = [
        (
            "00-critical.js",
            'function relay(value) { return "safe"; }\nfunction source() { return route.params.fromHelper; }\nweb.loadUrl(route.params.url);\nweb.loadUrl(relay(route.params.other));\nweb.loadUrl(source());',
        )
    ]
    sources.extend((f"filler{index}.js", "padding;" * 40000) for index in range(4))
    report = analyze_hybrid(sources)
    assert sum(item.get("tokens", 0) for item in report["metadata"]["files"]) > 300000
    assert len(matches(report["findings"], URL)) == 3, report["warnings"]
    assert any("budget" in warning for warning in report["warnings"])
    assert all(item["state"] == "partial" for item in report["coverage"])
    operations = report["metadata"]["operations"]
    assert operations["total"] <= operations["max_total"] == hybrid_analysis.MAX_OPERATIONS
    assert operations["summaries_complete"] is False


@pytest.mark.parametrize(
    "path,declaration",
    [
        ("App.ts", "const url: string = route.params.url;"),
        ("App.ts", "let url: Foo<Bar> = route.params.url;"),
        ("main.dart", 'final String url = Uri.base.queryParameters["url"];'),
        ("main.dart", 'String url = Uri.base.queryParameters["url"];'),
        ("App.js", 'let url = "safe"; url += route.params.url;'),
        ("App.js", 'let url = "safe"; url ||= route.params.url;'),
        ("App.js", 'let url = "safe"; url ??= route.params.url;'),
    ],
)
def test_typed_or_compound_assignment_retains_hybrid_input(path, declaration):
    report = analyze_hybrid([(path, declaration + " web.loadUrl(url);")])
    assert matches(report["findings"], URL), report


def test_member_assignment_does_not_taint_unrelated_bare_local():
    report = analyze_hybrid(
        [("App.js", 'let url = "safe"; object.url = route.params.url; web.loadUrl(url);')]
    )
    assert not matches(report["findings"], URL), report


def test_completed_closed_helper_summary_keeps_existing_safe_control():
    report = analyze_hybrid(
        [("App.js", 'function clean(value) { return "safe"; } web.loadUrl(clean(route.params.url));')]
    )
    assert not matches(report["findings"], URL), report


def test_declaration_binding_scan_stops_at_enclosing_block():
    class CountedTokens(list):
        reads = 0

        def __getitem__(self, key):
            self.reads += 1
            assert self.reads <= 20 * len(self), "declaration binding work is not linear in token count"
            return super().__getitem__(key)

    tokens = CountedTokens(_tokens("{" * 100 + "var name}" * 100 + "[value] " * 1000))
    assert "name" in _bindings(tokens)
    assert tokens.reads <= 20 * len(tokens)


def test_binding_budget_failure_is_explicit_without_raising_caps(monkeypatch):
    monkeypatch.setattr(hybrid_analysis, "MAX_OPERATIONS", 4)
    report = analyze_hybrid([("App.js", "const first = 1; const second = 2; web.loadUrl(route.params.url);")])
    assert any("declaration binding operation budget" in warning for warning in report["warnings"])
    assert report["metadata"]["files"][0]["analysis_state"] == "skipped"
    assert all(item["state"] == "partial" for item in report["coverage"])


def test_for_await_body_retains_enclosing_input_binding():
    report = analyze_hybrid(
        [("App.js", "const url = route.params.url; for await (const item of stream) { web.loadUrl(url); }")]
    )
    assert matches(report["findings"], URL), report


@pytest.mark.parametrize("other", ["missing", "compiled", "unresolved", "malformed"])
def test_nsc_coverage_tracks_every_module_reference(other):
    inventory = {
        "platforms": ["android"],
        "android_config": [
            {
                "path": "app/src/main/AndroidManifest.xml",
                "network_security_config": "@xml/nsc",
                "target_sdk": 36,
            },
            {
                "path": "wear/src/main/AndroidManifest.xml",
                "network_security_config": "unresolved-resource" if other == "unresolved" else "@xml/nsc",
                "target_sdk": 36,
            },
        ],
    }
    sources = [
        (
            "app/src/main/res/xml/nsc.xml",
            '<network-security-config><base-config><trust-anchors><certificates src="user"/></trust-anchors></base-config></network-security-config>',
        )
    ]
    if other == "compiled":
        sources.append(("wear/src/main/res/xml/nsc.xml", "binary-resource"))
    elif other == "malformed":
        sources.append(("wear/src/main/res/xml/nsc.xml", "<network-security-config>"))
    findings, coverage = _network_security_config(inventory, sources)
    assert matches(findings, "ANDROID-NSC-USER-CA")
    assert all(item["state"] == "partial" for item in coverage), coverage


def test_nsc_all_references_read_remains_checked():
    inventory = {
        "platforms": ["android"],
        "android_config": [
            {"path": f"{module}/src/main/AndroidManifest.xml", "network_security_config": "@xml/nsc"}
            for module in ("app", "wear")
        ],
    }
    sources = [
        (f"{module}/src/main/res/xml/nsc.xml", "<network-security-config/>") for module in ("app", "wear")
    ]
    _, coverage = _network_security_config(inventory, sources)
    assert all(item["state"] == "checked" for item in coverage)


@pytest.mark.parametrize("body", ["{}", "{ return; }"])
@pytest.mark.parametrize(
    "throws",
    ["", "throws CertificateException", "throws java.security.cert.CertificateException, OtherException"],
)
def test_trust_all_java_override_covers_throws_and_noop_return(body, throws):
    source = f"class Trust implements X509TrustManager {{ public void checkServerTrusted(X509Certificate[] chain, String authType) {throws} {body} }}"
    findings, _ = static_checks(INVENTORY, [("Trust.java", source)])
    assert matches(findings, TRUST), findings


@pytest.mark.parametrize(
    "body", ["{ throw new CertificateException(); }", "{ platform.checkServerTrusted(chain, authType); }"]
)
def test_trust_all_pattern_does_not_bless_throw_or_delegate_as_empty(body):
    source = f"class Trust implements X509TrustManager {{ public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {body} }}"
    findings, _ = static_checks(INVENTORY, [("Trust.java", source)])
    assert not matches(findings, TRUST)


@pytest.mark.parametrize("suffix", [".js", ".jsx", ".ts", ".tsx", ".dart", ".jsbundle"])
def test_hybrid_secret_formats_are_scanned_and_remain_masked(suffix):
    secret = "AKIA" + "A" * 16
    findings, coverage = _secrets(
        [("Native.java", "class Native {}"), ("config" + suffix, f'const credential = "{secret}";')]
    )
    assert matches(findings, "SOURCE-HARDCODED-SECRET")
    assert coverage[0]["state"] == "checked"
    assert secret not in json.dumps(findings)


def test_non_sensitive_js_does_not_need_an_ast_parse(monkeypatch):
    from mobile_audit import sensitive_logging_js

    def unexpected(*args, **kwargs):
        raise AssertionError("marker-free source should not invoke an AST parser")

    monkeypatch.setattr(sensitive_logging_js, "ast_sensitive_log_matches", unexpected)
    result = sensitive_log_matches("console.log('ready'); const broken = ;", ".js")
    assert not result.spans and not result.uncertain


@pytest.mark.parametrize("path", ["assets/index.android.bundle", "assets/main.jsbundle", "ios/Source.mm"])
def test_sensitive_log_suffixes_cover_admitted_bundle_and_objcpp(path):
    findings, _ = static_checks(
        INVENTORY, [(path, "console.log(password);" if not path.endswith(".mm") else "NSLog(password);")]
    )
    assert matches(findings, LOG), findings


def test_unknown_bundle_is_not_admitted_by_suffix_alone():
    findings, coverage = static_checks(INVENTORY, [("unknown.bundle", "console.log(password);")])
    assert not matches(findings, LOG)
    assert next(item for item in coverage if item["rule_id"] == LOG)["state"] == "not-run"


def test_rule_excerpt_uses_same_line_boundaries_as_location():
    source = "int padding = 0;\fclass Trust implements X509TrustManager { void checkServerTrusted(Object[] c, String t) {} }"
    findings, _ = static_checks(INVENTORY, [("Trust.java", source)])
    item = matches(findings, TRUST)[0]
    assert item["evidence"][0]["line"] == 1
    assert "checkServerTrusted" in item["evidence"][0]["excerpt"]
