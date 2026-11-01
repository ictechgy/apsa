"""Swift `if`/`guard` condition clauses run in source order.

Each comma-separated clause sees the names bound and the checks passed by the
clauses before it, like `&&`. `if let` names end with the branch, `guard let`
names stay bound after the statement, and a guard's else body runs from the
state before the guard. Fixtures resolve every type through explicit imports so
the bounded native flow stays complete and a missing finding is a real credit.
"""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

UNTRUSTED = {"AST-WEBVIEW-UNTRUSTED-URL"}
ALLOWLIST = {"AST-WEBVIEW-HOST-ALLOWLIST"}
IMPORTS = """import class UIKit.UIScene
import class UIKit.UIOpenURLContext
import class Foundation.NSUserActivity
import class WebKit.WKWebView
import class WebKit.WKNavigationAction
import enum WebKit.WKNavigationActionPolicy
import struct Foundation.URLRequest
import struct Foundation.URL
"""
ACTIVITY = (
    IMPORTS
    + """class Links {
    let webView: WKWebView
    var ok = false
    init(webView: WKWebView) { self.webView = webView }
    func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
        BODY
    }
}
"""
)
SCENE = ACTIVITY.replace(
    "continue userActivity: NSUserActivity", "openURLContexts URLContexts: Set<UIOpenURLContext>"
)
NAVIGATION = (
    IMPORTS
    + """class Policy {
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        BODY
        decisionHandler(.cancel)
    }
}
"""
)
CHECKS = 'url.scheme == "https", url.host == "example.com"'
SAFE = 'URL(string: "https://example.com/help")'
LOAD = "webView.load(URLRequest(url: url))"
LINK = "userActivity.webpageURL"


def analyze(template: str, body: str) -> tuple[set[str], str]:
    source = template.replace("BODY", body.replace("\n", "\n        "))
    report = analyze_sources([("App/Links.swift", source)])
    return {item["rule_id"] for item in report["findings"]}, report["metadata"]["native_flow"]["state"]


CASES = [
    # 1. Checks after an `if let` apply to the bound value, like the same checks on a local.
    ("plain-if-clauses", f"let url = {LINK}!\nif {CHECKS} {{ {LOAD} }}", set()),
    ("if-let-checked", f"if let url = {LINK}, {CHECKS} {{ {LOAD} }}", set()),
    ("if-let-scheme-only", f'if let url = {LINK}, url.scheme == "https" {{ {LOAD} }}', UNTRUSTED),
    ("if-let-unchecked", f"if let url = {LINK} {{ {LOAD} }}", UNTRUSTED),
    # A type annotation is not an initializer; `if let x` / `guard let x` unwrap the outer x.
    ("if-let-typed", f"if let url: URL = {LINK}, ok {{ {LOAD} }}", UNTRUSTED),
    ("if-let-shorthand", f"let url = {LINK}\nif let url, ok {{ {LOAD} }}", UNTRUSTED),
    ("if-let-shorthand-checked", f"let url = {LINK}\nif let url, {CHECKS} {{ {LOAD} }}", set()),
    ("guard-let-shorthand", f"let url = {LINK}\nguard let url, ok else {{ return }}\n{LOAD}", UNTRUSTED),
    (
        "guard-let-shorthand-checked",
        f"let url = {LINK}\nguard let url, {CHECKS} else {{ return }}\n{LOAD}",
        set(),
    ),
    (
        "if-let-checked-else-exits",
        f"let raw = {LINK}\nif let url = raw, {CHECKS} {{ }} else {{ return }}\nwebView.load(URLRequest(url: raw!))",
        set(),
    ),
    (
        "checks-before-the-binding",
        f"let url = {SAFE}!\nif {CHECKS}, let url = {LINK} {{ {LOAD} }}",
        UNTRUSTED,
    ),
    # 2. A binding initializer sees the earlier bindings of the same statement.
    (
        "if-let-chain",
        f"if let raw = {LINK}, let url = URL(string: raw.absoluteString) {{ {LOAD} }}",
        UNTRUSTED,
    ),
    (
        "if-let-chain-checked",
        f"if let raw = {LINK}, let url = URL(string: raw.absoluteString), {CHECKS} {{ {LOAD} }}",
        set(),
    ),
    (
        "guard-let-chain",
        f"guard let raw = {LINK}, let url = URL(string: raw.absoluteString) else {{ return }}\n{LOAD}",
        UNTRUSTED,
    ),
    ("if-case-pattern", f"if case let .some(url) = {LINK} {{ {LOAD} }}", UNTRUSTED),
    ("if-case-inner-binding", f"if case .some(let url) = {LINK} {{ {LOAD} }}", UNTRUSTED),
    # 3. A guard's else body is analyzed from the state before the guard.
    ("guard-else-body", f"let url = {LINK}!\nguard ok else {{ {LOAD}; return }}", UNTRUSTED),
    (
        "guard-else-body-is-not-checked",
        f"let url = {LINK}!\nguard {CHECKS} else {{ {LOAD}; return }}",
        UNTRUSTED,
    ),
    (
        "guard-else-body-sees-outer-name",
        f"let url = {SAFE}!\nguard let url = {LINK} else {{ {LOAD}; return }}",
        set(),
    ),
    ("guard-continuation-checked", f"let url = {LINK}!\nguard {CHECKS} else {{ return }}\n{LOAD}", set()),
    ("guard-let-checked", f"guard let url = {LINK}, {CHECKS} else {{ return }}\n{LOAD}", set()),
    # 5. Scoping and clause order.
    ("guard-let-unchecked", f"guard let url = {LINK} else {{ return }}\n{LOAD}", UNTRUSTED),
    (
        "guard-later-binding-replaces-checked-one",
        f"guard let url = {SAFE}, {CHECKS}, let url = {LINK} else {{ return }}\n{LOAD}",
        UNTRUSTED,
    ),
    (
        "if-let-shadow-does-not-check-outer-name",
        f"let url = {LINK}!\nif let url = {SAFE}, {CHECKS} {{ }} else {{ return }}\n{LOAD}",
        UNTRUSTED,
    ),
    (
        "if-let-shadow-with-body",
        f"let url = {LINK}!\nif let url = {SAFE}, {CHECKS} {{ ok = url.isFileURL }} else {{ return }}\n{LOAD}",
        UNTRUSTED,
    ),
    (
        "if-let-binding-ends-with-branch",
        f"let url = {SAFE}!\nif let url = {LINK} {{ ok = url.isFileURL }}\n{LOAD}",
        set(),
    ),
    (
        "guard-let-binding-ends-with-block",
        f"let url = {SAFE}!\ndo {{\n    guard let url = {LINK} else {{ return }}\n    ok = url.isFileURL\n}}\n{LOAD}",
        set(),
    ),
]


@pytest.mark.parametrize(("body", "expected"), [case[1:] for case in CASES], ids=[case[0] for case in CASES])
def test_swift_clauses_run_in_source_order(body, expected):
    rules, state = analyze(ACTIVITY, body)
    assert rules == expected
    assert state == "checked"


@pytest.mark.parametrize(
    "body",
    [
        "let u = URLContexts.first!.url\nguard ok else { webView.load(URLRequest(url: u)); return }",
        "if let raw = URLContexts.first?.url, let target = URL(string: raw.absoluteString) "
        "{ webView.load(URLRequest(url: target)) }",
        "if case .some(let u) = URLContexts.first?.url { webView.load(URLRequest(url: u)) }",
    ],
    ids=["guard-else-body", "if-let-chain", "if-case-pattern"],
)
def test_scene_url_context_reaches_sinks_through_clauses(body):
    assert analyze(SCENE, body)[0] == UNTRUSTED


def test_scene_url_context_checks_match_the_plain_form():
    # `URLContexts.first` is not modeled as a URL, so no form credits checks on it; the
    # binding form must report exactly what the equivalent local does.
    bound = analyze(SCENE, f"if let url = URLContexts.first?.url, {CHECKS} {{ {LOAD} }}")[0]
    plain = analyze(SCENE, f"let url = URLContexts.first!.url\nif {CHECKS} {{ {LOAD} }}")[0]
    assert bound == plain == UNTRUSTED


POLICY_CASES = [
    ("single-condition", 'if navigationAction.request.url?.host?.contains("example.com") == true', ALLOWLIST),
    (
        "clauses",
        'if navigationAction.request.url != nil, navigationAction.request.url?.host?.contains("example.com") == true',
        ALLOWLIST,
    ),
    (
        "if-let-contains",
        'if let url = navigationAction.request.url, url.host?.contains("example.com") == true',
        ALLOWLIST,
    ),
    ("if-let-host-equals", 'if let url = navigationAction.request.url, url.host == "example.com"', set()),
]


@pytest.mark.parametrize(
    ("condition", "expected"), [case[1:] for case in POLICY_CASES], ids=[case[0] for case in POLICY_CASES]
)
@pytest.mark.parametrize("decision", [".allow", ".cancel"])
def test_navigation_policy_reads_every_boolean_clause(condition, expected, decision):
    rules, state = analyze(NAVIGATION, f"{condition} {{ decisionHandler({decision}); return }}")
    assert rules == (expected if decision == ".allow" else set())
    assert state == "checked"
