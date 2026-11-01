"""WEBVIEW-HOST-MATCH spares dot-anchored suffix checks only for domains a project can own.

Anyone can register a subdomain of a shared-hosting suffix such as `github.io`, so
`host.endsWith(".github.io")` still accepts attacker-controlled hosts.
"""

from __future__ import annotations

import re

import pytest

from mobile_audit import source_analysis
from mobile_audit.rules import rules
from mobile_audit.source_analysis import analyze_sources

RULE = next(rule for rule in rules() if rule["id"] == "WEBVIEW-HOST-MATCH")
PATTERN = re.compile(RULE["pattern"], 0 if RULE.get("case_sensitive") else re.I)


@pytest.mark.parametrize(
    "check",
    [
        'host.endsWith(".github.io")',
        'uri.host?.endsWith(".firebaseapp.com") == true',
        'url.host?.hasSuffix(".web.app") == true',
        'host.endsWith(".herokuapp.com")',
        'host.endsWith(".appspot.com")',
        'host.hasSuffix(".cloudfront.net")',
        'host.endsWith(".azurewebsites.net")',
        'host.endsWith(".netlify.app")',
        'host.endsWith(".vercel.app")',
        'host.endsWith(".pages.dev")',
        'host.endsWith(".workers.dev")',
        'host.endsWith(".amazonaws.com")',
        'host.endsWith(".s3.amazonaws.com")',
        'host.endsWith(".execute-api.us-east-1.amazonaws.com")',
        'host.endsWith(".blogspot.com")',
        'host.endsWith(".GitHub.IO")',
        'uri.host?.endsWith(".github.io", ignoreCase = true) == true',
    ],
)
def test_dot_anchored_shared_hosting_suffix_is_reported(check):
    assert PATTERN.search(check)


@pytest.mark.parametrize(
    "check",
    [
        'host.endsWith(".example.com")',
        'uri.host?.endsWith(".example.com") == true',
        'url.host?.hasSuffix(".example.com") == true',
        'host.endsWith(".myapp.github.io")',
        'host.endsWith(".github.io.example.com")',
        'host.endsWith(".web.application.example")',
        'host.endsWith(".pages.dev.example.com")',
    ],
)
def test_dot_anchored_owned_domain_suffix_is_spared(check):
    assert not PATTERN.search(check)


@pytest.mark.parametrize("check", ['host.endsWith("example.com")', 'host.hasSuffix("github.io")'])
def test_suffix_without_dot_boundary_is_still_reported(check):
    assert PATTERN.search(check)


def test_rule_and_engine_share_one_suffix_list():
    assert "(?!(?:" + source_analysis.SHARED_HOSTING_SUFFIXES + ')\\"))' in RULE["pattern"]


KOTLIN = """package a
import android.content.Intent
import android.webkit.WebView
class Loader(private val web: WebView) {
    fun open(intent: Intent) {
        val uri = intent.data!!
        if (uri.scheme == "https" && uri.host?.endsWith("SUFFIX") == true) {
            web.loadUrl(uri.toString())
        }
    }
}
"""
SWIFT = """import class UIKit.UIScene
import class Foundation.NSUserActivity
import class WebKit.WKWebView
import struct Foundation.URLRequest
class Links {
    let webView: WKWebView
    init(webView: WKWebView) { self.webView = webView }
    func scene(_ scene: UIScene, continue userActivity: NSUserActivity) {
        guard let url = userActivity.webpageURL, url.scheme == "https", url.host?.hasSuffix("SUFFIX") == true
        else { return }
        webView.load(URLRequest(url: url))
    }
}
"""
REPORTED = {"AST-WEBVIEW-UNTRUSTED-URL", "AST-WEBVIEW-HOST-ALLOWLIST"}


@pytest.mark.parametrize(
    ("path", "template"), [("app/Loader.kt", KOTLIN), ("App/Links.swift", SWIFT)], ids=["kotlin", "swift"]
)
@pytest.mark.parametrize(
    ("suffix", "expected"),
    [(".example.com", set()), (".myapp.github.io", set()), (".github.io", REPORTED), (".web.app", REPORTED)],
    ids=["owned", "owned-under-shared", "github-io", "web-app"],
)
def test_engine_credits_dot_anchored_suffix_only_for_owned_domains(path, template, suffix, expected):
    report = analyze_sources([(path, template.replace("SUFFIX", suffix))])
    assert {item["rule_id"] for item in report["findings"]} & REPORTED == expected
    assert report["metadata"]["native_flow"]["state"] == "checked"
