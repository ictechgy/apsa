"""WEBVIEW-HOST-MATCH spares dot-anchored suffix checks only for domains a project can own.

Anyone can register a subdomain of a shared-hosting suffix such as `github.io`, so
`host.endsWith(".github.io")` still accepts attacker-controlled hosts.
"""

from __future__ import annotations

import re
import time

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
    exemption = "(?!(?:" + source_analysis.SHARED_HOSTING_SUFFIXES + ')\\")[\\w-]+(?:\\.[\\w-]+)+\\")'
    assert exemption in RULE["pattern"]


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


ADDED_SHARED = [
    ".storage.googleapis.com",
    ".firebasestorage.app",
    ".z13.web.core.windows.net",
    ".nyc3.digitaloceanspaces.com",
    ".ondigitalocean.app",
    ".r2.dev",
    ".up.railway.app",
    ".deno.dev",
    ".pythonanywhere.com",
    ".repl.co",
    ".azurefd.net",
]
PUBLIC = [".com", ".app", ".io", ".co.uk", ".org.uk", ".com.au", ".co.jp", ".co.kr", ".com.br", ".co.in"]
PUBLIC += [
    ".pe.kr",
    ".or.kr",
    ".ne.kr",
    ".go.kr",
    ".ac.kr",
    ".re.kr",
    ".com.vn",
    ".co.th",
    ".com.my",
    ".com.ph",
]


@pytest.mark.parametrize("suffix", ADDED_SHARED + PUBLIC)
def test_bare_or_public_dot_suffix_is_reported_by_the_rule(suffix):
    assert PATTERN.search(f'uri.host?.endsWith("{suffix}") == true')


@pytest.mark.parametrize(
    "suffix",
    [
        ".example.co.uk",
        ".example.com.au",
        ".shop.example.app",
        ".example.io",
        ".example.pe.kr",
        ".example.co.th",
    ],
)
def test_registrable_dot_suffix_under_a_public_one_is_spared(suffix):
    assert not PATTERN.search(f'uri.host?.endsWith("{suffix}") == true')


@pytest.mark.parametrize(
    ("path", "template"), [("app/Loader.kt", KOTLIN), ("App/Links.swift", SWIFT)], ids=["kotlin", "swift"]
)
@pytest.mark.parametrize(
    ("suffix", "expected"),
    [(".com", REPORTED), (".co.uk", REPORTED), (".r2.dev", REPORTED), (".example.co.uk", set())],
    ids=["tld", "country-second-level", "added-shared-host", "registrable"],
)
def test_engine_does_not_credit_a_public_suffix(path, template, suffix, expected):
    report = analyze_sources([(path, template.replace("SUFFIX", suffix))])
    assert {item["rule_id"] for item in report["findings"]} & REPORTED == expected


# Providers that issue hostnames one zone below their suffix: anyone can deploy under the zone.
PROVIDER_ZONES = [
    ".a.run.app",
    ".us-central1.run.app",
    ".uc.r.appspot.com",
    ".r.appspot.com",
    ".us-east-1.elasticbeanstalk.com",
    ".eastus2.azurestaticapps.net",
    ".2.azurestaticapps.net",
    ".eastus-01.azurewebsites.net",
    ".westeurope.cloudapp.azure.com",
    ".eu.ngrok.io",
]
OWNED_UNDER_ZONES = [
    ".svc-123.us-central1.run.app",
    ".myproject.appspot.com",
    ".myenv.us-east-1.elasticbeanstalk.com",
    ".gentle-sky.eastus2.azurestaticapps.net",
    ".myapp.azurewebsites.net",
    ".myname.ngrok.io",
]


@pytest.mark.parametrize("suffix", PROVIDER_ZONES)
def test_provider_zone_suffix_is_reported(suffix):
    assert PATTERN.search(f'uri.host?.endsWith("{suffix}") == true')
    assert not source_analysis.Analyzer.owned_suffix(suffix[1:])


@pytest.mark.parametrize("suffix", OWNED_UNDER_ZONES)
def test_owned_host_under_a_provider_zone_is_spared(suffix):
    assert not PATTERN.search(f'uri.host?.endsWith("{suffix}") == true')
    assert source_analysis.Analyzer.owned_suffix(suffix[1:])


@pytest.mark.parametrize(
    ("suffix", "expected"), [(".a.run.app", REPORTED), (".svc-123.us-central1.run.app", set())]
)
def test_engine_does_not_credit_a_provider_zone(suffix, expected):
    report = analyze_sources([("App/Links.swift", SWIFT.replace("SUFFIX", suffix))])
    assert {item["rule_id"] for item in report["findings"]} & REPORTED == expected


@pytest.mark.parametrize(
    "text",
    [
        'host.endsWith(".' + "a." * 100_000 + 'run.ap")',
        'host.endsWith(".' + "a" * 200_000 + '.r.appspot.co")',
        'host.endsWith(".x.r.appspot.co' * 7_000,
    ],
    ids=["many-labels", "long-label", "many-checks"],
)
def test_suffix_exemption_stays_linear(text):
    started = time.perf_counter()
    PATTERN.findall(text)
    assert time.perf_counter() - started < 1.0
