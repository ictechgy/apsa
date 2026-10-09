"""Regression contracts for source compatibility and bounded Apple branch decisions."""

import copy
import json
from pathlib import Path

import pytest

from mobile_audit.audit import correlate
from mobile_audit.intel import normalize_cve
from mobile_audit.ios_ranges import apple_branch_range, numeric_version, official_reference
from mobile_audit.parser_compat import kotlin_tokens
from mobile_audit.source_analysis import analyze_sources

PRIMARY = Path(__file__).parents[1] / "benchmarks/real_world_advisories.json"


def apple_records(version="18.3.2", product="iOS"):
    document = json.loads(PRIMARY.read_text())["cna"]["CVE-2025-24201"]
    cve = normalize_cve(document)
    references = {"18.3.2": "122281", "16.7.11": "122346", "15.8.4": "122345", "17.7.6": "122372"}
    vendor = {
        "source": "apple",
        "platform": "ios",
        "id": cve["id"],
        "title": "WebKit",
        "component": "WebKit",
        "fixed_release": product + " " + version,
        "references": ["https://support.apple.com/en-us/" + references[version]],
    }
    return cve, vendor


def state(cve, vendor, version, **environment):
    findings, advisories = correlate(
        {"dependencies": [], "platforms": ["ios"]},
        [cve, vendor],
        {"platform": "ios", "version": version, **environment},
    )
    return advisories[0]["state"], findings


@pytest.mark.parametrize("fixed,old", [("18.3.2", "18.3.1"), ("16.7.11", "16.7.10"), ("15.8.4", "15.8.3")])
def test_published_apple_branch_requires_cna_and_matching_bulletin(fixed, old):
    cve, vendor = apple_records(fixed)
    observed, findings = state(cve, vendor, old)
    assert observed == "version-affected"
    assert findings[0]["reachability"] == "unknown" and findings[0]["reproduced"] is False
    assert state(cve, vendor, fixed)[0] == "outside-published-affected-range"
    assert state(cve, vendor, "26.0")[0] == "applicability-unknown"


@pytest.mark.parametrize(
    "mutation",
    [
        "assigner",
        "provider",
        "vendor",
        "source",
        "reference",
        "fixed",
        "missing",
        "ambiguous",
        "changes",
        "lower",
        "inclusive",
        "unknown",
    ],
)
def test_unconfirmed_or_ambiguous_apple_branches_abstain(mutation):
    cve, vendor = apple_records()
    product = next(p for p in cve["affected"] if p["product"] == "iOS and iPadOS")
    entry = product["versions"][-1]
    if mutation == "assigner":
        cve["assigner_org_id"] = "other"
    elif mutation == "provider":
        cve["cna_org_id"] = "other"
    elif mutation == "vendor":
        product["vendor"] = "other"
    elif mutation == "source":
        vendor["source"] = "other"
    elif mutation == "reference":
        vendor["references"] = ["https://support.apple.com.evil.test/en-us/122281"]
    elif mutation == "fixed":
        vendor["fixed_release"] = "iOS 18.3.3"
    elif mutation == "missing":
        cve.pop("assigner_org_id")
    elif mutation == "ambiguous":
        product["versions"].append({**entry, "lessThan": "18.4.1"})
    elif mutation == "changes":
        entry["changes"] = [{"at": "18.3.1", "status": "unaffected"}]
    elif mutation == "lower":
        entry["version"] = "n/a"
    elif mutation == "inclusive":
        entry["lessThanOrEqual"] = entry.pop("lessThan")
    elif mutation == "unknown":
        entry["lessThan"] = "unpublished"
    assert apple_branch_range("18.3.1", product, cve, vendor, "ios") is None


def test_ipados_only_branch_requires_explicit_os_product():
    cve, vendor = apple_records("17.7.6", "iPadOS")
    assert state(cve, vendor, "17.7.5")[0] == "applicability-unknown"
    assert state(cve, vendor, "17.7.5", os_product="ipados")[0] == "version-affected"
    assert state(cve, vendor, "17.7.6", os_product="ipados")[0] == "outside-published-affected-range"
    assert state(cve, vendor, "17.7.5", simulator=True, os_product="ipados")[0] == "simulator-only"
    assert state(cve, vendor, "17.7.5", os_product=[])[0] == "applicability-unknown"


@pytest.mark.parametrize(
    "version", [None, [], "18.3.1beta", "v18.3.1", "018.3.1", "18", "18.3.1.1.1", "1" * 5000 + ".0", "１８.3"]
)
def test_malformed_or_unordered_os_versions_abstain(version):
    assert numeric_version(version) is None


@pytest.mark.parametrize(
    "url",
    [
        "https://[",
        "http://support.apple.com/1",
        "https://user@support.apple.com/1",
        "https://support.apple.com:443/1",
        "https://support.apple.com/1?q=x",
        "https://evil.test/1",
    ],
)
def test_only_exact_official_bulletin_references_confirm_custom_branches(url):
    assert not official_reference(url)


@pytest.mark.parametrize("field", ["assignerOrgId", "providerMetadata"])
def test_cna_identity_shape_is_validated(field):
    doc = json.loads(PRIMARY.read_text())["cna"]["CVE-2025-24201"]
    if field == "assignerOrgId":
        doc["cveMetadata"][field] = []
    else:
        doc["containers"]["cna"][field] = []
    with pytest.raises(ValueError):
        normalize_cve(doc)


def test_swift_nonisolated_local_variable_recovers_flow_and_original_offsets():
    source = """import WebKit
class LinkHandler {
 let browser = WKWebView()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {
  nonisolated(unsafe) let destination = incoming
  browser.load(URLRequest(url: destination))
 }
}"""
    report = analyze_sources([("App.swift", source)])
    assert report["metadata"]["functions"] == {"observed": 1, "analyzed": 1, "skipped": 0, "without_body": 0}
    assert report["coverage"][0]["state"] == "partial"
    assert not report["metadata"]["function_inventory_complete"]
    finding = next(f for f in report["findings"] if f["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL")
    assert finding["evidence"][0]["line"] == 6
    assert finding["evidence"][0]["offset"] == source.encode().index(b"browser.load")
    assert "browser.load" in finding["evidence"][0]["excerpt"]
    assert finding["status"] == "candidate"
    assert "App.swift" not in report["pattern_exclusions"]


def test_kotlin_open_identifier_preserves_modifier_and_source_identity():
    source = """open class LinkHandler {
 private val browser = WebView(context)
 private var open = false
 @Synchronized
 open fun open(incoming: Intent) {
   if (open) { return }
   val destination = incoming.getStringExtra("destination")
   browser.loadUrl(destination!!)
   open = true
 }
}"""
    report = analyze_sources([("App.kt", source)])
    assert report["metadata"]["functions"]["analyzed"] == 1
    assert report["coverage"][0]["state"] == "partial"
    item = next(f for f in report["findings"] if f["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL")
    assert item["evidence"][0]["function"] == "open"
    assert item["evidence"][0]["line"] == 8
    assert item["evidence"][0]["offset"] == source.encode().index(b"browser.loadUrl")


def test_compatibility_tokens_keep_comments_strings_backticks_and_unicode_opaque():
    raw = b'/* open /* nested open */ open */ "open" """open""" `open` \'o\' // open\nopen'
    assert [v for v, _, _ in kotlin_tokens(raw)].count(b"open") == 1
    raw = "éopen opené open".encode()
    assert [v for v, _, _ in kotlin_tokens(raw)].count(b"open") == 1


@pytest.mark.parametrize("raw", [b'"open', b"/* open", b"`open"])
def test_unterminated_compatibility_literals_fail_closed(raw):
    with pytest.raises(ValueError):
        kotlin_tokens(raw)


def test_nested_kotlin_templates_are_entirely_opaque():
    raw = b'"prefix ${foo("open", "${bar("open")}")} suffix" open'
    assert [v for v, _, _ in kotlin_tokens(raw)].count(b"open") == 1
    raw = b'"""prefix ${foo("""open""")} suffix""" open'
    assert [v for v, _, _ in kotlin_tokens(raw)].count(b"open") == 1


def test_normalized_swift_comment_and_literal_do_not_create_findings():
    source = """import WebKit
class A {
 var browser = WKWebView()
 func run() {
   nonisolated(unsafe) let docs = "browser.load(URLRequest(url: incoming)) nonisolated(unsafe)"
   // nonisolated(unsafe) var fake = incoming
 }
}"""
    report = analyze_sources([("A.swift", source)])
    assert not report["findings"]
    assert report["metadata"]["files"][0]["adaptations"][0]["edits"] == 1


def test_apple_cached_identity_must_be_refetched_before_custom_matching():
    cve, vendor = apple_records()
    cve.pop("assigner_org_id")
    cve.pop("cna_org_id")
    assert state(cve, vendor, "18.3.1")[0] == "applicability-unknown"


@pytest.mark.parametrize("label", ["iOS 18.3.2beta", "iOS 18.3.2 beta", "iOS 18.3.2 (a)", "iOS 18.3.2.0.1"])
def test_bulletin_release_label_is_not_a_version_prefix(label):
    cve, vendor = apple_records()
    vendor["fixed_release"] = label
    assert state(cve, vendor, "18.3.1")[0] == "applicability-unknown"


def test_function_counts_keep_invalid_and_unknown_inventory_visible(monkeypatch):
    from mobile_audit import source_analysis

    source = "class A { void valid() {} void invalid( { } }"
    report = analyze_sources([("A.java", source)])
    counts = report["metadata"]["functions"]
    assert counts["observed"] == counts["analyzed"] + counts["skipped"] + counts["without_body"]
    assert counts["analyzed"] >= 1 and not report["metadata"]["function_inventory_complete"]
    monkeypatch.setattr(source_analysis, "MAX_AST_BYTES", 2)
    report = analyze_sources([("A.java", source)])
    assert report["metadata"]["files"][0]["functions"] is None
    assert not report["metadata"]["function_inventory_complete"]


def test_bulletin_and_cna_inputs_are_not_mutated():
    cve, vendor = apple_records()
    before = copy.deepcopy((cve, vendor))
    assert state(cve, vendor, "18.3.1")[0] == "version-affected"
    assert (cve, vendor) == before
