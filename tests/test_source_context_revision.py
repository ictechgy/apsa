"""Context repair is explicit; missing ancestry never becomes SDK identity proof."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mobile_audit.source_analysis import analyze_sources

ROOT = Path(__file__).parents[1]
CASES = {"java": ("intent", "java"), "kotlin": ("query", "kt"), "swift": ("url", "swift")}
URL_RULE = "AST-WEBVIEW-UNTRUSTED-URL"


def source(language, variant="fixed", legacy=False):
    stem, extension = CASES[language]
    path = ROOT / (
        f"tests/fixtures/native_context_legacy/{language}-{variant}.{extension}"
        if legacy
        else f"benchmarks/cases/{language}/{stem}-{variant}.{extension}"
    )
    return path.read_text()


def analysis(language, text):
    return analyze_sources([("app/Entry." + CASES[language][1], text)])


def assert_result(language, text, *, unsafe, partial):
    report = analysis(language, text)
    assert bool([row for row in report["findings"] if row["rule_id"] == URL_RULE]) == unsafe
    assert report["metadata"]["native_flow"]["state"] == ("partial" if partial else "checked")
    if not partial:
        assert report["warnings"] == []
    return report


@pytest.mark.parametrize("language", CASES)
@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_complete_context_pairs_preserve_real_source_and_guard(language, variant):
    assert_result(language, source(language, variant), unsafe=variant == "vulnerable", partial=False)


@pytest.mark.parametrize("language", CASES)
@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_original_input_bytes_and_uncertainty_are_retained(language, variant):
    manifest = json.loads((ROOT / "benchmarks/corpus.json").read_text())
    stem, extension = CASES[language]
    case = next(
        row for row in manifest["cases"] if row["path"] == f"cases/{language}/{stem}-{variant}.{extension}"
    )
    old = source(language, variant, legacy=True)
    assert hashlib.sha256(old.encode()).hexdigest() == case["context_revision"]["legacy_sha256"]
    assert_result(language, old, unsafe=True, partial=variant == "fixed" or language == "swift")


@pytest.mark.parametrize("language", CASES)
@pytest.mark.parametrize("defect", ["scheme", "host", "or"])
def test_complete_context_rejects_incomplete_or_disjunctive_guards(language, defect):
    text = source(language)
    if language == "java":
        scheme, host = '"https".equals(parsed.getScheme())', '"guide.example.test".equals(parsed.getHost())'
    elif language == "kotlin":
        scheme, host = 'parsed.scheme == "https"', 'parsed.host == "guide.example.test"'
    else:
        scheme, host = 'link.scheme == "https"', 'link.host == "guide.example.test"'
    if defect == "or":
        text = text.replace(scheme + (" && " if language != "swift" else ", ") + host, scheme + " || " + host)
    else:
        text = text.replace(scheme if defect == "scheme" else host, "true")
    assert_result(language, text, unsafe=True, partial=False)


@pytest.mark.parametrize("language", CASES)
@pytest.mark.parametrize(
    "defect", ["missing", "nonempty", "duplicate", "unknown-chain", "cycle", "generic", "annotation"]
)
def test_only_unique_complete_empty_ancestry_can_discharge_lookup(language, defect):
    text = source(language)
    original = {
        "java": "class OwnedBase {}",
        "kotlin": "open class OwnedBase",
        "swift": "class OwnedBase {}",
    }[language]
    if defect == "missing":
        replacement = ""
    elif defect == "nonempty":
        replacement = {
            "java": "class OwnedBase { int marker; }",
            "kotlin": "open class OwnedBase { val marker = 1 }",
            "swift": "class OwnedBase { let marker = 1 }",
        }[language]
    elif defect == "duplicate":
        replacement = original + "\n" + original
    elif defect == "unknown-chain":
        replacement = {
            "java": "class OwnedBase extends Missing {}",
            "kotlin": "open class OwnedBase : Missing()",
            "swift": "class OwnedBase: Missing {}",
        }[language]
    elif defect == "cycle":
        replacement = {
            "java": "class OwnedBase extends Loop {}\nclass Loop extends OwnedBase {}",
            "kotlin": "open class OwnedBase : Loop()\nopen class Loop : OwnedBase()",
            "swift": "class OwnedBase: Loop {}\nclass Loop: OwnedBase {}",
        }[language]
    elif defect == "generic":
        replacement = original.replace("OwnedBase", "OwnedBase<T>")
    else:
        replacement = "@Foreign\n" + original
    assert original in text
    assert_result(language, text.replace(original, replacement), unsafe=True, partial=True)


@pytest.mark.parametrize("language", CASES)
def test_empty_lookup_depth_is_bounded_without_changing_unsafe_result(language, monkeypatch):
    import mobile_audit.native_flow as native

    with monkeypatch.context() as context:
        context.setattr(native, "MAX_EMPTY_BASE_DEPTH", 1)
        assert_result(language, source(language), unsafe=True, partial=True)
    assert_result(language, source(language), unsafe=False, partial=False)


def test_observed_swift_extension_and_typealias_keep_ancestry_unknown():
    text = source("swift")
    for extra in ["extension OwnedBase {}", "typealias Other = Int"]:
        assert_result("swift", text + "\n" + extra, unsafe=True, partial=True)


@pytest.mark.parametrize(
    "binding", ["member-function", "local-function", "parameter", "field", "type-parameter"]
)
def test_swift_source_bindings_precede_imported_sdk_constructor(binding):
    text = source("swift")
    if binding == "member-function":
        text = text.replace("let reader:", "func URLRequest(url: URL) -> Int { return 0 }\n    let reader:")
    elif binding == "local-function":
        text = text.replace(
            "guard link.scheme", "func URLRequest(url: URL) -> Int { return 0 }\n        guard link.scheme"
        )
    elif binding == "parameter":
        text = text.replace("options: [String: Any]", "URLRequest: (URL) -> Int, options: [String: Any]")
    elif binding == "field":
        text = text.replace("let reader:", "var URLRequest: (URL) -> Int\n    let reader:")
    else:
        text = text.replace("class Intake:", "class Intake<URLRequest>:")
    assert_result("swift", text, unsafe=True, partial=True)


@pytest.mark.parametrize("binding", ["global", "extension", "destructured"])
def test_kotlin_module_values_precede_sdk_expression_roots(binding):
    text = source("kotlin")
    helpers = """
class PretendParser {
    fun parse(ignored: String?): PretendUrl { return PretendUrl() }
}
class PretendUrl {
    val scheme: String = "https"
    val host: String = "guide.example.test"
}
"""
    declaration = {
        "global": "val Uri = PretendParser()",
        "extension": "val OwnedBase.Uri: PretendParser get() = PretendParser()",
        "destructured": "val (Uri, ignored) = Pair(PretendParser(), 0)",
    }[binding]
    assert_result("kotlin", text + helpers + declaration, unsafe=True, partial=True)


def test_kotlin_module_value_does_not_replace_type_annotation_identity():
    # reader.loadUrl uses reader's declared type. An unrelated value named
    # WebView does not replace that type annotation's identity.
    assert_result("kotlin", source("kotlin") + "\nval WebView = 42", unsafe=False, partial=False)


@pytest.mark.parametrize("private", [False, True])
def test_kotlin_other_file_value_visibility_precedes_sdk_namespace(private):
    helper = "package app\n" + ("private " if private else "") + "val Uri = 42"
    report = analyze_sources(
        [("app/Entry.kt", "package app\n" + source("kotlin")), ("app/Helper.kt", helper)]
    )
    assert any(row["rule_id"] == URL_RULE for row in report["findings"]) != private
    assert report["metadata"]["native_flow"]["state"] == ("checked" if private else "partial")


@pytest.mark.parametrize("multiple", [False, True])
def test_swift_module_function_values_precede_constructor_spelling(multiple):
    declaration = "let " + ("unused = 0, " if multiple else "") + "URLRequest: (URL) -> Int = { _ in 0 }"
    assert_result("swift", source("swift") + "\n" + declaration, unsafe=True, partial=True)


@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_swift_cross_file_source_namespace_cannot_borrow_sdk_identity(alias, reverse):
    entry = "import Foundation\n" + source("swift").replace(
        "reader.load(URLRequest(", "reader.load(Foundation.URLRequest("
    )
    helper = """
import Foundation
import struct Foundation.URL
import struct Foundation.URLRequest
func requestFromQuery(_ value: URL) -> URLRequest {
    let components = URLComponents(url: value, resolvingAgainstBaseURL: false)
    let redirect = components?.queryItems?.first?.value
    return URLRequest(url: URL(string: redirect!)!)
}
final class Foundation {
    static func URLRequest(url value: URL) -> URLRequest { return requestFromQuery(value) }
}
"""
    if alias:
        helper = helper.replace("final class Foundation", "typealias Foundation = Maker\nfinal class Maker")
    inputs = [("app/Entry.swift", entry), ("app/Helper.swift", helper)]
    report = analyze_sources(list(reversed(inputs)) if reverse else inputs)
    assert any(row["rule_id"] == URL_RULE for row in report["findings"])
    assert report["metadata"]["native_flow"]["state"] == "partial"


def test_context_revision_metadata_is_emitted_and_cannot_hide_input_drift(tmp_path):
    from benchmarks.run import run

    original = json.loads((ROOT / "benchmarks/corpus.json").read_text())
    case = next(row for row in original["cases"] if row["id"] == "java-intent-fixed")
    path = tmp_path / case["path"]
    path.parent.mkdir(parents=True)
    path.write_text(source("java"))
    original["cases"] = [case]
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(original))
    result = run(manifest)
    assert result["passed"] and result["input_revision"] == "explicit-source-context-r1"
    assert result["cases"][0]["context_revision"] == case["context_revision"]
    path.write_text(source("java").replace('"https".equals(parsed.getScheme())', "true"))
    drift = run(manifest)
    assert not drift["passed"] and "Context-revision input SHA-256 differs" in drift["cases"][0]["error"]


@pytest.mark.parametrize("revision", [None, "", " ", 1, "original-v1"])
def test_context_revision_cannot_be_missing_empty_or_labeled_as_original(tmp_path, revision):
    from benchmarks.run import run

    manifest = json.loads((ROOT / "benchmarks/corpus.json").read_text())
    case = next(row for row in manifest["cases"] if row["id"] == "java-intent-fixed")
    manifest["cases"] = [case]
    manifest["input_revision"] = case["context_revision"]["id"] = revision
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="explicit revision"):
        run(path)
