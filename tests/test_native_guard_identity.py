"""Boolean AST scope and visible Kotlin aliases cannot manufacture safety."""

from __future__ import annotations

import pytest

from mobile_audit import native_guards
from mobile_audit.source_analysis import Trace, Value, analyze_sources
from tests.test_native_flow import PATH, URL, findings, scan

SOURCES = {
    "java": 'import android.content.Intent;\nimport java.io.File;\nimport java.io.FileOutputStream;\nclass Saver {\n void save(Intent intent, File base, boolean flag) throws Exception {\n  String name = intent.getStringExtra("name");\n  File target = new File(base, name);\n  String canonical = target.getCanonicalPath();\n  {guard}\n  new FileOutputStream(canonical);\n }\n}\n',
    "kt": 'import android.content.Intent\nimport java.io.File\nimport java.io.FileOutputStream\nclass Saver {\n fun save(intent: Intent, base: File, flag: Boolean) {\n  val name = intent.getStringExtra("name")!!\n  val target = File(base, name)\n  val canonical = target.canonicalPath\n  {guard}\n  FileOutputStream(canonical)\n }\n}\n',
    "swift": "import Foundation\nclass Saver {\n func application(_ app: UIApplication, open incoming: URL, base: URL, flag: Bool) {\n  let name = incoming.absoluteString\n  let target = base.appendingPathComponent(name)\n  let canonical = target.resolvingSymlinksInPath().path\n  {guard}\n  _ = try? FileHandle(forWritingTo: target)\n }\n}\n",
}

KOTLIN_CALLER = 'package app\nimport android.content.Intent\nimport android.webkit.WebView\nopen class OwnedBase\nclass Intake : OwnedBase() {\n    lateinit var reader: WebView\n    fun onCreate(intent: Intent) {\n        val link = intent.data\n        val destination = link?.getQueryParameter("destination")\n        val parsed = Uri.parse(destination)\n        if (parsed.scheme == "https" && parsed.host == "guide.example.test") {\n            reader.loadUrl(destination!!)\n        }\n    }\n}\n'


@pytest.mark.parametrize("language", ["java", "kt"])
@pytest.mark.parametrize(
    "kind",
    [
        "unguarded",
        "leading-not-and",
        "leading-not-or",
        "leading-not-and-not-contains",
        "unary",
        "unary-parenthesized",
        "contains-reject",
    ],
)
def test_early_return_uses_boolean_scope_instead_of_leading_text(language, kind):
    prefix = (
        "canonical.startsWith(base.getCanonicalPath() + File.separator)"
        if language == "java"
        else "canonical.startsWith(base.canonicalPath + File.separator)"
    )
    condition = {
        "unguarded": None,
        "leading-not-and": f"!flag && {prefix}",
        "leading-not-or": f"!flag || {prefix}",
        "leading-not-and-not-contains": '!flag && !name.contains("..")',
        "unary": f"!{prefix}",
        "unary-parenthesized": f"!({prefix})",
        "contains-reject": 'name.contains("..")',
    }[kind]
    guard = f"if ({condition}) return" + (";" if language == "java" else "") if condition else ""
    report = scan((f"app/Saver.{language}", SOURCES[language].replace("{guard}", guard)))
    unsafe = kind in {"unguarded", "leading-not-and", "leading-not-or", "leading-not-and-not-contains"}
    assert bool(findings(report, PATH)) == unsafe, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("operator", ["&&", "||"])
def test_swift_compound_condition_does_not_supply_a_containment_proof(monkeypatch, operator):
    # The full Swift path fixture is already partial for a separate unsupported
    # field model. Use its actual parsed predicate with controlled path values
    # to test this independent guard defect without claiming full Swift support.
    guard = f'if !flag {operator} canonical.hasPrefix(base.resolvingSymlinksInPath().path + "/") {{ return }}'
    captured = []
    original = native_guards.path_predicate

    def record(analyzer, node, frame, *, positive=True):
        if not positive and node is not None:
            captured.append((analyzer, node, frame))
        return original(analyzer, node, frame, positive=positive)

    monkeypatch.setattr(native_guards, "path_predicate", record)
    analyze_sources([("App/Saver.swift", SOURCES["swift"].replace("{guard}", guard))])
    assert captured
    analyzer, node, frame = max(captured, key=lambda item: item[1].end_byte - item[1].start_byte)
    monkeypatch.setattr(native_guards, "path_predicate", original)

    class SyntheticValues:
        def __getattr__(self, key):
            return getattr(analyzer, key)

        def value(self, node, frame):
            text = analyzer.text(node).strip().strip("!() ")
            trace = Trace(1, "Synthetic path input", "synthetic", (), False, "synthetic-route")
            return (
                Value((trace,), "canonical-path" if text == "canonical" else "text")
                if text in {"canonical", "name"}
                else Value()
            )

    assert original(SyntheticValues(), node, frame, positive=False) == {}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize(
    "binding,expected_partial",
    [
        ("same-package", True),
        ("same-file", True),
        ("private-same-file", True),
        ("private-other-file", False),
        ("foreign-package", False),
        ("explicit-sdk", False),
        ("explicit-import", True),
        ("star-import", True),
    ],
)
def test_kotlin_type_alias_visibility_precedes_sdk_name_fallback(binding, expected_partial, reverse):
    caller = KOTLIN_CALLER
    alias = "package app\ntypealias Uri = com.vendor.LenientUri\n"
    if binding in {"same-file", "private-same-file"}:
        caller += (
            "\n"
            + ("private " if binding == "private-same-file" else "")
            + "typealias Uri = com.vendor.LenientUri\n"
        )
        sources = [("app/Entry.kt", caller)]
    else:
        if binding == "private-other-file":
            alias = alias.replace("typealias", "private typealias")
        elif binding in {"foreign-package", "explicit-import", "star-import"}:
            alias = alias.replace("package app", "package external")
        if binding == "explicit-sdk":
            caller = caller.replace(
                "import android.content.Intent", "import android.net.Uri\nimport android.content.Intent"
            )
            alias = "package external\ntypealias Uri = com.vendor.LenientUri\n"
        elif binding == "explicit-import":
            caller = caller.replace("package app", "package app\nimport external.Uri")
        elif binding == "star-import":
            caller = caller.replace("package app", "package app\nimport external.*")
        sources = [("app/Entry.kt", caller), ("helpers/Alias.kt", alias)]
    report = scan(*(list(reversed(sources)) if reverse else sources))
    assert bool(findings(report, URL)) == expected_partial, report
    assert report["metadata"]["native_flow"]["state"] == ("partial" if expected_partial else "checked"), (
        report
    )
