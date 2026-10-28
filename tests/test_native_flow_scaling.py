from __future__ import annotations

from collections import Counter

import pytest

from mobile_audit.native_flow import NativeFlow
from mobile_audit.source_analysis import Analyzer, analyze_sources


@pytest.mark.parametrize("depth", [4, 8, 16])
@pytest.mark.parametrize("language", ["java", "kotlin"])
def test_unknown_fluent_receivers_keep_taint_without_exponential_evaluation(monkeypatch, depth, language):
    origin = 'Builder(input.getStringExtra("url"))'
    chain = origin + ".step()" * depth
    if language == "java":
        origin = "new " + origin
        chain = "new " + chain
        source = f"""import sdk.Builder;
            import android.content.Intent; import android.webkit.WebView;
            class Handler {{ void open(Intent input, WebView browser) {{
                Object value = {chain}; browser.loadUrl(value);
            }} }}"""
        path = "Handler.java"
    else:
        source = f"""import sdk.Builder
            import android.content.Intent
            import android.webkit.WebView
            class Handler {{ fun open(input: Intent, browser: WebView) {{
                val value = {chain}
                browser.loadUrl(value)
            }} }}"""
        path = "Handler.kt"
    original = Analyzer.value
    origin_evaluations = 0

    def counted(self, node, frame):
        nonlocal origin_evaluations
        if node is not None and self.text(node) == origin:
            origin_evaluations += 1
            # Abort a regression without a machine-dependent wall-time assertion.
            assert origin_evaluations <= depth + 4
        return original(self, node, frame)

    monkeypatch.setattr(Analyzer, "value", counted)
    report = analyze_sources([(path, source)])
    assert 0 < origin_evaluations <= depth + 4
    assert any(item["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL" for item in report["findings"])
    assert report["metadata"]["native_flow"]["state"] == "partial"


@pytest.mark.parametrize("depth", [4, 8, 16])
@pytest.mark.parametrize("language", ["java", "kotlin"])
def test_qualified_members_evaluate_the_root_once(monkeypatch, depth, language):
    expression = "example." + ".".join(f"part{index}" for index in range(depth))
    source = (
        f"class Handler {{ void read() {{ Object value = {expression}; }} }}"
        if language == "java"
        else f"class Handler {{ fun read() {{ val value = {expression} }} }}"
    )
    suffix = "java" if language == "java" else "kt"
    original = Analyzer.value
    counts = Counter()

    def counted(self, node, frame):
        if node is not None:
            text = self.text(node)
            counts[text] += 1
            assert counts["example"] <= 2
        return original(self, node, frame)

    monkeypatch.setattr(Analyzer, "value", counted)
    report = analyze_sources([(f"Handler.{suffix}", source)])
    assert counts["example"] == 1
    assert report["findings"] == []


@pytest.mark.parametrize("depth", [4, 8, 16])
@pytest.mark.parametrize("language", ["java", "kotlin", "swift"])
@pytest.mark.parametrize("write", [False, True])
@pytest.mark.parametrize("declared", [False, True])
def test_typed_member_chains_evaluate_root_once(monkeypatch, depth, language, write, declared):
    expression = "item" + ".next" * depth
    if language == "java":
        field = "Holder next;" if declared else ""
        statement = f"{expression} = item;" if write else f"Object value = {expression};"
        source = (
            f"final class Holder {{ {field} }} class Handler {{ void read(Holder item) {{ {statement} }} }}"
        )
        suffix = "java"
    elif language == "kotlin":
        field = "lateinit var next: Holder" if declared else ""
        statement = f"{expression} = item" if write else f"val value = {expression}"
        source = (
            f"class Holder {{\n{field}\n}}\nclass Handler {{\nfun read(item: Holder) {{\n{statement}\n}}\n}}"
        )
        suffix = "kt"
    else:
        field = "var next: Holder!" if declared else ""
        statement = f"{expression} = item" if write else f"let value = {expression}"
        source = f"final class Holder {{ {field} }}\nfunc read(_ item: Holder) {{ {statement} }}"
        suffix = "swift"
    original = Analyzer.value
    roots = Counter()

    def counted(self, node, frame):
        if node is not None and self.text(node) == "item":
            roots[node.start_byte] += 1
            # Count each source occurrence, including assignment RHS, separately.
            assert roots[node.start_byte] <= 1
        return original(self, node, frame)

    monkeypatch.setattr(Analyzer, "value", counted)
    report = analyze_sources([(f"Handler.{suffix}", source)])
    assert len(roots) == (2 if write else 1)
    assert all(count == 1 for count in roots.values())
    assert report["findings"] == []


def test_pre_evaluated_receiver_keeps_unknown_mutator_effects():
    report = analyze_sources(
        [
            (
                "Handler.java",
                """import android.content.Intent; import android.webkit.WebView;
                final class Holder { String value; }
                class Handler {
                    static Holder select(Holder item) { return item; }
                    void open(Intent input, WebView web) {
                        Holder item = new Holder(); item.value = "https://safe.example";
                        select(item).unknown(input.getStringExtra("url"));
                        web.loadUrl(item.value);
                    }
                }""",
            )
        ]
    )
    assert any(item["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL" for item in report["findings"])
    assert (
        "unresolved callable identity or argument signature" in report["metadata"]["native_flow"]["reasons"]
    )


@pytest.mark.parametrize(
    "language,imports,name,classes,expected",
    [
        ("java", {"a.Widget", "static b.Tools.Widget"}, "Widget", True, {"a.Widget"}),
        ("java", {"a.Widget", "static b.Tools.Widget"}, "Widget", False, {"b.Tools.Widget"}),
        ("java", {"a.Widget", "b.Widget"}, "Widget", True, {"a.Widget", "b.Widget"}),
        ("kotlin", {"a.Widget as Local", "b.Widget as Local"}, "Local", True, {"a.Widget", "b.Widget"}),
        ("kotlin", {"a.Widget as Local"}, "Widget", True, set()),
        ("kotlin", {"a.action as Local"}, "Local", False, {"a.action"}),
        ("swift", {"class A.Widget", "func B.Widget"}, "Widget", True, {"A.Widget"}),
        ("swift", {"class A.Widget", "func B.Widget"}, "Widget", False, {"B.Widget"}),
        ("swift", {"struct A.Widget", "typealias B.Widget"}, "Widget", True, {"A.Widget", "B.Widget"}),
        ("swift", {"A.Widget", "A.*"}, "Widget", True, set()),
    ],
)
def test_import_index_preserves_modes_aliases_ambiguity_and_independent_sets(
    language, imports, name, classes, expected
):
    flow = NativeFlow([])
    analyzer = Analyzer("Example", "", language)
    analyzer.imports = imports
    result = flow.imported_symbols(analyzer, name, classes=classes)
    assert result == expected
    result.add("poisoned")
    assert flow.imported_symbols(analyzer, name, classes=classes) == expected
    for index in range(100):
        assert flow.imported_symbols(analyzer, f"unknown{index}", classes=classes) == set()
    assert len(flow.import_indexes) == 1
    assert sum(len(index) for index in flow.import_indexes.values()) <= len(imports)


def test_import_index_is_scoped_to_analyzer_and_analysis():
    first = Analyzer("Same.kt", "", "kotlin")
    second = Analyzer("Same.kt", "", "kotlin")
    first.imports = {"one.Widget"}
    second.imports = {"two.Widget"}
    flow = NativeFlow([])
    assert flow.imported_symbols(first, "Widget", classes=True) == {"one.Widget"}
    assert flow.imported_symbols(second, "Widget", classes=True) == {"two.Widget"}
    second.imports = {"three.Widget"}
    assert NativeFlow([]).imported_symbols(second, "Widget", classes=True) == {"three.Widget"}
