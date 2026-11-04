"""Native-flow reasons have explicit kinds, and a cut trace keeps its kind downstream.

A budget kind (a resource cap) leaves AST coverage partial; a precision kind (an
abstention of the bounded model) leaves it limited. Every fixture is new and
synthetic; no retained report, corpus or device is read.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import mobile_audit.native_flow as native_flow
from mobile_audit.native_flow import REASON_KINDS, reason_kind
from mobile_audit.source_analysis import (
    RULES,
    TRACE_LIMITED,
    TRACE_PARTIAL,
    Trace,
    Value,
    _union,
    analyze_sources,
    trace_cuts,
)

MODULES = (
    Path(native_flow.__file__),
    Path(native_flow.__file__).with_name("source_analysis.py"),
)


def test_review22_classification_exposes_precision_without_unmuting_execution_gaps():
    flow = native_flow.NativeFlow([])
    flow.muted = 1
    precision = "callable argument type identity unresolved"
    flow.partial(precision)
    flow.partial("closure value classification budget", classification_precision=True)
    assert not flow.reasons
    flow.partial(precision, classification_precision=True)
    assert flow.reasons == {precision}
    assert flow.partial_events == 1
    assert flow.muted == 1


def _strings(node: ast.expr) -> set[str] | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.IfExp):
        body, orelse = _strings(node.body), _strings(node.orelse)
        return None if body is None or orelse is None else body | orelse
    return None


def _returned_strings(function: ast.FunctionDef) -> set[str] | None:
    found: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Return) and node.value is not None:
            if isinstance(node.value, ast.Constant) and node.value.value is None:
                continue
            values = _strings(node.value)
            if values is None:
                return None
            found |= values
    return found


def recorded_reasons() -> set[str]:
    """Every reason any ``.partial(...)`` call can record, resolved from source.

    A literal, a conditional of literals, or a local name assigned from a method
    that returns only literals (or None) is resolved; anything else fails, so a
    new reason cannot bypass the kind table.
    """
    reasons: set[str] = set()
    for path in MODULES:
        tree = ast.parse(path.read_text())
        methods = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
        for function in methods.values():
            for call in ast.walk(function):
                if not (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Attribute)
                    and call.func.attr == "partial"
                    and call.args
                ):
                    continue
                argument = call.args[0]
                values = _strings(argument)
                if values is None and isinstance(argument, ast.Name):
                    sources = [
                        node.value
                        for node in ast.walk(function)
                        if isinstance(node, ast.Assign)
                        and any(isinstance(t, ast.Name) and t.id == argument.id for t in node.targets)
                    ]
                    values = set()
                    for source in sources:
                        callee = (
                            source.func.attr
                            if isinstance(source, ast.Call) and isinstance(source.func, ast.Attribute)
                            else None
                        )
                        returned = _returned_strings(methods[callee]) if callee in methods else None
                        if returned is None:
                            values = None
                            break
                        values |= returned
                    values = values if sources else None
                assert values is not None, f"{path.name}:{call.lineno} records an unresolvable reason"
                reasons |= values
    return reasons


def test_every_recorded_reason_has_an_explicit_kind():
    reasons = recorded_reasons()
    assert len(reasons) > 30  # The enumeration itself must keep working.
    assert sorted(reasons - REASON_KINDS.keys()) == []
    assert sorted(REASON_KINDS.keys() - reasons) == []  # No stale entries.
    assert set(REASON_KINDS.values()) == {"budget", "precision"}
    # Resource caps are budgets; non-convergence and abstentions are precision limits.
    assert reason_kind("source trace budget") == "budget"
    assert reason_kind("field summary fixed-point budget") == "budget"
    assert reason_kind("field summary fixed point unresolved") == "precision"
    assert reason_kind("source trace abstention") == "precision"
    assert reason_kind("new synthetic unlisted reason") == "budget"  # Conservative default.


def flow(path: str, text: str) -> tuple[dict, set[str]]:
    analysis = analyze_sources([(path, text)])
    states = {row["state"] for row in analysis["coverage"] if row["rule_id"] in RULES}
    return analysis, states


CONSTRUCTOR_ABSTENTION = """import android.content.Intent;
import android.webkit.WebView;
class NewSyntheticEntry {
  void entry(Intent input, WebView web) {
    NewSyntheticWrapper wrapped = new NewSyntheticWrapper(input.getStringExtra("u"));
    web.loadUrl(wrapped.toString());
  }
}
"""


def test_a_precision_abstention_passed_through_a_call_stays_limited():
    analysis, states = flow("NewSyntheticEntry.java", CONSTRUCTOR_ABSTENTION)
    native = analysis["metadata"]["native_flow"]
    assert native["budget_reasons"] == []
    assert {"constructor field mapping unavailable", "source trace abstention"} <= set(
        native["precision_reasons"]
    )
    assert states == {"limited"}
    (item,) = [row for row in analysis["findings"] if row["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL"]
    kinds = [source["kind"] for source in item["evidence"][0]["sources"]]
    assert all(TRACE_LIMITED in kind and TRACE_PARTIAL not in kind for kind in kinds)


def test_a_genuine_trace_budget_stays_partial():
    concatenated = " + ".join(f'input.getStringExtra("k{index}")' for index in range(12))
    analysis, states = flow(
        "NewSyntheticBudget.java",
        f"""import android.content.Intent;
import android.webkit.WebView;
class NewSyntheticBudget {{
  void entry(Intent input, WebView web) {{
    String url = {concatenated};
    web.loadUrl(url);
  }}
}}
""",
    )
    assert "source trace budget" in analysis["metadata"]["native_flow"]["budget_reasons"]
    assert states == {"partial"}
    assert any(row["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL" for row in analysis["findings"])


def test_a_trace_cap_drop_at_a_sink_is_a_budget_gap():
    # Five origins in the base URL and four in the data exceed the eight-trace cap
    # only when the sink merges its arguments; no later call records the cut.
    base = " + ".join(f'input.getStringExtra("a{index}")' for index in range(5))
    html = " + ".join(f'input.getStringExtra("b{index}")' for index in range(4))
    analysis, states = flow(
        "NewSyntheticLoader.java",
        f"""import android.content.Intent;
import android.webkit.WebView;
class NewSyntheticLoader {{
  void entry(Intent input, WebView web) {{
    String base = {base};
    String html = {html};
    web.loadDataWithBaseURL(base, html, "text/html", "utf-8", null);
  }}
}}
""",
    )
    assert analysis["metadata"]["native_flow"]["budget_reasons"] == ["source trace budget"]
    assert states == {"partial"}
    (item,) = [row for row in analysis["findings"] if row["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL"]
    assert any(TRACE_PARTIAL in source["kind"] for source in item["evidence"][0]["sources"])


NON_CONVERGENT_KOTLIN = """import android.app.Activity
import android.webkit.WebView
class NewSyntheticActivity : Activity() {
    lateinit var web: WebView
    fun setTarget(value: String) { web.loadUrl(value) }
    fun handle() { setTarget(intent.getStringExtra("u") ?: "") }
}
"""


def test_kotlin_field_summary_non_convergence_is_a_precision_limit():
    # Pinned at the default cap: each round re-derives origins for the same
    # content (1, 3, 5, 7 duplicate traces), staying under the eight-trace cap.
    assert native_flow.MAX_FIELD_ROUNDS == 4
    analysis, states = flow("NewSyntheticActivity.kt", NON_CONVERGENT_KOTLIN)
    native = analysis["metadata"]["native_flow"]
    assert native["budget_reasons"] == []
    assert "field summary fixed point unresolved" in native["precision_reasons"]
    assert states == {"limited"}


def test_one_more_field_round_turns_the_same_non_convergence_into_a_budget(monkeypatch):
    # Classification depends on the round cap: a fifth round passes the trace cap,
    # so the content changes and the cap hit is a budget gap.
    monkeypatch.setattr(native_flow, "MAX_FIELD_ROUNDS", 5)
    analysis, states = flow("NewSyntheticActivity.kt", NON_CONVERGENT_KOTLIN)
    native = analysis["metadata"]["native_flow"]
    assert native["budget_reasons"] == ["field summary fixed-point budget"]
    assert "field summary fixed point unresolved" not in native["precision_reasons"]
    assert states == {"partial"}


def test_a_field_written_from_two_churning_call_sites_is_a_budget_at_the_default_cap():
    assert native_flow.MAX_FIELD_ROUNDS == 4
    two_sites = NON_CONVERGENT_KOTLIN.replace(
        "    fun handle()",
        '    fun again() { setTarget(intent.getStringExtra("v") ?: "") }\n    fun handle()',
    )
    analysis, states = flow("NewSyntheticActivity.kt", two_sites)
    native = analysis["metadata"]["native_flow"]
    assert native["budget_reasons"] == ["field summary fixed-point budget", "source trace budget"]
    assert states == {"partial"}


def test_field_content_still_growing_at_the_round_cap_stays_a_budget():
    fields = "abcdef"
    chain = "\n".join(
        f"    void s{index}() {{ this.{fields[index]} = {fields[index - 1]}; }}" for index in range(5, 0, -1)
    )
    analysis, states = flow(
        "NewSyntheticChain.java",
        f"""class NewSyntheticChain {{
    String a; String b; String c; String d; String e; String f;
    void s0(Intent input) {{ this.a = input.getStringExtra("name"); }}
{chain}
    void later() {{ new FileOutputStream(f); }}
}}""",
    )
    native = analysis["metadata"]["native_flow"]
    assert native["budget_reasons"] == ["field summary fixed-point budget"]
    assert states == {"partial"}


@pytest.mark.parametrize("marker", [TRACE_PARTIAL, TRACE_LIMITED])
def test_trace_merges_keep_each_cut_kind(marker):
    cut = Value((Trace(1, None, "new synthetic source" + marker),))
    plain = Value((Trace(1, None, "new synthetic source"),))
    for values in ([cut, plain], [plain, cut]):
        assert trace_cuts(_union(values).traces[0].description) == trace_cuts(marker)
    both = Value((Trace(1, None, "new synthetic source" + TRACE_PARTIAL + TRACE_LIMITED),))
    assert trace_cuts(both.traces[0].description) == {"budget", "precision"}
