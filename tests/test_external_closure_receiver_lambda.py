"""Conservative receiver-lambda inspection without inline execution assertions."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

URL = "AST-WEBVIEW-UNTRUSTED-URL"
UNAVAILABLE = "Kotlin non-local return context unavailable"


def _matches(report: dict) -> list[dict]:
    return [row for row in report["findings"] if row["rule_id"] == URL]


@pytest.mark.parametrize(
    "call",
    [
        "with(receiver = { SINK }, block = { this() })",
        "with(block = { this() }, receiver = { SINK })",
        "with({ SINK }, { this() })",
        "with({ SINK }) { this() }",
        "with(receiver = { SINK }) { this() }",
        "with(block = { this() }, receiver = ({ SINK }))",
        'with(receiver = { SINK }, block = { "unused" })',
    ],
)
@pytest.mark.parametrize("tainted", [False, True])
def test_with_receiver_lambda_sink_is_inspected_in_each_spelling(call: str, tainted: bool) -> None:
    argument = 'input.getStringExtra("u")!!' if tainted else '"https://safe.example/"'
    expression = call.replace("SINK", f"browser.loadUrl({argument})")
    report = analyze_sources(
        [
            (
                "fresh/Receiver.kt",
                f"""import android.content.Intent
import android.webkit.WebView
class FreshEntry {{
fun inspect(input: Intent, browser: WebView) {{
 {expression}
}}
}}""",
            )
        ]
    )
    assert len(_matches(report)) == int(tainted), report
    if tainted:
        row = _matches(report)[0]
        assert row["status"] == "candidate", row
        assert any("loadUrl" in evidence["excerpt"] for evidence in row["evidence"]), row


@pytest.mark.parametrize(
    "receiver",
    [
        '{ input.getStringExtra("u")!! }',
        'local@ { return@local input.getStringExtra("u")!! }',
        '{ input.getStringExtra("u")!!.let { return@let it } }',
    ],
)
def test_receiver_lambda_value_does_not_become_enclosing_function_return(receiver: str) -> None:
    source = f"""import android.content.Intent
import android.webkit.WebView
class FreshEntry {{
fun value(input: Intent): String {{
 with(receiver = {receiver}, block = {{ return "https://safe.example/" }})
 return "https://safe.example/"
}}
fun inspect(input: Intent, browser: WebView) {{
 browser.loadUrl(value(input))
}}
}}"""
    report = analyze_sources([("fresh/ReceiverReturn.kt", source)])
    assert _matches(report) == [], report


def test_invalid_noninline_receiver_return_is_partial_without_summary_pollution() -> None:
    source = """import android.content.Intent
import android.webkit.WebView
class FreshEntry {
fun value(input: Intent): String {
 with(receiver = { return input.getStringExtra("u")!! }, block = { return "https://safe.example/" })
 return "https://safe.example/"
}
fun inspect(input: Intent, browser: WebView) {
 browser.loadUrl(value(input))
}
}"""
    report = analyze_sources([("fresh/InvalidReceiverReturn.kt", source)])
    assert _matches(report) == [], report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "body",
    [
        "source.run outer@ { return@run this }",
        "source.run(block = outer@ { return@run this })",
        "source.run outer@ { source.let inner@ { return@run it } }",
    ],
)
@pytest.mark.parametrize("tainted", [False, True])
def test_explicit_lambda_label_suppresses_implicit_callee_return_target(body: str, tainted: bool) -> None:
    receiver = 'input.getStringExtra("u")!!' if tainted else '"https://safe.example/"'
    source = f"""import android.content.Intent
import android.webkit.WebView
class FreshEntry {{
fun run(input: Intent): String {{
 val source = {receiver}
 {body}
 return "https://safe.example/"
}}
fun inspect(input: Intent, browser: WebView) {{
 browser.loadUrl(run(input))
}}
}}"""
    report = analyze_sources([("fresh/ExplicitLabel.kt", source)])
    assert bool(_matches(report)) is tainted, report


@pytest.mark.parametrize("label", ["outer", "run"])
def test_explicit_or_implicit_nearest_lambda_return_stays_local(label: str) -> None:
    declaration = " outer@" if label == "outer" else ""
    source = f"""import android.content.Intent
import android.webkit.WebView
class FreshEntry {{
fun run(input: Intent): String {{
 input.getStringExtra("u")!!.run{declaration} {{ return@{label} this }}
 return "https://safe.example/"
}}
fun inspect(input: Intent, browser: WebView) {{
 browser.loadUrl(run(input))
}}
}}"""
    report = analyze_sources([("fresh/NearestLabel.kt", source)])
    assert _matches(report) == [], report
