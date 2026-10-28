"""Fresh source-only controls for Kotlin non-local helper return summaries."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

URL = "AST-WEBVIEW-UNTRUSTED-URL"
PATH = "AST-PATH-TRAVERSAL"
UNAVAILABLE = "Kotlin non-local return context unavailable"


def _kotlin(body: str, *, prefix: str = "", extra: str = "", helpers: str = "") -> str:
    return f"""import android.content.Intent
import android.webkit.WebView
import java.io.InputStream
{prefix}
{helpers}
class FreshEntry {{
fun value(input: Intent, stream: InputStream{extra}): String {{
{body}
return "https://safe.example/"
}}
fun open(input: Intent, stream: InputStream, browser: WebView{extra}) {{
 browser.loadUrl(value(input, stream{", let" if extra else ""}))
}}
}}"""


def _matches(report: dict, rule: str = URL) -> list[dict]:
    return [row for row in report["findings"] if row["rule_id"] == rule]


def _scan(source: str, *others: tuple[str, str]) -> dict:
    return analyze_sources([("fresh/Nonlocal.kt", source), *others])


@pytest.mark.parametrize(
    "body",
    [
        'input.getStringExtra("url")?.let { return it }',
        'input.getStringExtra("url")?.let { text -> return text }',
        'input.getStringExtra("url")?.let { text -> text.also { return it } }',
    ],
    ids=["implicit-it", "explicit-parameter", "nested-inline"],
)
def test_unlabeled_inline_return_reaches_caller_webview(body: str) -> None:
    report = _scan(_kotlin(body))
    assert len(_matches(report)) == 1, report
    assert _matches(report)[0]["status"] == "candidate"
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["warnings"] == []


def test_use_nonlocal_return_keeps_taint_despite_constant_fallback() -> None:
    report = _scan(_kotlin('stream.use { return input.getStringExtra("url")!! }'))
    assert _matches(report), report
    # InputStream dispatch is already outside the bounded identity model;
    # the known use context must not introduce additional return uncertainty.
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"]


def test_use_reader_chain_retains_possible_return_taint() -> None:
    source = _kotlin(
        """val streamValue = java.io.ByteArrayInputStream(input.getStringExtra("url")!!.toByteArray())
streamValue.use { return it.reader().readText() }"""
    )
    report = _scan(source)
    assert _matches(report), report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"]


@pytest.mark.parametrize("scope", ["run", "apply", "with"])
@pytest.mark.parametrize("tainted", [False, True])
def test_receiver_scope_nonlocal_return_uses_lexical_this(scope: str, tainted: bool) -> None:
    value = 'input.getStringExtra("url")!!' if tainted else '"https://safe.example/"'
    body = f"with({value}) {{ return this }}" if scope == "with" else f"{value}.{scope} {{ return this }}"
    report = _scan(_kotlin(body))
    assert bool(_matches(report)) is tainted, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("inner_tainted", [False, True])
def test_nested_receiver_scope_restores_outer_this(inner_tainted: bool) -> None:
    outer = '"https://safe.example/"' if inner_tainted else 'input.getStringExtra("url")!!'
    inner = 'input.getStringExtra("url")!!' if inner_tainted else '"https://safe.example/"'
    report = _scan(_kotlin(f"{outer}.run {{ {inner}.apply {{ return@apply this }}; return this }}"))
    assert bool(_matches(report)) is not inner_tainted, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize(
    "body",
    [
        'input.getStringExtra("url")?.let { return@let it }',
        'input.getStringExtra("url")?.let { return "https://safe.example/" }',
    ],
)
def test_labeled_or_constant_return_does_not_supply_tainted_function_value(body: str) -> None:
    report = _scan(_kotlin(body))
    assert _matches(report) == [], report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_labeled_return_does_not_hide_actual_enclosing_tainted_return() -> None:
    source = _kotlin('input.getStringExtra("url")?.let { return@let "safe" }')
    source = source.replace('return "https://safe.example/"', 'return input.getStringExtra("url")!!')
    report = _scan(source)
    assert _matches(report), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize(
    "declaration",
    [
        "fun String.let(block: (String) -> Unit) {}",
        "inline fun String.let(crossinline block: (String) -> Unit) {}",
        "inline fun String.let(noinline block: (String) -> Unit) {}",
        "inline fun String.let(block: (String) -> Unit) {}",
    ],
)
@pytest.mark.parametrize("other_file", [False, True])
def test_project_declaration_does_not_gain_stdlib_inline_identity(declaration: str, other_file: bool) -> None:
    source = _kotlin(
        'input.getStringExtra("url")?.let { return it }', helpers="" if other_file else declaration
    )
    report = _scan(source, *(("fresh/CustomScope.kt", declaration),) if other_file else ())
    assert _matches(report), report  # Candidate over-approximation, never execution proof.
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"


@pytest.mark.parametrize("imported", ["import custom.let", "import custom.scope as let", "import custom.*"])
def test_import_shadow_retains_candidate_and_explicit_partial(imported: str) -> None:
    report = _scan(_kotlin('input.getStringExtra("url")?.let { return it }', prefix=imported))
    assert _matches(report), report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"


def test_callable_parameter_named_let_is_not_a_stdlib_proof() -> None:
    report = _scan(
        _kotlin('let { return input.getStringExtra("url")!! }', extra=", let: (() -> Unit) -> Unit")
    )
    assert _matches(report), report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report


def test_other_inline_callback_keeps_possible_return_with_partial_identity() -> None:
    report = _scan(
        _kotlin(
            'invokeCallback { return input.getStringExtra("url")!! }',
            helpers="inline fun invokeCallback(block: () -> Unit) { block() }",
        )
    )
    assert _matches(report), report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"


def test_kotlin_return_union_does_not_transfer_closure_guard() -> None:
    report = _scan("""import java.io.File
import android.content.Intent
class FreshEntry {
fun output(input: Intent, base: File, receiver: Any?): File {
 val target = File(base, input.getStringExtra("name")!!)
 receiver?.let {
  if (!target.canonicalPath.startsWith(base.canonicalPath + File.separator)) return target
 }
 return target
}
fun open(input: Intent, base: File, receiver: Any?) {
 output(input, base, receiver).delete()
}
}""")
    assert _matches(report, PATH), report


@pytest.mark.parametrize("tainted_return", [False, True])
def test_java_lambda_return_remains_local(tainted_return: bool) -> None:
    outer = 'input.getStringExtra("url")' if tainted_return else '"https://safe.example/"'
    source = f"""import android.content.Intent;
import android.webkit.WebView;
class FreshJava {{
static String value(Intent input) {{
 java.util.function.Supplier<String> callback = () -> {{ return input.getStringExtra("url"); }};
 return {outer};
}}
void open(Intent input, WebView browser) {{ browser.loadUrl(value(input)); }}
}}"""
    report = analyze_sources([("fresh/Local.java", source)])
    assert bool(_matches(report)) is tainted_return, report


@pytest.mark.parametrize("tainted_return", [False, True])
def test_swift_closure_return_remains_local(tainted_return: bool) -> None:
    outer = "incoming.absoluteString" if tainted_return else '"https://safe.example/"'
    source = f"""import WebKit
import UIKit
final class FreshSwift {{
 let web = WKWebView()
 func value(incoming: URL) -> String {{
  let callback: () -> String = {{ return incoming.absoluteString }}
  return {outer}
 }}
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
  web.loadHTMLString(value(incoming: incoming), baseURL: nil)
  return true
 }}
}}"""
    report = analyze_sources([("fresh/Local.swift", source)])
    assert bool(_matches(report)) is tainted_return, report
