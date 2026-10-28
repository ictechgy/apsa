"""Kotlin scope-call spelling must not change non-local helper return evidence."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

URL = "AST-WEBVIEW-UNTRUSTED-URL"
UNAVAILABLE = "Kotlin non-local return context unavailable"


def _scan(
    body: str, *, tainted: bool = True, prefix: str = "", helpers: str = "", direct: bool = False
) -> dict:
    receiver = 'input.getStringExtra("url")!!' if tainted else '"https://safe.example/"'
    declaration = f"val source = {receiver}"
    if direct:
        body = body.replace("source", receiver)
        declaration = ""
    source = f"""import android.content.Intent
import android.webkit.WebView
{prefix}
{helpers}
class FreshEntry {{
fun value(input: Intent): String {{
 {declaration}
 {body}
 return "https://safe.example/"
}}
fun navigate(input: Intent, browser: WebView) {{
 browser.loadUrl(value(input))
}}
}}"""
    return analyze_sources([("fresh/ArgumentScope.kt", source)])


def _matches(report: dict) -> list[dict]:
    return [row for row in report["findings"] if row["rule_id"] == URL]


@pytest.mark.parametrize(
    "body",
    [
        "source.let({ return it })",
        "source?.let({ text -> return text })",
        "source.let(block = { return it })",
        "source.let(({ return it }))",
        "source.also({ return it })",
        "source.run({ return this })",
        "source.run(block = { return this })",
        "source.apply({ return this })",
        "with(source, { return this })",
        "with(receiver = source, block = { return this })",
        "source.let { return it }",
        "with(source) { return this }",
    ],
)
@pytest.mark.parametrize("tainted", [False, True])
def test_argument_and_trailing_spellings_preserve_helper_return(body: str, tainted: bool) -> None:
    report = _scan(body, tainted=tainted)
    assert bool(_matches(report)) is tainted, report
    # Existing bounded object/call identity can independently remain partial for
    # argument lambdas. A bound standard scope must add no return uncertainty.
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report
    if body.endswith("{ return it }") or body == "with(source) { return this }":
        assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize(
    "body",
    [
        "source.let({ return it })",
        "source?.let({ text -> return text })",
        "source.let(block = { return it })",
        "source.let(({ return it }))",
        "source.run({ return this })",
        "source.run(block = { return this })",
        "with(source, { return this })",
        "with(receiver = source, block = { return this })",
    ],
)
@pytest.mark.parametrize("tainted", [False, True])
def test_direct_receiver_requires_real_argument_binding(body: str, tainted: bool) -> None:
    report = _scan(body, tainted=tainted, direct=True)
    assert bool(_matches(report)) is tainted, report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "body",
    [
        "source.let({ return@let it })",
        "source.let(block = { text -> return@let text })",
        "source.run({ return@run this })",
        "with(source, { return@with this })",
        "with(source) { return@with this }",
        'source.let({ return "https://safe.example/" })',
    ],
)
def test_local_or_constant_lambda_return_does_not_taint_function(body: str) -> None:
    report = _scan(body)
    assert _matches(report) == [], report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    ("prefix", "helpers"),
    [
        ("import custom.let", ""),
        ("import custom.callback as let", ""),
        ("import custom.*", ""),
        ("", "inline fun String.let(block: (String) -> Unit) { block(this) }"),
        ("", "fun String.let(block: (String) -> Unit) { block(this) }"),
    ],
)
def test_shadowed_argument_scope_retains_possible_value_and_partial(prefix: str, helpers: str) -> None:
    report = _scan("source.let(block = { return it })", prefix=prefix, helpers=helpers)
    assert _matches(report), report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"


@pytest.mark.parametrize("tainted", [False, True])
def test_nested_argument_scopes_restore_the_outer_receiver(tainted: bool) -> None:
    report = _scan('source.run({ "safe".apply({ return@apply this }); return this })', tainted=tainted)
    assert bool(_matches(report)) is tainted, report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


def test_unknown_argument_lambda_is_explicitly_partial() -> None:
    report = _scan(
        "callback({ return source })",
        helpers="inline fun callback(block: () -> Unit) { block() }",
    )
    assert _matches(report), report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "body",
    [
        "return@value source",
        "source.let { return@value it }",
        "source.let({ return@value it })",
        "source.let(block = { text -> return@value text })",
        "source.run({ return@value this })",
    ],
)
@pytest.mark.parametrize("tainted", [False, True])
def test_compiler_accepted_return_to_function_label_preserves_value(body: str, tainted: bool) -> None:
    report = _scan(body, tainted=tainted)
    assert bool(_matches(report)) is tainted, report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "body",
    [
        "source.let value@ { return@value it }",
        "source.let(block = value@ { return@value it })",
        "source.let({ return@let it })",
    ],
)
def test_nearest_explicit_or_implicit_lambda_label_stays_local(body: str) -> None:
    report = _scan(body)
    assert _matches(report) == [], report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


def test_same_named_call_implicit_label_shadows_enclosing_function() -> None:
    report = _scan(
        "source.value { return@value it }",
        helpers="inline fun String.value(block: (String) -> String) { block(this) }",
    )
    assert _matches(report) == [], report


def test_named_function_return_through_unknown_callback_is_partial_and_retained() -> None:
    report = _scan(
        "callback { return@value source }",
        helpers="inline fun callback(block: () -> Unit) { block() }",
    )
    assert _matches(report), report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "body",
    [
        "with(receiver = source, block = { return this })",
        "with(block = { return this }, receiver = source)",
        "with(block = { return this }, receiver = (source))",
        "with(block = ({ return this }), receiver = source)",
        "with(block = { return@value this }, receiver = source)",
        "with(receiver = source) { return this }",
        "with((source)) { return@value this }",
    ],
)
@pytest.mark.parametrize("tainted", [False, True])
def test_with_parameter_names_preserve_receiver_in_either_order(body: str, tainted: bool) -> None:
    report = _scan(body, tainted=tainted)
    assert bool(_matches(report)) is tainted, report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "body",
    [
        "with(block = { return@with this }, receiver = source)",
        "with(block = value@ { return@value this }, receiver = source)",
        "with(receiver = source) value@ { return@value this }",
    ],
)
def test_reordered_with_keeps_nearest_lambda_returns_local(body: str) -> None:
    report = _scan(body)
    assert _matches(report) == [], report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "body",
    [
        "with(block = { return this }, receiver = source, receiver = source)",
        "with(unknown = source, block = { return this })",
        "with(block = { return this }, source)",
        "with(receiver = source, block = { return this }) { return this }",
    ],
)
def test_ambiguous_with_layout_is_explicitly_partial(body: str) -> None:
    report = _scan(body)
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"


def test_lambda_valued_with_receiver_is_not_executed_as_its_block() -> None:
    report = _scan('with(block = { return "https://safe.example/" }, receiver = { source })')
    # The receiver lambda has no invocation and is distinct from the
    # constant-returning inline block.
    assert _matches(report) == [], report


def test_reordered_with_import_shadow_keeps_return_uncertainty() -> None:
    report = _scan("with(block = { return this }, receiver = source)", prefix="import custom.with")
    assert _matches(report), report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report
