"""Shadowed with receiver lambdas retain possible non-local helper returns."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

URL = "AST-WEBVIEW-UNTRUSTED-URL"
UNAVAILABLE = "Kotlin non-local return context unavailable"
TAINT = 'input.getStringExtra("u")!!'
INLINE = "inline fun <T, R> with(receiver: () -> T, block: T.() -> R): R = receiver().block()"
CALLABLE = """class CustomScope {
inline operator fun <T, R> invoke(receiver: () -> T, block: T.() -> R): R = receiver().block()
}"""


def _sources(
    shadow: str,
    call: str,
    *,
    caller_first: bool = False,
    helper: str = "",
    browser_parameter: bool = False,
) -> list[tuple[str, str]]:
    prefix = declarations = setup = extra = passed = ""
    others = []
    if shadow in {"import", "wildcard", "alias"}:
        prefix = {
            "import": "import custom.with",
            "wildcard": "import custom.*",
            "alias": "import custom.scope as with",
        }[shadow]
        declaration = INLINE.replace("with(", "scope(") if shadow == "alias" else INLINE
        others.append(("fresh/Custom.kt", "package custom\n" + declaration))
    elif shadow == "same-file":
        declarations = INLINE
    elif shadow == "project":
        others.append(("fresh/ProjectScope.kt", INLINE))
    elif shadow in {"local", "parameter"}:
        declarations = CALLABLE
        if shadow == "local":
            setup = "val with = CustomScope()"
        else:
            extra, passed = ", with: CustomScope", ", CustomScope()"
    if browser_parameter:
        extra += ", browser: WebView"
        passed += ", browser"
    value = f"""fun value(input: Intent{extra}): String {{
 {setup}
 {call}
 return "https://safe.example/"
}}"""
    caller = f"""fun inspect(input: Intent, browser: WebView) {{
 browser.loadUrl(value(input{passed}))
}}"""
    functions = [caller, value] if caller_first else [value, caller]
    function_source = "\n".join(functions)
    source = f"""import android.content.Intent
import android.webkit.WebView
{prefix}
{declarations}
{helper}
class FreshEntry {{
{function_source}
}}"""
    return [("fresh/Entry.kt", source), *others]


def _matches(report: dict) -> list[dict]:
    return [row for row in report["findings"] if row["rule_id"] == URL]


def _candidate_partial(report: dict, count: int = 1) -> None:
    matches = _matches(report)
    assert len(matches) == count, report
    assert all(row["status"] == "candidate" for row in matches), report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"
    assert not any("AST syntax recovery" in warning for warning in report["warnings"]), report


@pytest.mark.parametrize(
    "shadow", ["import", "wildcard", "alias", "same-file", "project", "local", "parameter"]
)
@pytest.mark.parametrize("reverse_sources", [False, True])
@pytest.mark.parametrize("caller_first", [False, True])
def test_shadowed_receiver_nonlocal_return_keeps_candidate(
    shadow: str, reverse_sources: bool, caller_first: bool
) -> None:
    sources = _sources(
        shadow,
        f"with(receiver = {{ return {TAINT} }}, block = {{ this }})",
        caller_first=caller_first,
    )
    report = analyze_sources(list(reversed(sources)) if reverse_sources else sources)
    _candidate_partial(report)


@pytest.mark.parametrize(
    "call",
    [
        f"with(block = {{ this }}, receiver = {{ return {TAINT} }})",
        f"with({{ return {TAINT} }}, {{ this }})",
        f"with({{ return {TAINT} }}) {{ this }}",
        f"with(receiver = {{ return {TAINT} }}) {{ this }}",
        f"with(block = {{ this }}, receiver = ({{ return {TAINT} }}))",
    ],
)
def test_shadowed_receiver_argument_layout_keeps_candidate(call: str) -> None:
    _candidate_partial(analyze_sources(_sources("same-file", call)))


@pytest.mark.parametrize(
    "receiver",
    [
        f"local@ {{ return@local {TAINT} }}",
        f"{{ return@with {TAINT} }}",
        '{ return "https://safe.example/" }',
    ],
)
def test_shadowed_local_or_constant_return_does_not_taint_helper(receiver: str) -> None:
    report = analyze_sources(_sources("same-file", f"with(receiver = {receiver}, block = {{ this }})"))
    assert _matches(report) == [], report


def test_shadowed_receiver_return_to_enclosing_function_label_is_retained() -> None:
    report = analyze_sources(
        _sources("same-file", f"with(receiver = {{ return@value {TAINT} }}, block = {{ this }})")
    )
    _candidate_partial(report)


def test_unshadowed_stdlib_invalid_receiver_return_stays_out_of_summary() -> None:
    report = analyze_sources(_sources("stdlib", f"with(receiver = {{ return {TAINT} }}, block = {{ this }})"))
    assert _matches(report) == [], report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report


def test_unshadowed_stdlib_callable_receiver_value_is_not_a_helper_return() -> None:
    report = analyze_sources(_sources("stdlib", f"with(receiver = {{ {TAINT} }}, block = {{ this() }})"))
    assert _matches(report) == [], report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("trailing", [False, True])
def test_shadowed_receiver_body_sink_is_inspected_once_and_return_is_retained(trailing: bool) -> None:
    receiver = f"{{ browser.loadUrl({TAINT}); return {TAINT} }}"
    call = f"with({receiver}) {{ this }}" if trailing else f"with(receiver = {receiver}, block = {{ this }})"
    report = analyze_sources(_sources("same-file", call, browser_parameter=True))
    _candidate_partial(report, 2)
    evidence = [entry for row in _matches(report) for entry in row["evidence"]]
    assert {entry["function"] for entry in evidence} == {"value", "inspect"}, report
    sink_points = [(entry["path"], entry["offset"]) for entry in evidence]
    assert len(sink_points) == len(set(sink_points)) == 2, report


@pytest.mark.parametrize("other_analyzer", [False, True])
def test_shadowed_receiver_preserves_return_summary_custody_during_helper_call(other_analyzer: bool) -> None:
    helper = f"fun relay(input: Intent): String = {TAINT}"
    sources = _sources(
        "same-file",
        "with(receiver = { return relay(input) }, block = { this })",
        helper="" if other_analyzer else helper,
    )
    if other_analyzer:
        sources.append(("fresh/Relay.kt", "import android.content.Intent\n" + helper))
    _candidate_partial(analyze_sources(sources))


def test_compiler_legal_shadowed_callable_this_body_retains_return() -> None:
    sources = _sources(
        "same-file",
        f"with(receiver = {{ return {TAINT} }}, block = {{ this() }})",
        helper="operator fun String.invoke(): String = this",
    )
    _candidate_partial(analyze_sources(sources))
