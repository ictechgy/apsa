"""Kotlin file and package callable properties cannot certify stdlib identity."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

URL = "AST-WEBVIEW-UNTRUSTED-URL"
UNAVAILABLE = "Kotlin non-local return context unavailable"
TAINT = 'input.getStringExtra("u")!!'
CALLABLE = """class CustomScope {
inline operator fun <T, R> invoke(receiver: () -> T, block: T.() -> R): R = receiver().block()
}"""


def _sources(
    location: str,
    *,
    mutable: bool = False,
    declaration_last: bool = False,
    caller_first: bool = False,
    receiver: str = "",
    trailing: bool = False,
    sink: bool = False,
    helper: str = "",
) -> list[tuple[str, str]]:
    imported = ""
    name = "scope" if location == "alias" else "with"
    private = "private " if location in {"private-file", "private-other-file"} else ""
    declaration = f"{CALLABLE}\n{private}{'var' if mutable else 'val'} {name} = CustomScope()"
    receiver = receiver or f"{{ return {TAINT} }}"
    call = f"with({receiver}) {{ this }}" if trailing else f"with(receiver = {receiver}, block = {{ this }})"
    extra, passed = (", browser: WebView", ", browser") if sink else ("", "")
    value = f"""fun value(input: Intent{extra}): String {{
 {call}
 return "https://safe.example/"
}}"""
    caller = f"""fun inspect(input: Intent, browser: WebView) {{
 browser.loadUrl(value(input{passed}))
}}"""
    functions = [caller, value] if caller_first else [value, caller]
    entry = "class FreshEntry {\n" + "\n".join(functions) + "\n}"
    others = []
    if location in {"same-file", "private-file"}:
        entry = f"{entry}\n{declaration}" if declaration_last else f"{declaration}\n{entry}"
    elif location != "stdlib":
        namespace = "fresh" if location in {"same-package", "private-other-file"} else "custom"
        others.append(("fresh/Scope.kt", f"package {namespace}\n{declaration}"))
        imported = {
            "import": "import custom.with",
            "wildcard": "import custom.*",
            "alias": "import custom.scope as with",
        }.get(location, "")
    source = f"""package fresh
import android.content.Intent
import android.webkit.WebView
{imported}
{helper}
{entry}
"""
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


@pytest.mark.parametrize("location", ["same-file", "private-file", "same-package"])
@pytest.mark.parametrize("mutable", [False, True])
@pytest.mark.parametrize("declaration_last", [False, True])
@pytest.mark.parametrize("caller_first", [False, True])
@pytest.mark.parametrize("reverse_sources", [False, True])
def test_callable_property_retains_possible_nonlocal_return(
    location: str, mutable: bool, declaration_last: bool, caller_first: bool, reverse_sources: bool
) -> None:
    sources = _sources(
        location, mutable=mutable, declaration_last=declaration_last, caller_first=caller_first
    )
    _candidate_partial(analyze_sources(sources[::-1] if reverse_sources else sources))


@pytest.mark.parametrize("location", ["import", "wildcard", "alias"])
@pytest.mark.parametrize("mutable", [False, True])
@pytest.mark.parametrize("reverse_sources", [False, True])
def test_imported_callable_property_retains_possible_return(
    location: str, mutable: bool, reverse_sources: bool
) -> None:
    sources = _sources(location, mutable=mutable)
    _candidate_partial(analyze_sources(sources[::-1] if reverse_sources else sources))


@pytest.mark.parametrize("location", ["stdlib", "unimported-other-package", "private-other-file"])
@pytest.mark.parametrize("mutable", [False, True])
@pytest.mark.parametrize("reverse_sources", [False, True])
def test_invisible_callable_property_does_not_shadow_stdlib_receiver(
    location: str, mutable: bool, reverse_sources: bool
) -> None:
    sources = _sources(location, mutable=mutable)
    report = analyze_sources(sources[::-1] if reverse_sources else sources)
    assert _matches(report) == [], report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("location", ["same-file", "same-package"])
@pytest.mark.parametrize(
    "receiver",
    [
        f"local@ {{ return@local {TAINT} }}",
        f"{{ return@with {TAINT} }}",
        '{ return "https://safe.example/" }',
    ],
)
def test_callable_property_local_or_constant_return_does_not_taint_helper(
    location: str, receiver: str
) -> None:
    report = analyze_sources(_sources(location, receiver=receiver))
    assert _matches(report) == [], report


@pytest.mark.parametrize("location", ["same-file", "same-package"])
def test_callable_property_enclosing_function_label_remains_nonlocal(location: str) -> None:
    _candidate_partial(analyze_sources(_sources(location, receiver=f"{{ return@value {TAINT} }}")))


@pytest.mark.parametrize("location", ["same-file", "same-package"])
@pytest.mark.parametrize("trailing", [False, True])
def test_callable_property_receiver_sink_is_visited_once(location: str, trailing: bool) -> None:
    receiver = f"{{ browser.loadUrl({TAINT}); return {TAINT} }}"
    report = analyze_sources(_sources(location, receiver=receiver, trailing=trailing, sink=True))
    _candidate_partial(report, 2)
    evidence = [entry for row in _matches(report) for entry in row["evidence"]]
    assert {entry["function"] for entry in evidence} == {"value", "inspect"}, report
    points = [(entry["path"], entry["offset"]) for entry in evidence]
    assert len(points) == len(set(points)) == 2, report


@pytest.mark.parametrize("other_analyzer", [False, True])
def test_callable_property_receiver_preserves_helper_return_custody(other_analyzer: bool) -> None:
    helper = f"fun relay(input: Intent): String = {TAINT}"
    sources = _sources(
        "same-package", receiver="{ return relay(input) }", helper="" if other_analyzer else helper
    )
    if other_analyzer:
        sources.append(("fresh/Relay.kt", "package fresh\nimport android.content.Intent\n" + helper))
    _candidate_partial(analyze_sources(sources))


@pytest.mark.parametrize("name", ["run", "let", "also", "apply", "use"])
@pytest.mark.parametrize("other_file", [False, True])
def test_other_unqualified_scope_callable_properties_cannot_certify_return_context(
    name: str, other_file: bool
) -> None:
    declaration = f"""class CustomBlockScope {{
inline operator fun <T> invoke(block: () -> T): T = block()
}}
val {name} = CustomBlockScope()
"""
    source = f"""package fresh
import android.content.Intent
import android.webkit.WebView
{"" if other_file else declaration}
class FreshEntry {{
fun value(input: Intent): String {{
 {name}(block = {{ return {TAINT} }})
 return "https://safe.example/"
}}
fun inspect(input: Intent, browser: WebView) {{ browser.loadUrl(value(input)) }}
}}
"""
    sources = [("fresh/Entry.kt", source)]
    if other_file:
        sources.append(("fresh/Scope.kt", "package fresh\n" + declaration))
    _candidate_partial(analyze_sources(sources))


def test_stdlib_callable_receiver_value_stays_out_of_helper_summary() -> None:
    report = analyze_sources(_sources("stdlib", receiver=f"{{ {TAINT} }}"))
    assert _matches(report) == [], report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report
