"""Unsupported Kotlin imports withdraw scope identity without decoding new syntax."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

URL = "AST-WEBVIEW-UNTRUSTED-URL"
UNAVAILABLE = "Kotlin scope import identity unavailable"
NONLOCAL = "Kotlin non-local return context unavailable"
TAINT = 'input.getStringExtra("u")!!'
CALLABLE = """class CustomScope {
inline operator fun <T, R> invoke(receiver: () -> T, block: T.() -> R): R = receiver().block()
}
val with = CustomScope()
"""


def _sources(
    imported: str,
    *,
    quoted_call: bool = False,
    caller_first: bool = False,
    trailing: bool = False,
    receiver: str = "",
    custom: bool = True,
) -> list[tuple[str, str]]:
    name = "`with`" if quoted_call else "with"
    receiver = receiver or f"{{ return {TAINT} }}"
    call = (
        f"{name}({receiver}) {{ this }}" if trailing else f"{name}(receiver = {receiver}, block = {{ this }})"
    )
    helper = f"""fun value(input: Intent): String {{
 {call}
 return "https://safe.example/"
}}"""
    caller = "fun inspect(input: Intent, browser: WebView) { browser.loadUrl(value(input)) }"
    methods = [caller, helper] if caller_first else [helper, caller]
    joined = "\n".join(methods)
    source = f"""package fresh
import android.content.Intent
import android.webkit.WebView
import {imported}
class FreshEntry {{
{joined}
}}
"""
    return [("fresh/Entry.kt", source)] + (
        [("fresh/Scope.kt", "package custom\n" + CALLABLE)] if custom else []
    )


def _matches(report: dict) -> list[dict]:
    return [row for row in report["findings"] if row["rule_id"] == URL]


def _candidate_partial(report: dict, *, uncertain_import: bool = True) -> None:
    matches = _matches(report)
    assert len(matches) == 1, report
    assert matches[0]["status"] == "candidate", report
    reasons = report["metadata"]["native_flow"]["reasons"]
    assert NONLOCAL in reasons, report
    assert (UNAVAILABLE in reasons) == uncertain_import, report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"
    assert not any("AST syntax recovery" in warning for warning in report["warnings"]), report


@pytest.mark.parametrize(
    "imported", ["custom /* comment */ . with", "custom. /* comment */ with", "custom /* comment */ . `with`"]
)
@pytest.mark.parametrize("quoted_call", [False, True])
@pytest.mark.parametrize("caller_first", [False, True])
@pytest.mark.parametrize("trailing", [False, True])
@pytest.mark.parametrize("reverse_sources", [False, True])
def test_compiler_legal_comment_import_retains_possible_nonlocal_return(
    imported: str, quoted_call: bool, caller_first: bool, trailing: bool, reverse_sources: bool
) -> None:
    # The independent compiler record certifies these three import directives.
    sources = _sources(imported, quoted_call=quoted_call, caller_first=caller_first, trailing=trailing)
    _candidate_partial(analyze_sources(sources[::-1] if reverse_sources else sources))


@pytest.mark.parametrize(
    "imported",
    [
        "custom /* outer /* nested */ remaining */ . with",
        "custom /* first */ . /* second */ with",
        "custom. // comment\n with",
        "custom /* comment */ .*",
        "custom.scope /* comment */ as with",
        "custom.scope as /* comment */ `with`",
        "custom.`not ordinary`",
    ],
)
def test_other_unsupported_imports_supply_uncertainty_not_absent_shadow_proof(imported: str) -> None:
    # No compiler-legality claim for these shape controls. The represented
    # import is unsupported, so stdlib identity must remain unavailable.
    _candidate_partial(analyze_sources(_sources(imported)))


@pytest.mark.parametrize(
    "imported",
    ["custom.with", "custom.`with`", "`custom`.`with`", "custom. with", "custom.\n with", "custom.*"],
)
def test_supported_custom_imports_keep_existing_conservative_candidate(imported: str) -> None:
    _candidate_partial(analyze_sources(_sources(imported)), uncertain_import=False)


@pytest.mark.parametrize(
    "imported",
    ["kotlin.with", "kotlin.`with`", "kotlin.with as `with`", "kotlin.*", "kotlin.io.*", "custom.unrelated"],
)
@pytest.mark.parametrize("quoted_call", [False, True])
def test_supported_stdlib_or_unrelated_import_does_not_taint_callable_receiver(
    imported: str, quoted_call: bool
) -> None:
    report = analyze_sources(_sources(imported, quoted_call=quoted_call, custom=False))
    assert _matches(report) == [], report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "receiver",
    [
        f"local@ {{ return@local {TAINT} }}",
        f"{{ return@with {TAINT} }}",
        '{ return "https://safe.example/" }',
    ],
)
def test_unsupported_import_does_not_leak_local_or_constant_return(receiver: str) -> None:
    report = analyze_sources(_sources("custom. /* comment */ with", receiver=receiver))
    assert _matches(report) == [], report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report


def test_unknown_import_withdrawal_is_file_wide_even_without_a_return_or_scope_call() -> None:
    source = """package fresh
import custom /* one */ . first
import custom /* two */ . second
fun safe(): String = "https://safe.example/"
"""
    report = analyze_sources([("fresh/Entry.kt", source)])
    assert _matches(report) == [], report
    flow = report["metadata"]["native_flow"]
    assert UNAVAILABLE in flow["reasons"], report
    details = [row for row in flow["partial_details"] if row["reason"] == UNAVAILABLE]
    assert len(details) == 1, report
    assert details[0]["path"] == "fresh/Entry.kt" and details[0]["line"] == 2, report
    assert all(row["state"] == "partial" for row in report["coverage"]), report


def test_comments_in_strings_cannot_withdraw_known_import_identity() -> None:
    sources = _sources("kotlin.with", custom=False)
    path, source = sources[0]
    sources[0] = (
        path,
        source.replace("class FreshEntry", 'val note = "import custom /* x */ . with"\nclass FreshEntry'),
    )
    report = analyze_sources(sources)
    assert _matches(report) == [], report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("name", ["run", "let", "also", "apply", "use"])
@pytest.mark.parametrize("quoted_call", [False, True])
def test_unknown_import_withdraws_other_supported_scope_identities(name: str, quoted_call: bool) -> None:
    callee = f"`{name}`" if quoted_call else name
    entry = f"""package fresh
import android.content.Intent
import android.webkit.WebView
import custom /* opaque */ . {name}
class FreshEntry {{
fun value(input: Intent): String {{ {callee}(block = {{ return {TAINT} }}); return "https://safe.example/" }}
fun inspect(input: Intent, browser: WebView) {{ browser.loadUrl(value(input)) }}
}}
"""
    scope = f"""package custom
class CustomBlockScope {{
inline operator fun <T> invoke(block: () -> T): T = block()
}}
val {name} = CustomBlockScope()
"""
    _candidate_partial(analyze_sources([("fresh/Entry.kt", entry), ("fresh/Scope.kt", scope)]))


@pytest.mark.parametrize("imported", ["custom. ? with", "custom..with"])
def test_recovered_import_cannot_establish_scope_identity(imported: str) -> None:
    # Invalid syntax is uncertainty evidence, not a compiler-legal attack flow.
    report = analyze_sources(_sources(imported))
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"


@pytest.mark.parametrize(
    "imported",
    [
        "custom.scope /* comment */ ? with",
        "custom.scope /* comment */ ???",
        "custom.scope /* first */ /* second */ ???",
        "custom.scope /* outer /* nested */ remaining */ ???",
        "custom.scope /* first\n second */ ???",
        "custom.scope // comment\n ???",
        "custom.scope /* comment */\n ???",
        "custom.scope /* first */\n // second\n ???",
    ],
)
def test_comment_siblings_cannot_hide_adjacent_import_recovery(imported: str) -> None:
    # These are invalid-syntax diagnostics, never compiler-legal vulnerabilities.
    report = analyze_sources(_sources(imported))
    flow = report["metadata"]["native_flow"]
    assert UNAVAILABLE in flow["reasons"], report
    details = [row for row in flow["partial_details"] if row["reason"] == UNAVAILABLE]
    assert len(details) == 1, report
    assert details[0]["path"] == "fresh/Entry.kt" and details[0]["line"] == 4, report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"


@pytest.mark.parametrize(
    "tail",
    [
        " /* comment */",
        " /* first */ /* second */",
        " /* outer /* nested */ remaining */",
        " /* first\n second */",
        " // comment",
        "\n /* comment */",
        "\n // first\n /* second */",
        '; /* comment */ val ordinary = "???"',
    ],
)
@pytest.mark.parametrize("quoted_import", [False, True])
def test_valid_following_comments_and_declarations_do_not_withdraw_stdlib_identity(
    tail: str, quoted_import: bool
) -> None:
    name = "kotlin.`with`" if quoted_import else "kotlin.with"
    report = analyze_sources(_sources(name + tail, custom=False))
    assert _matches(report) == [], report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report
    assert not any("AST syntax recovery" in warning for warning in report["warnings"]), report
