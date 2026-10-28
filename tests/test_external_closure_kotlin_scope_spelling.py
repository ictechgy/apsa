"""Escaped ordinary Kotlin names keep callable scope identity conservative."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import Analyzer, analyze_sources

URL = "AST-WEBVIEW-UNTRUSTED-URL"
UNAVAILABLE = "Kotlin non-local return context unavailable"
TAINT = 'input.getStringExtra("u")!!'
CALLABLE = """class CustomScope {
inline operator fun <T, R> invoke(receiver: () -> T, block: T.() -> R): R = receiver().block()
}"""
INLINE = "inline fun <T, R> NAME(receiver: () -> T, block: T.() -> R): R = receiver().block()"


def _sources(
    location: str,
    *,
    quoted_declaration: bool = True,
    quoted_call: bool = False,
    mutable: bool = False,
    declaration_last: bool = False,
    caller_first: bool = False,
    receiver: str = "",
    trailing: bool = False,
    sink: bool = False,
) -> list[tuple[str, str]]:
    declaration_name = "`with`" if quoted_declaration else "with"
    call_name = "`with`" if quoted_call else "with"
    receiver = receiver or f"{{ return {TAINT} }}"
    call = (
        f"{call_name}({receiver}) {{ this }}"
        if trailing
        else f"{call_name}(receiver = {receiver}, block = {{ this }})"
    )
    declaration = f"{'var' if mutable else 'val'} {declaration_name} = CustomScope()"
    setup = member = extra = passed = imported = prefix = ""
    others = []
    if location in {"function-file", "function-package", "function-import"}:
        declaration = INLINE.replace("NAME", declaration_name)
    elif location == "local":
        setup, declaration, prefix = declaration, "", CALLABLE
    elif location == "parameter":
        extra, passed, declaration, prefix = (
            f", {declaration_name}: CustomScope",
            ", CustomScope()",
            "",
            CALLABLE,
        )
    elif location == "member":
        member, declaration, prefix = declaration, "", CALLABLE
    elif location != "stdlib":
        declaration = CALLABLE + "\n" + declaration
    else:
        declaration = ""
    if location in {"same-file", "function-file", "private-file"}:
        if location == "private-file":
            declaration = declaration.replace("val ", "private val ").replace("var ", "private var ")
    elif location in {"same-package", "function-package", "private-other-file"}:
        if location == "private-other-file":
            declaration = declaration.replace("val ", "private val ").replace("var ", "private var ")
        others.append(("fresh/Scope.kt", "package fresh\n" + declaration))
        declaration = ""
    elif location in {"import", "escaped-import", "function-import", "unimported-other-package", "alias"}:
        if location == "alias":
            declaration = declaration.replace(declaration_name + " =", "scope =")
            imported = "import custom.scope as `with`"
        elif location != "unimported-other-package":
            imported = "import `custom`.`with`" if location == "escaped-import" else "import custom.with"
        others.append(("fresh/Scope.kt", "package custom\n" + declaration))
        declaration = ""
    if sink:
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
    methods = [caller, value] if caller_first else [value, caller]
    entry = "class FreshEntry {\n" + member + "\n" + "\n".join(methods) + "\n}"
    entry = f"{entry}\n{declaration}" if declaration_last else f"{declaration}\n{entry}"
    return [
        (
            "fresh/Entry.kt",
            f"package fresh\nimport android.content.Intent\nimport android.webkit.WebView\n{imported}\n{prefix}\n{entry}",
        ),
        *others,
    ]


def _matches(report: dict) -> list[dict]:
    return [row for row in report["findings"] if row["rule_id"] == URL]


def _candidate_partial(report: dict, count: int = 1) -> None:
    matches = _matches(report)
    assert len(matches) == count, report
    assert all(row["status"] == "candidate" for row in matches), report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report
    assert next(row for row in report["coverage"] if row["rule_id"] == URL)["state"] == "partial"
    assert not any("AST syntax recovery" in warning for warning in report["warnings"]), report


@pytest.mark.parametrize("location", ["same-file", "same-package", "private-file"])
@pytest.mark.parametrize("mutable", [False, True])
@pytest.mark.parametrize("quoted_call", [False, True])
@pytest.mark.parametrize("declaration_last", [False, True])
@pytest.mark.parametrize("caller_first", [False, True])
@pytest.mark.parametrize("reverse_sources", [False, True])
def test_escaped_property_retains_nonlocal_candidate(
    location: str,
    mutable: bool,
    quoted_call: bool,
    declaration_last: bool,
    caller_first: bool,
    reverse_sources: bool,
) -> None:
    sources = _sources(
        location,
        mutable=mutable,
        quoted_call=quoted_call,
        declaration_last=declaration_last,
        caller_first=caller_first,
    )
    _candidate_partial(analyze_sources(sources[::-1] if reverse_sources else sources))


@pytest.mark.parametrize(
    "location",
    [
        "import",
        "escaped-import",
        "function-file",
        "function-package",
        "function-import",
        "local",
        "parameter",
        "member",
    ],
)
@pytest.mark.parametrize("quoted_declaration", [False, True])
@pytest.mark.parametrize("quoted_call", [False, True])
@pytest.mark.parametrize("reverse_sources", [False, True])
def test_scope_binding_spelling_is_consistent(
    location: str, quoted_declaration: bool, quoted_call: bool, reverse_sources: bool
) -> None:
    sources = _sources(location, quoted_declaration=quoted_declaration, quoted_call=quoted_call)
    _candidate_partial(analyze_sources(sources[::-1] if reverse_sources else sources))


@pytest.mark.parametrize("location", ["stdlib", "private-other-file", "unimported-other-package"])
@pytest.mark.parametrize("quoted_call", [False, True])
@pytest.mark.parametrize("reverse_sources", [False, True])
def test_invisible_escaped_property_does_not_shadow_builtin_receiver(
    location: str, quoted_call: bool, reverse_sources: bool
) -> None:
    sources = _sources(location, quoted_call=quoted_call)
    report = analyze_sources(sources[::-1] if reverse_sources else sources)
    assert _matches(report) == [], report
    assert UNAVAILABLE in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("quoted_call", [False, True])
def test_quoted_alias_is_uncertain_not_a_stdlib_identity_proof(quoted_call: bool) -> None:
    # This non-local-return shape is compiler-rejected for the quoted alias.
    # Retaining a possible candidate is conservative, not execution/legality proof.
    _candidate_partial(analyze_sources(_sources("alias", quoted_call=quoted_call)))


@pytest.mark.parametrize("quoted_call", [False, True])
@pytest.mark.parametrize("receiver", [f"local@ {{ return@local {TAINT} }}", f"{{ return@with {TAINT} }}"])
def test_escaped_callable_local_labels_do_not_taint_helper(quoted_call: bool, receiver: str) -> None:
    report = analyze_sources(_sources("same-package", quoted_call=quoted_call, receiver=receiver))
    assert _matches(report) == [], report


@pytest.mark.parametrize("quoted_call", [False, True])
def test_escaped_callable_return_to_enclosing_function_is_retained(quoted_call: bool) -> None:
    _candidate_partial(
        analyze_sources(
            _sources("same-package", quoted_call=quoted_call, receiver=f"{{ return@value {TAINT} }}")
        )
    )


@pytest.mark.parametrize("quoted_call", [False, True])
@pytest.mark.parametrize("trailing", [False, True])
def test_escaped_receiver_sink_is_visited_once(quoted_call: bool, trailing: bool) -> None:
    report = analyze_sources(
        _sources(
            "same-package",
            quoted_call=quoted_call,
            trailing=trailing,
            sink=True,
            receiver=f"{{ browser.loadUrl({TAINT}); return {TAINT} }}",
        )
    )
    _candidate_partial(report, 2)
    evidence = [entry for row in _matches(report) for entry in row["evidence"]]
    points = [(entry["path"], entry["offset"]) for entry in evidence]
    assert len(points) == len(set(points)) == 2, report


@pytest.mark.parametrize("name", ["run", "let", "also", "apply", "use"])
@pytest.mark.parametrize("other_file", [False, True])
def test_other_escaped_scope_properties_remain_uncertain(name: str, other_file: bool) -> None:
    declaration = f"""class CustomBlockScope {{
inline operator fun <T> invoke(block: () -> T): T = block()
}}
val `{name}` = CustomBlockScope()
"""
    source = f"""package fresh
import android.content.Intent
import android.webkit.WebView
{"" if other_file else declaration}
class FreshEntry {{
fun value(input: Intent): String {{ {name}(block = {{ return {TAINT} }}); return "https://safe.example/" }}
fun inspect(input: Intent, browser: WebView) {{ browser.loadUrl(value(input)) }}
}}
"""
    sources = [("fresh/Entry.kt", source)]
    if other_file:
        sources.append(("fresh/Scope.kt", "package fresh\n" + declaration))
    _candidate_partial(analyze_sources(sources))


def test_string_content_cannot_supply_a_scope_shadow() -> None:
    sources = _sources("stdlib")
    path, source = sources[0]
    sources[0] = (
        path,
        source.replace("class FreshEntry", 'val note = "val `with` = CustomScope()"\nclass FreshEntry'),
    )
    assert _matches(analyze_sources(sources)) == []


@pytest.mark.parametrize("quoted_parameter", [False, True])
@pytest.mark.parametrize("quoted_reference", [False, True])
def test_data_parameter_spelling_keeps_its_value(quoted_parameter: bool, quoted_reference: bool) -> None:
    sources = _sources("same-package")
    path, source = sources[0]
    if quoted_parameter:
        source = source.replace("input: Intent", "`input`: Intent")
    if quoted_reference:
        source = source.replace("input.getStringExtra", "`input`.getStringExtra")
    sources[0] = (path, source)
    _candidate_partial(analyze_sources(sources))


@pytest.mark.parametrize("quoted_call", [False, True])
def test_scope_lambda_parameter_shadow_has_canonical_spelling(quoted_call: bool) -> None:
    sources = _sources("stdlib", quoted_call=quoted_call)
    path, source = sources[0]
    call = f"{'`with`' if quoted_call else 'with'}(receiver = {{ return {TAINT} }}, block = {{ this }})"
    source = source.replace(call, "CustomScope().let { `with` -> " + call + " }")
    sources[0] = (path, source.replace("class FreshEntry", CALLABLE + "\nclass FreshEntry"))
    _candidate_partial(analyze_sources(sources))


def test_escaped_enclosing_function_and_return_label_keep_summary_custody() -> None:
    sources = _sources("same-package", receiver=f"{{ return@`value` {TAINT} }}")
    path, source = sources[0]
    sources[0] = (path, source.replace("fun value(", "fun `value`("))
    _candidate_partial(analyze_sources(sources))


@pytest.mark.parametrize("language", ["java", "swift"])
def test_other_languages_do_not_normalize_kotlin_escapes(language: str) -> None:
    analyzer = Analyzer("fresh/Entry", "", language)
    assert analyzer.symbol_name("`with`") == "`with`"
    assert analyzer.import_name("custom.`with`") == "custom.`with`"


def test_ordinary_symbol_normalization_does_not_rewrite_source_or_accept_other_escapes() -> None:
    text = 'val note = "`with`"\n'
    analyzer = Analyzer("fresh/Entry.kt", text, "kotlin")
    assert analyzer.symbol_name("`with`") == "with"
    assert analyzer.symbol_name("`not ordinary`") == "`not ordinary`"
    assert analyzer.import_name("custom.`with` as `run`") == "custom.with as run"
    assert analyzer.import_name("custom.`not ordinary`") == "custom.`not ordinary`"
    assert analyzer.raw == text.encode()
