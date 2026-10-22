import pytest

from mobile_audit.hybrid_analysis import analyze_hybrid


def assert_uncertain_url_flow(result):
    assert any(finding["rule_id"] == "HYBRID-UNTRUSTED-URL" for finding in result["findings"])
    assert any("callable identity unresolved or shadowed" in warning for warning in result["warnings"])
    assert not any(edge["callee"] == "clean" for edge in result["metadata"]["call_edges"])


@pytest.mark.parametrize(
    ("path", "helper", "signature", "source"),
    [
        (
            "App.js",
            'function clean(value) { return "https://safe.example"; }',
            "function execute(clean)",
            "route.params.url",
        ),
        (
            "App.ts",
            'function clean(value: string): string { return "https://safe.example"; }',
            "function execute(clean: (value: string) => string)",
            "route.params.url",
        ),
        (
            "main.dart",
            'String clean(String value) { return "https://safe.example"; }',
            "void execute(String Function(String) clean)",
            'Uri.base.queryParameters["url"]',
        ),
    ],
)
def test_callable_parameter_shadows_unrelated_top_level_helper(path, helper, signature, source):
    body = f"{signature} {{ finalValue = {source}; web.loadUrl(clean(finalValue)); }}"
    assert_uncertain_url_flow(analyze_hybrid([(path, body)]))
    assert_uncertain_url_flow(analyze_hybrid([(path, helper + "\n" + body)]))


@pytest.mark.parametrize(
    "body",
    [
        "const clean = externalCleaner; const value = route.params.url; web.loadUrl(clean(value));",
        "let clean; const value = route.params.url; web.loadUrl(clean(value));",
        "const value = route.params.url; web.loadUrl(clean(value)); var clean;",
        "const { clean } = helpers; const value = route.params.url; web.loadUrl(clean(value));",
        "const value = route.params.url; ({ clean } = helpers); web.loadUrl(clean(value));",
        "clean = externalCleaner; const value = route.params.url; web.loadUrl(clean(value));",
        "function clean(value) { return value; } const value = route.params.url; web.loadUrl(clean(value));",
        "let unrelated = 1, clean; const value = route.params.url; web.loadUrl(clean(value));",
    ],
)
def test_local_binding_or_write_prevents_global_summary_from_erasing_taint(body):
    source = 'function clean(value) { return "https://safe.example"; } function execute() {' + body + "}"
    assert_uncertain_url_flow(analyze_hybrid([("App.js", source)]))


@pytest.mark.parametrize(
    "declaration",
    [
        'function unrelated() { function clean(value) { return "https://safe.example"; } }',
        'class Other { clean(value) { return "https://safe.example"; } }',
        'const unrelated = function clean(value) { return "https://safe.example"; };',
        'const unrelated = { clean(value) { return "https://safe.example"; } };',
    ],
)
def test_nested_member_or_function_expression_is_not_a_module_callable(declaration):
    source = declaration + " const value = route.params.url; web.loadUrl(clean(value));"
    assert_uncertain_url_flow(analyze_hybrid([("App.js", source)]))


def test_dart_member_scope_does_not_resolve_a_bare_call_to_an_unrelated_top_level_function():
    source = """
String clean(String value) { return "https://safe.example"; }
class Other {
  String clean(String value) { return value; }
  void execute() {
    final value = Uri.base.queryParameters["url"];
    web.loadUrl(clean(value));
  }
}
"""
    assert_uncertain_url_flow(analyze_hybrid([("main.dart", source)]))


def test_defaulted_parameter_still_shadows_top_level_helper():
    source = """
function clean(value) { return "https://safe.example"; }
function execute(clean = externalCleaner) {
  const value = route.params.url;
  web.loadUrl(clean(value));
}
"""
    assert_uncertain_url_flow(analyze_hybrid([("App.js", source)]))


@pytest.mark.parametrize("member_first", [False, True])
@pytest.mark.parametrize("returns_input", [False, True])
def test_same_line_same_name_member_has_a_separate_summary_identity(member_first, returns_input):
    returned = "value" if returns_input else '"https://safe.example"'
    other = '"https://safe.example"' if returns_input else "value"
    helper = f"function clean(value) {{ return {returned}; }}"
    member = f"class Other {{ clean(value) {{ return {other}; }} }}"
    declarations = (member + helper) if member_first else (helper + member)
    result = analyze_hybrid(
        [("App.js", declarations + "const value = route.params.url; web.loadUrl(clean(value));")]
    )
    assert bool(result["findings"]) is returns_input
    assert any(edge["callee"] == "clean" for edge in result["metadata"]["call_edges"])


def test_unshadowed_named_import_retains_argument_return_and_sink_flow():
    result = analyze_hybrid(
        [
            (
                "helper.ts",
                "export function clean(value: string) { return value; } "
                'class Other { clean(value: string) { return "https://safe.example"; } } '
                "export function execute(value: string) { eval(value); }",
            ),
            (
                "App.ts",
                'import { clean as forward, execute } from "./helper"; '
                "const value = route.params.url; web.loadUrl(forward(value)); execute(value);",
            ),
        ]
    )
    assert {finding["rule_id"] for finding in result["findings"]} == {
        "HYBRID-UNTRUSTED-URL",
        "HYBRID-JS-EVAL",
    }
    assert {edge["callee"] for edge in result["metadata"]["call_edges"]} == {"clean", "execute"}


def test_imported_callable_with_parameter_shadow_preserves_input():
    result = analyze_hybrid(
        [
            ("helper.ts", 'export function clean(value: string) { return "https://safe.example"; }'),
            (
                "App.ts",
                'import { clean } from "./helper"; function execute(clean: unknown) { '
                "const value = route.params.url; web.loadUrl(clean(value)); }",
            ),
        ]
    )
    assert_uncertain_url_flow(result)


def test_imported_callable_reassigned_in_exporting_module_remains_uncertain():
    result = analyze_hybrid(
        [
            (
                "helper.js",
                'export function clean(value) { return "https://safe.example"; } clean = externalCleaner;',
            ),
            (
                "App.js",
                'import { clean } from "./helper"; const value = route.params.url; web.loadUrl(clean(value));',
            ),
        ]
    )
    assert_uncertain_url_flow(result)


def test_unshadowed_dart_relative_function_remains_modeled():
    result = analyze_hybrid(
        [
            ("helper.dart", "String forward(String value) { return value; }"),
            (
                "main.dart",
                "import 'helper.dart'; void execute() { final value = Uri.base.queryParameters['url']; "
                "web.loadUrl(forward(value)); }",
            ),
        ]
    )
    assert result["findings"][0]["rule_id"] == "HYBRID-UNTRUSTED-URL"
    assert any(edge["callee_path"] == "helper.dart" for edge in result["metadata"]["call_edges"])


def test_unshadowed_function_after_automatic_semicolon_remains_modeled():
    result = analyze_hybrid(
        [
            (
                "App.js",
                '"use strict"\nfunction clean(value) { return "https://safe.example"; }\n'
                "const value = route.params.url; web.loadUrl(clean(value));",
            ),
        ]
    )
    assert not result["findings"]
    assert any(edge["callee"] == "clean" for edge in result["metadata"]["call_edges"])


@pytest.mark.parametrize(
    "parameter",
    ["clean", "(clean)", "(clean = externalCleaner)", "({ clean })", "([clean])", "(clean): Cleaner"],
)
def test_arrow_parameter_binding_cannot_select_module_helper(parameter):
    source = (
        'function clean(value) { return "https://safe.example"; } '
        f"const execute = {parameter} => {{ const value = route.params.url; web.loadUrl(clean(value)); }};"
    )
    assert_uncertain_url_flow(analyze_hybrid([("App.ts", source)]))


@pytest.mark.parametrize("target", ["clean", "{ clean }", "[clean]"])
@pytest.mark.parametrize("operator", ["of", "in"])
def test_loop_target_binding_cannot_select_module_helper(target, operator):
    source = (
        'function clean(value) { return "https://safe.example"; } '
        f"for ({target} {operator} cleaners) {{ const value = route.params.url; web.loadUrl(clean(value)); }}"
    )
    assert_uncertain_url_flow(analyze_hybrid([("App.js", source)]))


@pytest.mark.parametrize(
    "writer",
    [
        "function install() { clean = externalCleaner; } install();",
        "function install() { function nested() { clean = externalCleaner; } nested(); } install();",
        "const install = () => { clean = externalCleaner; }; install();",
        "function install() { ({ clean } = helpers); } install();",
        "function install() { [clean] = helpers; } install();",
        "function install() { clean ||= externalCleaner; } install();",
        "function install() { clean ??= externalCleaner; } install();",
        "function install() { globalThis.clean = externalCleaner; } install();",
        'function install() { globalThis["clean"] = externalCleaner; } install();',
    ],
)
def test_possible_module_binding_write_inside_another_callable_prevents_clean_summary(writer):
    source = (
        'function clean(value) { return "https://safe.example"; } '
        + writer
        + " const value = route.params.url; web.loadUrl(clean(value));"
    )
    assert_uncertain_url_flow(analyze_hybrid([("App.js", source)]))


def test_unshadowed_direct_helper_remains_modeled_alongside_an_unrelated_arrow():
    result = analyze_hybrid(
        [
            (
                "App.js",
                'function clean(value) { return "https://safe.example"; } '
                "const unrelated = (item) => item; const value = route.params.url; web.loadUrl(clean(value));",
            ),
        ]
    )
    assert not result["findings"]
    assert any(edge["callee"] == "clean" for edge in result["metadata"]["call_edges"])


def test_write_inside_exporter_function_makes_imported_binding_uncertain():
    result = analyze_hybrid(
        [
            (
                "helper.js",
                'export function clean(value) { return "https://safe.example"; } '
                "function install() { clean = externalCleaner; } install();",
            ),
            (
                "App.js",
                'import { clean } from "./helper"; const value = route.params.url; web.loadUrl(clean(value));',
            ),
        ]
    )
    assert_uncertain_url_flow(result)


def test_known_function_parameter_does_not_hide_an_unrelated_module_source_helper():
    result = analyze_hybrid(
        [
            (
                "App.js",
                "function readUrl() { return route.params.url; } "
                "function unrelated(readUrl) { return 1; } web.loadUrl(readUrl());",
            ),
        ]
    )
    assert result["findings"][0]["rule_id"] == "HYBRID-UNTRUSTED-URL"
    assert any(edge["callee"] == "readUrl" for edge in result["metadata"]["call_edges"])
