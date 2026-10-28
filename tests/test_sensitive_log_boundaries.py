"""Security controls for call-local sensitive-log pattern evidence."""

from __future__ import annotations

import json

import pytest

from mobile_audit import rules as rule_module
from mobile_audit.cli import main
from mobile_audit.rules import static_checks
from mobile_audit.sensitive_logging import CALL, MATCHER, SENSITIVE, sensitive_log_matches
from mobile_audit.source_analysis import analyze_sources

# Node accepts these exact fixtures, but the pinned JS grammar reports an
# unsupported parse. Keep candidate counts strict and expose partial coverage.
GRAMMAR_GAP_TEMPLATES = {
    'const value = 1 /*\n*/function done() {} /"/.test(x); console.log(PAYLOAD);',
    'function* f(){yield /* gap\n*/{} /"/.test(x); console.log(PAYLOAD);}',
    'debugger\n/"/.test(x); console.log(PAYLOAD);',
    'outer: while(x){break outer\n/"/.test(x); console.log(PAYLOAD);}',
    'outer: while(x){continue outer\n/"/.test(x); console.log(PAYLOAD);}',
    'const value=1\rfunction done() {} /"/.test(x); console.log(PAYLOAD);',
    'function f(){return\r{} /"/.test(x); console.log(PAYLOAD);}',
    'function f(){return /*\r*/ {} /"/.test(x); console.log(PAYLOAD);}',
    'import "pkg"\n/"/.test(x); console.log(PAYLOAD);',
    'import value from "pkg"\n/"/.test(x); console.log(PAYLOAD);',
    'export * from "pkg"\n/"/.test(x); console.log(PAYLOAD);',
    'export {value} from "pkg"\n/"/.test(x); console.log(PAYLOAD);',
    'type Shape={}\n/"/.test(x); console.log(PAYLOAD);',
}


def expected_js_coverage(source: str) -> str:
    normalized = source.replace('"status"', "PAYLOAD").replace("password", "PAYLOAD")
    return "partial" if normalized in GRAMMAR_GAP_TEMPLATES else "checked"


def inspect(source: str, suffix: str = ".js") -> tuple[list[dict], dict]:
    findings, coverage = static_checks(
        {"platforms": ["android", "ios"], "android_config": [], "ios_config": []},
        [("Independent" + suffix, source)],
    )
    return (
        [item for item in findings if item["rule_id"] == "STORAGE-SENSITIVE-LOG"],
        next(item for item in coverage if item["rule_id"] == "STORAGE-SENSITIVE-LOG"),
    )


@pytest.mark.parametrize(
    "source,suffix",
    [
        ('Log.d("tag", password);', ".java"),
        ('Log.e("tag", decorate(getSession()));', ".kt"),
        ("println(format(email))", ".kt"),
        ('print("password: \\(password)")', ".swift"),
        ('NSLog(@"password=%@", password);', ".m"),
        ('print("session: ${session}");', ".dart"),
        ('console.log("token", token);', ".js"),
        ("logger.error({details: {password}});", ".ts"),
        ('console.log("status", format("ok"), account.email);', ".js"),
        ('console.log(\n  "status",\n  getPassword()\n);', ".js"),
        ('Log.i(\n "tag",\n password\n);', ".java"),
        ('console.log("token=" + value + ")");', ".js"),
        ('console.log("status", /[)]/.test(text), password);', ".js"),
        ("console.log(2 / (count + 1), token);", ".js"),
        ("console.log(`status ${format(`nested ${password}`)}`);", ".js"),
        ('println("status ${format("password")}")', ".kt"),
        ('print("status \\(format("password"))")', ".swift"),
        ('print(#"status \\#(format("password"))"#)', ".swift"),
        ('print(r"status )", password);', ".dart"),
        ('print("""\nstatus )\n"password"\n""")', ".swift"),
        ("console.log(/\\)/, token);", ".js"),
        (r"console.log(/https?:\/\//.test(url), token);", ".js"),
        (r"const pattern = /\//; console.log(password);", ".js"),
        (r"const pattern = /console.log(password)/; console.log(token);", ".js"),
        (r"console.log(() => {if (ok) /[)]/.test(text); return token;});", ".js"),
    ],
)
def test_sensitive_values_within_the_call_remain_candidates(source, suffix):
    findings, coverage = inspect(source, suffix)
    assert len(findings) == 1
    assert findings[0]["status"] == "candidate"
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source,suffix",
    [
        ('console.log("status"); password = incoming;', ".js"),
        ('console.log("status"); popToken();', ".js"),
        ('console.log("status"), next(session);', ".js"),
        ('console.log(format("status")); password = incoming;', ".js"),
        ('console.log({event: "status"}); handleSession();', ".js"),
        ('console.log("status )"); password = incoming;', ".js"),
        ('console.log("status \\" )"); password = incoming;', ".js"),
        ("console.log('status )'); password = incoming;", ".js"),
        ("console.log(`status )`); password = incoming;", ".js"),
        ("console.log(`status ${format(`nested )`)}`); password = incoming;", ".js"),
        ("console.log(/\\)/.test(text)); password = incoming;", ".js"),
        ('console.log(/[")]/.test(text)); password = incoming;', ".js"),
        ("console.log(2 / (count + 1)); password = incoming;", ".js"),
        ('Log.d("tag", "status"); password = incoming;', ".java"),
        ('println("status ${format("ok")}"); password = incoming;', ".kt"),
        ('print("status \\(format("ok"))"); password = incoming;', ".swift"),
        ('print(#"status \\#(format("ok"))"#); password = incoming;', ".swift"),
        ('print(r"status )"); password = incoming;', ".dart"),
        ('print("""\nstatus )\n"ok"\n"""); password = incoming;', ".swift"),
        ('const documentation = "console.log(password)";', ".js"),
        ("const documentation = `console.log(password)`;", ".js"),
        ("const pattern = /console.log(password)/;", ".js"),
        (r"console.log(/https?:\/\//.test(url)); password = incoming;", ".js"),
        ('// console.log(password)\nconsole.log("status");', ".js"),
        ('/* console.log(password) */ console.log("status");', ".js"),
        ('blueprint("status"); password = incoming;', ".java"),
    ],
)
def test_later_statements_and_quoted_api_names_are_not_log_arguments(source, suffix):
    findings, coverage = inspect(source, suffix)
    assert not findings
    assert coverage["state"] == "checked"


def test_many_non_sensitive_calls_cannot_consume_the_finding_cap_before_a_real_log():
    source = 'console.log("status"); popToken();\n' * 100 + 'console.log("status", password);'
    findings, coverage = inspect(source)
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["line"] == 101
    assert coverage["state"] == "checked"
    assert coverage["truncated"] is False


def test_separate_calls_on_a_minified_line_each_keep_their_own_evidence():
    findings, coverage = inspect(
        'console.log("status"); next(token); console.log(password); logger.warn(secret);'
    )
    assert len(findings) == 2
    assert len({item["id"] for item in findings}) == 2
    assert [item["evidence"][0]["offset"] for item in findings] == [36, 59]
    assert coverage["state"] == "checked"


def test_ast_redacted_calls_cannot_consume_the_cap_before_a_real_log():
    source = (
        "/* 한글 */ class Probe { void audit(String password) { "
        + 'Log.d("tag", "password=[REDACTED]");' * 40
        + 'Log.d("tag", password); } }'
    )
    path = "Independent.java"
    structural = analyze_sources([(path, source)])
    findings, coverage = static_checks(
        {"platforms": ["android"], "android_config": [], "ios_config": []},
        [(path, source)],
        structural["pattern_exclusions"],
    )
    logs = [item for item in findings if item["rule_id"] == "STORAGE-SENSITIVE-LOG"]
    assert len(logs) == 1
    expected_offset = len(source[: source.index('Log.d("tag", password)')].encode("utf-8"))
    assert logs[0]["evidence"][0]["offset"] == expected_offset
    check = next(item for item in coverage if item["rule_id"] == "STORAGE-SENSITIVE-LOG")
    assert check["state"] == "checked"
    assert check["truncated"] is False


def test_quoted_fake_call_does_not_hide_the_following_real_call():
    findings, coverage = inspect('const text = "console.log(password)";\nconsole.log(token);')
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["line"] == 2
    assert coverage["state"] == "checked"


def test_interpolated_code_keeps_a_real_nested_log_call():
    findings, coverage = inspect("const text = `status ${logger.info(password)}`;")
    assert len(findings) == 1
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source",
    [
        "console.log(\n password;",
        'console.log({value: "status"); password;',
        'console.log("unterminated\n password;',
        "console.log(`unterminated ${password}",
    ],
)
def test_malformed_candidates_stay_visible_with_partial_boundary_coverage(source):
    findings, coverage = inspect(source)
    assert findings
    assert coverage["state"] == "partial"
    assert "boundaries" in coverage["note"]
    assert coverage["truncated"] is False


@pytest.mark.parametrize(
    "source,suffix",
    [
        ("const ratio = n++ / divisor; console.log(password); const other = x / y;", ".js"),
        ("const ratio = n-- / divisor; console.log(password); const other = x / y;", ".js"),
        ("const ratio = ++n / divisor; console.log(password); const other = x / y;", ".js"),
        ("const ratio = n! / divisor; console.log(password); const other = x / y;", ".ts"),
        ('if (ok) {} /"/.test(x); console.log(password);', ".js"),
        (r"console.log(() => { if(ok) {} /\}\)/.test(x); }, password);", ".js"),
        ('function done() {} /"/.test(x); console.log(password);', ".js"),
        ("const done = function() {} / divisor; console.log(password); const other = x / y;", ".js"),
        ("const done = (() => {}) / divisor; console.log(password); const other = x / y;", ".js"),
        ('class Done {} /"/.test(x); console.log(password);', ".js"),
        ("const Done = class {} / divisor; console.log(password); const other = x / y;", ".js"),
        ("const value = {} / divisor; console.log(password); const other = x / y;", ".js"),
        (r"print(/\)/, password)", ".swift"),
        (r'print(/"/, password)', ".swift"),
        (r"print(#/\)/#, password)", ".swift"),
        (r"let ratio = count! / divisor; print(password); let other = x / y;", ".swift"),
        ("console.log(/* ordinary comment */ password);", ".js"),
    ],
)
def test_slash_context_cannot_hide_a_real_sensitive_argument(source, suffix):
    findings, coverage = inspect(source, suffix)
    assert len(findings) == 1
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source,suffix",
    [
        ('const ratio = n++ / divisor; console.log("status"); const other = password / y;', ".js"),
        ('const ratio = n-- / divisor; console.log("status"); const other = password / y;', ".js"),
        ('const ratio = n! / divisor; console.log("status"); const other = password / y;', ".ts"),
        ('if (ok) {} /"/.test(x); console.log("status"); handle(password);', ".js"),
        (r'console.log(() => { if(ok) {} /\}\)/.test(x); }, "status"); handle(password);', ".js"),
        ('function done() {} /"/.test(x); console.log("status"); handle(password);', ".js"),
        ('const done = function() {} / divisor; console.log("status"); const other = password / y;', ".js"),
        ('const done = (() => {}) / divisor; console.log("status"); const other = password / y;', ".js"),
        ('class Done {} /"/.test(x); console.log("status"); handle(password);', ".js"),
        ('const Done = class {} / divisor; console.log("status"); const other = password / y;', ".js"),
        ('const value = {} / divisor; console.log("status"); const other = password / y;', ".js"),
        ('if (ok) {} /console.log(password)/.test(x); console.log("status");', ".js"),
        (r'print(/\)/, "status"); next(password)', ".swift"),
        (r'print(/"/, "status"); next(password)', ".swift"),
        (r'print(#/\)/#, "status"); next(password)', ".swift"),
        ('console.log(/* password */ "status");', ".js"),
        ('console.log("status" // password\n);', ".js"),
    ],
)
def test_slash_context_does_not_join_a_safe_log_to_later_sensitive_names(source, suffix):
    findings, coverage = inspect(source, suffix)
    assert not findings
    assert coverage["state"] == "checked"


def test_rule_catalog_exposes_canonical_matcher_and_patterns():
    rule = next(item for item in rule_module.rules() if item["id"] == "STORAGE-SENSITIVE-LOG")
    assert rule["matcher"] == MATCHER
    assert rule["pattern"] == CALL.pattern
    assert rule["argument_pattern"] == SENSITIVE.pattern
    assert "Call-prefix" in rule["pattern_scope"]
    assert "no dataflow" in rule["scope"]


def test_runtime_uses_the_catalog_call_and_argument_patterns(monkeypatch):
    rule = next(item for item in rule_module.rules() if item["id"] == "STORAGE-SENSITIVE-LOG")
    monkeypatch.setattr(
        rule_module,
        "rules",
        lambda: [{**rule, "pattern": r"trace\s*\(", "argument_pattern": "canaryMarker"}],
    )
    findings, _ = inspect("trace(canaryMarker); console.log(password);")
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["offset"] == 0


def test_cli_rule_export_keeps_canonical_matcher_metadata(tmp_path, capsys):
    assert main(["--home", str(tmp_path / "home"), "--json", "rules", "--id", "STORAGE-SENSITIVE-LOG"]) == 0
    rule = json.loads(capsys.readouterr().out)["data"]["rules"][0]
    assert rule["matcher"] == MATCHER
    assert rule["pattern"] == CALL.pattern
    assert rule["argument_pattern"] == SENSITIVE.pattern
    assert rule["pattern_scope"]


@pytest.mark.asyncio
async def test_mcp_rule_export_keeps_canonical_matcher_metadata(tmp_path):
    from mobile_audit.mcp_server import create_server

    server = create_server(tmp_path / "home", roots=[tmp_path])
    exported = list(await server.read_resource("mobile-audit://rules"))
    assert isinstance(exported[0].content, str)
    rule = next(item for item in json.loads(exported[0].content) if item["id"] == "STORAGE-SENSITIVE-LOG")
    assert rule["matcher"] == MATCHER
    assert rule["pattern"] == CALL.pattern
    assert rule["argument_pattern"] == SENSITIVE.pattern
    assert rule["pattern_scope"]


@pytest.mark.parametrize(
    "source,suffix",
    [
        ("console.log/* audit */(password);", ".js"),
        ("console.log // audit\n(password);", ".js"),
        ('Log.d/* audit */("tag", password);', ".java"),
        ('Log.d // audit\n("tag", password);', ".kt"),
        ("console.log/* first *//* second */ // third\n(password);", ".js"),
    ],
)
def test_comments_between_callee_and_parenthesis_do_not_hide_arguments(source, suffix):
    findings, coverage = inspect(source, suffix)
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["offset"] == 0
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source",
    [
        'console.log/* password */("status"); handle(password);',
        'const description = "console.log/* audit */(password)";',
        "// console.log /* audit */\n(password);",
        "/* console.log /* audit */ (password);",
    ],
)
def test_comment_aware_locator_cannot_turn_non_calls_into_sensitive_logs(source):
    findings, coverage = inspect(source)
    assert not findings
    assert coverage["state"] == "checked"


def test_many_commented_benign_calls_cannot_hide_a_real_later_candidate():
    source = 'console.log/* audit */("status"); popToken();\n' * 100 + "console.log/* audit */(password);"
    findings, coverage = inspect(source)
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["line"] == 101
    assert coverage["state"] == "checked" and not coverage["truncated"]


@pytest.mark.parametrize(
    "member", ["in", "return", "if", "for", "while", "catch", "case", "function", "class"]
)
@pytest.mark.parametrize("access", [".", "?."])
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_property_keywords_cannot_change_division_or_control_context(member, access, payload, expected):
    source = (
        f"const ratio = obj{access}{member}(x) / divisor; console.log({payload}); const other = password / y;"
    )
    findings, coverage = inspect(source)
    assert len(findings) == expected
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "prefix",
    [
        "const ratio = obj.in / divisor;",
        "const ratio = obj.return / divisor;",
        "const ratio = obj?.in / divisor;",
    ],
)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_property_values_do_not_turn_a_later_call_into_a_regex(prefix, payload, expected):
    findings, coverage = inspect(f"{prefix} console.log({payload}); const other = password / y;")
    assert len(findings) == expected
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source",
    [
        'export function done() {} /"/.test(x); console.log(PAYLOAD);',
        'export class Done {} /"/.test(x); console.log(PAYLOAD);',
        'export default function done() {} /"/.test(x); console.log(PAYLOAD);',
        'export default async function done() {} /"/.test(x); console.log(PAYLOAD);',
        'export default class Done {} /"/.test(x); console.log(PAYLOAD);',
        'label: {} /"/.test(x); console.log(PAYLOAD);',
        'switch(x){case 1:{} /"/.test(x); console.log(PAYLOAD);}',
        'switch(x){case ok ? 1 : 2:{} /"/.test(x); console.log(PAYLOAD);}',
        'switch(x){default:{} /"/.test(x); console.log(PAYLOAD);}',
        'async function f(){for await(const x of stream) /"/.test(x); console.log(PAYLOAD);}',
        'try {} catch {} /"/.test(x); console.log(PAYLOAD);',
        "const value = ok ? one : {} / divisor; console.log(PAYLOAD); const other = x / y;",
    ],
)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_declaration_label_case_and_for_await_contexts_preserve_call_boundaries(source, payload, expected):
    findings, coverage = inspect(source.replace("PAYLOAD", payload) + " handle(password);")
    assert len(findings) == expected
    assert coverage["state"] == expected_js_coverage(source)


@pytest.mark.parametrize("family", ["same-line", "multiline", "mixed-hashes"])
@pytest.mark.parametrize("count", [250, 500, 1000, 2000])
def test_malformed_swift_raw_regex_lookahead_has_a_global_linear_work_bound(family, count):
    if family == "same-line":
        malformed = "###/\n" + "#/ " * count
    elif family == "multiline":
        malformed = "#/\n" * count
    else:
        malformed = "".join("#" * (index % 17 + 1) + "/\n" for index in range(count))
    source = "print(password)\n" + malformed + "\nprint(token)\n"
    result = sensitive_log_matches(source, ".swift")
    assert result.uncertain
    assert len(result.spans) == 2
    assert result.regex_work <= 2 * len(source)


@pytest.mark.parametrize(
    "later",
    [
        r"print(/\)/, token)",
        r"print(#/\)/#, token)",
        "let pattern = #/\nvalue\n/#\nprint(token)",
        "let pattern = ##/\nvalue\n/##\nprint(token)",
    ],
)
def test_failed_multiline_raw_regex_recovers_later_hash_counts_and_real_logs(later):
    source = "print(password)\n###/\n" + later
    findings, coverage = inspect(source, ".swift")
    assert len(findings) == 2
    assert coverage["state"] == "partial"
    assert "line-bounded recovery" in next(
        item["scope"] for item in rule_module.rules() if item["id"] == "STORAGE-SENSITIVE-LOG"
    )


def test_valid_multiline_swift_raw_regex_keeps_quoted_fake_call_text_outside_code():
    source = 'let pattern = #/\nprint(password)\n/#\nprint("status"); next(password)'
    findings, coverage = inspect(source, ".swift")
    assert not findings
    assert coverage["state"] == "checked"
    positive, positive_coverage = inspect(source + "\nprint(token)", ".swift")
    assert len(positive) == 1
    assert positive_coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source",
    [
        'const value = 1\nfunction done() {} /"/.test(x); console.log(PAYLOAD);',
        'const value = 1\nclass Done {} /"/.test(x); console.log(PAYLOAD);',
        'const value = 1\nasync function done() {} /"/.test(x); console.log(PAYLOAD);',
        'const value = 1 /*\n*/function done() {} /"/.test(x); console.log(PAYLOAD);',
        'function f(){return\n{} /"/.test(x); console.log(PAYLOAD);}',
        'function f(){return /* gap\n*/{} /"/.test(x); console.log(PAYLOAD);}',
        'function f(){return // gap\n{} /"/.test(x); console.log(PAYLOAD);}',
    ],
)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_asi_declarations_and_restricted_return_keep_following_logs_visible(source, payload, expected):
    findings, coverage = inspect(source.replace("PAYLOAD", payload) + " handle(password);")
    assert len(findings) == expected
    assert coverage["state"] == expected_js_coverage(source)


@pytest.mark.parametrize(
    "prefix",
    [
        "const value = x\n/ divisor;",
        "const value = f\n({}) / divisor;",
        "const value = obj.return\n/ divisor;",
        "const value = obj?.return\n/ divisor;",
        "const value =\nfunction done() {} / divisor;",
        "const value =\nclass Done {} / divisor;",
        "const value = (\nfunction done() {}\n) / divisor;",
        "const value = (\nclass Done {}\n) / divisor;",
        "const value = (x ||\nfunction done() {}) / divisor;",
        "const value = (x ||\nclass Done {}) / divisor;",
    ],
)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_asi_handling_preserves_multiline_expression_and_call_continuations(prefix, payload, expected):
    findings, coverage = inspect(f"{prefix} console.log({payload}); const other=password/y;")
    assert len(findings) == expected
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_kotlin_raw_quote_run_cannot_hide_a_later_log(payload, expected):
    source = 'fun audit(password: String) { val s = """say "hi""""; println(PAYLOAD); next(password) }'
    findings, coverage = inspect(source.replace("PAYLOAD", payload), ".kt")
    assert len(findings) == expected
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_kotlin_benign_raw_argument_ends_at_the_last_three_quotes(payload, expected):
    source = 'println("""status "ok"""")\nprintln(PAYLOAD); next(password)'
    findings, coverage = inspect(source.replace("PAYLOAD", payload), ".kt")
    assert len(findings) == expected
    if expected:
        assert findings[0]["evidence"][0]["line"] == 2
    assert coverage["state"] == "checked"


def test_kotlin_sensitive_raw_argument_is_still_a_candidate_with_extra_closing_quotes():
    findings, coverage = inspect('println("""password="value"""")\nprintln("status")', ".kt")
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["line"] == 1
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("suffix,callee", [(".swift", "print"), (".kt", "println"), (".dart", "print")])
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_native_nested_block_comments_cannot_hide_or_invent_a_log(suffix, callee, payload, expected):
    source = f"/* outer /* inner {callee}(password) */ don't hide me */ {callee}({payload}); next(password)"
    findings, coverage = inspect(source, suffix)
    assert len(findings) == expected
    if expected:
        assert findings[0]["evidence"][0]["offset"] == len(source[: source.rindex(callee)].encode("utf-8"))
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source,suffix",
    [
        ("/* outer /* inner */ console.log(password);", ".js"),
        ('/* outer /* inner */ Log.d("tag", password);', ".java"),
    ],
)
def test_java_and_javascript_block_comments_remain_non_nested(source, suffix):
    findings, coverage = inspect(source, suffix)
    assert len(findings) == 1
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("separator", ["\n", "\r\n", "\r", "\u2028", "\u2029"])
@pytest.mark.parametrize(
    "source",
    [
        'const value=1SEPfunction done() {} /"/.test(x); console.log(password);',
        'function f(){returnSEP{} /"/.test(x); console.log(password);}',
        'function f(){return /*SEP*/ {} /"/.test(x); console.log(password);}',
        "// console.log(password)SEPconsole.log(password);",
    ],
)
def test_js_line_terminators_preserve_asi_comments_and_evidence(separator, source):
    source = source.replace("SEP", separator)
    findings, coverage = inspect(source)
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["line"] == 2
    assert findings[0]["evidence"][0]["offset"] == len(source[: source.rindex("console.log")].encode("utf-8"))
    assert coverage["state"] == expected_js_coverage(source)


@pytest.mark.parametrize("separator", ["\u2028", "\u2029"])
def test_modern_js_strings_keep_literal_unicode_line_separators(separator):
    # Unlike physical CR/LF, unescaped LS/PS are valid in modern JS strings.
    findings, coverage = inspect(f'const text="ordinary{separator}string"; console.log(password);')
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["line"] == 2
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source",
    [
        'const f = x => x; if(ok) {} /"/.test(x); console.log(PAYLOAD);',
        'const f = xs.map(x => x); if(ok) {} /"/.test(x); console.log(PAYLOAD);',
        'const f = x => ({value:x}); if(ok) {} /"/.test(x); console.log(PAYLOAD);',
        'const f = x => function(){return x}; if(ok) {} /"/.test(x); console.log(PAYLOAD);',
        'const f = x => class {}; if(ok) {} /"/.test(x); console.log(PAYLOAD);',
        'const f = x => {return x}; if(ok) {} /"/.test(x); console.log(PAYLOAD);',
        'const obj={function:0}; if(ok){foo();} if(ok){} /"/.test(x); console.log(PAYLOAD);',
        'const obj={class:0}; if(ok){foo();} if(ok){} /"/.test(x); console.log(PAYLOAD);',
        'const obj={function:()=>0,class:()=>0}; if(ok){} /"/.test(x); console.log(PAYLOAD);',
        'const obj={function(){return 0},class(){return 0}}; if(ok){} /"/.test(x); console.log(PAYLOAD);',
        'class Done extends (class {}) {} /"/.test(x); console.log(PAYLOAD);',
        'class Done extends mixin({class:0,function:0}) {} /"/.test(x); console.log(PAYLOAD);',
        'function done(x = () => 0) {} /"/.test(x); console.log(PAYLOAD);',
        'function done(x = function(){return 0}) {} /"/.test(x); console.log(PAYLOAD);',
        "const f = function(x = () => 0) {} / divisor; console.log(PAYLOAD); const other=x/y;",
        "const Done = class extends (class {}) {} / divisor; console.log(PAYLOAD); const other=x/y;",
    ],
)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_pending_header_and_body_state_cannot_leak_or_overwrite_its_parent(source, payload, expected):
    findings, coverage = inspect(source.replace("PAYLOAD", payload) + " handle(password);")
    assert len(findings) == expected
    assert coverage["state"] == expected_js_coverage(source)


@pytest.mark.parametrize(
    "source",
    [
        'const n = 1\nlabel: {} /"/.test(x); console.log(PAYLOAD);',
        'const n = 1\n{} /"/.test(x); console.log(PAYLOAD);',
        'function* f(){yield\n{} /"/.test(x); console.log(PAYLOAD);}',
        'function* f(){yield /* gap\n*/{} /"/.test(x); console.log(PAYLOAD);}',
        'function* f(){const value=yield\n{} /"/.test(x); console.log(PAYLOAD);}',
        'function* f(){yield\n/"/.test(x); console.log(PAYLOAD);}',
        'debugger\n{} /"/.test(x); console.log(PAYLOAD);',
        'debugger\n/"/.test(x); console.log(PAYLOAD);',
        'outer: while(x){break outer\n{} /"/.test(x); console.log(PAYLOAD);}',
        'outer: while(x){continue outer\n{} /"/.test(x); console.log(PAYLOAD);}',
        'outer: while(x){break outer\n/"/.test(x); console.log(PAYLOAD);}',
        'outer: while(x){continue outer\n/"/.test(x); console.log(PAYLOAD);}',
    ],
)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_general_asi_and_restricted_labeled_exits_preserve_following_calls(source, payload, expected):
    findings, coverage = inspect(source.replace("PAYLOAD", payload) + " handle(password);")
    assert len(findings) == expected
    assert coverage["state"] == expected_js_coverage(source)


@pytest.mark.parametrize(
    "source",
    [
        'interface Done {} /"/.test(x); console.log(PAYLOAD);',
        'enum Done {} /"/.test(x); console.log(PAYLOAD);',
        'namespace Done {} /"/.test(x); console.log(PAYLOAD);',
        'export interface Done {} /"/.test(x); console.log(PAYLOAD);',
        'export enum Done {} /"/.test(x); console.log(PAYLOAD);',
        'export namespace Done {} /"/.test(x); console.log(PAYLOAD);',
        'declare interface Done {} /"/.test(x); console.log(PAYLOAD);',
        'namespace Outer.Inner {} /"/.test(x); console.log(PAYLOAD);',
        'function done<T extends {}>(x:T) {} /"/.test(x); console.log(PAYLOAD);',
        'function done(): () => void {} /"/.test(x); console.log(PAYLOAD);',
        'const obj={interface:0,enum:0,namespace:0}; if(ok){} /"/.test(x); console.log(PAYLOAD);',
    ],
)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_typescript_statement_headers_have_scoped_declaration_bodies(source, payload, expected):
    findings, coverage = inspect(source.replace("PAYLOAD", payload) + " handle(password);", ".ts")
    assert len(findings) == expected
    assert coverage["state"] == "checked"


AST_CONTEXTS = [
    ('if(ok) foo(); else /"/.test(x); console.log(PAYLOAD);', ".js"),
    ('do /"/.test(x); while(false); console.log(PAYLOAD);', ".js"),
    ('const ok=value instanceof /"/.constructor; console.log(PAYLOAD);', ".js"),
    ('class C extends /"/.constructor {} console.log(PAYLOAD);', ".js"),
    ('import "pkg"\n/"/.test(x); console.log(PAYLOAD);', ".js"),
    ('import value from "pkg"\n/"/.test(x); console.log(PAYLOAD);', ".js"),
    ('export * from "pkg"\n/"/.test(x); console.log(PAYLOAD);', ".js"),
    ('export {value} from "pkg"\n/"/.test(x); console.log(PAYLOAD);', ".js"),
    ('type Shape={}\n/"/.test(x); console.log(PAYLOAD);', ".ts"),
    (
        'const f=function(): {a:number} { class C {} /"/.test(x); console.log(PAYLOAD); return {a:1}; };',
        ".ts",
    ),
]


@pytest.mark.parametrize("source,suffix", AST_CONTEXTS)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_ast_resolves_statement_and_type_contexts_without_keyword_heuristics(
    source, suffix, payload, expected
):
    findings, coverage = inspect(source.replace("PAYLOAD", payload) + " handle(password);", suffix)
    assert len(findings) == expected
    assert coverage["state"] == expected_js_coverage(source)


@pytest.mark.parametrize(
    "source,expected",
    [
        ('(console.log("status"), other)(password);', 0),
        ('factory(console.log("status"))(password);', 0),
        ('(console.log(password), other)("status");', 1),
        ('factory(console.log(password))("status");', 1),
        ("obj.console.log(password);", 1),
        ("new logger.warn(password);", 1),
        ("const text = `fake console.log(password) ${console.log(token)}`;", 1),
        ('const text = /console.log(password)/; const other="logger.info(token)";', 0),
        ("한console.log(password);", 0),
    ],
)
def test_ast_canonical_prefix_belongs_to_its_own_arguments(source, expected):
    findings, coverage = inspect(source)
    assert len(findings) == expected
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("suffix", [".js", ".jsx", ".jsbundle", ".ts", ".tsx"])
def test_js_family_dispatch_keeps_utf8_offsets_and_intervening_comments(suffix):
    source = "/* 한글😀 */ console.log /* 비밀😀 */ (password);"
    findings, coverage = inspect(source, suffix)
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["offset"] == len("/* 한글😀 */ ".encode())
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("suffix", [".jsx", ".tsx"])
def test_jsx_text_and_attribute_examples_remain_data_while_expression_calls_are_code(suffix):
    source = '<div title="console.log(password)">console.log(password){console.log(token)}</div>;'
    findings, coverage = inspect(source, suffix)
    assert len(findings) == 1
    assert findings[0]["evidence"][0]["offset"] == source.index("console.log(token)")
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "fake",
    [
        'const doc = "console.log(password)";',
        "const doc = /console.log(password)/;",
        "const doc = `console.log(password)`;",
        "/* console.log(password) */",
        "// console.log(password)\n",
    ],
)
def test_parse_error_elsewhere_does_not_promote_ast_literal_or_comment_text(fake):
    findings, coverage = inspect("const broken = ; " + fake + ' console.log("status");')
    assert not findings
    assert coverage["state"] == "partial"
    positive, positive_coverage = inspect("const broken = ; " + fake + " console.log(token);")
    assert len(positive) == 1
    assert positive_coverage["state"] == "partial"


@pytest.mark.parametrize("failure", ["unavailable", "deadline", "nodes", "bytes"])
def test_ast_failure_is_bounded_partial_and_keeps_scoped_candidates(monkeypatch, failure):
    from mobile_audit import sensitive_logging_js as js

    if failure == "unavailable":

        def unavailable(_suffix):
            raise ImportError("synthetic missing grammar")

        monkeypatch.setattr(js, "_new_parser", unavailable)
    elif failure == "deadline":

        class DeadlineParser:
            def parse(self, _raw):
                return None

        monkeypatch.setattr(js, "_new_parser", lambda _suffix: DeadlineParser())
    elif failure == "nodes":
        monkeypatch.setattr(js, "MAX_AST_NODES", 1)
    else:
        monkeypatch.setattr(js, "MAX_SOURCE_BYTES", 1)
    findings, coverage = inspect('console.log("status"); handle(password); console.log(token);')
    assert len(findings) == 1
    assert coverage["state"] == "partial"
    assert "JS/TS" in coverage["note"]
    assert (
        "unavailable" if failure == "unavailable" else "deadline" if failure == "deadline" else "budget"
    ) in coverage["note"]


def test_ast_fallback_byte_work_is_capped_without_splitting_unicode(monkeypatch):
    from mobile_audit import sensitive_logging as logging
    from mobile_audit import sensitive_logging_js as js

    monkeypatch.setattr(js, "MAX_SOURCE_BYTES", 1)
    monkeypatch.setattr(logging, "MAX_FALLBACK_BYTES", 40)
    seen = []
    original = logging._lexical_sensitive_log_matches

    def measured(text, suffix, **patterns):
        seen.append(len(text.encode("utf-8")))
        return original(text, suffix, **patterns)

    monkeypatch.setattr(logging, "_lexical_sensitive_log_matches", measured)
    result = sensitive_log_matches("console.log(password);" + "😀" * 100 + "console.log(token);", ".js")
    assert result.uncertain
    assert len(result.spans) == 1
    assert sum(seen) <= 40


@pytest.mark.parametrize(
    "callee",
    [
        "factory().print",
        "items[0].println",
        "(printer).print",
        "factory().NSLog",
        "factory().console.log",
        "items[0].Log.d",
        "(printer).logger.warn",
    ],
)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_static_log_method_tail_survives_complex_receivers(callee, payload, expected):
    findings, coverage = inspect(f"{callee}({payload}); handle(password);")
    assert len(findings) == expected
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source",
    [
        'factory("console.log(")("password");',
        'items["console.log("]("password");',
        '("console.log(")("password");',
        'factory(console.log("status"))(password);',
        'factory("print(").other(password);',
    ],
)
def test_receiver_data_cannot_supply_a_log_prefix_to_outer_arguments(source):
    findings, coverage = inspect(source)
    assert not findings
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "tag", ["tag`x`;", "console.log`x`;", "factory().print`x`;", "tag`console.log(password)`;"]
)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_tagged_templates_do_not_invoke_lexical_fallback_or_borrow_later_markers(
    monkeypatch, tag, payload, expected
):
    from mobile_audit import sensitive_logging as logging

    def forbidden(*_args, **_kwargs):
        pytest.fail("An error-free tagged template must not invoke recovery")

    monkeypatch.setattr(logging, "_lexical_sensitive_log_matches", forbidden)
    source = tag + ' console.log(() => {if(ok) foo(); else /"/.test(x);}, ' + payload + "); handle(password);"
    findings, coverage = inspect(source)
    assert len(findings) == expected
    assert coverage["state"] == "checked"


@pytest.mark.parametrize(
    "source",
    [
        "tag`text ${console.log(password)}`;",
        "console.log`text ${factory().print(password)}`;",
        "factory().print`fake console.log(password) ${logger.warn(token)}`;",
    ],
)
def test_tagged_template_interpolations_keep_real_log_calls(source):
    findings, coverage = inspect(source)
    assert len(findings) == 1
    assert coverage["state"] == "checked"


def test_many_tagged_templates_keep_the_ast_path_bounded_and_preserve_a_later_positive(monkeypatch):
    from mobile_audit import sensitive_logging as logging
    from mobile_audit.sensitive_logging_js import MAX_AST_NODES

    def forbidden(*_args, **_kwargs):
        pytest.fail("Valid tagged templates must not invoke lexical recovery")

    monkeypatch.setattr(logging, "_lexical_sensitive_log_matches", forbidden)
    source = "tag`fake console.log(password)`;" * 1000 + "factory().print(token);"
    result = sensitive_log_matches(source, ".js")
    assert len(result.spans) == 1
    assert result.spans[0][0] == source.rindex("print")
    assert not result.uncertain
    assert 0 < result.parser_nodes <= MAX_AST_NODES


@pytest.mark.parametrize(
    "source",
    [
        "tag`x`; console.log(password);",
        'console.log({value: "status"); password;',
        'console.log("unterminated\n password;',
        "const broken = ; console.log(password);",
    ],
)
def test_ast_recovery_always_has_an_explicit_partial_reason(source):
    from mobile_audit.sensitive_logging_js import ast_sensitive_log_matches

    result = ast_sensitive_log_matches(
        source, ".js", call_pattern=CALL.pattern, argument_pattern=SENSITIVE.pattern
    )
    assert not result.recovery or result.reason
    combined = sensitive_log_matches(source, ".js")
    assert not result.recovery or (combined.uncertain and combined.reason)


def test_pinned_binding_native_deadline_is_diagnosed_as_parse_failure_and_keeps_candidates(monkeypatch):
    from mobile_audit import sensitive_logging_js as js

    monkeypatch.setattr(js, "PARSE_TIMEOUT_MICROS", 1)
    source = "console.log(password);" * 1000
    result = sensitive_log_matches(source, ".js")
    assert result.uncertain
    assert len(result.spans) == 1000
    assert "deadline" in result.reason
    assert "ValueError" in result.reason
    assert "unavailable" not in result.reason


def test_tagged_console_call_cannot_turn_a_later_regex_literal_into_a_call(monkeypatch):
    from mobile_audit import sensitive_logging as logging

    def forbidden(*_args, **_kwargs):
        pytest.fail("Valid tagged templates must not invoke lexical recovery")

    monkeypatch.setattr(logging, "_lexical_sensitive_log_matches", forbidden)
    findings, coverage = inspect("console.log`safe`; if(ok)foo(); else /console.log(password)/.test(x);")
    assert not findings
    assert coverage["state"] == "checked"


PRIVATE_CALLEES = [
    ("#print(x){}", "#print"),
    ("#println(x){}", "#println"),
    ("#console;", "#console.log"),
    ("#logger;", "#logger.warn"),
]


@pytest.mark.parametrize("suffix", [".js", ".jsx", ".jsbundle", ".ts", ".tsx"])
@pytest.mark.parametrize("receiver", ["this", "(this)", "obj", "this?", "obj?"])
@pytest.mark.parametrize("declaration,callee", PRIVATE_CALLEES)
@pytest.mark.parametrize("payload,expected", [("password", 1), ('"status"', 0)])
def test_private_static_log_names_keep_canonical_prefix_parity(
    suffix, receiver, declaration, callee, payload, expected
):
    source = f"/* 한글😀 */ class C {{ {declaration} m(obj){{{receiver}.{callee}({payload}); handle(password);}} }}"
    findings, coverage = inspect(source, suffix)
    assert len(findings) == expected
    assert coverage["state"] == "checked"
    if expected:
        # Canonical prefix begins after '#', as in the original raw regex.
        prefix = callee[1:]
        assert findings[0]["evidence"][0]["offset"] == len(source[: source.rindex(prefix)].encode("utf-8"))


@pytest.mark.parametrize("suffix", [".js", ".ts"])
@pytest.mark.parametrize(
    "source",
    [
        "class C { #print; m(){this.#print?.(password);} }",
        'class C { #console; m(){this.#console["log"](password);} }',
        'class C { #holder; m(){this.#holder("console.log(")(password);} }',
        'class C { #holder; m(){this.#holder["console.log("](password);} }',
        'class C { #holder; m(){(this.#holder, "print(")(password);} }',
    ],
)
def test_private_receivers_do_not_expand_canonical_call_patterns_or_borrow_data(suffix, source):
    findings, coverage = inspect(source, suffix)
    assert not findings
    assert coverage["state"] == "checked"
