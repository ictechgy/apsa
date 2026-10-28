from __future__ import annotations

from types import SimpleNamespace
from typing import SupportsIndex, overload

import pytest

from mobile_audit.native_flow import NativeFlow
from mobile_audit.parser_compat import adapted_source
from mobile_audit.source_analysis import analyze_sources
from mobile_audit.specs import load_specs

PATH = "AST-PATH-TRAVERSAL"
URL = "AST-WEBVIEW-UNTRUSTED-URL"


def matches(report: dict, rule: str) -> list[dict]:
    return [item for item in report["findings"] if item["rule_id"] == rule]


@pytest.mark.parametrize("optional", [False, True])
def test_lambda_local_guard_cannot_validate_enclosing_path(optional):
    if optional:
        path = "Handler.kt"
        source = """import java.io.File
class Handler {
fun entry(input: Intent, base: File, root: Any?) {
val target = File(base, input.getStringExtra("name")!!)
root?.let { if (!target.canonicalPath.startsWith(base.canonicalPath + File.separator)) return@let }
target.parentFile.mkdirs()
target.delete()
}
}"""
    else:
        path = "Handler.java"
        source = """class Handler {
void entry(Intent input, File base, Executor executor) {
File target = new File(base, input.getStringExtra("name"));
executor.submit(() -> { if (!target.getCanonicalPath().startsWith(base.getCanonicalPath() + File.separator)) return null; return null; });
target.delete();
}
}"""
    report = analyze_sources([(path, source)])
    assert matches(report, PATH), report


@pytest.mark.parametrize("operation", ["mkdir", "mkdirs", "delete", "createNewFile"])
@pytest.mark.parametrize("guard_before", [False, True])
@pytest.mark.parametrize("receiver", ["target", "target.parentFile", "target.getParentFile()"])
def test_path_guard_must_precede_filesystem_effect(operation, guard_before, receiver):
    guard = "if (!target.getCanonicalPath().startsWith(base.getCanonicalPath() + File.separator)) return;"
    effect = f"{receiver}.{operation}();"
    statements = [guard, effect] if guard_before else [effect, guard]
    report = analyze_sources(
        [
            (
                "Handler.java",
                """class Handler { void entry(Intent input, File base) {
File target = new File(base, input.getStringExtra("name"));
"""
                + "\n".join(statements)
                + "} }",
            )
        ]
    )
    assert bool(matches(report, PATH)) is not guard_before, report


@pytest.mark.parametrize("reverse", [False, True])
def test_ambiguous_static_overloads_join_argument_object_writes(reverse):
    overloads = [
        "static void fill(Holder h, String s) { h.value = s; }",
        'static void fill(Holder h, Object s) { h.value = "safe"; }',
    ]
    if reverse:
        overloads.reverse()
    source = (
        """import android.content.Intent;
import android.webkit.WebView;
class Holder { String value; }
class Helper { """
        + "\n".join(overloads)
        + """ }
class Handler { void entry(Intent input, WebView browser) {
Holder holder = new Holder();
Helper.fill(holder, input.getStringExtra("url"));
browser.loadUrl(holder.value);
} }"""
    )
    report = analyze_sources([("Handler.java", source)])
    assert matches(report, URL), report
    assert "ambiguous direct call" in report["metadata"]["native_flow"]["reasons"]
    assert next(item for item in report["coverage"] if item["rule_id"] == URL)["state"] == "partial"


@pytest.mark.parametrize("unrelated_name", [None, "A.java", "Z.java"])
def test_helper_guard_transfer_is_independent_of_unrelated_file_order(unrelated_name):
    source = """class Handler {
void entry(Intent input, File root) {
File output = new File(root, input.getStringExtra("name"));
write(output, root);
}
private void write(File output, File root) {
if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
new FileOutputStream(output);
}
}"""
    sources = [("Handler.java", source)]
    if unrelated_name:
        sources.append(
            (
                unrelated_name,
                'class Unrelated { void other(Intent input) { missing(input.getStringExtra("url")); } }',
            )
        )
    report = analyze_sources(sources)
    assert not matches(report, PATH), report
    if unrelated_name:
        assert report["metadata"]["native_flow"]["state"] == "partial"


def test_uncertainty_inside_helper_still_prevents_guard_transfer():
    report = analyze_sources(
        [
            (
                "Handler.java",
                """class Handler {
void entry(Intent input, File root) {
File output = new File(root, input.getStringExtra("name"));
write(output, root);
}
private void write(File output, File root) {
missing(output);
if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
new FileOutputStream(output);
}
}""",
            )
        ]
    )
    assert matches(report, PATH), report
    assert report["metadata"]["native_flow"]["state"] == "partial"


@pytest.mark.parametrize("return_tainted", [False, True])
def test_nested_lambda_return_does_not_supply_enclosing_return(return_tainted):
    returned = 'input.getStringExtra("url")' if return_tainted else '"https://safe.example"'
    report = analyze_sources(
        [
            (
                "Handler.java",
                """import android.content.Intent;
import android.webkit.WebView;
class Handler {
static String value(Intent input, Executor executor) {
executor.submit(() -> { return input.getStringExtra("url"); });
return """
                + returned
                + """;
}
void entry(Intent input, Executor executor, WebView browser) {
browser.loadUrl(value(input, executor));
}
}""",
            )
        ]
    )
    assert bool(matches(report, URL)) is return_tainted, report


@pytest.mark.parametrize("language", ["java", "kotlin"])
@pytest.mark.parametrize("tainted", [False, True])
def test_optional_closure_field_effects_cannot_erase_possible_taint(language, tainted):
    initial = 'input.getStringExtra("url")' if tainted else '"https://safe.example"'
    if language == "java":
        source = (
            """class Holder { String value; }
class Handler { void entry(Intent input, WebView browser, Executor executor) {
Holder holder = new Holder();
holder.value = """
            + initial
            + """;
executor.submit(() -> { holder.value = "safe"; return null; });
browser.loadUrl(holder.value);
} }"""
        )
        path = "Handler.java"
    else:
        source = (
            """class Holder {
var value: String = ""
}
class Handler {
fun entry(input: Intent, browser: WebView, receiver: Any?) {
val holder = Holder()
holder.value = """
            + initial
            + """
receiver?.let { holder.value = "safe" }
browser.loadUrl(holder.value)
} }"""
        )
        path = "Handler.kt"
    report = analyze_sources([(path, source)])
    assert bool(matches(report, URL)) is tainted, report


@pytest.mark.parametrize("shadow", [None, "class", "import", "project"])
def test_wildcard_crypto_import_retains_framework_identity_and_shadowing(shadow):
    prefix = "package example;\nimport javax.crypto.*;\n"
    if shadow == "class":
        prefix += "class Cipher { static void getInstance(String name) {} }\n"
    elif shadow == "import":
        prefix += "import custom.Cipher;\n"
    sources = [("Handler.java", prefix + 'class Handler { void f() { Cipher.getInstance("DES"); } }')]
    if shadow == "project":
        sources.append(
            ("Cipher.java", "package example; class Cipher { static void getInstance(String name) {} }")
        )
    report = analyze_sources(sources)
    assert bool(matches(report, "AST-CRYPTO-WEAK-CIPHER")) is (shadow is None), report


@pytest.mark.parametrize("bound", [False, True])
def test_wildcard_sql_import_distinguishes_query_syntax_from_bound_values(bound):
    arguments = (
        '"select * from items where name=?", new String[]{input.getStringExtra("name")}'
        if bound
        else '"select * from items where name=" + input.getStringExtra("name"), null'
    )
    report = analyze_sources(
        [
            (
                "Handler.java",
                """import android.database.sqlite.*;
class Handler { void f(Intent input, SQLiteDatabase db) {
db.rawQuery("""
                + arguments
                + """);
} }""",
            )
        ]
    )
    assert bool(matches(report, "AST-SQL-CONCAT")) is not bound, report


def test_unimplemented_swift_checks_are_not_reported_as_inapplicable():
    report = analyze_sources([("Handler.swift", "func f() {}")])
    states = {item["rule_id"]: item["state"] for item in report["coverage"]}
    for rule in ("AST-CRYPTO-ECB", "AST-CRYPTO-WEAK-CIPHER", "AST-SQL-CONCAT"):
        assert states[rule] == "not-run"
    assert states["AST-WEBVIEW-SSL-BYPASS"] == "not-applicable"


def test_swift_declared_sql_sink_retains_candidate_and_partial_coverage():
    specs = {
        "sha256": "synthetic",
        "source": [{"id": "input", "method": "incoming", "returns": "text"}],
        "sink": [{"id": "query", "method": "query", "kind": "sql", "argument": 0}],
    }
    report = analyze_sources([("Handler.swift", "func f() { query(incoming()) }")], specs=specs)
    assert matches(report, "AST-SQL-CONCAT"), report
    assert (
        next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")["state"] == "partial"
    )


@pytest.mark.parametrize("suffix", ["json", "toml"])
def test_deep_specs_fail_as_validation_errors(tmp_path, suffix):
    raw = "[" * 5000 + "0" + "]" * 5000
    if suffix == "toml":
        raw = "source=" + raw
    path = tmp_path.resolve() / f"apsa-specs.{suffix}"
    path.write_text(raw)
    with pytest.raises(ValueError):
        load_specs(path)


def test_one_deep_expression_retains_other_file_findings_and_partial_inventory():
    deep = "class Deep { void f() { String value=" + "+".join(['"a"'] * 1200) + "; } }"
    ordinary = """class Handler { void entry(Intent input, WebView browser) {
browser.loadUrl(input.getStringExtra("url"));
} }"""
    report = analyze_sources([("A.java", deep), ("Z.java", ordinary)])
    assert matches(report, URL), report
    assert "native flow recursion budget" in report["metadata"]["native_flow"]["reasons"]
    assert report["metadata"]["function_inventory_complete"] is False
    assert (
        next(item for item in report["metadata"]["files"] if item["path"] == "A.java")["state"] == "partial"
    )


def test_swift_compatibility_work_is_bounded_by_error_spans():
    class CountedBytes(bytes):
        copied = 0

        @overload
        def __getitem__(self, key: SupportsIndex, /) -> int: ...

        @overload
        def __getitem__(self, key: slice, /) -> bytes: ...

        def __getitem__(self, key: SupportsIndex | slice, /) -> int | bytes:
            result = super().__getitem__(key)
            if isinstance(result, bytes):
                self.copied += len(result)
            return result

    raw = CountedBytes(b"nonisolated(unsafe) var value = 0\n//" + b"x" * (256 * 1024))
    nodes = [SimpleNamespace(type="identifier", start_byte=0, end_byte=len(raw)) for _ in range(1000)]
    end = len(b"nonisolated(unsafe)")
    nodes.append(SimpleNamespace(type="ERROR", start_byte=0, end_byte=end, parent=None))
    adapted, changes = adapted_source(raw, "swift", nodes)
    assert adapted[:end] == b" " * end
    assert adapted[end:] == raw[end:]
    assert changes == [{"kind": "swift-nonisolated-unsafe-variable", "edits": 1}]
    assert raw.copied < 10 * len(raw)


def test_many_allocations_do_not_rescan_all_callable_inventory(monkeypatch):
    original = NativeFlow.__init__
    enumerations = 0

    class CountedInventory(dict):
        def values(self):
            nonlocal enumerations
            enumerations += 1
            return super().values()

    def initialize(self, files):
        original(self, files)
        self.by_name = CountedInventory(self.by_name)

    monkeypatch.setattr(NativeFlow, "__init__", initialize)
    methods = "\n".join(f"void unused{index}() {{}}" for index in range(100))
    allocations = "\n".join(f"Holder value{index} = new Holder();" for index in range(32))
    report = analyze_sources(
        [("Handler.java", f"class Holder {{}} class Handler {{ {methods} void f() {{ {allocations} }} }}")]
    )
    assert not report["findings"]
    assert enumerations <= 1
