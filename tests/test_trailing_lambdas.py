"""Kotlin and Swift trailing lambdas (1.7.1).

A call written with a trailing lambda is the same call as the one with the lambda
in parentheses: it keeps its name, receiver and arguments, the lambda is its last
argument, and the call is followed into a project callee. Every closure that is not
a scope-function block is followed once where it is written, as a block that may
not run: guards that hold there apply inside, guards it establishes do not apply
after it, and its declared parameters are locals that shadow outer names.
"""

from __future__ import annotations

import importlib
import sys
from typing import Any

import pytest
import tree_sitter

from mobile_audit.source_analysis import Analyzer, analyze_sources

SQL = "AST-SQL-CONCAT"
URL = "AST-WEBVIEW-UNTRUSTED-URL"
ALLOWLIST = "AST-WEBVIEW-HOST-ALLOWLIST"
REDIRECTION = "AST-INTENT-REDIRECTION"
UNAVAILABLE = "Kotlin non-local return context unavailable"
KOTLIN = """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.app.Activity
import android.net.Uri
import android.webkit.WebView
import android.os.Handler
import android.os.Looper
import kotlinx.coroutines.*
"""
TAINT = 'intent.getStringExtra("q") ?: ""'


def _kotlin(body: str) -> dict:
    return analyze_sources([("app/R.kt", KOTLIN + body)])


def _swift(body: str) -> dict:
    return analyze_sources([("App.swift", body)])


def _hit(report: dict, rule: str) -> bool:
    return any(finding["rule_id"] == rule for finding in report["findings"])


def _state(report: dict, rule: str) -> str:
    return next(row["state"] for row in report["coverage"] if row["rule_id"] == rule)


def _reasons(report: dict) -> list[str]:
    return report["metadata"]["native_flow"]["reasons"]


CALLEE = """class R2(private val db: SQLiteDatabase) {{
    {declaration}
    fun q(intent: Intent) {{ {call} }}
}}
"""
ATTACH = 'fun attach(name: String, done: () -> Unit) { db.execSQL("DELETE FROM t WHERE id = " + name) }'


@pytest.mark.parametrize(
    "call",
    [
        f"attach({TAINT}, {{}})",
        f"attach({TAINT}) {{ }}",
        f"attach({TAINT}) l@{{ }}",
        f"attach({TAINT}) /* note */ {{ }}",
        f"this.attach({TAINT}) {{ }}",
        f"attach(name = {TAINT}) {{ }}",
        f"attach({TAINT}) {{ println(1) }}",
    ],
)
def test_call_with_a_trailing_lambda_is_followed_like_the_parenthesized_call(call: str) -> None:
    report = _kotlin(CALLEE.format(declaration=ATTACH, call=call))
    assert _hit(report, SQL), report
    assert _state(report, SQL) == "checked"


def test_generic_and_member_calls_with_a_trailing_lambda_are_followed() -> None:
    generic = _kotlin(
        CALLEE.format(
            declaration='fun <T> attach(name: String, done: () -> T) { db.execSQL("DELETE FROM t WHERE id = " + name) }',
            call=f'attach<String>({TAINT}) {{ "x" }}',
        )
    )
    member = _kotlin(
        """class Store(private val db: SQLiteDatabase) {
    fun attach(name: String, done: () -> Unit) { db.execSQL("DELETE FROM t WHERE id = " + name) }
}
class R4(private val store: Store) {
    fun q(intent: Intent) { store.attach(intent.getStringExtra("q") ?: "") { } }
}
"""
    )
    assert _hit(generic, SQL) and _hit(member, SQL)


def test_constant_argument_with_a_trailing_lambda_is_not_reported() -> None:
    report = _kotlin(CALLEE.format(declaration=ATTACH, call='attach("const") { }'))
    assert not _hit(report, SQL)
    assert _state(report, SQL) == "checked"


def test_callee_in_an_activity_accepts_a_lambda_for_its_function_parameter() -> None:
    report = _kotlin(
        """class E13(private val db: SQLiteDatabase) : Activity() {
    fun attach(name: String, done: () -> Unit) { db.execSQL("DELETE FROM t WHERE id = " + name) }
    fun q(intent: Intent) { val name: String = intent.getStringExtra("q")!!; attach(name) { } }
}
"""
    )
    assert _hit(report, SQL)
    assert _state(report, SQL) == "checked"


@pytest.mark.parametrize(
    "declaration",
    [
        'fun attach(name: String, done: () -> Unit) { done(); db.execSQL("DELETE FROM t WHERE id = " + name) }',
        'fun attach(name: String, done: (String) -> Unit) { done.invoke(name); db.execSQL("DELETE FROM t WHERE id = " + name) }',
        'fun attach(name: String, done: ((String) -> Unit)?) { done?.invoke(name); db.execSQL("DELETE FROM t WHERE id = " + name) }',
    ],
)
def test_callee_that_calls_its_lambda_keeps_the_finding_and_is_limited(declaration: str) -> None:
    report = _kotlin(CALLEE.format(declaration=declaration, call=f"attach({TAINT}) {{ }}"))
    assert _hit(report, SQL)
    assert _state(report, SQL) == "limited"
    assert "callable value binding unresolved" in _reasons(report)


def test_lambda_result_returned_by_the_callee_reaches_its_sink() -> None:
    report = _kotlin(
        CALLEE.format(
            declaration='fun attach(block: () -> String) { db.execSQL("DELETE FROM t WHERE id = " + block()) }',
            call=f"attach {{ {TAINT} }}",
        )
    )
    assert _hit(report, SQL)
    assert _state(report, SQL) == "limited"


def test_named_arguments_bind_by_name_or_the_call_is_not_followed() -> None:
    declaration = (
        'fun attach(a: String, b: String, done: () -> Unit) { db.execSQL("DELETE FROM t WHERE id = " + a) }'
    )
    reordered = _kotlin(
        CALLEE.format(declaration=declaration, call='attach(b = intent.getStringExtra("q")!!, a = "x") { }')
    )
    in_order = _kotlin(
        CALLEE.format(declaration=declaration, call='attach(a = intent.getStringExtra("q")!!, b = "x") { }')
    )
    assert not _hit(reordered, SQL)
    assert _state(reordered, SQL) == "limited"
    assert _hit(in_order, SQL)


def test_default_before_a_trailing_lambda_is_limited_not_silent() -> None:
    report = _kotlin(
        CALLEE.format(
            declaration=(
                "fun attach(name: String, tag: String = defaultTag(), done: () -> Unit) "
                '{ db.execSQL("DELETE FROM t WHERE id = " + name) }\n    fun defaultTag() = "t"'
            ),
            call=f"attach({TAINT}) {{ }}",
        )
    )
    assert _hit(report, SQL) or _state(report, SQL) == "limited"
    complete = _kotlin(
        CALLEE.format(
            declaration=(
                "fun attach(name: String, tag: String = defaultTag(), done: () -> Unit) "
                '{ db.execSQL("DELETE FROM t WHERE id = " + name + tag) }\n    fun defaultTag() = "t"'
            ),
            call=f'attach({TAINT}, "t") {{ }}',
        )
    )
    # The default value is not a parameter: the three-argument call matches.
    assert _hit(complete, SQL)
    assert "callable value binding unresolved" not in _reasons(complete)


@pytest.mark.parametrize(
    "call",
    [
        'web.evaluateJavascript(intent.getStringExtra("js")!!) { r -> println(r) }',
        'this.web.evaluateJavascript(intent.getStringExtra("js")!!) cb@{ }',
        'web.evaluateJavascript(script = intent.getStringExtra("js")!!) { }',
        'web.evaluateJavascript(intent.getStringExtra("js")!!, null)',
    ],
)
def test_sdk_sink_written_with_a_trailing_lambda_is_checked(call: str) -> None:
    report = _kotlin(
        f"""class W(private val web: WebView) {{
    fun q(intent: Intent) {{ {call} }}
}}
"""
    )
    assert _hit(report, URL)


def test_sam_opener_with_a_trailing_lambda_is_an_opener() -> None:
    report = _kotlin(
        """class E11 : Activity() {
    fun q(intent: Intent) {
        val db = openOrCreateDatabase("a.db", 0, null) { d -> }
        db.execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))
    }
}
"""
    )
    assert _hit(report, SQL)


BODY = """class R3(private val db: SQLiteDatabase, private val button: android.view.View) : Activity() {{
    fun q(intent: Intent) {{
        val id = intent.getStringExtra("q")
        {wrap}
    }}
}}
"""
SINK = 'db.execSQL("DELETE FROM t WHERE id = " + id)'


@pytest.mark.parametrize(
    "wrap,state",
    [
        (f"runOnUiThread {{ {SINK} }}", "checked"),
        (f"GlobalScope.launch {{ withContext(Dispatchers.IO) {{ {SINK} }} }}", "checked"),
        (f"listOf(1).forEach {{ {SINK} }}", "checked"),
        (f"listOf(1).forEach {{ x -> println(x); {SINK} }}", "checked"),
        (f"repeat(1) {{ {SINK} }}", "checked"),
        (f"GlobalScope.launch(Dispatchers.IO) {{ {SINK} }}", "checked"),
        (f"button.setOnClickListener {{ {SINK} }}", "checked"),
        (f"runOnUiThread l@{{ {SINK} }}", "checked"),
        (f"Thread({{ {SINK} }}).start()", "checked"),
        (f"Thread {{ {SINK} }}.start()", "checked"),
        (f"synchronized(this) {{ {SINK} }}", "limited"),
        (f'val s = "${{run {{ {SINK} }}}}"', "checked"),
    ],
)
def test_sink_inside_a_closure_is_reported(wrap: str, state: str) -> None:
    report = _kotlin(BODY.format(wrap=wrap))
    assert _hit(report, SQL), report
    assert _state(report, SQL) == state, _reasons(report)


def test_constant_sql_inside_a_closure_is_not_reported() -> None:
    report = _kotlin(BODY.format(wrap='runOnUiThread { db.execSQL("DELETE FROM t WHERE id = 1") }'))
    assert not _hit(report, SQL)
    assert _state(report, SQL) == "checked"


GUARD = """class G(private val browser: WebView, private val button: android.view.View) : Activity() {{
    fun open(incoming: Intent) {{
        val destination = incoming.getStringExtra("destination")
        val parsed = Uri.parse(destination)
        {body}
    }}
}}
"""
OK = 'parsed.scheme == "https" && parsed.host == "docs.example.test"'


@pytest.mark.parametrize(
    "body,expected",
    [
        # A guard that holds where the closure is written holds inside it.
        (f"if ({OK}) {{ runOnUiThread {{ browser.loadUrl(destination) }} }}", False),
        (f"if ({OK}) {{ }} else {{ return }}\n button.post {{ browser.loadUrl(destination) }}", False),
        # A Kotlin lambda body is a statement list: an early exit guards what follows.
        (
            f"button.setOnClickListener {{ if ({OK}) {{ }} else {{ return@setOnClickListener }}\n"
            " browser.loadUrl(destination) }",
            False,
        ),
        (f"button.setOnClickListener {{ if ({OK}) {{ browser.loadUrl(destination) }} }}", False),
        ("button.setOnClickListener { return@setOnClickListener\n browser.loadUrl(destination) }", False),
        # A guard established inside the closure does not hold after it.
        (
            f"runOnUiThread {{ if ({OK}) {{ }} else {{ return@runOnUiThread }} }}\n browser.loadUrl(destination)",
            True,
        ),
        ("button.post { browser.loadUrl(destination) }", True),
        # Negated early returns are not credited, inside a lambda as at function level.
        (
            f"button.setOnClickListener {{ if (!({OK})) return@setOnClickListener\n browser.loadUrl(destination) }}",
            True,
        ),
        (f"if (!({OK})) return\n browser.loadUrl(destination)", True),
    ],
)
def test_closure_guards_apply_inside_and_never_after(body: str, expected: bool) -> None:
    report = _kotlin(GUARD.format(body=body))
    assert _hit(report, URL) is expected, report


def test_partial_allowlist_is_read_from_conditions_not_from_whole_closures() -> None:
    clean = _kotlin(
        GUARD.format(
            body='button.post { browser.loadUrl("https://docs.example.test/"); val pdf = destination!!.endsWith(".pdf") }'
        )
    )
    partial = _kotlin(
        GUARD.format(
            body='button.post { if (destination!!.startsWith("https://docs.example.test")) browser.loadUrl(destination) }'
        )
    )
    assert not _hit(clean, ALLOWLIST)
    assert _hit(partial, ALLOWLIST)


@pytest.mark.parametrize(
    "wrap",
    [
        'listOf("a").forEach { id -> db.execSQL("DELETE FROM t WHERE id = " + id) }',
        'listOf("a").forEach({ id -> db.execSQL("DELETE FROM t WHERE id = " + id) })',
        'listOf("a").forEach { (id, _) -> db.execSQL("DELETE FROM t WHERE id = " + id) }',
        'id?.let { listOf("a").forEach { db.execSQL("DELETE FROM t WHERE id = " + it) } }',
        'intent.getStringArrayListExtra("ids")!!.forEachIndexed { i, x -> db.execSQL("DELETE FROM t WHERE id = " + i) }',
    ],
)
def test_closure_parameters_shadow_outer_names(wrap: str) -> None:
    report = _kotlin(BODY.format(wrap=wrap))
    assert not _hit(report, SQL), report


@pytest.mark.parametrize(
    "wrap",
    [
        'id?.let { runOnUiThread { db.execSQL("DELETE FROM t WHERE id = " + it) } }',
        'intent.getStringArrayListExtra("ids")!!.forEach { db.execSQL("DELETE FROM t WHERE id = " + it) }',
        'intent.getStringArrayListExtra("ids")!!.forEach { x -> db.execSQL("DELETE FROM t WHERE id = " + x) }',
        'intent.getStringArrayListExtra("ids")!!.filter { it.isNotEmpty() }.forEach { db.execSQL("DELETE FROM t WHERE id = " + it) }',
        'id.takeIf { it!!.isNotEmpty() }?.let { db.execSQL("DELETE FROM t WHERE id = " + it) }',
    ],
)
def test_element_and_enclosing_parameters_keep_provenance(wrap: str) -> None:
    report = _kotlin(BODY.format(wrap=wrap))
    assert _hit(report, SQL), report


def test_lambda_parameter_named_intent_is_not_the_activity_intent() -> None:
    report = _kotlin(
        """class E12 : Activity() {
    fun q(data: androidx.lifecycle.LiveData<Intent>) {
        data.observe(this) { intent -> startActivity(intent.getParcelableExtra<Intent>("next")!!) }
    }
}
"""
    )
    assert not _hit(report, REDIRECTION)


@pytest.mark.parametrize(
    "body",
    [
        """suspend fun q(intent: Intent) {
        val v = withContext(Dispatchers.IO) { intent.getStringExtra("q") }
        db.execSQL("DELETE FROM t WHERE id = " + v)
    }""",
        """suspend fun read(intent: Intent): String = withContext(Dispatchers.IO) { intent.getStringExtra("q")!! }
    suspend fun q(intent: Intent) { db.execSQL("DELETE FROM t WHERE id = " + read(intent)) }""",
        """fun q(intent: Intent) {
        val v = runCatching { intent.getStringExtra("q")!!.trim() }.getOrDefault("")
        db.execSQL("DELETE FROM t WHERE id = " + v)
    }""",
        """fun q(intent: Intent) {
        val v = listOf(1).map l@{ return@l intent.getStringExtra("q") }.first()
        db.execSQL("DELETE FROM t WHERE id = " + v)
    }""",
    ],
)
def test_closure_result_reaches_the_call_value(body: str) -> None:
    report = _kotlin(f"class V(private val db: SQLiteDatabase) {{\n    {body}\n}}\n")
    assert _hit(report, SQL), report


def test_non_local_return_from_an_unknown_inline_lambda_is_joined_and_limited() -> None:
    report = _kotlin(
        """class R1(private val db: SQLiteDatabase) {
    fun pick(intent: Intent): String { listOf(1).forEach { return intent.getStringExtra("q")!! }; return "" }
    fun q(intent: Intent) { db.execSQL("DELETE FROM t WHERE id = " + pick(intent)) }
}
"""
    )
    assert _hit(report, SQL)
    assert UNAVAILABLE in _reasons(report)


def test_optional_scope_written_with_parentheses_keeps_the_previous_value() -> None:
    report = _kotlin(
        BODY.format(
            wrap='var v = id\n id?.let() { v = "safe" }\n db.execSQL("DELETE FROM t WHERE id = " + v)'
        )
    )
    assert _hit(report, SQL)


def test_computed_callee_is_evaluated() -> None:
    report = _kotlin(
        """class E8(private val db: SQLiteDatabase) {
    fun pick(s: String): (() -> Unit) -> Unit { db.execSQL("DELETE FROM t WHERE id = " + s); return { } }
    fun q(intent: Intent) { pick(intent.getStringExtra("q")!!)() { } }
}
"""
    )
    assert _hit(report, SQL)


def test_runtime_filled_key_after_a_trailing_lambda_is_not_constant() -> None:
    report = _kotlin(
        """import javax.crypto.spec.SecretKeySpec
class K {
    fun fill(bytes: ByteArray, done: () -> Unit) { java.security.SecureRandom().nextBytes(bytes) }
    fun q() {
        val key = ByteArray(16)
        fill(key) { }
        SecretKeySpec(key, "AES")
    }
}
"""
    )
    assert "AST-CRYPTO-HARDCODED-KEY" not in {finding["rule_id"] for finding in report["findings"]}


SWIFT = """import UIKit
import WebKit
final class LinkHandler {{
 let browser = WKWebView()
 {declaration}
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {{
  {body}
 }}
}}"""
LATER = "func later(_ u: URL, _ done: () -> Void) { browser.load(URLRequest(url: u)) }"


@pytest.mark.parametrize(
    "declaration,body",
    [
        ("", "DispatchQueue.main.async { self.browser.load(URLRequest(url: incoming)) }"),
        ("", "[1].forEach { _ in self.browser.load(URLRequest(url: incoming)) }"),
        (
            "",
            "UIView.animate(withDuration: 1) { self.browser.load(URLRequest(url: incoming)) } completion: { _ in }",
        ),
        ("", "let xs = [incoming]\n  xs.forEach { self.browser.load(URLRequest(url: $0)) }"),
        (LATER, "later(incoming) { }"),
        (LATER, "later(incoming, { })"),
        (LATER, "let r: Void = later(incoming) { }"),
        (
            "func later(_ u: URL, completion: () -> Void) { browser.load(URLRequest(url: u)) }",
            "later(incoming) { }",
        ),
        (
            "func later(_ u: URL, success: () -> Void, failure: () -> Void) { browser.load(URLRequest(url: u)) }",
            "later(incoming) { } failure: { }",
        ),
        (
            "func later(_ u: URL, _ done: () -> Void) throws { browser.load(URLRequest(url: u)) }",
            "let r: Void? = try? later(incoming) { }",
        ),
    ],
)
def test_swift_trailing_closures_are_followed(declaration: str, body: str) -> None:
    report = _swift(SWIFT.format(declaration=declaration, body=body))
    assert _hit(report, URL), report


def test_swift_closure_guards_and_parameters() -> None:
    guarded = _swift(
        SWIFT.format(
            declaration="",
            body='DispatchQueue.main.async { guard incoming.scheme == "https", incoming.host == "docs.example.test" '
            "else { return }\n self.browser.load(URLRequest(url: incoming)) }",
        )
    )
    shadowed = _swift(
        SWIFT.format(
            declaration="",
            body='let safe = URL(string: "https://docs.example.test")!\n'
            "  [safe].forEach { incoming in self.browser.load(URLRequest(url: incoming)) }",
        )
    )
    mismatched = _swift(
        SWIFT.format(
            declaration="func later(_ u: URL, success: () -> Void, failure: () -> Void) { browser.load(URLRequest(url: u)) }",
            body="later(incoming) { } success: { }",
        )
    )
    assert not _hit(guarded, URL)
    assert not _hit(shadowed, URL)
    # A second trailing closure labelled for another parameter does not bind.
    assert not _hit(mismatched, URL) and _state(mismatched, URL) == "limited"


def test_swift_callee_with_a_closure_parameter_has_no_result_flow_gap() -> None:
    report = _swift(SWIFT.format(declaration=LATER, body="later(incoming) { }"))
    assert "return flow unavailable" not in _reasons(report)


def _calls(language: str, text: str) -> list:
    grammar = importlib.import_module(f"tree_sitter_{language}")
    tree = tree_sitter.Parser(tree_sitter.Language(grammar.language())).parse(text.encode())
    analyzer = Analyzer("Shape", text, language)
    found, stack = [], [tree.root_node]
    while stack:
        node = stack.pop()
        if (
            node.type == "call_expression"
            and node.parent is not None
            and node.parent.type != "call_expression"
        ):
            call = analyzer.call(node)
            assert call is not None
            found.append(
                (
                    call.name,
                    analyzer.text(call.receiver) if call.receiver is not None else None,
                    [analyzer.text(argument) for argument in call.args],
                    len(call.trailing),
                )
            )
        stack.extend(reversed(node.named_children))
    return found


@pytest.mark.parametrize(
    "language,text,expected",
    [
        ("kotlin", "fun m() { f(x) { } }", ("f", None, ["x", "{ }"], 1)),
        ("kotlin", "fun m() { o?.f<T>(x, y) l@{ it } }", ("f", "o", ["x", "y", "{ it }"], 1)),
        ("kotlin", "fun m() { f { } }", ("f", None, ["{ }"], 1)),
        ("kotlin", "fun m() { with(x) { } }", ("with", None, ["x", "{ }"], 1)),
        # The second lambda invokes f's result: no merge into one call.
        ("kotlin", "fun m() { f(x) {} {} }", ("f(x) {}", None, ["{}"], 1)),
        ("swift", "func m() { f(x) { } }", ("f", None, ["x", "{ }"], 1)),
        ("swift", "func m() { let r = o.f(x) { } }", ("f", "o", ["x", "{ }"], 1)),
        ("swift", "func m() { let r = try f(x) { } }", ("f", None, ["x", "{ }"], 1)),
        ("swift", "func m() { f(x) { } done: { } }", ("f", None, ["x", "{ }", "{ }"], 2)),
    ],
)
def test_call_model_appends_trailing_lambdas_as_last_arguments(
    language: str, text: str, expected: tuple
) -> None:
    assert _calls(language, text)[0] == expected


def _nested(depth: int) -> str:
    lines = ['    val label = intent.getStringExtra("q") ?: ""']
    for level in range(depth):
        lines.append("    " * (level + 1) + "Wrap {")
        lines.extend("    " * (level + 2) + f'Text("row{level}_{column}" + label)' for column in range(4))
    lines.extend("    " * (level + 1) + "}" for level in reversed(range(depth)))
    return (
        "package com.example.app\nimport android.content.Intent\n"
        "fun Wrap(content: () -> Unit) { content() }\nfun Text(s: String) {}\n"
        "class Screen {\n  fun render(intent: Intent) {\n" + "\n".join(lines) + "\n  }\n}\n"
    )


def test_nested_closures_are_evaluated_once_per_call() -> None:
    evaluations = {
        depth: analyze_sources([("app/S.kt", _nested(depth))])["metadata"]["native_flow"]["evaluations"]
        for depth in (8, 16)
    }
    # Each project call is followed once: linear in the number of calls, not in depth squared.
    assert evaluations[16] <= 2 * evaluations[8] + 4, evaluations


def test_collection_chain_keeps_each_source_once_without_a_trace_budget() -> None:
    report = _kotlin(
        BODY.format(
            wrap='intent.getStringArrayListExtra("ids")!!.map { it.trim() }.filter { it.isNotEmpty() }'
            '.map { it.lowercase() }.forEach { db.execSQL("DELETE FROM t WHERE id = " + it) }'
        )
    )
    finding = next(item for item in report["findings"] if item["rule_id"] == SQL)
    assert len(finding["evidence"][0]["sources"]) == 1, finding
    assert "source trace budget" not in _reasons(report)
    assert _state(report, SQL) != "partial"


@pytest.mark.parametrize("depth", [4, 8, 16])
def test_closure_chain_evaluates_its_origin_once_per_call(monkeypatch, depth: int) -> None:
    origin = 'intent.getStringArrayListExtra("ids")!!'
    original = Analyzer.value
    evaluations = 0

    def counted(self, node, frame):
        nonlocal evaluations
        if node is not None and self.text(node) == origin:
            evaluations += 1
            assert evaluations <= depth + 4
        return original(self, node, frame)

    monkeypatch.setattr(Analyzer, "value", counted)
    chain = "".join(".map { it }" for _ in range(depth))
    report = _kotlin(
        BODY.format(wrap=f'{origin}{chain}.forEach {{ db.execSQL("DELETE FROM t WHERE id = " + it) }}')
    )
    assert _hit(report, SQL)
    assert 0 < evaluations <= depth + 4


def _budget(report: dict) -> list[str]:
    return report["metadata"]["native_flow"].get("budget_reasons", [])


ACTIVITY = """class Repo(private val db: SQLiteDatabase) {{
    fun store(a: String, b: String) {{ db.execSQL("INSERT INTO t VALUES (?, ?)", arrayOf<Any>(a, b)) }}
}}
class Vm(private val repo: Repo) {{
    fun store(a: String, b: String) {{ repo.store(a, b) }}
}}
class DetailActivity : Activity() {{
    private var last = ""
    private lateinit var vm: Vm
    private lateinit var save: android.widget.Button
    private lateinit var scope: CoroutineScope
    private fun show(value: String) {{ last = value }}
    fun open(i: Intent) {{
        val a = i.getStringExtra("a") ?: return
        val b = i.getStringExtra("b") ?: ""
        {body}
    }}
}}
"""


@pytest.mark.parametrize(
    "body, direct",
    [
        ('i.getStringExtra("name")?.let { show(it) }', "show(a)"),
        ("run { show(a) }", "show(a)"),
        ("runOnUiThread { show(a) }", "show(a)"),
        ("save.setOnClickListener { show(a) }", "show(a)"),
        ("listOf(1).forEach { show(a) }", "show(a)"),
        ("scope.launch { vm.store(a, b) }", "vm.store(a, b)"),
        ("save.setOnClickListener { vm.store(a, b) }", "vm.store(a, b)"),
        ("save.post { vm.store(a, b) }", "vm.store(a, b)"),
        ("runOnUiThread { vm.store(a, b) }", "vm.store(a, b)"),
    ],
)
def test_closure_result_does_not_repeat_the_last_call(body: str, direct: str) -> None:
    """The closure's value reuses the visit's evaluation of its last call (no doubled weak writes)."""
    closure, written = _kotlin(ACTIVITY.format(body=body)), _kotlin(ACTIVITY.format(body=direct))
    assert _budget(closure) == [] == _budget(written)
    assert _state(closure, SQL) == _state(written, SQL) == "limited"


def test_receiver_and_swift_closures_calling_own_helpers_are_not_partial() -> None:
    receiver = _kotlin(
        """class Pong : android.content.BroadcastReceiver() {
    private var last = ""
    private fun handle(value: String) { last = value }
    override fun onReceive(context: android.content.Context, intent: Intent) {
        intent.getStringExtra("payload")?.let { handle(it) }
    }
}
"""
    )
    swift = _swift(
        """import UIKit
import WebKit
final class Browser: UIViewController, WKNavigationDelegate {
    var current = ""
    func handle(_ value: String) { current = value }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        let s = navigationAction.request.url?.absoluteString ?? ""
        DispatchQueue.main.async { self.handle(s) }
        decisionHandler(.allow)
    }
}
"""
    )
    assert _budget(receiver) == [] and _state(receiver, SQL) != "partial"
    assert _budget(swift) == [] and _state(swift, URL) != "partial"


def test_closure_ending_in_an_if_has_the_branch_values_not_the_condition() -> None:
    report = _kotlin(
        """class Logger {
    fun log(extras: android.os.Bundle) {
        extras.keySet().forEach { key ->
            val v = extras.getString(key)
            if (v != null && v.isNotEmpty() && key.isNotEmpty() && v.length < 64) android.util.Log.i("k", key)
        }
    }
}
"""
    )
    assert _budget(report) == []
    assert _state(report, SQL) == "checked"


@pytest.mark.parametrize(
    "exit_statement",
    ["return@setOnClickListener", 'throw IllegalStateException("x")'],
)
def test_statement_after_an_exit_is_not_the_closure_value(exit_statement: str) -> None:
    report = _kotlin(
        f"""class R(private val db: SQLiteDatabase, private val button: android.view.View) {{
    fun runQuery(id: String) {{ db.execSQL("DELETE FROM t WHERE id = " + id) }}
    fun q(intent: Intent) {{
        val id = intent.getStringExtra("q") ?: ""
        button.setOnClickListener {{
            {exit_statement}
            runQuery(id)
        }}
    }}
}}
"""
    )
    assert not _hit(report, SQL)


@pytest.mark.parametrize(
    "expression",
    [
        "synchronized(lock) { Cache() }",
        "synchronized(lock, { Cache() })",
        "runCatching { Cache() }.getOrNull()",
    ],
)
def test_object_made_in_a_closure_is_no_reference_argument(expression: str) -> None:
    report = _kotlin(
        f"""class Cache {{ var n = 0 }}
class Holder {{
    private val lock = Any()
    fun get(): Cache? = {expression}
}}
"""
    )
    assert _state(report, SQL) == "checked", _reasons(report)


def test_swift_object_made_in_a_closure_is_no_reference_argument() -> None:
    lock = _swift(
        """import UIKit
final class Model { var n = 0 }
final class Store {
    let lock = NSLock()
    func make() -> Model { lock.withLock { Model() } }
}
"""
    )
    views = _swift(
        """import SwiftUI
struct DetailView: View {
    let title: String
    var body: some View { Text(title) }
}
struct ContentView: View {
    @State private var shown = false
    var body: some View {
        VStack { DetailView(title: "a") }
            .sheet(isPresented: $shown) { DetailView(title: "b") }
    }
}
"""
    )
    for report in (lock, views):
        reasons = set(_reasons(report))
        assert "unresolved reference argument effects" not in reasons, reasons
        assert "reachable field ownership unavailable" not in reasons, reasons
    framework = {"VStack", "sheet"}
    assert not [
        row for row in views["metadata"]["native_flow"]["partial_details"] if row["call"] in framework
    ]


def test_use_keeps_its_close_effect_and_function_references_stay_limited() -> None:
    use = _kotlin(
        """class Res : java.io.Closeable {
    var src = ""
    var q = ""
    override fun close() { q = src }
}
class R(private val db: SQLiteDatabase) {
    fun go(intent: Intent) {
        val r = Res()
        r.src = intent.getStringExtra("q")!!
        r.use { }
        db.execSQL("DELETE FROM t WHERE id = " + r.q)
    }
}
"""
    )
    reference = _kotlin(
        """class Box { var q = "" }
class R(private val db: SQLiteDatabase) {
    private var pending = ""
    fun fill(b: Box) { b.q = pending }
    fun go(intent: Intent) {
        pending = intent.getStringExtra("q")!!
        val b = Box()
        b.also(::fill)
        db.execSQL("DELETE FROM t WHERE id = " + b.q)
    }
}
"""
    )
    assert _hit(use, SQL)
    assert _state(reference, SQL) == "limited"


@pytest.mark.parametrize(
    "loop",
    ["names.forEach { _ -> sink(it) }", "names.forEach({ _ -> sink(it) })"],
)
def test_underscore_parameter_keeps_the_enclosing_it(loop: str) -> None:
    tainted = _kotlin(
        f"""class R(private val db: SQLiteDatabase) {{
    fun sink(v: String) {{ db.execSQL("DELETE FROM t WHERE id = " + v) }}
    fun q(intent: Intent, names: List<String>) {{ intent.getStringExtra("q")?.let {{ {loop} }} }}
}}
"""
    )
    clean = _kotlin(
        f"""class R(private val db: SQLiteDatabase) {{
    fun sink(v: String) {{ db.execSQL("DELETE FROM t WHERE id = " + v) }}
    fun q(intent: Intent) {{
        val names = listOf(intent.getStringExtra("q")!!)
        "safe".let {{ {loop} }}
    }}
}}
"""
    )
    assert _hit(tainted, SQL)
    assert not _hit(clean, SQL)


@pytest.mark.parametrize(
    "loop",
    ["m.forEach { k, v -> sink(v) }", "m.forEach { _, v -> sink(v) }", "m.forEach({ _, v -> sink(v) })"],
)
def test_map_for_each_binds_the_value_parameter(loop: str) -> None:
    report = _kotlin(
        f"""class R(private val db: SQLiteDatabase) {{
    fun sink(v: String) {{ db.execSQL("DELETE FROM t WHERE id = " + v) }}
    fun q(intent: Intent) {{ val m = mapOf("a" to intent.getStringExtra("q")!!); {loop} }}
}}
"""
    )
    assert _hit(report, SQL)


@pytest.mark.parametrize(
    "loop",
    [
        "routes.forEach { _, value in self.browser.load(URLRequest(url: value)) }",
        "routes.map { $1 }.forEach { self.browser.load(URLRequest(url: $0)) }",
    ],
)
def test_swift_dictionary_closures_bind_the_value(loop: str) -> None:
    report = _swift(
        f"""import UIKit
import WebKit
final class LinkHandler {{
    let browser = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {{
        let routes = ["a": incoming]
        {loop}
    }}
}}
"""
    )
    assert _hit(report, URL)


def test_accumulators_keep_their_provenance() -> None:
    reduce = _kotlin(
        """class R(private val db: SQLiteDatabase) {
    fun sink(v: String) { db.execSQL("DELETE FROM t WHERE id = " + v) }
    fun q(intent: Intent) { val ids = listOf(intent.getStringExtra("q")!!); ids.reduce { acc, x -> sink(acc); acc + x } }
}
"""
    )
    fold = _kotlin(
        """class R(private val db: SQLiteDatabase) {
    fun sink(v: String) { db.execSQL("DELETE FROM t WHERE id = " + v) }
    fun q(intent: Intent) { listOf("a").fold(intent.getStringExtra("q")!!) { acc, x -> sink(acc); acc + x } }
}
"""
    )
    assert _hit(reduce, SQL) and _hit(fold, SQL)


@pytest.mark.parametrize(
    "call",
    [
        'web.evaluateJavascript(js) { js = intent.getStringExtra("q")!! }',
        'web.evaluateJavascript(js, { js = intent.getStringExtra("q")!! })',
    ],
)
def test_callback_writes_do_not_reach_the_arguments_of_its_call(call: str) -> None:
    report = _kotlin(
        f"""class W(private val web: WebView) {{
    fun q(intent: Intent) {{
        var js = "init()"
        {call}
    }}
}}
"""
    )
    assert not _hit(report, URL)


@pytest.mark.parametrize(
    "lookup, rule",
    [
        (
            'val url = allowed.firstOrNull { it.endsWith("/" + wanted) } ?: return\n        web.loadUrl(url)',
            URL,
        ),
        ("val url = allowed.find { it == wanted } ?: return\n        web.loadUrl(url)", URL),
        ("allowed.filter { it == wanted }.forEach { web.loadUrl(it) }", URL),
        ('db.execSQL("SELECT " + allowed.count { it == wanted })', SQL),
    ],
)
def test_predicate_result_is_not_the_selected_value(lookup: str, rule: str) -> None:
    report = _kotlin(
        f"""class W(private val web: WebView, private val db: SQLiteDatabase) {{
    private val allowed = listOf("https://docs.example.test/a", "https://docs.example.test/b")
    fun q(intent: Intent) {{
        val wanted = intent.getStringExtra("page") ?: return
        {lookup}
    }}
}}
"""
    )
    assert not _hit(report, rule)


KOTLIN_BUILDER = """class R(private val db: SQLiteDatabase) {{
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val s = {build}
        db.execSQL("SELECT " + s)
    }}
}}
"""


@pytest.mark.parametrize(
    "build",
    [
        'Markup.render({ sb -> sb.append("<b>"); sb.append(q); println(0) })',
        'Markup.render { sb -> sb.append("<b>"); sb.append(q); println(0) }',
        "Markup.render { it.append(q); println(0) }",
        'buildString { append("<b>"); append(q); append("</b>") }',
        "Req.make { r -> r.query = q; r.page = 1 }",
    ],
)
def test_values_written_into_callee_supplied_objects_reach_the_call_value(build: str) -> None:
    assert _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL)


def test_statement_lambda_results_reach_no_call_value() -> None:
    report = _kotlin(
        """class R(private val db: SQLiteDatabase, private val button: android.view.View) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        button.setOnClickListener { android.util.Log.d("t", q) }
        val label = "x"
        db.execSQL("SELECT " + label)
    }
}
"""
    )
    assert not _hit(report, SQL)
    assert _state(report, SQL) == "checked"


JAVA = """package com.example.app;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
"""


def _java(body: str) -> dict:
    return analyze_sources([("app/src/main/java/com/example/app/C.java", JAVA + body)])


@pytest.mark.parametrize(
    "body",
    [
        'String page = Templates.render(m -> { m.put("q", q); });\n    db.execSQL("SELECT " + page);',
        'String page = Markup.render(sb -> { sb.append("<b>"); sb.append(q); });\n    db.execSQL("SELECT " + page);',
        'Map<String, String> m = new HashMap<>();\n    m.computeIfAbsent("k", k -> q);\n    db.execSQL("SELECT " + m.get("k"));',
        'List<String> l = new ArrayList<>();\n    l.add("a");\n    l.replaceAll(s -> s + q);\n    db.execSQL("SELECT " + l.get(0));',
        'AtomicReference<String> r = new AtomicReference<>("a");\n    r.updateAndGet(v -> v + q);\n    db.execSQL("SELECT " + r.get());',
        'List<String> xs = intent.getStringArrayListExtra("ids");\n    xs.forEach(id -> db.execSQL("DELETE FROM t WHERE id = " + id));',
        'java.util.function.Supplier<String> s = () -> { return q; };\n    String v = Optional.of("a").map(a -> { return q; }).get();\n    db.execSQL("SELECT " + v);',
        'String page = Markup.render(m -> { Fill.into(m.attrs, q); });\n    db.execSQL("SELECT " + page);',
        'String page = Markup.render(m -> { Fill.into(m.getBody(), q); });\n    db.execSQL("SELECT " + page);',
        'String page = Markup.render(m -> { m.merge("q", "x", (a, b) -> q); });\n    db.execSQL("SELECT " + page);',
    ],
)
def test_java_lambdas_keep_their_flows(body: str) -> None:
    report = _java(
        f"""class C {{
  SQLiteDatabase db;
  void q(Intent intent) {{
    String q = intent.getStringExtra("q");
    {body}
  }}
}}
"""
    )
    assert _hit(report, SQL), _reasons(report)


def test_java_lambda_parameter_shadows_and_statement_lambdas_store_nothing() -> None:
    shadow = _java(
        """class C {
  SQLiteDatabase db;
  void q(Intent intent) {
    String id = intent.getStringExtra("q");
    List<String> safe = new ArrayList<>();
    safe.add("a");
    safe.forEach(id2 -> db.execSQL("DELETE FROM t WHERE id = " + id2));
  }
}
"""
    )
    statement = _java(
        """class C extends android.app.Activity {
  SQLiteDatabase db;
  String label = "x";
  void q(Intent intent) {
    String id = intent.getStringExtra("q");
    runOnUiThread(() -> android.util.Log.d("t", id));
    db.execSQL("SELECT " + label);
  }
}
"""
    )
    assert not _hit(shadow, SQL)
    assert not _hit(statement, SQL)


SWIFT_HANDLER = """import UIKit
import WebKit
final class LinkHandler {{
    let browser = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {{
        {body}
    }}
}}
"""


@pytest.mark.parametrize(
    "body",
    [
        "let u = [1].map { _ -> URL in let x = incoming\n return x }.first!\n        browser.load(URLRequest(url: u))",
        "DispatchQueue.main.async { [u = incoming] in self.browser.load(URLRequest(url: u)) }",
        'let html = Markup.render({ sb in sb.add("<b>"); sb.add(incoming.absoluteString) })\n        browser.load(URLRequest(url: URL(string: html)!))',
    ],
)
def test_swift_closure_returns_captures_and_supplied_objects(body: str) -> None:
    assert _hit(_swift(SWIFT_HANDLER.format(body=body)), URL)


def test_closure_whose_arity_does_not_match_keeps_the_callee_limited() -> None:
    report = _kotlin(
        """class C(private val db: SQLiteDatabase) : Activity() {
    fun attach(name: String, done: (Int, Int) -> Unit) { db.execSQL("DELETE FROM t WHERE id = " + name) }
    fun q() { attach(intent.getStringExtra("q")!!) { a -> } }
}
"""
    )
    assert _state(report, SQL) == "limited"


def test_declared_result_without_a_return_keeps_the_return_flow_limit() -> None:
    missing = _kotlin(
        """class C(private val db: SQLiteDatabase) {
    fun pick(i: Intent): String { throw IllegalStateException() }
    fun q(intent: Intent) { db.execSQL("DELETE FROM t WHERE id = " + pick(intent)) }
}
"""
    )
    unit = _kotlin(
        """class C(private val db: SQLiteDatabase) {
    fun pick(i: Intent): Unit { println(1) }
    fun q(intent: Intent) { pick(intent); db.execSQL("DELETE FROM t WHERE id = 1") }
}
"""
    )
    assert "return flow unavailable" in _reasons(missing)
    assert "return flow unavailable" not in _reasons(unit)


@pytest.mark.parametrize(
    "expression",
    [
        'Worker.call { safe?.let { intent.getStringExtra("q") } }',
        'Worker.call { run { intent.getStringExtra("q") } }',
        'safe?.let { intent.getStringExtra("q") }',
    ],
)
def test_scope_call_ending_a_closure_carries_its_block_result(expression: str) -> None:
    report = _kotlin(
        f"""class R(private val db: SQLiteDatabase) {{
    fun q(intent: Intent, safe: String?) {{
        val q = {expression}
        db.execSQL("SELECT " + q)
    }}
}}
"""
    )
    assert _hit(report, SQL)
    assert _state(report, SQL) == "checked"


@pytest.mark.parametrize(
    "expression, sink, rule",
    [
        ('buildString { println(q); append("safe") }', 'db.execSQL("SELECT " + s)', SQL),
        ('withContext(Dispatchers.IO) { println(q); "safe" }', 'db.execSQL("SELECT " + s)', SQL),
        ('runBlocking { println(q); "safe" }', 'db.execSQL("SELECT " + s)', SQL),
        (
            'withContext(Dispatchers.IO) { require(q.isNotEmpty()); "https://docs.example.test/static" }',
            "web.loadUrl(s)",
            URL,
        ),
    ],
)
def test_receiverless_calls_that_write_no_builder_are_not_the_closure_value(
    expression: str, sink: str, rule: str
) -> None:
    report = _kotlin(
        f"""class R(private val db: SQLiteDatabase, private val web: WebView) {{
    suspend fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val s = {expression}
        {sink}
    }}
}}
"""
    )
    assert not _hit(report, rule)


EXPLICIT = """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.app.Activity
import android.webkit.WebView
import android.view.View
import android.os.Handler
"""


def _explicit(body: str) -> dict:
    """A Kotlin file without wildcard imports: stdlib scope functions are provably unshadowed."""
    return analyze_sources([("app/E.kt", EXPLICIT + body)])


CONSUMER = """class ReaderActivity : Activity() {{
    private var lastKey = ""
    private lateinit var root: View
    private fun remember(key: String) {{ lastKey = key }}
    fun open(i: Intent) {{
        val key = i.getStringExtra("key") ?: return
        {body}
    }}
}}
"""


@pytest.mark.parametrize(
    "body, twin",
    [
        ("Thread { remember(key) }.start()", "remember(key); Thread { }.start()"),
        (
            "val r = Runnable { remember(key) }; root.postDelayed(r, 500)",
            "remember(key); root.postDelayed(Runnable { }, 500)",
        ),
        (
            "runCatching { remember(key) }.onFailure { println(it) }",
            "remember(key); runCatching { }.onFailure { println(it) }",
        ),
        ("Thread { remember(key); println(1) }.start()", "remember(key); Thread { }.start()"),
    ],
)
def test_consumed_closure_value_adds_no_budget_reason(body: str, twin: str) -> None:
    closure, direct = _explicit(CONSUMER.format(body=body)), _explicit(CONSUMER.format(body=twin))
    assert _budget(closure) == [] == _budget(direct)
    assert _state(closure, SQL) == _state(direct, SQL)


@pytest.mark.parametrize(
    "body, twin",
    [
        (
            'alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in self.remember(key) })',
            'self.remember(key); alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in })',
        ),
        (
            "let item = DispatchWorkItem { self.remember(key) }; DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: item)",
            "self.remember(key); DispatchQueue.main.asyncAfter(deadline: .now() + 1, execute: DispatchWorkItem { })",
        ),
    ],
)
def test_swift_consumed_closure_value_adds_no_budget_reason(body: str, twin: str) -> None:
    source = """import UIKit
import WebKit
final class Browser: UIViewController, WKNavigationDelegate {{
    var lastKey = ""
    let alert = UIAlertController(title: "t", message: nil, preferredStyle: .alert)
    func remember(_ key: String) {{ lastKey = key }}
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {{
        let key = navigationAction.request.url?.absoluteString ?? ""
        {body}
        decisionHandler(.allow)
    }}
}}
"""
    closure, direct = _swift(source.format(body=body)), _swift(source.format(body=twin))
    assert _budget(closure) == [] == _budget(direct)
    assert _state(closure, URL) == _state(direct, URL)


BRANCH = """class W(private val web: WebView) {{
    fun q(intent: Intent, flag: Boolean) {{
        val s = {expression}
        web.loadUrl(s)
    }}
}}
"""


@pytest.mark.parametrize(
    "expression",
    [
        'run { try { val raw = intent.getStringExtra("url")!!; raw } catch (e: Exception) { "https://h/" } }',
        'run { when (val u = intent.getStringExtra("url")) { null -> "https://h/"; else -> u } }',
        'run { if (flag) { val t = intent.getStringExtra("url")!!; t } else { "https://h/" } }',
        'run({ when (intent.action) { "open" -> { val u = intent.getStringExtra("url")!!; "https://h/" + u }; else -> "https://h/" } })',
        'run { when (intent.action) { "open" -> intent.getStringExtra("url")!! // deep link\n else -> "https://h/" } }',
        'run { when (intent.action) { "open" -> intent.getStringExtra("url")!!\n // fallback\n else -> "https://h/" } }',
    ],
)
def test_branch_values_are_read_where_each_branch_ends(expression: str) -> None:
    report = _kotlin(BRANCH.format(expression=expression))
    assert _hit(report, URL)


def test_branch_condition_is_not_the_closure_value() -> None:
    report = _kotlin(
        BRANCH.format(
            expression='Ext.pick { if (intent.getStringExtra("url") != null) "https://h/a" else "https://h/b" }'
        )
    )
    assert not _hit(report, URL)


@pytest.mark.parametrize(
    "body",
    [
        "let u = try? queue.sync { try resolve(incoming) }\n        browser.load(URLRequest(url: u!))",
        'let u = queue.sync { if let v = maybe { v } else { URL(string: "https://h/")! } }\n        browser.load(URLRequest(url: u))',
        'let u = queue.sync { switch maybe { case .some(let v): v\n case .none: URL(string: "https://h/")! } }\n        browser.load(URLRequest(url: u))',
    ],
)
def test_swift_closure_results_keep_try_and_bound_branch_values(body: str) -> None:
    report = _swift(
        f"""import UIKit
import WebKit
final class LinkHandler {{
    let browser = WKWebView()
    let queue = DispatchQueue(label: "q")
    func resolve(_ u: URL) throws -> URL {{ return u }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {{
        let maybe: URL? = incoming
        {body}
    }}
}}
"""
    )
    assert _hit(report, URL)


@pytest.mark.parametrize(
    "call",
    [
        'val r = attach(name) { name = intent.getStringExtra("q")!! }',
        'r = attach(name) { name = intent.getStringExtra("q")!! }',
    ],
)
def test_callback_write_does_not_reach_a_followed_callee_in_a_value_position(call: str) -> None:
    clean = _kotlin(
        f"""class R(private val db: SQLiteDatabase) {{
    private var r = ""
    fun attach(n: String, done: () -> Unit): String {{ db.execSQL("DELETE FROM t WHERE id = " + n); return n }}
    fun q(intent: Intent) {{
        var name = "const"
        {call}
    }}
}}
"""
    )
    flow = _kotlin(
        """class R(private val db: SQLiteDatabase) {
    fun attach(n: String, done: () -> Unit): String { db.execSQL("DELETE FROM t WHERE id = " + n); return n }
    fun q(intent: Intent) {
        var name = "const"
        name = intent.getStringExtra("q")!!
        val r = attach(name) { }
    }
}
"""
    )
    assert not _hit(clean, SQL)
    assert _hit(flow, SQL)


@pytest.mark.parametrize(
    "build",
    [
        "Markup.render({ sb -> val b = sb; b.append(q); println(0) })",
        "Markup.render { sb -> sb.let { it.append(q) }; println(0) }",
        "Markup.render({ sb -> fill(sb, q); println(0) })",
        "Markup.render({ b -> b.items[0].text = q; println(0) })",
        "Markup.render({ w -> w.group({ g -> g.append(q) }); println(0) })",
    ],
)
def test_writes_through_aliases_helpers_and_nested_builders_reach_the_call_value(build: str) -> None:
    assert _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL)


@pytest.mark.parametrize(
    "declaration",
    [
        'func page(_ q: String) -> String { Markup.render { b in b.add("<p>"); b.add(q) } }',
        'func page(_ q: String) -> String { Markup.render({ b in let c = b; c.add("<p>"); c.add(q) }) }',
    ],
)
def test_swift_single_expression_bodies_return_builder_values(declaration: str) -> None:
    report = _swift(
        f"""import UIKit
import WebKit
final class LinkHandler {{
    let browser = WKWebView()
    {declaration}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {{
        browser.load(URLRequest(url: URL(string: page(incoming.absoluteString))!))
    }}
}}
"""
    )
    assert _hit(report, URL)


@pytest.mark.parametrize(
    "pick",
    [
        'pages.sortedWith(compareBy { !it.endsWith("/" + wanted) }).first()',
        'pages.sortedWith(compareByDescending { it.endsWith("/" + wanted) }).first()',
        "pages.sortedWith(Comparator { a, b -> if (a.endsWith(wanted)) -1 else 1 }).first()",
    ],
)
def test_comparator_closures_are_not_the_selected_value(pick: str) -> None:
    report = _kotlin(
        f"""class W(private val web: WebView) {{
    private val pages = listOf("https://docs.example.test/a", "https://docs.example.test/b")
    fun q(intent: Intent) {{
        val wanted = intent.getStringExtra("page") ?: return
        web.loadUrl({pick})
    }}
}}
"""
    )
    assert not _hit(report, URL)


def test_nested_builders_stay_within_the_trace_budget() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val a = intent.getStringExtra("a") ?: ""
        val b = intent.getStringExtra("b") ?: ""
        val c = intent.getStringExtra("c") ?: ""
        val html = Html.node { n1 -> n1.text(a); n1.text(b); n1.text(c); n1.child(Html.node { n2 -> n2.text(a); n2.text(b); n2.text(c); n2.child(Html.node { n3 -> n3.text(a); n3.text(b); n3.text(c); n3.child(Html.node { n4 -> n4.text(a); n4.text(b); n4.text(c) }) }) }) }
        web.loadUrl(html)
    }
}
"""
    )
    assert _hit(report, URL)
    assert _budget(report) == []


def test_use_without_wildcard_imports_keeps_its_close_effect() -> None:
    report = _explicit(
        """class Res : java.io.Closeable {
    var src = ""
    var q = ""
    override fun close() { q = src }
}
class R(private val db: SQLiteDatabase) {
    fun go(intent: Intent) {
        val r = Res()
        r.src = intent.getStringExtra("q")!!
        r.use { }
        db.execSQL("DELETE FROM t WHERE id = " + r.q)
    }
}
"""
    )
    assert _hit(report, SQL)


def test_project_callee_argument_reassigned_by_its_callback_is_bound_before() -> None:
    report = _kotlin(
        """class R(private val db: SQLiteDatabase) {
    fun attach(n: String, done: () -> Unit) { db.execSQL("DELETE FROM t WHERE id = " + n) }
    fun q(intent: Intent) {
        var name = "const"
        attach(name) { name = intent.getStringExtra("q")!! }
    }
}
"""
    )
    assert not _hit(report, SQL)


def test_state_flow_update_stores_its_closure_result() -> None:
    report = _kotlin(
        """import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
class R(private val db: SQLiteDatabase) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val st = MutableStateFlow("")
        st.update { q }
        db.execSQL("SELECT " + st.value)
    }
}
"""
    )
    assert _hit(report, SQL)


def test_swift_dictionary_filter_binds_the_value_parameter() -> None:
    report = _swift(
        """import UIKit
import WebKit
final class LinkHandler {
    let browser = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {
        let routes = ["a": incoming]
        _ = routes.filter { key, value in self.browser.load(URLRequest(url: value)); return true }
    }
}
"""
    )
    assert _hit(report, URL)


def test_arity_mismatched_closure_with_an_intent_parameter_stays_limited() -> None:
    report = _kotlin(
        """class C(private val db: SQLiteDatabase) : Activity() {
    fun attach(name: String, done: (Int, Int) -> Unit) { db.execSQL("DELETE FROM t WHERE id = " + name) }
    fun q(intent: Intent) { attach(intent.getStringExtra("q")!!) { a -> } }
}
"""
    )
    assert _state(report, SQL) == "limited"
    assert not _hit(report, SQL)


WHEN_SUBJECT = """class LinkActivity : Activity() {{
    private var url: String? = null
    private lateinit var web: WebView
    fun open(i: Intent) {{
        {body}
    }}
}}
"""


@pytest.mark.parametrize(
    "body, expected",
    [
        ('when (val url = i.getStringExtra("url")) { null -> finish(); else -> web.loadUrl(url) }', True),
        (
            'when (val r = i.getStringExtra("url")) { null -> Unit; else -> println(r) }\n'
            '        when (val r = "https://docs.example.test/") { else -> web.loadUrl(r) }',
            False,
        ),
        (
            'when (val r = "https://docs.example.test/") { else -> println(r) }\n'
            '        when (val r = i.getStringExtra("url")) { null -> Unit; else -> web.loadUrl(r) }',
            True,
        ),
        (
            'val r = i.getStringExtra("url")!!\n'
            '        when (val r = "https://docs.example.test/") { else -> println(r) }\n'
            "        web.loadUrl(r)",
            True,
        ),
    ],
)
def test_when_subject_binds_its_name_for_the_entries_only(body: str, expected: bool) -> None:
    assert _hit(_kotlin(WHEN_SUBJECT.format(body=body)), URL) is expected


def test_builder_receiver_member_wins_over_a_project_function_of_the_same_name() -> None:
    report = _kotlin(
        """class R(private val db: SQLiteDatabase) {
    private val parts = mutableListOf<String>()
    fun append(part: String) { parts.add(part) }
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val sql = buildString { append("SELECT '"); append(q); append("'") }
        db.execSQL(sql)
    }
}
"""
    )
    assert _hit(report, SQL)


@pytest.mark.parametrize(
    "check, expected",
    [
        (
            'if url.scheme == "https", url.host == "app.example.com" { webView.load(URLRequest(url: url)) }',
            False,
        ),
        ("webView.load(URLRequest(url: url))", True),
    ],
)
def test_swift_case_binding_keeps_the_subject_category(check: str, expected: bool) -> None:
    report = _swift(
        f"""import UIKit
import WebKit
final class Browser {{
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {{
        switch navigationAction.request.url {{
        case let url?:
            {check}
        default:
            break
        }}
        decisionHandler(.allow)
    }}
}}
"""
    )
    assert _hit(report, URL) is expected


@pytest.mark.parametrize(
    "build",
    [
        'buildList { add(q); add("x") }.joinToString()',
        'buildMap { put("k", q); put("a", "b") }.toString()',
        'buildString { append("SELECT \'"); append(q); append("\'") }',
    ],
)
def test_builder_writes_survive_same_named_methods_in_other_files(build: str) -> None:
    kotlin = (
        KOTLIN
        + f"""class R(private val db: SQLiteDatabase) {{
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val s = {build}
        db.execSQL("SELECT " + s)
    }}
}}
"""
    )
    java = """package com.example.app;
class Recent { void add(String s) { } void put(String k, String v) { } void append(String s) { } }
"""
    report = analyze_sources([("app/R.kt", kotlin), ("app/src/main/java/com/example/app/Recent.java", java)])
    assert _hit(report, SQL)


@pytest.mark.parametrize(
    "build",
    [
        "div { text(q); br() }",
        "div { p { +q }; br() }",
        "div { +q; br() }",
        'Ext.request { parameter("q", q); header("a", "b") }',
        'Ext.request { url(q); method("GET") }',
    ],
)
def test_dsl_writes_into_an_implicit_receiver_reach_the_call_value(build: str) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val html = {build}
        web.loadUrl(html)
    }}
}}
"""
    )
    assert _hit(report, URL)


NINE = " + ".join(f'intent.getStringExtra("k{index}")!!' for index in range(9))


def test_distinct_source_loss_in_a_closure_result_remains_a_budget() -> None:
    unresolved = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        val s = Ext.compute {{ {NINE} }}
        web.loadUrl(s)
    }}
}}
"""
    )
    scope = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        val s = run {{ {NINE} }}
        web.loadUrl(s)
    }}
}}
"""
    )
    direct = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        val s = {NINE}
        web.loadUrl(s)
    }}
}}
"""
    )
    assert _hit(unresolved, URL) and _hit(scope, URL) and _hit(direct, URL)
    for report in (unresolved, scope, direct):
        assert "source trace budget" in _budget(report)
        assert _state(report, URL) == "partial"


def test_scope_block_with_an_own_call_in_a_component_stays_limited() -> None:
    report = _kotlin(
        """class A : Activity() {
    private var last = ""
    private fun remember(key: String): String { last = key; return key.trim() }
    fun show(i: Intent) {
        val s = i.getStringExtra("k")?.let { remember(it) }
        android.util.Log.d("t", s ?: "")
    }
}
"""
    )
    assert _budget(report) == [], _reasons(report)


def test_nested_builder_effects_add_no_precision_cut() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val a = intent.getStringExtra("a") ?: ""
        val b = intent.getStringExtra("b") ?: ""
        val c = intent.getStringExtra("c") ?: ""
        val html = Html.node { n1 -> n1.text(a); n1.text(b); n1.text(c); n1.child(Html.node { n2 -> n2.text(a); n2.text(b); n2.text(c); n2.child(Html.node { n3 -> n3.text(a); n3.text(b); n3.text(c) }) }) }
        web.loadUrl(html)
    }
}
"""
    )
    assert _hit(report, URL)
    assert "source trace abstention" not in _reasons(report) and _budget(report) == []


def test_nested_builder_write_that_is_not_last_reaches_the_call_value() -> None:
    build = 'Markup.render({ w -> w.group({ g -> g.append(q); g.append("x") }); println(0) })'
    assert _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL)


@pytest.mark.parametrize(
    "call",
    [
        'return attach(name) { name = intent.getStringExtra("q")!! }',
        'android.util.Log.d("t", attach(name) { name = intent.getStringExtra("q")!! })',
        'val r = attach(name) { name = intent.getStringExtra("q")!! }.trim()',
        'db.execSQL(attach(name) { name = intent.getStringExtra("q")!! })',
        'attach(name) { name = intent.getStringExtra("q")!! }.let { android.util.Log.d("t", it) }',
    ],
)
def test_callback_write_reaches_no_followed_callee_in_any_position(call: str) -> None:
    report = _kotlin(
        f"""class R(private val db: SQLiteDatabase) {{
    fun attach(n: String, done: () -> Unit): String {{ db.execSQL("DELETE FROM t WHERE id = " + n); return n }}
    fun q(intent: Intent): String {{
        var name = "const"
        {call}
        return ""
    }}
}}
"""
    )
    assert not _hit(report, SQL)


def test_deferred_callback_write_to_the_assigned_name_is_kept() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        var u = "https://docs.example.test/"
        u = Ext.wrap(u) { u = intent.getStringExtra("url")!! }
        web.loadUrl(u)
    }
}
"""
    )
    assert _hit(report, URL)


def test_branch_that_always_exits_leaves_no_value() -> None:
    report = _kotlin(
        BRANCH.format(
            expression='Ext.compute { if (flag) { throw IllegalStateException("x"); intent.getStringExtra("url")!! } else { "https://h/" } }'
        )
    )
    assert not _hit(report, URL)


@pytest.mark.parametrize(
    "pick",
    [
        "pages.sortedWith(compareBy<String> { it.length }.thenBy { it.endsWith(wanted) }).first()",
        "pages.maxWith(Comparator { a, b -> if (a.endsWith(wanted)) 1 else -1 })",
    ],
)
def test_chained_comparators_are_not_the_selected_value(pick: str) -> None:
    report = _kotlin(
        f"""class W(private val web: WebView) {{
    private val pages = listOf("https://docs.example.test/a", "https://docs.example.test/b")
    fun q(intent: Intent) {{
        val wanted = intent.getStringExtra("page") ?: return
        web.loadUrl({pick})
    }}
}}
"""
    )
    assert not _hit(report, URL)


def test_closure_whose_arity_does_not_match_is_not_admitted() -> None:
    report = _kotlin(
        """class C(private val db: SQLiteDatabase) : Activity() {
    fun attach(name: String, done: (Int, Int) -> Unit) { db.execSQL("DELETE FROM t WHERE id = " + name) }
    fun q(intent: Intent) { val name: String = intent.getStringExtra("q")!!; attach(name) { a -> } }
}
"""
    )
    matching = _kotlin(
        """class C(private val db: SQLiteDatabase) : Activity() {
    fun attach(name: String, done: (Int, Int) -> Unit) { db.execSQL("DELETE FROM t WHERE id = " + name) }
    fun q(intent: Intent) { val name: String = intent.getStringExtra("q")!!; attach(name) { a, b -> } }
}
"""
    )
    assert _state(report, SQL) == "limited" and not _hit(report, SQL)
    assert _hit(matching, SQL)


@pytest.mark.parametrize(
    "statement",
    [
        'val s = when (val r = parse(intent.getStringExtra("a"))) {\n            is Res.Ok -> r.value\n            else -> "https://h/"\n        }',
        'val r = parse(intent.getStringExtra("a"))\n        val s = when (r) {\n            is Res.Ok -> r.value\n            else -> "https://h/"\n        }',
    ],
)
def test_when_subject_used_as_a_value_is_counted_once(statement: str) -> None:
    report = _kotlin(
        f"""sealed class Res {{ object Fail : Res(); data class Ok(val value: String) : Res() }}
class W(private val web: WebView) {{
    fun parse(s: String?): Res = if (s == null) Res.Fail else Res.Ok(s)
    fun q(intent: Intent) {{
        {statement}
        web.loadUrl(s)
    }}
}}
"""
    )
    assert _budget(report) == []
    assert _hit(report, URL)


SWIFT_ROUTER = """import UIKit
import WebKit
enum DeepLink {{ case product(String), search(String), open(url: URL) }}
final class Router {{
    var pending = ""
    let web = WKWebView()
    func showProduct(_ id: String) {{ pending = id }}
    func application(_ app: UIApplication, open url: URL, options: [String: Any]) {{
        let link: DeepLink = url.host == "product" ? .product(url.query ?? "") : .open(url: url)
        let home = URL(string: "https://docs.example.test/")!
        switch link {{
        {body}
        default: break
        }}
    }}
}}
"""


def test_swift_case_bindings_follow_own_handlers_and_skip_labels() -> None:
    handler = _swift(SWIFT_ROUTER.format(body="case .product(let id): showProduct(id)"))
    label = _swift(
        SWIFT_ROUTER.format(body="case let .open(url: dest): print(dest); web.load(URLRequest(url: home))")
    )
    flow = _swift(SWIFT_ROUTER.format(body="case let .open(url: dest): web.load(URLRequest(url: dest))"))
    assert _budget(handler) == []
    assert not _hit(label, URL)
    assert _hit(flow, URL)


def test_swift_subscript_write_into_a_supplied_object_reaches_the_call_value() -> None:
    report = _swift(
        """import UIKit
import WebKit
final class LinkHandler {
    let browser = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {
        let html = Doc.make { d in d["term"] = incoming.absoluteString; print("built") }
        browser.loadHTMLString(html, baseURL: nil)
    }
}
"""
    )
    assert _hit(report, URL)


@pytest.mark.parametrize(
    "build",
    [
        'Markup.render { b -> Metrics.track(b.length, q); b.append("<p>static</p>"); Unit }',
        'Markup.render { b -> if (b.contains(q)) println("dup"); b.append("<p>static</p>"); Unit }',
        'Markup.render { b -> if (b.contentEquals(q)) println("dup"); b.append("<p>static</p>"); Unit }',
    ],
)
def test_reading_a_supplied_object_is_no_write_into_it(build: str) -> None:
    assert not _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL)


OWN_HELPER = """class R(private val db: SQLiteDatabase){supertype} {{
    {helpers}
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val s = {build}
        db.execSQL(s)
    }}
}}
"""


@pytest.mark.parametrize(
    "build",
    [
        'buildString { log(q); append("SELECT 1") }',
        'buildList { log(q); add("SELECT 1") }.joinToString()',
        'sequence { log(q); yield("SELECT 1") }.joinToString()',
        'Query.buildQuery { log(q); put("SELECT 1") }',
    ],
)
def test_own_helper_in_a_known_builder_writes_nothing_into_it(build: str) -> None:
    report = _kotlin(OWN_HELPER.format(supertype="", helpers="fun log(s: String) {}", build=build))
    assert not _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "helpers, build",
    [
        ("fun append(s: String) {}", 'buildString { append("SELECT "); append(q) }'),
        ("fun add(s: String) {}", 'buildList { add("SELECT "); add(q) }.joinToString()'),
        ("fun put(s: String) {}", "Query.buildQuery { put(q) }"),
        ("", "buildString { appendSql(q) }"),
    ],
)
def test_builder_members_are_writes_even_where_a_project_function_has_the_name(
    helpers: str, build: str
) -> None:
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL)


def test_inherited_project_helper_in_a_builder_writes_nothing_into_it() -> None:
    base = KOTLIN + "open class BaseRepo {\n    fun log(s: String) {}\n}\n"
    sub = KOTLIN + OWN_HELPER.format(
        supertype=" : BaseRepo()", helpers="", build='buildString { log(q); append("SELECT 1") }'
    )
    report = analyze_sources([("app/BaseRepo.kt", base), ("app/R.kt", sub)])
    assert not _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "members, call, expected",
    [
        ("companion object { fun log(s: String) {} }", 'log(q); "https://docs.example.test/"', False),
        (
            "companion object { fun log(s: String, level: Int = 0) {} }",
            'log(q); "https://docs.example.test/"',
            False,
        ),
        ("companion object { fun text(a: String, b: String) {} }", 'text(q); "x"', True),
        ("fun Page.text(s: String) {}", 'text(q); "x"', True),
    ],
)
def test_enclosing_class_and_companion_functions_are_no_dsl_writes(
    members: str, call: str, expected: bool
) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    {members}
    fun f(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(Ext.page {{ {call} }})
    }}
}}
"""
    )
    assert _hit(report, URL) is expected, report["findings"]


def test_unrelated_class_member_does_not_hide_a_dsl_write() -> None:
    report = _kotlin(
        """class Other { fun text(s: String) { } }
class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val html = div { text(q); br() }
        web.loadUrl(html)
    }
}
"""
    )
    assert _hit(report, URL)


@pytest.mark.parametrize(
    "assign",
    [
        'u = "https://docs.example.test/home".also { u = intent.getStringExtra("url")!! }',
        'u = listOf("https://docs.example.test/a").map { u = intent.getStringExtra("url")!!; it }.first()',
        'u = Ext.wrap("https://docs.example.test/") { u = "https://docs.example.test/x" }',
    ],
)
def test_assignment_keeps_only_what_a_callback_may_write_after_it(assign: str) -> None:
    start = 'intent.getStringExtra("url")!!' if "Ext.wrap" in assign else '"https://docs.example.test/"'
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        var u = {start}
        {assign}
        web.loadUrl(u)
    }}
}}
"""
    )
    assert not _hit(report, URL), report["findings"]


@pytest.mark.parametrize(
    "build",
    [
        "Markup.render { b -> Ext.fill(b!!, q); Unit }",
        "Markup.render { b -> b!!.append(q); Unit }",
    ],
)
def test_force_unwrapped_supplied_object_is_the_object(build: str) -> None:
    assert _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL)


@pytest.mark.parametrize(
    "use",
    [
        'val link = when (val r = parse("https://docs.example.test/")) { is Link.Web -> r.url; else -> "https://h/" }\n'
        "        web.loadUrl(link)",
        'web.loadUrl(when (val r = parse("https://docs.example.test/")) { is Link.Web -> r.url; else -> "https://h/" })',
        'show(when (val r = "https://docs.example.test/") { "" -> "https://h/"; else -> r })',
        'web.loadUrl("${when (val r = "https://docs.example.test/") { "" -> "https://h/"; else -> r }}")',
        'web.loadUrl(null ?: when (val r = "https://docs.example.test/") { "" -> "https://h/"; else -> r })',
    ],
)
def test_when_value_outside_a_closure_reads_its_own_binding(use: str) -> None:
    report = _kotlin(
        f"""sealed class Link {{ data class Web(val url: String) : Link(); object None : Link() }}
class W(private val web: WebView) {{
    fun parse(s: String): Link = Link.Web(s)
    fun show(u: String) {{ web.loadUrl(u) }}
    fun q(intent: Intent) {{
        val r = intent.getStringExtra("x")!!
        {use}
    }}
}}
"""
    )
    assert not _hit(report, URL), report["findings"]


def test_when_value_is_its_entries_and_not_the_subject_again() -> None:
    three = " + ".join(f'intent.getStringExtra("{key}")' for key in "abc")
    report = _kotlin(
        f"""class W(private val web: WebView) {{
    fun q(intent: Intent) {{
        val s = when (val r = {three}) {{ "" -> r; "x" -> r + "/"; else -> "https://h/" }}
        web.loadUrl(s)
    }}
}}
"""
    )
    assert _hit(report, URL)
    assert _state(report, URL) == "checked", _reasons(report)


def test_nested_builder_write_is_not_carried_to_another_visit_of_the_same_body() -> None:
    report = _kotlin(
        """class P(private val web: WebView) {
    fun page(t: String): String = Html.page { b -> b.section { s -> s.heading(t) } }
    fun open(intent: Intent) {
        Log.d("p", page(intent.getStringExtra("t")!!))
    }
    fun showAbout() {
        web.loadData(page("About"), "text/html", "utf-8")
    }
}
"""
    )
    assert not any(
        finding["rule_id"].startswith("AST-WEBVIEW") and finding["evidence"][0]["function"] == "showAbout"
        for finding in report["findings"]
    ), report["findings"]


@pytest.mark.parametrize(
    "helpers, build",
    [
        (
            "fun isValid(s: String) = s.isNotEmpty()",
            'buildString { if (isValid(q)) append("SELECT 1") else append("SELECT 2") }',
        ),
        ("", 'buildString { if (q.isEmpty()) throw IllegalStateException("bad " + q); append("SELECT 1") }'),
        ("", 'Ext.make { android.util.Log.e("t", "m", Exception(q)); "SELECT 1" }'),
        ("", 'Ext.make { val f = java.io.File("/data", q); android.util.Log.d("t", f.path); "SELECT 1" }'),
        ('fun mask(s: String) = "SELECT 1"', "buildString { append(mask(q)) }"),
        ("", 'runCatching { record(q); "SELECT 1" }.getOrDefault("SELECT 2")'),
    ],
)
def test_conditions_arguments_constructors_and_runners_write_into_no_receiver(
    helpers: str, build: str
) -> None:
    report = _kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build))
    assert not _hit(report, SQL), report["findings"]


def test_framework_member_in_a_coroutine_block_writes_into_nothing() -> None:
    report = _kotlin(
        """class A : Activity() {
    private lateinit var web: WebView
    suspend fun open(name: String) {
        val page = withContext(Dispatchers.IO) { deleteFile(name); "https://docs.example.test/cleared" }
        web.loadUrl(page)
    }
}
"""
    )
    assert not _hit(report, URL), report["findings"]


@pytest.mark.parametrize(
    "build",
    [
        'buildString { append("SELECT ").append(q); append("x") }',
        'buildString({ append("SELECT ").append(q); append("x") })',
        'buildString { this.append(q); append("x") }',
        'Markup.render { m -> m.getOrPut("q") { q }; Unit }',
        "Markup.render { b -> b.section { q }; Unit }",
        'Markup.render { b -> listOf(q).joinTo(b, ","); Unit }',
        "Markup.render { b -> Fill.paragraph(b.body, q); Unit }",
    ],
)
def test_chained_stored_and_handed_writes_reach_the_call_value(build: str) -> None:
    assert _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL)


@pytest.mark.parametrize(
    "build",
    [
        'Markup.render { b -> if (Text.same(b.text, q)) println(0); b.append("x"); Unit }',
        'Markup.render { sb -> sb.onClick { audit.log(q) }; sb.append("safe") }',
        'Markup.render { sb -> sb.onClick { record(q) }; sb.append("safe") }',
        'Markup.render { sb -> sb.setOnClickListener { record(q) }; sb.append("safe") }',
    ],
)
def test_conditions_and_callbacks_on_a_supplied_object_are_no_writes(build: str) -> None:
    assert not _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL)


def test_unimported_top_level_function_does_not_hide_a_dsl_write() -> None:
    other = """package com.example.other
fun text(s: String) {}
"""
    report = analyze_sources(
        [
            ("app/Other.kt", other),
            (
                "app/R.kt",
                KOTLIN
                + """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(div { text(q); br() })
    }
}
""",
            ),
        ]
    )
    assert _hit(report, URL)


def test_own_function_in_a_dsl_lambda_is_no_write() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun log(s: String) {}
    fun f(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(Ext.page { log(q); "https://docs.example.test/" })
    }
}
"""
    )
    assert not _hit(report, URL), report["findings"]


def test_unbraced_inner_branch_reads_names_of_its_enclosing_branch() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val s = run { try { val raw = intent.getStringExtra("u")!!; if (raw.isBlank()) "https://h/" else raw } catch (e: Exception) { "https://h/" } }
        web.loadUrl(s)
    }
}
"""
    )
    assert _hit(report, URL)


SWIFT_PAGE = """import UIKit
import WebKit
final class Page {{
    var homepage = "https://docs.example.test/"
    var nickname = ""
}}
final class Viewer {{
    let viewer = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {{
        let page = Page()
        page.nickname = incoming.absoluteString
        let maybe: Page? = page
        let safe = URL(string: "https://docs.example.test/")!
        {body}
    }}
}}
"""


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            "switch maybe { case let x?: viewer.load(URLRequest(url: URL(string: x.homepage)!)); default: break }",
            False,
        ),
        (
            "switch maybe { case .some(let x): viewer.load(URLRequest(url: URL(string: x.homepage)!)); default: break }",
            False,
        ),
        (
            "switch maybe { case let x?: viewer.load(URLRequest(url: URL(string: x.nickname)!)); default: break }",
            True,
        ),
        ("switch (safe, incoming) { case (let a, _): viewer.load(URLRequest(url: a)) }", False),
        ("switch (safe, incoming) { case let (a, b): print(b); viewer.load(URLRequest(url: a)) }", False),
        ("switch (safe, incoming) { case (_, let b): viewer.load(URLRequest(url: b)) }", True),
    ],
)
def test_swift_case_patterns_bind_the_value_they_match(body: str, expected: bool) -> None:
    assert _hit(_swift(SWIFT_PAGE.format(body=body)), URL) is expected


@pytest.mark.parametrize(
    "assign",
    [
        'u = run { u = intent.getStringExtra("url")!!; "https://docs.example.test/x" }',
        'u = StringBuilder().apply { u = intent.getStringExtra("url")!! }.toString()',
        'u = { u = intent.getStringExtra("url")!!; "https://docs.example.test/x" }()',
    ],
)
def test_closures_that_finish_before_the_assignment_keep_no_write(assign: str) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        var u = "https://docs.example.test/"
        {assign}
        web.loadUrl(u)
    }}
}}
"""
    )
    assert not _hit(report, URL), report["findings"]


def test_long_branch_chain_in_a_closure_stays_fast() -> None:
    import time

    def elapsed(branches: int) -> float:
        chain = " else ".join(
            f'if (k == "{i}") {{ "https://docs.example.test/{i}" }}' for i in range(branches)
        )
        source = f"""class M(private val web: WebView) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val k = intent.getStringExtra("k") ?: ""
        web.loadUrl(run {{ {chain} else {{ q }} }})
    }}
}}
"""
        started = time.process_time()
        assert _hit(_kotlin(source), URL)
        return time.process_time() - started

    # Each node's result and statement position is decided once. The time still grows about
    # n^1.6 here, from tree-sitter's parent walk on deep nesting (about 10 times for 4 times
    # the branches; the uncached walk grew about 50 times), so the time bound is loose; the
    # Python and C calls the analysis makes are counted exactly and grow linearly (3.8
    # times; uncached 6.6 times). The process's own CPU time is compared, the two sizes in
    # turn and each by its best run, so other processes' load does not decide the ratio.
    small = large = float("inf")
    for _ in range(3):
        small = min(small, elapsed(200))
        large = min(large, elapsed(800))
    assert large < 20 * max(small, 0.01)

    def calls(branches: int) -> int:
        chain = " else ".join(
            f'if (k == "{i}") {{ "https://docs.example.test/{i}" }}' for i in range(branches)
        )
        source = f"""class M(private val web: WebView) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val k = intent.getStringExtra("k") ?: ""
        web.loadUrl(run {{ {chain} else {{ q }} }})
    }}
}}
"""
        count = 0

        def profile(frame, event, arg) -> None:
            nonlocal count
            if event in {"call", "c_call"}:
                count += 1

        sys.setprofile(profile)
        try:
            _kotlin(source)
        finally:
            sys.setprofile(None)
        return count

    assert calls(800) < 5 * calls(200)


@pytest.mark.parametrize(
    "setup, load, expected",
    [
        (
            'let link: DeepLink = .open(url: incoming)\n        let url = URL(string: "https://docs.example.test/help")!',
            "web.load(URLRequest(url: url))",
            False,
        ),
        (
            'let link: DeepLink = .open(url: URL(string: "https://docs.example.test/")!)\n        let url = incoming',
            "web.load(URLRequest(url: url))",
            True,
        ),
    ],
)
def test_swift_associated_value_label_does_not_shadow_an_outer_name(
    setup: str, load: str, expected: bool
) -> None:
    report = _swift(
        f"""import UIKit
import WebKit
enum DeepLink {{ case open(url: URL), home }}
final class Router {{
    let web = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {{
        {setup}
        switch link {{
        case let .open(url: dest): print(dest); {load}
        default: break
        }}
    }}
}}
"""
    )
    assert _hit(report, URL) is expected


@pytest.mark.parametrize(
    "build",
    [
        "flow { emit(q) }.toString()",
        'sequence { yield(q); yield("x") }.joinToString()',
    ],
)
def test_lazy_builder_members_write_even_where_the_class_has_the_name(build: str) -> None:
    report = _kotlin(
        OWN_HELPER.format(
            supertype="", helpers="fun emit(s: String) {}\n    fun yield(s: String) {}", build=build
        )
    )
    assert _hit(report, SQL)


def test_java_method_of_the_same_name_does_not_hide_a_kotlin_dsl_write() -> None:
    java = """package com.example.app;
class Chip { void parameter(String k, String v) { } }
"""
    kotlin = (
        KOTLIN
        + """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(Ext.request { parameter("q", q); header("a", "b") })
    }
}
"""
    )
    report = analyze_sources([("app/R.kt", kotlin), ("app/src/main/java/com/example/app/Chip.java", java)])
    assert _hit(report, URL)


def test_function_typed_callback_keeps_a_distinct_source_budget_cut() -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    fun open(intent: Intent, render: (() -> String) -> String) {{
        val s = render {{ {NINE} }}
        web.loadUrl(s)
    }}
}}
"""
    )
    assert _hit(report, URL)
    assert "source trace budget" in _budget(report)
    assert _state(report, URL) == "partial"


def test_expression_body_callee_evaluates_its_calls_once() -> None:
    def evaluations(body: str) -> int:
        report = _kotlin(
            f"""class R(private val db: SQLiteDatabase) {{
    fun attach(n: String, done: () -> Unit): String {{ db.execSQL("DELETE FROM t WHERE id = " + n); return n }}
    fun page(intent: Intent): String {body}
    fun open(intent: Intent) {{ android.util.Log.d("t", page(intent)) }}
}}
"""
        )
        return report["metadata"]["native_flow"]["evaluations"]

    callback = 'attach("const") { android.util.Log.d("t", intent.getStringExtra("q")!!) }'
    assert evaluations("= " + callback) == evaluations("{ return " + callback + " }")


@pytest.mark.parametrize(
    "build",
    [
        'buildString { if (libCheck(q)) append("SELECT 1") else append("SELECT 2") }',
        'Ext.make { val f = libOpen(q); android.util.Log.d("t", f.toString()); "SELECT 1" }',
        'Ext.make { File(q).delete(); "SELECT 1" }',
        'Ext.make { !libCheck(q); "SELECT 1" }',
    ],
)
def test_library_calls_in_conditions_initializers_and_constructor_chains_write_nothing(build: str) -> None:
    assert not _hit(_kotlin(OWN_HELPER.format(supertype="", helpers="", build=build)), SQL)


def test_inherited_java_helper_in_a_builder_writes_nothing_into_it() -> None:
    java = """package com.example.app;
public class BaseRepo { public void log(String s) { } }
"""
    kotlin = KOTLIN + OWN_HELPER.format(
        supertype=" : BaseRepo()", helpers="", build='buildString { log(q); append("SELECT 1") }'
    )
    report = analyze_sources(
        [("app/src/main/java/com/example/app/BaseRepo.java", java), ("app/R.kt", kotlin)]
    )
    assert not _hit(report, SQL), report["findings"]


SWIFT_SWITCH_VALUE = """import UIKit
import WebKit
enum Route {{ case external(link: URL), home }}
final class Viewer {{
    let viewer = WKWebView()
    func application(_ app: UIApplication, open url: URL, options: [String: Any]) {{
        {body}
    }}
}}
"""


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            "let target = url\n        print(target)\n"
            '        let route: Route = .external(link: URL(string: "https://docs.example.test/a")!)\n'
            "        let page: URL = switch route {\n"
            "        case let .external(link: target): target\n"
            '        default: URL(string: "https://docs.example.test/")!\n'
            "        }\n        viewer.load(URLRequest(url: page))",
            False,
        ),
        (
            'let target = URL(string: "https://docs.example.test/")!\n        print(target)\n'
            "        let route: Route = .external(link: url)\n"
            "        let page: URL = switch route {\n"
            '        case let .external(link: target): target.appendingPathComponent("x")\n'
            '        default: URL(string: "https://docs.example.test/")!\n'
            "        }\n        viewer.load(URLRequest(url: page))",
            True,
        ),
    ],
)
def test_swift_switch_expression_value_reads_its_case_bindings(body: str, expected: bool) -> None:
    assert _hit(_swift(SWIFT_SWITCH_VALUE.format(body=body)), URL) is expected


@pytest.mark.parametrize(
    "build, expected",
    [
        (
            'Markup.render { b -> b.onClick { if (q.isEmpty()) log(q) else track(q) }; b.append("x"); Unit }',
            False,
        ),
        ('Markup.render { b -> b.section { if (q.isEmpty()) "x" else q }; Unit }', True),
        ("buildString { appendFilter(this, q) }", True),
        (
            'buildString { val other = StringBuilder(); other.apply { this.append(q) }; append("SELECT 1") }',
            False,
        ),
        ("buildString { apply { this.append(q) } }", True),
    ],
)
def test_callbacks_content_and_this_in_builder_lambdas(build: str, expected: bool) -> None:
    helpers = "private fun appendFilter(sb: StringBuilder, f: String) { sb.append(f) }"
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL) is expected


def test_inherited_helper_with_a_defaulted_parameter_writes_nothing() -> None:
    base = KOTLIN + 'open class BaseRepo {\n    fun log(msg: String, tag: String = "T") {}\n}\n'
    sub = KOTLIN + OWN_HELPER.format(
        supertype=" : BaseRepo()", helpers="", build='buildString { log(q); append("SELECT 1") }'
    )
    report = analyze_sources([("app/BaseRepo.kt", base), ("app/R.kt", sub)])
    assert not _hit(report, SQL), report["findings"]


SWIFT_QUERY = """import UIKit
import WebKit
final class V {{
    let web = WKWebView()
    func application(_ app: UIApplication, open url: URL, options: [String: Any]) {{
        let query = url.absoluteString
        {body}
    }}
}}
"""


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            "let html = Page.render { b in b.onTap { [weak self] in self?.track(query) }; "
            'b.add("<p>x</p>"); return b.html }\n        web.loadHTMLString(html, baseURL: nil)',
            False,
        ),
        (
            'let target: URL = switch query { case "help": URL(string: "https://docs.example.test/help")!; '
            'default: URL(string: "https://docs.example.test/")! }\n        web.load(URLRequest(url: target))',
            False,
        ),
        (
            'let target: URL = switch query { case "": URL(string: "https://docs.example.test/")!; default: url }\n'
            "        web.load(URLRequest(url: target))",
            True,
        ),
        (
            'let page = Markup.render({ b in try Fill.into(b, query); b.add("x") })\n'
            "        web.loadHTMLString(page, baseURL: nil)",
            True,
        ),
        (
            'let page = Markup.render({ b in _ = Fill.into(b, query); b.add("x") })\n'
            "        web.loadHTMLString(page, baseURL: nil)",
            True,
        ),
    ],
)
def test_swift_callbacks_switch_values_and_wrapped_helper_statements(body: str, expected: bool) -> None:
    assert _hit(_swift(SWIFT_QUERY.format(body=body)), URL) is expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (
            'when (val q = intent.getStringExtra("x")!!) { q.trim() -> "https://docs.example.test/a"; else -> HOME }',
            False,
        ),
        (
            'when (val q = intent.getStringExtra("x")!!) { "" -> { android.util.Log.d("t", q); HOME }; else -> HOME }',
            False,
        ),
        ('when (val q = intent.getStringExtra("x")!!) { "" -> HOME; else -> q }', True),
    ],
)
def test_when_value_is_its_entries_last_values_not_their_conditions(value: str, expected: bool) -> None:
    report = _kotlin(
        f"""const val HOME = "https://docs.example.test/"
class W(private val web: WebView) {{
    fun q(intent: Intent) {{
        val s = {value}
        web.loadUrl(s)
    }}
}}
"""
    )
    assert _hit(report, URL) is expected


@pytest.mark.parametrize(
    "case, expected",
    [
        ('case let x where x.count > 3: "https://docs.example.test/a"', False),
        ("case let x where x.count > 3: x", True),
    ],
)
def test_swift_case_value_is_its_last_statement_not_its_where_clause(case: str, expected: bool) -> None:
    body = (
        f'let target: String = switch query {{ {case}; default: "https://docs.example.test/b" }}\n'
        "        web.load(URLRequest(url: URL(string: target)!))"
    )
    assert _hit(_swift(SWIFT_QUERY.format(body=body)), URL) is expected


@pytest.mark.parametrize(
    "body",
    [
        'append("SELECT \'"); if (flag) append(q); append("\'")',
        'append("SELECT \'"); if (flag) append(q) else append("x"); append("\'")',
        'append("SELECT \'"); for (i in 0..1) append(q); append("\'")',
        'append("SELECT \'"); while (flag) append(q); append("\'")',
        'append("SELECT \'"); when (q.length) { 0 -> append("x"); else -> append(q) }; append("\'")',
    ],
)
def test_unbraced_bodies_in_a_builder_are_statements(body: str) -> None:
    report = _kotlin(
        f"""class R(private val db: SQLiteDatabase) {{
    var flag = true
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        db.execSQL(buildString {{ {body} }})
    }}
}}
"""
    )
    assert _hit(report, SQL)


@pytest.mark.parametrize(
    "build",
    [
        'Markup.render { b -> if (q.isNotEmpty()) Fill.paragraph(b, q); b.append("x"); Unit }',
        'Markup.render { b -> if (q.isNotEmpty()) b.group { g -> g.append(q) }; b.append("x"); Unit }',
    ],
)
def test_unbraced_helper_and_nested_builder_writes_reach_the_call_value(build: str) -> None:
    assert _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL)


def test_unary_plus_of_a_call_writes_its_result() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(div { +format(q); br() })
    }
}
"""
    )
    assert _hit(report, URL)


def test_aliased_project_function_is_no_dsl_write() -> None:
    util = """package com.example.util
fun log(s: String) {}
"""
    kotlin = (
        "package com.example.app\nimport android.content.Intent\nimport android.webkit.WebView\n"
        "import com.example.util.log as audit\n"
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(Ext.page { audit(q); "https://docs.example.test/" })
    }
}
"""
    )
    report = analyze_sources([("app/Util.kt", util), ("app/R.kt", kotlin)])
    assert not _hit(report, URL), report["findings"]


@pytest.mark.parametrize("build", ['buildString { note(q); append("SELECT 1") }'])
def test_helper_of_a_project_base_with_a_framework_base_writes_nothing(build: str) -> None:
    base = (
        KOTLIN
        + "import androidx.lifecycle.ViewModel\nopen class BaseVm : ViewModel() {\n    fun note(s: String) {}\n}\n"
    )
    sub = KOTLIN + OWN_HELPER.format(supertype=" : BaseVm()", helpers="", build=build)
    report = analyze_sources([("app/BaseVm.kt", base), ("app/R.kt", sub)])
    assert not _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "assign",
    [
        'u = Ext.fetch { if (u.isEmpty()) u = "https://docs.example.test/help" }',
        'u = Ext.fetch { Ext.inner { u = "https://docs.example.test/help" } }',
    ],
)
def test_conditional_callback_write_drops_the_value_from_before(assign: str) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        var u = intent.getStringExtra("u")!!
        println(u)
        {assign}
        web.loadUrl(u)
    }}
}}
"""
    )
    assert not _hit(report, URL), report["findings"]


def test_sam_constructor_lambda_has_no_data_receiver() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val page = java.util.concurrent.Callable { record(q); "https://docs.example.test/" }.call()
        web.loadUrl(page)
    }
}
"""
    )
    assert not _hit(report, URL), report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            'val key: String? = "0123456789abcdef"\n        println(SecretKeySpec(key!!.toByteArray(), "AES"))',
            True,
        ),
        (
            "val raw: ByteArray? = ByteArray(16)\n        java.security.SecureRandom().nextBytes(raw!!)\n"
            '        println(SecretKeySpec(raw, "AES"))',
            False,
        ),
    ],
)
def test_force_unwrap_is_the_value_for_key_material(body: str, expected: bool) -> None:
    report = analyze_sources(
        [
            (
                "app/K.kt",
                "package com.example.app\nimport javax.crypto.spec.SecretKeySpec\n"
                f"class K {{\n    fun make() {{\n        {body}\n    }}\n}}\n",
            )
        ]
    )
    assert _hit(report, "AST-CRYPTO-HARDCODED-KEY") is expected


@pytest.mark.parametrize(
    "helpers, build, expected",
    [
        ("", "Markup.render { b -> b.section { q.trim() }; Unit }", True),
        ("", "Ext.page { title { q }; footer() }", True),
        ("", 'buildString { listOf(q).joinTo(this); append("x") }', True),
        (
            "fun StringBuilder.appendSql(s: String) { append(s) }",
            'buildString { appendSql(q); append("x") }',
            True,
        ),
        ("", 'Sql.execute { where("name = \'" + q + "\'"); limit(10) }', True),
        ("", "Ext.flow { trySendBlocking(q); close() }.toString()", True),
        ("", 'buildString { checkArgument(q.length < 64, "long $q"); append("SELECT 1") }', False),
        ("", 'buildList { trace("open", q); add("SELECT 1") }.joinToString()', False),
        ("fun R.note(s: String) {}", 'Ext.page { note(q); "SELECT 1" }', False),
        (
            "companion object { fun log(vararg parts: String) {} }",
            'Ext.page { log(q, "x"); "SELECT 1" }',
            False,
        ),
        ("", 'buildString { val n: String? = null; n ?: append(q); append("x") }', True),
    ],
)
def test_builder_and_dsl_write_rules(helpers: str, build: str, expected: bool) -> None:
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL) is expected


@pytest.mark.parametrize(
    "build",
    [
        'buildString { logcat { "query for $q" }; append("SELECT 1") }',
        'Ext.page { logcat { "query for $q" }; "SELECT 1" }',
    ],
)
def test_imported_lazy_message_logger_is_no_content(build: str) -> None:
    kotlin = KOTLIN + "import logcat.logcat\n" + OWN_HELPER.format(supertype="", helpers="", build=build)
    assert not _hit(analyze_sources([("app/R.kt", kotlin)]), SQL)


@pytest.mark.parametrize(
    "build, expected",
    [
        ('Markup.render { b -> Analytics.track(b.id, q); b.append("x"); Unit }', False),
        ("Markup.render { b -> Fill.into(if (q.isEmpty()) b.body else b.head, q); Unit }", True),
    ],
)
def test_values_and_parts_of_a_supplied_object_handed_to_helpers(build: str, expected: bool) -> None:
    assert _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL) is expected


def test_java_getter_with_a_literal_argument_hands_a_part() -> None:
    report = _java(
        """class C {
  SQLiteDatabase db;
  void q(Intent intent) {
    String q = intent.getStringExtra("q");
    String page = Markup.render(m -> { Fill.into(m.getChild("body"), q); });
    db.execSQL("SELECT " + page);
  }
}
"""
    )
    assert _hit(report, SQL)


@pytest.mark.parametrize(
    "files",
    [
        [
            (
                "app/BaseRepo.kt",
                KOTLIN + "open class BaseRepo {\n    fun log(s: String) {}\n}\n",
            ),
            (
                "app/R.kt",
                KOTLIN
                + OWN_HELPER.format(
                    supertype=" : BaseRepo(), Runnable",
                    helpers="override fun run() {}",
                    build='buildString { log(q); append("SELECT 1") }',
                ),
            ),
        ],
        [
            (
                "app/src/main/java/com/example/base/BaseRepo.java",
                "package com.example.base;\npublic class BaseRepo { public void log(String s) { } }\n",
            ),
            (
                "app/R.kt",
                KOTLIN
                + "import com.example.base.*\n"
                + OWN_HELPER.format(
                    supertype=" : BaseRepo()", helpers="", build='buildString { log(q); append("SELECT 1") }'
                ),
            ),
        ],
    ],
)
def test_inherited_helpers_through_interfaces_and_star_imports_write_nothing(files: list) -> None:
    report = analyze_sources(files)
    assert not _hit(report, SQL), report["findings"]


SWIFT_TUPLES = """import UIKit
import WebKit
enum Route {{ case external(URL), home }}
final class V {{
    let web = WKWebView()
    func application(_ app: UIApplication, open url: URL, options: [String: Any]) {{
        let safe = URL(string: "https://docs.example.test/")!
        let route: Route = .external(safe)
        {body}
    }}
}}
"""


@pytest.mark.parametrize(
    "body",
    [
        "switch (route, url) { case (.external(let a), _): web.load(URLRequest(url: a)); default: break }",
        "switch (home: safe, link: url) { case (let a, _): web.load(URLRequest(url: a)) }",
        "switch (link: url, home: safe) { case (_, let b): web.load(URLRequest(url: b)) }",
        "switch ((safe, url), 1) { case ((let a, _), _): web.load(URLRequest(url: a)) }",
    ],
)
def test_swift_nested_and_labeled_tuple_patterns_bind_their_element(body: str) -> None:
    assert not _hit(_swift(SWIFT_TUPLES.format(body=body)), URL)


@pytest.mark.parametrize(
    "files, base",
    [
        (
            [
                (
                    "app/BaseVm.kt",
                    KOTLIN
                    + "import androidx.lifecycle.ViewModel\nopen class BaseVm : ViewModel() { fun note(s: String) {} }\n",
                ),
                (
                    "app/R.kt",
                    KOTLIN
                    + 'class R : BaseVm() {\n    fun q() { println(Ext.page { note("x"); "y" }) }\n}\n',
                ),
            ],
            "com.example.app.BaseVm",
        ),
        (
            [
                ("app/BaseRepo.kt", KOTLIN + "open class BaseRepo { fun note(s: String) {} }\n"),
                (
                    "app/R.kt",
                    KOTLIN
                    + "class R : BaseRepo(), Runnable {\n    override fun run() {}\n"
                    + '    fun q() { println(Ext.page { note("x"); "y" }) }\n}\n',
                ),
            ],
            "com.example.app.BaseRepo",
        ),
        (
            [
                (
                    "app/src/main/java/com/example/base/BaseRepo.java",
                    "package com.example.base;\npublic class BaseRepo { public void note(String s) { } }\n",
                ),
                (
                    "app/R.kt",
                    KOTLIN
                    + "import com.example.base.*\nclass R : BaseRepo() {\n"
                    + '    fun q() { println(Ext.page { note("x"); "y" }) }\n}\n',
                ),
            ],
            "com.example.base.BaseRepo",
        ),
    ],
)
def test_project_ancestry_reaches_bases_past_framework_parents_interfaces_and_star_imports(
    files: list, base: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mobile_audit import native_flow

    seen: dict[str, set[str]] = {}
    original = native_flow.NativeFlow.project_ancestry

    def spy(self, owner: str) -> set[str]:
        result = original(self, owner)
        seen[owner] = set(result)
        return result

    monkeypatch.setattr(native_flow.NativeFlow, "project_ancestry", spy)
    analyze_sources(files)
    assert base in seen.get("com.example.app.R", set()), seen


@pytest.mark.parametrize(
    "build, expected",
    [
        ('with(Ext.binding) { buildString { listOf(q).joinTo(this); append(" LIMIT 1") } }', True),
        ('Ext.binding.run { buildString { this.append(q); append(";") } }', True),
        ('Markup.render { b -> b.button("Go") { analytics.track(q) }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.button("Go") { Analytics.track(q) }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.section { String.format("%s", q) }; Unit }', True),
        ('Ext.page { p { +String.format("%s", q) }; footer() }', True),
        ("Ext.page { this.title { q }; footer() }", True),
        ('repo.flow { param("q", q) }.toString()', True),
    ],
)
def test_outer_this_callbacks_object_calls_and_project_flows(build: str, expected: bool) -> None:
    helpers = "private val analytics = Ext.analytics\n    private val repo = Ext.repo"
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL) is expected


def test_factory_chain_runner_and_qualified_sam_constructor_have_no_data_receiver() -> None:
    report = _kotlin(
        """import java.util.concurrent.Executors
class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val page = Executors.newSingleThreadExecutor()
            .submit<String> { record(q); "https://docs.example.test/" }.get()
        web.loadUrl(page)
        val listener = android.view.View.OnClickListener { record(q) }
        println(listener)
    }
}
"""
    )
    assert not _hit(report, URL), report["findings"]


def test_swift_ternary_part_handed_to_a_helper_writes_into_the_object() -> None:
    body = (
        'let page = Markup.render({ b in Fill.into(query.isEmpty ? b.body : b.head, query); b.add("x") })\n'
        "        web.loadHTMLString(page, baseURL: nil)"
    )
    assert _hit(_swift(SWIFT_QUERY.format(body=body)), URL)


@pytest.mark.parametrize(
    "assign",
    [
        "val requested = u\n        u = Ext.refresh { u = requested }",
        "u = Ext.refresh { val requested = u; u = requested }",
        "u = Ext.refresh { u = u }",
    ],
)
def test_callback_that_writes_back_the_value_from_before_keeps_it(assign: str) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        var u = intent.getStringExtra("url")!!
        {assign}
        web.loadUrl(u)
    }}
}}
"""
    )
    assert _hit(report, URL)


@pytest.mark.parametrize("call", ["analytics.track(q)", "presenter.open(q)", 'android.util.Log.d("t", q)'])
def test_side_effect_call_on_a_field_or_object_is_no_content(call: str) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    private val analytics = Ext.analytics
    private val presenter = Ext.presenter
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val page = Markup.render {{ b -> b.section {{ {call} }}; b.append("https://docs.example.test/"); Unit }}
        web.loadUrl(page)
    }}
}}
"""
    )
    assert not _hit(report, URL), report["findings"]


WHEN_VALUE = """class R(private val web: WebView) {{
    fun q(intent: Intent, mode: Int) {{
        val q = intent.getStringExtra("q") ?: ""
        {body}
    }}
}}
"""
HOME = '"https://docs.example.test/"'


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            f'val target = when (val r = mode) {{ 0 -> {HOME}; else -> {{ val v = q.lowercase(); "https://x.test/$v" }} }}'
            "\n        web.loadUrl(target)",
            True,
        ),
        (f"web.loadUrl(when (val r = mode) {{ 0 -> {HOME}; else -> {{ val v = q.lowercase(); v }} }})", True),
        (
            f'val target = when (val r = Result.success(q)) {{ null -> {HOME}; else -> {{ val v = r.getOrNull(); "https://$v" }} }}'
            "\n        web.loadUrl(target)",
            True,
        ),
        (
            f"val target = when (val r = mode) {{ 0 -> {HOME}; else -> {{ if (r > 1) {{ val v = q.trim(); v }} else {HOME} }} }}"
            "\n        web.loadUrl(target)",
            True,
        ),
        (
            f"val target = when (val r = mode) {{ 0 -> {HOME}; else -> {{ val v = q.lowercase(); println(v); {HOME} }} }}"
            "\n        web.loadUrl(target)",
            False,
        ),
    ],
)
def test_binding_when_braced_entry_is_read_with_its_own_locals(body: str, expected: bool) -> None:
    assert _hit(_kotlin(WHEN_VALUE.format(body=body)), URL) is expected


DSL_PAGE = """class R(private val web: WebView) {{
    fun q(intent: Intent, admin: Boolean, sort: Int, items: List<String>) {{
        val q = intent.getStringExtra("q") ?: ""
        val page = Ext.page {{
            {stmt}
            "https://docs.example.test/"
        }}
        web.loadUrl(page)
    }}
}}
"""


@pytest.mark.parametrize(
    "stmt, expected",
    [
        ('val label = if (admin) describe(q) else "Notes"\n            println(label.length)', False),
        (
            'val cls = when (sort) { 1 -> classesFor(q); else -> "plain" }\n            println(cls.length)',
            False,
        ),
        ("val ok = if (admin) { allowed(q) } else true\n            println(ok)", False),
        ("lookup(q) ?: footer()", False),
        ("require(if (admin) valid(q) else true)", False),
        ("if (if (admin) allowed(q) else false) footer()", False),
        ('if (q.length > 99) throw IllegalStateException(if (admin) describe(q) else "x")', False),
        ("if (isAllowed(q)) println(1)", False),
        ("when { isAllowed(q) -> footer(); else -> println(0) }", False),
        ("while (accept(q)) ;", False),
        ("do while (accept(q))", False),
        ("for (x in split(q)) ;", False),
        ("if (admin) text(q)", True),
        ("if (admin) { text(q) }", True),
        ("if (admin) footer() else text(q)", True),
        ("when { admin -> footer(); else -> text(q) }", True),
        ("while (items.isEmpty()) text(q)", True),
        ("do text(q) while (items.isEmpty())", True),
        ("for (x in items) text(q)", True),
        ("(items.firstOrNull() ?: text(q))", True),
        ("_text(q)", True),
        ("val n = q.length.let { if (it > 3) parseLen(q) else 0 }\n            println(n)", False),
        ("println(items.filter { isAllowed(q) })", False),
        ("q.let { text(it) }", True),
        ("try { footer() } catch (e: Exception) { text(q) }", True),
        ('val v = if (admin) { text(q); "x" } else "y"\n            println(v)', True),
        ("val v = q.let { text(it); 1 }\n            println(v)", True),
        ("lbl@ text(q)", True),
        ("Fill.section(this) { q }", True),
        ("val ok = try { allowed(q) } catch (e: Exception) { false }\n            println(ok)", False),
        ("val ok = try { true } catch (e: Exception) { allowed(q) }\n            println(ok)", False),
        ("val ok = when (sort) { 0 -> { allowed(q) }; else -> true }\n            println(ok)", False),
        ("listOf(q).forEach { text(it) }", True),
        ("val parts = items.map { describe(it, q) }\n            println(parts)", False),
        ("items.map { text(it + q) }", True),
        ("items.firstOrNull()?.let { h1(it) } ?: items.lastOrNull()?.let { h2(it) } ?: text(q)", True),
        ("q.takeIf { admin }?.let { h1(it) } ?: items.firstOrNull()?.let { h2(it) } ?: footer()", True),
        ("(q.takeIf { admin }?.let { h1(it) }) ?: footer()", True),
        ("val cached: String? = null\n            cached ?: load(q) ?: return@page", False),
        ('items.firstOrNull()?.let { h1(it) } ?: lookupName(q) ?: text("x")', False),
        ("header() and (q)", False),
        ("val mx = items.maxOfOrNull { weigh(it, q) }\n            println(mx)", False),
        ("val r = runCatching { parse(q) }\n            println(r)", False),
        ("val total = items.fold(0) { acc, x -> acc + weigh(x, q) }\n            println(total)", False),
        ("val g = items.groupBy { keyOf(it, q) }\n            println(g)", False),
        ("val n = items.sumOf { weigh(it, q) }\n            println(n)", False),
        ("items.firstOrNull()?.let { text(it) } ?: text(q)", True),
        ("q.takeIf { admin }?.let { text(it) } ?: footer()", True),
        ('val label = q.takeIf { admin }?.let { describe(it) } ?: "x"\n            println(label)', False),
        ("run { text(q) }", True),
    ],
)
def test_dsl_writes_are_statements_only_where_their_if_when_or_loop_is_one(stmt: str, expected: bool) -> None:
    assert _hit(_kotlin(DSL_PAGE.format(stmt=stmt)), URL) is expected


@pytest.mark.parametrize(
    "stmt",
    ["let _ = Fill.into(b, query)", "let _ = try? Fill.into(b, query)", "await Fill.into(b, query)"],
)
def test_swift_discarded_or_awaited_helper_is_a_statement(stmt: str) -> None:
    body = f'let page = Markup.render({{ b in {stmt}; b.add("x") }})\n        web.loadHTMLString(page, baseURL: nil)'
    assert _hit(_swift(SWIFT_QUERY.format(body=body)), URL)


@pytest.mark.parametrize(
    "helpers, build",
    [
        ("", 'buildString { appendln("SELECT \'$q\'"); append(";") }'),
        ("", 'buildString({ appendln("SELECT \'$q\'"); append(";") })'),
        ("", 'buildString { append("SELECT "); setCharAt(0, q[0]); append(";") }'),
        ("", 'buildMap { computeIfAbsent("k") { q }; put("a", "b") }.values.joinToString()'),
        ("", 'buildMap { merge("k", q) { a, b -> a + b }; put("a", "b") }.values.joinToString()'),
        ("", 'buildMap({ replace("k", q); put("a", "b") }).values.joinToString()'),
        ("", 'buildSpannedString { appendLine(q); append("x") }.toString()'),
        ("", 'buildList { add("SELECT 1"); fill(q); add("x") }.joinToString()'),
        ("", 'buildList { add("SELECT 1"); replaceAll { q }; add("x") }.joinToString()'),
        ("", 'buildSpannedString { insert(0, q); append("x") }.toString()'),
        ("", 'buildAnnotatedString { addStringAnnotation("t", q, 0, 1); append("x") }.toString()'),
        (
            "fun Appendable.appendQuoted(s: String) { append(s) }",
            'buildString { appendQuoted(q); append(";") }',
        ),
        (
            "fun <T : Appendable> T.appendQuoted(s: String): T = this",
            'buildString { appendQuoted(q); append(";") }',
        ),
        ("fun StringBuilder?.appendSql(s: String) {}", 'buildString { appendSql(q); append(";") }'),
        (
            "fun MutableCollection<String>.addTagged(s: String) { add(s) }",
            'buildList { addTagged(q); add("x") }.joinToString()',
        ),
        (
            "fun MutableList<String>.addSql(s: String) { add(s) }",
            'buildList { addSql(q); add("x") }.joinToString()',
        ),
        (
            "fun Editable.appendQ(s: String) { append(s) }",
            'buildSpannedString { appendQ(q); append("x") }.toString()',
        ),
    ],
)
def test_known_builder_members_and_supertype_extensions_write(helpers: str, build: str) -> None:
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL)


def test_typealias_receiver_extension_writes_into_a_known_builder() -> None:
    kotlin = "typealias Sb = StringBuilder\nfun Sb.appendSql(s: String) { append(s) }\n" + OWN_HELPER.format(
        supertype="", helpers="", build='buildString { appendSql(q); append(";") }'
    )
    assert _hit(_kotlin(kotlin), SQL)


@pytest.mark.parametrize(
    "build, expected",
    [
        ('buildString { appendSql(q); append(";") }', False),
        ('runBlocking { flowOf("SELECT 1").onStart { track(q); println() }.first() }', False),
    ],
)
def test_known_builder_other_calls_write_nothing(build: str, expected: bool) -> None:
    helpers = "fun StringBuilder.appendSql(a: String, b: String) { append(a) }"
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL) is expected


@pytest.mark.parametrize("operator", ["onStart", "onEmpty", "onCompletion"])
def test_flow_operator_block_emits_into_the_flow(operator: str) -> None:
    build = f'runBlocking {{ flowOf("SELECT 1").{operator} {{ emit(q); println() }}.first() }}'
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers="", build=build)), SQL)


@pytest.mark.parametrize(
    "stmt, expected",
    [
        ("Fill.into(b.isReady, q)", False),
        ("Fill.into(b.hasBody(), q)", False),
        ("Fill.into(b.enabled, q)", False),
        ("Fill.into(b.getName(), q)", False),
        ('Fill.into(b.getInt("rows"), q)', False),
        ('Fill.into(b.optString("k"), q)', False),
        ('Fill.into(b.attr("id"), q)', False),
        ("Log.d(b.body, q)", False),
        ("android.util.Log.d(q, b.body)", False),
        ('Timber.d("%s %s", b.body, q)', False),
        ("Analytics.track(b.text, q)", False),
        ("Fill.into(b.body, q)", True),
        ("Fill.into(b.getStringBuilder(), q)", True),
        ('Fill.into(b.getStringArrayList("tags"), q)', True),
        ("Fill.into(b.header(), q)", True),
        ("Fill.into(b.canEdit, q)", False),
        ('Fill.at("log").into(b, q)', True),
        ("Fill.with(tracker).into(b, q)", True),
        ("metricsWriter.write(b.body, q)", True),
        ("selectionTracker.select(b.body, q)", True),
        ("catalogHelper.fill(b.body, q)", True),
        ("dialogUtils.fill(b.body, q)", True),
        ("userTracking.event(b.body, q)", False),
        ("appTracker.track(b.body, q)", False),
        ("appointmentTracker.fill(b.body, q)", True),
        ("happinessTracker.fill(b.body, q)", True),
        ("mixpanelTracker.track(b.body, q)", False),
        ("firebaseTracker.logEvent(b.body, q)", False),
        ("screenViewTracker.track(b.body, q)", False),
        ("mAnalyticsTracker.track(b.body, q)", False),
        ("workoutLogHelper.fill(b.body, q)", True),
        ("CallLogHelper.fill(b.body, q)", True),
        ("ChangeLogUtils.fill(b.body, q)", True),
        ("orderTracking.fill(b.body, q)", True),
        ("appStateTracker.fill(b.body, q)", True),
        ("blogger.fill(b.body, q)", True),
        ("flogger.atInfo(b.body, q)", False),
        ("bugsnag.notify(b.body, q)", False),
        ("screenTracker.track(b.body, q)", False),
        ("_logger.debug(b.body, q)", False),
        ("m_logger.debug(b.body, q)", False),
        ("mlogger.debug(b.body, q)", False),
        ("_analytics.track(b.body, q)", False),
        ("mLogHelper.d(b.body, q)", False),
        ("sLogUtils.d(b.body, q)", False),
        ("FileLogUtils.d(b.body, q)", False),
        ("userActivityTracker.track(b.body, q)", False),
        ("userSessionTracker.track(b.body, q)", False),
        ("AppsFlyerTracker.track(b.body, q)", False),
        ("app_logger.debug(b.body, q)", False),
        ("firebase_analytics.track(b.body, q)", False),
        ("appLogHelper.d(b.body, q)", False),
        ('LogUtils.d("t", b.body, q)', False),
        ("AppLogHelper.debug(b.body, q)", False),
        ("Sentry.captureMessage(b.body, q)", False),
        ("selection_tracker.select(b.body, q)", True),
        ("userEngagementTracker.d(b.body, q)", False),
        ("debugLog.d(b.body, q)", False),
        ("app_log.d(b.body, q)", False),
        ("eventLog.fill(b.body, q)", True),
        ("audit_log.fill(b.body, q)", True),
        ("appsflyerTracker.track(b.body, q)", False),
        ("AppsflyerTracker.track(b.body, q)", False),
        ("slog.fill(b.body, q)", True),
        ("sLog.d(b.body, q)", False),
        ("change_log.fill(b.body, q)", True),
        ("call_log.fill(b.body, q)", True),
        ("order_tracking.fill(b.body, q)", True),
        ("app_state_tracker.fill(b.body, q)", True),
        ("app_metrics.write(b.body, q)", True),
        ("event_tracker.track(b.body, q)", False),
        ("screen_view_tracker.track(b.body, q)", False),
        ("m_log.d(b.body, q)", False),
        ("crash_logger.d(b.body, q)", False),
        ("Fill.into(b.code, q)", True),
        ("Fill.into(b.tag, q)", True),
        ('mLog.d("t", b.body, q)', False),
        ("eventTracker.track(b.body, q)", False),
        ("analyticsTracker.track(b.text, q)", False),
        ('mFirebaseAnalytics.logEvent("open", b.body, q)', False),
        ("Fill.into(b.title, q)", True),
        ("Fill.into(b.text, q)", True),
        ("Fill.into(b.child(0), q)", True),
        ("Fill.into(b.child(MAIN), q)", True),
        ("Fill.into(b) { q }", True),
        ('Fill.section(b, "h") { "<p>$q</p>" }', True),
    ],
)
def test_values_parts_and_logging_calls_with_a_supplied_object(stmt: str, expected: bool) -> None:
    build = f'Markup.render {{ b -> {stmt}; b.append("x"); Unit }}'
    assert _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL) is expected


@pytest.mark.parametrize(
    "stmt, expected",
    [
        ("Fill.into(m.isReady(), q);", False),
        ("Fill.into(m.getId(), q);", False),
        ('Fill.into(m.getInt("count"), q);', False),
        ("Fill.into(m.getText(), q);", True),
        ("Fill.into(m.getValue(), q);", True),
        ("Fill.into(m.getLabel(), q);", True),
        ("Fill.into(m.getCode(), q);", True),
        ('Fill.into(m.getCharSequence("k"), q);', False),
        ('System.err.printf("%s %s", m.getBody(), q);', False),
        ("System.arraycopy(q.getBytes(), 0, m.getBuf(), 0, 4);", True),
        ("Fill.into(m.getChild(0), q);", True),
        ("Fill.into(q == null ? m.getBody() : m.getHead(), q);", True),
        ("Fill.into(switch (q.length()) { case 0 -> m.getBody(); default -> m.getHead(); }, q);", True),
        (
            "Fill.into(switch (q.length()) { case 0: yield m.getBody(); default: yield m.getHead(); }, q);",
            True,
        ),
        ("m.section(() -> q);", True),
        ("m.section(() -> q.trim());", True),
        ("m.section(() -> { String t = q.trim(); return t.toUpperCase(); });", True),
    ],
)
def test_java_values_parts_and_suppliers_of_a_supplied_object(stmt: str, expected: bool) -> None:
    report = _java(
        f"""class C {{
  SQLiteDatabase db;
  void q(Intent intent) {{
    String q = intent.getStringExtra("q");
    String page = Markup.render(m -> {{ {stmt} }});
    db.execSQL("SELECT " + page);
  }}
}}
"""
    )
    assert _hit(report, SQL) is expected


@pytest.mark.parametrize(
    "imports, build, expected",
    [
        ("import logcat.*\n", 'Ext.page { logcat { "query for $q" }; "SELECT 1" }', False),
        ("import com.vendor.html.title\n", "Ext.page { title { q }; footer() }", True),
        ("", "Ext.page { info { q }; footer() }", True),
        ("import com.lib.log.*\n", 'Ext.page { debugLog { "query for $q" }; "SELECT 1" }', False),
        ("import com.lib.debugLog\n", 'Ext.page { debugLog { "query for $q" }; "SELECT 1" }', False),
        ("import com.app.ui.dialog.*\n", "Ext.page { info { q }; footer() }", True),
    ],
)
def test_lazy_loggers_by_import_and_imported_dsl_content(imports: str, build: str, expected: bool) -> None:
    kotlin = KOTLIN + imports + OWN_HELPER.format(supertype="", helpers="", build=build)
    assert _hit(analyze_sources([("app/R.kt", kotlin)]), SQL) is expected


@pytest.mark.parametrize(
    "build, expected",
    [
        ('Markup.render { b -> b.whenReady { audit.log(q) }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.footer { Log.d("t", q) }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.section { q.let { audit.log(it) } }; b.append("SELECT 1"); Unit }', False),
        (
            'Markup.render { b -> b.section { q.split(",").forEach { audit.log(it) } }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ("Markup.render { b -> b.section { q.let { it.trim() } }; Unit }", True),
        ('Markup.render { b -> b.doOnTextChanged { record(q) }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.doAfterTextChanged { record(q) }; b.append("SELECT 1"); Unit }', False),
        ("Markup.render { b -> b.section { return@section q }; Unit }", True),
        ("Markup.render { b -> b.section { val t = q.trim(); t.uppercase() }; Unit }", True),
        ("Markup.render { b -> b.section { q.run { trim() } }; Unit }", True),
        ("Markup.render { b -> b.section { with(q) { trim() } }; Unit }", True),
        ("Markup.render { b -> b.section { q.run { this.trim() } }; Unit }", True),
        (
            'Markup.render { b -> b.handler { prefs.edit().putString("k", q).apply() }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ("Markup.render { b -> b.section { q.substring(0, q.length - 1) }; Unit }", True),
        ('Markup.render { b -> b.section { (q + "x").trim() }; Unit }', True),
        ('Markup.render { b -> b.section { listOf(title, q).joinToString(" - ") }; Unit }', True),
        ("Markup.render { b -> b.section { StringBuilder(q).toString() }; Unit }", True),
        ('Markup.render { b -> b.section { title?.let { "$it: $q" } }; Unit }', True),
        ('Markup.render { b -> b.section { with(audit) { "$prefix/$q" } }; Unit }', True),
        ("Markup.render { b -> field = q; b.section { this.field.trim() }; Unit }", True),
        (
            'Markup.render { b -> b.button { val e = "open:$q"; audit.track(e) }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ('Markup.render { b -> b.section { q.let { audit.track(it) } }; b.append("SELECT 1"); Unit }', False),
        (
            'Markup.render { b -> b.section { with(q) { audit.track(this) } }; b.append("SELECT 1"); Unit }',
            False,
        ),
        (
            'Markup.render { b -> b.button { val t = Ext.tracker; t.track(q) }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ("Markup.render { b -> b.section { with(q) { val t = trim(); t.uppercase() } }; Unit }", True),
        ("Markup.render { b -> b.section { q.run { trim().lowercase() } }; Unit }", True),
        (
            'Markup.render { b -> b.section { q.run { length.toString() } }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ('Markup.render { b -> b.section { java.net.URLEncoder.encode(q, "UTF-8") }; Unit }', True),
        ("Markup.render { b -> b.section { q.let { val t = it.trim(); t.uppercase() } }; Unit }", True),
        ('Markup.render { b -> b.section { q.let { toString() } }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.section { q.run { println(this) } }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.section { this.audit.log(q) }; b.append("SELECT 1"); Unit }', False),
        (
            'Markup.render { b -> b.button { Analytics.shared.track(q); Analytics.shared.flush() }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ("Markup.render { b -> b.section { template.format(q) }; Unit }", True),
        (
            'run { val local = "name = {q}"; Markup.render { b -> b.section { local.replace("{q}", q) }; Unit } }',
            True,
        ),
        ('Markup.render { b -> b.section { audit.let { it.track(q) } }; b.append("SELECT 1"); Unit }', False),
        ("Markup.render { b -> b.section { prefix.plus(q) }; Unit }", True),
        ('Markup.render { b -> b.section { "$q".lowercase() }; Unit }', True),
        ('Markup.render { b -> b.section { "<p>$q</p>".lowercase() }; Unit }', True),
        ("Markup.render { b -> b.section { Uri.encode(q) }; Unit }", True),
        ("Markup.render { b -> b.section { q.let { v -> v.trim() } }; Unit }", True),
        ("Markup.render { b -> b.section { (q as CharSequence).trim().toString() }; Unit }", True),
        ("q.let { Markup.render { b -> b.section { it.trim() }; Unit } }", True),
        ("Markup.render { b -> field = q; b.section { field.trim() }; Unit }", True),
        ('Markup.render { b -> b.section { q.run { audit.log(this) } }; b.append("SELECT 1"); Unit }', False),
        ("Markup.render { b -> b.section { val t = repo.lookup(q); t.trim() }; Unit }", True),
        (
            'Markup.render { b -> b.button { val t = Tracker.get(); t.track(q) }; b.append("SELECT 1"); Unit }',
            False,
        ),
        (
            'Markup.render { b -> b.section { template.also { audit.track(q) } }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ("Markup.render { b -> b.section { repo.lookup(q).trim() }; Unit }", True),
        ("Markup.render { b -> field = q.trim(); b.section { field.escapeSql() }; Unit }", True),
        (
            "Markup.render { b -> field = \"name = '$q'\"; b.section { field?.let { it.escapeSql() } }; Unit }",
            True,
        ),
        ("Markup.render { b -> b.section { run { \"name = '$q'\" } }; Unit }", True),
        ('Markup.render { b -> b.section { template.contains(q) }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.section { prefix.equals(q) }; b.append("SELECT 1"); Unit }', False),
        (
            'Markup.render { b -> b.section { template.substringBefore(q) }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ('Markup.render { b -> b.section { q.isNotEmpty() }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.section { q.length }; b.append("SELECT 1"); Unit }', False),
        ('Markup.render { b -> b.section { q == "x" }; b.append("SELECT 1"); Unit }', False),
        (
            'Markup.render { b -> b.section { !q.isEmpty() && q.length > 2 }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ('Markup.render { b -> b.section { q.isValid() }; b.append("SELECT 1"); Unit }', False),
        ("Markup.render { b -> b.section { template.format(q).trim() }; Unit }", True),
        ("Markup.render { b -> b.section { listOf(title, q) }; Unit }", True),
        ("Markup.render { b -> b.section { Pair(title, q) }; Unit }", True),
        ("Markup.render { b -> b.section { requireNotNull(q) }; Unit }", True),
        ("Markup.render { b -> b.section { val t = repo.lookup(q); t.trim().lowercase() }; Unit }", True),
        (
            "Markup.render { b -> b.section { val t = repo.lookup(q); val u = t.trim(); u.uppercase() }; Unit }",
            True,
        ),
        ("Markup.render { b -> b.section { val t = repo.lookup(q); template.format(t) }; Unit }", True),
        ("Markup.render { b -> b.section { q.let { val t = repo.lookup(it); t.trim() } }; Unit }", True),
        (
            'Markup.render { b -> b.section { val t = repo.lookup(q); if (q.isEmpty()) audit.track("x") else t.trim() }; Unit }',
            True,
        ),
        ("Markup.render { b -> b.section { val t = repo.lookup(q); return@section t.trim() }; Unit }", True),
        (
            'Markup.render { b -> b.button { val t = audit.forUser(q); t.track("open") }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ('Markup.render { b -> b.section { (q + "x").ifBlank { "none" } }; Unit }', True),
        ('Markup.render { b -> b.section { template.replace(Regex("x")) { q } }; Unit }', True),
        (
            'Markup.render { b -> b.section { template.takeIf { q.isNotEmpty() } }; b.append("SELECT 1"); Unit }',
            False,
        ),
        ('Markup.render { b -> b.section { q.run { split(",").first() } }; Unit }', True),
        (
            'run { val tpl = "name = %s"; Markup.render { b -> b.section { q.let { tpl.format(it) } }; Unit } }',
            True,
        ),
        ("Markup.render { b -> b.section { StringBuilder(q) }; Unit }", True),
    ],
)
def test_callback_results_are_content_only_when_they_are_data(build: str, expected: bool) -> None:
    helpers = (
        'private val audit = Ext.audit\n    private val prefs = Ext.prefs\n    private val repo = Ext.repo\n    private var field = ""\n'
        '    private val title = "t"\n    private val template = "name = %s"\n    private val prefix: String = "x"'
    )
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL) is expected


@pytest.mark.parametrize("runner", ["remember", "lazy", "synchronized", "measureTimeMillis"])
def test_standard_runner_name_on_an_object_is_its_dsl(runner: str) -> None:
    build = f"dsl.{runner} {{ where(\"name = '$q'\"); limit(10) }}.toString()"
    helpers = "private val dsl = Ext.dsl"
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL)


@pytest.mark.parametrize(
    "call",
    [
        "scope.launchWhenStarted { openPage(q); println(1) }",
        "Scopes.main.async { record(q); println(1) }",
        "MainScope().async { record(q); println(1) }",
    ],
)
def test_coroutine_builders_on_any_receiver_have_no_data_receiver(call: str) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    private val scope = Ext.scope
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val job = {call}
        web.loadUrl(job.toString())
    }}
}}
"""
    )
    assert not _hit(report, URL), report["findings"]


@pytest.mark.parametrize(
    "files",
    [
        [
            (
                "app/A.kt",
                KOTLIN
                + """class A : Activity() {
    private val lock = Any()
    private lateinit var web: WebView
    fun go() {
        val q = intent.getStringExtra("q") ?: ""
        val page = synchronized(lock) { deleteFile(q); "https://docs.example.test/" }
        web.loadUrl(page)
    }
}
""",
            )
        ],
        [
            ("app/Log.kt", "package com.example.app\nfun log(s: String) {}\n"),
            (
                "app/R.kt",
                KOTLIN
                + """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(Ext.page { log(q); "https://docs.example.test/" })
    }
}
""",
            ),
        ],
        [
            ("app/util/Log.kt", "package com.example.util\nfun log(s: String) {}\n"),
            (
                "app/R.kt",
                KOTLIN
                + """import com.example.util.*
class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(Ext.page { log(q); "https://docs.example.test/" })
    }
}
""",
            ),
        ],
        [
            ("app/BaseRepo.kt", KOTLIN + "open class BaseRepo\nfun BaseRepo.log(s: String) {}\n"),
            (
                "app/R.kt",
                KOTLIN
                + """class R(private val web: WebView) : BaseRepo() {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(Ext.page { log(q); "https://docs.example.test/" })
    }
}
""",
            ),
        ],
        [
            (
                "app/R.kt",
                KOTLIN
                + """open class Base { fun log(msg: String, tag: String = "T") {} }
class R(private val web: WebView) : Base() {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        web.loadUrl(Ext.page { log(q); "https://docs.example.test/" })
    }
}
""",
            )
        ],
        [
            (
                "app/R.kt",
                KOTLIN
                + """class R(private val web: WebView) {
    private fun attach(n: String, done: () -> Unit): String { web.loadUrl(n); return n }
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        var name = "a"
        attach(name) { name = q }.run { android.util.Log.d("t", this) }
        var u = "https://docs.example.test/"
        u = runBlocking { withContext(Dispatchers.IO) { u = q; "https://docs.example.test/" } }
        web.loadUrl(u)
    }
}
""",
            )
        ],
    ],
)
def test_runners_project_functions_and_inline_writes_add_no_flow(files: list) -> None:
    report = analyze_sources(files)
    assert not _hit(report, URL), report["findings"]


def test_condition_helper_handed_the_object_writes_nothing() -> None:
    build = 'Markup.render { b -> if (Fill.check(b, q)) println(0); b.append("SELECT 1"); Unit }'
    assert not _hit(_kotlin(KOTLIN_BUILDER.format(build=build)), SQL)


@pytest.mark.parametrize("depth", [18, 200])
def test_long_getter_chain_part_is_handed_over(depth: int) -> None:
    chain = "".join(f".getC{index}()" for index in range(depth))
    report = _java(
        f"""class C {{
  SQLiteDatabase db;
  void q(Intent intent) {{
    String q = intent.getStringExtra("q");
    String page = Markup.render(m -> {{ Fill.into(m{chain}, q); }});
    db.execSQL("SELECT " + page);
  }}
}}
"""
    )
    assert _hit(report, SQL)


@pytest.mark.parametrize(
    "build, expected",
    [
        ('buildString { append("SELECT 1"); Log.d("t", q) }', False),
        ('buildString { append("SELECT 1"); if (q.isEmpty()) append(" LIMIT 1") else Log.d("t", q) }', False),
        ('buildString { append("SELECT 1"); println(q) }', False),
        ('buildString { append("SELECT 1"); listOf(q).forEach { println(it) } }', False),
        ('buildString { append("SELECT 1"); File(q).delete() }', False),
        ('buildString { append("x"); appendSql(q)' + ".trim()" * 20 + " }", True),
        (
            'runBlocking { channelFlow { val channel = Channel<String>(); channel.send(q); send("SELECT 1") }.first() }',
            False,
        ),
        ('runBlocking { flowOf("SELECT 1").onStart { text(q); emit("x") }.first() }', False),
        ('this@R.repo.flow { param("q", q); limit(10) }.toString()', True),
        ('com.myapp.db.flow { param("q", q); limit(10) }.toString()', True),
        ('buildString { append("SELECT 1"); Pair(q, 1).first }', False),
        ('buildString { append("SELECT "); if (q.isEmpty()) append("1") else appendQuoted(q) }', True),
        ('buildString { append("SELECT 1"); if (q.isEmpty()) append(";") else { Log.d("t", q) } }', False),
        (
            'buildString {\n            append(q)\n            where("x")\n            append(";")\n        }',
            True,
        ),
        ('buildString { append("SELECT "); q?.let { append(it) } ?: append("1") }', True),
        ('buildSet<String> { if (!contains("a")) add(q); add("SELECT 1") }.joinToString()', True),
        ('buildList { val added = add(q); add("SELECT 1") }.joinToString()', True),
        ('buildString { append("SELECT "); if (q.isNotEmpty()) appendSql(q) else append("1") }', True),
        ("runBlocking { channelFlow { channel.send(q) }.first() }", True),
        ('buildList { add("SELECT 1"); this += q }.joinToString()', True),
        ('buildMap<String, String> { put("a", "b"); this["k"] = q }.toString()', True),
        ('buildString { appendLine("SELECT 1"); appendHTML().html { body { p { +q } } } }', True),
        ('kotlinx.coroutines.flow.flow { track(q); emit("SELECT 1") }.toString()', False),
        ('repo.store.flow { param("q", q); limit(10) }.toString()', True),
    ],
)
def test_standard_builder_value_is_what_its_lambda_wrote(build: str, expected: bool) -> None:
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers="", build=build)), SQL) is expected


def test_getter_chain_past_the_link_bound_is_a_precision_limit() -> None:
    chain = "".join(f".getC{index}()" for index in range(300))
    report = _java(
        f"""class C {{
  SQLiteDatabase db;
  void q(Intent intent) {{
    String q = intent.getStringExtra("q");
    String page = Markup.render(m -> {{ Fill.into(m{chain}, q); }});
    db.execSQL("SELECT " + page);
  }}
}}
"""
    )
    assert _state(report, SQL) == "limited"
    assert "object alias identity unavailable" in _reasons(report)


def test_nested_tuple_patterns_cost_grows_with_the_depth() -> None:
    def calls(depth: int) -> int:
        subject, pattern = "url", "let a"
        for level in range(depth):
            subject = f"(safe, {subject})"
            pattern = f"(_, {pattern})" if level else "(_, let a)"
        entries = "\n".join(
            f'        case ("k{index}", {pattern}): web.load(URLRequest(url: a))' for index in range(20)
        )
        source = f"""import UIKit
import WebKit
final class Router {{
    let web = WKWebView()
    let safe = URL(string: "https://docs.example.org/")!
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {{
        let key = url.host ?? ""
        switch (key, {subject}) {{
{entries}
        default: break
        }}
        return true
    }}
}}
"""
        count = 0

        def profile(frame, event, arg) -> None:
            nonlocal count
            if event in {"call", "c_call"}:
                count += 1

        sys.setprofile(profile)
        try:
            report = _swift(source)
        finally:
            sys.setprofile(None)
        assert len([finding for finding in report["findings"] if finding["rule_id"] == URL]) == 20
        return count

    # Each case binds the element its path reaches, evaluating only that element: about 1.7
    # times the calls for twice the depth (re-evaluating every step took 3.5 times).
    assert calls(20) < 2.5 * calls(10)


def test_dsl_writes_in_a_long_branch_chain_cost_linear_calls() -> None:
    def calls(branches: int) -> int:
        chain = " else ".join(f'if (k == "{index}") text("{index}")' for index in range(branches))
        source = f"""class M(private val web: WebView) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val k = intent.getStringExtra("k") ?: ""
        web.loadUrl(Ext.page {{ {chain} else text(q); "https://docs.example.test/" }})
    }}
}}
"""
        count = 0

        def profile(frame, event, arg) -> None:
            nonlocal count
            if event in {"call", "c_call"}:
                count += 1

        sys.setprofile(profile)
        try:
            report = _kotlin(source)
        finally:
            sys.setprofile(None)
        assert _hit(report, URL)
        return count

    # Each node's statement position is decided once: about 3 times the calls for 4 times
    # the branches (deciding it again for every write took 10 times).
    assert calls(400) < 5 * calls(100)

    def elapsed(branches: int) -> float:
        import time

        chain = " else ".join(f'if (k == "{index}") text("{index}")' for index in range(branches))
        source = f"""class M(private val web: WebView) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val k = intent.getStringExtra("k") ?: ""
        web.loadUrl(Ext.page {{ {chain} else text(q); "https://docs.example.test/" }})
    }}
}}
"""
        best = float("inf")
        for _ in range(2):
            started = time.perf_counter()
            _kotlin(source)
            best = min(best, time.perf_counter() - started)
        return best

    # tree-sitter's parent walk costs the depth, which call counts do not see: the class
    # bodies around each node are found once (about 9 times for 4 times the branches, the
    # n^1.6 of the walk itself; walking to the root for every write took about 50 times).
    # The bound catches that walk, not a quadratic term (16 times), which load alone can
    # reach; quadratic Python work shows in the call count above. elapsed(200) is about
    # 0.04 s, so the floor stays below it and the bound is a ratio, not an absolute time;
    # 24 leaves room for oversubscribed CPUs and still catches the 50-times walk.
    assert elapsed(800) < 24 * max(elapsed(200), 0.01)


def test_member_extension_after_a_misparsed_where_line_still_writes() -> None:
    # tree-sitter-kotlin 1.1.0 reads `append(..)` and a following `where(..)` line as one
    # infix expression; the member write and the builder's final value still carry q.
    report = _kotlin(
        """class Screen(private val db: SQLiteDatabase) {
    private fun StringBuilder.where(c: String) { append(" WHERE "); append(c) }
    fun show(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val sql = buildString {
            append("SELECT * FROM t")
            where("n = '$q'")
            append(" LIMIT 1")
        }
        db.execSQL(sql)
    }
}
"""
    )
    assert _hit(report, SQL)


def test_source_read_on_an_object_is_content() -> None:
    report = _kotlin(
        """class A : Activity() {
    private lateinit var web: WebView
    private val analytics = Ext.analytics
    fun go() {
        val page = Markup.render { b -> b.section { intent.getStringExtra("q") }; b.append("x"); Unit }
        web.loadUrl(page)
    }
    fun stay() {
        val page = Markup.render { b -> b.section { analytics.track(intent.getStringExtra("q")) }; b.append("x"); Unit }
        web.loadUrl(page)
    }
}
"""
    )
    lines = {
        finding["evidence"][0].get("line") for finding in report["findings"] if finding["rule_id"] == URL
    }
    assert len(lines) == 1, report["findings"]


def test_flow_operator_block_may_assign_after_the_assignment_stores() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        var u = "https://docs.example.test/"
        u = flowOf(u).onStart { u = q }.toString()
        web.loadUrl(u)
    }
}
"""
    )
    assert _hit(report, URL)


def test_flat_builder_body_stays_linear() -> None:
    import time

    def elapsed(entries: int) -> float:
        puts = "; ".join(f'put("k{index}", "v{index}")' for index in range(entries))
        source = f"""class S(private val db: SQLiteDatabase) {{
    fun show(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val m = buildMap<String, String> {{ {puts}; put("q", q) }}
        db.execSQL(m.toString())
    }}
}}
"""
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            assert _hit(_kotlin(source), SQL)
            best = min(best, time.perf_counter() - started)
        return best

    # The last statement of each block or lambda is found once per parent: about 4 times for
    # 4 times the entries (finding it again for every statement took 12 to 16 times).
    assert elapsed(8000) < 8 * max(elapsed(2000), 0.05)


def test_project_function_hides_a_member_name_in_another_object_s_flow_dsl() -> None:
    helpers = "private val repo = Ext.repo\n    fun append(s: String) {}"
    build = "repo.flow { append(q); limit(10) }.toString()"
    assert not _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL)


def test_callback_assignment_to_its_own_shadowing_local_is_no_deferred_write() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        var u = "https://docs.example.test/"
        u = Ext.refresh { var u = q; u = u.trim(); "https://docs.example.test/" }
        web.loadUrl(u)
    }
}
"""
    )
    assert not _hit(report, URL), report["findings"]


def test_misparsed_where_line_keeps_the_lambda_result() -> None:
    report = _kotlin(
        """class Repo(private val db: SQLiteDatabase) {
    fun go(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val sql = Sql {
            select("*")
            where("name = '$q'")
        }
        db.execSQL(sql)
    }
}
"""
    )
    assert _hit(report, SQL)


@pytest.mark.parametrize(
    "stmt, expected",
    [
        ("let n = Fill.count(b, query); print(n)", False),
        ("let ok = Fill.into(b, query); print(ok)", False),
        ("print(b, query)", False),
        ("print(b.body, query)", False),
    ],
)
def test_swift_initializers_and_print_hand_nothing_over(stmt: str, expected: bool) -> None:
    body = f'let page = Markup.render({{ b in {stmt}; b.add("x") }})\n        web.loadHTMLString(page, baseURL: nil)'
    assert _hit(_swift(SWIFT_QUERY.format(body=body)), URL) is expected


@pytest.mark.parametrize(
    "section, expected",
    [
        ('String(format: "%@", query)', True),
        ("URL(string: query)", True),
        ('String(format: "%d", 1)', False),
        ("self.lookup(query).trimmingCharacters(in: .whitespaces)", True),
        ('self.lookup(query).components(separatedBy: ",")', False),
        ('"https://docs.example.test/".hasPrefix(query)', False),
        ("query.isEmpty", False),
        ('query == "x"', False),
        ("query.count > 2", False),
        ("query.count + 1", False),
        ('"\\(query.count) results"', False),
        ('"\\(query) results"', True),
        ("self.track(query)", False),
    ],
)
def test_swift_content_closures_by_their_value(section: str, expected: bool) -> None:
    body = (
        f'let page = Markup.render({{ b in b.section {{ {section} }}; b.add("x") }})\n'
        "        web.loadHTMLString(page, baseURL: nil)"
    )
    assert _hit(_swift(SWIFT_QUERY.format(body=body)), URL) is expected


@pytest.mark.parametrize(
    "tail",
    [
        'if (strict) { "https://docs.example.test/" } else { "https://x.test/$v" }',
        'try { "https://x.test/$v" } catch (e: Exception) { "https://docs.example.test/" }',
        'when { strict -> { "https://docs.example.test/" }; else -> { "https://x.test/$v" } }',
    ],
)
def test_binding_when_entry_ending_in_a_braced_branch_reads_the_entry_locals(tail: str) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView, private val strict: Boolean) {{
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val target = when (val u = q) {{ "" -> "https://docs.example.test/"; else -> {{ val v = u.lowercase(); {tail} }} }}
        web.loadUrl(target)
    }}
}}
"""
    )
    assert _hit(report, URL)


@pytest.mark.parametrize(
    "host, service",
    [
        ("fun show(intent: Intent, tracker: Tracker) {", "tracker"),
        (
            "fun show(intent: Intent) {\n        val analytics = FirebaseAnalytics.getInstance(this)",
            "analytics",
        ),
    ],
)
def test_callback_on_a_service_held_in_a_parameter_or_local_is_no_content(host: str, service: str) -> None:
    report = _kotlin(
        f"""class R(private val db: SQLiteDatabase) {{
    {host}
        val q = intent.getStringExtra("q") ?: ""
        val s = Markup.render {{ b -> b.button {{ {service}.track(q) }}; b.append("SELECT 1"); Unit }}
        db.execSQL(s)
    }}
}}
"""
    )
    assert not _hit(report, SQL), report["findings"]


def test_callback_flow_channel_is_the_scope_s_even_with_a_field_of_that_name() -> None:
    build = "runBlocking { callbackFlow { channel.send(q); awaitClose { } }.first() }"
    helpers = "private val channel = Ext.channel"
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL)


def test_scope_rebinding_this_to_the_enclosing_with_object_is_a_rebinding() -> None:
    build = 'with(sb) { buildString { sb.apply { this.append(q) }; append("SELECT 1") } }'
    helpers = "private val sb = StringBuilder()"
    assert not _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL)


def test_qualified_sam_constructor_value_has_no_data_receiver() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val listener = View.OnClickListener { openPage(q); println("x") }
        web.loadUrl(listener.toString())
    }
}
"""
    )
    assert not _hit(report, URL), report["findings"]


def test_callback_assignment_to_another_name_is_no_deferred_write() -> None:
    report = _kotlin(
        """class R(private val web: WebView) {
    private var other = ""
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        var u = "https://docs.example.test/"
        u = Ext.refresh { other = q; "https://docs.example.test/" }
        web.loadUrl(u)
    }
}
"""
    )
    assert not _hit(report, URL), report["findings"]


def test_swift_callback_posting_the_input_to_a_service_is_no_content() -> None:
    body = (
        "let page = Markup.render({ b in\n"
        '            b.whenLoaded { NotificationCenter.default.post(name: .init("x"), object: query) }\n'
        '            b.add("<p>x</p>")\n'
        "        })\n"
        "        web.loadHTMLString(page, baseURL: nil)"
    )
    assert not _hit(_swift(SWIFT_QUERY.format(body=body)), URL)


def test_misparsed_final_statement_of_a_builder_keeps_its_value() -> None:
    # tree-sitter-kotlin 1.1.0 reads `a@ b@ c@ for (..) append(q)` as an infix expression, not a
    # loop and a call: the builder's value keeps that final expression's value.
    build = "buildString {\n            a@ b@ c@ for (i in 0 until 2) append(q)\n        }"
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers="", build=build)), SQL)


@pytest.mark.parametrize(
    "assign, expected",
    [
        (
            'u = Ext.refresh { u = q; for (x in listOf("a")) { val u = x; println(u) }; "https://docs.example.test/" }',
            True,
        ),
        ('u = Ext.refresh { Ext.later { var u = q; u = u.trim() }; "https://docs.example.test/" }', False),
    ],
)
def test_callback_shadowing_is_decided_per_assignment(assign: str, expected: bool) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        var u = "https://docs.example.test/"
        {assign}
        web.loadUrl(u)
    }}
}}
"""
    )
    assert _hit(report, URL) is expected


def test_content_through_self_in_swift() -> None:
    swift = _swift(
        """import UIKit
import WebKit
final class V {
    let web = WKWebView()
    var query = ""
    func application(_ app: UIApplication, open url: URL, options: [String: Any]) {
        query = url.absoluteString
        let page = Markup.render({ b in b.section { self.query.uppercased() }; b.add("x") })
        web.loadHTMLString(page, baseURL: nil)
    }
}
"""
    )
    assert _hit(swift, URL)


def test_flat_dsl_body_of_braced_branches_stays_linear() -> None:
    import time

    def elapsed(statements: int) -> float:
        body = "; ".join(f'if (k == "{index}") {{ text("{index}") }}' for index in range(statements))
        source = f"""class M(private val web: WebView) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val k = intent.getStringExtra("k") ?: ""
        web.loadUrl(Ext.page {{ {body}; text(q); "https://docs.example.test/" }})
    }}
}}
"""
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            assert _hit(_kotlin(source), URL)
            best = min(best, time.perf_counter() - started)
        return best

    # A block's result position reads its parent's last statement once: about 4 times for 4
    # times the statements (re-listing the parent for every block took 12 times).
    assert elapsed(4000) < 8 * max(elapsed(1000), 0.05)


@pytest.mark.parametrize(
    "shape",
    [
        "val s = buildString {{ {items}; append(q) }}\n        db.execSQL(s)",
        'web.loadUrl(Ext.page {{ {items}; text(q); "x" }})',
    ],
)
def test_flat_bodies_of_braced_blocks_and_lambdas_stay_linear(shape: str) -> None:
    import time

    def elapsed(count: int) -> float:
        if shape.startswith("val s"):
            items = "; ".join(f'if (k == "{index}") {{ append("{index}") }}' for index in range(count))
        else:
            items = "; ".join(f'section {{ "{index}" }}' for index in range(count))
        source = f"""class M(private val web: WebView, private val db: SQLiteDatabase) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val k = intent.getStringExtra("k") ?: ""
        {shape.format(items=items)}
    }}
}}
"""
        best = float("inf")
        for _ in range(3):
            started = time.perf_counter()
            _kotlin(source)
            best = min(best, time.perf_counter() - started)
        return best

    # Whether a statement is its block's last, and whether a call's value is discarded, is
    # decided once per parent: about 4 times for 4 times the statements (listing the parent
    # for every statement took 12 times).
    assert elapsed(4000) < 8 * max(elapsed(1000), 0.05)


def test_misparsed_where_line_after_a_declaration_still_writes() -> None:
    report = _kotlin(
        """class Screen(private val db: SQLiteDatabase) {
    private fun StringBuilder.where(c: String) { append(" WHERE "); append(c) }
    fun show(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val sql = buildString {
            val start = append("SELECT * FROM t")
            where("n = '$q'")
        }
        db.execSQL(sql)
    }
}
"""
    )
    assert _hit(report, SQL)


@pytest.mark.parametrize(
    "assign, expected",
    [
        (
            'u = Ext.retry { if (q.isEmpty()) { var u = q; u = u.trim() }; "https://docs.example.test/" }',
            False,
        ),
        ('u = Ext.fetch { u = q; Ext.each { var u = ""; println(u) }; "https://docs.example.test/" }', True),
    ],
)
def test_callback_shadowing_in_nested_blocks_and_lambdas(assign: str, expected: bool) -> None:
    report = _kotlin(
        f"""class R(private val web: WebView) {{
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        var u = "https://docs.example.test/"
        {assign}
        web.loadUrl(u)
    }}
}}
"""
    )
    assert _hit(report, URL) is expected


def test_binding_when_entry_ending_in_an_else_if_chain_reads_the_entry_locals() -> None:
    report = _kotlin(
        """class R(private val web: WebView, private val strict: Boolean) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val target = when (val u = q) {
            "" -> "https://docs.example.test/"
            else -> {
                val v = u.lowercase()
                if (strict) { "https://docs.example.test/" } else if (u.length > 3) { "https://docs.example.test/" } else { "https://x.test/$v" }
            }
        }
        web.loadUrl(target)
    }
}
"""
    )
    assert _hit(report, URL)


def test_function_of_an_outer_class_binds_from_an_inner_class_dsl() -> None:
    report = _kotlin(
        """class Outer(private val web: WebView) {
    fun log(s: String) {}
    inner class In {
        fun go(q: String) { web.loadUrl(Ext.page { log(q); "https://docs.example.test/" }) }
    }
    fun open(intent: Intent) { In().go(intent.getStringExtra("q") ?: "") }
}
"""
    )
    assert not _hit(report, URL), report["findings"]


def test_standard_builder_through_a_field_named_like_a_package_root_is_a_dsl() -> None:
    helpers = "private val android = Ext.dsl"
    build = 'android.repo.flow { param("q", q); limit(10) }.toString()'
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers=helpers, build=build)), SQL)


def test_swift_string_property_holding_derived_input_is_content() -> None:
    report = _swift(
        """import UIKit
import WebKit
final class V {
    let web = WKWebView()
    var query = ""
    func application(_ app: UIApplication, open url: URL, options: [String: Any]) {
        query = url.query ?? ""
        let page = Markup.render({ b in b.section { self.query.components(separatedBy: "&") }; b.add("x") })
        web.loadHTMLString(page, baseURL: nil)
    }
}
"""
    )
    assert _hit(report, URL), report["findings"]


def test_java_string_field_holding_derived_input_is_content() -> None:
    report = analyze_sources(
        [
            (
                "app/R.java",
                """package com.example.app;
import android.content.Intent;
import android.webkit.WebView;
class R {
    String query;
    WebView web;
    void go(Intent i) {
        query = i.getStringExtra("q").trim();
        String page = Markup.render(m -> { m.section(() -> query.intern()); m.put("h", "x"); });
        web.loadUrl(page);
    }
}
""",
            )
        ]
    )
    assert _hit(report, URL), report["findings"]


@pytest.mark.parametrize(
    "section",
    [
        "b.section { val t = Ext.repo.lookup(q); t.trim() }",
        'b.button { val t = Ext.repo.lookup(q); t.track("x") }; b.append("x")',
        'b.section { audit.let { it.track(q) } }; b.append("x")',
    ],
)
def test_content_checks_in_a_followed_callee_record_no_reasons_of_their_own(section: str) -> None:
    def reasons(body: str) -> set[str]:
        report = _kotlin(
            f"""class Pages(private val web: WebView) {{
    private val audit = Ext.audit
    fun open(intent: Intent) {{ val q = intent.getStringExtra("q") ?: ""; web.loadUrl(render(q)) }}
    private fun render(q: String): String = Markup.render {{ b -> {body}; Unit }}
}}
"""
        )
        return set(_reasons(report))

    # A closure's names read from the enclosing frame, or a visited initializer read again
    # later, would record `receiver field inventory unavailable` or `object storage alias
    # unavailable` that the same calls written directly do not.
    assert reasons(section) <= reasons("b.section(Ext.repo.lookup(q).trim()); audit.track(q)")


def test_assignments_in_a_deferred_callback_cost_linear_calls() -> None:
    def calls(count: int) -> int:
        locals_ = "; ".join(f"var v{index} = 0" for index in range(count))
        assignments = "; ".join(f"v{index} = {index}" for index in range(count))
        source = f"""class S(private val web: WebView) {{
    fun go(intent: Intent) {{
        {locals_}
        var url = intent.getStringExtra("q") ?: ""
        url = Ext.configure {{ {assignments}; url = "https://docs.example.test/" }}
        web.loadUrl(url)
    }}
}}
"""
        total = 0

        def profile(frame, event, arg) -> None:
            nonlocal total
            if event in {"call", "c_call"}:
                total += 1

        sys.setprofile(profile)
        try:
            _kotlin(source)
        finally:
            sys.setprofile(None)
        return total

    # Only an assignment to the target name is checked for a shadowing local.
    assert calls(800) < 6 * calls(200)


@pytest.mark.parametrize(
    "build, expected",
    [
        ('Ext.page { runCatching { text(q) }.onFailure { println(it) }; "SELECT 1" }', True),
        ('Ext.page { runCatching { text(q) }.exceptionOrNull(); "SELECT 1" }', True),
        ('Ext.page { val ok = runCatching { text(q) }.isSuccess; "SELECT 1" }', True),
        ('Ext.page { val r = runCatching { parse(q) }.getOrNull(); "SELECT 1" }', False),
        (
            'Ext.page { val r = runCatching { parse(q) }.onFailure { println(it) }.getOrNull(); "SELECT 1" }',
            False,
        ),
    ],
)
def test_runcatching_block_value_goes_through_its_result_chain(build: str, expected: bool) -> None:
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers="", build=build)), SQL) is expected


@pytest.mark.parametrize(
    "build, expected",
    [
        ('Ext.page {\n            text(q)\n            where("x")\n            "SELECT 1"\n        }', True),
        (
            'Ext.page {\n            val t = text(q)\n            where("x")\n            "SELECT 1"\n        }',
            False,
        ),
    ],
)
def test_call_on_the_line_before_a_misparsed_where_line_stands_where_the_pair_does(
    build: str, expected: bool
) -> None:
    assert _hit(_kotlin(OWN_HELPER.format(supertype="", helpers="", build=build)), SQL) is expected


def test_string_locals_concatenate_and_char_locals_dispatch() -> None:
    def report(declaration: str, update: str) -> dict:
        return _kotlin(
            f"""class R(private val db: SQLiteDatabase) {{
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        {declaration}
        {update}
        db.execSQL("SELECT " + q + s)
    }}
}}
"""
        )

    # A local initialized from a string literal is a String: `+=` concatenates.
    assert _state(report('var s = ""', "s += q"), SQL) == "checked"
    # A character literal is no String: `+=` is an operator call the flow does not resolve.
    assert "compound assignment operator dispatch unavailable" in _reasons(report("var s = 'a'", "s += 1"))


NOTES = """package com.example.notes
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.webkit.WebView
{imports}
class Notes(private val db: SQLiteDatabase, private val web: WebView, private val strict: Boolean) {{
    private val audit = Ext.audit
    private val prefs = Ext.prefs
    private val template = "name = {{q}}"
{members}
    fun open(intent: Intent, items: List<String>) {{
        val q = intent.getStringExtra("q") ?: ""
{body}
    }}
}}
"""


def _notes(body: str, members: str = "", imports: str = "") -> dict:
    source = NOTES.format(body=body, members=members, imports=imports)
    return analyze_sources([("app/src/main/java/com/example/notes/Notes.kt", source)])


def _section(expr: str, host: str = "section", pre: str = "") -> str:
    return f'{pre}        val s = Markup.render {{ b -> b.{host} {{ {expr} }}; b.append("SELECT 1"); Unit }}\n        db.execSQL(s)'


def _page(stmt: str) -> str:
    return (
        f"        val page = Ext.page {{\n            {stmt}\n"
        '            "https://docs.example.test/"\n        }\n        web.loadUrl(page)'
    )


@pytest.mark.parametrize(
    "body, rule, expected, members, imports",
    [
        # values computed from input and closure locals
        (_section("u.encodeForWeb()", pre='        val u = "p/" + q\n'), SQL, True, "", ""),
        (_section("val t = q.trim(); val u = t.lowercase(); u.encodeForWeb()"), SQL, True, "", ""),
        (
            _section(
                'val label: String; if (q.isEmpty()) label = "none" else label = q.trim(); label.encodeForWeb()'
            ),
            SQL,
            True,
            "",
            "",
        ),
        (_section("\"name = '%s'\".format(q)"), SQL, True, "", ""),
        (_section('"name = ".plus(q)'), SQL, True, "", ""),
        (_section('if (q.isEmpty()) "1" else { val t = q.trim(); t.encodeForWeb() }'), SQL, True, "", ""),
        (_section("val t = q.trim(); template.format(t)"), SQL, True, "", ""),
        (_section("Ext.repo.lookup(q).let { it.trim() }"), SQL, True, "", ""),
        (
            _section('if (q.isEmpty()) audit.track("x") else { val t = Ext.repo.lookup(q); t.trim() }'),
            SQL,
            True,
            "",
            "",
        ),
        (
            _section('if (q.isEmpty()) audit.track("x") else { val t = q.trim(); t.encodeForWeb() }'),
            SQL,
            True,
            "",
            "",
        ),
        (_section('val t = q.trim(); (t + "x").encodeForWeb()'), SQL, True, "", ""),
        (
            _section("tpl.format(q)"),
            SQL,
            True,
            '    private val base = Ext.base\n    private val tpl = base + "?q=%s"',
            "",
        ),
        (_section("tpl.format(q)", pre="        val tpl = getString(R.string.where)\n"), SQL, True, "", ""),
        (_section('template.encodeForWeb(q).replace("a", "b").escape()'), SQL, False, "", ""),
        (_section("this.items.track(q)", host="button"), SQL, False, "    private val items = Ext.items", ""),
        (
            _section('val t = audit.make(q); t.track("x")', host="button", pre="        val t = q\n"),
            SQL,
            False,
            "",
            "",
        ),
        (
            _section(
                'this.holder.track("x")',
                host="button",
                pre="        holder = Wrapper(q)\n        val holder = q\n",
            ),
            SQL,
            False,
            "    private var holder: Any = Ext.h",
            "",
        ),
        (
            "        q.let { val s = Markup.render { b -> b.section { audit.let { it.track(q) } }; "
            'b.append("SELECT 1"); Unit }; db.execSQL(s) }',
            SQL,
            False,
            "",
            "",
        ),
        # side effects: services, built objects, a member named like a local, a nested block's local
        (
            _section('prefs.edit().putString("k", q).putInt("n", 1).apply()', host="button"),
            SQL,
            False,
            "",
            "",
        ),
        (_section("q.run { describe().uppercase() }", host="button"), SQL, False, "", ""),
        (_section("with(audit) { toString() }", host="button"), SQL, False, "", ""),
        (_section("audit.run { toString() }", host="button"), SQL, False, "", ""),
        (_section("ShareDialog(audit, q).show()", host="button"), SQL, False, "", ""),
        (_section("Uploader(q).start()", host="button"), SQL, False, "", ""),
        (_section("val u = Uploader(q); u.start()", host="button"), SQL, False, "", ""),
        (_section("Uploader(q).let { it.start() }", host="button"), SQL, False, "", ""),
        (_section('java.io.File(q, "x").delete()', host="button"), SQL, False, "", ""),
        (_section("val audit = q.trim(); this.audit.record(audit)", host="button"), SQL, False, "", ""),
        (
            _section('if (strict) { val audit = "x"; println(audit) }; audit.track(q)', host="button"),
            SQL,
            False,
            "",
            "",
        ),
        (_section("q.let { audit.track(it); Unit }", host="button"), SQL, False, "", ""),
        # templates by name, also qualified, in a companion object, at the top level, raw
        (_section('template.replace("{q}", q).encodeForWeb()'), SQL, True, "", ""),
        (_section('this.template.replace("{q}", q)'), SQL, True, "", ""),
        (
            _section("WHERE.format(q)"),
            SQL,
            True,
            "    companion object { const val WHERE = \"name = '%s'\" }",
            "",
        ),
        (
            _section("Notes.WHERE.format(q)"),
            SQL,
            True,
            "    companion object { const val WHERE = \"name = '%s'\" }",
            "",
        ),
        (_section("TOP.format(q)"), SQL, True, "", "const val TOP = \"name = '%s'\""),
        (
            _section("raw.format(q)"),
            SQL,
            True,
            '    private val raw = """\n        name = \'%s\'\n    """.trimIndent()',
            "",
        ),
        # deferred writes and their shadows
        (
            '        var u = "https://docs.example.test/"\n'
            '        u = Ext.fetch { u = q; val u = ""; println(u); "https://docs.example.test/" }\n'
            "        web.loadUrl(u)",
            URL,
            True,
            "",
            "",
        ),
        (
            '        var u = "https://docs.example.test/"\n'
            '        u = Ext.fetch { var (a, u) = Pair("x", "y"); u = q; println(a + u); "https://docs.example.test/" }\n'
            "        web.loadUrl(u)",
            URL,
            False,
            "",
            "",
        ),
        # statement positions: elvis chains, packages, mapping lambdas, misparsed lines
        (
            _page("items.firstOrNull()?.let { h1(it) } ?: q.takeIf { strict }?.let { text(it) } ?: footer()"),
            URL,
            True,
            "",
            "",
        ),
        (_page("(items.firstOrNull() ?: load(q)) ?: footer()"), URL, False, "", ""),
        (
            '        val s = io.myapp.db.flow { param("q", q); limit(10) }.toString()\n        db.execSQL(s)',
            SQL,
            True,
            "",
            "",
        ),
        (_page('info { "https://docs.example.test/$q" }'), URL, True, "", "import com.example.app.login.*"),
        (
            _page("val out = items.mapTo(mutableListOf()) { describe(it, q) }\n            println(out)"),
            URL,
            False,
            "",
            "",
        ),
        (_page("items.mapTo(mutableListOf()) { describe(it, q) }"), URL, False, "", ""),
        (_page("val mn = items.minOfOrNull { weigh(it, q) }\n            println(mn)"), URL, False, "", ""),
        (_page("val s = items.joinToString { describe(it, q) }\n            println(s)"), URL, False, "", ""),
        (
            _page("val z = items.zip(items) { a, x -> describe(a, q) }\n            println(z)"),
            URL,
            False,
            "",
            "",
        ),
        (_page('val c = "https://x.test/$q"\n            where(c)'), URL, True, "", ""),
        (_page('var c = ""\n            c = "https://x.test/$q"\n            where(c)'), URL, True, "", ""),
        (_page('val m = mapOf("k"\n                to(q))\n            println(m)'), URL, False, "", ""),
    ],
)
def test_round_ten_content_names_and_statements(
    body: str, rule: str, expected: bool, members: str, imports: str
) -> None:
    report = _notes(body, members=members, imports=imports)
    assert _hit(report, rule) is expected, report["findings"]


def test_swift_member_named_like_a_local_and_guard_binding_shadow() -> None:
    def report(body: str) -> dict:
        return _swift(
            f"""import UIKit
import WebKit
final class V {{
    let web = WKWebView()
    let analytics = Analytics()
    let template = "https://docs.example.test/?q={{q}}"
    func application(_ app: UIApplication, open url: URL, options: [String: Any]) {{
        let query = url.absoluteString
{body}
    }}
}}
"""
        )

    member = report(
        '        let page = Markup.render({ b in b.button { let analytics = "open"; return self.analytics.track(analytics, query) }; b.add("x") })\n'
        "        web.loadHTMLString(page, baseURL: nil)"
    )
    assert not _hit(member, URL), member["findings"]
    template = report(
        '        let page = Markup.render({ b in b.section { self.template.replacingOccurrences(of: "{q}", with: query) }; b.add("x") })\n'
        "        web.loadHTMLString(page, baseURL: nil)"
    )
    assert _hit(template, URL), template["findings"]
    shadow = report(
        '        var page = "https://docs.example.test/"\n'
        '        page = Ext.fetch { guard var page = Optional(query) else { return "x" }; page = page.lowercased(); print(page); return "y" }\n'
        "        web.load(URLRequest(url: URL(string: page)!))"
    )
    assert not _hit(shadow, URL), shadow["findings"]


def test_java_uninitialized_local_and_this_template_are_content() -> None:
    def report(members: str, section: str) -> dict:
        return analyze_sources(
            [
                (
                    "app/R.java",
                    f"""package com.example.app;
import android.content.Intent;
import android.webkit.WebView;
class R {{
    WebView web;
{members}
    void go(Intent i) {{
        String q = i.getStringExtra("q");
        String page = Markup.render(m -> {{ m.section({section}); m.put("h", "x"); }});
        web.loadUrl(page);
    }}
}}
""",
                )
            ]
        )

    local = report(
        "",
        '() -> { String label; if (q.isEmpty()) label = "none"; else label = q.trim(); return label.intern(); }',
    )
    assert _hit(local, URL), local["findings"]
    template = report(
        '    private final String template = "https://docs.example.test/?q={q}";',
        '() -> this.template.replace("{q}", q)',
    )
    assert _hit(template, URL), template["findings"]


def test_a_source_call_starts_a_content_chain() -> None:
    report = _kotlin(
        """class HelpActivity : Activity() {
    private lateinit var web: WebView
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        val page = Markup.render { b -> b.section { getIntent().getStringExtra("t").encodeForWeb() }; Unit }
        web.loadUrl(page)
    }
}
"""
    )
    assert _hit(report, URL), report["findings"]


def test_string_typed_locals_in_deep_dsls_cost_no_scope_walk() -> None:
    def calls(depth: int) -> int:
        expr = "text(q)"
        for level in range(depth):
            expr = f'div{level % 3} {{ val v{level} = "x{level}"; s = v{level}; section {{ "c{level}" }}; {expr} }}'
        source = f"""class P(private val web: WebView) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        var s = ""
        val page = Ext.page {{
            {expr}
            footer()
        }}
        web.loadUrl(page + s)
    }}
}}
"""
        total = 0

        def profile(frame, event, arg) -> None:
            nonlocal total
            if event in {"call", "c_call"}:
                total += 1

        sys.setprofile(profile)
        try:
            _kotlin(source)
        finally:
            sys.setprofile(None)
        return total

    # A local typed String by its literal takes the builtin String; resolving the spelling
    # through every enclosing scope grew about 4.9 times for 4 times the depth (3.4 now).
    assert calls(200) < 4.2 * calls(50)


@pytest.mark.parametrize(
    "callback, expected",
    [
        ('if let page = Ext.cached() { print(page) }; page = query; return "x"', True),
        ('if var page = Ext.cached() { page = "y"; print(page) } else { page = query }; return "x"', True),
        ('if var page = Ext.cached() { page = query; print(page) }; return "x"', False),
        ('guard var page = Ext.cached() else { return "x" }; page = query; print(page); return "y"', False),
    ],
)
def test_swift_if_binding_shadows_only_its_then_block(callback: str, expected: bool) -> None:
    body = (
        '        var page = "https://docs.example.test/"\n'
        f"        page = Ext.fetch {{ {callback} }}\n"
        "        web.load(URLRequest(url: URL(string: page)!))"
    )
    assert _hit(_swift(SWIFT_QUERY.format(body=body)), URL) is expected


@pytest.mark.parametrize(
    "expr, host, expected",
    [
        ("val t = q.trim(); Uploader(t).start()", "button", False),
        ('val t = q.trim(); java.io.File(t, "x").delete()', "button", False),
        ("val t = Ext.repo.lookup(q); listOf(t).joinToString()", "section", True),
        ("val t = q.trim(); listOf(t).joinToString()", "section", True),
    ],
)
def test_a_call_root_over_closure_locals_is_judged_by_its_value(expr: str, host: str, expected: bool) -> None:
    report = _notes(_section(expr, host=host))
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "expr, expected, members, imports",
    [
        ("val title = Ext.repo.find(q); title", False, "", ""),
        ("val u = Uploader(q); u", False, "", ""),
        ("val ok = q.isNotEmpty(); ok", False, "", ""),
        ("q.length + 1", False, "", ""),
        ("q.length - 1", False, "", ""),
        ('"${q.length} results"', False, "", ""),
        ("val t = q.trim(); t", True, "", ""),
        ('"${q.length} results for $q"', True, "", ""),
        ("q.substring(0, q.length - 1)", True, "", ""),
        (
            'title.replace("{q}", q)',
            False,
            "    private val title = Ext.header",
            'class Labels { val title = "Hello %s" }',
        ),
        (
            "count.format(q)",
            False,
            "    private val count = Ext.counter",
            'object Counts { const val count = "%s items" }',
        ),
        ("count.format(q)", True, "", 'object Counts { const val count = "%s items" }'),
    ],
)
def test_results_numbers_and_template_names_by_scope(
    expr: str, expected: bool, members: str, imports: str
) -> None:
    report = _notes(_section(expr), members=members, imports=imports)
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, rule, expected, members, imports",
    [
        # deferred writes, glued lines and statement positions
        (_page("val n = Ext.limit() ?: 10\n            where(\"n = '$q'\")"), URL, True, "", ""),
        (_page('val o = if (strict) "ASC" else "DESC"\n            where("n = \'$q\'")'), URL, True, "", ""),
        (_page("val ok = q.length > 3\n            where(\"n = '$q'\")"), URL, True, "", ""),
        (_page('val (a, c) = Pair("x", "y")\n            where("n = \'$q\'")'), URL, True, "", ""),
        (_page('val c = "x"\n            where(c)\n            where("n = \'$q\'")'), URL, True, "", ""),
        (_page("items.associateByTo(mutableMapOf()) { describe(it, q) }"), URL, False, "", ""),
        (_page("items.filterTo(mutableListOf()) { check(it, q) }"), URL, False, "", ""),
        (_page("runCatching { text(q) }.also { println(it) }"), URL, True, "", ""),
        (_page("runCatching { text(q) }.map { it }"), URL, True, "", ""),
        (_page("runCatching { text(q) }.getOrNull()"), URL, True, "", ""),
        (
            _page("runCatching { text(q) }.onSuccess { println(it) }.onFailure { println(it) }"),
            URL,
            True,
            "",
            "",
        ),
        (_page('((items.firstOrNull() ?: load(q))) ?: text("x")'), URL, False, "", ""),
        # content: results through scope blocks, computed roots, names, scalars, templates
        (_section("val t = Ext.repo.lookup(q); t.run { trim() }"), SQL, True, "", ""),
        (_section("val t = Ext.repo.lookup(q); t.run { lowercase().trim() }"), SQL, True, "", ""),
        (_section("val t = Ext.repo.lookup(q); with(t) { uppercase() }"), SQL, True, "", ""),
        (_section('val t = Ext.repo.lookup(q); t.ifBlank { "none" }'), SQL, True, "", ""),
        (_section("val t = Ext.repo.lookup(q); t.trim().also { println(it) }"), SQL, True, "", ""),
        (_section("val t = Ext.repo.lookup(q); t.repeat(2)"), SQL, True, "", ""),
        (_section('val col = Ext.sortColumn(); (col + " = \'" + q + "\'").escapeSql()'), SQL, True, "", ""),
        (_section("val r = Ext.repo.lookup(q); (Ext.wrap(r) + q).escapeSql()"), SQL, True, "", ""),
        (_section("val t = q.trim(); val r = Ext.repo.lookup(q); (t + r).escapeSql()"), SQL, True, "", ""),
        (_section('val r = Ext.repo.lookup(q); (Ext.wrap(r) + "x").escapeSql()'), SQL, False, "", ""),
        (_section('val t = Ext.repo.lookup(q); template.format("$t")'), SQL, True, "", ""),
        (_section("q.trim().lowercase().escapeSql()"), SQL, True, "", ""),
        (_section('(q + "x").escapeSql()'), SQL, True, "", ""),
        (_section("q.length.toString()"), SQL, False, "", ""),
        (_section("q.toIntOrNull() ?: 0"), SQL, False, "", ""),
        (_section("q in items"), SQL, False, "", ""),
        (_section('template.replace(q, "x")'), SQL, False, "", ""),
        (_section('val tpl = String.format("%s", "name = {q}"); tpl.replace("{q}", q)'), SQL, True, "", ""),
        (
            _section(
                "tag.let { t -> audit.let { it.track(t) } }", host="button", pre="        val tag = q\n"
            ),
            SQL,
            False,
            "",
            "",
        ),
        (_section("q.let { audit.let { it.track(q) } }", host="button"), SQL, False, "", ""),
        (
            _section(
                "if (strict) { audit.record(q) } else if (q.isEmpty()) { audit.record(q) } "
                "else { val audit = q.trim(); println(audit) }",
                host="button",
            ),
            SQL,
            False,
            "",
            "",
        ),
        (
            _section('displayName().ifBlank { "1=1" }', pre="        saved = q\n"),
            SQL,
            True,
            '    private var saved = ""\n    private fun displayName(): String = saved',
            "",
        ),
        (
            _section("displayName()", pre="        saved = q\n"),
            SQL,
            True,
            '    private var saved = ""\n    private fun displayName(): String = saved',
            "",
        ),
        (
            _section("displayName().escapeSql()", pre="        saved = q\n"),
            SQL,
            True,
            '    private var saved = ""\n    private fun displayName(): String = saved',
            "",
        ),
        (
            _section("this.displayName()", pre="        saved = q\n"),
            SQL,
            True,
            '    private var saved = ""\n    private fun displayName(): String = saved',
            "",
        ),
    ],
)
def test_round_eleven_content_and_statements(
    body: str, rule: str, expected: bool, members: str, imports: str
) -> None:
    report = _notes(body, members=members, imports=imports)
    assert _hit(report, rule) is expected, report["findings"]


def test_string_constants_and_fields_of_other_files_are_templates_and_data() -> None:
    sql = (
        "app/src/main/java/com/example/notes/Sql.kt",
        "package com.example.notes\nobject Sql { const val BY_NAME = \"name = '%s'\" }\n"
        "const val TOP = \"name = '%s'\"\n"
        'object Session { var query: String = "" }\n',
    )

    def report(expr: str, pre: str = "") -> dict:
        source = NOTES.format(body=_section(expr, pre=pre), members="", imports="")
        return analyze_sources([("app/src/main/java/com/example/notes/Notes.kt", source), sql])

    assert _hit(report("Sql.BY_NAME.format(q)"), SQL)
    assert _hit(report("com.example.notes.Sql.BY_NAME.uppercase().format(q)"), SQL)
    assert _hit(report("TOP.format(q)"), SQL)
    assert _hit(report("Session.query.encodeForWeb()", pre="        Session.query = q.trim()\n"), SQL)
    assert _hit(
        report("com.example.notes.Session.query.encodeForWeb()", pre="        Session.query = q.trim()\n"),
        SQL,
    )
    java = analyze_sources(
        [
            (
                "app/Queries.java",
                'package com.example.app;\nclass Queries { static final String BY_NAME = "name = {q}"; }\n',
            ),
            (
                "app/R.java",
                """package com.example.app;
import android.content.Intent;
import android.webkit.WebView;
class R {
    WebView web;
    void go(Intent i) {
        String q = i.getStringExtra("q");
        String page = Markup.render(m -> { m.section(() -> Queries.BY_NAME.replace("{q}", q)); m.put("h", "x"); });
        web.loadUrl(page);
    }
}
""",
            ),
        ]
    )
    assert _hit(java, URL), java["findings"]


def test_primary_constructor_string_property_holding_input_is_data() -> None:
    report = _kotlin(
        """class R(private val db: SQLiteDatabase, private var query: String) {
    fun q(intent: Intent) {
        query = (intent.getStringExtra("q") ?: "").trim()
        val s = Markup.render { b -> b.section { query.escapeSql() }; b.append("SELECT 1"); Unit }
        db.execSQL(s)
    }
}
"""
    )
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "section, expected",
    [
        ("() -> TPL.formatted(q)", True),
        ('() -> Optional.ofNullable(q).orElse("x")', True),
        ("() -> { String t = Ext.lookup(q); return t.strip(); }", True),
        ("() -> PREFIX.concat(q)", True),
        ('() -> { String t = Ext.lookup(q); return t.formatted("x"); }', True),
        ("() -> q instanceof String", False),
        ("() -> String.valueOf(q.length())", False),
        ("() -> { int n = q.length(); return String.valueOf(n); }", False),
        ("() -> String.valueOf(q)", True),
        ("() -> Integer.toString(Integer.parseInt(q))", False),
        ("() -> q.isEmpty() ? 0 : q.length()", False),
    ],
)
def test_java_content_values(section: str, expected: bool) -> None:
    report = analyze_sources(
        [
            (
                "app/R.java",
                f"""package com.example.app;
import android.content.Intent;
import android.webkit.WebView;
import java.util.Optional;
class R {{
    static final String TPL = "https://docs.example.test/?q=%s";
    static final String PREFIX = "https://docs.example.test/?q=";
    WebView web;
    void go(Intent i) {{
        String q = i.getStringExtra("q");
        String page = Markup.render(m -> {{ m.section({section}); m.put("h", "x"); }});
        web.loadUrl(page);
    }}
}}
""",
            )
        ]
    )
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize(
    "section, expected",
    [
        ("let t = Ext.lookup(query); return t.lowercased()", True),
        ('guard let t = Optional(query) else { return "" }; return t.lowercased()', True),
    ],
)
def test_swift_closure_locals_through_string_transforms(section: str, expected: bool) -> None:
    body = (
        f'let page = Markup.render({{ b in b.section {{ {section} }}; b.add("x") }})\n'
        "        web.loadHTMLString(page, baseURL: nil)"
    )
    assert _hit(_swift(SWIFT_QUERY.format(body=body)), URL) is expected


def test_a_content_check_does_not_hide_later_reasons() -> None:
    report = _kotlin(
        """class R(private val db: SQLiteDatabase) {
    fun q(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val s = Markup.render { b -> b.section { q.trim() }; Unit }
        var t = 'a'
        t += 1
        db.execSQL(s + q + t)
    }
}
"""
    )
    # The content check's re-read is muted; the compound assignment after it still records its
    # own operator-dispatch reason.
    assert "compound assignment operator dispatch unavailable" in _reasons(report)


def test_deferred_writes_cost_linear_calls_in_nested_and_wide_callbacks() -> None:
    def calls(source_body: str) -> int:
        source = f"""class S(private val web: WebView) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        var u = "https://docs.example.test/"
{source_body}
        web.loadUrl(u)
    }}
}}
"""
        total = 0

        def profile(frame, event, arg) -> None:
            nonlocal total
            if event in {"call", "c_call"}:
                total += 1

        sys.setprofile(profile)
        try:
            report = _kotlin(source)
        finally:
            sys.setprofile(None)
        assert _hit(report, URL)  # the deferred writes are found, not only cheap
        return total

    def nested(depth: int) -> str:
        expr = '"https://docs.example.test/"'
        for _ in range(depth):
            expr = f"Ext.fetch {{ u = q; {expr} }}"
        return f"        u = {expr}"

    def wide(count: int) -> str:
        return "        u = Ext.fetch { " + "; ".join("u = q" for _ in range(count)) + '; "x" }'

    # Each callback is read once: nested callbacks cost about linear calls (each nested one was
    # walked again for every enclosing callback, and every assignment walked to the root). The
    # first analysis warms per-process caches, so both sizes are counted after it (5 times the
    # calls for 4 times the depth; walking each nested callback again made it 7 times).
    calls(nested(15))
    assert calls(nested(60)) < 6 * calls(nested(15))
    assert calls(wide(2000)) < 6 * calls(wide(500))


def test_glued_destructuring_lines_cost_linear_calls() -> None:
    def calls(depth: int) -> int:
        inner = "where(\"name = '$q'\")"
        for level in range(depth):
            inner = f'val (a{level}, b{level}) = pair\nwhere(run {{\n{inner}\n"x"\n}})'
        source = f"""class W(private val db: SQLiteDatabase) {{
    val pair = Pair(1, 2)
    fun q(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val sql = Db.query {{
{inner}
        }}
        db.execSQL(sql)
    }}
}}
"""
        total = 0

        def profile(frame, event, arg) -> None:
            nonlocal total
            if event in {"call", "c_call"}:
                total += 1

        sys.setprofile(profile)
        try:
            report = _kotlin(source)
        finally:
            sys.setprofile(None)
        assert _hit(report, SQL)
        return total

    # A glued destructuring declaration is no glued line of its own: re-entering it visited
    # the glued call's arguments twice, so nested ones doubled the work per level.
    assert calls(12) < 3 * calls(8)


@pytest.mark.parametrize(
    "body, rule, expected",
    [
        # numbers and flags held in a closure's names, a let parameter or a number's text
        (_section("val n = q.length; n.toString()"), SQL, False),
        (_section('val n = q.length; "$n results"'), SQL, False),
        (_section('val n = q.length; "${n + 1} results"'), SQL, False),
        (_section("val ok = q.isNotEmpty(); ok.toString()"), SQL, False),
        (_section("val n = q.length; (n * 2).toString()"), SQL, False),
        (_section("val n = q.length; val m = n + 1; m.toString()"), SQL, False),
        (_section("val n = q.toIntOrNull() ?: 0; n.toString()"), SQL, False),
        (_section('val n = q.length; val s = n.toString(); "$s items"'), SQL, False),
        (_section("val s = q.length.toString(); s.padStart(3)"), SQL, False),
        (_section('val n: Long? = q.toLongOrNull(); "$n"'), SQL, False),
        (_section('val n: Int = Ext.lookup(q); "$n results"'), SQL, False),
        (_section('val n: Long? = Ext.lookup(q); "$n"'), SQL, False),
        (_section('val n = q.length; val s = n.toString(16); "$s"'), SQL, False),
        (_section("val n = q.length; (n + q.length).coerceAtLeast(1)"), SQL, False),
        (_section('var n: Any = "${q.length} rows"; n = audit.find(q); n'), SQL, False),
        (_section("val n = q.length; n.toString(16)"), SQL, False),
        (_section("var n: Int; n = q.length; n.toString()"), SQL, False),
        (_section('val ok = q.isEmpty(); "flag=$ok"'), SQL, False),
        (_section('q.length.let { n -> "$n results" }'), SQL, False),
        (_section("q.length.let { it.toString() }"), SQL, False),
        (_section("with(q) { length.toString() }"), SQL, False),
        (_section("Integer.parseInt(q).toString()"), SQL, False),
        (_section("Math.max(1, q.length).toString()"), SQL, False),
        (_section("java.lang.Long.parseLong(q).toString()"), SQL, False),
        (
            _section(
                "val n = q.trim(); if (strict) { val n = q.length; n.toString() } else { audit.clear() }"
            ),
            SQL,
            False,
        ),
        (_section('val t = q.trim(); "$t results"'), SQL, True),
        (_section('val n = q.length; "$n $q"'), SQL, True),
        (_section('val n = q.length; "$n ${q.trim()}"'), SQL, True),
        (_section("val t = q.trim(); t.toString()"), SQL, True),
        (_section("var n: Any = q.length; n = q; n.toString()"), SQL, True),
        (_section("var n: Any; n = q.trim(); n.toString()"), SQL, True),
        (_section("val n = q.length; q.let { n -> n.trim() }"), SQL, True),
        (_section("val n = q.length; run { val n = q.trim(); n.uppercase() }"), SQL, True),
        (_section('val n = q.length; q.trim().let { n -> "$n" }'), SQL, True),
        (
            _section(
                "val n = q.length; if (strict) { val n = q.trim(); n.uppercase() } else { audit.clear() }"
            ),
            SQL,
            True,
        ),
        # a branch's own locals replace the closure's
        (
            _section("val t = q.trim(); if (strict) { val t = audit.find(q); t } else { audit.clear() }"),
            SQL,
            False,
        ),
        (_section("val t = q.trim(); if (strict) { t } else { audit.clear() }"), SQL, True),
        (_section("val n = q.length; if (strict) { n.toString() } else { audit.clear() }"), SQL, False),
        (_section('val n = q.length; return@section "$n results"'), SQL, False),
        (_section("val n = q.length; n.toString().also { println(it) }"), SQL, False),
        (_section('val n = q.length; with(audit) { "$n" }'), SQL, False),
        (_section('val n = q.length; run { "$n" }'), SQL, False),
        # `*To` mapping lambdas of maps store their result
        (_page("items.associateWith { it }.mapKeysTo(mutableMapOf()) { describe(it.key, q) }"), URL, False),
        (
            _page("items.associateWith { it }.mapValuesTo(mutableMapOf()) { describe(it.value, q) }"),
            URL,
            False,
        ),
    ],
)
def test_round_twelve_numbers_branches_and_mappings(body: str, rule: str, expected: bool) -> None:
    report = _notes(body)
    assert _hit(report, rule) is expected, report["findings"]


@pytest.mark.parametrize(
    "own, expr, expected",
    [
        ("    fun record(q: String): Int = q.length\n", "record(q)", False),
        ("    fun record(q: String): Int = q.length\n", "this.record(q)", False),
        ("    fun record(q: String): String = q.trim()\n", "record(q)", True),
    ],
)
def test_own_string_functions_are_read_by_their_class(own: str, expr: str, expected: bool) -> None:
    report = _kotlin(
        f"""class R(private val db: SQLiteDatabase) {{
{own}    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val s = Markup.render {{ b -> b.section {{ {expr} }}; b.append("SELECT 1"); Unit }}
        db.execSQL(s)
    }}
}}
class Other {{
    fun record(q: String): String = q
}}
"""
    )
    assert _hit(report, SQL) is expected, report["findings"]


def test_constructor_properties_and_inherited_templates() -> None:
    nullable = _kotlin(
        """class R(private val db: SQLiteDatabase, private var query: String?) {
    fun go(intent: Intent) {
        query = intent.getStringExtra("q")?.trim()
        val s = Markup.render { b -> b.section { query!!.escapeSql() }; b.append("SELECT 1"); Unit }
        db.execSQL(s)
    }
}
"""
    )
    assert _hit(nullable, SQL), nullable["findings"]
    for qualifier in ["this.", "super."]:
        inherited = _kotlin(
            f"""abstract class BaseDao {{ protected val byName = "name = '%s'" }}
class NotesDao(private val db: SQLiteDatabase) : BaseDao() {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val s = Markup.render {{ b -> b.section {{ {qualifier}byName.format(q) }}; b.append("SELECT 1"); Unit }}
        db.execSQL(s)
    }}
}}
"""
        )
        assert _hit(inherited, SQL), (qualifier, inherited["findings"])
    enum = _kotlin(
        """enum class Query(private val unused: Int) {
    BY_NAME(0);
    val tpl = "name = '%s'"
    fun go(intent: Intent, db: SQLiteDatabase) {
        val q = intent.getStringExtra("q") ?: ""
        val s = Markup.render { b -> b.section { this.tpl.format(q) }; b.append("SELECT 1"); Unit }
        db.execSQL(s)
    }
}
"""
    )
    assert _hit(enum, SQL), enum["findings"]
    # A plain constructor parameter is no property: the top-level template of that name is read.
    plain = _kotlin(
        """const val template = "name = '%s'"
class R(private val db: SQLiteDatabase, template: Int = Ext.default("var")) {
    fun go(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val s = Markup.render { b -> b.section { template.format(q) }; b.append("SELECT 1"); Unit }
        db.execSQL(s)
    }
}
"""
    )
    assert _hit(plain, SQL), plain["findings"]


@pytest.mark.parametrize(
    "section, members, expected",
    [
        (
            'guard let q2 = Optional(query) else { return "" }; guard let q2 else { return "" }; return q2',
            "",
            True,
        ),
        ('guard let t: String = Optional(query) else { return "" }; return t', "", True),
        (
            "return self.title()",
            '    var saved = ""\n    func title() throws -> String { return saved }\n',
            True,
        ),
        (
            "return try! self.title()",
            '    var saved = ""\n    func title() async throws -> String { return saved }\n',
            True,
        ),
        (
            "return self.maker()()",
            '    var saved = ""\n    func maker() -> () -> String { return { "x" } }\n',
            False,
        ),
        ('let n = query.count; return "\\(n) results"', "", False),
        ("let n = query.count; return n.description", "", False),
        ("let n = query.count; return String(n)", "", False),
        ('let n = Int(query) ?? 0; return "\\(n) results"', "", False),
        ('let n: Int = Int(query) ?? 0; return "\\(n) results"', "", False),
        ('let n: Int = self.lookup(query); return "\\(n) results"', "", False),
        ('let t = self.lookup(query); guard let t else { return "" }; return t', "", False),
        ('return "\\(query.count + 1) results"', "", False),
        ('let t = query.lowercased(); return "\\(t) results"', "", True),
        ("let t = query.lowercased(); return String(t)", "", True),
        ("let t = query.lowercased(); return t.description", "", True),
    ],
)
def test_swift_round_twelve_content(section: str, members: str, expected: bool) -> None:
    body = ("saved = query\n" if members else "") + (
        f'        let page = Markup.render({{ b in b.section {{ {section} }}; b.add("x") }})\n'
        "        web.loadHTMLString(page, baseURL: nil)"
    )
    source = SWIFT_QUERY.format(body=body).replace(
        "    let web = WKWebView()\n", "    let web = WKWebView()\n" + members
    )
    assert _hit(_swift(source), URL) is expected


@pytest.mark.parametrize(
    "own, expected", [("int record(String q) { return q.length(); }", False), ("", True)]
)
def test_java_own_string_methods_are_read_by_their_class(own: str, expected: bool) -> None:
    report = analyze_sources(
        [
            (
                "app/R.java",
                f"""package com.example.app;
import android.content.Intent;
import android.webkit.WebView;
class R {{
    WebView web;
    {own}
    void go(Intent i) {{
        String q = i.getStringExtra("q");
        String page = Markup.render(m -> {{ m.section(() -> record(q)); m.put("h", "x"); }});
        web.loadUrl(page);
    }}
}}
class Other {{
    String record(String q) {{ return q; }}
}}
""",
            )
        ]
    )
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize(
    "expr, declaration",
    [
        ("displayName()!!.escapeSql()", "private fun displayName(): String? = saved"),
        ("displayName().escapeSql()", "private fun displayName() : kotlin.String = saved"),
    ],
)
def test_own_functions_by_their_declared_return_type(expr: str, declaration: str) -> None:
    report = _notes(
        _section(expr, pre="        saved = q\n"), members=f'    private var saved = ""\n    {declaration}'
    )
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "body, rule, expected",
    [
        # glued lines after `in`, and two glued lines with the input on the first
        (_page("val known = q in items\n            where(\"t = '$q'\")"), URL, True),
        (
            _page('val n = Ext.size() ?: 20\n            where("t = \'$q\'")\n            where("1 = 1")'),
            URL,
            True,
        ),
        (
            _page('val (k, v) = Pair(1, 2)\n            where("t = \'$q\'")\n            where("1 = 1")'),
            URL,
            True,
        ),
        (
            _page('val big = q.length > 5\n            where("t = \'$q\'")\n            where("1 = 1")'),
            URL,
            True,
        ),
        # computed roots over a closure's call result joined with input
        (_section('val col = Ext.sortColumn(); ("$col = \'$q\'" + " LIMIT 1").escapeSql()'), SQL, True),
        (_section("val col = Ext.sortColumn(); (col + \" = '$q'\").escapeSql()"), SQL, True),
        (_section('val col = Ext.sortColumn(); (col + " = " + q.trim()).escapeSql()'), SQL, True),
        (_section('val col = Ext.sortColumn(); (col + intent.getStringExtra("x")).escapeSql()'), SQL, True),
        (_section('val col = Ext.sortColumn(); (Ext.quote(col, q) + " ASC").escapeSql()'), SQL, True),
        (_section("val t = q.trim(); val r = Ext.lookup(q); (Ext.wrap(t) + r).escapeSql()"), SQL, True),
        (_section('val r = Ext.lookup(q); (Ext.wrap(r) + "x").escapeSql()'), SQL, False),
        # String transforms of a call's result in with/run, and a nested block rebinding `this`
        (_section("with(Ext.lookup(q)) { uppercase() }"), SQL, True),
        (_section("Ext.lookup(q).run { trim() }"), SQL, True),
        (_section("with(Ext.lookup(q)) { with(Formatters.date) { format(createdAt) } }"), SQL, False),
        (_section("Ext.lookup(q).run { Formatters.date.run { format(createdAt) } }"), SQL, False),
        # a closure's local returned bare is the value its initializer or a later assignment is
        (_section("val t = Ext.lookup(q).trim(); t"), SQL, True),
        (_section("val sql = template.format(q); sql"), SQL, True),
        (_section("val r = Ext.lookup(q); val u = r.trim(); u"), SQL, True),
        (_section('val label = Ext.title.let { "$it: $q" }; label'), SQL, True),
        (_section("val t = Ext.lookup(q); return@section t"), SQL, False),
        (_section("val t = Ext.lookup(q).trim(); return@section t"), SQL, True),
        (_section("var clause: String? = null; if (strict) clause = \"tag = '$q'\"; clause"), SQL, True),
        (_section("var u = Ext.home(); if (strict) u = \"n = '$q'\"; u"), SQL, True),
        (_section('val sb = StringBuilder("n = \'").append(q).append("\'").toString(); sb'), SQL, True),
        (_section("val row = Ext.find(q); row"), SQL, False),
        # numbers in a branch, a number's operation, Java-style empty-text concatenation
        (_section("if (strict) 0 else q.length"), SQL, False),
        (_section("q.length.plus(1).toString()"), SQL, False),
        (_section('"" + q.length'), SQL, False),
        (_section('"size = " + q'), SQL, True),
        (_section("q.length * 2"), SQL, False),
        (_section("q.length /* rows */ + 1"), SQL, False),
        (_section("val n = q.length; (n + q.length).let { it.toString() }"), SQL, False),
        (_section('val n = if (strict) 0 else q.length; "$n"'), SQL, False),
        (_section("template.format(q.length)"), SQL, False),
        (_section("template.format(q)"), SQL, True),
        (_section('val t = q.trim(); val r = Ext.lookup(q); (Ext.join(t, r) + "x").escapeSql()'), SQL, True),
        (
            _section(
                'val t = q.trim(); val r = Ext.lookup(q); (Ext.join(r, "n = \'$t\'") + "x").escapeSql()'
            ),
            SQL,
            True,
        ),
        # template fills by argument name
        (_section('template.replace(newValue = q, oldValue = "{q}")'), SQL, True),
        (_section('template.replace(newValue = "x", oldValue = q)'), SQL, False),
        # String.format templates outside the closure
        (
            _section(
                'tpl.replace("{q}", q)', pre='        val tpl = String.format("%s = \'{q}\'", "name")\n'
            ),
            SQL,
            True,
        ),
    ],
)
def test_round_twelve_internal_review_fixtures(body: str, rule: str, expected: bool) -> None:
    report = _notes(body)
    assert _hit(report, rule) is expected, report["findings"]


@pytest.mark.parametrize(
    "callback, expected",
    [
        ('Ext.later { u = q }; "x"', True),
        ('Ext.later { Ext.after { u = q } }; "x"', True),
        ('var u = ""; if (c) { u = q }; u.length; "x"', False),
        ('var u = ""; Ext.later { u = q }; "x"', False),
    ],
)
def test_writes_in_nested_callbacks(callback: str, expected: bool) -> None:
    report = _kotlin(
        f"""class S(private val web: WebView) {{
    fun go(intent: Intent, c: Boolean) {{
        val q = intent.getStringExtra("q") ?: ""
        var u = "https://docs.example.test/"
        u = Ext.fetch {{ {callback} }}
        web.loadUrl(u)
    }}
}}
"""
    )
    assert _hit(report, URL) is expected, report["findings"]


def test_swift_multi_binding_shadows_only_its_then_block() -> None:
    body = (
        'var page = "https://docs.example.test/"\n'
        '        page = Ext.fetch { if let a = Ext.a(), var page = Ext.cached() { page = query; print(a, page) }; return "x" }\n'
        "        web.load(URLRequest(url: URL(string: page)!))"
    )
    assert not _hit(_swift(SWIFT_QUERY.format(body=body)), URL)


def test_string_members_through_supertypes_interfaces_and_companions() -> None:
    def report(files: list[tuple[str, str]]) -> dict:
        return analyze_sources(files)

    holder = (
        "app/src/main/java/com/example/notes/Sql.kt",
        "package com.example.notes\nclass Holder { companion object { const val COMP = \"name = '%s'\" } }\n",
    )
    notes = NOTES.format(body=_section("Holder.COMP.format(q)"), members="", imports="")
    assert _hit(report([("app/src/main/java/com/example/notes/Notes.kt", notes), holder]), SQL)
    base = (
        "app/src/main/java/com/example/notes/BaseRepo.kt",
        "package com.example.notes\nopen class BaseRepo { protected val byTitle = \"title = '%s'\" }\n",
    )
    for expr in ["byTitle.format(q)", "this.byTitle.format(q)"]:
        source = f"""package com.example.notes
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Notes(private val db: SQLiteDatabase) : BaseRepo() {{
    fun open(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
{_section(expr)}
    }}
}}
"""
        assert _hit(report([("app/src/main/java/com/example/notes/Notes.kt", source), base]), SQL), expr
    urls = (
        "app/src/main/java/com/example/app/Urls.java",
        'package com.example.app;\npublic interface Urls { String SEARCH = "https://docs.example.test/?q={q}"; }\n',
    )
    for section, supertype in [
        ('() -> Urls.SEARCH.replace("{q}", q)', ""),
        ('() -> SEARCH.replace("{q}", q)', " implements Urls"),
        ("() -> SEARCH.concat(q)", " implements Urls"),
    ]:
        page = f"""package com.example.app;
import android.content.Intent;
import android.webkit.WebView;
class Page{supertype} {{
    WebView web;
    void go(Intent i) {{
        String q = i.getStringExtra("q");
        String page = Markup.render(m -> {{ m.section({section}); m.put("h", "x"); }});
        web.loadUrl(page);
    }}
}}
"""
        assert _hit(report([("app/src/main/java/com/example/app/Page.java", page), urls]), URL), section
    # A class's own member of that name decides, also over a String elsewhere.
    collision = _kotlin(
        """class R(private val db: SQLiteDatabase, private val template2: java.text.MessageFormat) {
    fun go(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        val s = Markup.render { b -> b.section { template2.format(q) }; b.append("SELECT 1"); Unit }
        db.execSQL(s)
    }
}
class Other { val template2 = "x = %s" }
"""
    )
    assert not _hit(collision, SQL), collision["findings"]


@pytest.mark.parametrize(
    "section, expected",
    [
        ("return displayName().escaped()", True),
        ("return displayName()", True),
        ("return self.displayName().escaped()", True),
        ('return "size=\\(self.size)"', True),
    ],
)
def test_swift_own_string_functions_and_string_members_named_like_numbers(
    section: str, expected: bool
) -> None:
    source = f"""import UIKit
import WebKit
final class V {{
    let web = WKWebView()
    var saved = ""
    var size: String = "M"
    func displayName() -> String {{ return saved }}
    func application(_ app: UIApplication, open url: URL, options: [String: Any]) {{
        let query = url.absoluteString
        saved = query
        size = query
        let page = Markup.render {{ b in b.section {{ {section} }}; b.add("x"); return b.html }}
        web.loadHTMLString(page, baseURL: nil)
    }}
}}
"""
    assert _hit(_swift(source), URL) is expected


@pytest.mark.parametrize(
    "section, expected",
    [
        ("() -> getTitle()", True),
        ("() -> this.getTitle().intern()", True),
        ("() -> Ext.wrap(getTitle())", False),
    ],
)
def test_java_own_string_getters(section: str, expected: bool) -> None:
    source = f"""package com.example.app;
import android.content.Intent;
import android.webkit.WebView;
class R {{
    String title = "";
    WebView web;
    String getTitle() {{ return title; }}
    void go(Intent i) {{
        String q = i.getStringExtra("q");
        title = q;
        String page = Markup.render(m -> {{ m.section({section}); m.put("h", "x"); }});
        web.loadUrl(page);
    }}
}}
"""
    report = analyze_sources([("app/R.java", source)])
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize(
    "expr, members, pre",
    [
        ("this.size.escapeSql()", '    private var size: String = "M"', "        size = q\n"),
        ("\"size = '${this.size}'\"", '    private var size: String = "M"', "        size = q\n"),
        (
            "profileUrl().escapeSql()",
            '    private var handle = ""\n    private fun profileUrl() = "https://docs.example.test/" + handle',
            "        handle = q\n",
        ),
        (
            "this.displayName().escapeSql()",
            '    private var saved = ""\n    private fun displayName(): String = saved',
            "        saved = q\n",
        ),
        (
            "label().escapeSql()",
            '    private var saved = ""\n    private fun label() = saved',
            "        saved = q\n",
        ),
    ],
)
def test_own_string_members_and_functions_through_this(expr: str, members: str, pre: str) -> None:
    report = _notes(_section(expr, pre=pre), members=members)
    assert _hit(report, SQL), report["findings"]


def test_constructor_string_properties_cost_linear_calls() -> None:
    def calls(count: int) -> int:
        params = ", ".join(f"private var c{i}: String" for i in range(count))
        assigns = "\n".join(f"        c{i} = q.trim()" for i in range(count))
        reads = "; ".join(f"b.where {{ c{i}.escapeSql() }}" for i in range(count))
        source = f"""class R(private val db: SQLiteDatabase, {params}) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
{assigns}
        val s = Markup.render {{ b -> {reads}; Unit }}
        db.execSQL(s)
    }}
}}
"""
        total = 0

        def profile(frame, event, arg) -> None:
            nonlocal total
            if event in {"call", "c_call"}:
                total += 1

        sys.setprofile(profile)
        try:
            report = _kotlin(source)
        finally:
            sys.setprofile(None)
        assert _hit(report, SQL)
        return total

    # Each class body's members are read once: 4 times the properties cost about 4 times the
    # calls (reading the body on every lookup cost about 8 times).
    calls(10)
    assert calls(200) < 6 * calls(50)


# Round 13: independently reproduced review findings and their no-input controls.
REVIEW13_KOTLIN = """package com.example.notes
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.webkit.WebView
class Notes(private val db: SQLiteDatabase, private val web: WebView, private val strict: Boolean) {
    private val audit = Ext.audit
    private val repo = Ext.repo
    private val template = "name = '%s'"

    fun open(intent: Intent, items: List<String>) {
        val q = intent.getStringExtra("q") ?: ""
        val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }
        db.execSQL(s)
    }
}
"""


@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param('"${q.length}: ".plus(q)', True, id="plus_interpolation"),
        pytest.param("q.length.toString().plus(q)", True, id="plus_length"),
        pytest.param("val n = q.length; n.toString().plus(q)", True, id="plus_local"),
        pytest.param('val n = q.length; n.toString().plus(" for ").plus(q)', True, id="plus_chain"),
        pytest.param("q.length.plus(1).toString()", False, id="plus_numbers"),
        pytest.param(
            "val n = q.length; if (strict) { val n = q.trim(); n } else n.toString()",
            True,
            id="branch_shadow",
        ),
        pytest.param(
            "val n = q.length; val m = if (strict) { val n = q.trim(); n } else n.toString(); m",
            True,
            id="branch_local_value",
        ),
        pytest.param(
            'val n = q.length; if (strict) n.toString() else "0"', False, id="branch_number_fallback"
        ),
        pytest.param('"LIMIT %d".format(q.length)', False, id="format_literal"),
        pytest.param('String.format("LIMIT %d", q.length)', False, id="format_static"),
        pytest.param("val n = q.length; template.format(n)", False, id="format_local"),
        pytest.param(
            'val n = q.length; val s = String.format("LIMIT %d", n); s.trim()',
            False,
            id="format_local_then_trim",
        ),
        pytest.param("q.length.let { template.format(it) }", False, id="format_let"),
        pytest.param('"name = %s".format(q)', True, id="format_text"),
        pytest.param('String.format("name = %s", q)', True, id="format_static_text"),
        pytest.param('var n = q.length; n = n + 1; "$n rows"', False, id="counter"),
        pytest.param('var n: Any = q.length; n = n.toString() + q; "$n rows"', True, id="counter_text"),
        pytest.param('val n = q.length.coerceIn(1, 50); "$n rows"', False, id="coerce_bounds"),
        pytest.param('val n = q.length.coerceIn(1..50); "$n rows"', False, id="coerce_range"),
        pytest.param("q.length.toString().plus(q).trim()", True, id="coerce_text"),
        pytest.param('q.toInt().let { n -> "LIMIT $n" }', False, id="toint_let"),
        pytest.param("val n = q.length; with(n) { toString() }", False, id="with_count"),
        pytest.param("q.toInt().run { toString() }", False, id="run_count"),
        pytest.param("var c: String? = null; val t = q.trim(); if (strict) c = t; c", True, id="late_local"),
        pytest.param(
            "var c: String? = null; val r = repo.find(q); if (strict) c = r.trim(); c", True, id="late_result"
        ),
        pytest.param("var t = repo.find(q); t = t.trim(); t", True, id="self_result"),
        pytest.param(
            "var c: String? = null; if (strict) { val u = q.trim(); c = u }; c", True, id="branch_local"
        ),
        pytest.param(
            "var c: String? = null; if (strict) { val u = repo.find(q); c = u }; c",
            False,
            id="branch_result_control",
        ),
        pytest.param(
            'var c: String? = null; if (strict) { val u = q.trim(); c = "name = " + u }; c',
            True,
            id="branch_concat",
        ),
        pytest.param('val r = repo.find(q); val s = "name = " + r; s', True, id="concat_result"),
        pytest.param("val r = repo.find(q); val s = r; s", False, id="result_alias_control"),
        pytest.param("val r = repo.find(q); r", False, id="result_only_control"),
        pytest.param("val t = Ext.tracker; t.record(q)", False, id="service_property_control"),
        pytest.param("val a = requireNotNull(audit); a.record(q)", False, id="factory_control"),
        pytest.param("val a = checkNotNull(repo); a.record(q)", False, id="factory_check_control"),
        pytest.param("val xs = mutableListOf<String>(); xs.add(q)", False, id="collection_control"),
        pytest.param("val a = run { audit }; a.record(q)", False, id="service_run_control"),
        pytest.param("val a = with(repo) { audit }; a.record(q)", False, id="service_with_control"),
        pytest.param("val a = audit.also { it.enable() }; a.record(q)", False, id="service_also_control"),
        pytest.param("val a = audit.apply { enable() }; a.record(q)", False, id="service_apply_control"),
        pytest.param("val a = audit.takeIf { strict }; a.record(q)", False, id="service_select_control"),
        pytest.param(
            "var c: String? = null; q.takeIf { it.isNotBlank() }?.let { c = \"title = '$it'\" }; c",
            True,
            id="let_assignment",
        ),
        pytest.param(
            'var c: String? = null; q.trim().also { c = "title = " + it }; c', True, id="also_assignment"
        ),
        pytest.param('var c: String? = null; run { c = "title = " + q }; c', True, id="run_assignment"),
        pytest.param(
            'var c: String? = null; listOf(q).forEach { c = "title = " + it }; c',
            True,
            id="foreach_assignment",
        ),
        pytest.param(
            'val t = repo.find(q); if (strict) { var t = ""; t = q; println(t) }; t', False, id="block_shadow"
        ),
        pytest.param(
            'val t = repo.find(q); q.let { var t = ""; t = q; println(t) }; t', False, id="lambda_shadow"
        ),
        pytest.param('val r = repo.find(q); (r.ifBlank { q } + " x").escapeSql()', True, id="outer_lambda"),
        pytest.param(
            'val r = repo.find(q); (r.ifBlank { "none" } + " x").escapeSql()',
            False,
            id="outer_lambda_control",
        ),
        pytest.param(
            'val r = repo.find(q); (Ext.wrap(r, { q }) + "x").escapeSql()', True, id="outer_lambda_argument"
        ),
        pytest.param(
            'val t = q.trim(); val r = repo.find(q); (Ext.page(r, t.length) + "x").escapeSql()',
            False,
            id="outer_number",
        ),
    ],
)
def test_review13_kotlin(body: str, expected: bool) -> None:
    report = analyze_sources(
        [("app/src/main/java/com/example/notes/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))]
    )
    assert _hit(report, SQL) is expected, report["findings"]


REVIEW13_JAVA = """package com.example.notes;
import android.content.Intent;
import android.webkit.WebView;
class Page {
    static final String TPL = "https://docs.example.test/?q=%s";
    WebView web;

    void go(Intent i) {
        String q = i.getStringExtra("q");
        String page = Markup.render(m -> { m.section(REVIEW_BODY); m.put("h", "x"); });
        web.loadUrl(page);
    }
}
"""


@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param(
            "() -> { String url = null; String t = q.trim(); if (!t.isEmpty()) url = t; return url; }",
            True,
            id="forward",
        ),
        pytest.param(
            "() -> { String url; String t = q.trim(); if (q != null) { url = TPL + t; } else { url = TPL; } return url; }",
            True,
            id="forward_uninitialized",
        ),
        pytest.param(
            "() -> { String url = null; if (q != null) { String u = q.trim(); url = u; } return url; }",
            True,
            id="branch_local",
        ),
        pytest.param(
            "() -> { String url = null; if (q != null) { String u = Ext.find(q); url = u; } return url; }",
            False,
            id="branch_result_control",
        ),
        pytest.param(
            "() -> { String url = null; if (q != null) { String u = q.trim(); url = TPL + u; } return url; }",
            True,
            id="branch_concat",
        ),
        pytest.param(
            "() -> { String id = Ext.find(q); String url = TPL + id; return url; }", True, id="result_concat"
        ),
        pytest.param(
            "() -> { String id = Ext.find(q); String url = id; return url; }",
            False,
            id="result_alias_control",
        ),
        pytest.param("() -> Integer.toString(q.length()).concat(q)", True, id="integer_concat"),
        pytest.param('() -> Integer.toString(q.length()).concat("x")', False, id="integer_control"),
        pytest.param('() -> String.format("LIMIT %d", q.length())', False, id="format_literal"),
        pytest.param("() -> String.format(TPL, q.length())", False, id="format_named"),
        pytest.param("() -> { int n = q.length(); return TPL.formatted(n); }", False, id="format_local"),
        pytest.param(
            "() -> { String n = String.format(TPL, q.length()); return n.trim(); }",
            False,
            id="format_named_then_trim",
        ),
        pytest.param(
            '() -> { String r = Ext.find(q); return (Ext.or(r, () -> q) + "x").intern(); }',
            True,
            id="supplier_input",
        ),
        pytest.param(
            '() -> { String r = Ext.find(q); return (Ext.or(r, () -> "none") + "x").intern(); }',
            False,
            id="supplier_control",
        ),
        pytest.param("() -> q.isEmpty() ? q : String.valueOf(0)", True, id="ternary_then"),
        pytest.param(
            "() -> q.isEmpty() ? String.valueOf(q.length()) : String.valueOf(0)", False, id="ternary_number"
        ),
    ],
)
def test_review13_java(body: str, expected: bool) -> None:
    report = analyze_sources(
        [("app/src/main/java/com/example/notes/Page.java", REVIEW13_JAVA.replace("REVIEW_BODY", body))]
    )
    assert _hit(report, URL) is expected, report["findings"]


REVIEW13_SWIFT = """import UIKit
import WebKit
import Foundation
final class Router {
    let web = WKWebView()
    let template = "https://docs.example.org/search?q={q}"
    var saved = ""

    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        let query = url.absoluteString
        let page = Markup.render({ b in b.section { REVIEW_BODY }; b.add("x") })
        web.loadHTMLString(page, baseURL: nil)
        return true
    }
}
"""


@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param('return String(format: "%d", query.count)', False, id="format_count"),
        pytest.param('return String(format: "%@", query)', True, id="format_text"),
        pytest.param("return String(query.count).appending(query)", True, id="append_count"),
        pytest.param('return String(query.count).appending("x")', False, id="append_count_control"),
        pytest.param("var u: String? = nil; let t = query.lowercased(); u = t; return u", True, id="forward"),
        pytest.param(
            'let r = Store.find(query); let s = "https://docs.example.test/" + r; return s',
            True,
            id="result_concat",
        ),
        pytest.param("var t = Store.find(query); t = t.lowercased(); return t", True, id="self_result"),
        pytest.param(
            'let t = Store.find(query); if true { var t = ""; t = query; print(t) }; return t',
            False,
            id="shadow_control",
        ),
        pytest.param(
            'guard let t = Optional(query) else { return "" }; guard let t else { return "" }; return t',
            True,
            id="guard_alias",
        ),
    ],
)
def test_review13_swift(body: str, expected: bool) -> None:
    report = analyze_sources([("App/Router.swift", REVIEW13_SWIFT.replace("REVIEW_BODY", body))])
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize(
    "tail, expected",
    [
        ('val clause = "title = \'$q\'"\n            where(clause)\n            where("1 = 1")', True),
        ('val clause = prefix ?: quote(q)\n            where("kept")', False),
        ('val clause = prefix ?: quote("kept")\n            where(q)\n            where("1 = 1")', True),
    ],
)
def test_review13_glued_initializers_and_every_write(tail: str, expected: bool) -> None:
    body = (
        '        val sql = Db.query {\n            select("*")\n            '
        + tail
        + "\n        }\n        db.execSQL(sql)"
    )
    report = _notes(body, members="    private val prefix: String? = null")
    assert _hit(report, SQL) is expected, report["findings"]
    assert _state(report, SQL) != "partial"


def test_review13_qualified_nullable_constructor_string() -> None:
    source = REVIEW13_KOTLIN.replace(
        "private val strict: Boolean)", "private val strict: Boolean, private var title: kotlin.String?)"
    )
    source = source.replace(
        'val q = intent.getStringExtra("q") ?: ""',
        'val q = intent.getStringExtra("q") ?: ""\n        title = q.trim()',
    )
    report = analyze_sources([("app/Notes.kt", source.replace("REVIEW_BODY", "title!!.escapeSql()"))])
    assert _hit(report, SQL), report["findings"]


def test_review13_own_java_string_function_lookup_costs_linear_calls() -> None:
    def lookup_calls(count: int) -> int:
        methods = "\n".join(
            f'String title{i}(String q) {{ return "https://docs.example.test/" + q; }}' for i in range(count)
        )
        sections = "; ".join(f"m.section(() -> title{i}(q))" for i in range(count))
        source = REVIEW13_JAVA.replace("REVIEW_BODY", '() -> "safe"')
        source = source.replace("    WebView web;", "    WebView web;\n" + methods)
        source = source.replace('m.section(() -> "safe")', sections)
        total, active = 0, 0

        def profile(frame, event, arg) -> None:
            nonlocal total, active
            target = frame.f_code.co_name in {"string_function", "body_string_functions"}
            if event == "call":
                if target:
                    active += 1
                if active:
                    total += 1
            elif event == "return" and target:
                active -= 1

        sys.setprofile(profile)
        try:
            report = analyze_sources([("app/Page.java", source)])
        finally:
            sys.setprofile(None)
        assert _hit(report, URL)
        return total

    lookup_calls(5)
    assert lookup_calls(120) < 6 * lookup_calls(30)


@pytest.mark.parametrize(
    "body",
    [
        "() -> String.format(q, q.length())",
        "() -> { String saved = q; return String.format(saved, q.length()); }",
    ],
)
def test_review13_numeric_fills_keep_input_from_the_template(body: str) -> None:
    report = analyze_sources([("app/Page.java", REVIEW13_JAVA.replace("REVIEW_BODY", body))])
    assert _hit(report, URL), report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ("val n = q.length; template.format(n).trim()", False),
        ("val n = q.length; template.format(n).plus(q)", True),
        ('val n = q.length; val tpl = "LIMIT %d"; tpl.format(n).trim()', False),
        ('val n = q.length; String.format("LIMIT %d", n).trim()', False),
    ],
)
def test_review13_numeric_formats_through_transforms(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ("let n = query.count; return String(format: template, n).lowercased()", False),
        ("let tpl = query; return String(format: tpl, query.count)", True),
    ],
)
def test_review13_swift_named_formats(body: str, expected: bool) -> None:
    report = analyze_sources([("App/Router.swift", REVIEW13_SWIFT.replace("REVIEW_BODY", body))])
    assert _hit(report, URL) is expected, report["findings"]


def test_review13_numeric_replace_fill_is_no_content() -> None:
    body = 'val n = q.length; template.replace("%s", n.toString())'
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert not _hit(report, SQL), report["findings"]


# Round 14: lexical binding, supplier value and bounded-classification regressions.
@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param("val q = q.toString(); q", True, id="shadow_string"),
        pytest.param('val q = "$q"; q', True, id="shadow_short"),
        pytest.param('val q = "${q}"; q', True, id="shadow_long"),
        pytest.param('val q = q + 1; "$q"', True, id="shadow_plus"),
        pytest.param("val t = q.trim(); val q = t.length; t", True, id="later_shadow"),
        pytest.param("val q = q.length; q.toString()", False, id="shadow_number_control"),
        pytest.param("var row = q.length; val alias = row; row = alias; row", False, id="scalar_alias_cycle"),
        pytest.param(
            'var row = q.length; val alias = row; row = alias; "$row rows"', False, id="scalar_alias_template"
        ),
        pytest.param(
            "var row = repo.find(q); val alias = row; row = alias; row", False, id="object_alias_cycle"
        ),
        pytest.param("var row = repo.find(q); row = row; row", False, id="object_self_alias"),
        pytest.param("var row = q.trim(); val alias = row; row = alias; row", True, id="data_alias_cycle"),
        pytest.param(
            "val n = q.length; val text = q.trim(); template.format(n).plus(text)",
            True,
            id="format_local_fill",
        ),
        pytest.param("q.let { x -> template.format(q.length).plus(x) }", True, id="format_scope_fill"),
        pytest.param("q.let { template.format(q.length).plus(it) }", True, id="format_implicit_fill"),
        pytest.param("q.run { template.format(q.length).plus(this) }", True, id="format_receiver_fill"),
        pytest.param("with(q) { template.format(q.length).plus(this) }", True, id="format_with_fill"),
        pytest.param(
            "val text = q.trim(); q.length.toString().plus(text)", True, id="number_text_local_fill"
        ),
        pytest.param(
            'val text = "safe"; q.length.toString().plus(text)', False, id="number_text_constant_control"
        ),
        pytest.param(
            'val text = q.trim(); template.format(q.length).replace("x", text)',
            True,
            id="format_replace_fill",
        ),
        pytest.param(
            "var c: String? = null; q.let { c = it.trim() }; c", True, id="let_assignment_transform"
        ),
        pytest.param(
            "var c: String? = null; q.let { x -> c = x.uppercase() }; c", True, id="let_assignment_named"
        ),
        pytest.param(
            "var c: String? = null; q.let { x -> val text = x.trim(); c = text }; c",
            True,
            id="let_assignment_local",
        ),
        pytest.param("var c: String? = null; q.run { c = trim() }; c", True, id="run_assignment_transform"),
        pytest.param(
            "var c: String? = null; with(q) { c = trim() }; c", True, id="with_assignment_transform"
        ),
        pytest.param(
            "var c: String? = null; q.run { c = this.trim() }; c", True, id="run_assignment_explicit"
        ),
        pytest.param(
            "var c: String? = null; repo.find(q).let { c = it }; c", False, id="result_scope_alias_control"
        ),
        pytest.param(
            "var c: String? = null; repo.find(q).let { c = it.trim() }; c", True, id="result_scope_transform"
        ),
        pytest.param(
            'var c: String? = null; q.length.let { c = it.toString() }; "$c rows"',
            False,
            id="numeric_scope_assignment",
        ),
        pytest.param(
            "var c: String? = null; listOf(q).forEach { c = it.trim() }; c",
            True,
            id="foreach_assignment_transform",
        ),
        pytest.param(
            'var c: String? = null; val x = q.trim(); listOf("safe").forEach { x -> c = x }; c',
            False,
            id="foreach_shadow_control",
        ),
        pytest.param(
            'val row = repo.find(q); (Ext.or(row, { row + q }) + "x").escapeSql()', True, id="supplier_mixed"
        ),
        pytest.param(
            'val row = repo.find(q); (Ext.page(row, { q.length }) + "x").escapeSql()',
            False,
            id="supplier_number_control",
        ),
        pytest.param(
            'val row = repo.find(q); (Ext.page(row, { val n = q.length; n }) + "x").escapeSql()',
            False,
            id="supplier_number_local_control",
        ),
        pytest.param(
            'val row = repo.find(q); (Ext.or(row, { row }) + "x").escapeSql()',
            False,
            id="supplier_row_control",
        ),
        pytest.param(
            'val row = repo.find(q); (row.takeIf { q.isNotBlank() } ?: "-").escapeSql()',
            False,
            id="predicate_control",
        ),
        pytest.param("q.length.run { toString().padStart(3, '0') }", False, id="numeric_run_chain_control"),
        pytest.param("q.toInt().run { this.toString().trim() }", False, id="numeric_explicit_this_control"),
        pytest.param("with(q.length) { this.toString().trim() }", False, id="numeric_with_this_control"),
        pytest.param("template.format(q.length).run { trim() }", False, id="numeric_format_run_control"),
        pytest.param("with(template.format(q.length)) { trim() }", False, id="numeric_format_with_control"),
        pytest.param(
            'String.format(java.util.Locale.US, "LIMIT %d", q.length)', False, id="locale_number_control"
        ),
        pytest.param('String.format(java.util.Locale.US, "name = %s", q)', True, id="locale_input_fill"),
    ],
)
def test_review14_kotlin(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param(
            '() -> { int n = q.length(); return String.valueOf(n).concat("x"); }',
            False,
            id="valueof_local_constant",
        ),
        pytest.param(
            "() -> { int n = q.length(); return String.valueOf(n).trim(); }", False, id="valueof_local_trim"
        ),
        pytest.param(
            '() -> { int n = q.length(); return String.valueOf(n).replace("0", "x"); }',
            False,
            id="valueof_local_replace",
        ),
        pytest.param(
            "() -> { int n = q.length(); return String.valueOf(n).concat(q); }",
            True,
            id="valueof_local_input",
        ),
        pytest.param(
            "() -> { int n = q.length(); String text = q.trim(); return String.format(TPL, n).concat(text); }",
            True,
            id="format_local_fill",
        ),
        pytest.param(
            "() -> { String text = q.trim(); return Integer.toString(q.length()).concat(text); }",
            True,
            id="integer_local_fill",
        ),
        pytest.param(
            "() -> { String row = Ext.find(q); String alias = row; row = alias; return row; }",
            False,
            id="object_alias_cycle",
        ),
        pytest.param(
            "() -> { int row = q.length(); int alias = row; row = alias; return String.valueOf(row); }",
            False,
            id="scalar_alias_cycle",
        ),
        pytest.param(
            '() -> { String row = Ext.find(q); return (Ext.or(row, () -> row + q) + "x").intern(); }',
            True,
            id="supplier_mixed",
        ),
        pytest.param(
            '() -> { String row = Ext.find(q); return (Ext.or(row, () -> q.isEmpty() ? row : q) + "x").intern(); }',
            True,
            id="supplier_mixed_branch",
        ),
        pytest.param(
            '() -> { String row = Ext.find(q); return (Ext.page(row, () -> q.length()) + "x").intern(); }',
            False,
            id="supplier_number_control",
        ),
        pytest.param(
            '() -> { String row = Ext.find(q); return (Ext.page(row, () -> { int n=q.length(); return n; }) + "x").intern(); }',
            False,
            id="supplier_number_local_control",
        ),
        pytest.param(
            '() -> { String row = Ext.find(q); return (Ext.or(row, () -> { System.out.println(q); return row; }) + "x").intern(); }',
            False,
            id="supplier_log_control",
        ),
        pytest.param(
            '() -> { String row = Ext.find(q); return (Ext.or(row, () -> Ext.test(q) ? row : "safe") + "x").intern(); }',
            False,
            id="supplier_condition_control",
        ),
        pytest.param(
            '() -> String.format(java.util.Locale.US, "LIMIT %d", q.length())',
            False,
            id="locale_number_control",
        ),
        pytest.param('() -> String.format(java.util.Locale.US, "name = %s", q)', True, id="locale_input"),
        pytest.param(
            '() -> { java.util.Locale locale=java.util.Locale.US; return String.format(locale, "LIMIT %d", q.length()); }',
            False,
            id="locale_local_control",
        ),
    ],
)
def test_review14_java(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Page.java", REVIEW13_JAVA.replace("REVIEW_BODY", body))])
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        pytest.param("let query = String(query); return query", True, id="shadow_string"),
        pytest.param('let query = "\\(query)"; return query', True, id="shadow_template"),
        pytest.param("let query = query.description; return query", True, id="shadow_description"),
        pytest.param("let query = query.count; return String(query)", False, id="scalar_shadow_control"),
        pytest.param(
            "let text = query.lowercased(); return String(format: template, query.count).appending(text)",
            True,
            id="format_local_fill",
        ),
        pytest.param(
            "let text = query.lowercased(); return String(query.count).appending(text)",
            True,
            id="number_local_fill",
        ),
        pytest.param(
            "var row = Store.find(query); let alias = row; row = alias; return row",
            False,
            id="object_alias_cycle",
        ),
    ],
)
def test_review14_swift(body: str, expected: bool) -> None:
    report = analyze_sources([("App/Router.swift", REVIEW13_SWIFT.replace("REVIEW_BODY", body))])
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize(
    "tail, expected",
    [
        ('val clause = prefix ?: quote(q)\n            where("kept")\n            where("1 = 1")', False),
        ('val clause = prefix ?: quote("kept")\n            where(q)\n            where("1 = 1")', True),
    ],
)
def test_review14_multiple_glued_lines_keep_the_initializer(tail: str, expected: bool) -> None:
    source = (
        '        val sql = Db.query {\n            select("*")\n            '
        + tail
        + "\n        }\n        db.execSQL(sql)"
    )
    report = _notes(source, members="    private val prefix: String? = null")
    assert _hit(report, SQL) is expected, report["findings"]


def test_review14_locale_named_like_an_input_string_remains_input() -> None:
    source = REVIEW13_KOTLIN.replace(
        'val q = intent.getStringExtra("q") ?: ""',
        'val q = intent.getStringExtra("q") ?: ""\n        Locale.US = q',
    )
    source += '\nobject Locale { var US: String = "" }\n'
    source = source.replace("REVIEW_BODY", 'String.format(Locale.US, "suffix", q.length)')
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL), report["findings"]


def test_review14_classifier_work_cut_is_an_execution_gap(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("mobile_audit.source_analysis")
    monkeypatch.setattr(module, "MAX_CLOSURE_CLASSIFICATIONS", 5)
    body = "var out: String? = null; q.let { out = it.trim() }; out"
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _state(report, SQL) == "partial", report["coverage"]
    assert "closure value classification budget" in _reasons(report)
    assert "closure value classification budget" in report["metadata"]["native_flow"]["budget_reasons"]


def test_review14_nested_assignment_scopes_are_classified_once(monkeypatch: pytest.MonkeyPatch) -> None:
    count = 0
    original = Analyzer.closure_data_locals

    def counted(self, *args, **kwargs):
        nonlocal count
        count += 1
        assert count <= 100, "nested assignment classification recursively rescanned scopes"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Analyzer, "closure_data_locals", counted)
    depth = 13
    body = "; ".join(f"v{i} = q.trim()" for i in range(depth))
    for i in reversed(range(depth)):
        body = f"var v{i}: String? = null; if (strict) {{ {body} }}"
    body += "; v0"
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL), report["findings"]
    assert _state(report, SQL) == "checked"
    assert count <= 4 * depth


def test_review14_reverse_numeric_aliases_cost_linear_work(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Analyzer.closure_work
    calls = 0

    def counted(self):
        nonlocal calls
        calls += 1
        return original(self)

    monkeypatch.setattr(Analyzer, "closure_work", counted)

    def work(size: int) -> int:
        nonlocal calls
        calls = 0
        declarations = "; ".join(f"var v{i}: Any = 0" for i in range(size))
        writes = f"v{size - 1} = q.length; " + "; ".join(
            f"v{i} = v{i + 1}" for i in reversed(range(size - 1))
        )
        body = declarations + "; " + writes + '; "$v0 rows"'
        report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
        assert not _hit(report, SQL), report["findings"]
        assert _state(report, SQL) != "partial"
        return calls

    assert work(160) < 6 * work(40)


@pytest.mark.parametrize(
    "body, expected",
    [
        ('var row: Any = 0; row = q; val alias = row; "$alias"', True),
        ('var row: Any = q.length; row = repo.find(q); "$row"', True),
        ("q.length.let { n -> val n = n.toString(); n }", False),
        ("var c: String? = null; repo.find(q).run { c = this }; c", False),
        ("var c: String? = null; q.run { c = this }; c", True),
        ("var c: String? = null; c?.record(q)", False),
    ],
)
def test_review14_binding_kinds_follow_real_lexical_values(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ('var c: String? = null; val r=repo.find(q); c=r + "x"; c', True),
        ('if(strict) String.format("LIMIT %d", q.length) else "0"', False),
        ('val n=q.length; if(strict) n.plus(1) else "0"', False),
        ("q.length.toString().escapeSql()", False),
        ('val row=repo.find(q); (row.takeIf { Ext.accept(q) } ?: "-").escapeSql()', False),
        ('val row=repo.find(q); (Ext.page(row, { val n=q.length; n.toString() }) + "x").escapeSql()', False),
        ('var row: Any? = null; row=q.length; val alias=row; "$alias rows"', False),
    ],
)
def test_review14_survivor_kotlin_boundaries(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ("() -> { int n=q.length(); return String.valueOf(n).intern(); }", False),
        ("() -> { int n=q.length(); return Integer.toString(n).intern(); }", False),
        ("() -> String.valueOf(q).intern()", True),
        (
            '() -> { String row=Ext.find(q); return (Ext.or(row, () -> { String text=q.trim(); return text; }) + "x").intern(); }',
            True,
        ),
    ],
)
def test_review14_survivor_java_boundaries(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Page.java", REVIEW13_JAVA.replace("REVIEW_BODY", body))])
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize("expression", ["q", "q.trim()", '"$q"'])
def test_review14_format_overload_uses_the_shadowing_string(expression: str) -> None:
    source = REVIEW13_KOTLIN.replace(
        "    private val audit",
        "    private val locale: java.util.Locale = java.util.Locale.US\n    private val audit",
    )
    body = f'val locale={expression}; String.format(locale, "suffix", q.length)'
    report = analyze_sources([("app/Notes.kt", source.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize("subject", ["q", "q.trim()"])
def test_review14_format_overload_uses_the_bound_scope_parameter(subject: str) -> None:
    source = REVIEW13_KOTLIN.replace(
        "    private val audit",
        "    private val locale: java.util.Locale = java.util.Locale.US\n    private val audit",
    )
    body = f'{subject}.let {{ locale -> String.format(locale, "suffix", q.length) }}'
    report = analyze_sources([("app/Notes.kt", source.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL), report["findings"]


def test_review14_format_overload_keeps_a_bound_locale() -> None:
    body = 'java.util.Locale.US.let { loc -> String.format(loc, "LIMIT %d", q.length) }'
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert not _hit(report, SQL), report["findings"]


@pytest.mark.parametrize("helper", ["trim", "padStart", "replace"])
@pytest.mark.parametrize(
    "body",
    [
        "q.length.run { HELPER(q) }",
        "with(q.length) { HELPER(q) }",
        "var out: String? = null; q.length.run { out = HELPER(q) }; out",
    ],
)
def test_review15_project_string_helper_keeps_its_value(helper: str, body: str) -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", body.replace("HELPER", helper)).replace(
        "    private val audit",
        f"    private fun {helper}(value: String): String = value\n    private val audit",
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL), report["findings"]


def test_review15_numeric_scope_ignores_an_unrelated_helper() -> None:
    body = '"%d".format(q.length).run { trim() }'
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", body)
    source += '\nclass Other { fun trim(): String = "safe" }\n'
    report = analyze_sources([("app/Notes.kt", source)])
    assert not _hit(report, SQL), report["findings"]


def test_review15_numeric_scope_keeps_a_top_level_helper() -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", "q.length.run { trim(q) }")
    source += "\nfun trim(value: String): String = value\n"
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "expression, expected",
    [
        ('switch(q) { case "" -> row; default -> row; }', False),
        ("switch(Ext.code(q)) { case 0 -> row; default -> row; }", False),
        ('switch(q) { case "" -> row; default -> q; }', True),
        ('switch(q) { case "" -> { yield row; } default -> { yield row; } }', False),
        (
            'switch(q) { case "" -> { int n=q.length(); yield String.valueOf(n); } default -> { yield row; } }',
            False,
        ),
        ('switch(q) { case "" -> { String text=q.trim(); yield text; } default -> { yield row; } }', True),
    ],
)
def test_review15_java_supplier_reads_switch_values(expression: str, expected: bool) -> None:
    body = "() -> { String row=Ext.find(q); return (Ext.or(row, () -> " + expression + ') + "x").intern(); }'
    report = analyze_sources([("app/Page.java", REVIEW13_JAVA.replace("REVIEW_BODY", body))])
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize(
    "expression, expected",
    [
        ("when(val x=q.length) { row.length -> x.toString(); else -> x.toString() }", False),
        ("when(val x=repo.find(q)) { row -> x; else -> x }", False),
        ("when(val x=q.trim()) { row -> x; else -> x }", True),
        ('when(q.trim()) { "" -> row; else -> row }', False),
        ("when(val x=q.length) { row.length -> { val n=x; n.toString() }; else -> x.toString() }", False),
        ("when(val x=q.trim()) { row -> { val text=x; text }; else -> x }", True),
        ('val x=q; when(val x=x.length) { row.length -> "$x"; else -> "$x" }', False),
    ],
)
def test_review15_kotlin_supplier_binds_when_subjects(expression: str, expected: bool) -> None:
    body = "val row=repo.find(q); (Ext.or(row, { " + expression + ' }) + "x").escapeSql()'
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize("helper", ["_format", "`format value`"])
@pytest.mark.parametrize(
    "body, expected", [(' +HELPER(q); +"safe"; Unit', True), ('+HELPER("safe"); Unit', False)]
)
def test_review15_unary_dsl_write_accepts_valid_names(helper: str, body: str, expected: bool) -> None:
    source = REVIEW13_KOTLIN.replace(
        'Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        "Markup.render { " + body.replace("HELPER", helper) + " }",
    ).replace(
        "    private val audit",
        f"    private fun {helper}(s: String): String = s.trim()\n    private val audit",
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ('val safe="fixed"; template.format(safe, q.length)', False),
        ('val row=repo.find("safe"); template.format(row, q.length)', False),
        ("val text=q.trim(); template.format(text, q.length)", True),
        ("val row=repo.find(q); template.format(row, q.length)", True),
        ('val safe="fixed"; String.format("%s %d", safe, q.length)', False),
        ('val safe="fixed"; template.replace(q, safe)', False),
        ('val safe="fixed"; template.replace(safe, q)', True),
        ('val text=q.trim(); ("$text" + "suffix").trim()', True),
        ('val text="safe"; ("$text" + "suffix").trim()', False),
    ],
)
def test_review15_template_fills_use_actual_input(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize("fill, expected", [('"safe"', False), ("q", True)])
def test_review15_java_formatted_number_keeps_scalar_context(fill: str, expected: bool) -> None:
    body = "() -> { int n=q.length(); return String.valueOf(n).formatted(" + fill + "); }"
    report = analyze_sources([("app/Page.java", REVIEW13_JAVA.replace("REVIEW_BODY", body))])
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            """val row=repo.find(q); (Ext.wrap(row) { sb -> sb.append(q); sb.append("'") } + "x").escapeSql()""",
            True,
        ),
        ('val row=repo.find(q); (Ext.wrap(row) { sb -> sb.append("safe") } + "x").escapeSql()', False),
        (
            'val row=repo.find(q); (Ext.pick(row) { if(strict) return@pick row; audit.last=q } + "x").escapeSql()',
            False,
        ),
        (
            'val row=repo.find(q); (Ext.pick(row) { if(strict) return@pick row; val text=q } + "x").escapeSql()',
            False,
        ),
        ('val row=repo.find(q); (Ext.pick(row) { if(strict) audit.record(q) } + "x").escapeSql()', False),
    ],
)
def test_review15_supplier_separates_writes_from_unit(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize("value, expected", [("q", True), ('"safe"', False)])
def test_review15_java_supplier_keeps_parameter_writes(value: str, expected: bool) -> None:
    body = (
        "() -> { String row=Ext.find(q); return (Ext.wrap(row, sb -> { sb.append("
        + value
        + '); }) + "x").intern(); }'
    )
    report = analyze_sources([("app/Page.java", REVIEW13_JAVA.replace("REVIEW_BODY", body))])
    assert _hit(report, URL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body",
    [
        "var c: String?=null; val q=with(q) { c=this; repo.find(this) }; c",
        "var c: String?=null; val q=q.let { c=it; repo.find(it) }; c",
        "var c: String?=null; val q=run { val text=q; c=text; repo.find(text) }; c",
    ],
)
def test_review15_initializer_nested_records_read_the_outer_name(body: str) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ("q.run { db.execSQL(trim()) }", True),
        ("with(q) { buildString { db.execSQL(trim()) } }", False),
        ("with(q) { buildString { append(q); db.execSQL(trim()) } }", True),
        ("with(q) { buildList { db.execSQL(trim()) } }", True),
        ("with(q) { buildString { with(q) { db.execSQL(trim()) } } }", True),
    ],
)
def test_review15_direct_sink_uses_the_nearest_applicable_receiver(body: str, expected: bool) -> None:
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize("subject, expected", [("q.length", False), ("q.trim()", True)])
def test_review15_when_assignment_uses_its_subject_binding(subject: str, expected: bool) -> None:
    body = "var c: String?=null; when(val x=" + subject + ') { else -> c="$x" }; c'
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize("value", ["q.trim()", '"$q"'])
def test_review15_string_local_replaces_a_scope_locale_alias(value: str) -> None:
    body = (
        "java.util.Locale.US.let { locale -> run { val locale="
        + value
        + '; String.format(locale, "suffix", q.length) } }'
    )
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "body",
    [
        'val locale: java.util.Locale=java.util.Locale.forLanguageTag(q); String.format(locale, "LIMIT %d", q.length)',
        'java.util.Locale.forLanguageTag(q).let { locale -> String.format(locale, "LIMIT %d", q.length) }',
    ],
)
def test_review15_locale_is_not_an_inserted_value(body: str) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert not _hit(report, SQL), report["findings"]


def test_review15_when_subject_initializer_reads_the_outer_name() -> None:
    body = "var c: String?=null; when(val q=with(q) { c=this; repo.find(this) }) { else -> c }; c"
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize("assignment, expected", [("q", True), ("1", False)])
def test_review15_callback_context_tracks_captured_kinds(assignment: str, expected: bool) -> None:
    body = (
        'var a: Any=q.length; val row=repo.find(q); val child=(Ext.or(row, { a }) + "x").escapeSql(); a='
        + assignment
        + "; child"
    )
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


def test_review15_callback_parameter_hides_a_captured_data_name() -> None:
    body = 'val x=q.trim(); val row=repo.find(q); (Ext.or(row, { x -> if(strict) row else x }) + "x").escapeSql()'
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert not _hit(report, SQL), report["findings"]


@pytest.mark.parametrize("receiver, expected", [('repo.find("safe")', False), ('"field=%s"', True)])
def test_review15_template_kind_does_not_override_a_shadowing_value(receiver: str, expected: bool) -> None:
    body = "val template=" + receiver + "; template.format(q).escapeSql()"
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


def test_review15_branch_initializers_share_the_lexical_graph(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Analyzer.classify_closure_locals
    builds = 0

    def counted(self, *args, **kwargs):
        nonlocal builds
        builds += 1
        assert builds <= 8, "nested initializer branches rebuilt their enclosing graph"
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Analyzer, "classify_closure_locals", counted)
    depth = 16
    declaration = f"val v{depth}=r"
    for index in reversed(range(depth)):
        declaration = f"val v{index}=if(strict) {{ {declaration}; v{index + 1} }} else r"
    body = f"val r=repo.find(q); {declaration}; v0"
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert not _hit(report, SQL), report["findings"]
    assert _state(report, SQL) == "checked", report["coverage"]
    assert builds <= 2


def test_review15_classification_keeps_distinct_frames(monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("mobile_audit.source_analysis")
    original = Analyzer.classify_closure_locals
    checked = False

    def compare(self, closure, frame, *args, **kwargs):
        nonlocal checked
        classified = original(self, closure, frame, *args, **kwargs)
        if not checked and "piece" in classified[0]:
            checked = True
            alternate = module.Frame(
                values={"q": module.Value(type_name="String")},
                types={"q": "String"},
                local_names={"q"},
            )
            visited = self.visited_values
            self.visited_values = {}
            try:
                other = self.closure_data_locals(closure, alternate, *args, **kwargs)
            finally:
                self.visited_values = visited
            assert "piece" not in other[0], "classification reused another frame's input"
        return classified

    monkeypatch.setattr(Analyzer, "classify_closure_locals", compare)
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", "val piece=q.trim(); piece")
    report = analyze_sources([("app/Notes.kt", source)])
    assert checked and _hit(report, SQL), report["findings"]


# Round 16: supported receiver signatures, visited fills and ordered bindings.
@pytest.mark.parametrize(
    "operation",
    [
        "lowercase()",
        "uppercase()",
        "format(1)",
        'replace("a", "b")',
        'replaceFirst("a", "b")',
        'substringBefore("a")',
        "trimIndent()",
        'plus("x")',
    ],
)
@pytest.mark.parametrize("outer_input", [True, False])
def test_review16_string_only_calls_keep_the_outer_receiver(operation: str, outer_input: bool) -> None:
    outer, inner = ("q", '"safe"') if outer_input else ('"safe"', "q")
    body = f"with({outer}) {{ buildString {{ append({inner}); db.execSQL({operation}) }} }}"
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is outer_input, report["findings"]


@pytest.mark.parametrize(
    "operation, inner_owns",
    [
        ("trim().toString()", True),
        ("padStart(3).toString()", True),
        ("take(1).toString()", True),
        ('removePrefix("a").toString()', True),
        ('replace(Regex("a"), "b")', True),
        ('replace("a".toRegex(), "b")', True),
        ('replace(0, 0, "b").toString()', True),
        ('replace("a", "b")', False),
    ],
)
@pytest.mark.parametrize("inner_input", [True, False])
def test_review16_charsequence_and_replace_overloads(
    operation: str, inner_owns: bool, inner_input: bool
) -> None:
    outer, inner = ('"safe"', "q") if inner_input else ("q", '"safe"')
    body = f"with({outer}) {{ buildString {{ append({inner}); db.execSQL({operation}) }} }}"
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is (inner_input if inner_owns else not inner_input), report["findings"]


@pytest.mark.parametrize(
    "operation, collection_owns",
    [
        ("trim().toString()", False),
        ("repeat(2)", False),
        ("take(1).toString()", True),
        ("toString()", True),
    ],
)
@pytest.mark.parametrize("list_input", [True, False])
def test_review16_intervening_collection_uses_the_applicable_receiver(
    operation: str, collection_owns: bool, list_input: bool
) -> None:
    text, item = ('"safe"', "q") if list_input else ("q", '"safe"')
    body = f'with("safe") {{ buildString {{ append({text}); buildList {{ add({item}); db.execSQL({operation}) }} }} }}'
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is (list_input if collection_owns else not list_input), report["findings"]


@pytest.mark.parametrize("name", ["trim", "toString", "minus", "coerceAtLeast"])
@pytest.mark.parametrize("scope", ["q.length.run { CALL }", "with(q.length) { CALL }"])
@pytest.mark.parametrize(
    "returned, value, expected",
    [("String", "v", True), ("String", '"safe"', False), ("Int", "7", False), ("Boolean", "true", False)],
)
def test_review16_project_return_wins_over_numeric_name_shortcuts(
    name: str, scope: str, returned: str, value: str, expected: bool
) -> None:
    body = scope.replace("CALL", f"{name}(q)")
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", body).replace(
        "    fun open(",
        f"    private fun {name}(v: String): {returned} = {value}\n    fun open(",
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ('guard let a = Optional(Optional(query)), let t = a else { return "" }; return t', True),
        (
            'guard let a = Optional(Optional(query)) else { return "" }; guard let t = a else { return "" }; return t',
            True,
        ),
        ('let t=query; guard let t=Optional(t) else { return "" }; return t', True),
        ('guard let a = Optional(Optional("safe")), let t = a else { return "" }; return t', False),
        ('let t = query.lowercased(); return String(format: "%@", t)', True),
        ('let t = query.lowercased(); let s = String(format: "%@", t); return s', True),
        ('let t = query.count; return String(format: "%d", t)', False),
        ('let t = "safe"; return String(format: "%@", t)', False),
    ],
)
def test_review16_swift_guard_clauses_and_local_format_fills(body: str, expected: bool) -> None:
    report = analyze_sources([("App/Router.swift", REVIEW13_SWIFT.replace("REVIEW_BODY", body))])
    assert _hit(report, URL) is expected, report["findings"]
    assert _state(report, URL) == "checked", report["coverage"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ("template.run { format(q) }", True),
        ("with(template) { format(q) }", True),
        ("template.let { it.format(q) }", True),
        ("template.run { format(q.length) }", False),
        ("with(template) { format(q.length) }", False),
        ('template.run { format("safe") }', False),
        ("template.run { trim() }", False),
    ],
)
def test_review16_receiverless_format_uses_its_visited_template(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "value, expected", [("row", False), ('"safe"', False), ("q", True), ("q.length", False)]
)
@pytest.mark.parametrize(
    "write", ["sb.append(VALUE)", "sb.text = VALUE", "sb.append(buildString { append(VALUE) })"]
)
def test_review16_supplied_writes_preserve_the_call_result_boundary(
    value: str, expected: bool, write: str
) -> None:
    body = (
        "val row=repo.find(q); (Ext.wrap(row) { sb -> "
        + write.replace("VALUE", value)
        + ' } + "x").escapeSql()'
    )
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


def test_review16_sibling_context_lookup_work_is_bounded() -> None:
    def calls(count: int) -> int:
        probes = 0

        def profile(frame, event, arg):
            nonlocal probes
            if event == "call" and frame.f_code.co_name == "reuse_context":
                probes += 1

        previous = sys.getprofile()
        sys.setprofile(profile)
        try:
            body = (
                "val row=repo.find(q); "
                + "".join(f'val a{i}=(Ext.or(row, {{ row }})+"x").escapeSql(); ' for i in range(count))
                + '(a0 + "x").escapeSql()'
            )
            report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
        finally:
            sys.setprofile(previous)
        assert not _hit(report, SQL), report["findings"]
        assert _state(report, SQL) == "checked", report["coverage"]
        return probes

    small = calls(40)
    assert calls(160) <= 6 * max(small, 1)


@pytest.mark.parametrize("name", ["minus", "coerceAtLeast", "toString"])
def test_review16_applicable_numeric_operation_stays_numeric(name: str) -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", f"q.length.run {{ {name}(q.length) }}").replace(
        "    fun open(",
        f"    private fun {name}(v: Int): String = v.toString()\n    fun open(",
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert not _hit(report, SQL), report["findings"]


@pytest.mark.parametrize("scope", ["q.length.run { trim() }", "with(q.length) { trim() }"])
@pytest.mark.parametrize("returned, value", [("String", '"safe"'), ("Int", "7"), ("Boolean", "true")])
def test_review16_inputfree_zero_argument_helper_keeps_its_actual_result(
    scope: str, returned: str, value: str
) -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", scope).replace(
        "    fun open(",
        f"    private fun trim(): {returned} = {value}\n    fun open(",
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert not _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ("val text=q.trim(); return@section text; template.plus(text)", True),
        (
            'val x=q.trim(); val row=repo.find(q); (Ext.or(row, { val part=Ext.audit.let { x -> x.track(q) }; part })+"x").escapeSql()',
            False,
        ),
        (
            'val row=repo.find(q); (Ext.or(row, { val part=with(Formatters.date) { row }; part })+"x").escapeSql()',
            False,
        ),
        (
            'val row=repo.find(q); (Ext.or(row, { val part=repo.find(q).let { t -> t }; part })+"x").escapeSql()',
            False,
        ),
        (
            'val row=repo.find(q); (Ext.or(row, { val part=with(repo.find(q)) { trim() }; part })+"x").escapeSql()',
            True,
        ),
        (
            'val row=repo.find(q); (Ext.or(row, { val part=repo.find(q).run { trim() }; part })+"x").escapeSql()',
            True,
        ),
        (
            'val n=q.length; val row=repo.find(q); (Ext.or(row, { val part=q.length.let { n -> n.toString() }; part })+"x").escapeSql()',
            False,
        ),
        (
            'val n=q.length; val row=repo.find(q); (Ext.or(row, { val part=template.format(q).let { n -> n.trim() }; part })+"x").escapeSql()',
            True,
        ),
        ('val n=q.length; val row=repo.find(q); (Ext.or(row, { val n=q.trim(); n })+"x").escapeSql()', True),
        (
            'val n=q.length; val row=repo.find(q); (Ext.or(row, { val part=if(strict) { n.toString() } else { Ext.safe() }; part })+"x").escapeSql()',
            False,
        ),
        (
            'val row=repo.find(q); (Ext.or(row, { val part=with(row) { with(Formatters.date) { format(createdAt) } }; part })+"x").escapeSql()',
            False,
        ),
        (
            'val row=repo.find(q); (Ext.or(row, { val part=row.run { Formatters.date.run { format(createdAt) } }; part })+"x").escapeSql()',
            False,
        ),
        (
            'val row=repo.find(q); (Ext.or(row, { val part=template.format(q.length).run { trim() }; part })+"x").escapeSql()',
            False,
        ),
    ],
)
def test_review16_captured_kinds_in_fallback_scope_initializers(body: str, expected: bool) -> None:
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]
    assert _state(report, SQL) == "checked", report["coverage"]


def test_review16_guard_else_reads_the_pre_guard_binding(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Analyzer.classify_closure_locals
    checked = False

    def classify(self, closure, frame, *args, **kwargs):
        nonlocal checked
        result = original(self, closure, frame, *args, **kwargs)
        if (
            not checked
            and self.closure_classification_work is not None
            and "guard let a" in self.text(closure)
        ):
            pending = [closure]
            guard = None
            while pending:
                part = pending.pop()
                if part.type == "guard_statement":
                    guard = part
                    break
                pending.extend(part.named_children)
            if guard is not None:
                alternative = self.swift_clauses(guard)[2]
                assert alternative is not None
                checked = True
                positions = list(args)
                options = dict(kwargs)
                if len(positions) > 5:
                    positions[5] = alternative
                else:
                    options["at"] = alternative
                held = original(self, closure, frame, *positions, **options)
                assert "a" not in held[0] and "a" in held[1], held
                assert "a" in result[0], result
        return result

    monkeypatch.setattr(Analyzer, "classify_closure_locals", classify)
    body = "let a=Store.find(query); guard let a=Optional(query) else { return a }; return a"
    report = analyze_sources([("App/Router.swift", REVIEW13_SWIFT.replace("REVIEW_BODY", body))])
    assert checked and _hit(report, URL), report["findings"]


def test_review16_traced_object_helper_can_still_become_text() -> None:
    source = (
        REVIEW13_KOTLIN.replace("REVIEW_BODY", "q.length.run { val box=trim(q); box.toString() }").replace(
            "    fun open(",
            "    private fun trim(v: String): Holder = Holder(v)\n    fun open(",
        )
        + "\nclass Holder(val value: String)\n"
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ("template.run { val s=format(q); ping(); s }", True),
        (
            'val row=repo.find(q); val part=(Ext.wrap(row) { sb -> sb.append(q) }+"x").escapeSql(); ping(); part',
            True,
        ),
        (
            'val row=repo.find(q); (Ext.wrap(row) { sb -> sb.append(buildString { append(q.length); ping() }) }+"x").escapeSql()',
            False,
        ),
    ],
)
def test_review16_native_calls_restore_closure_provenance(body: str, expected: bool) -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", body).replace(
        "    fun open(",
        '    private fun ping(): String = "safe"\n    fun open(',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize("method", ["replace", "replaceFirst"])
@pytest.mark.parametrize(
    "arguments", ['Regex("a"), "b"', 'regex=Regex("a"), replacement="b"', 'replacement="b", regex=Regex("a")']
)
@pytest.mark.parametrize("inner_input", [True, False])
def test_review17_named_regex_arguments_keep_the_receiver(
    method: str, arguments: str, inner_input: bool
) -> None:
    outer, inner = ('"safe"', "q") if inner_input else ("q", '"safe"')
    body = f"with({outer}) {{ buildString {{ append({inner}); db.execSQL({method}({arguments})) }} }}"
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is inner_input, report["findings"]


@pytest.mark.parametrize("initializer", ["0", "minOf(0, 1)", "maxOf(0, 0)", "0 + 0"])
@pytest.mark.parametrize("inner_input", [True, False])
def test_review17_inferred_integer_indices_select_the_builder(initializer: str, inner_input: bool) -> None:
    outer, inner = ('"safe"', "q") if inner_input else ("q", '"safe"')
    body = f'with({outer}) {{ buildString {{ append({inner}); val idx={initializer}; db.execSQL(replace(idx,0,"fixed").toString()) }} }}'
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is inner_input, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        ('val s2=buildString { with("safe") { replace(0,0,q) } }; db.execSQL(s2)', True),
        ('val s2=buildString { with("safe") { replace(0,0,"fixed") } }; db.execSQL(s2)', False),
        ('val s2=buildString { with("safe") { replace("a",q) } }; db.execSQL(s2)', False),
        (
            'with("safe") { buildString { append(q); with("safe") { db.execSQL(replace(0,0,"fixed").toString()) } } }',
            True,
        ),
    ],
)
def test_review17_inapplicable_string_does_not_hide_builder_replace(body: str, expected: bool) -> None:
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "write", ["sb.append(VALUE)", "Fill.into(sb, VALUE)", "sb.append(buildString { append(VALUE) })"]
)
@pytest.mark.parametrize(
    "value, expected", [("row", False), ("row.trim()", True), ("row.length", False), ("this.saved", True)]
)
def test_review17_written_content_keeps_transforms_and_qualified_fields(
    write: str, value: str, expected: bool
) -> None:
    body = (
        "val row=repo.find(q); (Ext.wrap(row) { sb -> "
        + write.replace("VALUE", value)
        + ' }+"x").escapeSql()'
    )
    source = (
        REVIEW13_KOTLIN.replace("REVIEW_BODY", body)
        .replace("    fun open(", '    private var saved=""\n    fun open(')
        .replace("val s = Markup.render", "saved=q.trim(); val s = Markup.render")
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "tail, expected",
    [
        ("appendSql(q)", True),
        ('if(strict) { appendSql(q) } else { append("safe") }', True),
        ("append(row)", False),
        ("append(q.length)", False),
        ('appendSql("safe")', False),
    ],
)
def test_review17_builder_final_extension_contributes_its_value(tail: str, expected: bool) -> None:
    body = "val row=repo.find(q); (row + buildString { " + tail + " }).escapeSql()"
    report = analyze_sources([("app/Notes.kt", REVIEW13_KOTLIN.replace("REVIEW_BODY", body))])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "method, member",
    [("toString", 'override fun toString(): String="Notes"'), ("trim", 'private fun trim(): String="safe"')],
)
@pytest.mark.parametrize("scope", ["q.run { CALL }", "with(q) { CALL }"])
def test_review17_string_receiver_precedes_outer_class_helper(method: str, member: str, scope: str) -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", scope.replace("CALL", method + "()")).replace(
        "    fun open(", "    " + member + "\n    fun open("
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL), report["findings"]


def test_review17_local_function_precedes_string_receiver() -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", "q.run { trim() }").replace(
        "val s = Markup.render", 'fun trim():String="safe"; val s = Markup.render'
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert not _hit(report, SQL), report["findings"]


@pytest.mark.parametrize("fill, expected", [("q", True), ("q.length", False)])
def test_review17_standard_format_precedes_outer_helper(fill: str, expected: bool) -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", "template.run { format(" + fill + ") }").replace(
        "    fun open(", '    private fun format(v: Any): String="safe"\n    fun open('
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "body, expected",
    [
        (
            'val row=repo.find(q); val part=(Ext.wrap(row) { sb -> sb.append(row.trim()) }+"x").escapeSql(); ping(); part',
            True,
        ),
        ("val row=repo.find(q); val part=(row+buildString { appendSql(q) }).escapeSql(); ping(); part", True),
        ("val n=0; q.length.run { val n=q; toString(n) }", True),
    ],
)
def test_review17_provenance_and_inferred_types_survive_scope_changes(body: str, expected: bool) -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", body).replace(
        "    fun open(",
        '    private fun ping():String="safe"\n    private fun toString(v:String):String=v\n    fun open(',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "member, call, expected",
    [
        ("private fun minus():String=captured", "minus()", True),
        ("private fun coerceAtLeast():String=captured", "coerceAtLeast()", True),
        ("private fun coerceIn():String=captured", "coerceIn()", True),
        ("private fun inc(v:Int):String=captured", "inc(q.length)", True),
        ("private fun dec(v:Int):String=captured", "dec(0)", True),
        ("private fun minus(value:Int):String=captured", "minus(value=q.length)", True),
        ("private fun minus(other:Int):String=captured", "minus(other=q.length)", False),
        ("private fun toString(v:Boolean):String=captured", "toString(q.isNotEmpty())", True),
        ("private fun toString(v:Double):String=captured", "toString(1.0)", True),
        ("private fun coerceAtLeast(v:Boolean):String=captured", "coerceAtLeast(q.isNotEmpty())", True),
        ("private fun coerceIn(v:Int):String=captured", "coerceIn(0)", True),
        ("private fun coerceIn(range:IntRange):String=captured", "coerceIn(range=0..2)", False),
    ],
)
def test_review17_numeric_precedence_requires_a_matching_signature(
    member: str, call: str, expected: bool
) -> None:
    source = (
        REVIEW13_KOTLIN.replace("REVIEW_BODY", "q.length.run { " + call + " }")
        .replace("    fun open(", '    private var captured=""\n    ' + member + "\n    fun open(")
        .replace("val s = Markup.render", "captured=q; val s = Markup.render")
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize(
    "builder, writer", [("flow", "emit"), ("sequence", "yield"), ("buildJsonObject", 'put("value",')]
)
def test_review17_protocol_builder_string_does_not_read_emitted_values(builder: str, writer: str) -> None:
    statement = writer + "q)" if writer.endswith(",") else writer + "(q)"
    body = f'with("safe") {{ {builder} {{ {statement}; db.execSQL(toString()) }} }}'
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert not _hit(report, SQL), report["findings"]


@pytest.mark.parametrize("inner_input", [True, False])
@pytest.mark.parametrize("kind", ["field", "local", "typed_local", "shadow"])
def test_review17_regex_value_types_and_shadowing(kind: str, inner_input: bool) -> None:
    outer, inner = ('"safe"', "q") if inner_input else ("q", '"safe"')
    declaration = (
        'val sep:Regex=Regex("a"); '
        if kind == "typed_local"
        else 'val sep=Regex("a"); '
        if kind == "local"
        else 'val sep="a"; '
        if kind == "shadow"
        else ""
    )
    prefix = 'val sep=Regex("x"); ' if kind == "shadow" else ""
    body = (
        prefix
        + f'with({outer}) {{ buildString {{ append({inner}); {declaration}db.execSQL(replace(sep,"b")) }} }}'
    )
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    if kind == "field":
        source = source.replace("    fun open(", '    private val sep:Regex=Regex("a")\n    fun open(')
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is (not inner_input if kind == "shadow" else inner_input), report["findings"]


def test_review17_local_numeric_named_function_keeps_precedence() -> None:
    source = REVIEW13_KOTLIN.replace("REVIEW_BODY", "q.length.run { minus(q.length) }").replace(
        "val s = Markup.render", "fun minus(other:Int):String=q; val s = Markup.render"
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "member,call,expected",
    [
        ("private fun coerceIn(range:CharRange):String=captured", "coerceIn(range='a'..'z')", True),
        ("private fun toString(v:Long):String=captured", "toString(q.length.toLong())", True),
        ("private fun toString(v:Int):String=captured", "toString(v=16)", True),
        ("private fun toString(radix:Int):String=captured", "toString(radix=16)", False),
    ],
)
def test_review17_numeric_kind_and_parameter_label_controls(member: str, call: str, expected: bool) -> None:
    source = (
        REVIEW13_KOTLIN.replace("REVIEW_BODY", "q.length.run { " + call + " }")
        .replace("    fun open(", '    private var captured=""\n    ' + member + "\n    fun open(")
        .replace("val s = Markup.render", "captured=q; val s = Markup.render")
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


def test_review17_qualified_project_object_is_not_a_numeric_return() -> None:
    source = REVIEW13_KOTLIN.replace(
        "REVIEW_BODY", "q.length.run { val box=trim(q); box.toString() }"
    ).replace(
        "    fun open(",
        "    private fun trim(v:String): other.Int = other.Int(v)\n    fun open(",
    )
    holder = (
        "package other\nclass Int(val raw:kotlin.String) { override fun toString(): kotlin.String = raw }\n"
    )
    report = analyze_sources([("app/Notes.kt", source), ("app/Holder.kt", holder)])
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "method,member",
    [("trim", 'private fun trim():String="safe"'), ("toString", 'override fun toString():String="Notes"')],
)
@pytest.mark.parametrize("scope", ["q.run { SINK }", "with(q) { SINK }"])
def test_review17_direct_sink_uses_the_string_before_outer_helper(
    method: str, member: str, scope: str
) -> None:
    body = scope.replace("SINK", "db.execSQL(" + method + "())")
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    ).replace("    fun open(", "    " + member + "\n    fun open(")
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL), report["findings"]


@pytest.mark.parametrize(
    "prefix,receiver,member,call,expected",
    [
        (
            "",
            "q.length",
            "private fun coerceAtLeast(minimumValue:Long):String=captured",
            "coerceAtLeast(0L)",
            True,
        ),
        (
            "",
            "q.length.toLong()",
            "private fun coerceAtLeast(minimumValue:Int):String=captured",
            "coerceAtLeast(0)",
            False,
        ),
        (
            "",
            "q.length.toDouble()",
            "private fun coerceAtLeast(minimumValue:Int):String=captured",
            "coerceAtLeast(0)",
            True,
        ),
        (
            "val small:Byte=1; ",
            "small",
            "private fun coerceAtLeast(minimumValue:Int):String=captured",
            "coerceAtLeast(0)",
            False,
        ),
        (
            "val small:Byte=1; val n=q.length; ",
            "small",
            "private fun coerceAtLeast(minimumValue:Int):String=captured",
            "coerceAtLeast(n)",
            True,
        ),
        (
            "val small:Byte=1; ",
            "small",
            "private fun coerceAtLeast(minimumValue:Int):String=captured",
            "coerceAtLeast(128)",
            True,
        ),
        (
            "val small:Byte=1; ",
            "small",
            "private fun coerceAtLeast(minimumValue:Int):String=captured",
            "coerceAtLeast(-128)",
            False,
        ),
        (
            "val small:Byte=1; ",
            "small",
            "private fun coerceAtLeast(minimumValue:Int):String=captured",
            "coerceAtLeast(-129)",
            True,
        ),
        (
            "val n:UInt=1u; ",
            "n",
            "private fun coerceAtLeast(minimumValue:Int):String=captured",
            "coerceAtLeast(0)",
            True,
        ),
        (
            "val n:UInt=1u; ",
            "n",
            "private fun coerceAtLeast(minimumValue:UInt):String=captured",
            "coerceAtLeast(0u)",
            False,
        ),
        (
            "val n:ULong=1uL; ",
            "n",
            "private fun coerceAtLeast(minimumValue:UInt):String=captured",
            "coerceAtLeast(0u)",
            False,
        ),
        (
            "",
            "q.length",
            "private fun coerceAtMost(maximumValue:Long):String=captured",
            "coerceAtMost(0L)",
            True,
        ),
        (
            "",
            "q.length",
            "private fun coerceIn(minimumValue:Int,maximumValue:Long):String=captured",
            "coerceIn(0,1L)",
            True,
        ),
        ("", "true", "private fun toString(radix:Int):String=captured", "toString(10)", True),
        ("", '"${q.length}"', "private fun toString(radix:Int):String=captured", "toString(10)", True),
        ("", "q.length.toDouble()", "private fun toString(radix:Int):String=captured", "toString(10)", True),
        (
            "val small:Byte=1; ",
            "small",
            "private fun toString(radix:Int):String=captured",
            "toString(10)",
            False,
        ),
        ("", "q.length", "private fun plus(other:Long):String=captured", "plus(1L)", False),
        ("", "q.length", "private fun plus(other:UInt):String=captured", "plus(1u)", True),
        ("val n:UInt=1u; ", "n", "private fun plus(other:Int):String=captured", "plus(1)", True),
    ],
)
def test_review17_primitive_overloads_keep_inapplicable_helpers(
    prefix: str, receiver: str, member: str, call: str, expected: bool
) -> None:
    source = (
        REVIEW13_KOTLIN.replace("REVIEW_BODY", prefix + receiver + ".run { " + call + " }")
        .replace("    fun open(", '    private var captured=""\n    ' + member + "\n    fun open(")
        .replace("val s = Markup.render", "captured=q; val s = Markup.render")
    )
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


@pytest.mark.parametrize("location", ["member", "top_level"])
@pytest.mark.parametrize("inline", [False, True])
@pytest.mark.parametrize("inner_input", [False, True])
def test_review17_project_regex_named_helpers_keep_their_string_return(
    location: str, inline: bool, inner_input: bool
) -> None:
    outer, inner = ('"safe"', "q") if inner_input else ("q", '"safe"')
    declaration = "" if inline else 'val sep=Regex("a"); '
    pattern = 'Regex("a")' if inline else "sep"
    body = f'with({outer}) {{ buildString {{ append({inner}); {declaration}db.execSQL(replace({pattern},"b")) }} }}'
    source = REVIEW13_KOTLIN.replace(
        'val s = Markup.render { b -> b.section { REVIEW_BODY }; b.append("SELECT 1"); Unit }',
        body + '; val s="safe"',
    )
    if location == "member":
        source = source.replace("    fun open(", "    private fun Regex(v:String):String=v\n    fun open(")
    else:
        source += "\nprivate fun Regex(v:String):String=v\n"
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is not inner_input, report["findings"]


REVIEW18_KOTLIN = """package app
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Notes(private val db: SQLiteDatabase) {
    MEMBER
    fun open(intent: Intent) {
        val q = intent.getStringExtra("q") ?: ""
        BODY
    }
}
"""


def _review18_cases() -> list[dict]:
    SOURCE = REVIEW18_KOTLIN
    S = 'private fun trim(): String = "safe"'
    INTEGER_HELPER = "private fun trim(): Int = 7"
    DIRECT = "q.run { db.execSQL(trim()) }"
    EXTRA = ("other/Util.kt", 'package unrelated\nprivate fun String.trim(): String = "unused"\n')
    CASES = []
    for label, member, body, extra in [
        ("F1/control", S, DIRECT, []),
        ("F1/invisible-extension", S, DIRECT, [EXTRA]),
        ("F2/direct", INTEGER_HELPER, DIRECT, []),
        ("F2/inferred", INTEGER_HELPER, "q.run { val s=trim(); s.run { db.execSQL(trim()) } }", []),
        ("F2/typed", INTEGER_HELPER, "q.run { val s:String=trim(); s.run { db.execSQL(trim()) } }", []),
        ("F3/run", S, "q.run { run { db.execSQL(trim()) } }", []),
        ("F3/let-implicit", S, 'q.run { "safe".let { db.execSQL(trim()) } }', []),
        ("F3/let-explicit", S, 'q.run { "safe".let { unused -> db.execSQL(trim()) } }', []),
    ]:
        source = SOURCE.replace("MEMBER", member).replace("BODY", body)
        CASES.append(
            dict(id=label, files=[("app/Notes.kt", source), *extra], rule="AST-SQL-CONCAT", expect=True)
        )
    for method in ["plus", "format"]:
        for scope in ["with(RECEIVER) { CALL }", "RECEIVER.run { CALL }"]:
            for input_receiver in [False, True]:
                for named in [False, True]:
                    receiver = "q" if input_receiver else '"fixed"'
                    result = '"fixed"' if input_receiver else "captured"
                    member = (
                        'private var captured=""\n    private fun ' + method + "(value:Int):String=" + result
                    )
                    call = method + "(" + ("value=" if named else "") + "0)"
                    body = "captured=q; " + scope.replace("RECEIVER", receiver).replace(
                        "CALL", "db.execSQL(" + call + ")"
                    )
                    source = SOURCE.replace("MEMBER", member).replace("BODY", body)
                    CASES.append(
                        dict(
                            id=f"CODE/{method}/{scope}/{input_receiver}/{named}",
                            files=[("app/Notes.kt", source)],
                            rule="AST-SQL-CONCAT",
                            expect=(not input_receiver if named else input_receiver),
                        )
                    )
    for label in ["locale", "args"]:
        member = 'private var captured=""\n    private fun format(' + label + ":Int):String=captured"
        body = 'captured=q; with("fixed") { db.execSQL(format(' + label + "=0)) }"
        CASES.append(
            dict(
                id="CODE/format/" + label + "-kind",
                files=[("app/Notes.kt", SOURCE.replace("MEMBER", member).replace("BODY", body))],
                rule="AST-SQL-CONCAT",
                expect=True,
            )
        )

    for method in ["plus", "format"]:
        for helper_tainted in [False, True]:
            receiver = '"fixed"' if helper_tainted else "q"
            result = "captured" if helper_tainted else '"fixed"'
            member = 'private var captured=""\n    private fun ' + method + "(value:Int):String=" + result
            expression = receiver + ".run { " + method + "(value=0) }"
            body = (
                "captured=q; val s=Markup.render { b -> b.section { "
                + expression
                + ' }; b.append("SELECT 1"); Unit }; db.execSQL(s)'
            )
            CASES.append(
                dict(
                    id=f"CODE/content/{method}/{helper_tainted}",
                    files=[("app/Notes.kt", SOURCE.replace("MEMBER", member).replace("BODY", body))],
                    rule="AST-SQL-CONCAT",
                    expect=helper_tainted,
                )
            )

    K = REVIEW13_KOTLIN
    for tainted in [False, True]:
        method = (
            ('private var captured=""\n    ' if tainted else "")
            + "private fun Any.trim():String="
            + ("captured" if tainted else '"safe"')
        )
        body = (
            ("captured=q; " if tainted else "")
            + ('"safe"' if tainted else "q")
            + ".run { db.execSQL(trim()) }"
        )
        CASES.append(
            dict(
                id=f"ADV/Any-extension/{tainted}",
                files=[("app/Notes.kt", SOURCE.replace("MEMBER", method).replace("BODY", body))],
                rule="AST-SQL-CONCAT",
                expect=tainted,
            )
        )
    for inner in [False, True]:
        outer, inside = ('"safe"', "q") if inner else ("q", '"safe"')
        body = f'val sep=Regex("x"); with({outer}) {{ buildString {{ append({inside}); listOf("x").forEach {{ sep -> db.execSQL(replace(sep,"y")) }} }} }}'
        CASES.append(
            dict(
                id=f"ADV/Regex-shadow/{inner}",
                files=[("app/Notes.kt", SOURCE.replace("MEMBER", "").replace("BODY", body))],
                rule="AST-SQL-CONCAT",
                expect=not inner,
            )
        )
    for outer in ["local", "parameter", "field"]:
        source = K.replace("REVIEW_BODY", "q.length.run { val n=q; toString(n) }").replace(
            "    fun open(", "    private fun toString(v:String):String=v\n    fun open("
        )
        if outer == "local":
            source = source.replace("val s = Markup.render", "val n=0; val s = Markup.render")
        elif outer == "field":
            source = source.replace("    fun open(", "    private val n:Int=0\n    fun open(")
        else:
            source = source.replace("fun open(", "fun open(n:Int, ")
        CASES.append(
            dict(id="CLAUDE/1/" + outer, files=[("app/Notes.kt", source)], rule="AST-SQL-CONCAT", expect=True)
        )
    for write in ["sb.section { VALUE }", 'sb.append(VALUE ?: "")', "sb.group { g -> g.append(VALUE) }"]:
        for transformed in [False, True]:
            body = (
                "val row=repo.find(q); (Ext.wrap(row) { sb -> "
                + write.replace("VALUE", "row.trim()" if transformed else "row")
                + ' }+"x").escapeSql()'
            )
            CASES.append(
                dict(
                    id=f"CLAUDE/2/{write}/{transformed}",
                    files=[("app/Notes.kt", K.replace("REVIEW_BODY", body))],
                    rule="AST-SQL-CONCAT",
                    expect=transformed,
                )
            )
    for id_, body, member, expected in [
        (
            "parseInt",
            'Integer.parseInt("5").run { coerceAtLeast(0) }',
            "private fun coerceAtLeast(minimumValue:Int):String=captured",
            False,
        ),
        ("Math", 'q.length.run { "${plus(Math.max(1,2))} rows" }', "", False),
        (
            "String-other",
            "q.length.run { plus(q.length.toString()) }",
            "private fun plus(other:String):String=captured",
            True,
        ),
    ]:
        source = (
            K.replace("REVIEW_BODY", body)
            .replace("    fun open(", '    private var captured=""\n    ' + member + "\n    fun open(")
            .replace("val s = Markup.render", "captured=q; val s = Markup.render")
        )
        CASES.append(
            dict(
                id="CLAUDE/3-4/" + id_,
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=expected,
            )
        )

    for scope in [
        "run { CALL }",
        '"safe".let { CALL }',
        '"safe".let { unused -> CALL }',
        '"safe".also { CALL }',
        '"safe".takeIf { CALL; true }',
        '"safe".takeUnless { CALL; false }',
    ]:
        source = SOURCE.replace("MEMBER", S).replace(
            "BODY", "q.run { " + scope.replace("CALL", "db.execSQL(trim())") + " }"
        )
        CASES.append(dict(id="scope/" + scope, files=[("app/Notes.kt", source)], rule=SQL, expect=True))
    for receiver in ["Any", "T"]:
        for tainted in [False, True]:
            member = (
                ('private var captured=""\n    ' if tainted else "")
                + "private fun "
                + ("<T> T" if receiver == "T" else receiver)
                + ".trim():String="
                + ("captured" if tainted else '"safe"')
            )
            body = (
                ("captured=q; " if tainted else "")
                + ('"safe"' if tainted else "q")
                + ".run { db.execSQL(trim()) }"
            )
            CASES.append(
                dict(
                    id=f"extension/{receiver}/{tainted}",
                    files=[("app/Notes.kt", SOURCE.replace("MEMBER", member).replace("BODY", body))],
                    rule=SQL,
                    expect=tainted,
                )
            )
    for method in ["plus", "toString"]:
        for input_receiver in [False, True]:
            member = (
                'private var captured=""\n    private fun Any.'
                + method
                + ("():String=" if method == "toString" else "(other:Int):String=")
                + ('"safe"' if input_receiver else "captured")
            )
            body = (
                "captured=q; "
                + ("q" if input_receiver else '"safe"')
                + ".run { db.execSQL("
                + method
                + ("()" if method == "toString" else "(0)")
                + ") }"
            )
            CASES.append(
                dict(
                    id=f"String-member/{method}/{input_receiver}",
                    files=[("app/Notes.kt", SOURCE.replace("MEMBER", member).replace("BODY", body))],
                    rule=SQL,
                    expect=input_receiver,
                )
            )
    for private in [False, True]:
        other = (
            "open class Parent { " + ("private " if private else "") + 'fun String.trim():String="fixed" }'
        )
        source = (
            SOURCE.replace(
                "class Notes(private val db: SQLiteDatabase) {",
                "class Notes(private val db: SQLiteDatabase):Parent() {",
            )
            .replace("MEMBER", S)
            .replace("BODY", DIRECT)
            + other
        )
        CASES.append(
            dict(
                id=f"inherited-extension/{private}",
                files=[("app/Notes.kt", source)],
                rule=SQL,
                expect=private,
            )
        )
    for label, source_extra, files, expected in [
        (
            "public-unimported",
            "",
            [("other/Public.kt", 'package elsewhere\nfun String.trim():String="fixed"')],
            True,
        ),
        (
            "private-other-file",
            "",
            [("app/Private.kt", 'package app\nprivate fun String.trim():String="fixed"')],
            True,
        ),
        ("unrelated-owner", '\nclass Other { fun String.trim():String="fixed" }', [], True),
        (
            "import-alias",
            "",
            [("helper/Clip.kt", 'package helpers\nfun String.clip():String="fixed"')],
            False,
        ),
    ]:
        source = SOURCE.replace("MEMBER", S).replace("BODY", DIRECT) + source_extra
        if label == "import-alias":
            source = source.replace(
                "import android.content.Intent", "import helpers.clip as trim\nimport android.content.Intent"
            )
        CASES.append(
            dict(
                id="visibility/" + label, files=[("app/Notes.kt", source), *files], rule=SQL, expect=expected
            )
        )
    for body, expected in [
        ('val r=repo.find(q); (r.substring(0,q.length)+"x").escapeSql()', False),
        (
            'val row=repo.find(q); (Ext.wrap(row) { sb -> sb.section { row.substring(0,q.length) } }+"x").escapeSql()',
            True,
        ),
    ]:
        CASES.append(
            dict(
                id="written-transform/" + str(expected),
                files=[("app/Notes.kt", K.replace("REVIEW_BODY", body))],
                rule=SQL,
                expect=expected,
            )
        )
    return CASES


@pytest.mark.parametrize("case", _review18_cases(), ids=lambda case: case["id"])
def test_review18_string_dispatch_and_lexical_facts(case: dict) -> None:
    report = analyze_sources(case["files"])
    assert _hit(report, case["rule"]) is case["expect"], report["findings"]
    reason = "Kotlin project extension receiver flow unavailable"
    if case["id"].startswith(("ADV/Any-extension", "extension/")):
        assert reason in _reasons(report)
        assert _state(report, SQL) == "limited"
    if case["id"].startswith("String-member/"):
        assert reason not in _reasons(report)


@pytest.mark.parametrize(
    "kind,imports,initializer,nominal,label,expected",
    [
        ("Array<String>", "", 'arrayOf("fixed")', "", "args", False),
        ("kotlin.Array<kotlin.String>", "", 'arrayOf("fixed")', "", "args", False),
        ("Values<String>", "import kotlin.Array as Values", 'arrayOf("fixed")', "", "args", False),
        ("java.util.Locale", "", "java.util.Locale.US", "", "locale", False),
        ("Locale", "import java.util.Locale", "java.util.Locale.US", "", "locale", False),
        ("L", "import java.util.Locale as L", "java.util.Locale.US", "", "locale", False),
        ("Array<String>", "", "Array<String>()", "class Array<T>", "args", True),
        ("Locale", "", "Locale()", "class Locale", "locale", True),
    ],
)
def test_review18_named_format_reference_identity(
    kind: str, imports: str, initializer: str, nominal: str, label: str, expected: bool
) -> None:
    source = f"""package synthetic
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
{imports}
{nominal}
class Notes(private val db:SQLiteDatabase) {{
    private var captured=""
    private fun format({label}:{kind}):String=captured
    fun open(intent:Intent) {{
        val q=intent.getStringExtra("q") ?: ""
        captured=q
        val values: {kind} = {initializer}
        with("fixed") {{ db.execSQL(format({label}=values)) }}
    }}
}}
"""
    report = analyze_sources([("app/Notes.kt", source)])
    assert _hit(report, SQL) is expected, report["findings"]


def _review19_dispatch_cases() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    for name, kind, nested, top, imports, factory, expected in [
        ("nested-array", "Array<String>", "class Array<T>", "", "", "ProbeINDEX.Array<String>()", True),
        (
            "nested-import-alias",
            "Values<String>",
            "class Values<T>",
            "",
            "import kotlin.Array as Values\n",
            "ProbeINDEX.Values<String>()",
            True,
        ),
        (
            "qualified-shadow",
            "kotlin.Array<String>",
            "",
            "class Array<T>",
            "",
            'kotlin.arrayOf("fixed")',
            False,
        ),
        (
            "qualified-element-shadow",
            "kotlin.Array<kotlin.String>",
            "",
            "class Array<T>",
            "",
            'kotlin.arrayOf("fixed")',
            False,
        ),
        ("top-level-project-array", "Array<String>", "", "class Array<T>", "", "Array<String>()", True),
    ]:
        source = (
            HEADER
            + imports
            + f"""
    {top}
    class Notes(private val db:SQLiteDatabase) {{
     {nested}
     private var captured=""
     private fun format(args:{kind}):String=captured
     fun scan(intent:Intent, values:{kind}) {{
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=values)) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id=name,
                group="identity",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=expected,
                factory=factory,
            )
        )
    for receiver, compatible in [
        ("Comparable<String>", True),
        ("kotlin.Comparable<kotlin.String>", True),
        ("Comparable<*>", True),
        ("java.io.Serializable", True),
        ("Comparable<Int>", False),
        ("<T> Comparable<T>", True),
        ("<T : Comparable<T>> T", True),
    ]:
        for tainted in [False, True]:
            member = (
                ('private var captured=""\n' if tainted else "")
                + "private fun "
                + receiver
                + ".trim():String="
                + ("captured" if tainted else '"fixed"')
            )
            body = (
                'captured=intent.getStringExtra("q") ?: ""; "fixed".run { db.execSQL(trim()) }'
                if tainted
                else 'val q=intent.getStringExtra("q") ?: ""; q.run { db.execSQL(trim()) }'
            )
            source = (
                HEADER
                + f"class Notes(private val db:SQLiteDatabase) {{\n{member}\nfun scan(intent:Intent) {{ {body} }}\n}}"
            )
            CASES.append(
                dict(
                    id=f"supertype/{receiver}/{tainted}",
                    group="supertype",
                    files=[("app/Notes.kt", source)],
                    rule="AST-SQL-CONCAT",
                    expect=tainted if compatible else not tainted,
                    factory="",
                )
            )
    for alias in ["locale", "array"]:
        for helper_tainted in [False, True]:
            declaration = (
                "typealias Loc = java.util.Locale"
                if alias == "locale"
                else "typealias Values<T> = kotlin.Array<T>"
            )
            kind = "Loc?" if alias == "locale" else "Values<String>"
            parameter = "" if alias == "locale" else ", values:Values<String>"
            initialization = "val values:Loc? = null\n" if alias == "locale" else ""
            receiver = '"fixed"' if helper_tainted else "q"
            source = (
                HEADER
                + f"""{declaration}
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format({alias if alias == "locale" else "args"}:{kind}):String={("captured" if helper_tainted else '"fixed"')}
     fun scan(intent:Intent{parameter}) {{
      val q=intent.getStringExtra("q") ?: ""
      captured=q
      {initialization}with({receiver}) {{ db.execSQL(format({alias if alias == "locale" else "args"}=values)) }}
     }}
    }}
    """
            )
            CASES.append(
                dict(
                    id=f"source-alias/{alias}/{helper_tainted}",
                    group="source-alias",
                    files=[("app/Notes.kt", source)],
                    rule="AST-SQL-CONCAT",
                    expect=not helper_tainted,
                    factory='kotlin.arrayOf("fixed")' if alias == "array" else "",
                )
            )
    return CASES


def _review19_numeric_cases() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    for argument, declaration, result, expected in [
        ("1", "v:Int", "v.toString()", True),
        ("1L", "v:Long", "v.toString()", True),
        ('"1"', "v:String", '"fixed"', False),
        ('"1"', "v:String", "captured", True),
    ]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun minus({declaration}):String={result}
     private fun trim():String=captured
     fun scan(intent:Intent) {{
      val q=intent.getStringExtra("q") ?: ""
      captured=q
      q.length.run {{ val s=minus({argument}); s.run {{ db.execSQL(trim()) }} }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id=f"numeric/{argument}/{result}",
                group="claude",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=expected,
                factory="",
            )
        )
    for parameter in [False, True]:
        member = "" if parameter else 'private var sep:Regex=Regex("a")'
        params = ", sep:Regex" if parameter else ""
        assignment = "" if parameter else 'sep="b".toRegex()'
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase) {{
     {member}
     fun scan(intent:Intent{params}) {{
      val q=intent.getStringExtra("q") ?: ""
      {assignment}
      with("safe") {{ buildString {{ append(q); db.execSQL(replace(sep,"c")) }} }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id=f"declared-regex/{parameter}",
                group="claude",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=True,
                factory='kotlin.text.Regex("b")' if parameter else "",
            )
        )
    source = (
        HEADER
        + """fun String.format(vararg args:Any?):String=this
    class Notes(private val db:SQLiteDatabase) {
     private fun format(c:Long):String=c.toString()
     fun scan(intent:Intent) { db.execSQL(format(5L)) }
    }
    """
    )
    CASES.append(
        dict(
            id="extension-without-string-subject",
            group="claude",
            files=[("app/Notes.kt", source)],
            rule="AST-SQL-CONCAT",
            expect=False,
            factory="",
            no_extension_reason=True,
        )
    )
    return CASES


@pytest.mark.parametrize(
    "case", _review19_dispatch_cases() + _review19_numeric_cases(), ids=lambda case: case["id"]
)
def test_review19_nominal_identity_and_selected_return(case: dict) -> None:
    report = analyze_sources(case["files"])
    assert _hit(report, case["rule"]) is case["expect"], report["findings"]
    extension_reason = "Kotlin project extension receiver flow unavailable"
    if case["id"].startswith("supertype/") and "Comparable<Int>" not in case["id"]:
        assert extension_reason in _reasons(report)
        assert _state(report, SQL) == "limited"
    if case.get("no_extension_reason"):
        assert extension_reason not in _reasons(report)
        assert _state(report, SQL) == "checked"


def _review19_alias_cases() -> list[dict]:
    CASES = []
    for name, reference, imports, declarations, other, expected in [
        ("same-file", "Values<String>", "", "typealias Values<T> = Array<T>", [], False),
        (
            "transitive",
            "Values<String>",
            "",
            "typealias Base<T> = kotlin.Array<T>\ntypealias Values<T> = Base<T>",
            [],
            False,
        ),
        (
            "stdlib-import-as",
            "Values<String>",
            "import kotlin.Array as Base",
            "typealias Values<T> = Base<T>",
            [],
            False,
        ),
        (
            "project-import-as",
            "Values<String>",
            "import helpers.Exported as Values",
            "",
            [
                (
                    "helpers/Alias.kt",
                    "package helpers\nimport kotlin.Array as Base\ntypealias Exported<T> = Base<T>",
                )
            ],
            False,
        ),
        (
            "same-package",
            "Values<String>",
            "",
            "",
            [("app/Alias.kt", "package synthetic\ntypealias Values<T> = kotlin.Array<T>")],
            False,
        ),
        (
            "declaring-context",
            "Values<String>",
            "import helpers.Values",
            "class Array<T>",
            [("helpers/Alias.kt", "package helpers\ntypealias Values<T> = Array<T>")],
            False,
        ),
        (
            "project-target",
            "Values<String>",
            "",
            "class ProjectArray<T>\ntypealias Values<T> = ProjectArray<T>",
            [],
            True,
        ),
        (
            "qualified-alias",
            "helpers.Exported<String>",
            "",
            "",
            [("helpers/Alias.kt", "package helpers\ntypealias Exported<T> = kotlin.Array<T>")],
            False,
        ),
        (
            "private-invisible",
            "Array<String>",
            "",
            "",
            [
                (
                    "elsewhere/Alias.kt",
                    "package elsewhere\nprivate typealias Array<T> = ProjectArray<T>\nclass ProjectArray<T>",
                )
            ],
            False,
        ),
    ]:
        source = f"""package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    {imports}
    {declarations}
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(args:{reference}):String=captured
     fun scan(intent:Intent, values:{reference}) {{
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=values)) }}
     }}
    }}
    """
        CASES.append(
            dict(
                id="alias-control/" + name,
                files=[("app/Notes.kt", source), *other],
                rule="AST-SQL-CONCAT",
                expect=expected,
            )
        )
    return CASES


def _review19_variance_cases() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    for receiver, compatible in [
        ("Comparable<in String>", True),
        ("Comparable<Nothing>", True),
        ("Comparable<in Nothing>", True),
        ("Comparable<CharSequence>", False),
        ("<T : CharSequence> Comparable<T>", True),
        ("<T : Int> Comparable<T>", False),
    ]:
        for tainted in [False, True]:
            member = (
                ('private var captured=""\n' if tainted else "")
                + "private fun "
                + receiver
                + ".trim():String="
                + ("captured" if tainted else '"fixed"')
            )
            body = (
                'captured=intent.getStringExtra("q") ?: ""; "fixed".run { db.execSQL(trim()) }'
                if tainted
                else 'val q=intent.getStringExtra("q") ?: ""; q.run { db.execSQL(trim()) }'
            )
            source = (
                HEADER
                + f"class Notes(private val db:SQLiteDatabase) {{\n{member}\nfun scan(intent:Intent) {{ {body} }}\n}}"
            )
            CASES.append(
                dict(
                    id=f"supertype/{receiver}/{tainted}",
                    group="super-extra",
                    files=[("app/Notes.kt", source)],
                    rule="AST-SQL-CONCAT",
                    expect=tainted if compatible else not tainted,
                    factory="",
                )
            )
    return CASES


@pytest.mark.parametrize(
    "case", _review19_alias_cases() + _review19_variance_cases(), ids=lambda case: case["id"]
)
def test_review19_alias_context_and_variance(case: dict) -> None:
    report = analyze_sources(case["files"])
    assert _hit(report, case["rule"]) is case["expect"], report["findings"]
    if case.get("group") == "super-extra" and case["expect"] == case["id"].endswith("/True"):
        assert "Kotlin project extension receiver flow unavailable" in _reasons(report)
        assert _state(report, SQL) == "limited"


@pytest.mark.parametrize("cycle", [True, False])
def test_review19_alias_expansion_limit_is_explicit(cycle: bool) -> None:
    aliases = (
        "typealias Values<T> = Next<T>\ntypealias Next<T> = Values<T>"
        if cycle
        else "typealias Values<T> = A0<T>\n"
        + "\n".join(f"typealias A{i}<T> = A{i + 1}<T>" for i in range(17))
        + "\ntypealias A17<T> = kotlin.Array<T>"
    )
    source = f"""package synthetic
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
{aliases}
class Notes(private val db:SQLiteDatabase) {{
    private fun format(args:Values<String>):String="fixed"
    fun open(intent:Intent, values:Values<String>) {{
        val q=intent.getStringExtra("q") ?: ""
        with(q) {{ db.execSQL(format(args=values)) }}
    }}
}}
"""
    report = analyze_sources([("app/Notes.kt", source)])
    assert "callable argument type identity unresolved" in _reasons(report)
    assert _state(report, SQL) == "limited"


def _review20_nullable_cases() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    for kind, alias in [
        ("Array<String>?", ""),
        ("kotlin.Array<String>?", ""),
        ("Values<String>?", "typealias Values<T> = kotlin.Array<T>"),
        ("Values<String>?", "typealias Base<T> = kotlin.Array<T>\ntypealias Values<T> = Base<T>"),
        ("Values<String>", "typealias Values<T> = kotlin.Array<T>"),
    ]:
        expected = kind.endswith("?")
        source = (
            HEADER
            + f"""{alias}
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(args:{kind}):String=captured
     fun scan(intent:Intent, values:{kind}) {{
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=values)) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="nullable/" + kind + "/" + str(len(CASES)),
                group="native19",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=expected,
                factory="null" if expected else 'kotlin.arrayOf("fixed")',
            )
        )
    for nested in [False, True]:
        body = "val s=minus(1); s.run { db.execSQL(trim()) }"
        if nested:
            body = '"safe".run { ' + body + " }"
        source = (
            HEADER
            + """class Notes(private val db:SQLiteDatabase) {
     private var captured=""
     private fun minus(value:Int):String="fixed"
     private fun trim():String=captured
     fun scan(intent:Intent) {
      val q=intent.getStringExtra("q") ?: ""
      captured=q
      q.length.run { """
            + body
            + """ }
     }
    }
    """
        )
        CASES.append(
            dict(
                id="nested-numeric/" + str(nested),
                group="native19",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=not nested,
                factory="",
            )
        )
    return CASES


def _review20_origin_cases() -> list[dict]:
    CASES = []
    for kind, alias in [("Array<String>", ""), ("Values<String>", "typealias Values<T> = kotlin.Array<T>")]:
        local = kind.split("<")[0]
        source = f"""package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    {alias}
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(args:{kind}):String=captured
     fun scan(intent:Intent, values:{kind}) {{
      class {local}<T>
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=values)) }}
     }}
    }}
    """
        CASES.append(
            dict(
                id="declaration-origin/" + kind,
                group="origin19",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=False,
                factory='kotlin.arrayOf("fixed")',
            )
        )
    return CASES


def _review20_extra_cases() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    for target, imports in [
        ("Array<T>?", ""),
        ("kotlin.Array<T>?", ""),
        ("Base<T>?", "import kotlin.Array as Base"),
    ]:
        source = (
            HEADER
            + imports
            + f"""
    typealias Values<T> = {target}
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(args:Values<String>):String=captured
     fun scan(intent:Intent, values:Values<String>) {{
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=values)) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="nullable-target/" + target,
                group="extra20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=True,
                factory="null",
            )
        )
    for annotation in ["", ":Array<String>"]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(args:Array<String>):String=captured
     fun scan(intent:Intent, values:Array<String>) {{
      val copy{annotation} = values
      class Array<T>
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=copy)) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="local-origin/" + annotation,
                group="extra20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=False,
                factory='kotlin.arrayOf("fixed")',
            )
        )
    for nullable in [False, True]:
        suffix = "?" if nullable else ""
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun values():Array<String>{suffix} = {"null" if nullable else 'arrayOf("fixed")'}
     private fun format(args:Array<String>{suffix}):String=captured
     fun scan(intent:Intent) {{
      class Array<T>
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=values())) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="return-origin/" + str(nullable),
                group="extra20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=nullable,
                factory="",
            )
        )
    for argument, parameter, initialization, expected in [
        ("1f", "v:Float", "", True),
        ("1.0", "v:Double", "", True),
        ("v", "v:Float", "val v:Float=1f;", True),
        ("v", "v:Double", "val v:Double=1.0;", True),
        ("1.toFloat()", "v:Float", "", True),
        ('"1"', "v:String", "", False),
    ]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun minus({parameter}):String="fixed"
     private fun trim():String=captured
     fun scan(intent:Intent) {{
      val q=intent.getStringExtra("q") ?: ""
      captured=q
      q.length.run {{ {initialization} val s=minus({argument}); s.run {{ db.execSQL(trim()) }} }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="numeric-literal/" + argument + "/" + parameter,
                group="extra20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=expected,
                factory="",
            )
        )
    for nested in [False, True]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase,private val values:Array<String>) {{
     {"class Array<T>" if nested else ""}
     private var captured=""
     private fun format(args:Array<String>):String=captured
     fun scan(intent:Intent) {{
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=values)) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="constructor-origin/" + str(nested),
                group="extra20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=nested,
                factory="",
                constructor="ProbeINDEX.Array<String>()" if nested else 'kotlin.arrayOf("fixed")',
            )
        )
    return CASES


def _review20_opaque_cases() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    source = (
        HEADER
        + """class Notes(private val db:SQLiteDatabase) {
     private fun <L> format(locale:L):String="fixed"
     fun <L> scan(intent:Intent, value:L) { db.execSQL(format(locale=value)) }
    }
    """
    )
    CASES.append(
        dict(
            id="identity-reason-without-string",
            group="claude19",
            files=[("app/Notes.kt", source)],
            rule="AST-SQL-CONCAT",
            expect=False,
            factory="java.util.Locale.US",
        )
    )
    for alias, receiver in [
        ("typealias C<T> = Comparable<String>", "C<Int>"),
        ("typealias P<A,B> = Comparable<B>", "P<Int,String>"),
    ]:
        source = (
            HEADER
            + f"""{alias}
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun {receiver}.trim():String=captured
     fun scan(intent:Intent) {{
      captured=intent.getStringExtra("q") ?: ""
      "fixed".run {{ db.execSQL(trim()) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="opaque-comparable/" + receiver,
                group="claude19",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=True,
                factory="",
            )
        )
    for receiver, expected in [("Int", True), ("String", False)]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun {receiver}.coerceAtLeast(minimumValue:Int):String=captured
     private fun trim():String="fixed"
     fun scan(intent:Intent) {{
      captured=intent.getStringExtra("q") ?: ""
      5.run {{ val s=coerceAtLeast(0); s.run {{ db.execSQL(trim()) }} }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="numeric-extension/" + receiver,
                group="claude19",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=expected,
                factory="",
            )
        )
    return CASES


@pytest.mark.parametrize(
    "case",
    _review20_nullable_cases()
    + _review20_origin_cases()
    + _review20_extra_cases()
    + _review20_opaque_cases(),
    ids=lambda case: case["id"],
)
def test_review20_reference_facts_and_numeric_literals(case: dict) -> None:
    report = analyze_sources(case["files"])
    if case["id"] == "numeric-extension/Int":
        # Existing incomplete explicit receiver flow remains visible; release item2.
        assert _state(report, SQL) == "limited"
        assert "unresolved callable identity or argument signature" in _reasons(report)
    else:
        assert _hit(report, case["rule"]) is case["expect"], report["findings"]
    if case["id"].startswith("opaque-comparable/"):
        assert _state(report, SQL) == "limited"
        assert "Kotlin project extension receiver flow unavailable" in _reasons(report)
    if case["id"] in {"identity-reason-without-string", "numeric-extension/String"}:
        assert _state(report, SQL) == "limited"
        assert "unresolved callable identity or argument signature" in _reasons(report)
    if case["id"].startswith("nullable/") and "?" in case["id"] or case["id"].startswith("nullable-target/"):
        assert _state(report, SQL) == "limited"
        assert "callable argument type identity unresolved" in _reasons(report)


def test_review20_nested_type_hints_have_bounded_work(monkeypatch: pytest.MonkeyPatch) -> None:
    original = Analyzer.known_value_type
    for size in [8, 16, 32, 64]:
        count = 0

        def counted(self: Analyzer, *args, **kwargs):
            nonlocal count
            count += 1
            assert count <= 512, "type hints repeat nested numeric argument work"
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Analyzer, "known_value_type", counted)
        expression = "1"
        for _ in range(size):
            expression = "plus(" + expression + ")"
        source = """import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Notes(private val db:SQLiteDatabase) {
    fun scan(intent:Intent) {
        val q=intent.getStringExtra("q") ?: ""
        q.length.run { val n=EXPRESSION; db.execSQL("SELECT "+n) }
    }
}
""".replace("EXPRESSION", expression)
        report = analyze_sources([("app/Notes.kt", source)])
        assert count <= 8 * size + 32
        if size >= 16:
            assert "callable argument type identity unresolved" in _reasons(report)
            assert _state(report, SQL) in {"limited", "partial"}


def _review20_smartcast_cases() -> list[dict]:
    CASES = []
    for tainted in [False, True]:
        source = f"""package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(args:Array<String>?):String={'"fixed"' if tainted else "captured"}
     fun scan(intent:Intent, values:Array<String>?) {{
      val q=intent.getStringExtra("q") ?: ""
      captured=q
      if(values!=null) {{ with({"q" if tainted else '"fixed"'}) {{ db.execSQL(format(args=values)) }} }}
     }}
    }}
    """
        CASES.append(
            dict(
                id="nullable-smartcast/" + str(tainted),
                group="smartcast20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect="LIMITED",
                runtime_expect=tainted,
                factory='kotlin.arrayOf("fixed")',
            )
        )
    return CASES


@pytest.mark.parametrize("case", _review20_smartcast_cases(), ids=lambda case: case["id"])
def test_review20_nullable_smartcast_is_explicitly_limited(case: dict) -> None:
    report = analyze_sources(case["files"])
    assert _state(report, SQL) == "limited"
    assert "callable argument type identity unresolved" in _reasons(report)


def _review20_callback_cases() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    for nominal, local, expected in [("", "class Array<T>", False), ("class Array<T>", "", True)]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase) {{
     {nominal}
     private var captured=""
     private fun format(args:Array<String>):String=captured
     fun scan(intent:Intent, values:Array<String>) {{
      captured=intent.getStringExtra("q") ?: ""
      values.let {{ value ->
       {local}
       with("fixed") {{ db.execSQL(format(args=value)) }}
      }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="callback-origin/" + str(expected),
                group="callback20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=expected,
                factory="ProbeINDEX.Array<String>()" if expected else 'kotlin.arrayOf("fixed")',
            )
        )
    source = (
        HEADER
        + """class Notes(private val db:SQLiteDatabase) {
     private var captured=""
     private fun format(locale:Regex):String=captured
     fun scan(intent:Intent) {
      captured=intent.getStringExtra("q") ?: ""
      val rx:Regex=Regex("x")
      rx.let { locale -> with("fixed") { db.execSQL(format(locale=locale)) } }
     }
    }
    """
    )
    CASES.append(
        dict(
            id="callback-known-incompatible-regex",
            group="callback20",
            files=[("app/Notes.kt", source)],
            rule="AST-SQL-CONCAT",
            expect=True,
            factory="",
        )
    )
    return CASES


@pytest.mark.parametrize("case", _review20_callback_cases(), ids=lambda case: case["id"])
def test_review20_callback_reference_origins(case: dict) -> None:
    report = analyze_sources(case["files"])
    assert _hit(report, SQL) is case["expect"], report["findings"]


@pytest.mark.parametrize("aliased", [False, True])
def test_review20_inferred_copy_keeps_the_parameter_type_origin(aliased: bool) -> None:
    kind = "Values" if aliased else "Array"
    alias = "typealias Values<T> = kotlin.Array<T>" if aliased else ""
    source = f"""package synthetic
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
{alias}
class Notes(private val db:SQLiteDatabase) {{
    private var captured=""
    private fun format(args:{kind}<String>):String=captured
    fun scan(intent:Intent, values:{kind}<String>) {{
        class {kind}<T>
        val copy=values
        captured=intent.getStringExtra("q") ?: ""
        with("fixed") {{ db.execSQL(format(args=copy)) }}
    }}
}}
"""
    report = analyze_sources([("app/Notes.kt", source)])
    assert not _hit(report, SQL), report["findings"]
    assert _state(report, SQL) == "checked"


def _review21_field_cases() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    for name, setup, argument in [
        ("bare", "", "values"),
        ("qualified", "", "this@Notes.values"),
        ("copy", "val copy=this.values", "copy"),
    ]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase,private val values:Array<String>?) {{
     private var captured=""
     private fun format(args:Array<String>?):String=captured
     fun scan(intent:Intent) {{
      captured=intent.getStringExtra("q") ?: ""
      {setup}
      with("fixed") {{ db.execSQL(format(args={argument})) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="nullable-field/" + name,
                group="native20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=True,
                factory="",
                constructor="null",
            )
        )
    return CASES


def _review21_underscore_cases() -> list[dict]:
    CASES = []
    for parameter, receiver, expected in [
        ("_ ->", 'kotlin.arrayOf("safe")', True),
        ("_:kotlin.Array<String> ->", 'kotlin.arrayOf("safe")', True),
        ("_:String ->", '"safe"', True),
        ("value ->", 'kotlin.arrayOf("safe")', True),
        ("", 'kotlin.arrayOf("safe")', False),
    ]:
        source = f"""package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    class Notes(private val db:SQLiteDatabase) {{
     class Array<T>
     private var captured=""
     private fun format(args:Array<String>):String=captured
     fun scan(intent:Intent,it:Array<String>) {{
      captured=intent.getStringExtra("q") ?: ""
      {receiver}.let {{ {parameter} with("fixed") {{ db.execSQL(format(args=it)) }} }}
     }}
    }}
    """
        CASES.append(
            dict(
                id="underscore/" + parameter,
                group="underscore20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=expected,
                factory="ProbeINDEX.Array<String>()",
            )
        )
    return CASES


def _review21_lambda_cases() -> list[dict]:
    CASES = []
    for nullable, annotation in [
        (True, ""),
        (True, ":Array<String>?"),
        (False, ""),
        (False, ":Array<String>"),
    ]:
        kind = "Array<String>" + ("?" if nullable else "")
        source = f"""package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(args:{kind}):String=captured
     fun scan(intent:Intent,values:{kind}) {{
      captured=intent.getStringExtra("q") ?: ""
      values.let {{ value ->
       val copy{annotation} = value
       with("fixed") {{ db.execSQL(format(args=copy)) }}
      }}
     }}
    }}
    """
        CASES.append(
            dict(
                id="lambda-copy/" + str(nullable) + "/" + annotation,
                group="lambda20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=nullable,
                factory="null" if nullable else 'kotlin.arrayOf("fixed")',
            )
        )
    return CASES


def _review21_scope_cases() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    for name, body, kind in [
        (
            "lambda-shadow",
            'with("fixed") { val locale=Regex("x"); db.execSQL(format(locale=locale)) }',
            "Regex",
        ),
        (
            "for-shadow",
            'for(locale in listOf(Regex("x"))) { with("fixed") { db.execSQL(format(locale=locale)) } }',
            "Regex",
        ),
        (
            "when-shadow",
            'when(val locale=Regex("x")) { else -> with("fixed") { db.execSQL(format(locale=locale)) } }',
            "Regex",
        ),
        (
            "catch-shadow",
            'try { error("x") } catch(locale:Throwable) { with("fixed") { db.execSQL(format(locale=locale)) } }',
            "Throwable",
        ),
    ]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(locale:{kind}):String=captured
     fun scan(intent:Intent,locale:java.util.Locale) {{
      captured=intent.getStringExtra("q") ?: ""
      {body}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="scope/" + name,
                group="claude20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=True,
                factory="java.util.Locale.US",
            )
        )
    source = (
        HEADER
        + """val locale:Regex=Regex("x")
    class Notes(private val db:SQLiteDatabase,locale:java.util.Locale) {
     private var captured=""
     private fun format(locale:Regex):String=captured
     fun scan(intent:Intent) {
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") { db.execSQL(format(locale=locale)) }
     }
    }
    """
    )
    CASES.append(
        dict(
            id="scope/plain-constructor",
            group="claude20",
            files=[("app/Notes.kt", source)],
            rule="AST-SQL-CONCAT",
            expect=True,
            factory="",
            constructor="java.util.Locale.US",
        )
    )
    for inner in ['"safe"', "q"]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun minus(value:Int):String="fixed"
     private fun trim():String="fixed"
     fun scan(intent:Intent) {{
      val q=intent.getStringExtra("q") ?: ""
      captured=q
      q.length.run {{ {inner}.run {{ val s=minus(1); s.run {{ db.execSQL(trim()) }} }} }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="mixed-receivers/" + inner,
                group="claude20",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=inner == "q",
                factory="",
            )
        )
    source = (
        HEADER
        + """class Notes(private val db:SQLiteDatabase) {
     fun scan(intent:Intent,view:android.view.View) {
      val q=intent.getStringExtra("q") ?: ""
      q.length.run { val n=plus(view.paddingLeft); db.execSQL("SELECT 1") }
     }
    }
    """
    )
    CASES.append(
        dict(
            id="no-competing-helper",
            group="noncompiler",
            files=[("app/Notes.kt", source)],
            rule="AST-SQL-CONCAT",
            expect=False,
            factory="",
        )
    )
    return CASES


@pytest.mark.parametrize(
    "case",
    _review21_field_cases()
    + _review21_underscore_cases()
    + _review21_lambda_cases()
    + _review21_scope_cases(),
    ids=lambda case: case["id"],
)
def test_review21_reference_scopes_and_receiver_limits(case: dict) -> None:
    report = analyze_sources(case["files"])
    if case["id"].startswith("mixed-receivers/"):
        # Minimum supported contract while receiver-tower overload flow is unproven.
        if not _hit(report, SQL) and case["expect"]:
            assert _state(report, SQL) == "limited"
            assert "unresolved callable identity or argument signature" in _reasons(report)
        if not case["expect"]:
            assert not _hit(report, SQL)
    else:
        assert _hit(report, SQL) is case["expect"], report["findings"]
    if (
        case["id"].startswith("nullable-field/")
        or case["id"].startswith("lambda-copy/True")
        or case["id"] == "scope/for-shadow"
    ):
        assert _state(report, SQL) == "limited"
        assert "callable argument type identity unresolved" in _reasons(report)
    if case["id"] == "no-competing-helper":
        assert _state(report, SQL) == "checked"


@pytest.mark.parametrize("content", [False, True])
def test_review21_receiver_and_content_hint_work_is_bounded(
    content: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_hint = Analyzer.known_value_type
    original_scalar = Analyzer.scalar_result

    def measure(size: int) -> None:
        count = 0
        typing = 0
        scalar_inside_type = 0

        def hint(self: Analyzer, *args, **kwargs):
            nonlocal count, typing
            count += 1
            assert count <= 4096, "nested receiver/content type queries repeat work"
            typing += 1
            try:
                return original_hint(self, *args, **kwargs)
            finally:
                typing -= 1

        def scalar(self: Analyzer, *args, **kwargs):
            nonlocal count, scalar_inside_type
            count += 1
            scalar_inside_type += bool(typing)
            assert count <= 4096
            return original_scalar(self, *args, **kwargs)

        monkeypatch.setattr(Analyzer, "known_value_type", hint)
        monkeypatch.setattr(Analyzer, "scalar_result", scalar)
        expression = "1" if content else "plus(1)"
        for _ in range(size):
            expression = "plus(" + expression + ")" if content else "plus(1).run { " + expression + " }"
        body = (
            "val s=Markup.render { b -> b.section { q.length.run { EXPRESSION } }; Unit }; db.execSQL(s)"
            if content
            else 'val n=q.length.run { EXPRESSION }; db.execSQL("SELECT "+n)'
        ).replace("EXPRESSION", expression)
        source = """import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Notes(private val db:SQLiteDatabase) {
    fun scan(intent:Intent) {
        val q=intent.getStringExtra("q") ?: ""
        BODY
    }
}
""".replace("BODY", body)
        analyze_sources([("app/Notes.kt", source)])
        assert count <= 32 * size + 128
        assert scalar_inside_type == 0

    for size in [4, 8, 16, 32, 64]:
        measure(size)


def _review21_member_controls() -> list[dict]:
    HEADER = """package synthetic
    import android.content.Intent
    import android.database.sqlite.SQLiteDatabase
    """
    CASES = []
    for form, setup, argument in [
        ("bare", "", "values"),
        ("qualified", "", "this@Notes.values"),
        ("copy", "val copy=this.values", "copy"),
    ]:
        source = (
            HEADER
            + f"""class Notes(private val db:SQLiteDatabase,private val values:Array<String>) {{
     private var captured=""
     private fun format(args:Array<String>):String=captured
     fun scan(intent:Intent) {{
      class Array<T>
      captured=intent.getStringExtra("q") ?: ""
      {setup}
      with("fixed") {{ db.execSQL(format(args={argument})) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="nonnull-field/" + form,
                group="extra21",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=False,
                factory="",
                constructor='kotlin.arrayOf("fixed")',
            )
        )
    for nullable in [False, True]:
        kind = "Array<String>" + ("?" if nullable else "")
        source = (
            HEADER
            + f"""class Holder(val values:{kind})
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(args:{kind}):String=captured
     fun scan(intent:Intent,holder:Holder) {{
      class Array<T>
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=holder.values)) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="project-field/" + str(nullable),
                group="extra21",
                files=[("app/Notes.kt", source)],
                rule="AST-SQL-CONCAT",
                expect=nullable,
                factory="ScopeINDEX.Holder(" + ("null" if nullable else 'kotlin.arrayOf("fixed")') + ")",
            )
        )
        other = f"""package helpers
    import kotlin.Array as Values
    class Box(val values:Values<String>{"?" if nullable else ""})
    """
        source = (
            HEADER
            + f"""import helpers.Box
    class Notes(private val db:SQLiteDatabase) {{
     private var captured=""
     private fun format(args:kotlin.Array<String>{"?" if nullable else ""}):String=captured
     fun scan(intent:Intent,holder:Box) {{
      class Values<T>
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") {{ db.execSQL(format(args=holder.values)) }}
     }}
    }}
    """
        )
        CASES.append(
            dict(
                id="project-field-context/" + str(nullable),
                group="extra21",
                files=[("app/Notes.kt", source), ("helpers/Box.kt", other)],
                rule="AST-SQL-CONCAT",
                expect=nullable,
                factory="ScopeINDEX.helpers.Box(" + ("null" if nullable else 'kotlin.arrayOf("fixed")') + ")",
            )
        )
    source = (
        HEADER
        + """typealias Loc=java.util.Locale
    class Notes(private val db:SQLiteDatabase,private val locale:Loc?) {
     private var captured=""
     private fun format(locale:Loc?):String=captured
     fun scan(intent:Intent) {
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") { db.execSQL(format(locale=this@Notes.locale)) }
     }
    }
    """
    )
    CASES.append(
        dict(
            id="nullable-locale-field",
            group="extra21",
            files=[("app/Notes.kt", source)],
            rule="AST-SQL-CONCAT",
            expect=False,
            factory="",
            constructor="null",
        )
    )
    source = (
        HEADER
        + """val locale:Regex=Regex("x")
    class Notes(private val db:SQLiteDatabase,private val locale:java.util.Locale) {
     private var captured=""
     private fun format(locale:Regex):String=captured
     fun scan(intent:Intent) {
      captured=intent.getStringExtra("q") ?: ""
      with("fixed") { db.execSQL(format(locale=locale)) }
     }
    }
    """
    )
    CASES.append(
        dict(
            id="property-constructor-control",
            group="extra21",
            files=[("app/Notes.kt", source)],
            rule="AST-SQL-CONCAT",
            expect=False,
            factory="",
            constructor="java.util.Locale.US",
        )
    )
    return CASES


@pytest.mark.parametrize("case", _review21_member_controls(), ids=lambda case: case["id"])
def test_review21_member_declaration_contexts(case: dict) -> None:
    report = analyze_sources(case["files"])
    assert _hit(report, SQL) is case["expect"], report["findings"]
    if case["expect"]:
        assert _state(report, SQL) == "limited"
        assert "callable argument type identity unresolved" in _reasons(report)
    else:
        assert _state(report, SQL) == "checked"


@pytest.mark.parametrize(
    ("case_id", "files", "expected", "uncertain", "checked"),
    [
        (
            "plain-control",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,locale:Regex) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  listOf(java.util.Locale.US).also { with("fixed") { db.execSQL(format(locale=locale)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "for-typed-iterable",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,locale:Regex) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  for(locale:java.util.Locale in listOf(java.util.Locale.US).also { with("fixed") { '
                    "db.execSQL(format(locale=locale)) } }) {}\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "for-typed-iterable-copy",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,locale:Regex) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  for(locale:java.util.Locale in listOf(java.util.Locale.US).also { val copy=locale; "
                    'with("fixed") { db.execSQL(format(locale=copy)) } }) {}\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "for-inferred-iterable",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,locale:Regex) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  for(locale in listOf(java.util.Locale.US).also { with("fixed") { '
                    "db.execSQL(format(locale=locale)) } }) {}\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "for-typed-body-control",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,locale:Regex) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  for(locale:java.util.Locale in listOf(java.util.Locale.US)) { with("fixed") { '
                    "db.execSQL(format(locale=locale)) } }\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "when-initializer",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,locale:Regex) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  when(val locale=java.util.Locale.US.also { with("fixed") { '
                    "db.execSQL(format(locale=locale)) } }) { else -> Unit }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "companion/helpers.Box.values",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import helpers.Box\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=helpers.Box.values)) }\n'
                    " }\n"
                    "}",
                ),
                (
                    "helpers/Box.kt",
                    "package helpers\n"
                    "class Box(val values:kotlin.Array<String>) {\n"
                    ' companion object { val values:Regex=Regex("x") }\n'
                    "}",
                ),
            ],
            True,
            False,
            False,
        ),
        (
            "companion/helpers.Box.values/copy",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import helpers.Box\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val copy=helpers.Box.values;with("fixed") { db.execSQL(format(args=copy)) }\n'
                    " }\n"
                    "}",
                ),
                (
                    "helpers/Box.kt",
                    "package helpers\n"
                    "class Box(val values:kotlin.Array<String>) {\n"
                    ' companion object { val values:Regex=Regex("x") }\n'
                    "}",
                ),
            ],
            True,
            False,
            False,
        ),
        (
            "companion/Box.values",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import helpers.Box\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=Box.values)) }\n'
                    " }\n"
                    "}",
                ),
                (
                    "helpers/Box.kt",
                    "package helpers\n"
                    "class Box(val values:kotlin.Array<String>) {\n"
                    ' companion object { val values:Regex=Regex("x") }\n'
                    "}",
                ),
            ],
            True,
            False,
            False,
        ),
        (
            "companion/Box.values/copy",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import helpers.Box\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val copy=Box.values;with("fixed") { db.execSQL(format(args=copy)) }\n'
                    " }\n"
                    "}",
                ),
                (
                    "helpers/Box.kt",
                    "package helpers\n"
                    "class Box(val values:kotlin.Array<String>) {\n"
                    ' companion object { val values:Regex=Regex("x") }\n'
                    "}",
                ),
            ],
            True,
            False,
            False,
        ),
        (
            'destructure/val (locale,_) = Pair(Regex("x"),1)',
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent , locale:java.util.Locale) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { val (locale,_) = Pair(Regex("x"),1); db.execSQL(format(locale=locale)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            'destructure/val (locale:Regex,_) = Pair(Regex("x"),1)',
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent , locale:java.util.Locale) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { val (locale:Regex,_) = Pair(Regex("x"),1); '
                    "db.execSQL(format(locale=locale)) }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "when-self-initializer-safe",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent , locale:java.util.Locale) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { when(val locale=locale) { else -> db.execSQL(format(locale=locale)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "nullable-expression/if(flag) values else null",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=if(flag) values else null)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/if(flag) values else null/copy",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val copy=if(flag) values else null;with("fixed") { db.execSQL(format(args=copy)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/if(flag) values else values",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=if(flag) values else values)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/if(flag) values else values/copy",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val copy=if(flag) values else values;with("fixed") { db.execSQL(format(args=copy)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/when(flag) { true -> values; else -> null }",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=when(flag) { true -> values; else -> null })) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/when(flag) { true -> values; else -> null }/copy",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val copy=when(flag) { true -> values; else -> null };with("fixed") { '
                    "db.execSQL(format(args=copy)) }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/try { values } catch(e:Exception) { null }",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=try { values } catch(e:Exception) { null })) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/try { values } catch(e:Exception) { null }/copy",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val copy=try { values } catch(e:Exception) { null };with("fixed") { '
                    "db.execSQL(format(args=copy)) }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/values ?: null",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=values ?: null)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            True,
            False,
        ),
        (
            "nullable-expression/values ?: null/copy",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val copy=values ?: null;with("fixed") { db.execSQL(format(args=copy)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/values?.copyOf()",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=values?.copyOf())) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nullable-expression/values?.copyOf()/copy",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>?,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val copy=values?.copyOf();with("fixed") { db.execSQL(format(args=copy)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "project-array-expression",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " class Array<T>\n"
                    " private fun format(args:Array<String>):String=captured\n"
                    " fun scan(intent:Intent , values:Array<String>,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=if(flag) values else values)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "nonnull-expression-control",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>?):String=captured\n"
                    " fun scan(intent:Intent , values:kotlin.Array<String>,flag:Boolean) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(args=if(flag) values else values)) }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            'mixed/plus("x")',
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    ' private fun plus(other:String):String="fixed"\n'
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  q.run { 1.run { db.execSQL(plus("x")) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            True,
            False,
        ),
        (
            "mixed/plus(true)",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    ' private fun plus(other:String):String="fixed"\n'
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  q.run { 1.run { db.execSQL(plus(true).toString()) } }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            True,
            False,
        ),
        (
            "mixed/plus(1)",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    ' private fun plus(other:String):String="fixed"\n'
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  q.run { 1.run { db.execSQL(plus(1).toString()) } }\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "ordinary-chain/9",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Notes(private val db:SQLiteDatabase) { fun scan(intent:Intent) { val t="notes"; val '
                    'sql="CREATE TABLE " + t + "x" + "x" + "x" + "x" + "x" + "x" + "x"; db.execSQL(sql) } }',
                )
            ],
            False,
            False,
            True,
        ),
        (
            "ordinary-chain/10",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Notes(private val db:SQLiteDatabase) { fun scan(intent:Intent) { val t="notes"; val '
                    'sql="CREATE TABLE " + t + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x"; db.execSQL(sql) } '
                    "}",
                )
            ],
            False,
            False,
            True,
        ),
        (
            "ordinary-chain/16",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Notes(private val db:SQLiteDatabase) { fun scan(intent:Intent) { val t="notes"; val '
                    'sql="CREATE TABLE " + t + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + '
                    '"x" + "x" + "x"; db.execSQL(sql) } }',
                )
            ],
            False,
            False,
            True,
        ),
        (
            "ordinary-chain/32",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Notes(private val db:SQLiteDatabase) { fun scan(intent:Intent) { val t="notes"; val '
                    'sql="CREATE TABLE " + t + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + '
                    '"x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" + "x" '
                    '+ "x" + "x" + "x"; db.execSQL(sql) } }',
                )
            ],
            False,
            False,
            True,
        ),
        (
            "element-it/forEach/False",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(args:Array<String>):String=captured\n"
                    " fun scan(intent:Intent,it:Array<String>,items:List<kotlin.Array<String>>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  items.forEach { with("fixed") { db.execSQL(format(args=it)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "element-it/forEach/True",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(args:Array<String>):String=captured\n"
                    " fun scan(intent:Intent,it:kotlin.Array<String>,items:List<Array<String>>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  items.forEach { with("fixed") { db.execSQL(format(args=it)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "element-it/map/False",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(args:Array<String>):String=captured\n"
                    " fun scan(intent:Intent,it:Array<String>,items:List<kotlin.Array<String>>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  items.map { with("fixed") { db.execSQL(format(args=it)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "element-it/map/True",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(args:Array<String>):String=captured\n"
                    " fun scan(intent:Intent,it:kotlin.Array<String>,items:List<Array<String>>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  items.map { with("fixed") { db.execSQL(format(args=it)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "scalar-local-helper-priority",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val s=Markup.render { b -> b.section { val n=q.indexOf("x").coerceAtLeast(0); q.length.run '
                    '{ minus(n) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                ),
                (
                    "app/Markup.kt",
                    "package synthetic\n"
                    "class Builder {\n"
                    " private val b=StringBuilder()\n"
                    " fun section(f:()->Any?) { f() }\n"
                    " fun append(s:String) { b.append(s) }\n"
                    " fun output()=b.toString()\n"
                    "}\n"
                    "object Markup {\n"
                    " fun render(f:(Builder)->Unit):String { val b=Builder(); f(b); return b.output() }\n"
                    "}",
                ),
            ],
            False,
            False,
            False,
        ),
        (
            "classification/Int/False",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val s=Markup.render { b -> b.section { val n=q.indexOf("x").coerceAtLeast(0); q.length.run '
                    '{ minus(n) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            True,
            False,
        ),
        (
            "classification/Int/True",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val s=Markup.render { b -> b.section { val n:Int=q.indexOf("x").coerceAtLeast(0); '
                    'q.length.run { minus(n) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "classification/Boolean/False",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Boolean):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  val s=Markup.render { b -> b.section { val n=q.isBlank(); q.length.run { minus(n) } }; "
                    'b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "classification/Boolean/True",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Boolean):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  val s=Markup.render { b -> b.section { val n:Boolean=q.isBlank(); q.length.run { minus(n) } "
                    '}; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "stdlib/constant-qualified",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(locale=java.util.Locale.US)) }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            True,
        ),
        (
            "stdlib/constant-import-alias",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale as LC\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(locale=LC.US)) }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            True,
        ),
        (
            "stdlib/constructor",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(locale=java.util.Locale("en"))) }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "stdlib/factory-default",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(locale=java.util.Locale.getDefault())) }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "stdlib/factory-language-tag",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(locale=java.util.Locale.forLanguageTag("en"))) }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "stdlib/array-constructor",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " class Array<T>\n"
                    ' private var captured=""\n'
                    " private fun format(args:Array<String>):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(args=kotlin.Array(1) { "safe" })) }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "stdlib/project-class-shadow",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' class Locale { companion object { val US=Regex("x") } }\n'
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(locale=Locale.US)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_review22_reference_dispatch_boundaries(case_id, files, expected, uncertain, checked):
    report = analyze_sources(files)
    hit = any(finding["rule_id"] == "AST-SQL-CONCAT" for finding in report["findings"])
    state = next(row["state"] for row in report["coverage"] if row["rule_id"] == "AST-SQL-CONCAT")
    assert state in {"checked", "limited"}, case_id
    assert hit is expected or uncertain and state == "limited", case_id
    if checked:
        assert state == "checked"
        assert not report["metadata"]["native_flow"]["reasons"]


def test_review22_inapplicable_receiver_queries_have_bounded_work(monkeypatch):
    from mobile_audit.source_analysis import Analyzer

    original = Analyzer.known_value_type

    def measure(size):
        count = 0

        def hint(self, *args, **kwargs):
            nonlocal count
            count += 1
            assert count <= 4096
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Analyzer, "known_value_type", hint)
        body = 'val s=minus("a"); db.execSQL("SELECT 1")'
        for _ in range(size):
            body = 'minus("a").run { ' + body + " }"
        source = """import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Notes(private val db:SQLiteDatabase) {
    private fun minus(value:String):String="fixed"
    fun scan(intent:Intent) {
        val q=intent.getStringExtra("q") ?: ""
        q.length.run { BODY }
    }
}
""".replace("BODY", body)
        report = analyze_sources([("app/Notes.kt", source)])
        assert count <= 32 * size + 128
        assert not any(row["rule_id"] == "AST-SQL-CONCAT" for row in report["findings"])

    for size in [4, 8, 16, 32, 64]:
        measure(size)


def test_review22_reference_alias_dag_queries_have_bounded_work(monkeypatch):
    from mobile_audit.source_analysis import Analyzer

    original = Analyzer.library_argument_type

    def measure(size):
        count = 0

        def signature(self, *args, **kwargs):
            nonlocal count
            count += 1
            assert count <= 2048
            return original(self, *args, **kwargs)

        monkeypatch.setattr(Analyzer, "library_argument_type", signature)
        statements = ["val a0=values"] + [
            f"val a{i}=if(flag) a{i - 1} else a{i - 1}" for i in range(1, size + 1)
        ]
        source = """import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Notes(private val db:SQLiteDatabase) {
    private var captured=""
    private fun format(args:kotlin.Array<String>):String=captured
    fun scan(intent:Intent,values:kotlin.Array<String>,flag:Boolean) {
        captured=intent.getStringExtra("q") ?: ""
        STATEMENTS
        with("fixed") { db.execSQL(format(args=LAST)) }
    }
}
""".replace("STATEMENTS", "\n".join(statements)).replace("LAST", "a" + str(size))
        report = analyze_sources([("app/Notes.kt", source)])
        assert count <= 32 * size + 64
        if size <= 6:
            assert not any(row["rule_id"] == "AST-SQL-CONCAT" for row in report["findings"])
        else:
            assert (
                next(row["state"] for row in report["coverage"] if row["rule_id"] == "AST-SQL-CONCAT")
                == "limited"
            )

    for size in [2, 4, 6, 8, 16, 32]:
        measure(size)


@pytest.mark.parametrize(
    ("case_id", "files", "expected", "uncertain", "checked"),
    [
        (
            "empty-for/;",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent , locale:Regex) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  for(locale:java.util.Locale in listOf(java.util.Locale.US).also { with("fixed") { '
                    "db.execSQL(format(locale=locale)) } });\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            True,
        ),
        (
            "empty-for/{}",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent , locale:Regex) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  for(locale:java.util.Locale in listOf(java.util.Locale.US).also { with("fixed") { '
                    "db.execSQL(format(locale=locale)) } }){}\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            True,
        ),
        (
            "indexed-parameter",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(locale:Int):String=captured\n"
                    " fun scan(intent:Intent , items:List<java.util.Locale>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  items.forEachIndexed { locale, _ -> with("fixed") { db.execSQL(format(locale=locale)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "array-accumulator/fold",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>):String=captured\n"
                    " fun scan(intent:Intent , items:List<Regex>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  items.fold(arrayOf("safe")) { args, _ -> with("fixed") { db.execSQL(format(args=args)) }; '
                    "args }\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "array-accumulator/foldIndexed",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:kotlin.Array<String>):String=captured\n"
                    " fun scan(intent:Intent , items:List<Regex>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  items.foldIndexed(arrayOf("safe")) { _, args, _ -> with("fixed") { '
                    "db.execSQL(format(args=args)) }; args }\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "regex-accumulator",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent , items:List<java.util.Locale>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  items.fold(Regex("x")) { locale, _ -> with("fixed") { db.execSQL(format(locale=locale)) }; '
                    "locale }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "implicit-Locale",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,source:Source) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with(source) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "kotlin-method",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class FakeKotlin { fun arrayOf():Regex=Regex("x") }\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent,kotlin:FakeKotlin) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(args=kotlin.arrayOf())) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "kotlin-callable-property",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Box { val arrayOf = { Regex("x") } }\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent,kotlin:Box) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(args=kotlin.arrayOf())) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "ordinary-callable-property",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Box { val arrayOf = { Regex("x") } }\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent,factory:Box) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(args=factory.arrayOf())) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "classification/Int/False/n+1",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val s=Markup.render { b -> b.section { val n=q.indexOf("x").coerceAtLeast(0); q.length.run '
                    '{ minus(n+1) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            True,
            False,
        ),
        (
            "classification/Int/False/-n",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val s=Markup.render { b -> b.section { val n=q.indexOf("x").coerceAtLeast(0); q.length.run '
                    '{ minus(-n) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            True,
            False,
        ),
        (
            "classification/Int/False/n.coerceAtLeast(0)",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val s=Markup.render { b -> b.section { val n=q.indexOf("x").coerceAtLeast(0); q.length.run '
                    '{ minus(n.coerceAtLeast(0)) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            True,
            False,
        ),
        (
            "classification/Int/True/n+1",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val s=Markup.render { b -> b.section { val n:Int=q.indexOf("x").coerceAtLeast(0); '
                    'q.length.run { minus(n+1) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            True,
            False,
        ),
        (
            "classification/Int/True/-n",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val s=Markup.render { b -> b.section { val n:Int=q.indexOf("x").coerceAtLeast(0); '
                    'q.length.run { minus(-n) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            True,
            False,
        ),
        (
            "classification/Int/True/n.coerceAtLeast(0)",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  val s=Markup.render { b -> b.section { val n:Int=q.indexOf("x").coerceAtLeast(0); '
                    'q.length.run { minus(n.coerceAtLeast(0)) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            True,
            False,
        ),
        (
            "classification/Boolean/False/n && true",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Boolean):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  val s=Markup.render { b -> b.section { val n=q.isBlank(); q.length.run { minus(n && true) } "
                    '}; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "classification/Boolean/True/n && true",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Boolean):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  val s=Markup.render { b -> b.section { val n:Boolean=q.isBlank(); q.length.run { minus(n && "
                    'true) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "repeat-it",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Int):String=captured\n"
                    " fun scan(intent:Intent,rows:List<java.util.Locale>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  rows.forEach { repeat(1) { with("fixed") { db.execSQL(format(locale=it)) } } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "onSuccess-it",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,rows:List<Regex>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  rows.forEach { runCatching { java.util.Locale.US }.onSuccess { with("fixed") { '
                    "db.execSQL(format(locale=it)) } } }\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            True,
            False,
        ),
        (
            "consumed-numeric-depth/8",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun minus(value:Int):String="fixed"\n'
                    " private fun trim():String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  val n=q.length+1+1+1+1+1+1+1\n"
                    "  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            True,
        ),
        (
            "consumed-numeric-depth/9",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun minus(value:Int):String="fixed"\n'
                    " private fun trim():String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  val n=q.length+1+1+1+1+1+1+1+1\n"
                    "  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            True,
        ),
        (
            "consumed-numeric-depth/16",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun minus(value:Int):String="fixed"\n'
                    " private fun trim():String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  val n=q.length+1+1+1+1+1+1+1+1+1+1+1+1+1+1+1\n"
                    "  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "classification/inline",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    "  val s=Markup.render { b -> b.section { q.length.run { "
                    'minus(q.indexOf("x").coerceAtLeast(0)) } }; b.append("SELECT 1"); Unit }\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}",
                )
            ],
            False,
            True,
            False,
        ),
        (
            "fold-explicit-widening",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Any):String=captured\n"
                    " fun scan(intent:Intent , items:List<Regex>) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  items.fold<Regex,Any>(arrayOf("safe")) { args,_ -> with("fixed") { '
                    "db.execSQL(format(args=args)) }; args }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "fold-initial-cast",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Any):String=captured\n"
                    " fun scan(intent:Intent , items:List<Regex>) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  items.fold(arrayOf("safe") as Any) { args,_ -> with("fixed") { '
                    "db.execSQL(format(args=args)) }; args }\n"
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "element-explicit-widening",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Any):String=captured\n"
                    " fun scan(intent:Intent , items:List<kotlin.Array<String>>) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  items.forEach<Any> { args -> with("fixed") { db.execSQL(format(args=args)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "destructured-array-element",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent , items:List<kotlin.Array<Regex>>) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  items.forEach { (args) -> with("fixed") { db.execSQL(format(args=args)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "cast-Locale-to-Any",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(locale:Any):String=captured\n"
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with("fixed") { db.execSQL(format(locale=java.util.Locale.US as Any)) }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            True,
        ),
        (
            "source-parameterless",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun own(block:()->Unit) { block() }\n"
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent , items:List<kotlin.Array<String>>) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  items.forEach { own { with("fixed") { db.execSQL(format(args=it)) } } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "standard-run",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent , items:List<kotlin.Array<String>>) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  items.forEach { run { with("fixed") { db.execSQL(format(args=it)) } } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "standard-runCatching",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent , items:List<kotlin.Array<String>>) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  items.forEach { runCatching { with("fixed") { db.execSQL(format(args=it)) } } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            False,
        ),
        (
            "repeat-scalar/",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " \n"
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  q.let { repeat(1) {  db.execSQL("SELECT "+it) } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            True,
        ),
        (
            "repeat-scalar/index ->",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " \n"
                    " \n"
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  q.let { repeat(1) { index -> db.execSQL("SELECT "+index) } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            True,
        ),
        (
            "inherited-Locale",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "open class Base { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Source:Base()\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent , source:Source) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with(source) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "receiver-no-shadow",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    "class Source { val other:Int=0 }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent , source:Source) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with(source) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            True,
        ),
        (
            "text-receiver-no-shadow",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent ) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  q.run { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            False,
            False,
            True,
        ),
        (
            "implicit-kotlin",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class Factory { fun arrayOf():Regex=Regex("x") }\n'
                    "class Source { val kotlin:Factory=Factory() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent , source:Source) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  captured=q\n"
                    '  with(source) { with("fixed") { db.execSQL(format(args=kotlin.arrayOf())) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "ancestry-bound-head",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "open class Base39 { val Locale:FakeLocale=FakeLocale() }\n"
                    "open class Base38:Base39()\n"
                    "open class Base37:Base38()\n"
                    "open class Base36:Base37()\n"
                    "open class Base35:Base36()\n"
                    "open class Base34:Base35()\n"
                    "open class Base33:Base34()\n"
                    "open class Base32:Base33()\n"
                    "open class Base31:Base32()\n"
                    "open class Base30:Base31()\n"
                    "open class Base29:Base30()\n"
                    "open class Base28:Base29()\n"
                    "open class Base27:Base28()\n"
                    "open class Base26:Base27()\n"
                    "open class Base25:Base26()\n"
                    "open class Base24:Base25()\n"
                    "open class Base23:Base24()\n"
                    "open class Base22:Base23()\n"
                    "open class Base21:Base22()\n"
                    "open class Base20:Base21()\n"
                    "open class Base19:Base20()\n"
                    "open class Base18:Base19()\n"
                    "open class Base17:Base18()\n"
                    "open class Base16:Base17()\n"
                    "open class Base15:Base16()\n"
                    "open class Base14:Base15()\n"
                    "open class Base13:Base14()\n"
                    "open class Base12:Base13()\n"
                    "open class Base11:Base12()\n"
                    "open class Base10:Base11()\n"
                    "open class Base9:Base10()\n"
                    "open class Base8:Base9()\n"
                    "open class Base7:Base8()\n"
                    "open class Base6:Base7()\n"
                    "open class Base5:Base6()\n"
                    "open class Base4:Base5()\n"
                    "open class Base3:Base4()\n"
                    "open class Base2:Base3()\n"
                    "open class Base1:Base2()\n"
                    "open class Base0:Base1()\n"
                    "class Source:Base0()\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,source:Source) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with(source) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}",
                )
            ],
            True,
            False,
            False,
        ),
        (
            "receiver-return-context",
            [
                (
                    "app/Notes.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    "import helpers.make\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  val source=make()\n"
                    '  with(source) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}",
                ),
                (
                    "helpers/Factory.kt",
                    "package helpers\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class String { val Locale:FakeLocale=FakeLocale() }\n"
                    "fun make():String=String()\n",
                ),
            ],
            True,
            False,
            False,
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_review23_callback_and_reference_boundaries(case_id, files, expected, uncertain, checked):
    report = analyze_sources(files)
    hit = any(row["rule_id"] == "AST-SQL-CONCAT" for row in report["findings"])
    state = next(row["state"] for row in report["coverage"] if row["rule_id"] == "AST-SQL-CONCAT")
    reasons = report["metadata"]["native_flow"]["reasons"]
    assert state in {"checked", "limited"}, case_id
    if case_id == "consumed-numeric-depth/16":
        assert state == "limited"
        assert "callable argument type identity unresolved" in reasons
    if hit is not expected:
        assert uncertain and state == "limited", case_id
        assert "callable argument type identity unresolved" in reasons, case_id
    if checked:
        assert state == "checked" and not reasons, case_id


@pytest.mark.parametrize(
    "case,files,expected,mode",
    [
        (
            "inherited-lexical-Locale",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeLocale { val US:Regex=Regex("x") }; open class Base { val Locale:FakeLocale=FakeLocale() }\nclass Notes(private val db: SQLiteDatabase): Base() {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  with("fixed") { db.execSQL(format(locale=Locale.US)) }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "let-generic-widening",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent, values:Array<Regex>) {\n  captured=intent.getStringExtra("q") ?: ""\n  values.let<Any,Unit> { args -> with("fixed") { db.execSQL(format(args=args)) } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "let-component-Regex",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, values:Array<Regex>) {\n  captured=intent.getStringExtra("q") ?: ""\n  values.let { (args) -> with("fixed") { db.execSQL(format(args=args)) } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "also-component-Regex",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, values:Array<Regex>) {\n  captured=intent.getStringExtra("q") ?: ""\n  values.also { (args) -> with("fixed") { db.execSQL(format(args=args)) } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "project-number-Int",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Int\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent,n:Int) {\n  captured=intent.getStringExtra("q") ?: ""\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                )
            ],
            True,
            "checked",
        ),
        (
            "project-number-synthetic.Int",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Int\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent,n:synthetic.Int) {\n  captured=intent.getStringExtra("q") ?: ""\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                )
            ],
            True,
            "checked",
        ),
        (
            "project-number-kotlin.Int",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Int\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent,n:kotlin.Int) {\n  captured=intent.getStringExtra("q") ?: ""\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                )
            ],
            False,
            "checked",
        ),
        (
            "plain-let-array",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent, values:Array<Regex>) {\n  captured=intent.getStringExtra("q") ?: ""\n  values.let { args -> with("fixed") { db.execSQL(format(args=args)) } }\n }\n}\n',
                )
            ],
            False,
            "checked",
        ),
        (
            "generic-let-explicit-Any",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent, values:Array<Regex>) {\n  captured=intent.getStringExtra("q") ?: ""\n  values.let<Any,Unit> { args:Any -> with("fixed") { db.execSQL(format(args=args)) } }\n }\n}\n',
                )
            ],
            True,
            "checked",
        ),
        (
            "typed-component-let",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, values:Array<Regex>) {\n  captured=intent.getStringExtra("q") ?: ""\n  values.let { (args):Array<Regex> -> with("fixed") { db.execSQL(format(args=args)) } }\n }\n}\n',
                )
            ],
            True,
            "parser",
        ),
        (
            "typed-component-also",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, values:Array<Regex>) {\n  captured=intent.getStringExtra("q") ?: ""\n  values.also { (args):Array<Regex> -> with("fixed") { db.execSQL(format(args=args)) } }\n }\n}\n',
                )
            ],
            True,
            "parser",
        ),
        (
            "private-inherited-Locale",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeLocale { val US:Regex=Regex("x") }; open class Base { private val Locale:FakeLocale=FakeLocale() }\nclass Notes(private val db: SQLiteDatabase): Base() {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  with("fixed") { db.execSQL(format(locale=Locale.US)) }\n }\n}\n',
                )
            ],
            False,
            "checked",
        ),
        (
            "no-inherited-Locale",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nopen class Base { val fixed=0 }\nclass Notes(private val db: SQLiteDatabase): Base() {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  with("fixed") { db.execSQL(format(locale=Locale.US)) }\n }\n}\n',
                )
            ],
            False,
            "checked",
        ),
        (
            "inherited-lexical-kotlin",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeKotlin { fun arrayOf():Regex=Regex("x") }; open class Base { val kotlin:FakeKotlin=FakeKotlin() }\nclass Notes(private val db: SQLiteDatabase): Base() {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  with("fixed") { db.execSQL(format(args=kotlin.arrayOf())) }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "numeric-inferred-constructor",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Int\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent,unused:kotlin.Int) {\n  captured=intent.getStringExtra("q") ?: ""\n  val n=Int()\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                )
            ],
            True,
            "checked",
        ),
        (
            "numeric-copy",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Int\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent,n:Int) {\n  captured=intent.getStringExtra("q") ?: ""\n  val copy=n\n  copy.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                )
            ],
            True,
            "checked",
        ),
        (
            "numeric-import-alias",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport helpers.Amount as Int\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent,n:Int) {\n  captured=intent.getStringExtra("q") ?: ""\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                ),
                ("Amount.kt", "package helpers; class Amount"),
            ],
            True,
            "checked",
        ),
        (
            "numeric-standard-alias",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\ntypealias Int=kotlin.Int\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent,n:Int) {\n  captured=intent.getStringExtra("q") ?: ""\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                )
            ],
            False,
            "checked",
        ),
        (
            "numeric-project-alias",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Amount\ntypealias Int=Amount\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent,n:Int) {\n  captured=intent.getStringExtra("q") ?: ""\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "numeric-type-parameter",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Amount\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun <Int> scan(intent:Intent,n:Int) {\n  captured=intent.getStringExtra("q") ?: ""\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "numeric-nullable-standard",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Int\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent,n:kotlin.Int?) {\n  captured=intent.getStringExtra("q") ?: ""\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "numeric-return-context",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun minus(other:kotlin.Int):String=captured\n private fun trim():String="fixed"\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  val n=helpers.make()\n  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n }\n}\n',
                ),
                ("Numbers.kt", "package helpers; class Int; fun make():Int=Int()"),
            ],
            True,
            "checked",
        ),
        (
            "cast-scope-as",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeLocale { val US:Regex=Regex("x") }; class Source { val Locale:FakeLocale=FakeLocale() }\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent, holder:Any) {\n  captured=intent.getStringExtra("q") ?: ""\n  with(holder as Source) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "cast-scope-safe-as",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeLocale { val US:Regex=Regex("x") }; class Source { val Locale:FakeLocale=FakeLocale() }\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent, holder:Any) {\n  captured=intent.getStringExtra("q") ?: ""\n  (holder as? Source)?.run { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "cast-scope-smart-cast",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeLocale { val US:Regex=Regex("x") }; class Source { val Locale:FakeLocale=FakeLocale() }\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent, holder:Any) {\n  captured=intent.getStringExtra("q") ?: ""\n  if (holder is Source) with(holder) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "nonnull-widened-Locale",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(locale:Any):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  with("fixed") { db.execSQL(format(locale=(java.util.Locale.US as Any)!!)) }\n }\n}\n',
                )
            ],
            True,
            "checked",
        ),
        (
            "unknown-member-async",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, client:helpers.Client, items:List<kotlin.Array<String>>) {\n  captured=intent.getStringExtra("q") ?: ""\n  items.forEach { client.async { with("fixed") { db.execSQL(format(args=it)) } } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "unknown-member-run",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, client:helpers.Client, items:List<kotlin.Array<String>>) {\n  captured=intent.getStringExtra("q") ?: ""\n  items.forEach { client.run { with("fixed") { db.execSQL(format(args=it)) } } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "source-lazy-one-argument",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n private fun lazy(block:(Regex)->Unit) { block(Regex("x")) }\n fun scan(intent:Intent, items:List<kotlin.Array<String>>) {\n  captured=intent.getStringExtra("q") ?: ""\n  items.forEach { lazy { with("fixed") { db.execSQL(format(args=it)) } } }\n }\n}\n',
                )
            ],
            True,
            "flow",
        ),
        (
            "unused-hint-extras",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  intent.extras.run { val label=toString(); db.execSQL("SELECT 1") }\n }\n}\n',
                )
            ],
            False,
            "checked",
        ),
        (
            "traced-zero-callback-runOnUiThread",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent, client:helpers.Client) {\n  captured=intent.getStringExtra("q") ?: ""\n  listOf(captured).forEach { client.runOnUiThread { println(it) }; db.execSQL("SELECT 1") }\n }\n}\n',
                )
            ],
            False,
            "flow",
        ),
        (
            "traced-zero-callback-post",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent, client:helpers.Client) {\n  captured=intent.getStringExtra("q") ?: ""\n  listOf(captured).forEach { client.post { println(it) }; db.execSQL("SELECT 1") }\n }\n}\n',
                )
            ],
            False,
            "flow",
        ),
        (
            "traced-zero-callback-execute",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent, client:helpers.Client) {\n  captured=intent.getStringExtra("q") ?: ""\n  listOf(captured).forEach { client.execute { println(it) }; db.execSQL("SELECT 1") }\n }\n}\n',
                )
            ],
            False,
            "flow",
        ),
        (
            "unknown-run-member-it",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport helpers.Runner\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, values:List<Array<String>>, runner:Runner) {\n  captured=intent.getStringExtra("q") ?: ""\n  values.forEach { runner.run { with("fixed") { db.execSQL(format(args=it)) } } }\n }\n}\n',
                )
            ],
            True,
            "identity",
        ),
        (
            "distinct-source-budget-direct",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  val q0=intent.getStringExtra("q0") ?: ""\nval q1=intent.getStringExtra("q1") ?: ""\nval q2=intent.getStringExtra("q2") ?: ""\nval q3=intent.getStringExtra("q3") ?: ""\nval q4=intent.getStringExtra("q4") ?: ""\nval q5=intent.getStringExtra("q5") ?: ""\nval q6=intent.getStringExtra("q6") ?: ""\nval q7=intent.getStringExtra("q7") ?: ""\nval q8=intent.getStringExtra("q8") ?: ""\n val s=q0+q1+q2+q3+q4+q5+q6+q7+q8\n db.execSQL(s)\n }\n}\n',
                )
            ],
            True,
            "budget",
        ),
        (
            "distinct-source-budget-run",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  val q0=intent.getStringExtra("q0") ?: ""\nval q1=intent.getStringExtra("q1") ?: ""\nval q2=intent.getStringExtra("q2") ?: ""\nval q3=intent.getStringExtra("q3") ?: ""\nval q4=intent.getStringExtra("q4") ?: ""\nval q5=intent.getStringExtra("q5") ?: ""\nval q6=intent.getStringExtra("q6") ?: ""\nval q7=intent.getStringExtra("q7") ?: ""\nval q8=intent.getStringExtra("q8") ?: ""\n val s=run { q0+q1+q2+q3+q4+q5+q6+q7+q8 }\n db.execSQL(s)\n }\n}\n',
                )
            ],
            True,
            "budget",
        ),
        (
            "distinct-source-budget-let",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  val q0=intent.getStringExtra("q0") ?: ""\nval q1=intent.getStringExtra("q1") ?: ""\nval q2=intent.getStringExtra("q2") ?: ""\nval q3=intent.getStringExtra("q3") ?: ""\nval q4=intent.getStringExtra("q4") ?: ""\nval q5=intent.getStringExtra("q5") ?: ""\nval q6=intent.getStringExtra("q6") ?: ""\nval q7=intent.getStringExtra("q7") ?: ""\nval q8=intent.getStringExtra("q8") ?: ""\n val s="fixed".let { q0+q1+q2+q3+q4+q5+q6+q7+q8 }\n db.execSQL(s)\n }\n}\n',
                )
            ],
            True,
            "budget",
        ),
        (
            "distinct-source-budget-unknown",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Any):String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  val q0=intent.getStringExtra("q0") ?: ""\nval q1=intent.getStringExtra("q1") ?: ""\nval q2=intent.getStringExtra("q2") ?: ""\nval q3=intent.getStringExtra("q3") ?: ""\nval q4=intent.getStringExtra("q4") ?: ""\nval q5=intent.getStringExtra("q5") ?: ""\nval q6=intent.getStringExtra("q6") ?: ""\nval q7=intent.getStringExtra("q7") ?: ""\nval q8=intent.getStringExtra("q8") ?: ""\n val s=helpers.render { q0+q1+q2+q3+q4+q5+q6+q7+q8 }\n db.execSQL(s)\n }\n}\n',
                )
            ],
            True,
            "budget",
        ),
        (
            "Any-without-narrowing",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeLocale { val US:Regex=Regex("x") }; class Source { val Locale:FakeLocale=FakeLocale() }\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent, holder:Any) {\n  captured=intent.getStringExtra("q") ?: ""\n  with(holder) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n }\n}\n',
                )
            ],
            False,
            "checked",
        ),
        (
            "negative-is-arm",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeLocale { val US:Regex=Regex("x") }; class Source { val Locale:FakeLocale=FakeLocale() }\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent, holder:Any) {\n  captured=intent.getStringExtra("q") ?: ""\n  if (holder !is Source) with(holder) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n }\n}\n',
                )
            ],
            False,
            "checked",
        ),
        (
            "shadowed-is-binding",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeLocale { val US:Regex=Regex("x") }; class Source { val Locale:FakeLocale=FakeLocale() }\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent, holder:Any) {\n  captured=intent.getStringExtra("q") ?: ""\n  if (holder is Source) { val holder:Any="fixed"; with(holder) { with("fixed") { db.execSQL(format(locale=Locale.US)) } } }\n }\n}\n',
                )
            ],
            False,
            "flow",
        ),
        (
            "cast-widened-subject",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\nclass FakeLocale { val US:Regex=Regex("x") }; class Source { val Locale:FakeLocale=FakeLocale() }\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(locale:Regex):String=captured\n fun scan(intent:Intent, holder:Any) {\n  captured=intent.getStringExtra("q") ?: ""\n  with(holder as Any) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n }\n}\n',
                )
            ],
            False,
            "checked",
        ),
        (
            "standard-literal-run-outer-it",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, items:List<Array<String>>) {\n  captured=intent.getStringExtra("q") ?: ""\n  items.forEach { "fixed".run { with("fixed") { db.execSQL(format(args=it)) } } }\n }\n}\n',
                )
            ],
            False,
            "zero",
        ),
        (
            "source-member-run-0",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, client:helpers.Client, items:List<Array<String>>) {\n  captured=intent.getStringExtra("q") ?: ""\n  items.forEach { client.run { with("fixed") { db.execSQL(format(args=it)) } } }\n }\n}\n',
                ),
                ("Client.kt", "package helpers; class Client { fun run(block:()->Unit) { block() } }"),
            ],
            False,
            "zero",
        ),
        (
            "source-member-run-1",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, client:helpers.Client, items:List<Array<String>>) {\n  captured=intent.getStringExtra("q") ?: ""\n  items.forEach { client.run { with("fixed") { db.execSQL(format(args=it)) } } }\n }\n}\n',
                ),
                (
                    "Client.kt",
                    'package helpers; class Client { fun run(block:(Regex)->Unit) { block(Regex("x")) } }',
                ),
            ],
            True,
            "identity",
        ),
        (
            "source-member-async-0",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, client:helpers.Client, items:List<Array<String>>) {\n  captured=intent.getStringExtra("q") ?: ""\n  items.forEach { client.async { with("fixed") { db.execSQL(format(args=it)) } } }\n }\n}\n',
                ),
                ("Client.kt", "package helpers; class Client { fun async(block:()->Unit) { block() } }"),
            ],
            False,
            "zero",
        ),
        (
            "source-member-async-1",
            [
                (
                    "Main.kt",
                    'package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.util.Locale\n\nclass Notes(private val db: SQLiteDatabase) {\n private var captured=""\n private fun format(args:Regex):String=captured\n fun scan(intent:Intent, client:helpers.Client, items:List<Array<String>>) {\n  captured=intent.getStringExtra("q") ?: ""\n  items.forEach { client.async { with("fixed") { db.execSQL(format(args=it)) } } }\n }\n}\n',
                ),
                (
                    "Client.kt",
                    'package helpers; class Client { fun async(block:(Regex)->Unit) { block(Regex("x")) } }',
                ),
            ],
            True,
            "identity",
        ),
    ],
)
def test_review24_nominal_and_budget_boundaries(case, files, expected, mode):
    report = analyze_sources(files)
    state = _state(report, SQL)
    if mode == "parser" and not _hit(report, SQL):
        assert state == "partial"
        assert any(row.get("parse_errors") for row in report["metadata"]["files"])
        return
    assert _hit(report, SQL) is expected, (case, _reasons(report))
    if mode == "budget":
        assert state == "partial"
        assert "source trace budget" in _budget(report)
        return
    assert state in {"checked", "limited"}
    if mode == "checked":
        assert state == "checked" and not _reasons(report)
    elif mode == "identity":
        assert state == "limited"
        assert "callable argument type identity unresolved" in _reasons(report)
    elif mode == "zero":
        assert "callable argument type identity unresolved" not in _reasons(report)


_REVIEW24_HEADER = (
    "package synthetic\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\n"
)


def _review24_work(size: int, mode: str) -> dict[str, Any]:
    from unittest.mock import patch

    from mobile_audit.native_flow import NativeFlow

    counts = dict(result_walks=0, result_steps=0, resolve=0)
    original_result = Analyzer.closure_value_expressions
    original_work = Analyzer.closure_work
    original_resolve = NativeFlow.resolve
    active = 0

    def results(self, closure):
        nonlocal active
        owner = self.closure_owner(closure)
        selected = (
            mode == "fold"
            and owner is not None
            and owner.name == "fold"
            and self.closure_classification_work is None
        )
        if selected:
            counts["result_walks"] += 1
            active += 1
        try:
            return original_result(self, closure)
        finally:
            if selected:
                active -= 1

    def work(self):
        if active:
            counts["result_steps"] += 1
        return original_work(self)

    def resolve(self, *args, **kwargs):
        counts["resolve"] += 1
        return original_resolve(self, *args, **kwargs)

    if mode == "fold":
        body = (
            'items.fold(arrayOf("safe")) { args, _ ->\n'
            + "\n".join('with("fixed") { db.execSQL(format(args=args)) }' for _ in range(size))
            + "\nargs\n}"
        )
        parameter = "items:List<Regex>"
    else:
        body = (
            "listOf(captured).forEach { client.run { "
            + ";".join("println(it)" for _ in range(size))
            + ' } }; db.execSQL("SELECT 1")'
        )
        parameter = "client:helpers.Client"
    source = (
        _REVIEW24_HEADER
        + """class Notes(private val db:SQLiteDatabase) {
 private var captured=""
 private fun format(args:Any):String=captured
 fun scan(intent:Intent, """
        + parameter
        + """) {
  captured=intent.getStringExtra("q") ?: ""
  """
        + body
        + """
 }
}
"""
    )
    with (
        patch.object(Analyzer, "closure_value_expressions", results),
        patch.object(Analyzer, "closure_work", work),
        patch.object(NativeFlow, "resolve", resolve),
    ):
        report = analyze_sources([("Main.kt", source)])
    return dict(
        size=size,
        counts=counts,
        hit=any(f["rule_id"] == "AST-SQL-CONCAT" for f in report["findings"]),
        state=next(r["state"] for r in report["coverage"] if r["rule_id"] == "AST-SQL-CONCAT"),
        reasons=report["metadata"]["native_flow"]["reasons"],
    )


def test_review24_repeated_accumulator_consumers_have_linear_syntax_work():
    rows = [_review24_work(size, "fold") for size in (8, 32, 64)]
    assert all(not row["hit"] and row["state"] != "partial" for row in rows)
    assert rows[0]["counts"]["result_steps"] > 0
    assert rows[-1]["counts"]["result_steps"] <= 9 * rows[0]["counts"]["result_steps"]
    assert rows[-1]["counts"]["resolve"] <= 9 * rows[0]["counts"]["resolve"]


def test_review24_unknown_callback_reads_have_bounded_resolution_work():
    rows = [_review24_work(size, "callback") for size in (8, 32, 64)]
    assert all(not row["hit"] and row["state"] == "limited" for row in rows)
    assert all("callable argument type identity unresolved" in row["reasons"] for row in rows)
    assert rows[0]["counts"]["resolve"] > 0
    assert rows[-1]["counts"]["resolve"] <= 9 * rows[0]["counts"]["resolve"]


@pytest.mark.parametrize(
    "case,files,expected,mode",
    [
        (
            "default-package-Int",
            [
                (
                    "Caller.kt",
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Int\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:kotlin.Int):String=captured\n"
                    ' private fun trim():String="fixed"\n'
                    " fun scan(intent:Intent,n:Int) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "project-String",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class String\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent,n:String) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "reassigned-is-subject",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,initial:Any) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  var holder:Any=initial\n"
                    "  if (holder is kotlin.String) {\n"
                    "   holder=Source()\n"
                    '   with(holder) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    "  }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "content-project-Int-inline",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " private fun trim(v:String):Int=Int(v)\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    '  val s=Markup.render({ b -> b.section({ trim(q).toString() }); b.append("SELECT 1"); Unit '
                    "})\n"
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}\n",
                ),
                (
                    "Holder.kt",
                    "package synthetic\n"
                    "class Int(val raw:kotlin.String) { override fun toString():kotlin.String=raw }",
                ),
            ],
            True,
            "constructor field mapping unavailable",
        ),
        (
            "content-project-Int-explicit-local",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    " private fun trim(v:String):Int=Int(v)\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q=intent.getStringExtra("q") ?: ""\n'
                    "  val s=Markup.render({ b -> b.section({ val box:Int=trim(q); box.toString() }); "
                    'b.append("SELECT 1"); Unit })\n'
                    "  db.execSQL(s)\n"
                    " }\n"
                    "}\n",
                ),
                (
                    "Holder.kt",
                    "package synthetic\n"
                    "class Int(val raw:kotlin.String) { override fun toString():kotlin.String=raw }",
                ),
            ],
            True,
            "constructor field mapping unavailable",
        ),
        (
            "upward-String-cast",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  ("fixed" as Any).run { db.execSQL(trim()) }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "String-import-alias-input",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import helpers.Payload as String\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "open class Base { fun pick(v:kotlin.String):kotlin.String=v }\n"
                    "class Notes(private val db:SQLiteDatabase):Base() {\n"
                    ' private fun pick(v:String):kotlin.String="fixed"\n'
                    ' fun scan(intent:Intent) { db.execSQL(pick(intent.getStringExtra("q")!!)) }\n'
                    "}\n",
                ),
                ("Payload.kt", "package helpers; class Payload"),
            ],
            True,
            "budget",
        ),
        (
            "String-import-alias-fixed",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import helpers.Payload as String\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "open class Base { fun pick(v:kotlin.String):kotlin.String=v }\n"
                    "class Notes(private val db:SQLiteDatabase):Base() {\n"
                    ' private fun pick(v:String):kotlin.String="fixed"\n'
                    ' fun scan(intent:Intent) { db.execSQL(pick("fixed")) }\n'
                    "}\n",
                ),
                ("Payload.kt", "package helpers; class Payload"),
            ],
            False,
            "inherited overload signature unresolved",
        ),
        (
            "typed-source-any-guard",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }; class Source { val '
                    "Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent, holder:Source) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  if (holder is Any) with(holder) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "nullable-source-any-guard",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }; class Source { val '
                    "Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent, holder:Source?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  if (holder is Any) with(holder) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "typed-source-marker-guard",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'interface Marker; class FakeLocale { val US:Regex=Regex("x") }; class Source:Marker { val '
                    "Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent, holder:Source) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  if (holder is Marker) with(holder) { with("fixed") { db.execSQL(format(locale=Locale.US)) } '
                    "}\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "eight-source-duplicate-last",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  val q0=intent.getStringExtra("q0") ?: ""\n'
                    'val q1=intent.getStringExtra("q1") ?: ""\n'
                    'val q2=intent.getStringExtra("q2") ?: ""\n'
                    'val q3=intent.getStringExtra("q3") ?: ""\n'
                    'val q4=intent.getStringExtra("q4") ?: ""\n'
                    'val q5=intent.getStringExtra("q5") ?: ""\n'
                    'val q6=intent.getStringExtra("q6") ?: ""\n'
                    'val q7=intent.getStringExtra("q7") ?: ""\n'
                    " val s=run { q0+q1+q2+q3+q4+q5+q6+q7+q0.trim() }; db.execSQL(s)\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "budget",
        ),
        (
            "eight-source-all-locations-retained",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  val q0=intent.getStringExtra("q0") ?: ""\n'
                    'val q1=intent.getStringExtra("q1") ?: ""\n'
                    'val q2=intent.getStringExtra("q2") ?: ""\n'
                    'val q3=intent.getStringExtra("q3") ?: ""\n'
                    'val q4=intent.getStringExtra("q4") ?: ""\n'
                    'val q5=intent.getStringExtra("q5") ?: ""\n'
                    'val q6=intent.getStringExtra("q6") ?: ""\n'
                    'val q7=intent.getStringExtra("q7") ?: ""\n'
                    " val s=run { q0+q1+q2+q3+q4+q5+q6+q0.trim()+q7 }; db.execSQL(s)\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "source trace abstention",
        ),
        (
            "implicit-unknown-run",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    " \n"
                    " fun scan(intent:Intent, values:List<Array<String>>, runner:helpers.Runner) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with(runner) { values.forEach { run { with("fixed") { db.execSQL(format(args=it)) } } } }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "shadowed-client-parameter",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    " \n"
                    " fun scan(intent:Intent, client:String, factory:helpers.Factory, items:List<Array<String>>) "
                    "{\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  val client=factory.client(); items.forEach { client.run { with("fixed") { '
                    "db.execSQL(format(args=it)) } } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "own-companion-Locale",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " companion object { val Locale:FakeLocale=FakeLocale() }\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(locale=Locale.US)) }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "inherited-companion-Locale",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "open class Base { companion object { val Locale:FakeLocale=FakeLocale() } }\n"
                    "class Notes(private val db:SQLiteDatabase):Base() {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with("fixed") { db.execSQL(format(locale=Locale.US)) }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "guard-after-receiver-capture",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " \n"
                    " fun scan(intent:Intent, holder:Any) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  with(holder) { if (holder is Source) { with("fixed") { db.execSQL(format(locale=Locale.US)) '
                    "} } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "anonymous-inherited-Locale",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "open class Base { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  val receiver=object:Base() { fun execute() { with("fixed") { '
                    "db.execSQL(format(locale=Locale.US)) } } }; receiver.execute()\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "anonymous callable scope unavailable",
        ),
        (
            "genuine-String-with-project-shadow",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class String\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent,n:kotlin.String) { captured=intent.getStringExtra("q") ?: ""; n.run { '
                    "db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "overload-project-typealias",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "typealias String=helpers.Payload\n"
                    "open class Base { fun pick(v:kotlin.String):kotlin.String=v.toString() }\n"
                    "class Notes(private val db:SQLiteDatabase):Base() { private fun "
                    'pick(v:String):kotlin.String="fixed"; fun scan(intent:Intent) { '
                    'db.execSQL(pick(intent.getStringExtra("q")!!)) } }',
                ),
                ("Payload.kt", "package helpers; class Payload"),
            ],
            True,
            "budget",
        ),
        (
            "overload-generic-String-parameter",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "open class Base { fun pick(v:kotlin.String):kotlin.String=v.toString() }\n"
                    "class Notes(private val db:SQLiteDatabase):Base() { private fun <String> "
                    'pick(v:String):kotlin.String="fixed"; fun scan(intent:Intent) { '
                    'db.execSQL(pick(intent.getStringExtra("q")!!)) } }',
                )
            ],
            True,
            "budget",
        ),
        (
            "overload-standard-typealias",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "typealias String=kotlin.String\n"
                    "open class Base { fun pick(v:Any):kotlin.String=v.toString() }\n"
                    "class Notes(private val db:SQLiteDatabase):Base() { private fun "
                    'pick(v:String):kotlin.String="fixed"; fun scan(intent:Intent) { '
                    'db.execSQL(pick(intent.getStringExtra("q")!!)) } }',
                )
            ],
            False,
            "checked",
        ),
        (
            "mutable-now-String",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    ' fun scan(intent:Intent,initial:Any) { captured=intent.getStringExtra("q") ?: ""; var '
                    'holder:Any=initial; if(holder is Source) { holder="fixed"; with(holder) { with("fixed") { '
                    "db.execSQL(format(locale=Locale.US)) } } } }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "write-before-test",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    ' fun scan(intent:Intent,initial:Any) { captured=intent.getStringExtra("q") ?: ""; var '
                    'holder:Any=initial; holder="fixed"; if(holder is kotlin.String) { with(holder) { '
                    'with("fixed") { db.execSQL(format(locale=Locale.US)) } } } }\n'
                    "}\n",
                )
            ],
            False,
            "object alias identity unavailable",
        ),
        (
            "write-after-capture",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    ' fun scan(intent:Intent,initial:Any) { captured=intent.getStringExtra("q") ?: ""; var '
                    'holder:Any=initial; if(holder is kotlin.String) with(holder) { holder=Source(); with("fixed") '
                    "{ db.execSQL(format(locale=Locale.US)) } } }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "private-inherited-companion",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "open class Base { companion object { private val Locale:FakeLocale=FakeLocale() } }\n"
                    "class Notes(private val db:SQLiteDatabase):Base() {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; with("fixed") { '
                    "db.execSQL(format(locale=Locale.US)) } }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "builtin-index-with-project-Int",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Int(val raw:kotlin.String)\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' fun scan(intent:Intent) { val q=intent.getStringExtra("q") ?: ""; val s=Markup.render { b -> '
                    "b.section { buildString { listOf(q).forEachIndexed { index, _ -> append(index.toString()) } } "
                    '}; b.append("SELECT 1"); Unit }; db.execSQL(s) }\n'
                    "}\n",
                )
            ],
            False,
            "unresolved callable identity",
        ),
        (
            "nullable-builtin-content",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' fun scan(intent:Intent) { val q=intent.getStringExtra("q") ?: ""; val s=Markup.render { b -> '
                    'b.section { val n:Long?=q.length.toLong(); "$n" }; b.append("SELECT 1"); Unit }; '
                    "db.execSQL(s) }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "inferred-source-any-guard",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }; class Source { val '
                    "Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  val holder=Source(); if (holder is Any) with(holder) { with("fixed") { '
                    "db.execSQL(format(locale=Locale.US)) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "nested-source-any-guards",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }; class Source { val '
                    "Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent, holder:Any) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  if (holder is Source) if(holder is Any) with(holder) { with("fixed") { '
                    "db.execSQL(format(locale=Locale.US)) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "callback-upcast-to-Any",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent, client:helpers.Client, items:List<Array<String>>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '   items.forEach { (client as Any).run { with("fixed") { db.execSQL(format(args=it)) } } }\n'
                    " }\n"
                    "}\n",
                ),
                (
                    "Client.kt",
                    'package helpers; class Client { fun run(block:(Regex)->Unit) { block(Regex("x")) } }',
                ),
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "callback-positive-source-test",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent, client:Any, items:List<Array<String>>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  if(client is helpers.Client) items.forEach { client.run { with("fixed") { '
                    "db.execSQL(format(args=it)) } } }\n"
                    " }\n"
                    "}\n",
                ),
                (
                    "Client.kt",
                    'package helpers; class Client { fun run(block:(Regex)->Unit) { block(Regex("x")) } }',
                ),
            ],
            True,
            "callable argument type identity unresolved",
        ),
    ],
)
def test_review25_type_origins_and_receiver_facts(case, files, expected, mode):
    report = analyze_sources(files)
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), case
    assert _hit(report, SQL) is expected, (case, _reasons(report))
    state = _state(report, SQL)
    if mode == "checked":
        assert state == "checked" and not _reasons(report), case
    elif mode == "budget":
        assert state == "partial" and "source trace budget" in _budget(report), case
    else:
        assert state == "limited" and mode in _reasons(report), (case, _reasons(report))
        assert not _budget(report), case


@pytest.mark.parametrize("last_source, loses_location", [(0, True), (7, False)])
def test_review25_source_cap_compares_retained_locations(last_source, loses_location):
    from types import SimpleNamespace

    from mobile_audit.source_analysis import TRACE_SOURCE_LOSS, SourceNode, Trace, Value, _union

    nodes = [SimpleNamespace(id=i, type="identifier") for i in range(8)]
    values = [Value((Trace(i, node, "input"),)) for i, node in enumerate(nodes)]
    # Raw and located forms of one syntax node denote the same source site.
    located = SourceNode(nodes[last_source], {"path": "Main.kt", "offset": last_source})
    values.append(Value((Trace(8, located, "input"),)))
    value = _union(values)
    assert len(value.traces) == 8
    assert any(TRACE_SOURCE_LOSS in trace.description for trace in value.traces) is loses_location


@pytest.mark.parametrize(
    "case,files,expected,mode",
    [
        (
            "escaped-declaration-default-package-Int",
            [
                (
                    "Caller.kt",
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class `Int`\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:kotlin.Int):String=captured\n"
                    ' private fun trim():String="fixed"\n'
                    " fun scan(intent:Intent,n:Int) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "escaped-declaration-project-String",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class `String`\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent,n:String) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-source-String",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class String\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent,n:String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-standard-String",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent,n:String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-alias-String",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Payload\n"
                    "typealias String = Payload\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent,n:String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "source_string_constructor",
            [
                (
                    "app/Case0.kt",
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class String\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; val n=String(); n.run { '
                    "db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "source_regex_constructor",
            [
                (
                    "app/Case1.kt",
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Regex\n"
                    "class RegexProbe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun replace(regex:Regex, replacement:kotlin.String):kotlin.String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; val pattern=Regex(); '
                    'with("fixed") { db.execSQL(replace(regex=pattern, replacement="x")) } }\n'
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "qualified_source_string_constructor",
            [
                (
                    "app/Case2.kt",
                    "package constructors\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class String\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; val n=String(); n.run { '
                    "db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "safe_cast_string",
            [
                (
                    "app/Case3.kt",
                    "package safecast\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent, receiver:Any) { captured=intent.getStringExtra("q") ?: ""; '
                    "with(receiver as? kotlin.String) { db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "explicit_nullable_string_cast",
            [
                (
                    "app/Case4.kt",
                    "package nullablecast\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent, receiver:Any) { captured=intent.getStringExtra("q") ?: ""; '
                    "with(receiver as kotlin.String?) { db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "safe_cast_numeric",
            [
                (
                    "app/Case5.kt",
                    "package numericcast\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class NumericProbe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:kotlin.Int):String=captured\n"
                    ' private fun trim():String="fixed"\n'
                    ' fun scan(intent:Intent, receiver:Any) { captured=intent.getStringExtra("q") ?: ""; '
                    "with(receiver as? kotlin.Int) { val text=minus(1); text.run { db.execSQL(trim()) } } }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "private_inherited_callback",
            [
                (
                    "app/Case6.kt",
                    "package privatecallback\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'open class Base { private fun run(block:(Regex)->Unit) { block(Regex("x")) } }\n'
                    "class PrivateProbe(private val db:SQLiteDatabase):Base() {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    ' fun scan(intent:Intent, items:List<Array<String>>) { captured=intent.getStringExtra("q") ?: '
                    '""; items.forEach { run { with("fixed") { db.execSQL(format(args=it)) } } } }\n'
                    "}\n",
                )
            ],
            False,
            "boundary",
        ),
        (
            "private_companion_callback",
            [
                (
                    "app/Case7.kt",
                    "package privatecompanioncallback\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'open class Base { companion object { private fun run(block:(Regex)->Unit) { block(Regex("x")) '
                    "} } }\n"
                    "class CompanionProbe(private val db:SQLiteDatabase):Base() {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    ' fun scan(intent:Intent, items:List<Array<String>>) { captured=intent.getStringExtra("q") ?: '
                    '""; items.forEach { run { with("fixed") { db.execSQL(format(args=it)) } } } }\n'
                    "}\n",
                )
            ],
            False,
            "boundary",
        ),
        (
            "explicit_source_string_local",
            [
                (
                    "app/Case8.kt",
                    "package explicitconstruct\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class String\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; val n:String=String(); '
                    "n.run { db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "direct_source_string_constructor",
            [
                (
                    "app/Case9.kt",
                    "package directconstruct\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class String\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; String().run { '
                    "db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "trace_loses_location",
            [
                (
                    "app/Case10.kt",
                    "package trace_loses_location\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q0=intent.getStringExtra("q0") ?: ""\n'
                    '  val q1=intent.getStringExtra("q1") ?: ""\n'
                    '  val q2=intent.getStringExtra("q2") ?: ""\n'
                    '  val q3=intent.getStringExtra("q3") ?: ""\n'
                    '  val q4=intent.getStringExtra("q4") ?: ""\n'
                    '  val q5=intent.getStringExtra("q5") ?: ""\n'
                    '  val q6=intent.getStringExtra("q6") ?: ""\n'
                    '  val q7=intent.getStringExtra("q7") ?: ""\n'
                    '  val s="fixed".let { q0+q1+q2+q3+q4+q5+q6+q7+q1.trim() }; db.execSQL(s)\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "budget",
        ),
        (
            "trace_retains_locations",
            [
                (
                    "app/Case11.kt",
                    "package trace_retains_locations\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  val q0=intent.getStringExtra("q0") ?: ""\n'
                    '  val q1=intent.getStringExtra("q1") ?: ""\n'
                    '  val q2=intent.getStringExtra("q2") ?: ""\n'
                    '  val q3=intent.getStringExtra("q3") ?: ""\n'
                    '  val q4=intent.getStringExtra("q4") ?: ""\n'
                    '  val q5=intent.getStringExtra("q5") ?: ""\n'
                    '  val q6=intent.getStringExtra("q6") ?: ""\n'
                    '  val q7=intent.getStringExtra("q7") ?: ""\n'
                    '  val s="fixed".let { q0+q1+q2+q3+q4+q5+q6+q1.trim()+q7 }; db.execSQL(s)\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "source trace abstention",
        ),
        (
            "nullable_string_alias",
            [
                (
                    "app/Case12.kt",
                    "package nullstringalias\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "typealias String=kotlin.String?\n"
                    "class AliasProbe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent, receiver:String) { captured=intent.getStringExtra("q") ?: ""; '
                    "receiver.run { db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable_numeric_alias",
            [
                (
                    "app/Case13.kt",
                    "package nullnumericalias\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "typealias Int=kotlin.Int?\n"
                    "class AliasProbe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:kotlin.Int):String=captured\n"
                    ' private fun trim():String="fixed"\n'
                    ' fun scan(intent:Intent, receiver:Int) { captured=intent.getStringExtra("q") ?: ""; '
                    "receiver.run { val text=minus(1); text.run { db.execSQL(trim()) } } }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "literal-nullable-String-cast",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; ("fixed" as '
                    "kotlin.String?).run { db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "literal-safe-String-cast",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; ("fixed" as? '
                    "kotlin.String).run { db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "literal-nonnullable-String-cast",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; ("fixed" as '
                    "kotlin.String).run { db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "nullable-String-copy",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' fun scan(intent:Intent,initial:kotlin.String?) { captured=intent.getStringExtra("q") ?: ""; '
                    "val holder=initial; holder.run { db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "cross-file-default-Int",
            [
                (
                    "Caller.kt",
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:kotlin.Int):String=captured\n"
                    ' private fun trim():String="fixed"\n'
                    " fun scan(intent:Intent,n:Int) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                ),
                ("Kind.kt", "class Int\n"),
            ],
            True,
            "checked",
        ),
        (
            "cross-file-default-String",
            [
                (
                    "Caller.kt",
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent,n:String) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
                ("Kind.kt", "class String\n"),
            ],
            True,
            "checked",
        ),
        (
            "write-no-is-guard",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    " fun scan(intent:Intent,initial:Any) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  var holder:Any=initial; holder=Source()\n"
                    '  with(holder) { with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "callback-write-no-is-guard",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(args:Regex):String=captured\n"
                    " fun scan(intent:Intent,initial:Any,items:List<Array<String>>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  var client:Any=initial; client=helpers.Client()\n"
                    '  items.forEach { client.run { with("fixed") { db.execSQL(format(args=it)) } } }\n'
                    " }\n"
                    "}\n",
                ),
                (
                    "Client.kt",
                    'package helpers; class Client { fun run(block:(Regex)->Unit) { block(Regex("x")) } }',
                ),
            ],
            True,
            "callable argument type identity unresolved",
        ),
        (
            "escaped-String-alias",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "typealias `String`=helpers.Payload\n"
                    "open class Base { fun pick(v:kotlin.String):kotlin.String=v.toString() }\n"
                    "class Notes(private val db:SQLiteDatabase):Base() { private fun "
                    'pick(v:String):kotlin.String="fixed"; fun scan(intent:Intent) { '
                    'db.execSQL(pick(intent.getStringExtra("q")!!)) } }',
                ),
                ("Payload.kt", "package helpers; class Payload"),
            ],
            True,
            "budget",
        ),
        (
            "escaped-String-type-parameter",
            [
                (
                    "Main.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "open class Base { fun pick(v:kotlin.String):kotlin.String=v.toString() }\n"
                    "class Notes(private val db:SQLiteDatabase):Base() { private fun <`String`> "
                    'pick(v:String):kotlin.String="fixed"; fun scan(intent:Intent) { '
                    'db.execSQL(pick(intent.getStringExtra("q")!!)) } }',
                )
            ],
            True,
            "budget",
        ),
        (
            "final-String-write-keeps-standard-head",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun format(locale:Regex):String=captured\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; var holder="first"; '
                    'holder="fixed"; with(holder) { db.execSQL(format(locale=Locale.US)) } }\n'
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
    ],
)
def test_review26_nominal_and_nullable_boundaries(case, files, expected, mode):
    report = analyze_sources(files)
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), case
    hit = _hit(report, SQL)
    state = _state(report, SQL)
    if mode == "boundary":
        # These valid private-callback controls already conservatively report
        # input. If it remains, its actual precision gap must stay visible.
        if hit:
            assert state in {"limited", "partial"}, case
            assert "callable argument type identity unresolved" in _reasons(report), case
        return
    assert hit is expected, (case, _reasons(report))
    if mode == "checked":
        assert state == "checked" and not _reasons(report), case
    elif mode == "budget":
        assert state == "partial" and "source trace budget" in _budget(report), case
    else:
        assert state == "limited" and mode in _reasons(report), (case, _reasons(report))
        assert not _budget(report), case


@pytest.mark.parametrize(
    "case,files,expected,mode",
    [
        (
            "nullable-return-direct",
            [
                (
                    "fixtures/Case0.kt",
                    "package adversarial.c0\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private fun value():kotlin.String?="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-return-copy",
            [
                (
                    "fixtures/Case1.kt",
                    "package adversarial.c1\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private fun value():kotlin.String?="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  val holder=value(); holder.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nonnullable-return-direct-control",
            [
                (
                    "fixtures/Case2.kt",
                    "package adversarial.c2\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private fun value():kotlin.String="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "nullable-return-escaped-alias",
            [
                (
                    "fixtures/Case3.kt",
                    "package adversarial.c3\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "typealias `String`=kotlin.String?\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private fun value():String="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-source-return",
            [
                (
                    "fixtures/Case4.kt",
                    "package adversarial.c4\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class `String`\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value():String?=String()\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-field-qualified",
            [
                (
                    "fixtures/Case5.kt",
                    "package adversarial.c5\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private val value:kotlin.String?="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  this.value.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-field-unqualified-control",
            [
                (
                    "fixtures/Case6.kt",
                    "package adversarial.c6\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private val value:kotlin.String?="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-return-top-level",
            [
                (
                    "fixtures/Case7.kt",
                    "package adversarial.c7\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    'private fun value():kotlin.String?="fixed"\n'
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-safe-cast-copy-control",
            [
                (
                    "fixtures/Case8.kt",
                    "package adversarial.c8\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  val original=("fixed" as? kotlin.String); val holder=original; holder.run { '
                    "db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nonnullable-cast-copy-control",
            [
                (
                    "fixtures/Case9.kt",
                    "package adversarial.c9\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  val original=("fixed" as kotlin.String); val holder=original; holder.run { '
                    "db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "nullable-alias-cast-control",
            [
                (
                    "fixtures/Case10.kt",
                    "package adversarial.c10\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "typealias `String`=kotlin.String?\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  ("fixed" as String).run { db.execSQL(trim()) }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "escaped-source-constructor-copy-control",
            [
                (
                    "fixtures/Case11.kt",
                    "package adversarial.c11\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class `String`\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  val original=String(); val holder=original; holder.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "postwrite-standard-test-control",
            [
                (
                    "fixtures/Case12.kt",
                    "package adversarial.c12\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun format(locale:Regex):kotlin.String=captured\n"
                    " fun scan(intent:Intent,initial:Any) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  var holder:Any=initial; holder="fixed"; if(holder is kotlin.String) { with(holder) { '
                    "db.execSQL(format(locale=Locale.US)) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "boundary",
        ),
        (
            "write-after-standard-test",
            [
                (
                    "fixtures/Case13.kt",
                    "package adversarial.c13\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun format(locale:Regex):kotlin.String=captured\n"
                    " fun scan(intent:Intent,initial:Any) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  var holder:Any=initial; if(holder is kotlin.String) { holder=Source(); with(holder) { "
                    'with("fixed") { db.execSQL(format(locale=Locale.US)) } } }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "identity",
        ),
        (
            "write-copy-no-test-control",
            [
                (
                    "fixtures/Case14.kt",
                    "package adversarial.c14\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun format(locale:Regex):kotlin.String=captured\n"
                    " fun scan(intent:Intent,initial:Any) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  var holder:Any=initial; holder=Source(); val copy=holder; with(copy) { with("fixed") { '
                    "db.execSQL(format(locale=Locale.US)) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "identity",
        ),
        (
            "qualified-source-escaped-String-field",
            [
                (
                    "adjacent/Case0.kt",
                    "package adjacent.c0\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class `String`\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private val value:String=String()\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  this.value.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "qualified-nullable-numeric-field",
            [
                (
                    "adjacent/Case1.kt",
                    "package adjacent.c1\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private val value:kotlin.Int?=1\n"
                    " private fun minus(other:kotlin.Int):kotlin.String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  this.value.run { val text=minus(1); text.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "identity",
        ),
        (
            "qualified-source-String-copy",
            [
                (
                    "adjacent/Case2.kt",
                    "package adjacent.c2\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class String\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private val value:String=String()\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  val holder=this.value; holder.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "qualified-nullable-String-parameter-field",
            [
                (
                    "adjacent/Case3.kt",
                    "package adjacent.c3\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Holder(val value:kotlin.String?)\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent,holder:Holder) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  holder.value.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "qualified-nonnullable-String-parameter-control",
            [
                (
                    "adjacent/Case4.kt",
                    "package adjacent.c4\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Holder(val value:kotlin.String)\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent,holder:Holder) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  holder.value.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "escaped-source-field-unqualified-control",
            [
                (
                    "adjacent/Case5.kt",
                    "package adjacent.c5\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class `String`\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private val value:String=String()\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "cross-file-root-private-String",
            [
                (
                    "adjacent/Case6.kt",
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent,n:String) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
                ("adjacent/Case6Helper0.kt", "private class `String`\n"),
            ],
            False,
            "checked",
        ),
        (
            "implicit-String-callable-property",
            [
                (
                    "Factory.kt",
                    "package adversarial.factory\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Payload\n"
                    "class Factory(val String:()->Payload)\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent,factory:Factory) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  with(factory) { String().run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-safe-call",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent, n:kotlin.String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n?.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "nullable-force-assert",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent, n:kotlin.String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n!!.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "nullable-with-force-assert",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent, n:kotlin.String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  with(n!!) { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "safe-cast-safe-call",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent, n:Any) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  (n as? kotlin.String)?.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "nullable-member-force-assert",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Holder(val value:kotlin.String?)\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent, holder:Holder) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  holder.value!!.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "nullable-return-force-assert",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private fun value():kotlin.String?="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value()!!.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "cross-file-global-nullable",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  label.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
                ("Globals.kt", 'package synthetic\nvar label:kotlin.String?="fixed"\n'),
            ],
            True,
            "checked",
        ),
        (
            "companion-nullable",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Holder { companion object { var label:kotlin.String?="fixed" } }\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  Holder.label.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "cross-file-global-nonnull",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  label.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
                ("Globals.kt", 'package synthetic\nvar label:kotlin.String="fixed"\n'),
            ],
            False,
            "checked",
        ),
        (
            "companion-nonnull",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Holder { companion object { var label:kotlin.String="fixed" } }\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  Holder.label.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "escaped-supertype-extension",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'open class Parent { protected var captured=""; fun '
                    "kotlin.String.trim():kotlin.String=captured }\n"
                    "class Notes(private val db:SQLiteDatabase):`Parent`() {\n"
                    ' fun scan(intent:Intent) { captured=intent.getStringExtra("q") ?: ""; "fixed".run { '
                    "db.execSQL(trim()) } }\n"
                    "}\n",
                )
            ],
            True,
            "extension",
        ),
        (
            "copied-receiver-before-later-test",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "import java.util.Locale\n"
                    'class FakeLocale { val US:Regex=Regex("x") }\n'
                    "class Source { val Locale:FakeLocale=FakeLocale() }\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun format(locale:Regex):kotlin.String=captured\n"
                    " fun scan(intent:Intent, initial:Any) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  var h:Any=initial; h=Source(); val copy=h; h="fixed"; if(h is kotlin.String) with(copy) { '
                    'with("fixed") { db.execSQL(format(locale=Locale.US)) } }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "identity",
        ),
        (
            "constructor-with-default-copy",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class String(val raw:kotlin.String="")\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  val value=String(); value.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "constructor",
        ),
        (
            "constructor-with-default-direct",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class String(val raw:kotlin.String="")\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  String().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "constructor",
        ),
        (
            "inferred-source-constructor-return",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class String(val raw:kotlin.String="")\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value() = String()\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "constructor",
        ),
        (
            "nullable-conversion-plain-run",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun trim():kotlin.String="fixed"\n'
                    " private fun minus(other:kotlin.Int):kotlin.String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  "42".toIntOrNull().run { val s=minus(1); s.run { db.execSQL(trim()) } }\n'
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "identity",
        ),
        (
            "nullable-conversion-safe-call",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun trim():kotlin.String="fixed"\n'
                    " private fun minus(other:kotlin.Int):kotlin.String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  "42".toIntOrNull()?.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n'
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "same-file-private-source-constructor",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "private class String\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  String().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "inferred-captured-String-return",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun trim():kotlin.String="fixed"\n'
                    " private fun value()=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nullable-let",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent, n:kotlin.String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.let { it.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "nonnull-safe-let",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent, n:kotlin.String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n?.let { it.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
        (
            "nullable-list-element",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent, items:List<kotlin.String?>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  items.forEach { it.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "aggregate",
        ),
        (
            "nonnull-safe-element",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent, items:List<kotlin.String?>) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  items.forEach { it?.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "aggregate",
        ),
        (
            "nullable-alias-let",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "typealias String=kotlin.String?\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent, n:String) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n.let { it.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                )
            ],
            True,
            "checked",
        ),
        (
            "literal-element-with-nullable-alias",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "typealias String=kotlin.String?\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  listOf("fixed").forEach { it.run { db.execSQL(trim()) } }\n'
                    " }\n"
                    "}\n",
                )
            ],
            False,
            "checked",
        ),
    ],
)
def test_review27_receiver_type_origin_and_nonnull_policy(case, files, expected, mode):
    report = analyze_sources(files)
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), case
    hit = _hit(report, SQL)
    state = _state(report, SQL)
    reasons = _reasons(report)
    if mode == "boundary":
        if hit:
            assert state in {"limited", "partial"} and "object alias identity unavailable" in reasons
        return
    if mode == "extension":
        assert state in {"limited", "partial"}
        assert "Kotlin project extension receiver flow unavailable" in reasons
        return
    assert hit is expected, (case, reasons)
    if mode == "checked":
        assert state == "checked" and not reasons, (case, reasons)
    else:
        reason = {
            "identity": "callable argument type identity unresolved",
            "constructor": "constructor field mapping unavailable",
            "aggregate": "aggregate reference ownership unavailable",
        }[mode]
        assert state == "limited" and reason in reasons, (case, reasons)
        assert not _budget(report), case


@pytest.mark.parametrize(
    "case,files,expected,mode",
    [
        (
            "inferred-return-caller-parameter-collision",
            [
                (
                    "Probe0.kt",
                    "package proof.context0\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Other\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private val n:kotlin.String="fixed"\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value()=n\n"
                    " fun scan(intent:Intent,n:Other) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            False,
            "checked",
        ),
        (
            "inferred-return-renamed-caller-parameter",
            [
                (
                    "Probe1.kt",
                    "package proof.context1\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Other\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private val n:kotlin.String="fixed"\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value()=n\n"
                    " fun scan(intent:Intent,other:Other) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            False,
            "checked",
        ),
        (
            "inferred-return-explicit-type-control",
            [
                (
                    "Probe2.kt",
                    "package proof.context2\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Other\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private val n:kotlin.String="fixed"\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value():kotlin.String=n\n"
                    " fun scan(intent:Intent,n:Other) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            False,
            "checked",
        ),
        (
            "inferred-return-callee-owner-collision",
            [
                (
                    "Probe0.kt",
                    "package proof.callcontext0\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Other\n"
                    "private fun origin():Other=Other()\n"
                    "private fun value()=origin()\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private fun origin():kotlin.String="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "inferred-return-renamed-caller-method",
            [
                (
                    "Probe1.kt",
                    "package proof.callcontext1\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Other\n"
                    "private fun origin():Other=Other()\n"
                    "private fun value()=origin()\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private fun unrelated():kotlin.String="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "inferred-return-explicit-source-type",
            [
                (
                    "Probe2.kt",
                    "package proof.callcontext2\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Other\n"
                    "private fun origin():Other=Other()\n"
                    "private fun value():Other=origin()\n"
                    "class Probe(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    ' private fun origin():kotlin.String="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "direct-nullable-safe-result",
            [
                (
                    "Probe0.kt",
                    "package proof.safe0\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase,private val n:kotlin.String?) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n?.toString().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "inferred-nullable-safe-result",
            [
                (
                    "Probe1.kt",
                    "package proof.safe1\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase,private val n:kotlin.String?) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value()=n?.toString()\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "copied-nullable-safe-result",
            [
                (
                    "Probe2.kt",
                    "package proof.safe2\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase,private val n:kotlin.String?) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  val copy=n?.toString(); copy.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "direct-nullable-safe-entry-control",
            [
                (
                    "Probe3.kt",
                    "package proof.safe3\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase,private val n:kotlin.String?) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n?.toString()?.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            False,
            "checked",
        ),
        (
            "nonnull-unnecessary-safe-call-control",
            [
                (
                    "Probe4.kt",
                    "package proof.safe4\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase,private val n:kotlin.String) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " \n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n?.toString().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "inherited-nullable-return-caller-collision",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "open class Base { protected val n:kotlin.String? = null }\n"
                    "class Other\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase):Base() {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value()=n\n"
                    " fun scan(intent:Intent,n:kotlin.String) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "identity",
        ),
        (
            "inherited-nonnull-return-caller-collision",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'open class Base { protected val n:kotlin.String = "fixed" }\n'
                    "class Other\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase):Base() {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value()=n\n"
                    " fun scan(intent:Intent,n:Other) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            False,
            "identity-boundary",
        ),
        (
            "safe-length-plain",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun trim():kotlin.String="fixed"\n'
                    " private fun minus(other:kotlin.Int):kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent,n:kotlin.String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n?.length.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "identity",
        ),
        (
            "safe-length-safe-entry",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun trim():kotlin.String="fixed"\n'
                    " private fun minus(other:kotlin.Int):kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent,n:kotlin.String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n?.length?.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            False,
            "checked",
        ),
        (
            "safe-conversion-plain",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun trim():kotlin.String="fixed"\n'
                    " private fun minus(other:kotlin.Int):kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent,n:kotlin.String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n?.toInt().run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "identity",
        ),
        (
            "safe-conversion-safe-entry",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun trim():kotlin.String="fixed"\n'
                    " private fun minus(other:kotlin.Int):kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent,n:kotlin.String?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  n?.toInt()?.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            False,
            "checked",
        ),
        (
            "safe-project-return-plain",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Holder { fun label():kotlin.String="fixed" }\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent,holder:Holder?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  holder?.label().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "safe-project-return-asserted",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    'class Holder { fun label():kotlin.String="fixed" }\n'
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent,holder:Holder?) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  holder?.label()!!.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            False,
            "checked",
        ),
        (
            "nullable-fold-element-discarded-accumulator",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  listOf<kotlin.String?>(null).fold("fixed") { _, e -> e.run { db.execSQL(trim()) }; "fixed" }\n'
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "nullable-fold-element-named-accumulator",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  listOf<kotlin.String?>(null).fold("fixed") { acc, e -> e.run { db.execSQL(trim()) }; "fixed" }\n'
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "fold-indexed-element-discarded-slots",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun trim():kotlin.String="fixed"\n'
                    " private fun minus(other:kotlin.Int):kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  listOf("fixed").foldIndexed("fixed") { _, _, value -> value.run { val s=minus(1); s.run { db.execSQL(trim()) } }; "fixed" }\n'
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "fold-indexed-element-named-slots",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    ' private fun trim():kotlin.String="fixed"\n'
                    " private fun minus(other:kotlin.Int):kotlin.String=captured\n"
                    "\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  listOf("fixed").foldIndexed("fixed") { index, acc, value -> value.run { val s=minus(1); s.run { db.execSQL(trim()) } }; "fixed" }\n'
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "calibration-nullable-return",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase,private val n:kotlin.String?) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value():kotlin.String?=n?.toString()\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value().run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "calibration-nullable-return-safe-control",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase,private val n:kotlin.String?) {\n"
                    ' private var captured=""\n'
                    " private fun trim():kotlin.String=captured\n"
                    " private fun value():kotlin.String?=n?.toString()\n"
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    "  value()?.run { db.execSQL(trim()) }\n"
                    " }\n"
                    "}\n",
                ),
            ],
            False,
            "checked",
        ),
        (
            "calibration-indexed-discard",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):kotlin.String=captured\n"
                    ' private fun trim():kotlin.String="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  listOf("fixed").forEachIndexed { _, value -> value.run { val s=minus(1); s.run { db.execSQL(trim()) } } }\n'
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
        (
            "calibration-indexed-discard-named-control",
            [
                (
                    "Caller.kt",
                    "package synthetic\n"
                    "import android.content.Intent\n"
                    "import android.database.sqlite.SQLiteDatabase\n"
                    "class Notes(private val db:SQLiteDatabase) {\n"
                    ' private var captured=""\n'
                    " private fun minus(other:Int):kotlin.String=captured\n"
                    ' private fun trim():kotlin.String="fixed"\n'
                    " fun scan(intent:Intent) {\n"
                    '  captured=intent.getStringExtra("q") ?: ""\n'
                    '  listOf("fixed").forEachIndexed { index, value -> value.run { val s=minus(1); s.run { db.execSQL(trim()) } } }\n'
                    " }\n"
                    "}\n",
                ),
            ],
            True,
            "checked",
        ),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_review28_declaration_context_safe_results_and_callback_slots(case, files, expected, mode):
    report = analyze_sources(files)
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), case
    hit = _hit(report, SQL)
    state = _state(report, SQL)
    reasons = _reasons(report)
    if mode == "identity-boundary":
        if hit is not expected:
            assert state in {"limited", "partial"}
            assert "callable argument type identity unresolved" in reasons
        return
    assert hit is expected, (case, reasons)
    if mode == "identity":
        assert state in {"limited", "partial"}
        assert "callable argument type identity unresolved" in reasons
    else:
        assert state == "checked" and not reasons, (case, state, reasons)


@pytest.mark.parametrize("first", [False, True])
def test_review28_nullable_type_query_policies_are_isolated(monkeypatch, first):
    from mobile_audit.source_analysis import Analyzer

    original = Analyzer.known_value_type
    observed = False

    def query(self, node, frame, *args, **kwargs):
        nonlocal observed
        if not observed and self.text(node) == "n" and self.parameter_types.get("n") == "kotlin.String?":
            observed = True
            memo = {}
            for policy in [first, not first, first]:
                kind = original(self, node, frame, receiver_kinds=memo, allow_nullable=policy)
                assert kind == ("String" if policy else "")
        return original(self, node, frame, *args, **kwargs)

    monkeypatch.setattr(Analyzer, "known_value_type", query)
    source = """import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Notes(private val db:SQLiteDatabase) {
 private var captured=""
 private fun trim():kotlin.String=captured
 fun scan(intent:Intent,n:kotlin.String?) {
  captured=intent.getStringExtra("q") ?: ""
  n.run { db.execSQL(trim()) }
 }
}
"""
    assert _hit(analyze_sources([("Caller.kt", source)]), SQL)
    assert observed


def test_review28_inferred_query_restores_caller_after_failure(monkeypatch):
    from mobile_audit.source_analysis import Analyzer

    infer = Analyzer.inferred_function_kind
    known = Analyzer.known_value_type
    injected = False
    restored = False

    def fail_once(self, *args, **kwargs):
        nonlocal injected
        if self.type_query_active and not injected:
            injected = True
            raise RuntimeError("synthetic type query failure")
        return known(self, *args, **kwargs)

    def checked(self, *args, **kwargs):
        nonlocal restored
        if not restored:
            before = {
                name: getattr(self, name)
                for name in (
                    "function",
                    "function_source",
                    "scope",
                    "parameter_types",
                    "field_types",
                    "visited_values",
                    "type_query_active",
                )
            }
            with pytest.raises(RuntimeError, match="synthetic type query failure"):
                infer(self, *args, **kwargs)
            assert all(getattr(self, name) is value for name, value in before.items())
            restored = True
        return infer(self, *args, **kwargs)

    monkeypatch.setattr(Analyzer, "known_value_type", fail_once)
    monkeypatch.setattr(Analyzer, "inferred_function_kind", checked)
    source = """import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Other
class Notes(private val db:SQLiteDatabase) {
 private var captured=""
 private val n:kotlin.String="fixed"
 private fun trim():kotlin.String=captured
 private fun value()=n
 fun scan(intent:Intent,n:Other) {
  captured=intent.getStringExtra("q") ?: ""
  value().run { db.execSQL(trim()) }
 }
}
"""
    report = analyze_sources([("Caller.kt", source)])
    assert not _hit(report, SQL)
    assert _state(report, SQL) == "checked"
    assert injected and restored


def test_review28_foreign_initializer_receiver_query_has_no_function_context_crash():
    files = [
        (
            "Caller.kt",
            """package synthetic
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Notes(private val db:SQLiteDatabase) {
 fun scan(intent:Intent) {
  val q=intent.getStringExtra("q") ?: ""
  val sql=AppExecutors.io.submit<String> { "SELECT * FROM t WHERE x = $q" }.get()
  db.execSQL(sql)
 }
}
""",
        ),
        (
            "AppExecutors.kt",
            """package synthetic
import java.util.concurrent.Executors
object AppExecutors { val io=Executors.newSingleThreadExecutor() }
""",
        ),
    ]
    report = analyze_sources(files)
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"])
    assert _state(report, SQL) in {"limited", "partial"}
    assert "unresolved callable identity or argument signature" in _reasons(report)


_REVIEW29_CASES = [
    (
        "constructor-origin-qualified-owner-collision-nullable",
        [
            (
                "Caller.kt",
                'package adv.r28.c2\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Provider { private fun label():kotlin.String?="fixed"; fun value()=label() }\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val provider=Provider()\n private fun label():Other=Other()\n class Other\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  provider.value().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        True,
        "constructor-boundary",
    ),
    (
        "constructor-origin-qualified-owner-collision-nonnull",
        [
            (
                "Caller.kt",
                'package adv.r28.c5\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Provider { private fun label():kotlin.String="fixed"; fun value()=label() }\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val provider=Provider()\n private fun label():Other=Other()\n class Other\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  provider.value().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        False,
        "constructor-boundary",
    ),
    (
        "foreign-inferred-function-initializer-multiline",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  Values.value.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            (
                "Values.kt",
                "package synthetic\n"
                'private fun trim():kotlin.String="fixed"\n'
                "object Values {\n"
                " val value=trim()\n"
                "}\n",
            ),
        ],
        False,
        "initializer-boundary",
    ),
    (
        "foreign-declared-function-initializer-multiline",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  Values.value.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            (
                "Values.kt",
                "package synthetic\n"
                'private fun trim():kotlin.String="fixed"\n'
                "object Values { val value:kotlin.String=trim()\n"
                "}\n",
            ),
        ],
        False,
        "checked",
    ),
    (
        "foreign-literal-initializer-control-multiline",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  Values.value.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            (
                "Values.kt",
                "package synthetic\n"
                'private fun trim():kotlin.String="fixed"\n'
                "object Values {\n"
                ' val value="fixed"\n'
                "}\n",
            ),
        ],
        False,
        "checked",
    ),
    (
        "declaring-return-owner-simple-name",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "import external.factory\n"
                "class Holder { fun label():kotlin.Int=0 }\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun minus(other:Int):kotlin.String=captured\n"
                ' private fun trim():kotlin.String="fixed"\n'
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  factory().label().run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                " }\n"
                "}\n",
            ),
            (
                "Library.kt",
                "package external\n"
                'class Holder { fun label():kotlin.String="fixed" }\n'
                "fun factory():Holder=Holder()\n",
            ),
        ],
        True,
        "checked",
    ),
    (
        "declaring-return-owner-qualified-control",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "import external.factory\n"
                "class Holder { fun label():kotlin.Int=0 }\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun minus(other:Int):kotlin.String=captured\n"
                ' private fun trim():kotlin.String="fixed"\n'
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  factory().label().run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                " }\n"
                "}\n",
            ),
            (
                "Library.kt",
                "package external\n"
                'class Holder { fun label():kotlin.String="fixed" }\n'
                "fun factory():external.Holder=Holder()\n",
            ),
        ],
        True,
        "checked",
    ),
    (
        "foreign-source-conversion-untyped",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun minus(other:Int):kotlin.String=captured\n"
                ' private fun trim():kotlin.String="fixed"\n'
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  Globals.label.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                " }\n"
                "}\n",
            ),
            ("Globals.kt", "package synthetic\nobject Globals { val label=Helper().toInt() }\n"),
            ("Helper.kt", 'package synthetic\nclass Helper { fun toInt():kotlin.String="fixed" }\n'),
        ],
        True,
        "identity",
    ),
    (
        "foreign-source-conversion-typed",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun minus(other:Int):kotlin.String=captured\n"
                ' private fun trim():kotlin.String="fixed"\n'
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  Globals.label.run { val s=minus(1); s.run { db.execSQL(trim()) } }\n"
                " }\n"
                "}\n",
            ),
            (
                "Globals.kt",
                "package synthetic\nobject Globals { val label:kotlin.String=Helper().toInt() }\n",
            ),
            ("Helper.kt", 'package synthetic\nclass Helper { fun toInt():kotlin.String="fixed" }\n'),
        ],
        True,
        "checked",
    ),
    (
        "readonly-receiver-proof-inferred",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private fun reset():kotlin.String? { captured="fixed"; return null }\n'
                " private val t=reset()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  t.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "execution-boundary",
    ),
    (
        "readonly-receiver-proof-declared",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private fun reset():kotlin.String? { captured="fixed"; return null }\n'
                " private val t:kotlin.String?=reset()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  t.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
    ),
    (
        "readonly-receiver-proof-literal",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private fun reset():kotlin.String? { captured="fixed"; return null }\n'
                " private val t:kotlin.String?=null\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  t.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
    ),
    (
        "represented-module-inferred-return-nullable",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private fun value()=label\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            ("Globals.kt", 'package synthetic\nvar label:kotlin.String?="fixed"\n'),
        ],
        True,
        "module-value",
    ),
    (
        "represented-module-inferred-return-nonnull",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private fun value()=label\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            ("Globals.kt", 'package synthetic\nvar label:kotlin.String="fixed"\n'),
        ],
        False,
        "module-value",
    ),
    (
        "represented-module-nullable-direct",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                "\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  label.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            ("Globals.kt", 'package synthetic\nvar label:kotlin.String?="fixed"\n'),
        ],
        True,
        "checked",
    ),
    (
        "member-declaration-owner-simple",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                'class Item { fun label():kotlin.String="fixed" }\n'
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                "\n"
                " fun scan(intent:Intent,holder:support.Holder) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  holder.box.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            (
                "Library.kt",
                "package support\n"
                "class Other\n"
                "class Item { fun label():Other=Other() }\n"
                "class Holder(val box:Item)\n",
            ),
        ],
        True,
        "checked",
    ),
    (
        "member-declaration-owner-qualified",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                'class Item { fun label():kotlin.String="fixed" }\n'
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                "\n"
                " fun scan(intent:Intent,holder:support.Holder) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  holder.box.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            (
                "Library.kt",
                "package support\n"
                "class Other\n"
                "class Item { fun label():Other=Other() }\n"
                "class Holder(val box:support.Item)\n",
            ),
        ],
        True,
        "checked",
    ),
    (
        "initializer-copy-caller-parameter-n",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private val n:kotlin.String="fixed"\n'
                " private val m=n\n"
                " fun scan(intent:Intent,n:Other) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  m.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        False,
        "checked",
    ),
    (
        "initializer-copy-caller-parameter-other",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private val n:kotlin.String="fixed"\n'
                " private val m=n\n"
                " fun scan(intent:Intent,other:Other) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  m.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        False,
        "checked",
    ),
    (
        "initializer-caller-method-inferred",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other\n"
                "private fun origin():Other=Other()\n"
                "private val value=origin()\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private fun origin():kotlin.String="fixed"\n'
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "identity",
    ),
    (
        "initializer-caller-method-typed",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other\n"
                "private fun origin():Other=Other()\n"
                "private val value:Other=origin()\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private fun origin():kotlin.String="fixed"\n'
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
    ),
    (
        "qualified-return-import-alias-nullable",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "import helpers.value\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            ("Values.kt", 'package helpers\nimport kotlin.String as Text\nfun value():Text?="fixed"\n'),
        ],
        True,
        "checked",
    ),
    (
        "qualified-return-import-alias-nonnull",
        [
            (
                "Caller.kt",
                "package synthetic\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "import helpers.value\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            ("Values.kt", 'package helpers\nimport kotlin.String as Text\nfun value():Text="fixed"\n'),
        ],
        False,
        "checked",
    ),
    (
        "callback-slots-runningFoldIndexed",
        [
            (
                "Caller.kt",
                "package adv.r28.c19\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " \n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                '  listOf("fixed").runningFoldIndexed("fixed") { _, _, value -> value.run { db.execSQL(trim()) }; "fixed" }\n'
                " }\n"
                "}\n",
            ),
        ],
        False,
        "callback-boundary",
    ),
    (
        "callback-slots-scanIndexed",
        [
            (
                "Caller.kt",
                "package adv.r28.c20\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " \n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                '  listOf("fixed").scanIndexed("fixed") { _, _, value -> value.run { db.execSQL(trim()) }; "fixed" }\n'
                " }\n"
                "}\n",
            ),
        ],
        False,
        "callback-boundary",
    ),
]


@pytest.mark.parametrize("case,files,expected,mode", _REVIEW29_CASES, ids=[row[0] for row in _REVIEW29_CASES])
def test_review29_receiver_fact_origin_and_readonly_proofs(case, files, expected, mode):
    report = analyze_sources(files)
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), case
    hit, state, reasons = _hit(report, SQL), _state(report, SQL), _reasons(report)
    if mode in {"initializer-boundary", "callback-boundary"}:
        if hit is not expected:
            assert state in {"limited", "partial"}
            assert "callable argument type identity unresolved" in reasons
        return
    if mode == "module-value":
        assert "callable argument type identity unresolved" not in reasons
        if hit is not expected or state != "checked":
            assert state in {"limited", "partial"}
            assert "receiver field inventory unavailable" in reasons
        return
    assert hit is expected, (case, state, reasons)
    if mode == "identity":
        assert state in {"limited", "partial"}
        assert "callable argument type identity unresolved" in reasons
    elif mode == "constructor-boundary":
        assert "callable argument type identity unresolved" not in reasons
        if state != "checked":
            assert state == "limited" and reasons == ["constructor field mapping unavailable"]
    elif mode == "execution-boundary":
        budget = report["metadata"]["native_flow"].get("budget_reasons", [])
        if budget:
            assert state == "partial"
        elif state != "checked":
            assert reasons
    else:
        assert state == "checked" and not reasons, (case, state, reasons)


def test_review29_receiver_proof_does_not_execute_unvisited_initializers(monkeypatch):
    from mobile_audit.native_flow import NativeFlow
    from mobile_audit.source_analysis import Analyzer

    original_root, original_call = Analyzer.string_template_root, NativeFlow.call
    active = 0
    seen = False

    def root(self, *args, **kwargs):
        nonlocal active, seen
        proof = kwargs.get("receiver_proof", False)
        seen = seen or proof
        active += int(proof)
        before = self.native_flow.evaluations if self.native_flow is not None else 0
        try:
            result = original_root(self, *args, **kwargs)
            if proof and self.native_flow is not None:
                assert self.native_flow.evaluations == before
            return result
        finally:
            active -= int(proof)

    def call(self, *args, **kwargs):
        assert not active, "receiver proof entered project execution"
        return original_call(self, *args, **kwargs)

    monkeypatch.setattr(Analyzer, "string_template_root", root)
    monkeypatch.setattr(NativeFlow, "call", call)
    files = next(row[1] for row in _REVIEW29_CASES if row[0] == "readonly-receiver-proof-inferred")
    report = analyze_sources(files)
    assert _hit(report, SQL)
    assert seen and active == 0


def test_review29_represented_module_type_proof_adds_no_identity_gap(monkeypatch):
    from mobile_audit.source_analysis import Analyzer

    original = Analyzer.known_value_type
    checked = False

    def query(self, node, frame, *args, **kwargs):
        nonlocal checked
        result = original(self, node, frame, *args, **kwargs)
        if not checked and self.text(node) == "value()" and not self.type_query_active:
            checked = True
            before = self.native_flow.partial_events
            assert not self.string_template_root(node, frame, receiver_proof=True)
            assert self.native_flow.partial_events == before
        return result

    monkeypatch.setattr(Analyzer, "known_value_type", query)
    files = next(row[1] for row in _REVIEW29_CASES if row[0] == "represented-module-inferred-return-nullable")
    report = analyze_sources(files)
    assert _hit(report, SQL)
    assert checked


_REVIEW30_CASES = [
    (
        "01-detached-alias-caller-nullable",
        [
            (
                "Caller.kt",
                "package adv.r29.p01\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private val origin:kotlin.String?="fixed"\n'
                " private val receiver=origin\n"
                " fun scan(intent:Intent, origin:kotlin.String) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  receiver.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "02-detached-alias-caller-nonnull",
        [
            (
                "Caller.kt",
                "package adv.r29.p02\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private val origin:kotlin.String="fixed"\n'
                " private val receiver=origin\n"
                " fun scan(intent:Intent, origin:kotlin.String) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  receiver.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        False,
        "checked",
        [],
    ),
    (
        "03-inherited-callable-property",
        [
            (
                "Caller.kt",
                "package adv.r29.p03\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other { fun label():Other=Other() }\n"
                'class Thing { fun label():kotlin.String="fixed" }\n'
                "open class Base { val Thing: ()->Other = {Other()} }\n"
                "class Notes(private val db:SQLiteDatabase):Base() {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val value=Thing()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "04-companion-callable-property",
        [
            (
                "Caller.kt",
                "package adv.r29.p04\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other { fun label():Other=Other() }\n"
                'class Thing { fun label():kotlin.String="fixed" }\n'
                "class Notes(private val db:SQLiteDatabase) {\n"
                " companion object { val Thing: ()->Other = {Other()} }\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val value=Thing()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "05-uncompeted-source-constructor",
        [
            (
                "Caller.kt",
                "package adv.r29.p05\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other { fun label():Other=Other() }\n"
                'class Thing { fun label():kotlin.String="fixed" }\n'
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val value=Thing()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        False,
        "checked",
        [],
    ),
    (
        "06-imported-factory-alias",
        [
            (
                "Caller.kt",
                "package adv.r29.p06\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "import adv.r29.external6.make as Thing\n"
                'class Thing(val unused:Int) { fun label():kotlin.String="fixed" }\n'
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val value=Thing()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            (
                "Library.kt",
                "package adv.r29.external6\n"
                "class Other { fun label():Other=Other() }\n"
                "fun make():Other=Other()\n",
            ),
        ],
        True,
        "limit-control",
        ["constructor field mapping unavailable", "unresolved callable identity or argument signature"],
    ),
    (
        "07-member-copy-origin-nullable",
        [
            (
                "Caller.kt",
                "package adv.r29.p07\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "import adv.r29.external7.Carrier\n"
                'class Holder { fun label():kotlin.String="fixed" }\n'
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  val carrier:Carrier=Carrier()\n"
                "  val copy=carrier.item\n"
                "  copy.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            (
                "Library.kt",
                "package adv.r29.external7\n"
                'class Holder { fun label():kotlin.String?="fixed" }\n'
                "class Carrier { val item:Holder=Holder() }\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "08-factory-element-alias-nullable",
        [
            (
                "Caller.kt",
                "package adv.r29.p08\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "import kotlin.String as Text\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                '  listOf<Text?>("fixed").forEach { item ->\n'
                '   class Text { fun trim():kotlin.String="shadow" }\n'
                "   item.run { db.execSQL(trim()) }\n"
                "  }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "09-factory-element-alias-nonnull",
        [
            (
                "Caller.kt",
                "package adv.r29.p09\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "import kotlin.String as Text\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                '  listOf<Text>("fixed").forEach { item ->\n'
                '   class Text { fun trim():kotlin.String="shadow" }\n'
                "   item.run { db.execSQL(trim()) }\n"
                "  }\n"
                " }\n"
                "}\n",
            ),
        ],
        False,
        "checked",
        [],
    ),
    (
        "10-readonly-initializer-copy",
        [
            (
                "Caller.kt",
                "package adv.r29.p10\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                ' private fun reset():kotlin.String? { captured="fixed"; return null }\n'
                " private val original=(reset())\n"
                " private val receiver=original\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  receiver.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "execution-boundary",
        [],
    ),
    (
        "11-local-class-captured-callable",
        [
            (
                "Caller.kt",
                "package adv.r29.p11\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other { fun label():Other=Other() }\n"
                'class Thing { fun label():kotlin.String="fixed" }\n'
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  val Thing: ()->Other = {Other()}\n"
                "  class Local {\n"
                "   private val value=Thing()\n"
                "   fun get()=value\n"
                "  }\n"
                "  Local().get().label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "limit-control",
        [
            "callable value binding unresolved",
            "constructor field mapping unavailable",
            "object alias identity unavailable",
            "unresolved callable identity or argument signature",
            "callable argument type identity unresolved",
        ],
    ),
    (
        "12-root-source-string-alias",
        [
            (
                "Caller.kt",
                "package adv.r29.p12\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "import String as Text\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  val t:Text=Text()\n"
                "  t.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
            ("Root.kt", "class String\n"),
        ],
        True,
        "limit-control",
        ["constructor field mapping unavailable"],
    ),
    (
        "root-source-alias-parameter",
        [
            ("Root.kt", "class String\n"),
            (
                "Alias.kt",
                "package adv.r29.followup\n"
                "import String as Text\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class AliasNotes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent,t:Text) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  t.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "root-source-inferred-member",
        [
            ("Root.kt", "class String\n"),
            (
                "Member.kt",
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class MemberNotes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val n=String()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  n.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "root-source-explicit-member-control",
        [
            ("Root.kt", "class String\n"),
            (
                "Member.kt",
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class MemberNotes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val n:String=String()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  n.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "root-source-direct-import-control",
        [
            ("Root.kt", "class String\n"),
            (
                "Alias.kt",
                "package adv.r29.followup\n"
                "import String\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class AliasNotes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent,t:String) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  t.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "claude-01-any-tostring-input-candidate",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p01\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                ' private fun trim():kotlin.String="fixed"\n'
                " fun scan(intent:Intent) {\n"
                "  \n"
                '  val label:Any=intent.getStringExtra("q") ?: ""\n'
                "  label.toString().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "claude-02-any-tostring-reverse-control",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p02\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                '  val label:Any="fixed"\n'
                "  label.toString().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        False,
        "limit-control",
        ["object alias identity unavailable"],
    ),
    (
        "claude-03-stringbuilder-tostring-input-candidate",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p03\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                ' private fun trim():kotlin.String="fixed"\n'
                " fun scan(intent:Intent) {\n"
                "  \n"
                '  val label:StringBuilder=StringBuilder(intent.getStringExtra("q") ?: "")\n'
                "  label.toString().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "limit-control",
        ["object alias identity unavailable"],
    ),
    (
        "claude-04-stringbuilder-tostring-reverse-control",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p04\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                '  val label:StringBuilder=StringBuilder("fixed")\n'
                "  label.toString().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        False,
        "limit-control",
        ["object alias identity unavailable"],
    ),
    (
        "claude-05-detached-arithmetic-caller-name-candidate",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p05\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val n=2+3\n"
                " private val m=n\n"
                " fun scan(intent:Intent,n:kotlin.String) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  m.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "identity-control",
        ["callable argument type identity unresolved"],
    ),
    (
        "claude-06-detached-arithmetic-renamed-control",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p06\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val n=2+3\n"
                " private val m=n\n"
                " fun scan(intent:Intent,other:kotlin.String) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  m.run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "identity-control",
        ["callable argument type identity unresolved"],
    ),
    (
        "claude-07-builder-regex-inferred-candidate",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p07\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private val sep=Regex("a")\n'
                " fun scan(intent:Intent) {\n"
                '  val q=intent.getStringExtra("q") ?: ""\n'
                '  with("safe") {\n'
                "   buildString {\n"
                "    append(q)\n"
                '    db.execSQL(replace(sep,"b"))\n'
                "   }\n"
                "  }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "factory-boundary",
        [],
    ),
    (
        "claude-08-builder-regex-declared-control",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p08\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private val sep:kotlin.text.Regex=Regex("a")\n'
                " fun scan(intent:Intent) {\n"
                '  val q=intent.getStringExtra("q") ?: ""\n'
                '  with("safe") {\n'
                "   buildString {\n"
                "    append(q)\n"
                '    db.execSQL(replace(sep,"b"))\n'
                "   }\n"
                "  }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "limit-control",
        ["unresolved callable identity"],
    ),
    (
        "builder-regex-factory-identity-boundary",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p07\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private fun makeRegex():kotlin.text.Regex=Regex("a")\n'
                " private val sep=makeRegex()\n"
                " fun scan(intent:Intent) {\n"
                '  val q=intent.getStringExtra("q") ?: ""\n'
                '  with("safe") {\n'
                "   buildString {\n"
                "    append(q)\n"
                '    db.execSQL(replace(sep,"b"))\n'
                "   }\n"
                "  }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "factory-boundary",
        [],
    ),
    (
        "unanchored-standard-receiver-identity-boundary",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p01\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                ' private fun trim():kotlin.String="fixed"\n'
                " fun scan(intent:Intent) {\n"
                "  \n"
                '  val label:Thread=Thread(intent.getStringExtra("q") ?: "")\n'
                "  label.toString().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "receiver-boundary",
        [],
    ),
    (
        "nullable-any-project-tostring-control",
        [
            (
                "Caller.kt",
                "package adv.r29.claude.p01\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private fun Any?.toString():Other=Other()\n"
                " fun scan(intent:Intent) {\n"
                "  \n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  val label:Any?=null\n"
                "  label.toString().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "identity-control",
        ["callable argument type identity unresolved"],
    ),
    (
        "constructor-A-private-constructor-companion-invoke",
        [
            (
                "Caller.kt",
                "package adv.r30.constructor.p1\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other { fun label():Other=Other() }\n"
                "class Thing private constructor() {\n"
                ' fun label():kotlin.String="fixed"\n'
                " companion object { operator fun invoke():Other=Other() }\n"
                "}\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val value=Thing()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "limit-control",
        ["nominal callable scope unavailable"],
    ),
    (
        "constructor-B-object-invoke",
        [
            (
                "Caller.kt",
                "package adv.r30.constructor.p2\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other { fun label():Other=Other() }\n"
                "object Thing {\n"
                " operator fun invoke():Other=Other()\n"
                ' fun label():kotlin.String="fixed"\n'
                "}\n"
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val value=Thing()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        True,
        "checked",
        [],
    ),
    (
        "constructor-C-public-constructor-control",
        [
            (
                "Caller.kt",
                "package adv.r30.constructor.p3\n"
                "import android.content.Intent\n"
                "import android.database.sqlite.SQLiteDatabase\n"
                "class Other { fun label():Other=Other() }\n"
                'class Thing { fun label():kotlin.String="fixed" }\n'
                "class Notes(private val db:SQLiteDatabase) {\n"
                ' private var captured=""\n'
                " private fun trim():kotlin.String=captured\n"
                " private val value=Thing()\n"
                " fun scan(intent:Intent) {\n"
                '  captured=intent.getStringExtra("q") ?: ""\n'
                "  value.label().run { db.execSQL(trim()) }\n"
                " }\n"
                "}\n",
            ),
        ],
        False,
        "checked",
        [],
    ),
]


@pytest.mark.parametrize(
    "case,files,expected,mode,allowed", _REVIEW30_CASES, ids=[row[0] for row in _REVIEW30_CASES]
)
def test_review30_source_nominal_identity_and_constructor_competition(case, files, expected, mode, allowed):
    report = analyze_sources(files)
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), case
    hit, state, reasons = _hit(report, SQL), _state(report, SQL), _reasons(report)
    details = report["metadata"]["native_flow"].get("partial_details", [])
    if mode in {"factory-boundary", "receiver-boundary"}:
        if state == "partial":
            assert report["metadata"]["native_flow"].get("budget_reasons")
        elif state == "limited":
            assert reasons
        else:
            assert state == "checked" and not reasons
        if hit is not expected:
            assert state in {"limited", "partial"}
            consumer = "replace" if mode == "factory-boundary" else "toString"
            assert any(
                row.get("reason") == "callable argument type identity unresolved"
                and row.get("call") == consumer
                for row in details
            ), (case, reasons, details)
        if state == "partial":
            assert report["metadata"]["native_flow"].get("budget_reasons")
        return
    assert hit is expected, (case, state, reasons)
    if mode == "execution-boundary":
        budgets = report["metadata"]["native_flow"].get("budget_reasons", [])
        if budgets:
            assert state == "partial"
        elif state != "checked":
            assert state == "limited" and reasons
    elif mode in {"limit-control", "identity-control"}:
        if state != "checked":
            assert state == "limited" and reasons
            assert set(reasons) <= set(allowed), (case, reasons)
    else:
        assert state == "checked" and not reasons, (case, state, reasons)


_REVIEW31_CASES = [
    (
        "01-protected-primary",
        [
            (
                "Caller.kt",
                'package fresh.r30.protected_primary\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Thing protected constructor() {\n fun label():kotlin.String="fixed"\n companion object { operator fun invoke():Other=Other() }\n}\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Thing()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  value.label().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        True,
        "limited",
        ["nominal callable scope unavailable"],
    ),
    (
        "02-required-arity",
        [
            (
                "Caller.kt",
                'package fresh.r30.required_arity\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Thing(val required:Int) {\n fun label():kotlin.String="fixed"\n companion object { operator fun invoke():Other=Other() }\n}\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Thing()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  value.label().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        True,
        "limited",
        ["nominal callable scope unavailable", "constructor field mapping unavailable"],
    ),
    (
        "03-public-primary-control",
        [
            (
                "Caller.kt",
                'package fresh.r30.public_primary_control\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Thing public constructor() {\n fun label():kotlin.String="fixed"\n companion object { operator fun invoke():Other=Other() }\n}\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Thing()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  value.label().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        False,
        "limited",
        ["nominal callable scope unavailable"],
    ),
    (
        "04-root-alias-member-origin",
        [
            (
                "Caller.kt",
                'package fresh.r30.root_consumer\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport fresh.r30.root_model.Origin\nclass StringBuilder { fun label():kotlin.String="fixed" }\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val origin=Origin()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  origin.payload.label().run { db.execSQL(trim()) }\n }\n}\n',
            ),
            (
                "Origin.kt",
                "package fresh.r30.root_model\nimport StringBuilder as RootPayload\nclass Origin { val payload=RootPayload() }\n",
            ),
            ("Root.kt", "class StringBuilder { fun label():StringBuilder=StringBuilder() }\n"),
        ],
        True,
        "limited",
        [
            "object alias identity unavailable",
            "reachable field ownership unavailable",
            "unresolved callable identity or argument signature",
        ],
    ),
    (
        "05-standard-alias-nonnull-control",
        [
            (
                "Caller.kt",
                'package fresh.r30.standard_alias_nonnull_control\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport fresh.r30.standard_alias_nonnull_control.kinds.OriginAny as Display\nclass Other\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Display?.toString():Other=Other()\n private val label:Display="fixed"\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) }\n }\n}\n',
            ),
            (
                "Kinds.kt",
                "package fresh.r30.standard_alias_nonnull_control.kinds\ntypealias OriginAny = kotlin.Any\n",
            ),
        ],
        False,
        "limited",
        ["unresolved callable identity or argument signature"],
    ),
    (
        "06-standard-alias-nullable",
        [
            (
                "Caller.kt",
                'package fresh.r30.standard_alias_nullable\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport fresh.r30.standard_alias_nullable.kinds.OriginAny as Display\nclass Other\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Display?.toString():Other=Other()\n private val label:Display?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) }\n }\n}\n',
            ),
            (
                "Kinds.kt",
                "package fresh.r30.standard_alias_nullable.kinds\ntypealias OriginAny = kotlin.Any\n",
            ),
        ],
        True,
        "identity",
        ["unresolved callable identity or argument signature", "callable argument type identity unresolved"],
    ),
    (
        "07-unanchored-thread-consumer",
        [
            (
                "Caller.kt",
                'package fresh.r30.thread_consumer\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Notes(private val db:SQLiteDatabase) {\n private fun trim():kotlin.String="fixed"\n fun scan(intent:Intent) {\n  val q=intent.getStringExtra("q") ?: ""\n  val label:java.lang.Thread=java.lang.Thread("review-"+q)\n  label.toString().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        True,
        "toString-boundary",
        [],
    ),
    (
        "08-copied-regex-consumer",
        [
            (
                "Caller.kt",
                'package fresh.r30.pattern_consumer\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Notes(private val db:SQLiteDatabase) {\n private val origin="never".toRegex()\n private val mask=origin\n fun scan(intent:Intent) {\n  val q=intent.getStringExtra("q") ?: ""\n  with("fixed") {\n   buildString {\n    append(q)\n    db.execSQL(replace(mask,"unchanged"))\n   }\n  }\n }\n}\n',
            )
        ],
        True,
        "replace-boundary",
        [],
    ),
    (
        "09-readonly-initializer-copy",
        [
            (
                "Caller.kt",
                'package fresh.r30.readonly_copy\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\n\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun clearBeforeScan():kotlin.String? { captured="CLEAR"; return null }\n private val origin=clearBeforeScan()\n private val mirror=origin\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  mirror.run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        True,
        "execution-boundary",
        [],
    ),
    (
        "10-framework-io-control",
        [
            (
                "Caller.kt",
                'package fresh.r30.normal_io_control\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport java.io.File\nclass Notes(private val db:SQLiteDatabase) {\n fun scan(intent:Intent) {\n  val q=intent.getStringExtra("q") ?: ""\n  val file=File("fresh-synthetic.txt")\n  db.execSQL("SELECT "+file.path.length)\n  db.execSQL(q.trim())\n }\n}\n',
            )
        ],
        True,
        "framework-control",
        [],
    ),
    (
        "claude30-01-interface-invoke",
        [
            (
                "Caller.kt",
                'package fresh.claude30.interface_case\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\ninterface Thing {\n fun label():kotlin.String="fixed"\n companion object { operator fun invoke():Other=Other() }\n}\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Thing()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  value.label().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        True,
        "limited",
        ["nominal callable scope unavailable", "receiver runtime dispatch unresolved"],
    ),
    (
        "claude30-02-inner-outer-inherited-value",
        [
            (
                "Caller.kt",
                'package fresh.claude30.outer_inherited\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Thing { fun label():kotlin.String="fixed" }\nopen class Base { val Thing:()->Other={Other()} }\nclass Outer:Base() {\n inner class Notes(private val db:SQLiteDatabase) {\n  private var captured=""\n  private fun trim():kotlin.String=captured\n  private val value=Thing()\n  fun scan(intent:Intent) {\n   captured=intent.getStringExtra("q") ?: ""\n   value.label().run { db.execSQL(trim()) }\n  }\n }\n}\n',
            )
        ],
        True,
        "checked",
        [],
    ),
    (
        "claude30-03-nested-outer-companion-value",
        [
            (
                "Caller.kt",
                'package fresh.claude30.nested_companion\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Thing { fun label():kotlin.String="fixed" }\nclass Outer {\n companion object { val Thing:()->Other={Other()} }\n class Notes(private val db:SQLiteDatabase) {\n  private var captured=""\n  private fun trim():kotlin.String=captured\n  private val value=Thing()\n  fun scan(intent:Intent) {\n   captured=intent.getStringExtra("q") ?: ""\n   value.label().run { db.execSQL(trim()) }\n  }\n }\n}\n',
            )
        ],
        True,
        "checked",
        [],
    ),
    (
        "claude30-04-nullable-string-project-tostring",
        [
            (
                "Caller.kt",
                'package fresh.claude30.nullable_string_project_tostring\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:kotlin.String?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        True,
        "identity",
        ["callable argument type identity unresolved"],
    ),
    (
        "claude30-05-nullable-string-standard-control",
        [
            (
                "Caller.kt",
                'package fresh.claude30.nullable_string_standard_control\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val label:kotlin.String?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        False,
        "checked",
        [],
    ),
    (
        "claude30-06-nullable-int-project-tostring",
        [
            (
                "Caller.kt",
                'package fresh.claude30.nullable_int_project_tostring\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:kotlin.Int?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        True,
        "identity",
        ["callable argument type identity unresolved"],
    ),
    (
        "claude30-07-unused-char-throwable-list-tostring",
        [
            (
                "Caller.kt",
                'package fresh.claude30.unused_tostring\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Notes(private val db:SQLiteDatabase) {\n fun scan(intent:Intent) {\n  val letter:Char=\'x\'\n  val error:Throwable=IllegalStateException("fixed")\n  val entries:List<String> = listOf("fixed")\n  val a=letter.toString()\n  val b=error.toString()\n  val c=entries.toString()\n  db.execSQL("SELECT 1")\n }\n}\n',
            )
        ],
        False,
        "unused-hint",
        [
            "aggregate reference ownership unavailable",
            "object alias identity unavailable",
            "unresolved reference argument effects",
        ],
    ),
    (
        "claude30-08-default-root-holder-copy-control",
        [
            (
                "Caller.kt",
                'import android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Holder(\n val label:String="fixed"\n) {\n}\nclass Carrier(\n val item:Holder=Holder()\n) {\n}\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():String=captured\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  val carrier=Carrier()\n  val copy=carrier.item\n  copy.label.run { db.execSQL(trim()) }\n }\n}\n',
            )
        ],
        False,
        "limited",
        ["constructor field mapping unavailable"],
    ),
    (
        "inner-no-head-control",
        [
            (
                "Caller.kt",
                'package fresh.claude30.outer_inherited.parentcontrol\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Thing { fun label():kotlin.String="fixed" }\nopen class Base { }\nclass Outer:Base() {\n inner class Notes(private val db:SQLiteDatabase) {\n  private var captured=""\n  private fun trim():kotlin.String=captured\n  private val value=Thing()\n  fun scan(intent:Intent) {\n   captured=intent.getStringExtra("q") ?: ""\n   value.label().run { db.execSQL(trim()) }\n  }\n }\n}\n',
            )
        ],
        False,
        "checked",
        [],
    ),
    (
        "nested-outer-instance-control",
        [
            (
                "Caller.kt",
                'package fresh.claude30.nested_companion.parentcontrol\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Thing { fun label():kotlin.String="fixed" }\nclass Outer {\n val Thing:()->Other={Other()}\n class Notes(private val db:SQLiteDatabase) {\n  private var captured=""\n  private fun trim():kotlin.String=captured\n  private val value=Thing()\n  fun scan(intent:Intent) {\n   captured=intent.getStringExtra("q") ?: ""\n   value.label().run { db.execSQL(trim()) }\n  }\n }\n}\n',
            )
        ],
        False,
        "checked",
        [],
    ),
]


@pytest.mark.parametrize(
    "case,files,expected,mode,allowed", _REVIEW31_CASES, ids=[r[0] for r in _REVIEW31_CASES]
)
def test_review31_constructor_applicability_nullable_alias_and_consumed_proof(
    case, files, expected, mode, allowed
):
    report = analyze_sources(files)
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), case
    hit, state, reasons = _hit(report, SQL), _state(report, SQL), _reasons(report)
    flow = report["metadata"]["native_flow"]
    details = flow.get("partial_details", [])
    if state == "partial":
        assert flow.get("budget_reasons"), (case, state, reasons)
    elif state == "limited":
        assert reasons and not flow.get("budget_reasons"), (case, state, reasons)
    else:
        assert state == "checked" and not reasons, (case, state, reasons)
    if mode in {"toString-boundary", "replace-boundary"}:
        if hit is not expected:
            consumer = mode.removesuffix("-boundary")
            assert state in {"limited", "partial"}
            assert any(
                row.get("reason") == "callable argument type identity unresolved"
                and row.get("call") == consumer
                for row in details
            ), (case, reasons, details)
        return
    assert hit is expected, (case, state, reasons)
    if mode == "execution-boundary":
        return
    assert state != "partial", (case, state, reasons)
    if mode in {"checked", "framework-control"}:
        assert state == "checked" and not reasons, (case, state, reasons)
    else:
        assert set(reasons) <= set(allowed), (case, reasons)
        if mode == "identity" and state == "limited":
            assert any(
                row.get("reason") == "callable argument type identity unresolved"
                and row.get("call") == "toString"
                for row in details
            ), (case, details)
        if mode == "unused-hint":
            assert "callable argument type identity unresolved" not in reasons
    if mode == "framework-control":
        findings = [row for row in report["findings"] if row["rule_id"] == SQL]
        assert len(findings) == 1
        assert findings[0]["evidence"][0]["excerpt"].strip() == "db.execSQL(q.trim())"


def test_review31_optional_initializer_hint_restores_query_depth_after_failure(monkeypatch):
    from mobile_audit.native_flow import NativeFlow
    from mobile_audit.source_analysis import Frame

    flow = NativeFlow([])
    analyzer = object.__new__(Analyzer)
    analyzer.native_flow = flow
    flow.type_hint_depth = 1

    def failed_hint(*args, **kwargs):
        raise LookupError("synthetic type query failure")

    monkeypatch.setattr(analyzer, "known_value_type", failed_hint)
    with pytest.raises(LookupError, match="synthetic type query failure"):
        analyzer.initializer_type_hint(None, Frame())
    assert flow.type_hint_depth == 1


_REVIEW32_PROGRAMS = {
    "01-constructor-applicability": [
        (
            "Caller.kt",
            'package fresh.adversarial31.constructors\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Required(val n:Int) {\n fun label():kotlin.String="fixed"\n companion object { operator fun invoke():Other=Other() }\n}\nclass Defaulted(val n:Int=7) {\n fun label():kotlin.String="fixed"\n companion object { operator fun invoke():Other=Other() }\n}\nclass Secondary private constructor(n:Int) {\n constructor():this(7)\n fun label():kotlin.String="fixed"\n companion object { operator fun invoke():Other=Other() }\n}\nclass Protected protected constructor() {\n fun label():kotlin.String="fixed"\n companion object { operator fun invoke():Other=Other() }\n}\nclass Public public constructor() {\n fun label():kotlin.String="fixed"\n companion object { operator fun invoke():Other=Other() }\n}\nclass NotesRequired(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Required()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  value.label().run { db.execSQL(trim()) } // ROW:101\n }\n}\nclass NotesDefaulted(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Defaulted()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  value.label().run { db.execSQL(trim()) } // ROW:102\n }\n}\nclass NotesSecondary(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Secondary()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  value.label().run { db.execSQL(trim()) } // ROW:103\n }\n}\nclass NotesProtected(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Protected()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  value.label().run { db.execSQL(trim()) } // ROW:104\n }\n}\nclass NotesPublic(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Public()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  value.label().run { db.execSQL(trim()) } // ROW:105\n }\n}\n',
        )
    ],
    "02-implicit-outer-heads": [
        (
            "Caller.kt",
            'package fresh.adversarial31.outerheads\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Thing { fun label():kotlin.String="fixed" }\nclass OuterHead {\n companion object { val Thing:()->Other={Other()} }\n class Middle {\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Thing()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  value.label().run { db.execSQL(trim()) } // ROW:201\n }\n}\n }\n}\nclass OuterInstance {\n val Thing:()->Other={Other()}\n class Middle {\nclass Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Thing()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  value.label().run { db.execSQL(trim()) } // ROW:202\n }\n}\n }\n}\nopen class Base { val Thing:()->Other={Other()} }\nclass OuterInherited:Base() {\ninner class Notes(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val value=Thing()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  value.label().run { db.execSQL(trim()) } // ROW:203\n }\n}\n}\n',
        )
    ],
    "03-nullable-carriers": [
        (
            "Caller.kt",
            'package fresh.adversarial31.nullable\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport fresh.adversarial31.nullable.kinds.MaybeText\nimport fresh.adversarial31.nullable.kinds.Text\nclass Other\nclass Holder { val label:kotlin.String?=null }\nclass NotesThis(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:kotlin.String?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  this.label.toString().run { db.execSQL(trim()) } // ROW:301\n }\n}\nclass NotesParenthesized(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:kotlin.String?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  (label).toString().run { db.execSQL(trim()) } // ROW:302\n }\n}\nclass NotesCast(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:kotlin.String?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  (label as kotlin.String?).toString().run { db.execSQL(trim()) } // ROW:303\n }\n}\nclass NotesCopy(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:kotlin.String?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  val copy=label\n  copy.toString().run { db.execSQL(trim()) } // ROW:304\n }\n}\nclass NotesBare(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:kotlin.String?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  label.toString().run { db.execSQL(trim()) } // ROW:305\n }\n}\nclass NotesMember(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val holder=Holder()\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  holder.label.toString().run { db.execSQL(trim()) } // ROW:306\n }\n}\nclass NotesReturn(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private fun label():kotlin.String?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  label().toString().run { db.execSQL(trim()) } // ROW:307\n }\n}\nclass NotesAlias(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:MaybeText=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  label.toString().run { db.execSQL(trim()) } // ROW:308\n }\n}\nclass NotesNonnull(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:Text="fixed"\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  label.toString().run { db.execSQL(trim()) } // ROW:309\n }\n}\nclass NotesAsserted(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:kotlin.String?="fixed"\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  label!!.toString().run { db.execSQL(trim()) } // ROW:310\n }\n}\nclass NotesSafe(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Any?.toString():Other=Other()\n private val label:kotlin.String?="fixed"\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label?.toString()?.run { db.execSQL(trim()) } // ROW:311\n }\n}\n',
        ),
        (
            "Kinds.kt",
            "package fresh.adversarial31.nullable.kinds\ntypealias MaybeText=kotlin.String?\ntypealias Text=kotlin.String\n",
        ),
    ],
    "04-diagnostic-consumption": [
        (
            "Caller.kt",
            'package fresh.adversarial31.consumption\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass NotesUnused(private val db:SQLiteDatabase) {\n fun scan(intent:Intent) {\n  val letter:Char=\'z\'\n  val unused=letter.toString()\n  db.execSQL("fixed") // ROW:401\n }\n}\nclass NotesThread(private val db:SQLiteDatabase) {\n private fun trim():kotlin.String="fixed"\n fun scan(intent:Intent) {\n  val q=intent.getStringExtra("q") ?: ""\n  val thread:java.lang.Thread=java.lang.Thread("bounded-"+q)\n  val converted=thread.toString()\n  converted.run { db.execSQL(trim()) } // ROW:402\n }\n}\nclass NotesRegex(private val db:SQLiteDatabase) {\n private val first="unmatched".toRegex()\n private val second=first\n private val copied=second\n fun scan(intent:Intent) {\n  val q=intent.getStringExtra("q") ?: ""\n  with("fixed") {\n   buildString {\n    append(q)\n    db.execSQL(replace(copied,"unused")) // ROW:403\n   }\n  }\n }\n}\n',
        )
    ],
    "05-exact-root-member-copies": [
        (
            "Caller.kt",
            'package fresh.adversarial31.rootcopies\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport FixedCarrier as RootFixed\nimport TaintCarrier as RootTaint\nclass Other\nclass FixedPayload { val label:Other=Other() }\nclass TaintPayload { fun label():kotlin.String="fixed" }\nclass NotesFixed(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n \n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  val carrier=RootFixed()\n  val copy=carrier.item\n  copy.label.run { db.execSQL(trim()) } // ROW:501\n }\n}\nclass NotesTaint(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n \n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  val carrier=RootTaint()\n  val copy=carrier.item\n  copy.label().run { db.execSQL(trim()) } // ROW:502\n }\n}\n',
        ),
        (
            "Root.kt",
            'class FixedPayload(\n val label:kotlin.String="fixed"\n)\nclass FixedCarrier(\n val item:FixedPayload=FixedPayload()\n)\nclass TaintPayload { fun label():TaintPayload=TaintPayload() }\nclass TaintCarrier(\n val item:TaintPayload=TaintPayload()\n)\n',
        ),
    ],
    "06-query-isolation": [
        (
            "Caller.kt",
            'package fresh.adversarial31.queryisolation\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass NotesQuery(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun clearBeforeScan():kotlin.String? { captured="CLEARED"; return null }\n private val origin=clearBeforeScan()\n private val mirror=origin\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  mirror.run { db.execSQL(trim()) } // ROW:601\n }\n}\nclass NotesFixed(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private val origin="fixed"\n private val mirror=origin\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  \n  mirror.run { db.execSQL(trim()) } // ROW:602\n }\n}\n',
        )
    ],
    "modeled-alias-names-and-inapplicable-extension": [
        (
            "Caller.kt",
            'package fresh.r32.modeledaliases\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nimport fresh.r32.modeledaliases.kinds.OriginAny as String\nimport fresh.r32.modeledaliases.kinds.OriginAny as Int\nimport fresh.r32.modeledaliases.kinds.OriginAny as Regex\nclass Other\nclass NotesString(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun String?.toString():Other=Other()\n private val label:String=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) } // ROW:String\n }\n}\nclass NotesInt(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Int?.toString():Other=Other()\n private val label:Int=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) } // ROW:Int\n }\n}\nclass NotesRegex(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Regex?.toString():Other=Other()\n private val label:Regex=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) } // ROW:Regex\n }\n}\nclass NotesNonnullableExtension(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun kotlin.String.toString():Other=Other()\n private val label:kotlin.String?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) } // ROW:nonnullable-extension\n }\n}\n',
        ),
        ("Kinds.kt", "package fresh.r32.modeledaliases.kinds\ntypealias OriginAny=kotlin.Any?\n"),
    ],
    "nullable-supertypes": [
        (
            "Caller.kt",
            'import android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other\nopen class Base\nclass Derived:Base()\nclass Holder\nclass NotesNumber(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Number?.toString():Other=Other()\n private val label:kotlin.Int?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) } // ROW:1\n }\n}\nclass NotesComparable(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Comparable<Int>?.toString():Other=Other()\n private val label:kotlin.Int?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) } // ROW:2\n }\n}\nclass NotesSerializable(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun java.io.Serializable?.toString():Other=Other()\n private val label:java.lang.Integer?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) } // ROW:3\n }\n}\nclass NotesAncestry(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Base?.toString():Other=Other()\n private val label:Derived?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) } // ROW:4\n }\n}\nclass NotesDefaultRoot(private val db:SQLiteDatabase) {\n private var captured=""\n private fun trim():kotlin.String=captured\n private fun Holder?.toString():Other=Other()\n private val label:Holder?=null\n fun scan(intent:Intent) {\n  captured=intent.getStringExtra("q") ?: ""\n  label.toString().run { db.execSQL(trim()) } // ROW:5\n }\n}\n',
        )
    ],
    "singleton-and-captured-heads": [
        (
            "Caller.kt",
            'import android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\nclass Other { fun label():Other=Other() }\nclass Thing { fun label():kotlin.String="fixed" }\nopen class Base { val Thing:()->Other={Other()} }\nobject Outer {\n val Thing:()->Other={Other()}\n class Notes(private val db:SQLiteDatabase) {\n  private var captured=""\n  private fun trim():kotlin.String=captured\n  private val value=Thing()\n  fun scan(intent:Intent) {\n   captured=intent.getStringExtra("q") ?: ""\n   value.label().run { db.execSQL(trim()) } // ROW:1\n  }\n }\n}\nfun runLocal(intent:Intent, db:SQLiteDatabase) {\n val Thing:()->Other={Other()}\n class LocalNotes {\n  private var captured=""\n  private fun trim():kotlin.String=captured\n  private val value=Thing()\n  fun scan() {\n   captured=intent.getStringExtra("q") ?: ""\n   value.label().run { db.execSQL(trim()) } // ROW:2\n  }\n }\n LocalNotes().scan()\n}\nfun runAnonymous(intent:Intent,db:SQLiteDatabase) {\n val notes=object:Base() {\n  private var captured=""\n  private fun trim():kotlin.String=captured\n  private val value=Thing()\n  fun scan() {\n   captured=intent.getStringExtra("q") ?: ""\n   value.label().run { db.execSQL(trim()) } // ROW:3\n  }\n }\n notes.scan()\n}\n',
        )
    ],
}

_REVIEW32_ROWS = [
    ("01-constructor-applicability", "101", "Caller.kt", 33, True, "exact", 0, (0, 0)),
    ("01-constructor-applicability", "102", "Caller.kt", 43, False, "exact", 0, (0, 0)),
    ("01-constructor-applicability", "103", "Caller.kt", 53, False, "exact", 0, (0, 0)),
    ("01-constructor-applicability", "104", "Caller.kt", 63, True, "exact", 0, (0, 0)),
    ("01-constructor-applicability", "105", "Caller.kt", 73, False, "exact", 0, (0, 0)),
    ("02-implicit-outer-heads", "201", "Caller.kt", 16, True, "exact", 0, (0, 0)),
    ("02-implicit-outer-heads", "202", "Caller.kt", 31, False, "exact", 0, (0, 0)),
    ("02-implicit-outer-heads", "203", "Caller.kt", 45, True, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "301", "Caller.kt", 16, True, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "302", "Caller.kt", 27, True, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "303", "Caller.kt", 38, True, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "304", "Caller.kt", 49, True, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "305", "Caller.kt", 60, True, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "306", "Caller.kt", 71, True, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "307", "Caller.kt", 82, True, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "308", "Caller.kt", 93, True, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "309", "Caller.kt", 104, False, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "310", "Caller.kt", 115, False, "exact", 0, (0, 0)),
    ("03-nullable-carriers", "311", "Caller.kt", 125, False, "exact", 0, (0, 0)),
    ("04-diagnostic-consumption", "401", "Caller.kt", 8, False, "exact", 0, (0, 0)),
    ("04-diagnostic-consumption", "402", "Caller.kt", 17, True, "toString-boundary", 16, (0, 0)),
    ("04-diagnostic-consumption", "403", "Caller.kt", 29, True, "replace-boundary", 29, (0, 0)),
    ("05-exact-root-member-copies", "501", "Caller.kt", 17, False, "known-root-boundary", 0, (14, 17)),
    ("05-exact-root-member-copies", "502", "Caller.kt", 28, True, "exact", 0, (0, 0)),
    ("06-query-isolation", "601", "Caller.kt", 13, True, "exact", 0, (0, 0)),
    ("06-query-isolation", "602", "Caller.kt", 24, False, "exact", 0, (0, 0)),
    ("modeled-alias-names-and-inapplicable-extension", "String", "Caller.kt", 15, True, "exact", 0, (0, 0)),
    ("modeled-alias-names-and-inapplicable-extension", "Int", "Caller.kt", 25, True, "exact", 0, (0, 0)),
    ("modeled-alias-names-and-inapplicable-extension", "Regex", "Caller.kt", 35, True, "exact", 0, (0, 0)),
    (
        "modeled-alias-names-and-inapplicable-extension",
        "nonnullable-extension",
        "Caller.kt",
        45,
        False,
        "exact",
        0,
        (0, 0),
    ),
    ("nullable-supertypes", "1", "Caller.kt", 14, True, "exact", 0, (0, 0)),
    ("nullable-supertypes", "2", "Caller.kt", 24, True, "exact", 0, (0, 0)),
    ("nullable-supertypes", "3", "Caller.kt", 34, True, "exact", 0, (0, 0)),
    ("nullable-supertypes", "4", "Caller.kt", 44, True, "exact", 0, (0, 0)),
    ("nullable-supertypes", "5", "Caller.kt", 54, True, "exact", 0, (0, 0)),
    ("singleton-and-captured-heads", "1", "Caller.kt", 14, True, "exact", 0, (0, 0)),
    ("singleton-and-captured-heads", "2", "Caller.kt", 26, True, "scope-boundary", 0, (20, 29)),
    ("singleton-and-captured-heads", "3", "Caller.kt", 38, True, "scope-boundary", 0, (32, 41)),
]


@pytest.mark.parametrize(
    "program,marker,path,line,expected,mode,consumer,scope",
    _REVIEW32_ROWS,
    ids=[r[0] + ":" + r[1] for r in _REVIEW32_ROWS],
)
def test_review32_nullable_origin_and_lexical_constructor_evidence(
    program, marker, path, line, expected, mode, consumer, scope
):
    report = analyze_sources(_REVIEW32_PROGRAMS[program])
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), (program, marker)
    hits = {
        (ev["path"], ev["line"])
        for finding in report["findings"]
        if finding["rule_id"] == SQL
        for ev in finding["evidence"]
    }
    hit = (path, line) in hits
    state, reasons = _state(report, SQL), _reasons(report)
    flow = report["metadata"]["native_flow"]
    details = flow.get("partial_details", [])
    if state == "partial":
        assert flow.get("budget_reasons"), (program, marker, state, reasons)
    elif state == "limited":
        assert reasons and not flow.get("budget_reasons"), (program, marker, state, reasons)
    else:
        assert state == "checked" and not reasons, (program, marker, state, reasons)
    if mode in {"toString-boundary", "replace-boundary"} and hit is not expected:
        assert state in {"limited", "partial"}
        assert any(
            row.get("reason") == "callable argument type identity unresolved"
            and row.get("call") == mode.removesuffix("-boundary")
            and row.get("path") == path
            and row.get("line") == consumer
            for row in details
        ), (program, marker, details)
    elif mode == "known-root-boundary" and hit is not expected:
        assert state == "limited" and any(
            row.get("reason")
            in {
                "constructor field mapping unavailable",
                "object alias identity unavailable",
                "unresolved callable identity or argument signature",
            }
            and row.get("path") == path
            and scope[0] <= row.get("line", 0) <= scope[1]
            for row in details
        ), (program, marker, details)
    elif mode == "scope-boundary" and hit is not expected:
        assert state in {"limited", "partial"} and any(
            row.get("reason")
            in {
                "nominal callable scope unavailable",
                "anonymous callable scope unavailable",
                "callable value binding unresolved",
            }
            and row.get("path") == path
            and scope[0] <= row.get("line", 0) <= scope[1]
            for row in details
        ), (program, marker, details)
    else:
        assert hit is expected, (program, marker, state, reasons, hits)
    if marker == "401":
        assert not any(
            row.get("reason") == "callable argument type identity unresolved"
            and row.get("path") == path
            and row.get("line") == 7
            for row in details
        ), details


# Compiler/runtime-accepted R32 adversarial and post-review calibration fixtures.
_REVIEW33_PROGRAMS = {
    "review32-01-nullable-origin-aliases": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "import fresh.proofs.kinds.NullableText as Long\n"
            "import fresh.proofs.kinds.FixedText as Regex\n"
            "class Other\n"
            "class Box { val value:Long=null }\n"
            "class AliasThis(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun Any?.toString():Other=Other()\n"
            " private val origin:Long=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  this.origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1101\n"
            " }\n"
            "}\n"
            "class AliasParen(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun Any?.toString():Other=Other()\n"
            " private val origin:Long=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  ((origin)).toString().run { db.execSQL(trim()) } // "
            "ROW:1102\n"
            " }\n"
            "}\n"
            "class AliasCast(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun Any?.toString():Other=Other()\n"
            " private val origin:Long=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  (origin as kotlin.String?).toString().run { "
            "db.execSQL(trim()) } // ROW:1103\n"
            " }\n"
            "}\n"
            "class AliasCopy(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun Any?.toString():Other=Other()\n"
            " private val origin:Long=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  val copy=this.origin; copy.toString().run { "
            "db.execSQL(trim()) } // ROW:1104\n"
            " }\n"
            "}\n"
            "class AliasMember(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun Any?.toString():Other=Other()\n"
            " private val box=Box()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  box.value.toString().run { db.execSQL(trim()) } // "
            "ROW:1105\n"
            " }\n"
            "}\n"
            "class AliasFixed(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun Any?.toString():Other=Other()\n"
            ' private val origin:Regex="fixed"\n'
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1106\n"
            " }\n"
            "}\n"
            "class AliasAsserted(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun Any?.toString():Other=Other()\n"
            ' private val origin:Long="fixed"\n'
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin!!.toString().run { db.execSQL(trim()) } // "
            "ROW:1107\n"
            " }\n"
            "}\n",
        ),
        (
            "Kinds.kt",
            "package fresh.proofs.kinds\n"
            "typealias NullableText=kotlin.String?\n"
            "typealias FixedText=kotlin.String\n",
        ),
    ],
    "review32-02-extension-applicability": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class Other\n"
            "typealias NullableNumber=kotlin.Number?\n"
            "class NullableNumberExtension(private val "
            "db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun kotlin.Number?.toString():Other=Other()\n"
            " private val origin:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1201\n"
            " }\n"
            "}\n"
            "class NonnullNumberExtension(private val "
            "db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun kotlin.Number.toString():Other=Other()\n"
            " private val origin:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1202\n"
            " }\n"
            "}\n"
            "class NullableCharsExtension(private val "
            "db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun "
            "kotlin.CharSequence?.toString():Other=Other()\n"
            " private val origin:kotlin.String?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1203\n"
            " }\n"
            "}\n"
            "class NonnullCharsExtension(private val "
            "db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun "
            "kotlin.CharSequence.toString():Other=Other()\n"
            " private val origin:kotlin.String?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1204\n"
            " }\n"
            "}\n"
            "class NullableAliasExtension(private val "
            "db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun NullableNumber.toString():Other=Other()\n"
            " private val origin:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1205\n"
            " }\n"
            "}\n"
            "class NonnullExactExtension(private val "
            "db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun kotlin.Int.toString():Other=Other()\n"
            " private val origin:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1206\n"
            " }\n"
            "}\n"
            "class DistinctFinalExtension(private val "
            "db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun kotlin.String?.toString():Other=Other()\n"
            " private val origin:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1207\n"
            " }\n"
            "}\n"
            "class NonnullSerializableExtension(private val "
            "db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun "
            "java.io.Serializable.toString():Other=Other()\n"
            " private val origin:kotlin.String?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.toString().run { db.execSQL(trim()) } // "
            "ROW:1208\n"
            " }\n"
            "}\n",
        )
    ],
    "review32-03-constructor-heads": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class Other { fun label():Other=Other() }\n"
            "class Defaulted(val n:Int=17) { fun "
            'label():kotlin.String="fixed" }\n'
            "class Secondary private constructor(n:Int) {\n"
            " constructor():this(17)\n"
            ' fun label():kotlin.String="fixed"\n'
            "}\n"
            "class Varargs(vararg val n:Int) { fun "
            'label():kotlin.String="fixed" }\n'
            "class PrivateCtor private constructor() {\n"
            ' fun label():kotlin.String="fixed"\n'
            " companion object { operator fun invoke():Other=Other() }\n"
            "}\n"
            "object Lexical {\n"
            " val Defaulted:()->Other={Other()}\n"
            "class HeadNotes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val origin=Defaulted()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.label().run { db.execSQL(trim()) } // ROW:1304\n"
            " }\n"
            "}\n"
            "}\n"
            "class DefaultNotes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val origin=Defaulted()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.label().run { db.execSQL(trim()) } // ROW:1301\n"
            " }\n"
            "}\n"
            "class SecondaryNotes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val origin=Secondary()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.label().run { db.execSQL(trim()) } // ROW:1302\n"
            " }\n"
            "}\n"
            "class VarargNotes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val origin=Varargs()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.label().run { db.execSQL(trim()) } // ROW:1303\n"
            " }\n"
            "}\n"
            "class PrivateNotes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val origin=PrivateCtor()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.label().run { db.execSQL(trim()) } // ROW:1305\n"
            " }\n"
            "}\n",
        )
    ],
    "review32-04-singleton-captured-heads": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class Other { fun label():Other=Other() }\n"
            'class Thing { fun label():kotlin.String="fixed" }\n'
            "object Global {\n"
            " val Thing:()->Other={Other()}\n"
            " class Middle {\n"
            "class SingletonNotes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val origin=Thing()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.label().run { db.execSQL(trim()) } // "
            "ROW:1401\n"
            " }\n"
            "}\n"
            "}\n"
            "}\n"
            "class Ordinary {\n"
            " val Thing:()->Other={Other()}\n"
            " class Middle {\n"
            "class StaticNotes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val origin=Thing()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  origin.label().run { db.execSQL(trim()) } // "
            "ROW:1402\n"
            " }\n"
            "}\n"
            "}\n"
            "}\n"
            "open class HeadBase { val Thing:()->Other={Other()} }\n"
            "fun localCase(intent:Intent,db:SQLiteDatabase) {\n"
            " val Thing:()->Other={Other()}\n"
            " class Captured {\n"
            '  private var captured=""\n'
            "  private fun trim():kotlin.String=captured\n"
            "  private val origin=Thing()\n"
            "  fun scan() {\n"
            '   captured=intent.getStringExtra("q") ?: ""\n'
            "   origin.label().run { db.execSQL(trim()) } // "
            "ROW:1403\n"
            "  }\n"
            " }\n"
            " Captured().scan()\n"
            "}\n"
            "fun anonymousCase(intent:Intent,db:SQLiteDatabase) {\n"
            " val notes=object:HeadBase() {\n"
            '  private var captured=""\n'
            "  private fun trim():kotlin.String=captured\n"
            "  private val origin=Thing()\n"
            "  fun scan() {\n"
            '   captured=intent.getStringExtra("q") ?: ""\n'
            "   origin.label().run { db.execSQL(trim()) } // "
            "ROW:1404\n"
            "  }\n"
            " }\n"
            " notes.scan()\n"
            "}\n",
        )
    ],
    "review32-05-diagnostic-consumption": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class UnusedNotes(private val db:SQLiteDatabase) {\n"
            " fun scan(intent:Intent) {\n"
            "  val letter:Char='x'\n"
            "  val unused=(letter).toString()\n"
            '  db.execSQL("fixed") // ROW:1501\n'
            " }\n"
            "}\n"
            "class ThreadNotes(private val db:SQLiteDatabase) {\n"
            ' private fun trim():kotlin.String="fixed"\n'
            " fun scan(intent:Intent) {\n"
            '  val q=intent.getStringExtra("q") ?: ""\n'
            "  val "
            'worker:java.lang.Thread=java.lang.Thread("synthetic-"+q)\n'
            "  val result=worker.toString()\n"
            "  result.run { db.execSQL(trim()) } // ROW:1502\n"
            " }\n"
            "}\n"
            "class RegexNotes(private val db:SQLiteDatabase) {\n"
            ' private val original="unmatched".toRegex()\n'
            " private val retained=original\n"
            " private val pattern=retained\n"
            " fun scan(intent:Intent) {\n"
            '  val q=intent.getStringExtra("q") ?: ""\n'
            '  with("fixed") {\n'
            "   buildString {\n"
            "    append(q)\n"
            '    db.execSQL(replace(pattern,"unused")) // ROW:1503\n'
            "   }\n"
            "  }\n"
            " }\n"
            "}\n",
        )
    ],
    "review32-06-query-isolation": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class QueryNotes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            ' private fun initialize():kotlin.String? { captured="CLEARED"; '
            "return null }\n"
            " private val origin=initialize()\n"
            " private val mirror=origin\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  mirror.run { db.execSQL(trim()) } // ROW:1601\n"
            " }\n"
            "}\n"
            "class FixedNotes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            ' private val origin="fixed"\n'
            " private val mirror=origin\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            "  mirror.run { db.execSQL(trim()) } // ROW:1602\n"
            " }\n"
            "}\n",
        )
    ],
    "claude32-01-inherited-singleton-head": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class Other { fun label():Other=Other() }\n"
            'class Thing { fun label():kotlin.String="fixed" }\n'
            "open class Base { val Thing:()->Other={Other()} }\n"
            "object SingletonOuter:Base() {\n"
            " class Notes(private val db:SQLiteDatabase) {\n"
            '  private var captured=""\n'
            "  private fun trim():kotlin.String=captured\n"
            "  private val value=Thing()\n"
            "  fun scan(intent:Intent) {\n"
            '   captured=intent.getStringExtra("q") ?: ""\n'
            "   value.label().run { db.execSQL(trim()) } // "
            "ROW:33011\n"
            "  }\n"
            " }\n"
            "}\n"
            "class OrdinaryOuter:Base() {\n"
            " class Notes(private val db:SQLiteDatabase) {\n"
            '  private var captured=""\n'
            "  private fun trim():kotlin.String=captured\n"
            "  private val value=Thing()\n"
            "  fun scan(intent:Intent) {\n"
            '   captured=intent.getStringExtra("q") ?: ""\n'
            "   value.label().run { db.execSQL(trim()) } // "
            "ROW:33012\n"
            "  }\n"
            " }\n"
            "}\n",
        )
    ],
    "claude32-02-ordinary-companion": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class Host {\n"
            " companion object {\n"
            "  fun scan(db:SQLiteDatabase,intent:Intent) {\n"
            '   listOf(intent.getStringExtra("q") ?: "").forEach {\n'
            "    run { db.execSQL(it) } // ROW:33021\n"
            "   }\n"
            "  }\n"
            " }\n"
            "}\n"
            "fun plainScan(db:SQLiteDatabase,intent:Intent) {\n"
            ' listOf(intent.getStringExtra("q") ?: "").forEach {\n'
            "  run { db.execSQL(it) } // ROW:33022\n"
            " }\n"
            "}\n",
        )
    ],
    "claude32-03-extension-implicit-locale": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "import java.util.Locale\n"
            'class FakeLocale { val US:kotlin.String="fake-us" }\n'
            "class Source(val db:SQLiteDatabase) {\n"
            " val Locale=FakeLocale()\n"
            ' var captured:kotlin.String=""\n'
            " fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            " fun memberScan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("q") ?: ""\n'
            '  with("fixed") { '
            "db.execSQL(format(locale=Locale.US)) } // ROW:33033\n"
            " }\n"
            "}\n"
            "fun Source.scan(intent:Intent) {\n"
            ' captured=intent.getStringExtra("q") ?: ""\n'
            ' with("fixed") { db.execSQL(format(locale=Locale.US)) '
            "} // ROW:33031\n"
            "}\n"
            "fun Source.standardControl(intent:Intent) {\n"
            ' captured=intent.getStringExtra("q") ?: ""\n'
            ' with("fixed") { '
            "db.execSQL(format(locale=java.util.Locale.US)) } // "
            "ROW:33032\n"
            "}\n",
        )
    ],
    "claude32-04-unused-generic-extension": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class GenericNotes(private val db:SQLiteDatabase) {\n"
            ' private fun<T>T?.toString():kotlin.String="x"\n'
            " fun scan(intent:Intent) {\n"
            '  val unused="fixed".toString()\n'
            '  db.execSQL("fixed") // ROW:33041\n'
            " }\n"
            "}\n"
            "class PlainNotes(private val db:SQLiteDatabase) {\n"
            " fun scan(intent:Intent) {\n"
            '  val unused="fixed".toString()\n'
            '  db.execSQL("fixed") // ROW:33042\n'
            " }\n"
            "}\n",
        )
    ],
}

_REVIEW33_ROWS = [
    ("review32-01-nullable-origin-aliases", "1101", "Caller.kt", 14, True, "exact", 0, (0, 0)),
    ("review32-01-nullable-origin-aliases", "1102", "Caller.kt", 24, True, "exact", 0, (0, 0)),
    ("review32-01-nullable-origin-aliases", "1103", "Caller.kt", 34, True, "exact", 0, (0, 0)),
    ("review32-01-nullable-origin-aliases", "1104", "Caller.kt", 44, True, "exact", 0, (0, 0)),
    ("review32-01-nullable-origin-aliases", "1105", "Caller.kt", 54, True, "exact", 0, (0, 0)),
    ("review32-01-nullable-origin-aliases", "1106", "Caller.kt", 64, False, "exact", 0, (0, 0)),
    ("review32-01-nullable-origin-aliases", "1107", "Caller.kt", 74, False, "exact", 0, (0, 0)),
    ("review32-02-extension-applicability", "1201", "Caller.kt", 12, True, "exact", 0, (0, 0)),
    ("review32-02-extension-applicability", "1202", "Caller.kt", 22, False, "exact", 0, (0, 0)),
    ("review32-02-extension-applicability", "1203", "Caller.kt", 32, True, "exact", 0, (0, 0)),
    ("review32-02-extension-applicability", "1204", "Caller.kt", 42, False, "exact", 0, (0, 0)),
    ("review32-02-extension-applicability", "1205", "Caller.kt", 52, True, "exact", 0, (0, 0)),
    ("review32-02-extension-applicability", "1206", "Caller.kt", 62, False, "exact", 0, (0, 0)),
    ("review32-02-extension-applicability", "1207", "Caller.kt", 72, False, "exact", 0, (0, 0)),
    ("review32-02-extension-applicability", "1208", "Caller.kt", 82, False, "exact", 0, (0, 0)),
    ("review32-03-constructor-heads", "1301", "Caller.kt", 32, False, "exact", 0, (0, 0)),
    ("review32-03-constructor-heads", "1302", "Caller.kt", 41, False, "exact", 0, (0, 0)),
    ("review32-03-constructor-heads", "1303", "Caller.kt", 50, False, "exact", 0, (0, 0)),
    ("review32-03-constructor-heads", "1305", "Caller.kt", 59, True, "exact", 0, (0, 0)),
    ("review32-03-constructor-heads", "1304", "Caller.kt", 22, True, "exact", 0, (0, 0)),
    ("review32-04-singleton-captured-heads", "1401", "Caller.kt", 14, True, "exact", 0, (0, 0)),
    ("review32-04-singleton-captured-heads", "1402", "Caller.kt", 28, False, "exact", 0, (0, 0)),
    ("review32-04-singleton-captured-heads", "1403", "Caller.kt", 42, True, "scope-boundary", 0, (36, 44)),
    ("review32-04-singleton-captured-heads", "1404", "Caller.kt", 54, True, "scope-boundary", 0, (48, 56)),
    ("review32-05-diagnostic-consumption", "1501", "Caller.kt", 7, False, "exact", 0, (0, 0)),
    ("review32-05-diagnostic-consumption", "1502", "Caller.kt", 16, True, "toString-boundary", 15, (0, 0)),
    ("review32-05-diagnostic-consumption", "1503", "Caller.kt", 28, True, "replace-boundary", 28, (0, 0)),
    ("review32-06-query-isolation", "1601", "Caller.kt", 11, True, "exact", 0, (0, 0)),
    ("review32-06-query-isolation", "1602", "Caller.kt", 21, False, "exact", 0, (0, 0)),
    ("claude32-01-inherited-singleton-head", "33011", "Caller.kt", 13, True, "exact", 0, (0, 0)),
    ("claude32-01-inherited-singleton-head", "33012", "Caller.kt", 24, False, "exact", 0, (0, 0)),
    ("claude32-02-ordinary-companion", "33021", "Caller.kt", 7, True, "exact", 0, (0, 0)),
    ("claude32-02-ordinary-companion", "33022", "Caller.kt", 14, True, "exact", 0, (0, 0)),
    (
        "claude32-03-extension-implicit-locale",
        "33031",
        "Caller.kt",
        16,
        True,
        "extension-origin-boundary",
        16,
        (0, 0),
    ),
    ("claude32-03-extension-implicit-locale", "33032", "Caller.kt", 20, False, "exact", 0, (0, 0)),
    ("claude32-03-extension-implicit-locale", "33033", "Caller.kt", 11, True, "exact", 0, (0, 0)),
    ("claude32-04-unused-generic-extension", "33041", "Caller.kt", 7, False, "exact", 0, (0, 0)),
    ("claude32-04-unused-generic-extension", "33042", "Caller.kt", 13, False, "exact", 0, (0, 0)),
]


@pytest.mark.parametrize(
    "program,marker,path,line,expected,mode,consumer,scope",
    _REVIEW33_ROWS,
    ids=[r[0] + ":" + r[1] for r in _REVIEW33_ROWS],
)
def test_review33_extension_nullability_and_implicit_head_evidence(
    program, marker, path, line, expected, mode, consumer, scope
):
    report = analyze_sources(_REVIEW33_PROGRAMS[program])
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), (program, marker)
    hits = {
        (ev["path"], ev["line"])
        for finding in report["findings"]
        if finding["rule_id"] == SQL
        for ev in finding["evidence"]
    }
    hit = (path, line) in hits
    state, reasons = _state(report, SQL), _reasons(report)
    flow = report["metadata"]["native_flow"]
    details = flow.get("partial_details", [])
    if state == "partial":
        assert flow.get("budget_reasons"), (program, marker, state, reasons)
    elif state == "limited":
        assert reasons and not flow.get("budget_reasons"), (program, marker, state, reasons)
    else:
        assert state == "checked" and not reasons, (program, marker, state, reasons)
    if mode in {"toString-boundary", "replace-boundary"} and hit is not expected:
        assert state in {"limited", "partial"}
        assert any(
            row.get("reason") == "callable argument type identity unresolved"
            and row.get("call") == mode.removesuffix("-boundary")
            and row.get("path") == path
            and row.get("line") == consumer
            for row in details
        ), (program, marker, details)
    elif mode == "scope-boundary" and hit is not expected:
        assert state in {"limited", "partial"} and any(
            row.get("reason")
            in {
                "nominal callable scope unavailable",
                "anonymous callable scope unavailable",
                "callable value binding unresolved",
            }
            and row.get("path") == path
            and scope[0] <= row.get("line", 0) <= scope[1]
            for row in details
        ), (program, marker, details)
    elif mode == "extension-origin-boundary" and hit is not expected:
        assert state in {"limited", "partial"} and any(
            row.get("reason") == "unresolved callable identity or argument signature"
            and row.get("call") == "format"
            and row.get("path") == path
            and row.get("line") == consumer
            for row in details
        ), (program, marker, details)
    else:
        assert hit is expected, (program, marker, state, reasons, hits)
    if marker in {"1501", "33021"}:
        unused = {"1501": 6, "33021": 7}[marker]
        assert not any(
            row.get("reason") == "callable argument type identity unresolved"
            and row.get("path") == path
            and row.get("line") == unused
            for row in details
        ), details
    if marker in {"33041", "33042"}:
        assert state == "checked" and not reasons


def test_review33_declared_extension_receiver_vetoes_imported_locale_head(monkeypatch):
    standard, argument = Analyzer.standard_reference_kind, Analyzer.library_argument_type
    standards, arguments = {}, {}

    def observe_standard(self, node, frame):
        result = standard(self, node, frame)
        if self.text(node) in {"Locale.US", "java.util.Locale.US"}:
            standards.setdefault(self.location(node)["line"], set()).add(result)
        return result

    def observe_argument(self, node, frame, qualified, **kwargs):
        result = argument(self, node, frame, qualified, **kwargs)
        if self.text(node) in {"Locale.US", "java.util.Locale.US"} and qualified == "java.util.Locale":
            arguments.setdefault(self.location(node)["line"], set()).add(result)
        return result

    monkeypatch.setattr(Analyzer, "standard_reference_kind", observe_standard)
    monkeypatch.setattr(Analyzer, "library_argument_type", observe_argument)
    analyze_sources(_REVIEW33_PROGRAMS["claude32-03-extension-implicit-locale"])
    assert standards.get(16) == {""}, standards
    assert standards.get(20) == {"java.util.Locale"}, standards
    assert arguments.get(16) == {False}, arguments
    assert arguments.get(20) == {True}, arguments


def test_review33_inherited_singleton_value_head_is_not_a_detached_constructor(monkeypatch):
    constructor = Analyzer.detached_constructor_kind
    observations = {}

    def observe_constructor(self, node):
        result = constructor(self, node)
        if self.text(node) == "Thing()":
            observations.setdefault(self.location(node)["line"], set()).add(result)
        return result

    monkeypatch.setattr(Analyzer, "detached_constructor_kind", observe_constructor)
    analyze_sources(_REVIEW33_PROGRAMS["claude32-01-inherited-singleton-head"])
    assert observations.get(10) == {""}, observations
    assert observations.get(21) == {"@source:Thing"}, observations


# Fresh compiler-accepted callable head, visibility and retained-fact regressions.
_REVIEW34_PROGRAMS = {
    "review33-01-extension-universe": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class Token\n"
            "typealias FixedNumeric=kotlin.Number\n"
            "typealias MaybeNumeric=kotlin.Number?\n"
            "class NonNullComparable(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun "
            "kotlin.Comparable<kotlin.Int>.toString():Token=Token()\n"
            " private val subject:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.toString().run { db.execSQL(trim()) } // ROW:4101\n"
            " }\n"
            "}\n"
            "class NonNullAlias(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun FixedNumeric.toString():Token=Token()\n"
            " private val subject:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.toString().run { db.execSQL(trim()) } // ROW:4102\n"
            " }\n"
            "}\n"
            "class NullableAlias(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun MaybeNumeric.toString():Token=Token()\n"
            " private val subject:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.toString().run { db.execSQL(trim()) } // ROW:4103\n"
            " }\n"
            "}\n"
            "class UnknownGeneric(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun <T>T?.toString():Token=Token()\n"
            " private val subject:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.toString().run { db.execSQL(trim()) } // ROW:4104\n"
            " }\n"
            "}\n"
            "class NonNullSerializable(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun java.io.Serializable.toString():Token=Token()\n"
            " private val subject:kotlin.String?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.toString().run { db.execSQL(trim()) } // ROW:4105\n"
            " }\n"
            "}\n"
            "class NullableComparable(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun "
            "kotlin.Comparable<kotlin.Int>?.toString():Token=Token()\n"
            " private val subject:kotlin.Int?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.toString().run { db.execSQL(trim()) } // ROW:4106\n"
            " }\n"
            "}\n"
            "class NonNullFunction(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private fun (()->Unit).toString():Token=Token()\n"
            " private val subject:kotlin.String?=null\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.toString().run { db.execSQL(trim()) } // ROW:4107\n"
            " }\n"
            "}\n",
        )
    ],
    "review33-02-inherited-heads": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class Token { fun label():Token=Token() }\n"
            'class Candidate { fun label():kotlin.String="constant" }\n'
            "open class PropertyHeads { val Candidate:()->Token={Token()} }\n"
            "open class FunctionHeads { fun Candidate():Token=Token() }\n"
            "object InheritedValue:PropertyHeads() {\n"
            " class Level {\n"
            "class Notes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val subject=Candidate()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.label().run { db.execSQL(trim()) } // ROW:4201\n"
            " }\n"
            "}\n"
            "}\n"
            "}\n"
            "object InheritedFunction:FunctionHeads() {\n"
            " class Level {\n"
            "class Notes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val subject=Candidate()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.label().run { db.execSQL(trim()) } // ROW:4202\n"
            " }\n"
            "}\n"
            "}\n"
            "}\n"
            "class Ordinary:PropertyHeads() {\n"
            " class Level {\n"
            "class Notes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val subject=Candidate()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.label().run { db.execSQL(trim()) } // ROW:4203\n"
            " }\n"
            "}\n"
            "}\n"
            "}\n"
            "object Empty {\n"
            " class Level {\n"
            "class Notes(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val subject=Candidate()\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  subject.label().run { db.execSQL(trim()) } // ROW:4204\n"
            " }\n"
            "}\n"
            "}\n"
            "}\n",
        )
    ],
    "review33-03-companion-competition": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "import java.util.Locale\n"
            'class FakeLocale { val US="text" }\n'
            "open class LocaleHeads { val Locale=FakeLocale() }\n"
            "class Plain {\n"
            " companion object {\n"
            '  private var captured=""\n'
            "  private fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            "  fun scan(intent:Intent,db:SQLiteDatabase) {\n"
            '   captured=intent.getStringExtra("query") ?: ""\n'
            '   with("constant") { '
            "db.execSQL(format(locale=Locale.US)) } // ROW:4301\n"
            "  }\n"
            " }\n"
            "}\n"
            "class ValueHead {\n"
            " companion object {\n"
            " val Locale=FakeLocale()\n"
            '  private var captured=""\n'
            "  private fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            "  fun scan(intent:Intent,db:SQLiteDatabase) {\n"
            '   captured=intent.getStringExtra("query") ?: ""\n'
            '   with("constant") { '
            "db.execSQL(format(locale=Locale.US)) } // ROW:4302\n"
            "  }\n"
            " }\n"
            "}\n"
            "class InheritedHead {\n"
            " companion object:LocaleHeads() {\n"
            '  private var captured=""\n'
            "  private fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            "  fun scan(intent:Intent,db:SQLiteDatabase) {\n"
            '   captured=intent.getStringExtra("query") ?: ""\n'
            '   with("constant") { '
            "db.execSQL(format(locale=Locale.US)) } // ROW:4303\n"
            "  }\n"
            " }\n"
            "}\n"
            "class NamedHead {\n"
            " companion object Locale {\n"
            ' val US="text"\n'
            '  private var captured=""\n'
            "  private fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            "  fun scan(intent:Intent,db:SQLiteDatabase) {\n"
            '   captured=intent.getStringExtra("query") ?: ""\n'
            '   with("constant") { '
            "db.execSQL(format(locale=Locale.US)) } // ROW:4304\n"
            "  }\n"
            " }\n"
            "}\n"
            "class InnerParameter {\n"
            " companion object {\n"
            "  fun scan(intent:Intent,db:SQLiteDatabase) {\n"
            '   with("constant") { '
            'intent.getStringExtra("query")!!.let { '
            "db.execSQL(it.trim()) } } // ROW:4305\n"
            "  }\n"
            " }\n"
            "}\n",
        )
    ],
    "review33-04-extension-shadow": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "import java.util.Locale\n"
            'class FakeLocale { val US="text" }\n'
            "open class Source(val db:SQLiteDatabase) {\n"
            ' var captured=""\n'
            " val Locale=FakeLocale()\n"
            " fun format(locale:kotlin.String):kotlin.String=captured\n"
            " fun member(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") { db.execSQL(format(locale=Locale.US)) } // '
            "ROW:4401\n"
            " }\n"
            "}\n"
            "typealias SourceAlias=Source\n"
            "fun Source.scan(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            ' with("constant") { db.execSQL(format(locale=Locale.US)) } // '
            "ROW:4402\n"
            "}\n"
            "fun SourceAlias.aliased(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            ' with("constant") { db.execSQL(format(locale=Locale.US)) } // '
            "ROW:4403\n"
            "}\n"
            "fun<T:Source>T.generic(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            ' with("constant") { db.execSQL(format(locale=Locale.US)) } // '
            "ROW:4404\n"
            "}\n"
            "fun Source.qualified(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            ' with("constant") { '
            "db.execSQL(format(locale=java.util.Locale.US)) } // ROW:4405\n"
            "}\n"
            "class CallableSource(val db:SQLiteDatabase) {\n"
            ' var captured=""\n'
            ' fun Locale():kotlin.String="text"\n'
            " fun format(locale:kotlin.String):kotlin.String=captured\n"
            " fun member(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") { db.execSQL(format(locale=Locale())) } // '
            "ROW:4407\n"
            " }\n"
            "}\n"
            "fun CallableSource.scan(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            ' with("constant") { db.execSQL(format(locale=Locale())) } // '
            "ROW:4406\n"
            "}\n"
            "fun CallableSource.qualified(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            ' with("constant") { '
            "db.execSQL(format(locale=java.util.Locale.US)) } // ROW:4408\n"
            "}\n",
        )
    ],
    "review33-05-diagnostic-consumers": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class UnusedGeneric(private val db:SQLiteDatabase) {\n"
            ' private fun<T>T?.toString():kotlin.String="discarded"\n'
            " fun scan(intent:Intent) {\n"
            '  val discarded="constant".toString()\n'
            '  db.execSQL("constant") // ROW:4501\n'
            " }\n"
            "}\n"
            "class ThreadConsumer(private val db:SQLiteDatabase) {\n"
            ' private fun trim():kotlin.String="constant"\n'
            " fun scan(intent:Intent) {\n"
            '  val q=intent.getStringExtra("query") ?: ""\n'
            "  val "
            'worker:java.lang.Thread=java.lang.Thread("worker-"+q)\n'
            "  val text=worker.toString() // CONSUMER:4502\n"
            "  text.run { db.execSQL(trim()) } // ROW:4502\n"
            " }\n"
            "}\n"
            "class BuilderConsumer(private val db:SQLiteDatabase) {\n"
            ' private val first="never-match".toRegex()\n'
            " private val middle=first\n"
            " private val pattern=middle\n"
            " fun scan(intent:Intent) {\n"
            '  val q=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") {\n'
            "   buildString {\n"
            "    append(q)\n"
            '    db.execSQL(replace(pattern,"unused")) // ROW:4503\n'
            "   }\n"
            "  }\n"
            " }\n"
            "}\n"
            "class Token { fun label():Token=Token() }\n"
            'class Candidate { fun label():kotlin.String="constant" }\n'
            "fun localScope(intent:Intent,db:SQLiteDatabase) {\n"
            " val Candidate:()->Token={Token()}\n"
            " class LocalNotes {\n"
            '  private var captured=""\n'
            "  private fun trim():kotlin.String=captured\n"
            "  private val subject=Candidate() // CONSUMER:4504\n"
            "  fun scan() {\n"
            '   captured=intent.getStringExtra("query") ?: ""\n'
            "   subject.label().run { db.execSQL(trim()) } // ROW:4504\n"
            "  }\n"
            " }\n"
            " LocalNotes().scan()\n"
            "}\n"
            "open class Heads { val Candidate:()->Token={Token()} }\n"
            "fun anonymousScope(intent:Intent,db:SQLiteDatabase) {\n"
            " val notes=object:Heads() {\n"
            '  private var captured=""\n'
            "  private fun trim():kotlin.String=captured\n"
            "  private val subject=Candidate()\n"
            "  fun scan() { // CONSUMER:4505\n"
            '   captured=intent.getStringExtra("query") ?: ""\n'
            "   subject.label().run { db.execSQL(trim()) } // ROW:4505\n"
            "  }\n"
            " }\n"
            " notes.scan()\n"
            "}\n",
        )
    ],
    "review33-06-query-isolation": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class MutatingQuery(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            ' private fun initialize():kotlin.String? { captured="RESET"; '
            "return null }\n"
            " private val subject=initialize()\n"
            " private val mirrored=subject\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  mirrored.run { db.execSQL(trim()) } // ROW:4601\n"
            " }\n"
            "}\n"
            "class FixedQuery(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            ' private val subject="constant"\n'
            " private val mirrored=subject\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  mirrored.run { db.execSQL(trim()) } // ROW:4602\n"
            " }\n"
            "}\n"
            "class ExpressionQuery(private val db:SQLiteDatabase) {\n"
            ' private var captured=""\n'
            " private fun trim():kotlin.String=captured\n"
            " private val subject:kotlin.String?=null\n"
            " private fun projected()=subject\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  projected().run { db.execSQL(trim()) } // ROW:4603\n"
            " }\n"
            "}\n",
        )
    ],
    "parent34-callable-arity-visibility": [
        (
            "Caller.kt",
            "package fresh.r34.callables\n"
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "import java.util.Locale\n"
            "open class PublicHead { fun "
            'Locale():kotlin.String="text" }\n'
            "open class PrivateHead { private fun "
            'Locale(language:kotlin.String):kotlin.String="text" }\n'
            "class DefaultNotes(val db:SQLiteDatabase) {\n"
            ' var captured:kotlin.String=""\n'
            " fun "
            'Locale(language:kotlin.String="en"):kotlin.String="text"\n'
            " fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") { db.execSQL(format(locale=Locale())) '
            "} // ROW:4701\n"
            " }\n"
            "}\n"
            "class VarargNotes(val db:SQLiteDatabase) {\n"
            ' var captured:kotlin.String=""\n'
            " fun Locale(vararg "
            'words:kotlin.String):kotlin.String="text"\n'
            " fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") { db.execSQL(format(locale=Locale())) '
            "} // ROW:4702\n"
            " }\n"
            "}\n"
            "class OneArgNotes(val db:SQLiteDatabase) {\n"
            ' var captured:kotlin.String=""\n'
            " fun "
            'Locale(language:kotlin.String):kotlin.String="text"\n'
            " fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") { '
            'db.execSQL(format(locale=Locale("en"))) } // ROW:4703\n'
            " }\n"
            "}\n"
            "class InheritedNotes(val db:SQLiteDatabase):PublicHead() "
            "{\n"
            ' var captured:kotlin.String=""\n'
            " \n"
            " fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") { db.execSQL(format(locale=Locale())) '
            "} // ROW:4704\n"
            " }\n"
            "}\n"
            "class ArityNotes(val db:SQLiteDatabase) {\n"
            ' var captured:kotlin.String=""\n'
            " fun "
            'Locale(first:kotlin.Int,second:kotlin.Int):kotlin.String="text"\n'
            " fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") { '
            'db.execSQL(format(locale=Locale("en"))) } // ROW:4706\n'
            " }\n"
            "}\n"
            "class PrivateNotes(val db:SQLiteDatabase):PrivateHead() "
            "{\n"
            ' var captured:kotlin.String=""\n'
            " \n"
            " fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") { '
            'db.execSQL(format(locale=Locale("en"))) } // ROW:4707\n'
            " }\n"
            "}\n"
            "class ConstantNotes(val db:SQLiteDatabase) {\n"
            ' var captured:kotlin.String=""\n'
            ' fun Locale():kotlin.String="text"\n'
            " fun "
            "format(locale:kotlin.String):kotlin.String=captured\n"
            " fun scan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            '  with("constant") { '
            "db.execSQL(format(locale=Locale.US)) } // ROW:4708\n"
            " }\n"
            "}\n"
            "fun InheritedNotes.extension(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            ' with("constant") { db.execSQL(format(locale=Locale())) '
            "} // ROW:4705\n"
            "}\n",
        )
    ],
    "claude33-01-extension-accessor": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "import java.util.Locale\n"
            'class FakeLocale { val US:kotlin.String="fake-us" }\n'
            "class Source(val db:SQLiteDatabase) {\n"
            " val Locale=FakeLocale()\n"
            ' var captured:kotlin.String=""\n'
            " fun format(locale:kotlin.String):kotlin.String=captured\n"
            " val memberProbe:Unit\n"
            '  get() { with("fixed") { '
            "db.execSQL(format(locale=Locale.US)) } } // ROW:5102\n"
            " fun memberScan(intent:Intent) {\n"
            '  captured=intent.getStringExtra("query") ?: ""\n'
            "  val ignored:Unit=memberProbe\n"
            " }\n"
            "}\n"
            "val Source.probe:Unit\n"
            ' get() { with("fixed") { '
            "db.execSQL(format(locale=Locale.US)) } } // ROW:5101\n"
            "val Source.qualifiedProbe:Unit\n"
            ' get() { with("fixed") { '
            "db.execSQL(format(locale=java.util.Locale.US)) } } // "
            "ROW:5103\n"
            "fun Source.scan(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            " val ignored:Unit=probe\n"
            "}\n"
            "fun Source.qualifiedScan(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            " val ignored:Unit=qualifiedProbe\n"
            "}\n",
        )
    ],
    "claude33-02-external-file-receiver": [
        (
            "Caller.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "fun java.io.File.scan(db:SQLiteDatabase,intent:Intent) "
            "{\n"
            ' listOf(intent.getStringExtra("query") ?: "").forEach {\n'
            "  run { db.execSQL(it) } // ROW:5201\n"
            " }\n"
            "}\n"
            "fun plainScan(db:SQLiteDatabase,intent:Intent) {\n"
            ' listOf(intent.getStringExtra("query") ?: "").forEach {\n'
            "  run { db.execSQL(it) } // ROW:5202\n"
            " }\n"
            "}\n"
            "fun java.io.File.qualified(db:SQLiteDatabase) {\n"
            ' with("fixed") { '
            "db.execSQL(format(locale=java.util.Locale.US)) } // "
            "ROW:5203\n"
            "}\n"
            "fun plainQualified(db:SQLiteDatabase) {\n"
            ' with("fixed") { '
            "db.execSQL(format(locale=java.util.Locale.US)) } // "
            "ROW:5204\n"
            "}\n",
        )
    ],
    "claude33-03-unused-nullable-generic": [
        (
            "Nullable.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class NullableGeneric(private val db:SQLiteDatabase) {\n"
            ' private fun<T>T?.toString():kotlin.String="x"\n'
            " fun scan(intent:Intent) {\n"
            "  val n:kotlin.Int?=null\n"
            "  val unused=n.toString() // UNUSED:5301\n"
            '  db.execSQL("fixed") // ROW:5301\n'
            " }\n"
            "}\n",
        ),
        (
            "Plain.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class NullablePlain(private val db:SQLiteDatabase) {\n"
            " fun scan(intent:Intent) {\n"
            "  val n:kotlin.Int?=null\n"
            "  val unused=n.toString() // UNUSED:5302\n"
            '  db.execSQL("fixed") // ROW:5302\n'
            " }\n"
            "}\n",
        ),
        (
            "NonNull.kt",
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class NonNullGeneric(private val db:SQLiteDatabase) {\n"
            ' private fun<T>T?.toString():kotlin.String="x"\n'
            " fun scan(intent:Intent) {\n"
            "  val n:kotlin.Int=7\n"
            "  val unused=n.toString() // UNUSED:5303\n"
            '  db.execSQL("fixed") // ROW:5303\n'
            " }\n"
            "}\n",
        ),
    ],
    "retained34-unavailable-dependency": [
        (
            "Caller.kt",
            "package fresh.r34.retained\n"
            "import android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "import java.util.Locale\n"
            "import vendor.Hidden\n"
            "fun Hidden.scan(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            ' with("fixed") { db.execSQL(format(locale=Locale())) } // '
            "ROW:4801\n"
            "}\n"
            "fun Hidden.qualified(intent:Intent) {\n"
            ' captured=intent.getStringExtra("query") ?: ""\n'
            ' with("fixed") { '
            "db.execSQL(format(locale=java.util.Locale.US)) } // "
            "ROW:4802\n"
            "}\n"
            "fun plain(db:SQLiteDatabase) {\n"
            ' with("fixed") { db.execSQL(format(locale=Locale("en"))) '
            "} // ROW:4803\n"
            "}\n",
        )
    ],
}

_REVIEW34_ROWS = [
    ("review33-01-extension-universe", "4101", "Caller.kt", 13, False, "exact", 13, (0, 0)),
    ("review33-01-extension-universe", "4102", "Caller.kt", 23, False, "exact", 23, (0, 0)),
    ("review33-01-extension-universe", "4103", "Caller.kt", 33, True, "exact", 33, (0, 0)),
    ("review33-01-extension-universe", "4104", "Caller.kt", 43, True, "exact", 43, (0, 0)),
    ("review33-01-extension-universe", "4105", "Caller.kt", 53, False, "exact", 53, (0, 0)),
    ("review33-01-extension-universe", "4106", "Caller.kt", 63, True, "exact", 63, (0, 0)),
    (
        "review33-01-extension-universe",
        "4107",
        "Caller.kt",
        73,
        False,
        "inapplicable-function-boundary",
        73,
        (0, 0),
    ),
    ("review33-02-inherited-heads", "4201", "Caller.kt", 15, True, "exact", 15, (0, 0)),
    ("review33-02-inherited-heads", "4202", "Caller.kt", 28, True, "exact", 28, (0, 0)),
    ("review33-02-inherited-heads", "4203", "Caller.kt", 41, False, "exact", 41, (0, 0)),
    ("review33-02-inherited-heads", "4204", "Caller.kt", 54, False, "exact", 54, (0, 0)),
    (
        "review33-03-companion-competition",
        "4301",
        "Caller.kt",
        12,
        False,
        "known-companion-boundary",
        12,
        (9, 12),
    ),
    ("review33-03-companion-competition", "4302", "Caller.kt", 23, True, "exact", 23, (0, 0)),
    ("review33-03-companion-competition", "4303", "Caller.kt", 33, True, "exact", 33, (0, 0)),
    ("review33-03-companion-competition", "4304", "Caller.kt", 44, True, "exact", 44, (0, 0)),
    ("review33-03-companion-competition", "4305", "Caller.kt", 51, True, "exact", 51, (0, 0)),
    ("review33-04-extension-shadow", "4401", "Caller.kt", 11, True, "exact", 11, (0, 0)),
    ("review33-04-extension-shadow", "4402", "Caller.kt", 17, True, "extension-origin-boundary", 17, (0, 0)),
    ("review33-04-extension-shadow", "4403", "Caller.kt", 21, True, "extension-origin-boundary", 21, (0, 0)),
    ("review33-04-extension-shadow", "4404", "Caller.kt", 25, True, "extension-origin-boundary", 25, (0, 0)),
    ("review33-04-extension-shadow", "4405", "Caller.kt", 29, False, "exact", 29, (0, 0)),
    ("review33-04-extension-shadow", "4406", "Caller.kt", 42, True, "extension-origin-boundary", 42, (0, 0)),
    ("review33-04-extension-shadow", "4407", "Caller.kt", 37, True, "exact", 37, (0, 0)),
    ("review33-04-extension-shadow", "4408", "Caller.kt", 46, False, "exact", 46, (0, 0)),
    ("review33-05-diagnostic-consumers", "4501", "Caller.kt", 7, False, "exact", 7, (0, 0)),
    ("review33-05-diagnostic-consumers", "4502", "Caller.kt", 16, True, "toString-boundary", 15, (0, 0)),
    ("review33-05-diagnostic-consumers", "4503", "Caller.kt", 28, True, "replace-boundary", 28, (0, 0)),
    ("review33-05-diagnostic-consumers", "4504", "Caller.kt", 43, True, "scope-boundary", 40, (40, 43)),
    ("review33-05-diagnostic-consumers", "4505", "Caller.kt", 56, True, "scope-boundary", 54, (54, 56)),
    ("review33-06-query-isolation", "4601", "Caller.kt", 11, True, "exact", 11, (0, 0)),
    ("review33-06-query-isolation", "4602", "Caller.kt", 21, False, "exact", 21, (0, 0)),
    ("review33-06-query-isolation", "4603", "Caller.kt", 31, True, "exact", 31, (0, 0)),
    ("parent34-callable-arity-visibility", "4701", "Caller.kt", 13, True, "exact", 13, (0, 0)),
    ("parent34-callable-arity-visibility", "4702", "Caller.kt", 22, True, "exact", 22, (0, 0)),
    ("parent34-callable-arity-visibility", "4703", "Caller.kt", 31, True, "exact", 31, (0, 0)),
    ("parent34-callable-arity-visibility", "4704", "Caller.kt", 40, True, "exact", 40, (0, 0)),
    (
        "parent34-callable-arity-visibility",
        "4705",
        "Caller.kt",
        72,
        True,
        "extension-origin-boundary",
        72,
        (0, 0),
    ),
    ("parent34-callable-arity-visibility", "4706", "Caller.kt", 49, False, "exact", 49, (0, 0)),
    ("parent34-callable-arity-visibility", "4707", "Caller.kt", 58, False, "exact", 58, (0, 0)),
    ("parent34-callable-arity-visibility", "4708", "Caller.kt", 67, False, "exact", 67, (0, 0)),
    (
        "claude33-01-extension-accessor",
        "5101",
        "Caller.kt",
        17,
        True,
        "extension-origin-boundary",
        17,
        (0, 0),
    ),
    ("claude33-01-extension-accessor", "5102", "Caller.kt", 10, True, "exact", 10, (0, 0)),
    ("claude33-01-extension-accessor", "5103", "Caller.kt", 19, False, "exact", 19, (0, 0)),
    ("claude33-02-external-file-receiver", "5201", "Caller.kt", 5, True, "exact", 5, (0, 0)),
    ("claude33-02-external-file-receiver", "5202", "Caller.kt", 10, True, "exact", 10, (0, 0)),
    ("claude33-02-external-file-receiver", "5203", "Caller.kt", 14, False, "exact", 14, (0, 0)),
    ("claude33-02-external-file-receiver", "5204", "Caller.kt", 17, False, "exact", 17, (0, 0)),
    ("claude33-03-unused-nullable-generic", "5301", "Nullable.kt", 8, False, "exact", 8, (0, 0)),
    ("claude33-03-unused-nullable-generic", "5302", "Plain.kt", 7, False, "exact", 7, (0, 0)),
    ("claude33-03-unused-nullable-generic", "5303", "NonNull.kt", 8, False, "exact", 8, (0, 0)),
    (
        "retained34-unavailable-dependency",
        "4801",
        "Caller.kt",
        8,
        True,
        "retained-constructor-boundary",
        8,
        (0, 0),
    ),
    ("retained34-unavailable-dependency", "4802", "Caller.kt", 12, False, "exact", 12, (0, 0)),
    ("retained34-unavailable-dependency", "4803", "Caller.kt", 15, False, "exact", 15, (0, 0)),
]


@pytest.mark.parametrize(
    "program,marker,path,line,expected,mode,consumer,scope",
    _REVIEW34_ROWS,
    ids=[r[0] + ":" + r[1] for r in _REVIEW34_ROWS],
)
def test_review34_callable_heads_and_constructor_visibility(
    program, marker, path, line, expected, mode, consumer, scope
):
    report = analyze_sources(_REVIEW34_PROGRAMS[program])
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"])
    hits = {
        (ev["path"], ev["line"])
        for finding in report["findings"]
        if finding["rule_id"] == SQL
        for ev in finding["evidence"]
    }
    hit = (path, line) in hits
    flow = report["metadata"]["native_flow"]
    state, reasons = _state(report, SQL), _reasons(report)
    details = flow.get("partial_details", [])
    if state == "partial":
        assert flow.get("budget_reasons"), (program, marker, reasons)
    elif state == "limited":
        assert reasons and not flow.get("budget_reasons"), (program, marker, reasons)
    else:
        assert state == "checked" and not reasons, (program, marker, state, reasons)
    if hit is not expected and mode in {
        "toString-boundary",
        "replace-boundary",
        "inapplicable-function-boundary",
    }:
        call = "toString" if mode == "inapplicable-function-boundary" else mode.removesuffix("-boundary")
        assert state in {"limited", "partial"} and any(
            d.get("reason") == "callable argument type identity unresolved"
            and d.get("call") == call
            and d.get("path") == path
            and d.get("line") == consumer
            for d in details
        ), (program, marker, details)
    elif hit is not expected and mode == "retained-constructor-boundary":
        assert state in {"limited", "partial"} and any(
            d.get("reason") == "callable argument type identity unresolved"
            and d.get("call") == "Locale"
            and d.get("path") == path
            and d.get("line") == consumer
            for d in details
        ), (program, marker, details)
    elif hit is not expected and mode == "extension-origin-boundary":
        assert state in {"limited", "partial"} and any(
            d.get("reason") == "unresolved callable identity or argument signature"
            and d.get("call") == "format"
            and d.get("path") == path
            and d.get("line") == consumer
            for d in details
        ), (program, marker, details)
    elif hit is not expected and mode == "scope-boundary":
        assert state in {"limited", "partial"} and any(
            d.get("reason")
            in {
                "nominal callable scope unavailable",
                "anonymous callable scope unavailable",
                "callable value binding unresolved",
            }
            and d.get("path") == path
            and scope[0] <= d.get("line", 0) <= scope[1]
            for d in details
        ), (program, marker, details)
    elif hit is not expected and mode == "known-companion-boundary":
        assert state in {"limited", "partial"}
        assert any(
            d.get("reason") == "nominal callable scope unavailable"
            and d.get("path") == path
            and 9 <= d.get("line", 0) <= 10
            for d in details
        ), details
        assert any(
            d.get("reason") == "receiver field inventory unavailable"
            and d.get("path") == path
            and d.get("line") == 11
            for d in details
        ), details
    else:
        assert hit is expected, (program, marker, state, reasons, hits)
    if marker in {"5201", "5203"}:
        precision = 5 if marker == "5201" else 13
        assert any(
            d.get("reason") == "callable argument type identity unresolved"
            and d.get("path") == path
            and d.get("line") == precision
            for d in details
        ), details
    if marker in {"5301", "5303"}:
        assert not any(
            d.get("reason") == "callable argument type identity unresolved"
            and d.get("path") == path
            and d.get("line") == 5
            for d in details
        ), details
    if marker in {"4305", "4501"}:
        unused = 51 if marker == "4305" else 6
        assert not any(
            d.get("reason") == "callable argument type identity unresolved"
            and d.get("path") == path
            and d.get("line") == unused
            for d in details
        ), details


@pytest.mark.parametrize(
    "program,expected",
    [
        ("review33-04-extension-shadow", {37: False, 42: False, 46: True}),
        ("review33-03-companion-competition", {12: True}),
        (
            "parent34-callable-arity-visibility",
            {13: False, 22: False, 31: False, 40: False, 72: False, 49: True, 58: True, 67: True},
        ),
    ],
)
def test_review34_callable_locale_proof_rejects_false_and_retains_standard_heads(
    monkeypatch, program, expected
):
    argument, standard = Analyzer.library_argument_type, Analyzer.standard_reference_kind
    observations = {}

    def observe(self, node, frame, qualified, **kwargs):
        before = self.native_flow.evaluations
        result = argument(self, node, frame, qualified, **kwargs)
        line = self.location(node)["line"]
        if qualified == "java.util.Locale" and line in expected:
            proof = standard(self, node, frame)
            observations.setdefault(line, set()).add((result, proof))
        assert self.native_flow.evaluations == before
        return result

    monkeypatch.setattr(Analyzer, "library_argument_type", observe)
    analyze_sources(_REVIEW34_PROGRAMS[program])
    for line, wanted in expected.items():
        assert observations.get(line) == {(wanted, "java.util.Locale" if wanted else "")}, (
            line,
            observations,
        )


@pytest.mark.parametrize(
    "program,expected",
    [
        (
            "parent34-callable-arity-visibility",
            {13: None, 22: None, 31: None, 40: None, 72: None, 49: "Locale", 58: "Locale"},
        ),
        ("retained34-unavailable-dependency", {8: "Locale", 15: "Locale"}),
    ],
)
def test_review34_constructor_facts_exclude_only_represented_visible_callable_heads(
    monkeypatch, program, expected
):
    from mobile_audit.native_flow import NativeFlow

    constructor = NativeFlow.constructor_type
    observations = {}

    def observe(self, analyzer, call, frame):
        before = self.evaluations
        result = constructor(self, analyzer, call, frame)
        line = analyzer.location(call.node)["line"]
        if call.name == "Locale" and line in expected:
            observations.setdefault(line, set()).add(result)
        assert self.evaluations == before
        return result

    monkeypatch.setattr(NativeFlow, "constructor_type", observe)
    analyze_sources(_REVIEW34_PROGRAMS[program])
    assert observations == {line: {kind} for line, kind in expected.items()}, observations


@pytest.mark.parametrize(
    "program,expected",
    [
        ("claude33-01-extension-accessor", {10: False, 17: False, 19: True}),
        ("claude33-02-external-file-receiver", {14: False, 17: True}),
    ],
)
def test_review34_accessor_and_external_receiver_proof_boundaries(monkeypatch, program, expected):
    argument, standard = Analyzer.library_argument_type, Analyzer.standard_reference_kind
    observations = {}

    def observe(self, node, frame, qualified, **kwargs):
        before = self.native_flow.evaluations
        result = argument(self, node, frame, qualified, **kwargs)
        line = self.location(node)["line"]
        if qualified == "java.util.Locale" and line in expected:
            proof = standard(self, node, frame)
            observations.setdefault(line, set()).add((result, proof))
        assert self.native_flow.evaluations == before
        return result

    monkeypatch.setattr(Analyzer, "library_argument_type", observe)
    analyze_sources(_REVIEW34_PROGRAMS[program])
    for line, wanted in expected.items():
        assert observations.get(line) == {(wanted, "java.util.Locale" if wanted else "")}, (
            line,
            observations,
        )


@pytest.mark.parametrize("path", ["Nullable.kt", "Plain.kt", "NonNull.kt"])
def test_review34_unused_nullable_generic_hint_does_not_leak_type_identity(path):
    files = [item for item in _REVIEW34_PROGRAMS["claude33-03-unused-nullable-generic"] if item[0] == path]
    assert len(files) == 1
    report = analyze_sources(files)
    assert not _hit(report, SQL)
    assert "callable argument type identity unresolved" not in _reasons(report), report
    if path in {"Nullable.kt", "Plain.kt"}:
        assert _state(report, SQL) == "checked" and not _reasons(report), report


def test_review34_retained_possible_constructor_cannot_prove_library_argument(monkeypatch):
    argument, standard = Analyzer.library_argument_type, Analyzer.standard_reference_kind
    observations = {}
    expected = {8: False, 12: False, 15: True}

    def observe(self, node, frame, qualified, **kwargs):
        before = self.native_flow.evaluations
        result = argument(self, node, frame, qualified, **kwargs)
        line = self.location(node)["line"]
        if qualified == "java.util.Locale" and line in expected:
            observations.setdefault(line, set()).add((result, standard(self, node, frame)))
        assert self.native_flow.evaluations == before
        return result

    monkeypatch.setattr(Analyzer, "library_argument_type", observe)
    analyze_sources(_REVIEW34_PROGRAMS["retained34-unavailable-dependency"])
    for line, wanted in expected.items():
        assert observations.get(line) == {(wanted, "java.util.Locale" if wanted else "")}, observations
