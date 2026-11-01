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
