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


def test_trace_cut_in_a_possible_closure_result_is_a_precision_limit() -> None:
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
    assert _budget(unresolved) == [] and "source trace abstention" in _reasons(unresolved)
    # A scope block's result is recorded the same way (documented), unlike the direct value.
    assert _budget(scope) == [] and "source trace abstention" in _reasons(scope)
    assert _state(scope, URL) == "limited" and _state(direct, URL) == "partial"


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

    chain = " else ".join(f'if (k == "{i}") {{ "https://docs.example.test/{i}" }}' for i in range(800))
    started = time.perf_counter()
    report = _kotlin(
        f"""class M(private val web: WebView) {{
    fun go(intent: Intent) {{
        val q = intent.getStringExtra("q") ?: ""
        val k = intent.getStringExtra("k") ?: ""
        web.loadUrl(run {{ {chain} else {{ q }} }})
    }}
}}
"""
    )
    # Each node's result position is decided once; the uncached walk took about 9 s here.
    assert time.perf_counter() - started < 5
    assert _hit(report, URL)


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


def test_function_typed_parameter_called_with_a_closure_keeps_the_cut_a_precision_limit() -> None:
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
    assert _budget(report) == [] and "source trace abstention" in _reasons(report)


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
