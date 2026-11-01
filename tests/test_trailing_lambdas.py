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
