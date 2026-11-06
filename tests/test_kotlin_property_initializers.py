"""Fresh synthetic construction-flow fixtures; no application data is read."""

from __future__ import annotations

import textwrap

import pytest

from mobile_audit.source_analysis import analyze_sources

SQL = "AST-SQL-CONCAT"
UNAVAILABLE = "Kotlin stored property initializer flow unavailable"
IMPORTS = """\
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
"""
INPUT = 'intent.getStringExtra("q") ?: ""'


def scan(body: str) -> dict:
    return analyze_sources([("Construction.kt", IMPORTS + textwrap.dedent(body).strip())])


def sql_findings(report: dict) -> list[dict]:
    return [finding for finding in report["findings"] if finding["rule_id"] == SQL]


def assert_checked(report: dict) -> None:
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert not report["metadata"]["native_flow"]["budget_reasons"], report


@pytest.mark.parametrize("source", [True, False], ids=["intent", "constant"])
@pytest.mark.parametrize("consumer", ["property", "init", "method"])
def test_stored_property_construction_sources_reach_sql(consumer: str, source: bool) -> None:
    value = INPUT if source else '"fixed"'
    query = f'"SELECT * FROM entries WHERE label = \'" + ({value}) + "\'"'
    statements = {
        "property": f"val initialized: Unit = db.execSQL({query})",
        "init": f"val query: String = {query}\ninit {{ db.execSQL(query) }}",
        "method": f"val query: String = {query}\nfun run() {{ db.execSQL(query) }}",
    }
    report = scan(
        f"class Handler(intent: Intent, private val db: SQLiteDatabase) {{\n{statements[consumer]}\n}}"
    )
    assert bool(sql_findings(report)) is source, report
    assert_checked(report)
    functions = report["metadata"]["functions"]
    assert functions["observed"] == (0 if consumer == "property" else 1), report
    assert functions["analyzed"] == functions["observed"], report


def test_properties_and_init_blocks_execute_in_declaration_order() -> None:
    report = scan(
        f"""class Handler(intent: Intent, private val db: SQLiteDatabase) {{
            var query: String = {INPUT}
            init {{ db.execSQL("SELECT " + query) }}
            val reset: Unit = run {{ query = "fixed" }}
            init {{ db.execSQL("SELECT " + query) }}
        }}"""
    )
    matches = sql_findings(report)
    assert len(matches) == 1, report
    assert {evidence["line"] for evidence in matches[0]["evidence"]} == {5}, report
    assert_checked(report)


def test_init_local_shadow_does_not_replace_stored_property() -> None:
    report = scan(
        f"""class Handler(intent: Intent, private val db: SQLiteDatabase) {{
            val query: String = {INPUT}
            init {{ val query = "fixed"; db.execSQL("SELECT " + query) }}
            init {{ db.execSQL("SELECT " + this.query) }}
            fun run() {{ db.execSQL("SELECT " + query) }}
        }}"""
    )
    assert len(sql_findings(report)) == 2, report
    assert_checked(report)


def test_constructor_parameter_shadow_keeps_this_field_separate() -> None:
    report = scan(
        """class Handler(query: Intent, private val db: SQLiteDatabase) {
            val query: String = "fixed"
            val result: Unit = db.execSQL("SELECT " + (query.getStringExtra("q") ?: ""))
            init { db.execSQL("SELECT " + this.query) }
            fun run() { db.execSQL("SELECT " + query) }
        }"""
    )
    assert len(sql_findings(report)) == 1, report
    assert_checked(report)


def test_nonstored_constructor_parameter_is_not_published_as_field() -> None:
    report = scan(
        f"""class Handler(intent: Intent, private val db: SQLiteDatabase) {{
            val query: String = {INPUT}
            fun run() {{ db.execSQL("SELECT " + query) }}
        }}
        class Other(private val db: SQLiteDatabase) {{
            val query: String = "fixed"
            fun run() {{ db.execSQL("SELECT " + query) }}
        }}"""
    )
    assert len(sql_findings(report)) == 1, report
    assert_checked(report)


def test_later_property_and_learned_method_writes_do_not_seed_construction() -> None:
    report = scan(
        """class Handler(private val intent: Intent, private val db: SQLiteDatabase) {
            var query: String = "fixed"
            init { db.execSQL("SELECT " + query) }
            fun fill() { query = intent.getStringExtra("q") ?: "" }
            fun run() { db.execSQL("SELECT " + query) }
        }"""
    )
    matches = sql_findings(report)
    assert len(matches) == 1, report
    assert {evidence["line"] for evidence in matches[0]["evidence"]} == {7}, report
    assert_checked(report)


def test_initializer_helper_cannot_load_a_later_field_from_method_summaries() -> None:
    report = scan(
        """class Handler(private val db: SQLiteDatabase) {
            val early: String = read()
            var query: String = "fixed"
            fun read(): String = query
            fun fill(intent: Intent) { query = intent.getStringExtra("q") ?: "" }
            fun run() { db.execSQL("SELECT " + early) }
        }"""
    )
    assert not sql_findings(report), report
    assert_checked(report)


def test_sql_receiver_identity_survives_a_property_alias() -> None:
    report = scan(
        f"""class Handler(intent: Intent, original: SQLiteDatabase) {{
            val database: SQLiteDatabase = original
            val alias: SQLiteDatabase = database
            val query: String = {INPUT}
            init {{ alias.execSQL("SELECT " + query) }}
            fun run() {{ alias.execSQL("SELECT " + query) }}
        }}"""
    )
    assert len(sql_findings(report)) == 2, report
    assert_checked(report)


def test_ordinary_unrelated_call_does_not_acquire_property_source() -> None:
    report = scan(
        """fun unrelated(value: String, db: SQLiteDatabase) { db.execSQL("SELECT 1") }
        fun run(intent: Intent, db: SQLiteDatabase) {
            unrelated(intent.getStringExtra("q") ?: "", db)
        }"""
    )
    assert not sql_findings(report), report
    assert_checked(report)


def test_unrelated_top_level_factory_does_not_downgrade_construction() -> None:
    report = scan(
        f"""val unrelated = Regex("x")
        class Handler(intent: Intent, private val db: SQLiteDatabase) {{
            val query: String = {INPUT}
            init {{ db.execSQL("SELECT " + query) }}
        }}"""
    )
    assert len(sql_findings(report)) == 1, report
    assert_checked(report)


def test_inferred_literal_field_does_not_acquire_a_project_string_type() -> None:
    report = scan(
        """class String
        class Handler(private val db: SQLiteDatabase) {
            var captured = "fixed"
            fun fill(intent: Intent) { captured = intent.getStringExtra("q") ?: "" }
            fun run() { db.execSQL("SELECT " + captured) }
        }"""
    )
    assert len(sql_findings(report)) == 1, report
    assert_checked(report)


def test_null_return_in_construction_helper_is_not_an_unknown_field() -> None:
    report = scan(
        """class Handler(private val db: SQLiteDatabase) {
            var captured = "fixed"
            private fun reset(): kotlin.String? { captured = "fixed"; return null }
            val unused: kotlin.String? = reset()
            fun fill(intent: Intent) { captured = intent.getStringExtra("q") ?: "" }
            fun run() { db.execSQL("SELECT " + captured) }
        }"""
    )
    assert len(sql_findings(report)) == 1, report
    assert_checked(report)


def test_setter_input_summary_remains_available_to_its_body() -> None:
    report = scan(
        """import android.app.Activity
        import android.webkit.WebView
        class Screen: Activity() {
            lateinit var web: WebView
            var target: String = ""
                set(value) { field = value; web.loadUrl(value) }
            fun go() { target = intent.getStringExtra("u")!! }
        }"""
    )
    assert (
        len([finding for finding in report["findings"] if finding["rule_id"] == "AST-WEBVIEW-UNTRUSTED-URL"])
        == 1
    ), report
    assert_checked(report)


@pytest.mark.parametrize(
    "body",
    [
        'val query = Intent().getStringExtra("q")',
        'class Outer { object Holder { val query = Intent().getStringExtra("q") } }',
        'class Handler(intent: Intent) { val query by lazy { intent.getStringExtra("q") } }',
    ],
    ids=["top-level", "nested-object", "delegate"],
)
def test_unexecuted_initializer_has_precise_boundary(body: str) -> None:
    report = scan(body)
    metadata = report["metadata"]["native_flow"]
    assert UNAVAILABLE in metadata["precision_reasons"], report
    assert UNAVAILABLE not in metadata["budget_reasons"], report
    details = [item for item in metadata["partial_details"] if item["reason"] == UNAVAILABLE]
    assert details and all(item["path"] == "Construction.kt" and item["line"] for item in details), report


def test_unsupported_owner_plain_constant_stays_checked() -> None:
    report = scan('object Holder { val query: String = "fixed" }')
    assert not sql_findings(report), report
    assert_checked(report)


@pytest.mark.parametrize("source", [True, False], ids=["call-default", "constant-default"])
def test_primary_stored_parameter_default_is_not_assumed_to_run(source: bool) -> None:
    value = 'Intent().getStringExtra("q")' if source else '"fixed"'
    report = scan(f'class Handler(val query: String = {value})\nfun readQuery(): String = "fixed"')
    metadata = report["metadata"]["native_flow"]
    assert (UNAVAILABLE in metadata["precision_reasons"]) is source, report
    assert not metadata["budget_reasons"], report


def test_existing_local_and_anonymous_init_execution_is_preserved() -> None:
    report = scan(
        f"""fun run(intent: Intent, db: SQLiteDatabase) {{
            class Local {{ init {{ db.execSQL("SELECT " + ({INPUT})) }} }}
            val local = Local()
            val anonymous = object {{ init {{ db.execSQL("SELECT " + ({INPUT})) }} }}
        }}"""
    )
    assert len(sql_findings(report)) == 2, report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


def test_custom_accessor_body_remains_analyzed() -> None:
    report = scan(
        """class Handler(private val intent: Intent, private val db: SQLiteDatabase) {
            val query: String
                get() { db.execSQL("SELECT " + (intent.getStringExtra("q") ?: "")); return "fixed" }
        }"""
    )
    assert report["metadata"]["functions"]["analyzed"] == 1, report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("source", [True, False], ids=["intent", "constant"])
def test_custom_accessor_does_not_hide_a_direct_property_rhs(source: bool) -> None:
    value = INPUT if source else '"fixed"'
    report = scan(
        f"""class Handler(intent: Intent, private val db: SQLiteDatabase) {{
            val initialized: Unit = db.execSQL("SELECT " + ({value}))
                get() = field
        }}"""
    )
    assert bool(sql_findings(report)) is source, report
    assert report["metadata"]["functions"]["analyzed"] == 1, report
    assert_checked(report)


@pytest.mark.parametrize("source", [True, False], ids=["intent", "constant"])
def test_unmodeled_getter_read_does_not_borrow_its_backing_initializer(source: bool) -> None:
    value = INPUT if source else '"fixed"'
    report = scan(
        f"""class Handler(intent: Intent, private val db: SQLiteDatabase) {{
            val query: String = {value}
                get() {{ if (field.isEmpty()) return "fixed"; return "fixed" }}
            init {{ db.execSQL("SELECT " + query) }}
            fun run() {{ db.execSQL("SELECT " + query) }}
        }}"""
    )
    assert not sql_findings(report), report
    assert "receiver field inventory unavailable" in report["metadata"]["native_flow"]["precision_reasons"], (
        report
    )
    assert not report["metadata"]["native_flow"]["budget_reasons"], report


@pytest.mark.parametrize("source", [True, False], ids=["intent", "constant"])
def test_foreign_static_snapshot_does_not_hide_later_method_write(source: bool) -> None:
    value = INPUT if source else '"fixed"'
    report = scan(
        f"""object Shared {{ var query: String = "fixed" }}
        class Handler(private val intent: Intent, private val db: SQLiteDatabase) {{
            val marker: String = "fixed"
            init {{ Shared.query = "fixed" }}
            fun fill() {{ Shared.query = {value} }}
            fun run() {{ db.execSQL("SELECT " + Shared.query) }}
        }}"""
    )
    assert bool(sql_findings(report)) is source, report
    assert_checked(report)


def test_local_class_primary_parameter_boundary_is_precise() -> None:
    report = scan(
        f"""fun run(db: SQLiteDatabase) {{
            class Local(intent: Intent) {{
                val query: String = {INPUT}
                init {{ db.execSQL("SELECT " + query) }}
            }}
            Local(Intent())
        }}"""
    )
    metadata = report["metadata"]["native_flow"]
    assert UNAVAILABLE in metadata["precision_reasons"], report
    assert UNAVAILABLE not in metadata["budget_reasons"], report


def test_anonymous_property_capture_keeps_existing_inline_execution() -> None:
    report = scan(
        f"""fun run(intent: Intent, db: SQLiteDatabase) {{
            val objectValue = object {{
                val query: String = {INPUT}
                init {{ db.execSQL("SELECT " + query) }}
            }}
        }}"""
    )
    assert len(sql_findings(report)) == 1, report
    assert UNAVAILABLE not in report["metadata"]["native_flow"]["reasons"], report


def test_inferred_string_property_can_be_a_modeled_receiver() -> None:
    report = scan(
        f"""class Handler(intent: Intent, private val db: SQLiteDatabase) {{
            val query = {INPUT}
            init {{ db.execSQL("SELECT " + query.trim()) }}
            fun run() {{ db.execSQL("SELECT " + query.trim()) }}
        }}"""
    )
    assert len(sql_findings(report)) == 2, report
    assert_checked(report)


def test_initialization_is_not_replayed_for_each_method() -> None:
    report = scan(
        f"""fun pass(value: String): String = value
        class Handler(intent: Intent, private val db: SQLiteDatabase) {{
            val query = pass({INPUT})
            init {{ db.execSQL("SELECT " + query) }}
            fun first() {{}}
            fun second() {{}}
            fun third() {{}}
        }}"""
    )
    assert len(sql_findings(report)) == 1, report
    # One construction pass in each of two rounds, independent of method count.
    assert report["metadata"]["native_flow"]["evaluations"] == 2, report
    assert_checked(report)


def test_initializer_helper_obeys_call_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    import mobile_audit.native_flow as native_flow

    monkeypatch.setattr(native_flow, "MAX_CALL_EVALUATIONS", 0)
    report = scan(
        f"""fun pass(value: String): String = value
        class Handler(intent: Intent, private val db: SQLiteDatabase) {{
            val query: String = pass({INPUT})
            init {{ db.execSQL("SELECT " + query) }}
        }}"""
    )
    assert "recursion or call evaluation budget" in report["metadata"]["native_flow"]["budget_reasons"], (
        report
    )
    assert sql_findings(report), report


def test_initializer_recursion_cut_does_not_invent_a_skipped_function(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mobile_audit.source_analysis import Analyzer

    visit = Analyzer.visit

    def bounded_visit(self, node, frame, guards, conditions):
        if self.function is not None and self.function.type == "property_declaration":
            raise RecursionError("fresh synthetic visitor cut")
        return visit(self, node, frame, guards, conditions)

    monkeypatch.setattr(Analyzer, "visit", bounded_visit)
    report = scan('class Handler { val query = "fixed"; fun run() {} }')
    assert report["metadata"]["functions"] == {
        "observed": 1,
        "analyzed": 1,
        "skipped": 0,
        "without_body": 0,
    }, report
    assert "native flow recursion budget" in report["metadata"]["native_flow"]["budget_reasons"], report
