"""Fresh synthetic construction-flow fixtures; no application data is read."""

from __future__ import annotations

import textwrap

import pytest

from mobile_audit.source_analysis import analyze_sources

SQL = "AST-SQL-CONCAT"
UNAVAILABLE = "Kotlin stored property initializer flow unavailable"
DEFAULT_UNAVAILABLE = "Kotlin constructor default argument flow unavailable"
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


def assert_default_boundary(report: dict, line: int, extra_precision: tuple[str, ...] = ()) -> None:
    metadata = report["metadata"]["native_flow"]
    assert set(metadata["precision_reasons"]) == {DEFAULT_UNAVAILABLE, *extra_precision}, report
    assert not metadata["budget_reasons"], report
    assert not sql_findings(report), report
    details = [item for item in metadata["partial_details"] if item["reason"] == DEFAULT_UNAVAILABLE]
    assert len(details) == 1, report
    assert details[0]["reason"] == DEFAULT_UNAVAILABLE, report
    assert details[0]["kind"] == "precision", report
    assert details[0]["path"] == "Construction.kt" and details[0]["line"] == line, report
    assert details[0]["column"] > 0, report


@pytest.mark.parametrize("receiver", ["Intent()", "externalIntent"], ids=["direct", "parameter"])
@pytest.mark.parametrize("consumer", ["property", "init", "method"])
def test_nonstored_source_default_marks_its_conditional_construction_boundary(
    receiver: str, consumer: str
) -> None:
    statements = {
        "property": 'val initialized: Unit = db.execSQL("SELECT " + stored)',
        "init": 'init { db.execSQL("SELECT " + stored) }',
        "method": 'fun run() { db.execSQL("SELECT " + this.stored) }',
    }
    report = scan(
        f"""class Handler(
            externalIntent: Intent,
            private val db: SQLiteDatabase,
            query: String =
                {receiver}.getStringExtra("q") ?: ""
        ) {{
            val stored: String = query
            {statements[consumer]}
        }}"""
    )
    # The source default is conditional, so neither construction nor the later
    # stored-property read may acquire an unconditional source finding.
    assert_default_boundary(report, 7)


@pytest.mark.parametrize("source", [True, False], ids=["source-sql", "constant-sql"])
def test_nonstored_sink_default_has_boundary_without_executing_its_side_effect(source: bool) -> None:
    value = 'externalIntent.getStringExtra("q") ?: ""' if source else '"fixed"'
    report = scan(
        f"""class Handler(
            externalIntent: Intent,
            db: SQLiteDatabase,
            ignored: Unit =
                db.execSQL("SELECT " + ({value}))
        )"""
    )
    assert_default_boundary(report, 7)
    assert report["metadata"]["functions"]["observed"] == 0, report


@pytest.mark.parametrize("value", ['"fixed"', "readQuery()"], ids=["constant", "unrelated-call"])
def test_nonstored_constant_or_unrelated_default_stays_checked(value: str) -> None:
    report = scan(
        f"""fun readQuery(): String = "fixed"
        class Handler(private val db: SQLiteDatabase, query: String = {value}) {{
            val stored: String = query
            init {{ db.execSQL("SELECT " + stored) }}
            fun run() {{ db.execSQL("SELECT " + this.stored) }}
        }}"""
    )
    assert not sql_findings(report), report
    assert_checked(report)


@pytest.mark.parametrize(
    ("helper", "parameters", "value"),
    [
        ('fun getStringExtra(): String = "fixed"', "", "getStringExtra()"),
        (
            'class Other { fun getStringExtra(key: String): String = "fixed" }',
            "other: Other, ",
            'other.getStringExtra("q")',
        ),
        (
            "class Other { fun execSQL(query: String): Unit {} }",
            "other: Other, ",
            'other.execSQL("fixed")',
        ),
    ],
    ids=["ordinary-function", "ordinary-source-named-member", "ordinary-sink-named-member"],
)
def test_nonstored_default_api_lookalikes_with_inert_bodies_stay_checked(
    helper: str, parameters: str, value: str
) -> None:
    report = scan(f"{helper}\nclass Handler({parameters}ignored: Any = {value})")
    assert not sql_findings(report), report
    assert_checked(report)


@pytest.mark.parametrize(
    ("helper", "parameters", "value"),
    [
        (
            'fun getStringExtra(intent: Intent): String = intent.getStringExtra("q") ?: ""',
            "intent: Intent, ",
            "getStringExtra(intent)",
        ),
        (
            'class Other { fun execSQL(db: SQLiteDatabase): String { db.execSQL("SELECT 1"); '
            'return "fixed" } }',
            "other: Other, db: SQLiteDatabase, ",
            "other.execSQL(db)",
        ),
        (
            'fun getStringExtra(query: String = Intent().getStringExtra("q") ?: ""): String = "fixed"',
            "",
            "getStringExtra()",
        ),
        (
            'class Other { fun execSQL(db: SQLiteDatabase, ignored: Unit = db.execSQL("SELECT 1"))'
            ': String = "fixed" }',
            "other: Other, db: SQLiteDatabase, ",
            "other.execSQL(db)",
        ),
        (
            'fun readQuery(db: SQLiteDatabase): String { db.execSQL("SELECT 1"); return "fixed" }\n'
            'fun getStringExtra(key: String): String = "fixed"',
            "db: SQLiteDatabase, ",
            "getStringExtra(readQuery(db))",
        ),
    ],
    ids=["source-result", "sink-before-constant-return", "source-default", "sink-default", "argument-effect"],
)
def test_nonstored_default_project_helpers_with_possible_effects_keep_the_boundary(
    helper: str, parameters: str, value: str
) -> None:
    report = scan(f"{helper}\nclass Handler({parameters}ignored: Any = {value})")
    assert_default_boundary(report, 3 + helper.count("\n") + 1)


@pytest.mark.parametrize(
    ("helper", "parameters", "value"),
    [
        (
            'open class Other { open fun getStringExtra(key: String): String = "fixed" }',
            "other: Other, ",
            'other.getStringExtra("q")',
        ),
        ("import external.Other", "other: Other, ", 'other.getStringExtra("q")'),
        (
            'fun getStringExtra(): String = "fixed"',
            "getStringExtra: () -> String, ",
            "getStringExtra()",
        ),
        (
            "class Other(val getStringExtra: (String) -> String) { "
            'fun getStringExtra(key: Int): String = "fixed" }',
            "other: Other, ",
            'other.getStringExtra("q")',
        ),
    ],
    ids=["open-member", "unknown-imported-receiver", "callable-parameter-shadow", "callable-member-shadow"],
)
def test_nonstored_default_uncertain_api_lookalikes_keep_the_boundary(
    helper: str, parameters: str, value: str
) -> None:
    report = scan(f"{helper}\nclass Handler({parameters}ignored: Any = {value})")
    assert_default_boundary(report, 4)


@pytest.mark.parametrize("shadow", ["nested-type", "when-binding", "companion-member"])
def test_nonstored_default_nearer_binding_cannot_borrow_an_inert_lookalike(shadow: str) -> None:
    helper = 'class Other { fun getStringExtra(key: String): String = "fixed" }'
    if shadow == "nested-type":
        body = """class Handler(other: Other, query: String = other.getStringExtra("q")) {
            class Other { fun getStringExtra(key: String): String = Intent().getStringExtra(key) ?: "" }
        }"""
    elif shadow == "when-binding":
        body = """class Handler(other: Other, query: String = when (val other = Intent()) {
            else -> other.getStringExtra("q")
        })"""
    else:
        helper = 'fun getStringExtra(): String = "fixed"'
        body = """class Handler(query: String = getStringExtra()) {
            companion object { fun getStringExtra(): String = Intent().getStringExtra("q") ?: "" }
        }"""
    report = scan(f"{helper}\n{body}")
    extra = ("nominal callable scope unavailable",) if shadow == "companion-member" else ()
    assert_default_boundary(report, 4, extra)


def test_stored_default_api_lookalike_retains_its_existing_boundary_and_location() -> None:
    report = scan(
        'fun getStringExtra(): String = "fixed"\nclass Handler(val query: String = getStringExtra())'
    )
    metadata = report["metadata"]["native_flow"]
    assert metadata["precision_reasons"] == [UNAVAILABLE], report
    assert DEFAULT_UNAVAILABLE not in metadata["reasons"], report
    details = metadata["partial_details"]
    assert len(details) == 1 and details[0]["reason"] == UNAVAILABLE, report
    assert details[0]["line"] == 4 and details[0]["column"] == 15, report
    assert not sql_findings(report), report


def test_explicit_argument_does_not_execute_default_or_publish_nonstored_parameter() -> None:
    report = scan(
        """class Handler(
            externalIntent: Intent,
            private val db: SQLiteDatabase,
            query: String =
                externalIntent.getStringExtra("q") ?: ""
        ) {
            val query: String = "fixed"
            fun run() { db.execSQL("SELECT " + this.query) }
        }
        fun construct(intent: Intent, db: SQLiteDatabase): Handler =
            Handler(intent, db, query = "fixed")"""
    )
    # The model reports declarations without constructor-call specialization:
    # this explicit argument does not discharge the unused default boundary or
    # the existing constructor-to-field mapping boundary.
    assert_default_boundary(report, 7, ("constructor field mapping unavailable",))


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


@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reversed"])
def test_nonstored_default_empty_package_overload_keeps_identity_unavailable(reverse: bool) -> None:
    sources = [
        (
            "Construction.kt",
            IMPORTS + 'fun getStringExtra(value: Any): String = "fixed"\n'
            'class Handler(private val db: SQLiteDatabase, query: String = getStringExtra("constant")) {\n'
            '    init { db.execSQL("SELECT " + query) }\n'
            "}",
        ),
        (
            "Other.kt",
            "import android.content.Intent\n"
            'fun getStringExtra(value: String): String = Intent().getStringExtra("q") ?: ""',
        ),
    ]
    report = analyze_sources(list(reversed(sources)) if reverse else sources)
    # The second default-package file is visible, and its more specific overload
    # can be selected. The default remains conditional; no body is executed.
    assert_default_boundary(report, 4)


def test_nonstored_default_unique_same_file_literal_argument_stays_checked() -> None:
    report = scan(
        """fun getStringExtra(value: Any): String = "fixed"
        class Handler(private val db: SQLiteDatabase, query: String = getStringExtra("constant")) {
            init { db.execSQL("SELECT " + query) }
        }"""
    )
    assert not sql_findings(report), report
    assert_checked(report)


@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reversed"])
@pytest.mark.parametrize("package", ["", "sample"])
@pytest.mark.parametrize("rival", ["class", "alias", "object", "property"])
def test_nonstored_default_peer_nonfunction_keeps_identity_unavailable(
    rival: str, package: str, reverse: bool
) -> None:
    prefix = f"package {package}\n" if package else ""
    source = 'Intent().getStringExtra(key) ?: ""'
    rivals = {
        "class": f"class getStringExtra(key: String) {{ val query = {source} }}",
        "alias": f"class SourceValue(key: String) {{ val query = {source} }}\n"
        "typealias getStringExtra = SourceValue",
        "object": f"object getStringExtra {{ operator fun invoke(key: String): String = {source} }}",
        "property": f"val getStringExtra: (String) -> String = {{ key -> {source} }}",
    }
    files = [
        (
            "Construction.kt",
            prefix + IMPORTS + 'fun getStringExtra(key: Int): String = "fixed"\n'
            'class Handler(ignored: Any = getStringExtra("q"))',
        ),
        ("Other.kt", prefix + "import android.content.Intent\n" + rivals[rival]),
    ]
    report = analyze_sources(list(reversed(files)) if reverse else files)
    assert_default_boundary(report, 4 + bool(package), (UNAVAILABLE,) if rival == "property" else ())


@pytest.mark.parametrize("rival", ["class", "alias", "object", "property"])
def test_nonstored_default_other_package_nonfunction_does_not_shadow_inert_helper(rival: str) -> None:
    declarations = {
        "class": "class getStringExtra(key: String)",
        "alias": "class SourceValue(key: String)\ntypealias getStringExtra = SourceValue",
        "object": 'object getStringExtra { operator fun invoke(key: String): String = "fixed" }',
        "property": 'val getStringExtra: (String) -> String = { "fixed" }',
    }
    files = [
        (
            "Construction.kt",
            IMPORTS + 'fun getStringExtra(key: String): String = "fixed"\n'
            'class Handler(ignored: Any = getStringExtra("q"))',
        ),
        ("Other.kt", "package separate\n" + declarations[rival]),
    ]
    report = analyze_sources(files)
    assert not sql_findings(report), report
    assert_checked(report)


@pytest.mark.parametrize("peer", [False, True], ids=["same-file", "peer-file"])
def test_nonstored_default_inapplicable_member_cannot_borrow_inert_body(peer: bool) -> None:
    extension = 'fun Other.getStringExtra(key: String): String = Intent().getStringExtra(key) ?: ""'
    helper = 'class Other { fun getStringExtra(key: Int): String = "fixed" }\n'
    body = 'class Handler(other: Other, ignored: Any = other.getStringExtra("q"))'
    main = IMPORTS + helper + ("" if peer else extension + "\n") + body
    files = [("Construction.kt", main)]
    if peer:
        files.append(("Other.kt", "import android.content.Intent\n" + extension))
    report = analyze_sources(files)
    assert_default_boundary(report, 4 if peer else 5)


@pytest.mark.parametrize("peer", [False, True], ids=["same-file", "peer-file"])
def test_nonstored_default_callable_extension_property_keeps_member_identity_unavailable(
    peer: bool,
) -> None:
    extension = (
        'val Other.getStringExtra: (String) -> String get() = { key -> Intent().getStringExtra(key) ?: "" }'
    )
    helper = 'class Other { fun getStringExtra(key: Int): String = "fixed" }\n'
    main = (
        IMPORTS
        + helper
        + ("" if peer else extension + "\n")
        + 'class Handler(other: Other, ignored: Any = other.getStringExtra("q"))'
    )
    files = [("Construction.kt", main)]
    if peer:
        files.append(("Other.kt", "import android.content.Intent\n" + extension))
    report = analyze_sources(files)
    assert_default_boundary(report, 4 if peer else 5)
