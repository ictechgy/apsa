"""Fresh explicit Kotlin extension boundaries retain examined-code precision."""

from __future__ import annotations

import pytest

from mobile_audit.native_flow import NativeFlow
from mobile_audit.source_analysis import Analyzer, analyze_sources

SQL = "AST-SQL-CONCAT"
REASON = "Kotlin project extension receiver flow unavailable"
HEADER = (
    "package synthetic.item2\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\n"
)
INPUT = 'intent.getStringExtra("q") ?: ""'


def _state(report: dict) -> str:
    return next(row["state"] for row in report["coverage"] if row["rule_id"] == SQL)


def _native(report: dict) -> dict:
    return report["metadata"]["native_flow"]


def _sql(report: dict) -> list[dict]:
    return [finding for finding in report["findings"] if finding["rule_id"] == SQL]


def _program(member: bool, receiver: str = INPUT) -> str:
    if member:
        return (
            HEADER
            + "class MemberExtension(private val db: SQLiteDatabase) {\n"
            + '    fun String.go() { db.execSQL("SELECT * FROM entries WHERE label = \'" + this + "\'") }\n'
            + f"    fun run(intent: Intent) {{ ({receiver}).go() }}\n"
            + "}\n"
        )
    return (
        HEADER
        + "fun String.go(db: SQLiteDatabase) {\n"
        + '    db.execSQL("SELECT * FROM entries WHERE label = \'" + this + "\'")\n'
        + "}\n"
        + f"fun run(intent: Intent, db: SQLiteDatabase) {{ ({receiver}).go(db) }}\n"
    )


@pytest.mark.parametrize("member", [True, False], ids=["member", "top-level"])
def test_explicit_extension_source_receiver_is_precisely_limited(member: bool) -> None:
    source = _program(member)
    report = analyze_sources([("app/Extension.kt", source)])
    native = _native(report)
    assert _state(report) == "limited", report
    assert not _sql(report)  # no invented execution of the extension's receiver/body
    assert native["budget_reasons"] == []
    assert native["precision_reasons"] == [REASON]
    details = [detail for detail in native["partial_details"] if detail["reason"] == REASON]
    assert details and all(detail["call"] == "go" for detail in details)
    assert {detail["line"] for detail in details} == {
        next(index for index, line in enumerate(source.splitlines(), 1) if ").go(" in line)
    }


@pytest.mark.parametrize("member", [True, False], ids=["member", "top-level"])
def test_constant_extension_receiver_remains_checked(member: bool, monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("an untainted receiver must not trigger extension receiver proof")

    monkeypatch.setattr(NativeFlow, "kotlin_extension_string_receiver", forbidden)
    report = analyze_sources([("app/Extension.kt", _program(member, '"fixed"'))])
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


def test_ordinary_project_call_with_unused_source_argument_remains_checked() -> None:
    report = analyze_sources(
        [
            (
                "app/Ordinary.kt",
                HEADER
                + 'fun unrelated(value: String, db: SQLiteDatabase) { db.execSQL("SELECT 1") }\n'
                + f"fun run(intent: Intent, db: SQLiteDatabase) {{ unrelated({INPUT}, db) }}\n",
            )
        ]
    )
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


@pytest.mark.parametrize(
    ("declaration", "invocation"),
    [
        ('fun String.toString(): String = "fixed"', "toString()"),
        ('fun String.plus(other: Any?): String = "fixed"', 'plus("fixed")'),
    ],
    ids=["toString-member", "plus-member"],
)
def test_modeled_string_member_precedes_same_named_extension(declaration: str, invocation: str) -> None:
    report = analyze_sources(
        [
            (
                "app/Shadow.kt",
                HEADER
                + "class MemberShadow(private val db: SQLiteDatabase) {\n"
                + declaration
                + "\n"
                + f"fun run(intent: Intent) {{ ({INPUT}).{invocation} }}\n"
                + "}\n",
            )
        ]
    )
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert REASON not in _native(report)["reasons"]


def test_import_alias_preserves_visible_extension_identity() -> None:
    report = analyze_sources(
        [
            (
                "app/Caller.kt",
                HEADER.replace(
                    "import android.content.Intent\n", "import android.content.Intent\nimport ext.go as hop\n"
                )
                + f"fun run(intent: Intent, db: SQLiteDatabase) {{ ({INPUT}).hop(db) }}\n",
            ),
            (
                "ext/Extension.kt",
                "package ext\nimport android.database.sqlite.SQLiteDatabase\n"
                + "typealias Selected = String\n"
                + "fun Selected.go(db: SQLiteDatabase) { db.execSQL(this) }\n",
            ),
        ]
    )
    assert _state(report) == "limited", report
    assert REASON in _native(report)["precision_reasons"]
    assert not _sql(report)


def test_explicit_local_string_alias_is_a_receiver_fact() -> None:
    report = analyze_sources(
        [
            (
                "app/Alias.kt",
                HEADER
                + "typealias Text = String\nfun Text.go() {}\n"
                + f"fun run(intent: Intent) {{ val value: Text = {INPUT}; value.go() }}\n",
            )
        ]
    )
    assert _state(report) == "limited", report
    assert REASON in _native(report)["precision_reasons"]


@pytest.mark.parametrize(
    ("declaration", "kind"),
    [("fun Any.go() {}", "Any"), ("fun String?.go() {}", "String?")],
    ids=["stronger-Any-type", "nullable-String"],
)
def test_local_content_does_not_override_stronger_receiver_type(declaration: str, kind: str) -> None:
    report = analyze_sources(
        [
            (
                "app/StrongerType.kt",
                HEADER
                + declaration
                + "\n"
                + f"fun run(intent: Intent) {{ val value: {kind} = {INPUT}; value.go() }}\n",
            )
        ]
    )
    assert REASON not in _native(report)["reasons"], report
    assert not _sql(report)


def test_type_parameter_named_string_is_not_a_standard_string_receiver() -> None:
    report = analyze_sources(
        [
            (
                "app/TypeParameter.kt",
                HEADER
                + "fun <String> String.go() {}\n"
                + "fun <String> consume(value: String) { value.go() }\n"
                + f"fun run(intent: Intent) {{ consume({INPUT}) }}\n",
            )
        ]
    )
    assert REASON not in _native(report)["reasons"], report
    assert not _sql(report)


@pytest.mark.parametrize(
    ("extension", "imports", "invocation"),
    [
        ("fun String.go(db: SQLiteDatabase) { db.execSQL(this) }", "", "go(db)"),
        ("private fun String.go(db: SQLiteDatabase) { db.execSQL(this) }", "import ext.go\n", "go(db)"),
        ("class Unrelated { fun String.go(db: SQLiteDatabase) {} }", "", "go(db)"),
        ("fun String.go() {}", "import ext.go\n", "go(db)"),
        ("fun Int.go(db: SQLiteDatabase) {}", "import ext.go\n", "go(db)"),
        ("fun <T: Number> T.go(db: SQLiteDatabase) {}", "import ext.go\n", "go(db)"),
        ("class String\nfun String.go(db: SQLiteDatabase) {}", "import ext.go\n", "go(db)"),
    ],
    ids=[
        "not-imported",
        "private",
        "unrelated-owner",
        "arity",
        "incompatible",
        "type-bound",
        "source-String",
    ],
)
def test_inapplicable_extension_does_not_create_receiver_precision(
    extension: str, imports: str, invocation: str
) -> None:
    report = analyze_sources(
        [
            (
                "app/Caller.kt",
                HEADER
                + imports
                + f"fun run(intent: Intent, db: SQLiteDatabase) {{ ({INPUT}).{invocation} }}\n",
            ),
            (
                "ext/Extension.kt",
                "package ext\nimport android.database.sqlite.SQLiteDatabase\n" + extension + "\n",
            ),
        ]
    )
    assert REASON not in _native(report)["reasons"], report
    assert _state(report) == "checked", report
    assert not _sql(report)


@pytest.mark.parametrize("receiver", [f"opaque({INPUT})", f"if (flag) {INPUT} else 1"])
def test_unknown_receiver_type_does_not_become_string_from_taint(receiver: str) -> None:
    report = analyze_sources(
        [
            (
                "app/Unknown.kt",
                HEADER
                + "fun opaque(value: Any?): Any? = value\nfun String.go() {}\n"
                + f"fun run(intent: Intent, flag: Boolean) {{ ({receiver}).go() }}\n",
            )
        ]
    )
    assert REASON not in _native(report)["reasons"], report
    assert not _sql(report)


def test_receiver_boundary_queries_do_not_evaluate_or_change_attribution_ledgers(monkeypatch) -> None:
    original = NativeFlow.call
    seen = []

    def observe(flow, analyzer, call, frame, receiver, args):
        if analyzer.scope != "run" or call.name != "go":
            return original(flow, analyzer, call, frame, receiver, args)
        assert receiver.traces
        before = (
            flow.evaluations,
            flow.partial_events,
            repr(flow.reasons),
            repr(flow.partial_details),
            repr(frame),
            repr(analyzer.visited_values),
            analyzer.builder_label_queries,
            analyzer.builder_label_candidates,
            analyzer.builder_label_query_active,
            analyzer.type_query_active,
        )
        modes = [(1, 0, False, False), (0, 1, False, False), (0, 0, True, False), (0, 0, False, True)]
        for muted, hint, query, attribution in modes:
            saved = (
                flow.muted,
                flow.type_hint_depth,
                analyzer.type_query_active,
                analyzer.builder_label_query_active,
            )
            flow.muted, flow.type_hint_depth = muted, hint
            analyzer.type_query_active, analyzer.builder_label_query_active = query, attribution
            try:
                assert not flow.kotlin_extension_receiver_unavailable(analyzer, call, receiver, frame)
                assert flow.muted == muted and flow.type_hint_depth == hint
                assert (
                    analyzer.type_query_active == query and analyzer.builder_label_query_active == attribution
                )
            finally:
                (
                    flow.muted,
                    flow.type_hint_depth,
                    analyzer.type_query_active,
                    analyzer.builder_label_query_active,
                ) = saved

        def forbidden(*args, **kwargs):
            pytest.fail("receiver/type proof must not evaluate expressions or source bodies")

        with monkeypatch.context() as pure:
            pure.setattr(Analyzer, "value", forbidden)
            pure.setattr(Analyzer, "visit", forbidden)
            pure.setattr(Analyzer, "known_value_type", forbidden)
            pure.setattr(NativeFlow, "call", forbidden)
            assert flow.kotlin_extension_receiver_unavailable(analyzer, call, receiver, frame)
        assert before == (
            flow.evaluations,
            flow.partial_events,
            repr(flow.reasons),
            repr(flow.partial_details),
            repr(frame),
            repr(analyzer.visited_values),
            analyzer.builder_label_queries,
            analyzer.builder_label_candidates,
            analyzer.builder_label_query_active,
            analyzer.type_query_active,
        )
        seen.append(True)
        return original(flow, analyzer, call, frame, receiver, args)

    monkeypatch.setattr(NativeFlow, "call", observe)
    analyze_sources([("app/Extension.kt", _program(False))])
    assert seen


def test_receiver_boundary_restores_query_modes_after_proof_failure(monkeypatch) -> None:
    original = NativeFlow.call
    seen = []

    def observe(flow, analyzer, call, frame, receiver, args):
        if analyzer.scope == "run" and call.name == "go":
            before = flow.muted, flow.type_hint_depth, analyzer.type_query_active

            def unavailable(*args, **kwargs):
                raise RuntimeError("fresh synthetic receiver proof failure")

            with monkeypatch.context() as failing:
                failing.setattr(Analyzer, "project_extension", unavailable)
                with pytest.raises(RuntimeError, match="fresh synthetic"):
                    flow.kotlin_extension_receiver_unavailable(analyzer, call, receiver, frame)
            assert before == (flow.muted, flow.type_hint_depth, analyzer.type_query_active)
            seen.append(True)
        return original(flow, analyzer, call, frame, receiver, args)

    monkeypatch.setattr(NativeFlow, "call", observe)
    analyze_sources([("app/Extension.kt", _program(False))])
    assert seen
