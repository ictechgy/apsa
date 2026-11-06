"""Fresh explicit Kotlin extension boundaries retain examined-code precision."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from mobile_audit.native_flow import NativeFlow
from mobile_audit.source_analysis import Analyzer, Frame, analyze_sources

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


def _position(source: str, expression: str) -> tuple[int, int, int]:
    offset = source.index(expression)
    return source.count("\n", 0, offset) + 1, offset - source.rfind("\n", 0, offset), offset


def _actual_receiver_sources(monkeypatch, path: str, source: str) -> tuple[dict, set[tuple]]:
    """Observe provenance on actual visits; no fabricated analyzer/frame facts."""
    original = NativeFlow.call
    origins = set()

    def observe(flow, analyzer, call, frame, receiver, args):
        if analyzer.path == path and call.name == "go":
            for trace in receiver.traces:
                point = analyzer.location(trace.source)
                origins.add((point["path"], point["line"], point["column"], point["offset"]))
        return original(flow, analyzer, call, frame, receiver, args)

    monkeypatch.setattr(NativeFlow, "call", observe)
    return analyze_sources([(path, source)]), origins


def _assert_exact_boundary(
    report: dict, path: str, source: str, invocation: str, *, other_reasons: tuple[str, ...] = ()
) -> None:
    native = _native(report)
    assert _state(report) == "limited", report
    assert not _sql(report), report
    assert native["state"] == "partial"  # metadata summarizes all native limits
    assert native["reasons"] == native["precision_reasons"] == sorted([REASON, *other_reasons])
    assert native["budget_reasons"] == []
    assert not native["partial_details_truncated"]
    details = [detail for detail in native["partial_details"] if detail["reason"] == REASON]
    assert len(details) == 1
    detail = details[0]
    line, column, _offset = _position(source, invocation)
    assert {key: detail[key] for key in ("reason", "kind", "path", "line", "column", "call")} == {
        "reason": REASON,
        "kind": "precision",
        "path": path,
        "line": line,
        "column": column,
        "call": "go",
    }
    assert detail["scope"] == "file-call"
    assert SQL in detail["rule_ids"]


def _stored_program(
    receiver: str,
    *,
    initializer: bool,
    declared: str = "String",
    value: str = INPUT,
    extension: str = "String",
    extra: str = "",
    local: str = "",
    safe: bool = False,
) -> tuple[str, str]:
    invocation = receiver + ("?." if safe else ".") + "go(db)"
    context = "init" if initializer else "fun run()"
    source = (
        HEADER
        + extra
        + f'fun {extension}.go(db: SQLiteDatabase) {{ db.execSQL("SELECT " + this) }}\n'
        + "class StoredReceiver(intent: Intent, val db: SQLiteDatabase) {\n"
        + f"    val q: {declared} = {value}\n"
        + f"    {context} {{ {local}{invocation} }}\n"
        + "}\n"
    )
    return source, invocation


@pytest.mark.parametrize("receiver", ["q", "this.q"])
@pytest.mark.parametrize("initializer", [False, True], ids=["method", "init"])
@pytest.mark.parametrize("declared", ["String", "Text"], ids=["explicit", "alias"])
def test_stored_source_string_extension_has_exact_boundary(
    receiver: str, initializer: bool, declared: str, monkeypatch
) -> None:
    source, invocation = _stored_program(
        receiver,
        initializer=initializer,
        declared=declared,
        extra="typealias Text = String\n" if declared == "Text" else "",
    )
    path = "app/StoredReceiver.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    other_reasons = (
        (
            "unresolved callable identity or argument signature",
            *(("object alias identity unavailable",) if initializer else ()),
        )
        if declared == "Text"
        else ()
    )
    _assert_exact_boundary(report, path, source, invocation, other_reasons=other_reasons)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}


@pytest.mark.parametrize("receiver", ["q", "this.q"])
@pytest.mark.parametrize("initializer", [False, True], ids=["method", "init"])
def test_stored_nullable_source_safe_call_has_exact_boundary(
    receiver: str, initializer: bool, monkeypatch
) -> None:
    source, invocation = _stored_program(
        receiver,
        initializer=initializer,
        declared="String?",
        value='intent.getStringExtra("q")',
        safe=True,
    )
    path = "app/StoredNullable.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    _assert_exact_boundary(report, path, source, invocation)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}


@pytest.mark.parametrize("local", [False, True], ids=["direct", "local"])
def test_nullable_source_safe_call_has_exact_boundary(local: bool, monkeypatch) -> None:
    receiver = "q" if local else 'intent.getStringExtra("q")'
    invocation = receiver + "?.go(db)"
    source = (
        HEADER
        + 'fun String.go(db: SQLiteDatabase) { db.execSQL("SELECT " + this) }\n'
        + "fun run(intent: Intent, db: SQLiteDatabase) {\n"
        + ('    val q: String? = intent.getStringExtra("q")\n' if local else "")
        + f"    {invocation}\n"
        + "}\n"
    )
    path = "app/SafeReceiver.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    _assert_exact_boundary(report, path, source, invocation)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}


@pytest.mark.parametrize("receiver", ["q", "this.q"])
@pytest.mark.parametrize("initializer", [False, True], ids=["method", "init"])
def test_stored_constant_receiver_remains_checked(receiver: str, initializer: bool) -> None:
    source, _invocation = _stored_program(receiver, initializer=initializer, value='"fixed"')
    report = analyze_sources([("app/StoredConstant.kt", source)])
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


@pytest.mark.parametrize("local", [False, True], ids=["direct", "local"])
def test_constant_nullable_safe_call_remains_checked(local: bool) -> None:
    expression = "q" if local else '("fixed" as String?)'
    source = (
        HEADER
        + 'fun String.go(db: SQLiteDatabase) { db.execSQL("SELECT " + this) }\n'
        + "fun run(db: SQLiteDatabase) {\n"
        + ('    val q: String? = "fixed"\n' if local else "")
        + f"    {expression}?.go(db)\n"
        + "}\n"
    )
    report = analyze_sources([("app/SafeConstant.kt", source)])
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


@pytest.mark.parametrize("receiver", ["q", "this.q"])
@pytest.mark.parametrize(
    ("declared", "extension", "safe"),
    [("Any", "Any", False), ("Any?", "Any?", True), ("String?", "String?", False)],
    ids=["stronger-Any", "stronger-nullable-Any", "nullable-without-safe-call"],
)
def test_stored_receiver_content_does_not_override_declared_type(
    receiver: str, declared: str, extension: str, safe: bool, monkeypatch
) -> None:
    source, _invocation = _stored_program(
        receiver, initializer=False, declared=declared, extension=extension, safe=safe
    )
    path = "app/StoredStrongerType.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


def test_local_any_shadow_precedes_same_named_stored_string(monkeypatch) -> None:
    source, _invocation = _stored_program(
        "q",
        initializer=False,
        extension="Any",
        local="val q: Any = q; ",
    )
    path = "app/LocalShadow.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


def test_explicit_this_field_retains_ownership_despite_local_any_shadow(monkeypatch) -> None:
    source, invocation = _stored_program("this.q", initializer=False, local='val q: Any = "fixed"; ')
    path = "app/ExplicitField.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    _assert_exact_boundary(
        report, path, source, invocation, other_reasons=("object alias identity unavailable",)
    )
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}


@pytest.mark.parametrize("receiver", ["q", "this.q"])
def test_default_getter_with_custom_setter_retains_extension_boundary(receiver: str, monkeypatch) -> None:
    source, invocation = _stored_program(receiver, initializer=False)
    source = source.replace("val q: String", "var q: String").replace(
        "    fun run()", "        set(value) { field = value }\n    fun run()"
    )
    path = "app/SetterOnly.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    _assert_exact_boundary(
        report, path, source, invocation, other_reasons=("receiver field inventory unavailable",)
    )
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}


@pytest.mark.parametrize("access", ["get() = raw", "by lazy { raw }"], ids=["getter", "delegate"])
def test_custom_property_read_does_not_supply_stored_receiver_proof(access: str, monkeypatch) -> None:
    source = (
        HEADER
        + 'fun String.go(db: SQLiteDatabase) { db.execSQL("SELECT " + this) }\n'
        + "class CustomRead(intent: Intent, val db: SQLiteDatabase) {\n"
        + f"    val raw: String = {INPUT}\n"
        + f"    val q: String {access}\n"
        + "    fun run() { q.go(db) }\n"
        + "}\n"
    )
    path = "app/CustomRead.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}
    assert _state(report) == "limited", report
    assert not _sql(report)
    native = _native(report)
    assert native["reasons"] == native["precision_reasons"] == ["receiver field inventory unavailable"]
    assert native["budget_reasons"] == []
    line, column, _offset = _position(source, "q.go(db)")
    assert [
        (detail["path"], detail["line"], detail["column"], detail["call"])
        for detail in native["partial_details"]
    ] == [(path, line, column, None)]


def test_alias_of_this_does_not_expand_extension_field_proof_to_general_instances(monkeypatch) -> None:
    source, _invocation = _stored_program(
        "other.q", initializer=False, local="val other: StoredReceiver = this; "
    )
    path = "app/AliasedOwner.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


def test_unrelated_nominal_string_field_does_not_override_owned_any_field(monkeypatch) -> None:
    source, _invocation = _stored_program(
        "q",
        initializer=False,
        declared="Any",
        extension="Any",
        extra='class Unrelated { val q: String = "fixed" }\n',
    )
    path = "app/UnrelatedField.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


def test_source_nominal_named_string_does_not_gain_standard_field_receiver_identity(monkeypatch) -> None:
    source, _invocation = _stored_program(
        "q",
        initializer=False,
        value=f"String({INPUT})",
        extra="class String(val raw: kotlin.String)\n",
    )
    path = "app/ShadowedString.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}
    assert _state(report) == "limited", report
    assert not _sql(report)
    assert _native(report)["reasons"] == [
        "constructor field mapping unavailable",
        "reachable field ownership unavailable",
        "source trace abstention",
        "unresolved callable identity or argument signature",
    ]
    assert _native(report)["budget_reasons"] == []


@pytest.mark.parametrize(
    ("receiver", "context"),
    [
        pytest.param("q", "direct", id="q"),
        pytest.param("this.q", "direct", id="this.q"),
        *[
            pytest.param(receiver, context, id=f"{context}-{receiver}")
            for context in (
                "let",
                "forEach",
                "nested",
                "also",
                "takeIf",
                "takeUnless",
                "let-nested",
                "forEach-parameter",
                "forEach-string",
            )
            for receiver in ("q", "this.q")
        ],
    ],
)
def test_stored_boundary_proof_is_pure_during_actual_source_call(
    receiver: str, context: str, monkeypatch
) -> None:
    source, invocation = _stored_program(receiver, initializer=False, declared="String?", safe=True)
    if context != "direct":
        if context in {"forEach-parameter", "forEach-string"}:
            parameter = "items: List<String>" if context == "forEach-parameter" else "items: String"
            source = source.replace("fun run()", f"fun run({parameter})")
        subject = (
            "listOf(q).forEach"
            if context == "forEach"
            else "items.forEach"
            if context.startswith("forEach-")
            else "q." + context
        )
        callback = invocation + ("; true" if context in {"takeIf", "takeUnless"} else "")
        body = (
            f"fun nested() {{ {invocation} }}; nested()"
            if context == "nested"
            else f"q.let {{ fun nested() {{ {invocation} }}; nested() }}"
            if context == "let-nested"
            else f"{subject} {{ {callback} }}"
        )
        source = source.replace(invocation, body)
    path = "app/PureStoredProof.kt"
    original = NativeFlow.call
    seen = []

    def observe(flow, analyzer, call, frame, value, args):
        if analyzer.path == path and call.name == "go" and value.traces:

            def snapshot():
                return (
                    {("flow", name): repr(item) for name, item in vars(flow).items()}
                    | {
                        (source.path, name): repr(item)
                        for source, _root, _nodes in flow.files
                        for name, item in vars(source).items()
                    }
                    | {("frame", "state"): repr(frame)}
                )

            def forbidden(*args, **kwargs):
                pytest.fail("stored receiver proof must read declarations and retained facts only")

            with monkeypatch.context() as pure:
                pure.setattr(Analyzer, "value", forbidden)
                pure.setattr(Analyzer, "visit", forbidden)
                pure.setattr(Analyzer, "known_value_type", forbidden)
                pure.setattr(NativeFlow, "call", forbidden)
                pure.setattr(Frame, "__init__", forbidden)
                # The complete boundary query consumes the state retained at
                # this real source call, including every persistent cache.
                for _ in range(2):
                    before = snapshot()
                    assert flow.kotlin_extension_receiver_unavailable(analyzer, call, value, frame)
                    after = snapshot()
                    changed = {
                        key for key in before.keys() | after.keys() if before.get(key) != after.get(key)
                    }
                    assert not changed, ("actual-source-state", sorted(changed))

                # Independently exercise the new nominal-owner proof with
                # warm and cold syntax indexes; missing entries stay local.
                nominal = flow.enclosing_scope(analyzer.function)
                assert nominal is not None and nominal.kind == "nominal"
                for temperature in ("warm", "cold"):
                    if temperature == "cold":
                        for name, cache in vars(flow).items():
                            if name.endswith("_cache") or name == "import_indexes":
                                cache.clear()
                        analyzer.class_context_cache.clear()
                    for _ in range(2):
                        before = snapshot()
                        assert flow.kotlin_extension_nominal_receiver(
                            analyzer, call.receiver, nominal.node, frame
                        )
                        after = snapshot()
                        changed = {
                            key for key in before.keys() | after.keys() if before.get(key) != after.get(key)
                        }
                        assert not changed, (temperature, sorted(changed))

                # A bounded lookup abstains without recording precision or
                # creating syntax entries, even when no owner can be reached.
                scope = None
                for index in range(65):
                    scope = SimpleNamespace(id=-(index + 1), type="unknown", parent=scope)
                before = snapshot()
                assert (
                    analyzer.reference_binding(call.node, "missing", scope=scope, frame=frame, cache=False)
                    is None
                )
                assert not flow.kotlin_extension_nominal_receiver(analyzer, scope, nominal.node, frame)
                assert snapshot() == before
            seen.append(True)
        return original(flow, analyzer, call, frame, value, args)

    monkeypatch.setattr(NativeFlow, "call", observe)
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    assert seen
    _assert_exact_boundary(
        report,
        path,
        source,
        invocation,
        other_reasons=("unresolved callable identity",)
        if context == "forEach"
        else (
            ("aggregate reference ownership unavailable", "unresolved reference argument effects")
            if context == "forEach-parameter"
            else ()
        ),
    )
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}


def _asserted_receiver_program(
    binding: str,
    *,
    declared: str = "String?",
    value: str = 'intent.getStringExtra("q")',
    extension: str = "String",
) -> tuple[str, str]:
    if binding != "local":
        return _stored_program(
            "this.q!!" if binding.startswith("explicit-stored") else "q!!",
            initializer=binding.endswith("-init"),
            declared=declared,
            value=value,
            extension=extension,
        )
    invocation = "q!!.go(db)"
    return (
        HEADER
        + f'fun {extension}.go(db: SQLiteDatabase) {{ db.execSQL("SELECT " + this) }}\n'
        + "fun run(intent: Intent, db: SQLiteDatabase) {\n"
        + f"    val q: {declared} = {value}\n"
        + f"    {invocation}\n"
        + "}\n",
        invocation,
    )


@pytest.mark.parametrize(
    "binding", ["stored", "explicit-stored", "stored-init", "explicit-stored-init", "local"]
)
def test_nullable_asserted_source_receiver_has_exact_boundary(binding: str, monkeypatch) -> None:
    source, invocation = _asserted_receiver_program(binding)
    path = "app/AssertedSource.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    _assert_exact_boundary(report, path, source, invocation)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}


@pytest.mark.parametrize("binding", ["stored", "explicit-stored", "local"])
def test_constant_nullable_assertion_remains_checked(binding: str, monkeypatch) -> None:
    source, _invocation = _asserted_receiver_program(binding, value='"fixed"')
    report, origins = _actual_receiver_sources(monkeypatch, "app/AssertedConstant.kt", source)
    assert not origins
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


@pytest.mark.parametrize("binding", ["stored", "explicit-stored", "local"])
def test_nullable_assertion_does_not_override_stronger_any_receiver(binding: str, monkeypatch) -> None:
    source, _invocation = _asserted_receiver_program(binding, declared="Any?", extension="Any")
    path = "app/AssertedAny.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


@pytest.mark.parametrize(
    ("body", "invocation", "nullable"),
    [
        ("q.let { q.go(db) }", "q.go(db)", False),
        ("q.let { this.q.go(db) }", "this.q.go(db)", False),
        ("q.also { q.go(db) }", "q.go(db)", False),
        ("listOf(q).forEach { q.go(db) }", "q.go(db)", False),
        ("q.let { q?.go(db) }", "q?.go(db)", True),
        ("q.let { q!!.go(db) }", "q!!.go(db)", True),
        ("fun nested() { this.q.go(db) }; nested()", "this.q.go(db)", False),
        ("q.let { fun nested() { this.q.go(db) }; nested() }", "this.q.go(db)", False),
    ],
    ids=["let", "let-this", "also", "forEach", "safe", "asserted", "nested", "let-nested"],
)
def test_nonreceiver_capture_retains_stored_string_boundary(
    body: str, invocation: str, nullable: bool, monkeypatch
) -> None:
    source, original = _stored_program("q", initializer=False, declared="String?" if nullable else "String")
    source = source.replace(original, body)
    path = "app/StoredCapture.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    _assert_exact_boundary(
        report,
        path,
        source,
        invocation,
        other_reasons=("unresolved callable identity",) if ".forEach" in body else (),
    )
    assert origins == {(path, *_position(source, 'intent.getStringExtra("q")'))}


@pytest.mark.parametrize("body", ["q.let { q.go(db) }", "listOf(q).forEach { q.go(db) }"])
def test_constant_nonreceiver_capture_remains_checked(body: str, monkeypatch) -> None:
    source, original = _stored_program("q", initializer=False, value='"fixed"')
    source = source.replace(original, body)
    report, origins = _actual_receiver_sources(monkeypatch, "app/ConstantCapture.kt", source)
    assert not origins
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []


@pytest.mark.parametrize("receiver", ["q", "this.q"])
@pytest.mark.parametrize("context", ["extension", "property", "run", "callback", "shadowed-let"])
def test_nearer_receiver_through_local_function_does_not_borrow_stored_string(
    receiver: str, context: str, monkeypatch
) -> None:
    nested = f"fun nested() {{ {receiver}.go(db) }}; nested()"
    declarations = ""
    if context == "extension":
        member = f"fun Other.run() {{ {nested} }}"
    elif context == "property":
        member = f"val Other.foo: Unit\n        get() {{ {nested} }}"
    elif context == "run":
        member = f'fun run() {{ Other("fixed").run {{ {nested} }} }}'
    elif context == "callback":
        declarations = 'fun capture(block: Other.() -> Unit) { Other("fixed").block() }\n'
        member = f"fun run() {{ capture {{ {nested} }} }}"
    else:
        declarations = 'fun String.let(block: Other.() -> Unit) { Other("fixed").block() }\n'
        member = f"fun run() {{ q.let {{ {nested} }} }}"
    source = (
        HEADER
        + 'fun Any.go(db: SQLiteDatabase) { db.execSQL("SELECT " + this) }\n'
        + "class Other(val q: Any)\n"
        + declarations
        + "class StoredReceiver(intent: Intent, val db: SQLiteDatabase) {\n"
        + f"    val q: String = {INPUT}\n"
        + f"    {member}\n"
        + "}\n"
    )
    path = "app/NearerReceiver.kt"
    report, origins = _actual_receiver_sources(monkeypatch, path, source)
    assert origins  # Actual modeled visits can carry the outer source; it is not type proof.
    assert not any(
        detail["reason"] == REASON and detail.get("call") == "go"
        for detail in _native(report)["partial_details"]
    ), report
    if context != "shadowed-let":
        assert REASON not in _native(report)["reasons"], report
    assert not _sql(report)
    assert _native(report)["budget_reasons"] == []


@pytest.mark.parametrize("declaration", ['val q = "fixed"', "val q: Any = this.q"])
def test_nonreceiver_capture_preserves_local_shadow(declaration: str, monkeypatch) -> None:
    source, original = _stored_program(
        "q", initializer=False, extension="Any" if ": Any" in declaration else "String"
    )
    source = source.replace(original, f"q.let {{ {declaration}; q.go(db) }}")
    report, _origins = _actual_receiver_sources(monkeypatch, "app/CaptureShadow.kt", source)
    assert REASON not in _native(report)["reasons"], report
    assert _state(report) == "checked", report
    assert not _sql(report)
    assert _native(report)["reasons"] == []
