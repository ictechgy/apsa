"""Synthetic declared database returns are resolved in their declaration's context."""

from __future__ import annotations

import pytest
import tree_sitter_java
import tree_sitter_kotlin
from tree_sitter import Language, Parser

from mobile_audit.native_flow import NativeFlow
from mobile_audit.source_analysis import Analyzer, _walk, analyze_sources

SQL = "AST-SQL-CONCAT"


def _case(
    name,
    declaration,
    *,
    imports="import android.database.sqlite.SQLiteDatabase",
    stored="SQLiteDatabase",
    extra=(),
    caller_imports="",
    expression="openDatabase()",
    sink=True,
    expectation="database-declaration",
    note="",
) -> dict:
    declaring = f"package synthetic49\n{imports}\nlateinit var stored: {stored}\n{declaration}\n"
    body = (
        f'{expression}.rawQuery("SELECT * FROM t WHERE id = " + intent.getStringExtra("q"), null)'
        if sink
        else f'val returned = {expression}\n    controlDb.rawQuery("SELECT 1", null)'
    )
    caller = (
        "package synthetic49\nimport android.content.Intent\n"
        "import android.database.sqlite.SQLiteDatabase\n" + caller_imports + "\n"
        "lateinit var seed: SQLiteDatabase\n"
        f"fun scan(intent: Intent, controlDb: SQLiteDatabase) {{\n    {body}\n}}\n"
    )
    return dict(
        name=name,
        files=[["app/Decl.kt", declaring], ["app/Caller.kt", caller], *extra],
        expectation=expectation,
        note=note,
        database_sink=sink,
    )


def _fixtures() -> list[dict]:
    source_db = ["other/Db.kt", "package other49\nclass Db {\n fun rawQuery(sql: String, args: Any?) {}\n}\n"]
    source_sqlite = [
        "other/SQLiteDatabase.kt",
        "package other49\nclass SQLiteDatabase {\n fun rawQuery(sql: String, args: Any?) {}\n}\n",
    ]
    alias_extra = [
        "other/Alias.kt",
        "package unrelated49\nimport android.database.sqlite.SQLiteDatabase\ntypealias Db = SQLiteDatabase\n",
    ]
    rows = [
        _case("direct", "fun openDatabase(): SQLiteDatabase { return stored }"),
        _case("qualified", "fun openDatabase(): android.database.sqlite.SQLiteDatabase { return stored }"),
        _case(
            "import_alias",
            "fun openDatabase(): Db { return stored }",
            imports="import android.database.sqlite.SQLiteDatabase as Db",
            stored="Db",
        ),
        _case(
            "import_alias_unrelated_same_leaf",
            "fun openDatabase(): Db { return stored }",
            imports="import android.database.sqlite.SQLiteDatabase as Db",
            stored="Db",
            extra=[source_db],
        ),
        _case(
            "direct_unrelated_SQLiteDatabase",
            "fun openDatabase(): SQLiteDatabase { return stored }",
            extra=[source_sqlite],
        ),
        _case(
            "import_alias_conflicting_caller",
            "fun openDatabase(): Db { return stored }",
            imports="import android.database.sqlite.SQLiteDatabase as Db",
            stored="Db",
            caller_imports="import other49.Db as Db",
            extra=[source_db],
        ),
        _case(
            "alias_chain_declaring_import",
            "typealias Mid = RootDb\ntypealias Db = Mid\nfun openDatabase(): Db { return stored }",
            imports="import android.database.sqlite.SQLiteDatabase as RootDb",
            stored="RootDb",
        ),
        _case(
            "alias_chain_standard",
            "typealias Mid = SQLiteDatabase\ntypealias Db = Mid\nfun openDatabase(): Db { return stored }",
        ),
        _case(
            "alias_chain_cross_file",
            "fun openDatabase(): Db { return stored }",
            imports="import alias49.Db\nimport android.database.sqlite.SQLiteDatabase",
            extra=[
                [
                    "alias/Alias.kt",
                    "package alias49\nimport android.database.sqlite.SQLiteDatabase as RootDb\ntypealias Mid = RootDb\ntypealias Db = Mid\n",
                ]
            ],
        ),
        _case(
            "source_nominal",
            "fun openDatabase(): Db { return stored }",
            imports="import other49.Db",
            stored="Db",
            extra=[source_db],
            expectation="provably-non-database",
        ),
        _case(
            "source_nominal_unrelated_database_alias",
            "fun openDatabase(): Db { return stored }",
            imports="import other49.Db",
            stored="Db",
            extra=[source_db, alias_extra],
            expectation="provably-non-database",
        ),
        _case(
            "source_nominal_SQLiteDatabase",
            "fun openDatabase(): SQLiteDatabase { return stored }",
            imports="import other49.SQLiteDatabase",
            extra=[source_sqlite],
            expectation="provably-non-database",
        ),
        _case(
            "string_return",
            'fun openDatabase(): String { return "constant" }',
            expectation="provably-non-database",
            sink=False,
        ),
        _case(
            "unknown_external",
            "fun openDatabase(): Thing { return stored }",
            imports="import vendor49.Thing",
            stored="Thing",
            expectation="unknown-library-return",
            note="External library identity deliberately unrepresented; no compiler acceptance claimed.",
        ),
        _case(
            "bounded_parameter",
            "fun <T : SQLiteDatabase> openDatabase(value: T): T { return value }",
            expression="openDatabase(seed)",
        ),
        _case(
            "where_bound",
            "fun <T> openDatabase(value: T): T where T : SQLiteDatabase { return value }",
            expression="openDatabase(seed)",
        ),
        _case(
            "bound_import_alias",
            "fun <T : Db> openDatabase(value: T): T { return value }",
            imports="import android.database.sqlite.SQLiteDatabase as Db",
            stored="Db",
            expression="openDatabase(seed)",
        ),
        _case("parenthesized_database", "fun openDatabase(): (SQLiteDatabase) { return stored }"),
        _case(
            "nonnull_database_bound",
            "fun <T : SQLiteDatabase?> openDatabase(value: T): T & Any { return value!! }",
            expression="openDatabase(seed)",
        ),
        _case(
            "nonnull_unknown_bound",
            "fun <T> openDatabase(value: T): T & Any { return value!! }",
            expression="openDatabase(seed)",
            expectation="generic-return-without-database-bound",
        ),
        _case(
            "function_return",
            "fun openDatabase(): () -> SQLiteDatabase { return { stored } }",
            sink=False,
            expectation="function-object-return",
            note="No rawQuery call on a function object; constant typed database site is a safe control.",
        ),
        _case(
            "parenthesized_function_return",
            "fun openDatabase(): (() -> SQLiteDatabase) { return { stored } }",
            sink=False,
            expectation="function-object-return",
            note="No rawQuery call on a function object; constant typed database site is a safe control.",
        ),
        _case(
            "parameter_direct",
            "fun openDatabase(value: SQLiteDatabase): SQLiteDatabase { return value }",
            expression="openDatabase(controlDb)",
        ),
        _case(
            "parameter_import_alias",
            "fun openDatabase(value: Db): Db { return value }",
            imports="import android.database.sqlite.SQLiteDatabase as Db",
            stored="Db",
            expression="openDatabase(controlDb)",
        ),
        _case(
            "parameter_import_alias_unrelated_same_leaf",
            "fun openDatabase(value: Db): Db { return value }",
            imports="import android.database.sqlite.SQLiteDatabase as Db",
            stored="Db",
            extra=[source_db],
            expression="openDatabase(controlDb)",
        ),
        _case(
            "parameter_alias_chain",
            "typealias Mid = RootDb\ntypealias Db = Mid\nfun openDatabase(value: Db): Db { return value }",
            imports="import android.database.sqlite.SQLiteDatabase as RootDb",
            stored="RootDb",
            expression="openDatabase(controlDb)",
        ),
        _case(
            "parameter_parenthesized_database",
            "fun openDatabase(value: SQLiteDatabase): (SQLiteDatabase) { return value }",
            expression="openDatabase(controlDb)",
        ),
        _case(
            "shadowed_parameter_alias",
            "fun <Db> openDatabase(value: Db): Db { return value }",
            expression='openDatabase("constant")',
            extra=[alias_extra],
            sink=False,
            expectation="shadowed-generic-not-database",
        ),
        _case(
            "malformed_return_negative",
            "fun openDatabase(): (SQLiteDatabase { return stored }",
            expectation="intentionally-malformed",
            note="Parser/setup negative only; excluded from capability conclusions.",
        ),
    ]
    selected = {
        "import_alias",
        "import_alias_unrelated_same_leaf",
        "import_alias_conflicting_caller",
        "alias_chain_cross_file",
        "source_nominal_unrelated_database_alias",
        "nonnull_database_bound",
    }
    for row in list(rows):
        if row["name"] in selected:
            clone = dict(row)
            clone["name"] += "__reordered"
            clone["files"] = list(reversed(row["files"]))
            clone["reordered_of"] = row["name"]
            rows.append(clone)
    return rows


CASES = _fixtures()


def _flow(files, language="kotlin"):
    grammar = tree_sitter_kotlin if language == "kotlin" else tree_sitter_java
    parser = Parser(Language(grammar.language()))
    parsed = []
    for path, source in files:
        root = parser.parse(source.encode()).root_node
        assert not root.has_error, (path, root)
        parsed.append((Analyzer(path, source, language), root, list(_walk(root))))
    return NativeFlow(parsed)


def _return_facts(flow):
    target = flow.by_name["openDatabase"][0]
    caller = next((source for source, _, _ in flow.files if "Caller" in source.path), target.analyzer)
    return (
        caller.declared_return(target),
        caller.declares_database(target),
        caller.not_database_return(target),
        caller.return_known(target),
    )


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["name"])
def test_original_return_identity_controls(case):
    report = analyze_sources(case["files"])
    state = next(row["state"] for row in report["coverage"] if row["rule_id"] == SQL)
    native = report["metadata"]["native_flow"]
    findings = [finding for finding in report["findings"] if finding["rule_id"] == SQL]
    if case["expectation"] == "intentionally-malformed":
        assert state == "partial", report
        return  # a parser negative, never a positive return-identity proof
    assert native["budget_reasons"] == [], report
    facts = _return_facts(_flow(case["files"]))
    assert facts[0], facts  # all original valid controls explicitly declare a return type
    if case["expectation"] == "database-declaration":
        assert facts[1:] == (True, False, True), facts
        assert len(findings) == 1, report
    elif case["expectation"] in {"provably-non-database", "function-object-return"}:
        assert facts[1:] == (False, True, True), facts
        assert not findings, report
    else:
        assert facts[1:] == (False, False, True), facts
        assert not findings, report
    checked = {
        "bounded_parameter",
        "where_bound",
        "bound_import_alias",
        "nonnull_database_bound",
        "parameter_direct",
        "parameter_import_alias",
        "parameter_import_alias_unrelated_same_leaf",
        "parameter_parenthesized_database",
        "string_return",
    }
    name = case["name"].removesuffix("__reordered")
    assert state == ("checked" if name in checked else "limited"), report
    expected_precision = [] if name in checked else ["receiver field inventory unavailable"]
    if name.startswith("source_nominal"):
        expected_precision = [
            "object alias identity unavailable",
            "receiver field inventory unavailable",
            "unresolved callable identity or argument signature",
        ]
    elif name == "parameter_alias_chain":
        expected_precision = [
            "callable argument type identity unresolved",
            "unresolved callable identity or argument signature",
        ]
    elif name == "shadowed_parameter_alias":
        expected_precision = [
            "callable argument type identity unresolved",
            "opener receiver identity unresolved",
            "unresolved callable identity or argument signature",
        ]
    elif name in {"unknown_external", "nonnull_unknown_bound"}:
        expected_precision = ["opener receiver identity unresolved"]
        if name == "unknown_external":
            expected_precision.append("receiver field inventory unavailable")
    assert native["precision_reasons"] == expected_precision, report


@pytest.mark.parametrize(
    ("declaration", "identity"),
    [
        ("fun openDatabase(): ((SQLiteDatabase)?) = TODO()", True),
        ("fun openDatabase(): (() -> SQLiteDatabase)? = TODO()", False),
        ("fun openDatabase(): (SQLiteDatabase) -> SQLiteDatabase = TODO()", False),
        ("fun <T: SQLiteDatabase?> openDatabase(): (T & Any) = TODO()", True),
        ("fun <T> openDatabase(): T & Any = TODO()", None),
        ("fun <T: Unknown> openDatabase(): T & Any = TODO()", None),
        ("fun <T: SQLiteDatabase> openDatabase(): T & String = TODO()", None),
        ("fun openDatabase(): SQLiteDatabase & Any = TODO()", None),
        ("fun <T: String> openDatabase(): T = TODO()", False),
        ("fun <T: T> openDatabase(): T = TODO()", None),
        ("fun <T: U, U: T> openDatabase(): T = TODO()", None),
        ("fun <T: U, U: SQLiteDatabase> openDatabase(): T = TODO()", True),
        ("fun <T, U> openDatabase(): T where T: U, U: SQLiteDatabase = TODO()", True),
        ("fun <T> openDatabase(): T where T: SQLiteDatabase, T: Unknown = TODO()", None),
        ("class Owner<T: SQLiteDatabase> {\n fun <T> openDatabase(): T = TODO()\n}", None),
        ("class Owner<T: SQLiteDatabase> {\n fun openDatabase(): T = TODO()\n}", True),
        ("class Owner<T: Unknown> {\n fun <T: SQLiteDatabase> openDatabase(): T = TODO()\n}", True),
        ("typealias Db = Other\ntypealias Other = Db\nfun openDatabase(): Db = TODO()", None),
        ("fun openDatabase() {}", False),
        ("fun openDatabase() = TODO()", None),
    ],
)
def test_return_wrappers_and_nearest_parameter_bounds(declaration, identity):
    flow = _flow([("app/Decl.kt", "import android.database.sqlite.SQLiteDatabase\n" + declaration + "\n")])
    target = flow.by_name["openDatabase"][0]
    assert target.analyzer.database_return_identity(target) is identity
    assert target.analyzer.declares_database(target) is (identity is True)
    assert target.analyzer.not_database_return(target) is (identity is False)


@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reversed"])
@pytest.mark.parametrize(
    ("imports", "declaration", "extra", "identity"),
    [
        ("import other.Db", "fun openDatabase(): other.Db = TODO()", "package other\nclass Db\n", False),
        (
            "import other.Db",
            "typealias Alias = Db\nfun openDatabase(): Alias = TODO()",
            "package other\nclass Db\n",
            False,
        ),
        (
            "import android.database.sqlite.SQLiteDatabase",
            "fun openDatabase(): SQLiteDatabase = TODO()",
            "package other\nclass SQLiteDatabase\n",
            True,
        ),
        (
            "import vendor.String",
            "fun openDatabase(): String = TODO()",
            "package other\nclass String\n",
            None,
        ),
        (
            "import android.database.sqlite.SQLiteDatabase as Db",
            "fun <Db> openDatabase(): Db = TODO()",
            "package other\ntypealias Db = android.database.sqlite.SQLiteDatabase\n",
            None,
        ),
        (
            "import android.database.sqlite.SQLiteDatabase",
            "class Any\nfun <T: SQLiteDatabase> openDatabase(): T & Any = TODO()",
            "package other\nclass Empty\n",
            None,
        ),
    ],
)
def test_scoped_source_and_shadow_controls(imports, declaration, extra, identity, reverse):
    files = [
        ("app/Decl.kt", "package app\n" + imports + "\n" + declaration + "\n"),
        ("other/Types.kt", extra),
    ]
    if reverse:
        files.reverse()
    flow = _flow(files)
    target = flow.by_name["openDatabase"][0]
    assert target.analyzer.database_return_identity(target) is identity


@pytest.mark.parametrize(
    ("declaration", "identity"),
    [
        ("SQLiteDatabase openDatabase() { return null; }", True),
        ("android.database.sqlite.SQLiteDatabase openDatabase() { return null; }", True),
        ("<T extends SQLiteDatabase> T openDatabase() { return null; }", True),
        ("<T> T openDatabase() { return null; }", None),
        ("String openDatabase() { return null; }", False),
        ("int openDatabase() { return 0; }", False),
        ("void openDatabase() {}", False),
    ],
)
def test_java_return_controls(declaration, identity):
    flow = _flow(
        [
            (
                "app/Decl.java",
                "import android.database.sqlite.SQLiteDatabase;\nclass Decl {\n" + declaration + "\n}\n",
            )
        ],
        "java",
    )
    target = flow.by_name["openDatabase"][0]
    assert target.analyzer.database_return_identity(target) is identity


def test_return_identity_queries_are_inert_and_extension_roots_unchanged(monkeypatch):
    row = next(case for case in CASES if case["name"] == "alias_chain_cross_file")
    flow = _flow(row["files"])
    target = flow.by_name["openDatabase"][0]
    analyzer = target.analyzer
    node = analyzer.declared_return_node(target)
    before = {key: repr(value) for key, value in vars(flow).items()}

    def forbidden(*args, **kwargs):
        pytest.fail("a declaration identity query must not emit precision or evaluate code")

    monkeypatch.setattr(flow, "partial", forbidden)
    monkeypatch.setattr(flow, "resolve", forbidden)
    monkeypatch.setattr(analyzer, "library_reference_type", forbidden)
    for _ in range(3):
        assert analyzer.database_return_identity(target) is True
        assert analyzer.declares_database(target)
        assert not analyzer.not_database_return(target)
        assert (
            analyzer.reference_type_identity(analyzer.text(node), node, context=analyzer, cache=False)[0]
            == ""
        )
    after = {key: repr(value) for key, value in vars(flow).items() if key not in {"partial", "resolve"}}
    assert before == after
