"""Fresh Kotlin sources for the lexical scope of local constructor parameters.

Constructor arguments remain an explicit precision boundary; these fixtures do
not claim constructor specialization or runtime reproduction.
"""

from __future__ import annotations

import textwrap

import pytest

from mobile_audit.source_analysis import analyze_sources

SQL = "AST-SQL-CONCAT"
UNAVAILABLE = "constructor field mapping unavailable"
IMPORTS = """\
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
"""
INPUT = 'intent.getStringExtra("query") ?: ""'
CASES: list[tuple[str, str]] = []

for modifier in ("", "val ", "var "):
    for outer_input in (False, True):
        for actual_input in (False, True):
            outer = INPUT if outer_input else '"fixed outer"'
            actual = INPUT if actual_input else '"fixed actual"'
            CASES.append(
                (
                    f"{modifier.strip() or 'bare'}-shadow-outer{outer_input}-actual{actual_input}",
                    f"""fun run(intent: Intent, db: SQLiteDatabase) {{
                        val query = {outer}
                        class Local({modifier}query: String) {{
                            init {{ db.execSQL("SELECT " + query) }}
                        }}
                        Local({actual}) // CONSTRUCTION
                    }}""",
                )
            )
    CASES.append(
        (
            f"{modifier.strip() or 'bare'}-restore-outer-value",
            f"""fun run(intent: Intent, db: SQLiteDatabase) {{
                val query = {INPUT}
                class Local({modifier}query: String) {{
                    init {{ db.execSQL("SELECT " + query) }}
                }}
                Local("fixed") // CONSTRUCTION
                db.execSQL("SELECT " + query) // FINDING
            }}""",
        )
    )

for outer_input in (False, True):
    for actual_input in (False, True):
        outer = INPUT if outer_input else '"fixed outer"'
        actual = INPUT if actual_input else '"fixed actual"'
        marker = " // FINDING" if outer_input else ""
        CASES.append(
            (
                f"different-parameter-captures-outer{outer_input}-actual{actual_input}",
                f"""fun run(intent: Intent, db: SQLiteDatabase) {{
                    val query = {outer}
                    class Local(incoming: String) {{
                        init {{ db.execSQL("SELECT " + query) }}{marker}
                    }}
                    Local({actual}) // CONSTRUCTION
                }}""",
            )
        )

for actual_input in (False, True):
    actual = INPUT if actual_input else '"fixed actual"'
    CASES.append(
        (
            f"no-outer-homonym-actual{actual_input}",
            f"""fun run(intent: Intent, db: SQLiteDatabase) {{
                class Local(query: String) {{ init {{ db.execSQL("SELECT " + query) }} }}
                Local({actual}) // CONSTRUCTION
            }}""",
        )
    )

CASES.extend(
    [
        (
            "parameter-write-does-not-replace-outer-value",
            f"""fun run(intent: Intent, db: SQLiteDatabase) {{
                val query = {INPUT}
                class Local(var query: String) {{ init {{ query = "fixed" }} }}
                Local("fixed") // CONSTRUCTION
                db.execSQL("SELECT " + query) // FINDING
            }}""",
        ),
        (
            "captured-outer-write-is-retained",
            f"""fun run(intent: Intent, db: SQLiteDatabase) {{
                var captured = "fixed"
                class Local(query: String) {{ init {{ captured = {INPUT} }} }}
                Local("fixed") // CONSTRUCTION
                db.execSQL("SELECT " + captured) // FINDING
            }}""",
        ),
        (
            "captured-outer-reset-is-retained",
            f"""fun run(intent: Intent, db: SQLiteDatabase) {{
                var captured = {INPUT}
                class Local(query: String) {{ init {{ captured = "fixed" }} }}
                Local("fixed") // CONSTRUCTION
                db.execSQL("SELECT " + captured)
            }}""",
        ),
        (
            "scope-alias-restored-after-parameter-shadow",
            """fun run(intent: Intent, db: SQLiteDatabase) {
                intent.let { query ->
                    class Local(query: String) { init { db.execSQL("SELECT " + query) } }
                    Local("fixed") // CONSTRUCTION
                    db.execSQL("SELECT " + query.getStringExtra("q")) // FINDING
                }
            }""",
        ),
        (
            "receiver-type-and-identity-restored",
            f"""class Silent {{ fun execSQL(sql: String) {{}} }}
            fun run(intent: Intent, db: SQLiteDatabase) {{
                val query = {INPUT}
                class Local(db: Silent) {{ init {{ db.execSQL("SELECT " + query) }} }}
                Local(Silent()) // CONSTRUCTION
                db.execSQL("SELECT " + query) // FINDING
            }}""",
        ),
        (
            "nested-parameter-scopes-do-not-recover-outer-homonym",
            f"""fun run(intent: Intent, db: SQLiteDatabase) {{
                val query = {INPUT}
                class Local(query: String) {{
                    init {{
                        class Inner(incoming: String) {{ init {{ db.execSQL("SELECT " + query) }} }}
                        Inner("fixed") // CONSTRUCTION
                    }}
                }}
                Local("fixed") // CONSTRUCTION
            }}""",
        ),
    ]
)


def source_text(body: str) -> str:
    return IMPORTS + textwrap.dedent(body).strip()


@pytest.mark.parametrize(("case", "body"), CASES, ids=[case for case, _ in CASES])
def test_local_constructor_parameters_have_their_own_lexical_bindings(case: str, body: str) -> None:
    source = source_text(body)
    report = analyze_sources([("Local.kt", source)])
    expected_lines = {line for line, text in enumerate(source.splitlines(), 1) if "// FINDING" in text}
    findings = [finding for finding in report["findings"] if finding["rule_id"] == SQL]
    actual_lines = {evidence["line"] for finding in findings for evidence in finding["evidence"]}
    assert actual_lines == expected_lines, (case, report)
    assert len(findings) == len(expected_lines), (case, report)
    metadata = report["metadata"]["native_flow"]
    assert metadata["state"] == "partial", (case, report)
    assert UNAVAILABLE in metadata["precision_reasons"], (case, report)
    assert not metadata["budget_reasons"], (case, report)
    details = [item for item in metadata["partial_details"] if item["reason"] == UNAVAILABLE]
    expected_calls = {line for line, text in enumerate(source.splitlines(), 1) if "// CONSTRUCTION" in text}
    assert {item["line"] for item in details} == expected_calls, (case, report)
    assert all(item["kind"] == "precision" and item["path"] == "Local.kt" for item in details)
    [coverage] = [item for item in report["coverage"] if item["rule_id"] == SQL]
    assert coverage["state"] == "limited", (case, report)
    assert coverage["function_inventory_complete"] is True
