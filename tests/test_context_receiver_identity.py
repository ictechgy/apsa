"""Qualified Android identities and proven source exclusions precede name guesses."""

import pytest

from mobile_audit.source_analysis import analyze_sources

SQL = "AST-SQL-CONCAT"
FRAMEWORK = (
    "android.content.Context",
    "android.content.ContextWrapper",
    "android.view.ContextThemeWrapper",
    "android.app.Activity",
    "android.app.Application",
)


def _caller(kind, receiver="host", imported=""):
    return f"""package fresh57
import android.content.Intent
{imported}
fun run({receiver}: {kind}, intent: Intent) {{
    val db = {receiver}.openOrCreateDatabase("a.db", 0, null)
    db.execSQL("SELECT " + intent.getStringExtra("q"))
}}
"""


def _assert_checked(report, found):
    assert bool([f for f in report["findings"] if f["rule_id"] == SQL]) is found
    assert next(c["state"] for c in report["coverage"] if c["rule_id"] == SQL) == "checked"
    assert report["metadata"]["native_flow"]["reasons"] == []


@pytest.mark.parametrize("kind", FRAMEWORK)
@pytest.mark.parametrize("shadow_package", ["fresh57", "unrelated57"])
def test_qualified_framework_context_ignores_other_nominal_leaf_names(kind, shadow_package):
    caller = _caller(kind)
    leaf = kind.rsplit(".", 1)[-1]
    clean = analyze_sources([("Caller.kt", caller)])
    shadowed = analyze_sources(
        [
            ("Caller.kt", caller),
            ("Other.kt", f"package {shadow_package}\nclass {leaf}\n"),
        ]
    )
    _assert_checked(clean, True)
    _assert_checked(shadowed, True)
    assert shadowed["findings"] == clean["findings"]


@pytest.mark.parametrize("kind", FRAMEWORK)
def test_explicit_framework_import_keeps_its_nominal_identity(kind):
    leaf = kind.rsplit(".", 1)[-1]
    report = analyze_sources(
        [
            ("Caller.kt", _caller(leaf, imported=f"import {kind}")),
            ("Other.kt", f"package unrelated57\nclass {leaf}\n"),
        ]
    )
    _assert_checked(report, True)


@pytest.mark.parametrize("receiver", ["host", "ctx", "context", "appContext"])
@pytest.mark.parametrize("qualified", [False, True])
def test_source_context_exclusion_cannot_be_overridden_by_receiver_name(receiver, qualified):
    kind = "fresh57.Context" if qualified else "Context"
    report = analyze_sources(
        [
            ("Caller.kt", _caller(kind, receiver)),
            (
                "Context.kt",
                """package fresh57
class Store { fun execSQL(sql: String) {} }
class Context {
    fun openOrCreateDatabase(n: String, mode: Int, factory: Any?): Store = Store()
}
""",
            ),
        ]
    )
    _assert_checked(report, False)


def test_source_ancestry_retains_qualified_framework_context_with_leaf_shadow():
    report = analyze_sources(
        [
            ("Caller.kt", _caller("Shell")),
            (
                "Shell.kt",
                """package fresh57
class Shell(base: android.content.Context) : android.content.ContextWrapper(base)
class ContextWrapper
""",
            ),
        ]
    )
    _assert_checked(report, True)
