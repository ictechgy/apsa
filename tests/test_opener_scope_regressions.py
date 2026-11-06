"""Fresh synthetic controls for opener result identity and implicit receiver scope."""

from __future__ import annotations

import json

import pytest

from mobile_audit.source_analysis import analyze_sources

SQL = "AST-SQL-CONCAT"
SDK_RESULTS = (
    "androidx.sqlite.db.SupportSQLiteDatabase",
    "androidx.sqlite.db.SupportSQLiteOpenHelper",
    "androidx.room.RoomDatabase",
)


def _sql_state(report):
    return next(row["state"] for row in report["coverage"] if row["rule_id"] == SQL)


def _assert_twins(report, safe):
    normalized = json.loads(json.dumps(safe).replace("loadResource", "openDatabase"))
    assert report["metadata"] == normalized["metadata"]
    assert report["coverage"] == normalized["coverage"]
    # Finding IDs include the renamed declaration's identity; compare every
    # evidence and flow field while keeping locations stable with equal names.
    assert [{key: value for key, value in item.items() if key != "id"} for item in report["findings"]] == [
        {key: value for key, value in item.items() if key != "id"} for item in normalized["findings"]
    ]


def _sdk_source(sdk, qualified, inherited, body_sink, name):
    kind = sdk if qualified else sdk.rsplit(".", 1)[1]
    imports = "" if qualified else "import " + sdk
    contract = f"interface FactoryContract {{ fun {name}(q: String?): {kind} }}" if inherited else ""
    base = " : FactoryContract" if inherited else ""
    modifier = "override" if inherited else "private"
    sink = 'controlDb.execSQL("DELETE FROM t WHERE id = " + q); ' if body_sink else ""
    return f"""package synthetic55
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
{imports}
{contract}
class Factory(private val store: {kind}, private val controlDb: SQLiteDatabase){base} {{
    {modifier} fun {name}(q: String?): {kind} {{ {sink}return store }}
    fun run(intent: Intent) {{ {name}(intent.getStringExtra("q")) }}
}}
"""


@pytest.mark.parametrize("sdk", SDK_RESULTS)
@pytest.mark.parametrize("qualified", [False, True], ids=["imported", "qualified"])
@pytest.mark.parametrize("inherited", [False, True], ids=["resolved", "interface-implementation"])
@pytest.mark.parametrize("body_sink", [False, True], ids=["safe", "real-sql-body"])
def test_external_non_database_returns_match_ordinary_project_calls(sdk, qualified, inherited, body_sink):
    # The SDK types remain external; no synthetic AndroidX declaration can make
    # source-nominal identity accidentally satisfy this result classification.
    report, safe = (
        analyze_sources([("app/Factory.kt", _sdk_source(sdk, qualified, inherited, body_sink, name))])
        for name in ("openDatabase", "loadResource")
    )
    _assert_twins(report, safe)
    if inherited:
        assert report["findings"] == []
        assert _sql_state(report) == "limited"
        assert report["metadata"]["native_flow"]["reasons"] == [
            "field summary fixed point unresolved",
            "inherited overload signature unresolved",
            "unresolved callable identity or argument signature",
        ]
    else:
        assert {item["rule_id"] for item in report["findings"]} == ({SQL} if body_sink else set())
        assert _sql_state(report) == "checked"
        assert report["metadata"]["native_flow"]["reasons"] == []


def _private_owner_files(placement, before, name, property_homonym=False):
    source = f"""package synthetic55
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Factory(private val db: SQLiteDatabase) {{
    private fun {name}(q: String?) {{ db.execSQL("DELETE FROM t WHERE id = " + q) }}
    fun run(intent: Intent) {{ {name}(intent.getStringExtra("q")) }}
}}
"""
    other = (
        f"object Other {{ val {name}: (String?) -> Unit = {{}} }}\n"
        if property_homonym
        else f"class Other {{ fun {name}(q: String?) {{}} }}\n"
    )
    if placement == "same-file":
        source = source.replace("class Factory", other + "class Factory") if before else source + other
        return [("app/Factory.kt", source)]
    namespace = "synthetic55" if placement == "same-package" else "unrelated55"
    files = [("app/Factory.kt", source), ("app/Other.kt", "package " + namespace + "\n" + other)]
    return list(reversed(files)) if before else files


@pytest.mark.parametrize("placement", ["same-file", "same-package", "other-package"])
@pytest.mark.parametrize("before", [False, True], ids=["after", "before"])
@pytest.mark.parametrize("property_homonym", [False, True], ids=["public-method", "callable-property"])
def test_unrelated_owner_does_not_poison_a_private_project_opener(placement, before, property_homonym):
    report, safe = (
        analyze_sources(_private_owner_files(placement, before, name, property_homonym))
        for name in ("openDatabase", "loadResource")
    )
    _assert_twins(report, safe)
    assert {item["rule_id"] for item in report["findings"]} == {SQL}
    assert _sql_state(report) == "checked"
    assert report["metadata"]["native_flow"]["reasons"] == []


@pytest.mark.parametrize("base", ["Activity", "Application"])
@pytest.mark.parametrize("override", ["none", "unrelated", "reachable-inferred", "reachable-declared"])
def test_context_openers_keep_explicit_intent_flows_and_reachable_override_limits(base, override):
    source = """package synthetic55
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
"""
    method = (
        "override fun openOrCreateDatabase(n: String, m: Int, f: SQLiteDatabase.CursorFactory?)"
        + (": SQLiteDatabase" if override == "reachable-declared" else "")
        + " = super.openOrCreateDatabase(n, m, f)\n"
    )
    parent = "android.app." + base
    if override.startswith("reachable"):
        source += "open class Base : " + parent + "() { " + method + " }\n"
        parent = "Base"
    elif override == "unrelated":
        source += "class Other : android.content.ContextWrapper(null) { " + method + " }\n"
    source += f"""class Factory : {parent}() {{
    fun run(intent: Intent) {{
        val db = openOrCreateDatabase("a.db", 0, null)
        db.execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))
    }}
}}
"""
    report = analyze_sources([("app/Factory.kt", source)])
    assert {item["rule_id"] for item in report["findings"]} == {SQL}
    expected = (
        []
        if override == "none"
        else [
            "object alias identity unavailable",
            "unresolved callable identity or argument signature",
        ]
    )
    if override.startswith("reachable"):
        expected.insert(1, "opener receiver identity unresolved")
    assert report["metadata"]["native_flow"]["reasons"] == expected
    assert _sql_state(report) == ("checked" if override == "none" else "limited")


@pytest.mark.parametrize("kind", ["Context", "ContextWrapper", "Shell"])
@pytest.mark.parametrize("receiver", ["host", "ctx"])
def test_explicit_context_receivers_use_type_ancestry_independently_of_variable_name(kind, receiver):
    source = """package synthetic55
import android.content.Intent
import android.content.Context
import android.content.ContextWrapper
"""
    if kind == "Shell":
        source += "class Shell(base: Context) : ContextWrapper(base)\n"
    source += f"""fun run({receiver}: {kind}, intent: Intent) {{
    val db = {receiver}.openOrCreateDatabase("a.db", 0, null)
    db.execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))
}}
"""
    report = analyze_sources([("app/Factory.kt", source)])
    assert {item["rule_id"] for item in report["findings"]} == {SQL}
    assert _sql_state(report) == "checked"
    assert report["metadata"]["native_flow"]["reasons"] == []


def test_a_source_context_homonym_is_not_a_framework_receiver():
    source = """package synthetic55
import android.content.Intent
fun run(host: Context, intent: Intent) {
    val result = host.openOrCreateDatabase("a.db", 0, null)
    result.execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))
}
"""
    declarations = """package synthetic55
class Store { fun execSQL(sql: String) {} }
class Context {
    fun openOrCreateDatabase(n: String, mode: Int, factory: Any?): Store = Store()
}
"""
    report = analyze_sources([("app/Factory.kt", source), ("lib/Context.kt", declarations)])
    assert report["findings"] == []
    assert _sql_state(report) == "checked"
    assert report["metadata"]["native_flow"]["reasons"] == []


@pytest.mark.parametrize("shape", ["within-companion", "containing-class", "unused-companion"])
def test_private_companion_scope_keeps_its_specific_execution_limit(shape):
    header = """package synthetic55
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
"""
    caller = 'fun run(intent: Intent) { openDatabase(intent.getStringExtra("q")) }'
    sink = 'private fun openDatabase(q: String?) { db.execSQL("DELETE FROM t WHERE id = " + q) }'
    if shape == "unused-companion":
        source = (
            f"class Factory(private val db: SQLiteDatabase) {{ {sink}\n {caller} }}\n"
            "class Other { companion object { private fun openDatabase(q: String?) {} } }\n"
        )
    else:
        companion = f"companion object {{ lateinit var db: SQLiteDatabase\n{sink}\n"
        source = (
            f"class Factory {{ {companion}{caller} }} }}\n"
            if shape == "within-companion"
            else f"class Factory {{ {companion}}}\n {caller} }}\n"
        )
    report = analyze_sources([("app/Factory.kt", header + source)])
    assert {item["rule_id"] for item in report["findings"]} == (
        {SQL} if shape == "unused-companion" else set()
    )
    assert _sql_state(report) == "limited"
    native = report["metadata"]["native_flow"]
    assert native["reasons"] == ["nominal callable scope unavailable"]
    assert native["budget_reasons"] == []
    assert all(
        detail["reason"] == "nominal callable scope unavailable" for detail in native["partial_details"]
    )


def test_a_reachable_outer_callable_property_retains_its_exact_precision_limit():
    source = """package synthetic55
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Factory(private val db: SQLiteDatabase) {
    val openDatabase: (String?) -> Unit = { q -> db.execSQL("DELETE FROM t WHERE id = " + q) }
    inner class Inner { fun run(intent: Intent) { openDatabase(intent.getStringExtra("q")) } }
}
"""
    report = analyze_sources([("app/Factory.kt", source)])
    assert report["findings"] == []
    assert _sql_state(report) == "limited"
    native = report["metadata"]["native_flow"]
    assert native["reasons"] == ["opener receiver identity unresolved"]
    assert native["budget_reasons"] == []
    assert len(native["partial_details"]) == 1
    assert SQL in native["partial_details"][0]["rule_ids"]
