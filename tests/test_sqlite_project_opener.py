"""A project method named like a framework database opener is analyzed as project code.

Only a receiverless `openDatabase`/`openOrCreateDatabase` that the analyzed sources do
not declare is typed as the framework `SQLiteDatabase` opener.
"""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import analyze_sources

JAVA = """package a;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;
final class Store {
    private final SQLiteDatabase db;
    Store(SQLiteDatabase db) { this.db = db; }
    private void NAME(String n) {
        db.execSQL("ATTACH DATABASE '" + n + "' AS extra");
    }
    void handle(Intent intent) {
        NAME(intent.getStringExtra("q"));
    }
}
"""
KOTLIN = """package a
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Store(private val db: SQLiteDatabase) {
    private fun NAME(n: String?) {
        db.execSQL("ATTACH DATABASE '" + n + "' AS extra")
    }
    fun handle(intent: Intent) {
        NAME(intent.getStringExtra("q"))
    }
}
"""
FRAMEWORK = """package a
import android.app.Activity
import android.content.Intent
class Main : Activity() {
    fun handle(intent: Intent) {
        val q = intent.getStringExtra("q")
        val db = NAME("x.db", 0, null)
        db.execSQL("DELETE FROM t WHERE q='" + q + "'")
    }
}
"""


def rules(path: str, source: str) -> tuple[set[str], str]:
    report = analyze_sources([(path, source)])
    return {item["rule_id"] for item in report["findings"]}, report["metadata"]["native_flow"]["state"]


@pytest.mark.parametrize("name", ["openDatabase", "openOrCreateDatabase", "attachDatabase"])
@pytest.mark.parametrize(
    ("path", "template"), [("app/Store.java", JAVA), ("app/Store.kt", KOTLIN)], ids=["java", "kotlin"]
)
def test_project_opener_flows_into_its_sql_sink(path, template, name):
    assert rules(path, template.replace("NAME", name)) == ({"AST-SQL-CONCAT"}, "checked")


@pytest.mark.parametrize("name", ["openDatabase", "openOrCreateDatabase"])
def test_framework_opener_still_returns_a_database(name):
    assert "AST-SQL-CONCAT" in rules("app/Main.kt", FRAMEWORK.replace("NAME", name))[0]


ACTIVITY = """package com.example.app
import android.app.Activity
import android.content.Context
class MainActivity : BASE {
    fun query() {
        val db = openOrCreateDatabase("app.db", Context.MODE_PRIVATE, null)
        db.rawQuery("SELECT * FROM t WHERE id = " + intent.data.toString(), null)
    }
}
"""
CONTEXT_WRAPPER = """package com.example.app
import android.content.Context
import android.content.ContextWrapper
import android.database.sqlite.SQLiteDatabase
class AppContext(base: Context) : ContextWrapper(base) {
    override fun openOrCreateDatabase(name: String, mode: Int, factory: SQLiteDatabase.CursorFactory?): SQLiteDatabase {
        return super.openOrCreateDatabase(name, mode, factory)
    }
}
"""
BASE_ACTIVITY = CONTEXT_WRAPPER.replace(
    "import android.content.ContextWrapper", "import android.app.Activity"
).replace("class AppContext(base: Context) : ContextWrapper(base)", "open class BaseActivity : Activity()")
UNRELATED_KOTLIN = """package com.example.app
import java.io.File
class Archive {
    fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): File = File(name)
}
"""
UNRELATED_JAVA = """package com.example.app;
class Legacy { Object openOrCreateDatabase(String n, int mode, Object f) { return null; } }
"""
SAME_CLASS_OVERRIDE = ACTIVITY.replace(
    "    fun query() {",
    "    override fun openOrCreateDatabase(name: String, mode: Int, factory: android.database.sqlite.SQLiteDatabase"
    ".CursorFactory?) = super.openOrCreateDatabase(name, mode, factory)\n    fun query() {",
)


@pytest.mark.parametrize(
    "files",
    [
        [
            ("app/MainActivity.kt", ACTIVITY.replace("BASE", "Activity()")),
            ("app/AppContext.kt", CONTEXT_WRAPPER),
        ],
        [
            ("app/MainActivity.kt", ACTIVITY.replace("BASE", "Activity()")),
            ("app/Archive.kt", UNRELATED_KOTLIN),
        ],
        [
            ("app/MainActivity.kt", ACTIVITY.replace("BASE", "Activity()")),
            ("app/Legacy.java", UNRELATED_JAVA),
        ],
        [
            ("app/MainActivity.kt", ACTIVITY.replace("BASE", "BaseActivity()")),
            ("app/BaseActivity.kt", BASE_ACTIVITY),
        ],
        [("app/MainActivity.kt", SAME_CLASS_OVERRIDE.replace("BASE", "Activity()"))],
    ],
    ids=[
        "context-wrapper-override",
        "unrelated-kotlin-method",
        "unrelated-java-method",
        "base-override",
        "own-override",
    ],
)
def test_framework_opener_keeps_sdk_identity_when_call_site_cannot_reach_project_code(files):
    report = analyze_sources(files)
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


TOP_LEVEL_FILE_OPENER = """package com.example.app
import java.io.File
fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): File = File(name)
"""
SDK_ACTIVITY = """package com.example.app
import android.app.Activity
class Main : Activity() {
    fun run() {
        val db = openOrCreateDatabase("app.db", 0, null)
        db.execSQL("DELETE FROM t WHERE id = " + (intent.getStringExtra("q") ?: ""))
    }
}
"""


@pytest.mark.parametrize(
    "files",
    [
        [("app/Main.kt", SDK_ACTIVITY), ("app/Db.kt", TOP_LEVEL_FILE_OPENER)],
        [("app/Main.kt", SDK_ACTIVITY + TOP_LEVEL_FILE_OPENER.split("\n", 2)[2])],
    ],
    ids=["same-package", "same-file"],
)
def test_inherited_member_hides_a_top_level_opener(files):
    report = analyze_sources(files)
    assert {item["rule_id"] for item in report["findings"]} == {"AST-SQL-CONCAT"}
    assert report["metadata"]["native_flow"]["state"] == "checked"


def test_top_level_opener_is_followed_from_a_class_without_supertypes():
    top_level = """package com.example.app
import android.database.sqlite.SQLiteDatabase
fun openDatabase(db: SQLiteDatabase, n: String?) {
    db.execSQL("ATTACH DATABASE '" + n + "' AS extra")
}
"""
    caller = """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Handler(private val db: SQLiteDatabase) {
    fun run(intent: Intent) {
        openDatabase(db, intent.getStringExtra("q"))
    }
}
"""
    report = analyze_sources([("app/Db.kt", top_level), ("app/Handler.kt", caller)])
    assert {item["rule_id"] for item in report["findings"]} == {"AST-SQL-CONCAT"}
    assert report["metadata"]["native_flow"]["state"] == "checked"
