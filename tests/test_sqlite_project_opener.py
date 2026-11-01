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
