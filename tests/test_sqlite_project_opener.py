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


# Resolution from the call site decides, exactly as the bounded flow resolves calls.
FILE_OPENER = "fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): File = File(name)"
SDK_QUERY = 'openOrCreateDatabase("app.db", 0, null).execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))'
HELPER = """
fun openDatabase(db: SQLiteDatabase, n: String) {
    db.execSQL("ATTACH DATABASE '" + n + "' AS extra")
}
"""
HELPER_CALL = 'val q: String = intent.getStringExtra("q") ?: ""\n        openDatabase(db, q)'
RESOLUTION = {
    "member-extension": [
        (
            "app/Main.kt",
            "package com.example.app\nimport android.app.Activity\nimport java.io.File\n"
            "class Main : Activity() {\n    fun File." + FILE_OPENER[4:].replace("File(name)", "this") + "\n"
            "    fun run() {\n        " + SDK_QUERY + "\n    }\n}\n",
        )
    ],
    "local-function-elsewhere": [
        (
            "app/Main.kt",
            "package com.example.app\nimport android.app.Activity\nimport java.io.File\n"
            "class Main : Activity() {\n    fun other() {\n        " + FILE_OPENER + "\n"
            '        openOrCreateDatabase("x", 0, null)\n    }\n'
            "    fun run() {\n        " + SDK_QUERY + "\n    }\n}\n",
        )
    ],
    "anonymous-activity-init": [
        (
            "app/Run.kt",
            "package com.example.app\nimport android.app.Activity\nimport android.content.Intent\n"
            "fun run(intent: Intent) {\n    object : Activity() {\n        init {\n"
            '            val db = openOrCreateDatabase("app.db", 0, null)\n'
            '            db.execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))\n'
            "        }\n    }\n}\n",
        ),
        ("app/Db.kt", "package com.example.app\nimport java.io.File\n" + FILE_OPENER + "\n"),
    ],
    "activity-calls-project-helper": [
        (
            "app/Main.kt",
            "package com.example.app\nimport android.app.Activity\nimport android.database.sqlite.SQLiteDatabase\n"
            "class Main : Activity() {\n    lateinit var db: SQLiteDatabase\n"
            "    fun run() {\n        " + HELPER_CALL + "\n    }\n}\n" + HELPER,
        )
    ],
    "nested-class-calls-project-helper": [
        (
            "app/Main.kt",
            "package com.example.app\nimport android.app.Activity\nimport android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase\n"
            "class Main : Activity() {\n    class Worker(private val db: SQLiteDatabase) {\n"
            "        fun run(intent: Intent) {\n        " + HELPER_CALL + "\n        }\n    }\n}\n" + HELPER,
        )
    ],
    "sdk-static-import-wins": [
        (
            "app/Main.kt",
            "package com.example.app\nimport android.content.Intent\n"
            "import android.database.sqlite.SQLiteDatabase.openDatabase\n"
            "class Main {\n    fun run(intent: Intent) {\n"
            '        val db = openDatabase("app.db", null, 0)\n'
            '        db.execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))\n    }\n}\n',
        ),
        (
            "app/Db.kt",
            "package com.example.app\nimport java.io.File\n"
            "fun openDatabase(path: String, factory: Any?, flags: Int): File = File(path)\n",
        ),
    ],
    "import-alias-to-project-helper": [
        (
            "app/Main.kt",
            "package com.example.app\nimport android.content.Intent\nimport android.database.sqlite.SQLiteDatabase\n"
            "import com.example.db.execRaw as openDatabase\n"
            "class Main(private val db: SQLiteDatabase) {\n    fun run(intent: Intent) {\n"
            '        openDatabase(db, intent.getStringExtra("q"))\n    }\n}\n',
        ),
        (
            "app/db/Db.kt",
            "package com.example.db\nimport android.database.sqlite.SQLiteDatabase\n"
            "fun execRaw(db: SQLiteDatabase, n: String?) {\n"
            '    db.execSQL("ATTACH DATABASE \'" + n + "\' AS extra")\n}\n',
        ),
    ],
    "package-less-files": [
        ("Db.kt", "import java.io.File\n" + FILE_OPENER + "\n"),
        (
            "Main.kt",
            "import android.content.Intent\nfun run(intent: Intent) {\n"
            '    val db = openOrCreateDatabase("app.db", 0, null)\n'
            '    db.execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))\n}\n',
        ),
    ],
}


@pytest.mark.parametrize("files", list(RESOLUTION.values()), ids=list(RESOLUTION))
def test_opener_identity_follows_call_site_resolution(files):
    report = analyze_sources(files)
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


LOCAL_CLASS_IN_ACTIVITY = """package com.example.app
import android.app.Activity
class Main : Activity() {
    fun run() {
        class Job {
            fun go() {
                val db = openOrCreateDatabase("app.db", 0, null)
                db.execSQL("DELETE FROM t WHERE id = " + (intent.getStringExtra("q") ?: ""))
            }
        }
        Job().go()
    }
}
"""


def test_local_class_sees_the_enclosing_activity_member_before_a_top_level_opener():
    # A local class has the enclosing Activity as an implicit receiver, so Kotlin
    # resolves the call to the inherited Context member, not the top-level function:
    # declaring that function must not change how the call is typed.
    alone = analyze_sources([("app/Main.kt", LOCAL_CLASS_IN_ACTIVITY)])
    both = analyze_sources([("app/Main.kt", LOCAL_CLASS_IN_ACTIVITY), ("app/Db.kt", TOP_LEVEL_FILE_OPENER)])
    assert [item["rule_id"] for item in both["findings"]] == [item["rule_id"] for item in alone["findings"]]
    assert both["metadata"]["native_flow"]["reasons"] == alone["metadata"]["native_flow"]["reasons"]


EXTENSION_RECEIVER = """package com.example.app
import android.app.Activity
import android.content.Intent
fun Activity.purge(i: Intent) {
    val q = i.getStringExtra("q") ?: ""
    openOrCreateDatabase("app.db", 0, null).execSQL("DELETE FROM t WHERE id = " + q)
}
"""
MEMBER_EXTENSION_RECEIVER = """package com.example.app
import android.app.Activity
import android.content.Intent
class Purger {
    fun Activity.purge(i: Intent) {
        val q = i.getStringExtra("q") ?: ""
        openOrCreateDatabase("app.db", 0, null).execSQL("DELETE FROM t WHERE id = " + q)
    }
}
"""


@pytest.mark.parametrize(
    "caller", [EXTENSION_RECEIVER, MEMBER_EXTENSION_RECEIVER], ids=["top-level", "member"]
)
def test_extension_receiver_keeps_the_inherited_member_ahead_of_a_top_level_opener(caller):
    # Kotlin resolves the call to the extension receiver's inherited Context member.
    report = analyze_sources([("app/Purge.kt", caller), ("app/Db.kt", TOP_LEVEL_FILE_OPENER)])
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


# Round-4 external review scenarios: Kotlin and Java pick an implicit receiver's
# inherited Context member only when Context's openOrCreateDatabase can apply.
EXTENSION_PROPERTY = """package com.example.app
import android.content.Context
import android.content.Intent
val Context.purgeDb get() = openOrCreateDatabase("app.db", 0, null)
fun Context.purge(intent: Intent) {
    purgeDb.execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))
}
"""
OWN_MEMBER_WITH_CONTEXT = """package com.example.app
import android.content.Context
import android.content.Intent
import java.io.File
class Repo(private val ctx: Context) {
    fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): File = File(name)
    fun go(intent: Intent) {
        with(ctx) {
            openOrCreateDatabase("app.db", 0, null).execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))
        }
    }
}
"""
JAVA_STATIC_IMPORT = {
    "app/Db.java": """package com.example;
import android.database.sqlite.SQLiteDatabase;
import java.io.File;
public final class Db {
    public static File openOrCreateDatabase(String name, int mode, SQLiteDatabase.CursorFactory factory) {
        return new File(name);
    }
}
""",
    "app/Main.java": """package com.example;
import static com.example.Db.openOrCreateDatabase;
import android.app.Activity;
import android.database.sqlite.SQLiteDatabase;
public class Main extends Activity {
    void purge(String name, int mode, SQLiteDatabase.CursorFactory factory) {
        String q = getIntent().getStringExtra("q");
        openOrCreateDatabase(name, mode, factory).execSQL("DELETE FROM t WHERE id = " + q);
    }
}
""",
}
NON_CONTEXT_SHAPED_HELPER = {
    "app/Db.kt": """package com.example.app
import android.database.sqlite.SQLiteDatabase
fun openOrCreateDatabase(db: SQLiteDatabase, name: String, extra: String) {
    db.execSQL("ATTACH DATABASE '" + name + "' AS " + extra)
}
""",
    "app/Main.kt": """package com.example.app
import android.app.Activity
import android.database.sqlite.SQLiteDatabase
class Main(private val db: SQLiteDatabase) : Activity() {
    fun run() {
        val q: String = intent.getStringExtra("q") ?: ""
        openOrCreateDatabase(db, "aux", q)
    }
}
""",
}
SCOPE_LAMBDA_LOCAL_FUNCTION = """package com.example.app
import android.app.Activity
import android.content.Intent
fun handle(activity: Activity, intent: Intent) {
    activity.run {
        fun runSql() {
            val db = openOrCreateDatabase("app.db", 0, null)
            db.execSQL("DELETE FROM t WHERE id = " + (intent.getStringExtra("q") ?: ""))
        }
        runSql()
    }
}
"""


@pytest.mark.parametrize(
    "files",
    [
        [("app/Repo.kt", OWN_MEMBER_WITH_CONTEXT)],
        list(JAVA_STATIC_IMPORT.items()),
        list(NON_CONTEXT_SHAPED_HELPER.items()),
    ],
    ids=["own-member-in-with", "java-static-import", "non-context-shaped-helper"],
)
def test_receiver_precedence_follows_kotlin_and_java_resolution(files):
    report = analyze_sources(files)
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


@pytest.mark.parametrize(
    ("path", "caller"),
    [("app/Handle.kt", SCOPE_LAMBDA_LOCAL_FUNCTION), ("app/Purge.kt", EXTENSION_PROPERTY)],
    ids=["scope-lambda-local-function", "extension-property"],
)
def test_receiver_typing_does_not_depend_on_a_top_level_opener(path, caller):
    # A local function inside `activity.run { }` and an extension property getter see
    # a Context receiver, so a same-package top-level opener must not change the typing.
    alone = analyze_sources([(path, caller)])
    both = analyze_sources([(path, caller), ("app/Db.kt", TOP_LEVEL_FILE_OPENER)])
    assert [item["rule_id"] for item in both["findings"]] == [item["rule_id"] for item in alone["findings"]]
    assert both["metadata"]["native_flow"]["reasons"] == alone["metadata"]["native_flow"]["reasons"]


# Only a receiver that is a Context supplies the inherited member: a known non-Context
# receiver follows the project function, and an unknown one follows it as well while
# the result keeps the framework type, so neither reading hides a finding silently.
SINKING_HELPER = """package com.example.app
import android.database.sqlite.SQLiteDatabase
fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): SQLiteDatabase {
    val db = SQLiteDatabase.openOrCreateDatabase(":memory:", null)
    db.execSQL("ATTACH DATABASE '" + name + "' AS extra")
    return db
}
"""
STRING_SCOPE_RECEIVER = """package com.example.app
import android.content.Intent
class Handler {
    fun go(intent: Intent) {
        intent.getStringExtra("q")?.apply { openOrCreateDatabase(this, 0, null) }
    }
}
"""
UNKNOWN_SUPERTYPE = """package com.example.app
import android.content.Intent
import android.view.View
class Handler : View.OnClickListener {
    override fun onClick(v: View?) {}
    fun go(intent: Intent) {
        openOrCreateDatabase(intent.getStringExtra("q") ?: "", 0, null)
    }
}
"""


def test_a_non_context_scope_receiver_follows_the_project_opener():
    report = analyze_sources([("app/Db.kt", SINKING_HELPER), ("app/Handler.kt", STRING_SCOPE_RECEIVER)])
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


def test_an_unknown_receiver_follows_the_project_opener_without_claiming_checked():
    report = analyze_sources([("app/Db.kt", SINKING_HELPER), ("app/Handler.kt", UNKNOWN_SUPERTYPE)])
    flow = report["metadata"]["native_flow"]
    # The project opener was followed: either it reports, or the flow records why not.
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or (
        "inherited overload signature unresolved" in flow["reasons"]
    )
    assert flow["state"] != "checked"


DATABASE_RETURNING_OPENER = """package com.example.app
import android.database.sqlite.SQLiteDatabase
fun openOrCreateDatabase(name: String, mode: Int, factory: SQLiteDatabase.CursorFactory?): SQLiteDatabase =
    SQLiteDatabase.openOrCreateDatabase(name, factory)
"""
NON_CONTEXT_SUPERTYPE_CALLER = """package com.example.app
import android.content.Intent
class Repo : Runnable {
    override fun run() {}
    fun q(intent: Intent) {
        openOrCreateDatabase("app.db", 0, null).rawQuery("SELECT * FROM t WHERE id = " + intent.dataString, null)
    }
}
"""


def test_a_followed_opener_declared_to_return_a_database_keeps_that_type():
    # Runnable is no Context, so the project function is followed; when the bounded flow
    # abstains on the call, its declared SQLiteDatabase return still types the sink.
    report = analyze_sources(
        [("app/Db.kt", DATABASE_RETURNING_OPENER), ("app/Repo.kt", NON_CONTEXT_SUPERTYPE_CALLER)]
    )
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}
