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
    # The Activity's inherited member types the result; the same-named top-level
    # function is followed as well, and any abstention on it is recorded.
    report = analyze_sources(files)
    assert {item["rule_id"] for item in report["findings"]} == {"AST-SQL-CONCAT"}


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
    # The same-named function is followed too, so only the findings must agree.
    assert [item["rule_id"] for item in both["findings"]] == [item["rule_id"] for item in alone["findings"]]


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
    [("app/Handle.kt", SCOPE_LAMBDA_LOCAL_FUNCTION)],
    ids=["scope-lambda-local-function"],
)
def test_receiver_typing_does_not_depend_on_a_top_level_opener(path, caller):
    # A local function inside `activity.run { }` sees the Activity receiver, so a
    # same-package top-level opener must not change the findings; which callee runs
    # stays a recorded guess.
    alone = analyze_sources([(path, caller)])
    both = analyze_sources([(path, caller), ("app/Db.kt", TOP_LEVEL_FILE_OPENER)])
    assert [item["rule_id"] for item in both["findings"]] == [item["rule_id"] for item in alone["findings"]]
    assert "opener receiver identity unresolved" in both["metadata"]["native_flow"]["reasons"]


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


# A project opener the flow resolves is always followed; the receiver decision only
# adds the framework type. No reading may drop a flow while coverage says checked.
R5_FILE_OPENER = """package com.example.app
import java.io.File
fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): File = File(name)
"""
R5_CASES = {
    "1-string-return-in-apply": [
        (
            "app/Db.kt",
            """package com.example.app
fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): String = "DELETE FROM t WHERE id = '" + name + "'"
""",
        ),
        (
            "app/H.kt",
            """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Handler(private val db: SQLiteDatabase) {
    fun go(intent: Intent) {
        "scope".apply { val sql = openOrCreateDatabase(intent.getStringExtra("q") ?: "", 0, null); db.execSQL(sql) }
    }
}
""",
        ),
    ],
    "2-shape-third-param-db": [
        (
            "app/Db.kt",
            """package com.example.app
import android.database.sqlite.SQLiteDatabase
fun openOrCreateDatabase(name: String, mode: Int, db: SQLiteDatabase) { db.execSQL("ATTACH DATABASE '" + name + "' AS extra") }
""",
        ),
        (
            "app/Main.kt",
            """package com.example.app
import android.app.Activity
import android.database.sqlite.SQLiteDatabase
class Main(private val db: SQLiteDatabase) : Activity() {
    fun go() { openOrCreateDatabase(intent.getStringExtra("q") ?: "", 0, db) }
}
""",
        ),
    ],
    "3-java-static-method": [
        (
            "app/Db.java",
            """package com.example;
import android.database.sqlite.SQLiteDatabase;
public final class Db {
    static SQLiteDatabase shared;
    public static SQLiteDatabase openOrCreateDatabase(String name, int mode, SQLiteDatabase.CursorFactory factory) {
        shared.execSQL("ATTACH DATABASE '" + name + "' AS extra");
        return shared;
    }
}
""",
        ),
        (
            "app/Main.java",
            """package com.example;
import static com.example.Db.openOrCreateDatabase;
import android.content.Intent;
import android.database.sqlite.SQLiteDatabase;
public class Main {
    static void purge(Intent intent, int mode, SQLiteDatabase.CursorFactory factory) {
        openOrCreateDatabase(intent.getStringExtra("q"), mode, factory);
    }
}
""",
        ),
    ],
    "4.1-local-function-shadow": [
        (
            "app/P.kt",
            """package com.example.app
import android.app.Activity
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class P(private val db: SQLiteDatabase) {
    fun Activity.purge(intent: Intent) {
        fun openOrCreateDatabase(name: String, mode: Int, factory: Any?) { db.execSQL("ATTACH DATABASE '" + name + "' AS extra") }
        openOrCreateDatabase(intent.getStringExtra("q") ?: "", 0, null)
    }
}
""",
        ),
    ],
    "4.2-own-member-anon-activity-init": [
        (
            "app/Repo.kt",
            """package com.example.app
import android.app.Activity
import android.content.Intent
import java.io.File
class Repo {
    fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): File = File(name)
    fun run(intent: Intent) {
        object : Activity() { init { openOrCreateDatabase("app.db", 0, null).execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q")) } }
    }
}
""",
        ),
    ],
    "5-with-local-function": [
        ("app/Db.kt", R5_FILE_OPENER),
        (
            "app/H.kt",
            """package com.example.app
import android.app.Activity
import android.content.Intent
fun handle(activity: Activity, intent: Intent) {
    with(activity) {
        fun runSql() {
            val db = openOrCreateDatabase("app.db", 0, null)
            db.execSQL("DELETE FROM t WHERE id = " + (intent.getStringExtra("q") ?: ""))
        }
        runSql()
    }
}
""",
        ),
    ],
    "6-nested-service-name": [
        (
            "app/Db.kt",
            """package com.example.app
import android.database.sqlite.SQLiteDatabase
lateinit var shared: SQLiteDatabase
fun openOrCreateDatabase(name: String, mode: Int, factory: Any?) { shared.execSQL("ATTACH DATABASE '" + name + "' AS extra") }
""",
        ),
        (
            "app/O.kt",
            """package com.example.app
import android.content.Intent
class Outer {
    class SyncService
    fun SyncService.run(intent: Intent) { openOrCreateDatabase(intent.getStringExtra("q") ?: "", 0, null) }
}
""",
        ),
    ],
}


@pytest.mark.parametrize(
    "name",
    [
        "1-string-return-in-apply",
        "3-java-static-method",
        "4.2-own-member-anon-activity-init",
        "5-with-local-function",
    ],
)
def test_followed_project_openers_keep_their_flows(name):
    report = analyze_sources(R5_CASES[name])
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


@pytest.mark.parametrize("name", sorted(R5_CASES))
def test_a_project_opener_never_disappears_under_checked_coverage(name):
    report = analyze_sources(R5_CASES[name])
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or (
        report["metadata"]["native_flow"]["state"] != "checked"
    )


RECURSIVE_SCOPE_RECEIVER = """package com.example.app
class Handler { fun go() { with(openOrCreateDatabase("a.db", 0, null)) { openOrCreateDatabase("b.db", 0, null) } } }
"""
EXECUTOR_DELEGATE = """package com.example.app
import java.util.concurrent.ExecutorService
class TracingExecutor(d: ExecutorService) : ExecutorService by d {
    fun purge(q: String) { openOrCreateDatabase(q, 0, null) }
}
"""


def test_an_opener_used_as_its_own_scope_receiver_does_not_recurse():
    report = analyze_sources([("app/Db.kt", SINKING_HELPER), ("app/Handler.kt", RECURSIVE_SCOPE_RECEIVER)])
    assert "native flow recursion budget" not in report["metadata"]["native_flow"]["reasons"]


def test_a_non_context_library_base_does_not_claim_checked_over_a_skipped_helper():
    # ExecutorService is no Context; its imported identity keeps the helper followed.
    report = analyze_sources([("app/Db.kt", SINKING_HELPER), ("app/Tracing.kt", EXECUTOR_DELEGATE)])
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or (
        report["metadata"]["native_flow"]["state"] != "checked"
    )


UNKNOWN_LIBRARY_SCOPE_RECEIVER = """package com.example.app
import android.content.Intent
import com.lib.Thing
fun go(x: Thing, i: Intent) {
    val q = i.getStringExtra("q") ?: ""
    with(x) {
        val db = openOrCreateDatabase("app.db", 0, null)
        db.execSQL("DELETE FROM t WHERE id = " + q)
    }
}
"""


def test_keeping_a_project_return_type_for_an_unknown_receiver_is_recorded():
    # `Thing` may be a Context whose inherited member would run; the project function
    # returns File, so the framework type is withheld and the guess is recorded.
    report = analyze_sources(
        [("app/Go.kt", UNKNOWN_LIBRARY_SCOPE_RECEIVER), ("app/Db.kt", TOP_LEVEL_FILE_OPENER)]
    )
    sql = next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or sql["state"] != "checked"
    assert "opener receiver identity unresolved" in report["metadata"]["native_flow"]["reasons"]


# Round-6 review shapes: calls the flow resolves only partly are still followed, a
# Context-shaped overload must fit Context's own parameters, a static method has no
# instance receiver, and named or wrapped scope receivers keep their identity.
R6_FILE_OPENER = """package com.example.app
import java.io.File
fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): File = File(name)
"""
R6_CASES = {
    "1a-default-param-member": [
        (
            "app/S.kt",
            """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Store(private val db: SQLiteDatabase) {
    fun openDatabase(name: String, mode: Int = 0) { db.execSQL("ATTACH DATABASE '" + name + "' AS extra") }
    fun go(intent: Intent) { openDatabase(intent.getStringExtra("q") ?: "") }
}
""",
        )
    ],
    "1b-callable-param": [
        (
            "app/S.kt",
            """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
class Store(private val db: SQLiteDatabase) {
    fun go(intent: Intent, openDatabase: (String) -> String) {
        val sql = openDatabase(intent.getStringExtra("q") ?: "")
        db.execSQL(sql)
    }
}
""",
        )
    ],
    "2a-query-builder-third-string": [
        (
            "app/A.kt",
            """package com.example.app
import android.app.Activity
import android.content.Intent
import android.database.sqlite.SQLiteQueryBuilder
fun openOrCreateDatabase(name: String, mode: Int, table: String): SQLiteQueryBuilder = SQLiteQueryBuilder()
fun Activity.handle(intent: Intent) {
    val qb = openOrCreateDatabase("app.db", 0, "users")
    qb.appendWhere("id = " + intent.getStringExtra("q"))
}
""",
        )
    ],
    "3a-named-with-receiver": [
        ("app/Db.kt", R6_FILE_OPENER),
        (
            "app/H.kt",
            """package com.example.app
import android.app.Activity
import android.content.Intent
fun handle(activity: Activity, intent: Intent) {
    with(receiver = activity) {
        fun runSql() {
            val db = openOrCreateDatabase("app.db", 0, null)
            db.execSQL("DELETE FROM t WHERE id = " + (intent.getStringExtra("q") ?: ""))
        }
        runSql()
    }
}
""",
        ),
    ],
    "3b-bang-receiver": [
        ("app/Db.kt", R6_FILE_OPENER),
        (
            "app/H.kt",
            """package com.example.app
import android.app.Activity
import android.content.Intent
fun handle(activity: Activity?, intent: Intent) {
    with(activity!!) {
        fun runSql() {
            val db = openOrCreateDatabase("app.db", 0, null)
            db.execSQL("DELETE FROM t WHERE id = " + (intent.getStringExtra("q") ?: ""))
        }
        runSql()
    }
}
""",
        ),
    ],
    "4-nested-sync-activity": [
        (
            "app/O.kt",
            """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteQueryBuilder
fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): SQLiteQueryBuilder = SQLiteQueryBuilder()
class Outer {
    class SyncActivity
    fun SyncActivity.run(intent: Intent) {
        val qb = openOrCreateDatabase("app.db", 0, null)
        qb.appendWhere("id = " + intent.getStringExtra("q"))
    }
}
""",
        )
    ],
}


@pytest.mark.parametrize(
    "name",
    [
        "1b-callable-param",
        "2a-query-builder-third-string",
        "3a-named-with-receiver",
        "3b-bang-receiver",
        "4-nested-sync-activity",
    ],
)
def test_round_six_opener_shapes_keep_their_findings(name):
    report = analyze_sources(R6_CASES[name])
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


@pytest.mark.parametrize("name", sorted(R6_CASES))
def test_round_six_opener_shapes_never_claim_checked_without_a_finding(name):
    report = analyze_sources(R6_CASES[name])
    sql = next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or sql["state"] != "checked"


@pytest.mark.parametrize(
    "receiver",
    [
        "with(requireContext())",
        "getApplicationContext().run",
        "getBaseContext().apply",
        "with(applicationContext)",
    ],
)
def test_context_accessor_scope_receivers_keep_the_framework_member(receiver):
    # A scope block whose receiver is a Context accessor supplies Context's member,
    # which Kotlin picks over a same-package top-level function.
    caller = (
        "package com.example.app\nimport android.content.Intent\nclass H {\n    fun go(intent: Intent) { "
        + receiver
        + ' { openOrCreateDatabase("app.db", 0, null).execSQL("DELETE FROM t WHERE id = " + '
        + '(intent.getStringExtra("q") ?: "")) } }\n}\n'
    )
    report = analyze_sources([("app/H.kt", caller), ("app/Db.kt", TOP_LEVEL_FILE_OPENER)])
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


FILE_PARAMETER_OPENER = """package com.example.app
import java.io.File
fun openOrCreateDatabase(name: String, mode: Int, f: File?): File = File(name)
"""
ACTIVITY_EXTENSION_NULL_FACTORY = """package com.example.app
import android.app.Activity
import android.content.Intent
fun Activity.go(i: Intent) {
    val q = i.getStringExtra("q") ?: ""
    val db = openOrCreateDatabase("app.db", 0, null)
    db.execSQL("DELETE FROM t WHERE id = " + q)
}
"""
UNRELATED_HELPER_METHOD = """package com.example.app
class DbHelper { fun openOrCreateDatabase(): Int = 0 }
"""


def test_a_null_factory_argument_lets_the_context_receiver_decide():
    # Context's member takes a null CursorFactory, so it applies and wins over a
    # top-level function whose third parameter is a File.
    report = analyze_sources(
        [("app/Go.kt", ACTIVITY_EXTENSION_NULL_FACTORY), ("app/Db.kt", FILE_PARAMETER_OPENER)]
    )
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


def test_an_unrelated_class_method_does_not_make_framework_openers_limited():
    report = analyze_sources([("app/Main.kt", SDK_ACTIVITY), ("app/DbHelper.kt", UNRELATED_HELPER_METHOD)])
    sql = next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}
    assert sql["state"] == "checked"


@pytest.mark.parametrize(
    "declaration",
    ["val factory: SQLiteDatabase.CursorFactory? = null", "val factory: MyFactory? = null"],
    ids=["framework-factory", "project-factory"],
)
def test_a_typed_factory_argument_lets_the_context_receiver_decide(declaration):
    # Only Context's member takes a CursorFactory argument, so it runs, not the helper.
    caller = (
        "package com.example.app\nimport android.app.Activity\nimport android.content.Intent\n"
        "import android.database.sqlite.SQLiteDatabase\n"
        "abstract class MyFactory : SQLiteDatabase.CursorFactory\n"
        'fun Activity.go(i: Intent) {\n    val q = i.getStringExtra("q") ?: ""\n    '
        + declaration
        + '\n    val db = openOrCreateDatabase("app.db", 0, factory)\n'
        + '    db.execSQL("DELETE FROM t WHERE id = " + q)\n}\n'
    )
    report = analyze_sources([("app/Go.kt", caller), ("app/Db.kt", FILE_PARAMETER_OPENER)])
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


INHERITED_BASE_REPO = """package com.example.app
import android.database.sqlite.SQLiteDatabase
import java.io.File
open class BaseRepo {
    fun openDatabase(name: String): SQLiteDatabase {
        val db = SQLiteDatabase.openOrCreateDatabase(File("x.db"), null)
        db.execSQL("ATTACH DATABASE '" + name + "' AS extra")
        return db
    }
}
"""
INHERITING_CALLER = """package com.example.app
import android.content.Intent
class Main : BaseRepo() {
    fun q(intent: Intent) { openDatabase(intent.dataString ?: "") }
}
"""


def test_an_opener_inherited_from_a_source_base_in_another_file_is_followed():
    # Kotlin resolves the call to BaseRepo.openDatabase; the flow follows it or says why.
    report = analyze_sources([("app/Base.kt", INHERITED_BASE_REPO), ("app/Main.kt", INHERITING_CALLER)])
    sql = next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or sql["state"] != "checked"


def test_an_annotation_mentioning_static_does_not_make_a_java_method_static():
    files = dict(JAVA_STATIC_IMPORT)
    files["app/Main.java"] = files["app/Main.java"].replace(
        "    void purge(", '    @SuppressWarnings("static-access")\n    void purge('
    )
    report = analyze_sources(list(files.items()))
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]}


SAME_PACKAGE_JAVA_ACTIVITY_NAME = [
    ("app/SyncActivity.java", "package com.example.app;\npublic class SyncActivity {}\n"),
    (
        "app/O.kt",
        """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteQueryBuilder
fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): SQLiteQueryBuilder = SQLiteQueryBuilder()
fun SyncActivity.run(intent: Intent) {
    val qb = openOrCreateDatabase("app.db", 0, null)
    qb.appendWhere("id = " + intent.getStringExtra("q"))
}
""",
    ),
]


def test_a_source_class_of_another_language_is_not_a_context_by_name():
    # SyncActivity is a plain Java class, so the project opener's query builder is kept.
    report = analyze_sources(SAME_PACKAGE_JAVA_ACTIVITY_NAME)
    sql = next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or sql["state"] != "checked"


REPO_WITH_OPENER = """package com.example.app
import android.database.sqlite.SQLiteDatabase
import java.io.File
class Repo {
    fun openDatabase(name: String): SQLiteDatabase {
        val db = SQLiteDatabase.openOrCreateDatabase(File("x.db"), null)
        db.execSQL("ATTACH DATABASE '" + name + "' AS extra")
        return db
    }
}
"""
WITH_REPO_CALLER = """package com.example.app
import android.content.Intent
class Main { fun q(intent: Intent, repo: Repo) { with(repo) { openDatabase(intent.dataString ?: "") } } }
"""


def test_a_scope_receiver_method_in_another_file_is_followed_or_recorded():
    report = analyze_sources([("app/Repo.kt", REPO_WITH_OPENER), ("app/Main.kt", WITH_REPO_CALLER)])
    sql = next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or sql["state"] != "checked"


# Round-8 review shapes: an opener is certain only when its arity or the targets'
# declared SQLiteDatabase return proves the callee; every other guess is recorded.
R8_FILE_OPENER = """package com.example.app
import java.io.File
fun openOrCreateDatabase(path: String, flags: Int, cb: Any?): File = File(path)
"""
R8_CASES = {
    "c1-ext-repo-other-file": [
        (
            "app/Repo.kt",
            """package com.example.app
import android.database.sqlite.SQLiteDatabase
class Repo(private val db: SQLiteDatabase) {
    fun openDatabase(name: String) { db.execSQL("ATTACH DATABASE '" + name + "' AS extra") }
}
""",
        ),
        (
            "app/Sync.kt",
            """package com.example.app
import android.content.Intent
fun Repo.attach(intent: Intent) { openDatabase(intent.getStringExtra("q") ?: "") }
""",
        ),
    ],
    "c1-java-anon-base": [
        (
            "app/BaseTask.java",
            """package com.example;
import android.database.sqlite.SQLiteDatabase;
public abstract class BaseTask implements Runnable {
    protected SQLiteDatabase db;
    protected void openDatabase(String name) { db.execSQL("ATTACH DATABASE '" + name + "' AS extra"); }
}
""",
        ),
        (
            "app/Main.java",
            """package com.example;
import android.app.Activity;
public class Main extends Activity {
    void go() { new BaseTask() { public void run() { openDatabase(getIntent().getStringExtra("q")); } }.run(); }
}
""",
        ),
    ],
    "c2-java-base-kotlin-sub": [
        (
            "app/Base.java",
            """package com.example.app;
import android.database.sqlite.SQLiteDatabase;
import java.io.File;
public class BaseRepo {
    protected SQLiteDatabase openDatabase(String name) {
        SQLiteDatabase db = SQLiteDatabase.openOrCreateDatabase(new File("x.db"), null);
        db.execSQL("ATTACH DATABASE '" + name + "' AS extra");
        return db;
    }
}
""",
        ),
        (
            "app/Main.kt",
            """package com.example.app
import android.content.Intent
class Main : BaseRepo() { fun q(intent: Intent) { openDatabase(intent.dataString ?: "") } }
""",
        ),
    ],
    "c3-override-interface-querybuilder": [
        (
            "app/S.kt",
            """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteQueryBuilder
interface Finder { fun openDatabase(): SQLiteQueryBuilder }
class Search : Finder {
    override fun openDatabase(): SQLiteQueryBuilder = SQLiteQueryBuilder()
    fun find(i: Intent) { openDatabase().appendWhere("name = '" + i.getStringExtra("q") + "'") }
}
""",
        )
    ],
    "g1-named-args-reordered": [
        ("app/Db.kt", R8_FILE_OPENER),
        (
            "app/A.kt",
            """package com.example.app
import android.app.Activity
import android.content.Intent
fun Activity.go(intent: Intent) {
    val db = openOrCreateDatabase(factory = null, mode = 0, name = "app.db")
    db.execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q"))
}
""",
        ),
    ],
    "g2-activity-receiver-lambda": [
        ("app/Db.kt", R8_FILE_OPENER),
        (
            "app/R.kt",
            """package com.example.app
import android.app.Activity
import android.content.Intent
class Repository { fun load(intent: Intent) { val q = intent.getStringExtra("q") ?: ""; val read: Activity.() -> Unit = { openOrCreateDatabase("app.db", 0, null).execSQL("DELETE FROM t WHERE id = " + q) } } }
""",
        ),
    ],
    "g3-override-queries-interface": [
        (
            "app/S.kt",
            """package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteQueryBuilder
interface Queries { fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): SQLiteQueryBuilder }
class Store : Queries {
    override fun openOrCreateDatabase(name: String, mode: Int, factory: Any?): SQLiteQueryBuilder = SQLiteQueryBuilder()
    fun go(intent: Intent) { openOrCreateDatabase("app.db", 0, null).appendWhere("id = " + intent.getStringExtra("q")) }
}
""",
        )
    ],
}


@pytest.mark.parametrize("name", sorted(R8_CASES))
def test_round_eight_opener_shapes_never_claim_checked_without_a_finding(name):
    report = analyze_sources(R8_CASES[name])
    sql = next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or sql["state"] != "checked"


# Round-9 review shapes: a call is certain only when resolution covers every source
# callable of that name that could take its arguments; otherwise the guess is recorded.
R9_REPO = """package com.example.app
import android.database.sqlite.SQLiteDatabase
import java.io.File
class Repo {
    fun openDatabase(name: String): SQLiteDatabase {
        val db = SQLiteDatabase.openOrCreateDatabase(File("x.db"), null)
        db.execSQL("ATTACH DATABASE '" + name + "' AS extra")
        return db
    }
}
"""
R9_CASES = {
    "1-with-repo-plus-top-level": [
        ("app/Repo.kt", R9_REPO),
        (
            "app/Main.kt",
            """package com.example.app
import android.content.Intent
class Main { fun q(intent: Intent, repo: Repo) { with(repo) { openDatabase(intent.dataString ?: "") } } }
""",
        ),
        (
            "app/Db.kt",
            """package com.example.app
import android.database.sqlite.SQLiteDatabase
import java.io.File
fun openDatabase(name: String): SQLiteDatabase = SQLiteDatabase.openOrCreateDatabase(File("x.db"), null)
""",
        ),
    ],
    "1-java-base-plus-static-import": [
        (
            "app/BaseRepo.java",
            """package com.example;
import android.database.sqlite.SQLiteDatabase;
public class BaseRepo { protected SQLiteDatabase db; protected void openDatabase(String n) { db.execSQL("ATTACH DATABASE '" + n + "' AS extra"); } }
""",
        ),
        (
            "app/Db.java",
            """package com.example;
public final class Db { public static Object openDatabase(String n) { return null; } }
""",
        ),
        (
            "app/Main.java",
            """package com.example;
import static com.example.Db.openDatabase;
import android.content.Intent;
public class Main extends BaseRepo { void go(Intent i) { String q = i.getStringExtra("q"); openDatabase(q); } }
""",
        ),
    ],
    "2-java-on-demand-static": [
        (
            "app/Db.java",
            """package com.example;
import android.database.sqlite.SQLiteDatabase;
public final class Db { static SQLiteDatabase db; public static void openDatabase(String n) { db.execSQL("ATTACH DATABASE '" + n + "' AS extra"); } }
""",
        ),
        (
            "app/Main.java",
            """package com.example;
import static com.example.Db.*;
import android.content.Intent;
public class Main { void go(Intent intent) { openDatabase(intent.getStringExtra("q")); } }
""",
        ),
    ],
    "3-jbase-kbase-main": [
        (
            "app/JBase.java",
            """package com.example.app;
import android.database.sqlite.SQLiteDatabase;
public class JBase { protected SQLiteDatabase db; protected void openDatabase(String n) { db.execSQL("ATTACH DATABASE '" + n + "' AS extra"); } }
""",
        ),
        ("app/KBase.kt", "package com.example.app\nopen class KBase : JBase()\n"),
        (
            "app/Main.kt",
            """package com.example.app
import android.content.Intent
class Main : KBase() { fun q(intent: Intent) { openDatabase(intent.dataString ?: "") } }
""",
        ),
    ],
    "4-typed-receiver-lambda": [
        ("app/Repo.kt", R9_REPO),
        (
            "app/R.kt",
            """package com.example.app
import android.content.Intent
class Repository { fun load(intent: Intent) { val q = intent.getStringExtra("q") ?: ""; val attach: Repo.() -> Unit = { openDatabase(q) } } }
""",
        ),
    ],
    "control-activity-plain": [
        (
            "app/Main.kt",
            """package com.example.app
import android.app.Activity
class Main : Activity() { fun go() { openOrCreateDatabase("a.db", 0, null).execSQL("DELETE FROM t WHERE id = " + intent.getStringExtra("q")) } }
""",
        )
    ],
}


@pytest.mark.parametrize("name", sorted(R9_CASES))
def test_round_nine_opener_shapes_never_claim_checked_without_a_finding(name):
    report = analyze_sources(R9_CASES[name])
    sql = next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or sql["state"] != "checked"


def test_a_swift_homonym_does_not_make_kotlin_framework_openers_limited():
    swift = (
        "ios/DB.swift",
        "enum DB { static func openOrCreateDatabase(_ a: String, _ b: Int, _ c: Any?) {} }\n",
    )
    report = analyze_sources([("app/Main.kt", SDK_ACTIVITY), swift])
    assert "opener receiver identity unresolved" not in report["metadata"]["native_flow"]["reasons"]


MID_INTERFACE = [
    (
        "app/Repo.kt",
        """package com.example
import android.database.sqlite.SQLiteDatabase
interface Repo { fun getDb(): SQLiteDatabase
    fun openDatabase(name: String) { getDb().execSQL("ATTACH DATABASE '" + name + "' AS extra") } }
""",
    ),
    ("app/Mid.java", "package com.example;\npublic interface Mid extends Repo {}\n"),
    (
        "app/Main.java",
        """package com.example;
import android.app.Activity;
import android.database.sqlite.SQLiteDatabase;
public class Main extends Activity implements Mid {
    public SQLiteDatabase getDb() { return null; }
    void go() { openDatabase(getIntent().getStringExtra("q")); }
}
""",
    ),
]
NINE_LINK_CHAIN = (
    [
        (
            "app/C0.java",
            "package com.example;\nimport android.app.Activity;\nimport android.database.sqlite.SQLiteDatabase;\n"
            "public class C0 extends Activity { protected SQLiteDatabase db; protected void openDatabase(String n) "
            '{ db.execSQL("ATTACH DATABASE \'" + n + "\' AS extra"); } }\n',
        )
    ]
    + [
        (f"app/C{i}.java", f"package com.example;\npublic class C{i} extends C{i - 1} {{}}\n")
        for i in range(1, 10)
    ]
    + [
        (
            "app/Main.java",
            "package com.example;\npublic class Main extends C9 { void go() "
            '{ openDatabase(getIntent().getStringExtra("q")); } }\n',
        )
    ]
)
TWO_DAOS = [
    (
        f"app/{name}.kt",
        f"""package com.example.app
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import java.io.File
class {name} {{
    private fun openDatabase(): SQLiteDatabase = SQLiteDatabase.openOrCreateDatabase(File("x.db"), null)
    fun q(i: Intent) {{ openDatabase().rawQuery("SELECT * FROM t WHERE id = " + i.dataString, null) }}
}}
""",
    )
    for name in ("UserDao", "OrderDao")
]


@pytest.mark.parametrize("files", [MID_INTERFACE, NINE_LINK_CHAIN], ids=["mid-interface", "nine-link-chain"])
def test_inherited_homonyms_beyond_direct_bases_are_recorded(files):
    report = analyze_sources(files)
    sql = next(item for item in report["coverage"] if item["rule_id"] == "AST-SQL-CONCAT")
    assert "AST-SQL-CONCAT" in {item["rule_id"] for item in report["findings"]} or sql["state"] != "checked"


def test_another_class_private_homonym_is_not_a_candidate():
    report = analyze_sources(TWO_DAOS)
    assert "opener receiver identity unresolved" not in report["metadata"]["native_flow"]["reasons"]
