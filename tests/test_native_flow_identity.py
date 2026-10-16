"""Fresh source-only fixtures: unrelated symbol inventories cannot establish safety."""

from __future__ import annotations

import hashlib

import pytest

from tests.test_native_flow import URL, findings, scan

KOTLIN_CALLER = """package app
import external.route
class Handler {
    val web: WebView = WebView(context)
    fun open(intent: Intent) { web.loadUrl(route(intent.getDataString())) }
}
"""
JAVA_CONSTRUCTOR_CALLER = """package app;
import external.Box;
class Handler {
    WebView web;
    void open(Intent intent) {
        Box box = new Box(intent.getDataString());
        web.loadUrl(box.value);
    }
}
"""
SWIFT_CALLER = """import WebKit
class Handler {
    let web = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
        web.load(URLRequest(url: route(incoming)))
        return true
    }
}
"""


def candidate_and_partial(report):
    assert findings(report, URL), report
    assert all(item["status"] == "candidate" for item in findings(report, URL))
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert report["metadata"]["native_flow"]["reasons"], report
    assert next(item["state"] for item in report["coverage"] if item["rule_id"] == URL) == "partial", report


@pytest.mark.parametrize("reverse", [False, True])
def test_unrelated_kotlin_top_level_constant_cannot_replace_imported_unknown_helper(reverse):
    baseline = scan(("app/Handler.kt", KOTLIN_CALLER))
    candidate_and_partial(baseline)
    sources = [
        ("app/Handler.kt", KOTLIN_CALLER),
        (
            "unused/Safe.kt",
            'package unrelated\nfun route(input: String): String { return "https://safe.example/" }',
        ),
    ]
    report = scan(*(list(reversed(sources)) if reverse else sources))
    candidate_and_partial(report)
    assert report["metadata"]["native_flow"]["evaluations"] == 0


@pytest.mark.parametrize("reverse", [False, True])
def test_unrelated_swift_file_cannot_supply_unproven_module_sanitizer(reverse):
    candidate_and_partial(scan(("App/Handler.swift", SWIFT_CALLER)))
    sources = [
        ("App/Handler.swift", SWIFT_CALLER),
        (
            "Unrelated/Safe.swift",
            'func route(_ input: URL) -> URL { return URL(string: "https://safe.example/")! }',
        ),
    ]
    report = scan(*(list(reversed(sources)) if reverse else sources))
    candidate_and_partial(report)
    assert report["metadata"]["native_flow"]["evaluations"] == 0


@pytest.mark.parametrize("package", ["unrelated", ""])
@pytest.mark.parametrize("reverse", [False, True])
def test_unrelated_java_constructor_keeps_argument_taint_in_unknown_fields(package, reverse):
    candidate_and_partial(scan(("app/Handler.java", JAVA_CONSTRUCTOR_CALLER)))
    sources = [
        ("app/Handler.java", JAVA_CONSTRUCTOR_CALLER),
        (
            "unused/Box.java",
            (f"package {package};\n" if package else "")
            + 'class Box { String value; Box(String input) { this.value = "https://safe.example/"; } }',
        ),
    ]
    report = scan(*(list(reversed(sources)) if reverse else sources))
    candidate_and_partial(report)
    assert report["metadata"]["native_flow"]["evaluations"] == 0
    assert "constructor field mapping unavailable" in report["metadata"]["native_flow"]["reasons"]


@pytest.mark.parametrize(
    "binding", ["same-file", "same-package", "imported", "alias", "qualified", "wildcard"]
)
def test_kotlin_top_level_identity_is_supported_by_source_package_or_import(binding):
    declaration = 'fun route(input: String): String { return "https://safe.example/" }'
    caller = KOTLIN_CALLER
    helper_package = "external"
    if binding == "same-file":
        caller = caller.replace("import external.route\n", "") + "\n" + declaration
        sources = [("app/Handler.kt", caller)]
    else:
        if binding == "same-package":
            helper_package = "app"
            caller = caller.replace("import external.route\n", "")
        elif binding == "alias":
            caller = caller.replace("import external.route", "import external.route as boundRoute").replace(
                "loadUrl(route(", "loadUrl(boundRoute("
            )
        elif binding == "qualified":
            caller = caller.replace("import external.route\n", "").replace(
                "loadUrl(route(", "loadUrl(external.route("
            )
        elif binding == "wildcard":
            caller = caller.replace("import external.route", "import external.*")
        sources = [
            ("app/Handler.kt", caller),
            ("helpers/Safe.kt", f"package {helper_package}\n{declaration}"),
        ]
    report = scan(*sources)
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_same_file_swift_top_level_helper_remains_resolvable():
    report = scan(
        (
            "App/Handler.swift",
            SWIFT_CALLER
            + '\nfunc route(_ input: URL) -> URL { return URL(string: "https://safe.example/")! }',
        )
    )
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked"


@pytest.mark.parametrize(
    "import_line,path",
    [("", "App/Helpers.swift"), ("import func External.route\n", "External/Helpers.swift")],
)
def test_swift_directory_or_scoped_import_does_not_invent_compiler_module_membership(import_line, path):
    report = scan(
        ("App/Handler.swift", import_line + SWIFT_CALLER),
        (path, 'func route(_ input: URL) -> URL { return URL(string: "https://safe.example/")! }'),
    )
    candidate_and_partial(report)


@pytest.mark.parametrize("binding", ["same-file", "same-package", "imported", "qualified"])
def test_java_constructor_identity_resolves_only_source_supported_class(binding):
    declaration = 'class Box { String value; Box(String input) { this.value = "https://safe.example/"; } }'
    caller = JAVA_CONSTRUCTOR_CALLER
    if binding == "same-file":
        sources = [("app/Handler.java", caller.replace("import external.Box;\n", "") + "\n" + declaration)]
    else:
        package = "external"
        if binding == "same-package":
            package = "app"
            caller = caller.replace("import external.Box;\n", "")
        elif binding == "qualified":
            caller = caller.replace("import external.Box;\n", "").replace("new Box(", "new external.Box(")
        sources = [("app/Handler.java", caller), ("helpers/Box.java", f"package {package};\n{declaration}")]
    report = scan(*sources)
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked"


@pytest.mark.parametrize("suffix", ["java", "kt"])
@pytest.mark.parametrize("qualified", [False, True])
def test_unrelated_class_method_cannot_supply_imported_or_qualified_sanitizer(suffix, qualified):
    if suffix == "java":
        caller = "package app; import external.Helper; class Handler { WebView web; void open(Intent input) { web.loadUrl(Helper.route(input.getDataString())); } }"
        helper = 'package unrelated; class Helper { static String route(String input) { return "https://safe.example/"; } }'
    else:
        caller = "package app\nimport external.Helper\nclass Handler { val web: WebView = WebView(context); fun open(input: Intent) { web.loadUrl(Helper.route(input.getDataString())) } }"
        helper = 'package unrelated\nobject Helper { fun route(input: String): String { return "https://safe.example/" } }'
    if qualified:
        caller = caller.replace("Helper.route(", "external.Helper.route(")
    candidate_and_partial(scan((f"App.{suffix}", caller), (f"Unrelated.{suffix}", helper)))


def test_static_java_import_matches_actual_class_identity():
    caller = "package app; import static external.Helper.route; class Handler { WebView web; void open(Intent input) { web.loadUrl(route(input.getDataString())); } }"
    actual = 'package external; class Helper { static String route(String input) { return "https://safe.example/"; } }'
    unrelated = actual.replace("package external", "package unrelated")
    candidate_and_partial(scan(("App.java", caller), ("Unused.java", unrelated)))
    report = scan(("App.java", caller), ("External.java", actual), ("Unused.java", unrelated))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked"


@pytest.mark.parametrize("suffix", ["java", "kt"])
def test_ambiguous_exported_identity_never_establishes_safety(suffix):
    if suffix == "java":
        caller = JAVA_CONSTRUCTOR_CALLER
        helper = 'package external; class Box { String value; Box(String input) { value = "https://safe.example/"; } }'
    else:
        caller = KOTLIN_CALLER
        helper = 'package external\nfun route(input: String): String { return "https://safe.example/" }'
    candidate_and_partial(
        scan((f"App.{suffix}", caller), (f"One.{suffix}", helper), (f"Two.{suffix}", helper))
    )


@pytest.mark.parametrize(
    "helper",
    [
        'package app\nprivate fun route(input: String): String { return "https://safe.example/" }',
        'package app\nfun outer() { fun route(input: String): String { return "https://safe.example/" } }',
    ],
)
def test_inaccessible_kotlin_callable_is_not_a_sanitizer(helper):
    caller = KOTLIN_CALLER.replace("import external.route\n", "")
    candidate_and_partial(scan(("App.kt", caller), ("Other.kt", helper)))


def test_kotlin_extension_receiver_cannot_be_discarded_by_name_and_arity():
    helper = 'package external\nfun String.route(input: String): String { return "https://safe.example/" }'
    candidate_and_partial(scan(("App.kt", KOTLIN_CALLER), ("External.kt", helper)))


@pytest.mark.parametrize("suffix", ["java", "kt"])
def test_type_receiver_cannot_call_an_instance_method_as_a_sanitizer(suffix):
    if suffix == "java":
        caller = "package app; import external.Helper; class Handler { WebView web; void open(Intent input) { web.loadUrl(Helper.route(input.getDataString())); } }"
        helper = 'package external; class Helper { String route(String input) { return "https://safe.example/"; } }'
    else:
        caller = "package app\nimport external.Helper\nclass Handler { val web: WebView = WebView(context); fun open(input: Intent) { web.loadUrl(Helper.route(input.getDataString())) } }"
        helper = 'package external\nclass Helper { fun route(input: String): String { return "https://safe.example/" } }'
    candidate_and_partial(scan((f"App.{suffix}", caller), (f"External.{suffix}", helper)))


@pytest.mark.parametrize("matching_label", [False, True])
def test_swift_argument_label_is_part_of_callable_identity(matching_label):
    caller = SWIFT_CALLER.replace(
        "route(incoming)", "route(safe: incoming)" if matching_label else "route(incoming)"
    )
    helper = '\nfunc route(safe input: URL) -> URL { return URL(string: "https://safe.example/")! }'
    report = scan(("App.swift", caller + helper))
    if matching_label:
        assert not findings(report, URL), report
        assert report["metadata"]["native_flow"]["state"] == "checked"
    else:
        candidate_and_partial(report)


@pytest.mark.parametrize("suffix", ["java", "kt"])
def test_comment_cannot_forge_package_identity(suffix):
    prefix = "/*\npackage external\n*/\n"
    if suffix == "java":
        caller = JAVA_CONSTRUCTOR_CALLER
        helper = 'package unrelated; class Box { String value; Box(String input) { value = "https://safe.example/"; } }'
    else:
        caller = KOTLIN_CALLER
        helper = 'package unrelated\nfun route(input: String): String { return "https://safe.example/" }'
    candidate_and_partial(scan((f"App.{suffix}", caller), (f"Unrelated.{suffix}", prefix + helper)))


def test_resolved_lexical_helper_keeps_actual_captured_caller_taint():
    report = scan(
        (
            "App.kt",
            """package app
class Handler {
    val web: WebView = WebView(context)
    fun open(intent: Intent) {
        val input = intent.getDataString()
        fun route(): String { return input }
        web.loadUrl(route())
    }
}""",
        )
    )
    assert findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_unknown_java_constructor_field_taint_exists_before_any_inventory_match():
    caller = """package app;
class Handler {
    WebView web;
    void open(Intent intent) {
        UnknownBox box = new UnknownBox(intent.getDataString());
        web.loadUrl(box.value);
    }
}"""
    baseline = scan(("App.java", caller))
    candidate_and_partial(baseline)
    unrelated = 'package unrelated; class UnknownBox { String value; UnknownBox(String input) { value = "https://safe.example/"; } }'
    report = scan(("App.java", caller), ("Unused.java", unrelated))
    candidate_and_partial(report)
    assert len(findings(baseline, URL)) == len(findings(report, URL)) == 1


def test_kotlin_default_package_cross_file_function_has_no_module_identity():
    caller = KOTLIN_CALLER.replace("package app\nimport external.route\n", "")
    helper = 'fun route(input: String): String { return "https://safe.example/" }'
    candidate_and_partial(scan(("OneModule/App.kt", caller), ("OtherModule/Safe.kt", helper)))


def test_kotlin_default_package_cross_file_class_has_no_module_identity():
    caller = """class Handler {
    val web: WebView = WebView(context)
    fun open(intent: Intent) { val box = Box(intent.getDataString()); web.loadUrl(box.value) }
}"""
    helper = "class Box(val input: String)"
    candidate_and_partial(scan(("OneModule/App.kt", caller), ("OtherModule/Box.kt", helper)))


@pytest.mark.parametrize("suffix", ["java", "kt"])
def test_unique_source_implicit_no_arg_constructor_is_complete(suffix):
    if suffix == "java":
        source = """package app;
class AccountBridge { void idle() {} }
class Handler { void open() { AccountBridge bridge = new AccountBridge(); bridge.idle(); } }
"""
    else:
        source = """package app
class AccountBridge {
    fun idle() {}
}
class Handler {
    fun open() { val bridge = AccountBridge(); bridge.idle() }
}
"""
    report = scan((f"App.{suffix}", source))
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["evaluations"] == 1, report


def test_explicit_constructor_with_unmatched_signature_remains_partial():
    report = scan(
        (
            "App.java",
            """package app;
class Box { Box(String name) {} }
class Handler { void open() { Box box = new Box(); } }
""",
        )
    )
    assert report["metadata"]["native_flow"]["state"] == "partial", report


def test_imported_framework_file_model_preserves_basename_containment_and_single_io_candidate():
    report = scan(
        (
            "App.kt",
            """package app
import java.io.File
import java.io.FileOutputStream
class Handler {
    fun open(input: Intent, root: File) {
        val name = input.getStringExtra("name")!!
        val unsafe = File(root, name)
        FileOutputStream(unsafe)
        val basename = File(root, File(name).name)
        FileOutputStream(basename)
    }
    fun guarded(input: Intent, root: File) {
        val name = input.getStringExtra("name")!!
        val path = File(root, name)
        if (!path.canonicalPath.startsWith(root.canonicalPath + File.separator)) return
        FileOutputStream(path)
    }
}
""",
        )
    )
    assert len(findings(report)) == 1, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_external_class_named_file_cannot_borrow_framework_basename_safety():
    source = """package app
import external.File
class Handler {
    val web: WebView = WebView(context)
    fun open(input: Intent) { web.loadUrl(File(input.getDataString()).name) }
}
"""
    candidate_and_partial(scan(("App.kt", source)))


def test_framework_nested_intent_model_is_not_intercepted_by_unrelated_source_class():
    caller = """package app
import android.content.Intent
import androidx.core.content.IntentCompat
class Handler {
    fun open(input: Intent) {
        val next = IntentCompat.getParcelableExtra(input, "next", Intent::class.java)
        startActivity(next)
    }
}
"""
    unrelated = """package unrelated
object IntentCompat {
    fun getParcelableExtra(input: Intent, name: String, kind: Class): Intent { return Intent() }
}
"""
    for sources in [[("App.kt", caller)], [("App.kt", caller), ("Unused.kt", unrelated)]]:
        report = scan(*sources)
        assert len(findings(report, "AST-INTENT-REDIRECTION")) == 1, report
        assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_unknown_method_on_a_framework_type_still_retains_taint_and_partial_coverage():
    caller = """package app
import java.io.File
class Handler {
    val web: WebView = WebView(context)
    fun open(input: Intent) { web.loadUrl(File.route(input.getDataString())) }
}
"""
    candidate_and_partial(scan(("App.kt", caller)))


def test_qualified_unknown_receiver_does_not_bind_unrelated_same_name_method():
    report = scan(
        (
            "App.kt",
            """class Handler {
    val web: WebView = WebView(context)
    fun record(input: Intent, flag: Boolean) {
        val destination = "https://safe.example/"
        if (flag) {
            val destination = input.getDataString()
            audit.record(destination)
        }
        web.loadUrl(destination)
    }
}
""",
        )
    )
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["evaluations"] == 0, report


def test_matching_unknown_receiver_signature_remains_partial_without_global_dispatch():
    report = scan(
        (
            "App.java",
            """class Handler {
    WebView web;
    void record(Intent input) {
        String destination = input.getDataString();
        audit.record(destination);
    }
    void help() { web.loadUrl("https://safe.example/"); }
}
""",
        )
    )
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert report["metadata"]["native_flow"]["evaluations"] == 0, report


@pytest.mark.parametrize("local_helper", [False, True])
def test_block_local_kotlin_helper_cannot_resolve_a_call_outside_its_declaration_block(local_helper):
    declaration = (
        'fun route(value: String): String { return "https://safe.example/" }' if local_helper else ""
    )
    caller = f"""package app
import external.route
class Handler {{
    val web: WebView = WebView(context)
    fun open(input: Intent, flag: Boolean) {{
        if (flag) {{ {declaration} }}
        web.loadUrl(route(input.getDataString()))
    }}
}}
"""
    report = scan(("App.kt", caller))
    candidate_and_partial(report)
    assert report["metadata"]["native_flow"]["evaluations"] == 0, report


def test_block_local_kotlin_helper_resolves_after_declaration_in_the_same_block():
    source = """package app
import external.route
class Handler {
    val web: WebView = WebView(context)
    fun open(input: Intent, flag: Boolean) {
        if (flag) {
            fun route(value: String): String { return "https://safe.example/" }
            web.loadUrl(route(input.getDataString()))
        }
    }
}
"""
    report = scan(("App.kt", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["evaluations"] > 0, report


@pytest.mark.parametrize("suffix", ["kt", "swift"])
@pytest.mark.parametrize("binding", ["parameter", "local-value", "unshadowed", "explicit-member"])
def test_lexical_callable_values_take_precedence_over_same_name_native_members(suffix, binding):
    if suffix == "kt":
        parameter = ", route: (String) -> String" if binding in {"parameter", "explicit-member"} else ""
        local = "val route = externalTransform" if binding == "local-value" else ""
        callee = "this.route" if binding == "explicit-member" else "route"
        source = f"""package app
class Handler {{
    val web: WebView = WebView(context)
    fun route(input: String): String {{ return "https://safe.example/" }}
    fun open(intent: Intent{parameter}) {{
        {local}
        web.loadUrl({callee}(intent.getDataString()))
    }}
}}
"""
    else:
        parameter = ", route: (URL) -> URL" if binding in {"parameter", "explicit-member"} else ""
        local = "let route = externalTransform" if binding == "local-value" else ""
        callee = "self.route" if binding == "explicit-member" else "route"
        source = f"""import WebKit
class Handler {{
    let web = WKWebView()
    final func route(_ input: URL) -> URL {{ return URL(string: "https://safe.example/")! }}
    func application(_ app: UIApplication, open incoming: URL{parameter}) {{
        {local}
        web.load(URLRequest(url: {callee}(incoming)))
    }}
}}
"""
    report = scan((f"App.{suffix}", source))
    if binding in {"parameter", "local-value"}:
        candidate_and_partial(report)
        assert "callable value binding unresolved" in report["metadata"]["native_flow"]["reasons"], report
        assert report["metadata"]["native_flow"]["evaluations"] == 0, report
    else:
        assert not findings(report, URL), report
        assert report["metadata"]["native_flow"]["state"] == "checked", report
        assert report["metadata"]["native_flow"]["evaluations"] > 0, report


def test_swift_class_inventory_cannot_classify_an_unbound_kotlin_no_arg_call_as_a_constructor():
    caller = """class Handler {
    fun open() { val web = WebView(context); web.addJavascriptInterface(AccountBridge(), "account") }
}
"""
    baseline = scan(("App.kt", caller))
    combined = scan(
        ("App.kt", caller),
        ("Other.swift", "import WebKit\nclass AccountBridge: WKScriptMessageHandler {}"),
    )
    assert baseline["metadata"]["native_flow"]["state"] == "checked", baseline
    assert combined["metadata"]["native_flow"]["state"] == "checked", combined
    assert combined["metadata"]["native_flow"]["evaluations"] == 0, combined
    assert baseline["findings"] == combined["findings"], combined


def test_java_value_names_do_not_shadow_method_or_constructor_namespaces():
    source = """package app;
class Box {
    String value;
    Box(String input) { value = "https://safe.example/"; }
}
class Handler {
    WebView web;
    private final String route(String input) { return "https://safe.example/"; }
    void open(Intent input, String route, String Box) {
        web.loadUrl(route(input.getDataString()));
        Box box = new Box(input.getDataString());
        web.loadUrl(box.value);
    }
}
"""
    report = scan(("App.java", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("receiver", ["", "this."])
@pytest.mark.parametrize("override", [False, True])
def test_overridable_java_same_receiver_call_never_supplies_a_sanitizer(receiver, override):
    source = f"""class Handler {{
    WebView web;
    String route(String input) {{ return "https://safe.example/"; }}
    void open(Intent input) {{ web.loadUrl({receiver}route(input.getDataString())); }}
}}
"""
    if override:
        source += "class Child extends Handler { @Override String route(String input) { return input; } }"
    report = scan(("App.java", source))
    candidate_and_partial(report)
    assert "receiver runtime dispatch unresolved" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("closed", ["private", "final", "static", "final-class"])
def test_java_declared_closed_dispatch_preserves_constant_helper_positive(closed):
    method = "" if closed == "final-class" else closed + " "
    kind = "final class" if closed == "final-class" else "class"
    source = f"""{kind} Handler {{
    WebView web;
    {method}String route(String input) {{ return "https://safe.example/"; }}
    void open(Intent input) {{ web.loadUrl(route(input.getDataString())); }}
}}
"""
    report = scan(("App.java", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("receiver", ["", "self."])
def test_original_nonfinal_swift_member_remains_a_partial_candidate(receiver):
    source = f"""import WebKit
class Handler {{
    let web = WKWebView()
    func route(_ input: URL) -> URL {{ return URL(string: "https://safe.example/")! }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {{
        web.load(URLRequest(url: {receiver}route(incoming)))
    }}
}}
"""
    candidate_and_partial(scan(("App.swift", source)))


@pytest.mark.parametrize("closed", ["private", "final", "final-class", "struct"])
def test_swift_declared_closed_dispatch_preserves_constant_helper_positive(closed):
    method = closed + " " if closed in {"private", "final"} else ""
    kind = {"final-class": "final class", "struct": "struct"}.get(closed, "class")
    source = f"""import WebKit
{kind} Handler {{
    let web = WKWebView()
    {method}func route(_ input: URL) -> URL {{ return URL(string: "https://safe.example/")! }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {{
        web.load(URLRequest(url: self.route(incoming)))
    }}
}}
"""
    report = scan(("App.swift", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("closed", [False, True])
def test_kotlin_open_member_is_partial_but_default_final_member_remains_supported(closed):
    modifier = "" if closed else "open "
    source = f"""open class Handler {{
    val web: WebView = WebView(context)
    {modifier}fun route(input: String): String {{ return "https://safe.example/" }}
    fun open(input: Intent) {{ web.loadUrl(this.route(input.getDataString())) }}
}}
"""
    report = scan(("App.kt", source))
    if closed:
        assert not findings(report, URL), report
        assert report["metadata"]["native_flow"]["state"] == "checked", report
    else:
        candidate_and_partial(report)


@pytest.mark.parametrize("helper", ["idle-path", "idle-allocation", "containment"])
def test_original_overridable_java_guard_and_idle_controls_remain_uncertain(helper):
    sources = {
        "idle-path": """class Handler {
    File output;
    void open(Intent input, File root) {
        output = new File(root, input.getStringExtra("name"));
        idle();
        if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
        new FileOutputStream(output);
    }
    void idle() {}
}""",
        "idle-allocation": """class Box {
    String name;
    Box(String value) { name = value; }
    String get() { return name; }
}
class Handler {
    Box box;
    void open(Intent input) {
        box = new Box(input.getStringExtra("name"));
        idle();
        new FileOutputStream(box.get());
    }
    void idle() {}
}""",
        "containment": """class Handler {
    void entry(Intent input, File root) {
        File output = new File(root, input.getStringExtra("name"));
        write(output, root);
    }
    void write(File output, File root) {
        if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
        new FileOutputStream(output);
    }
}""",
    }
    report = scan(("App.java", sources[helper]))
    assert findings(report), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "receiver runtime dispatch unresolved" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("member", [False, True])
def test_virtual_writes_cannot_erase_receiver_or_argument_field_taint(member):
    if member:
        source = """class Handler {
    WebView web;
    String value;
    void clear(String input) { value = "https://safe.example/"; }
    void open(Intent input) {
        value = input.getDataString();
        this.clear(value);
        web.loadUrl(value);
    }
}
class Child extends Handler { @Override void clear(String input) { value = input; } }
"""
    else:
        source = """class Box {
    String value;
    Box(String input) { value = input; }
}
class Handler {
    WebView web;
    void clear(Box box) { box.value = "https://safe.example/"; }
    void open(Intent input) {
        Box box = new Box(input.getDataString());
        clear(box);
        web.loadUrl(box.value);
    }
}
class Child extends Handler { @Override void clear(Box box) {} }
"""
    candidate_and_partial(scan(("App.java", source)))


def test_exact_java_allocation_type_propagates_into_nested_this_summaries_and_cache(monkeypatch):
    from mobile_audit.native_flow import NativeFlow

    observed = []
    original = NativeFlow.call

    def capture(self, analyzer, call, frame, receiver, args):
        result = original(self, analyzer, call, frame, receiver, args)
        if call.name == "inner":
            observed.append((self.concrete_receiver(analyzer, call, receiver), list(frame.call_results)))
        return result

    monkeypatch.setattr(NativeFlow, "call", capture)
    source = """class Helper {
    String outer(String input) { return this.inner(input); }
    String inner(String input) { return "https://safe.example/"; }
}
class Handler {
    WebView web;
    void open(Intent input, Helper unknown) {
        Helper exact = new Helper();
        web.loadUrl(exact.outer(input.getDataString()));
        web.loadUrl(unknown.outer(input.getDataString()));
    }
}
"""
    report = scan(("App.java", source))
    matches = findings(report, URL)
    assert len(matches) == 1, report
    assert matches[0]["evidence"][0]["line"] == 10, report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    exact = [(context, keys) for context, keys in observed if context is not None]
    assert exact and all(context[0] == "Helper" for context, _keys in exact), observed
    assert all(any(key[-1] == context for key in keys) for context, keys in exact), observed
    assert any(context is None for context, _keys in observed), observed


def test_exact_imported_sdk_sinks_defer_to_existing_models_without_native_body_uncertainty():
    source = """import android.content.Intent;
import android.webkit.WebView;
import android.webkit.SslErrorHandler;
import android.app.PendingIntent;
import android.database.sqlite.SQLiteDatabase;
import android.util.Log;
import javax.crypto.Cipher;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
class Handler {
    WebView web;
    void open(Intent input, SQLiteDatabase db, SslErrorHandler handler) {
        web.loadUrl(input.getDataString());
        handler.proceed();
        Cipher.getInstance("AES");
        MessageDigest.getInstance("MD5");
        new SecretKeySpec("literal".getBytes(), "AES");
        db.execSQL("SELECT * FROM items WHERE name=" + input.getDataString());
        Log.d("tag", input.getDataString());
        PendingIntent.getActivity(context, 0, new Intent("app.INTERNAL"), PendingIntent.FLAG_MUTABLE);
    }
}
"""
    report = scan(("App.java", source))
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    for rule in [
        URL,
        "AST-CRYPTO-ECB",
        "AST-CRYPTO-WEAK-HASH",
        "AST-CRYPTO-HARDCODED-KEY",
        "AST-SQL-CONCAT",
        "AST-PENDINGINTENT-MUTABLE",
    ]:
        assert findings(report, rule), report


@pytest.mark.parametrize("direct_expression", [False, True])
@pytest.mark.parametrize("anonymous", [False, True])
def test_java_anonymous_override_never_receives_base_allocation_dispatch_proof(direct_expression, anonymous):
    allocation = "new Helper()"
    if anonymous:
        allocation += " { @Override String route(String input) { return input; } }"
    declaration = "" if direct_expression else f"Helper helper = {allocation};"
    receiver = allocation if direct_expression else "helper"
    source = f"""class Helper {{
    String route(String input) {{ return "https://safe.example/"; }}
}}
class Handler {{
    WebView web;
    void open(Intent input) {{
        {declaration}
        web.loadUrl({receiver}.route(input.getDataString()));
    }}
}}
"""
    report = scan(("App.java", source))
    if anonymous:
        candidate_and_partial(report)
        assert "anonymous allocation dispatch unresolved" in report["metadata"]["native_flow"]["reasons"], (
            report
        )
    else:
        assert not findings(report, URL), report
        assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_anonymous_subclass_nested_this_call_preserves_actual_caller_taint():
    source = """class FreshBase {
    String route(String input) { return "https://safe.example/"; }
    void open(String input, WebView browser) { browser.loadUrl(this.route(input)); }
}
class Handler {
    WebView web;
    void entry(Intent input) {
        FreshBase helper = new FreshBase() { @Override String route(String input) { return input; } };
        helper.open(input.getDataString(), web);
    }
}
"""
    report = scan(("App.java", source))
    candidate_and_partial(report)
    assert any(
        step["line"] == 9
        for item in findings(report, URL)
        for evidence in item["evidence"]
        for step in evidence["flow"]
    ), report


def test_anonymous_subclass_cannot_clear_constructor_argument_field_taint():
    source = """class Helper {
    String value;
    Helper(String input) { value = input; }
    void clear() { value = "https://safe.example/"; }
}
class Handler {
    WebView web;
    void open(Intent input) {
        Helper helper = new Helper(input.getDataString()) { @Override void clear() {} };
        helper.clear();
        web.loadUrl(helper.value);
    }
}
"""
    candidate_and_partial(scan(("App.java", source)))


def test_ordinary_and_anonymous_allocations_keep_distinct_nested_dispatch_cache_contexts(monkeypatch):
    from mobile_audit.native_flow import NativeFlow

    allocations = []
    original = NativeFlow.allocation

    def capture(self, analyzer, call, declared, identity):
        original(self, analyzer, call, declared, identity)
        if call.name == "Helper":
            allocations.append(
                (
                    any(child.type == "class_body" for child in call.node.named_children),
                    self.allocations.get(identity),
                )
            )

    monkeypatch.setattr(NativeFlow, "allocation", capture)
    source = """class Helper {
    String route(String input) { return "https://safe.example/"; }
}
class Handler {
    WebView web;
    static String forward(Helper helper, String input) { return helper.route(input); }
    void open(Intent input) {
        Helper exact = new Helper();
        Helper anonymous = new Helper() { @Override String route(String input) { return input; } };
        web.loadUrl(forward(exact, input.getDataString()));
        web.loadUrl(forward(anonymous, input.getDataString()));
    }
}
"""
    report = scan(("App.java", source))
    matches = findings(report, URL)
    assert len(matches) == 1, report
    assert matches[0]["evidence"][0]["line"] == 11, report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert any(not anonymous and owner == "Helper" for anonymous, owner in allocations), allocations
    assert any(anonymous for anonymous, _owner in allocations), allocations
    assert all(owner is None for anonymous, owner in allocations if anonymous), allocations


@pytest.mark.parametrize("static_import", [False, True])
def test_anonymous_method_cannot_become_a_surrounding_class_or_imported_helper(static_import):
    prefix = "import static external.Helper.route;\n" if static_import else ""
    source = (
        prefix
        + """class Handler {
    WebView web;
    void open(Intent input) {
        Object ignored = new Object() {
            String route(String value) { return "https://safe.example/"; }
        };
        web.loadUrl(route(input.getDataString()));
    }
}
"""
    )
    report = scan(("App.java", source))
    candidate_and_partial(report)
    assert report["metadata"]["native_flow"]["evaluations"] == 0, report
    assert "anonymous callable scope unavailable" in report["metadata"]["native_flow"]["reasons"], report


def test_named_nested_class_still_has_a_proven_ordinary_java_allocation():
    source = """class Handler {
    WebView web;
    static class Nested {
        String route(String input) { return "https://safe.example/"; }
    }
    void open(Intent input) {
        Handler.Nested helper = new Handler.Nested();
        web.loadUrl(helper.route(input.getDataString()));
    }
}
"""
    report = scan(("App.java", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["evaluations"] > 0, report


@pytest.mark.parametrize("placement", ["local", "member"])
@pytest.mark.parametrize("imported", [False, True])
def test_java_lexical_class_cannot_borrow_top_level_or_imported_allocation_identity(placement, imported):
    shadow = "class Helper { String route(String value) { return value; } }"
    source = f"""package app;
{"import external.Helper;" if imported else ""}
class Handler {{
    WebView web;
    {"static " + shadow if placement == "member" else ""}
    void open(Intent input) {{
        {shadow if placement == "local" else ""}
        Helper helper = new Helper();
        web.loadUrl(helper.route(input.getDataString()));
    }}
}}
"""
    helper = f"""package {"external" if imported else "app"};
class Helper {{ String route(String value) {{ return "https://safe.example/"; }} }}
"""
    report = scan(("app/Handler.java", source), ("helpers/Helper.java", helper))
    candidate_and_partial(report)
    assert report["metadata"]["native_flow"]["evaluations"] == 0, report


@pytest.mark.parametrize("placement", ["local", "member"])
def test_kotlin_lexical_class_cannot_borrow_package_class_identity(placement):
    shadow = "class Helper {\nfun route(value: String): String { return value }\n}"
    source = f"""package app
class Helper {{
    fun route(value: String): String {{ return "https://safe.example/" }}
}}
class Handler {{
    val web: WebView = WebView(context)
    {shadow if placement == "member" else ""}
    fun open(input: Intent) {{
        {shadow if placement == "local" else ""}
        val helper = Helper()
        web.loadUrl(helper.route(input.getDataString()))
    }}
}}
"""
    report = scan(("App.kt", source))
    candidate_and_partial(report)
    assert report["metadata"]["native_flow"]["evaluations"] == 0, report


@pytest.mark.parametrize("method_parameter", [False, True])
def test_java_type_parameter_cannot_borrow_final_package_class_sanitizer(method_parameter):
    source = f"""package app;
interface Routing {{ String route(String value); }}
final class Helper {{ String route(String value) {{ return "https://safe.example/"; }} }}
class Handler{"" if method_parameter else "<Helper extends Routing>"} {{
    WebView web;
    {"<Helper extends Routing> " if method_parameter else ""}void open(Intent input, Helper helper) {{
        web.loadUrl(helper.route(input.getDataString()));
    }}
}}
"""
    candidate_and_partial(scan(("App.java", source)))


def test_kotlin_type_parameter_cannot_borrow_final_package_class_sanitizer():
    source = """package app
interface Routing {
    fun route(value: String): String
}
class Helper {
    fun route(value: String): String { return "https://safe.example/" }
}
class Handler<Helper: Routing> {
    val web: WebView = WebView(context)
    fun open(input: Intent, helper: Helper) { web.loadUrl(helper.route(input.getDataString())) }
}
"""
    candidate_and_partial(scan(("App.kt", source)))


@pytest.mark.parametrize("placement", ["local", "member", "type-parameter"])
def test_swift_lexical_alias_or_type_parameter_cannot_borrow_static_class_sanitizer(placement):
    source = f"""import WebKit
protocol Routing {{ static func route(_ value: URL) -> URL }}
final class Helper {{
    static func route(_ value: URL) -> URL {{ return URL(string: "https://safe.example/")! }}
}}
class Handler{"<Helper: Routing>" if placement == "type-parameter" else ""} {{
    let web = WKWebView()
    {"typealias Helper = ExternalRouting" if placement == "member" else ""}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        {"typealias Helper = ExternalRouting" if placement == "local" else ""}
        web.load(URLRequest(url: Helper.route(incoming)))
        return true
    }}
}}
"""
    candidate_and_partial(scan(("App.swift", source)))


@pytest.mark.parametrize("qualified", [False, True])
def test_java_shadowed_sdk_file_cannot_borrow_basename_safety(qualified):
    source = f"""package app;
import java.io.File;
import java.io.FileOutputStream;
class Handler {{
    static class File {{
        String value;
        File(String input) {{ value = input; }}
        String getName() {{ return value; }}
    }}
    void open(Intent input) {{
        new FileOutputStream(new {"java.io.File" if qualified else "File"}(input.getStringExtra("name")).getName());
    }}
}}
"""
    report = scan(("App.java", source))
    if qualified:
        assert not findings(report), report
        assert report["metadata"]["native_flow"]["state"] == "checked", report
    else:
        assert findings(report), report
        assert report["metadata"]["native_flow"]["state"] == "partial", report
        assert report["metadata"]["native_flow"]["evaluations"] == 0, report


def test_qualified_sdk_spelling_with_lexical_first_segment_cannot_borrow_basename_safety():
    source = """package app;
import java.io.FileOutputStream;
class Handler {
    static class java {
        static class io {
            static class File {
                String value;
                File(String input) { value = input; }
                String getName() { return value; }
            }
        }
    }
    void open(Intent input) {
        new FileOutputStream(new java.io.File(input.getStringExtra("name")).getName());
    }
}
"""
    report = scan(("App.java", source))
    assert findings(report), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize("safe_package_helper", [False, True])
@pytest.mark.parametrize("inheritance", ["extends Parent", "implements Parent", "enclosing"])
def test_java_inherited_member_type_precedes_unrelated_package_class(safe_package_helper, inheritance):
    parent_kind = "interface" if inheritance == "implements Parent" else "class"
    caller = f"""package app;
{parent_kind} Parent {{
    public static class Helper {{ public String route(String value) {{ return value; }} }}
}}
class Handler {"extends Parent" if inheritance == "enclosing" else inheritance} {{
    {"class Inner {" if inheritance == "enclosing" else ""}
    WebView web;
    void open(Intent input) {{
        Helper helper = new Helper();
        web.loadUrl(helper.route(input.getDataString()));
    }}
    {"}" if inheritance == "enclosing" else ""}
}}
"""
    sources = [("app/Handler.java", caller)]
    if safe_package_helper:
        sources.append(
            (
                "app/Helper.java",
                'package app; class Helper { String route(String value) { return "https://safe.example/"; } }',
            )
        )
    report = scan(*sources)
    candidate_and_partial(report)
    assert report["metadata"]["native_flow"]["evaluations"] == 0, report


@pytest.mark.parametrize("safe_package_helper", [False, True])
@pytest.mark.parametrize("wildcard", [False, True])
def test_java_static_type_import_precedes_unrelated_package_class(safe_package_helper, wildcard):
    caller = f"""package app;
import static external.Parent.{"*" if wildcard else "Helper"};
class Handler {{
    WebView web;
    void open(Intent input) {{
        Helper helper = new Helper();
        web.loadUrl(helper.route(input.getDataString()));
    }}
}}
"""
    sources = [
        ("app/Handler.java", caller),
        (
            "external/Parent.java",
            """package external;
public class Parent {
    public static class Helper { public String route(String value) { return value; } }
}
""",
        ),
    ]
    if safe_package_helper:
        sources.append(
            (
                "app/Helper.java",
                'package app; class Helper { String route(String value) { return "https://safe.example/"; } }',
            )
        )
    report = scan(*sources)
    candidate_and_partial(report)
    assert report["metadata"]["native_flow"]["evaluations"] == 0, report


@pytest.mark.parametrize("represented_parent", [False, True])
def test_inherited_qualified_sdk_root_never_supplies_basename_safety(represented_parent):
    caller = """package app;
import java.io.FileOutputStream;
class Handler extends Parent {
    void open(Intent input) {
        new FileOutputStream(new java.io.File(input.getStringExtra("name")).getName());
    }
}
"""
    sources = [("app/Handler.java", caller)]
    if represented_parent:
        sources.append(
            (
                "app/Parent.java",
                """package app;
class Parent {
    static class java {
        static class io {
            static class File {
                String value;
                File(String input) { value = input; }
                String getName() { return value; }
            }
        }
    }
}
""",
            )
        )
    report = scan(*sources)
    assert findings(report), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize("suffix", ["kt", "swift"])
def test_unknown_inherited_type_root_cannot_borrow_same_file_sanitizer(suffix):
    if suffix == "kt":
        source = """package app
class Helper {
    fun route(value: String): String { return "https://safe.example/" }
}
class Handler: ExternalParent() {
    val web: WebView = WebView(context)
    fun open(input: Intent) {
        val helper = Helper()
        web.loadUrl(helper.route(input.getDataString()))
    }
}
"""
    else:
        source = """import WebKit
final class Helper {
    static func route(_ value: URL) -> URL { return URL(string: "https://safe.example/")! }
}
class Handler: ExternalParent {
    let web = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
        web.load(URLRequest(url: Helper.route(incoming)))
        return true
    }
}
"""
    candidate_and_partial(scan((f"App.{suffix}", source)))


@pytest.mark.parametrize("inherited", [False, True])
@pytest.mark.parametrize("canonical_guard", [False, True])
def test_framework_path_safety_requires_resolved_type_root_while_input_taint_survives(
    inherited, canonical_guard
):
    expression = (
        'val path = File(root, input.getStringExtra("name"))\n'
        "        if (!path.canonicalPath.startsWith(root.canonicalPath + File.separator)) return\n"
        "        FileOutputStream(path)"
        if canonical_guard
        else 'FileOutputStream(File(input.getStringExtra("name")).name)'
    )
    source = f"""package app
import android.content.Intent
import java.io.File
import java.io.FileOutputStream
class Handler{": Activity()" if inherited else ""} {{
    fun open(input: Intent, root: File) {{
        {expression}
    }}
}}
"""
    report = scan(("App.kt", source))
    if inherited:
        assert findings(report), report
        assert report["metadata"]["native_flow"]["state"] == "partial", report
    else:
        assert not findings(report), report
        assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_unknown_inherited_sdk_type_keeps_nested_intent_compat_source_provenance():
    source = """package app
import android.content.Intent
import androidx.core.content.IntentCompat
class Handler: Activity() {
    fun open(input: Intent) {
        val nested = IntentCompat.getParcelableExtra(input, "next", Intent::class.java)
        startActivity(nested)
    }
}
"""
    report = scan(("App.kt", source))
    assert findings(report, "AST-INTENT-REDIRECTION"), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


ORIGINAL_INHERITED_PATHS_KT = """package com.example.breadth

import android.app.Activity
import android.content.Intent
import android.provider.OpenableColumns
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

class Files : Activity() {
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val uri = data?.data ?: return
        var name = "default"
        contentResolver.query(uri, null, null, null, null)?.use {
            val index = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (it.moveToFirst()) {
                name = it.getString(index)
            }
        }
        val target = File(filesDir, name)
        FileOutputStream(target).use { it.write(1) }
        val safe = File(filesDir, File(name).name)
        val extra = File(cacheDir, intent.getStringExtra("file") ?: "x")
    }

    fun unzip(stream: ZipInputStream, dir: File) {
        var entry = stream.nextEntry
        while (entry != null) {
            val out = File(dir, entry.name)
            entry = stream.nextEntry
        }
    }

    fun guarded(stream: ZipInputStream, dir: File) {
        val entry = stream.nextEntry ?: return
        val out = File(dir, entry.name)
        if (!out.canonicalPath.startsWith(dir.canonicalPath + File.separator)) {
            throw SecurityException("zip slip")
        }
    }

    fun local() {
        val file = File(filesDir, "settings.json")
    }
}
"""


ORIGINAL_INHERITED_FINAL_KT = """package com.example.breadth

import android.app.Activity
import android.content.ComponentName
import android.content.Intent
import android.webkit.WebView
import java.io.File
import java.io.FileOutputStream
import java.util.zip.ZipInputStream

class Final : Activity() {
    fun unzip(zis: ZipInputStream, dest: File) {
        val entry = zis.nextEntry ?: return
        if (".." in entry.name) return
        FileOutputStream(File(dest, entry.name))
    }

    fun unzipSlash(zis: ZipInputStream, dest: File) {
        val entry = zis.nextEntry ?: return
        if (entry.name.contains("../")) return
        FileOutputStream(File(dest, entry.name))
    }

    fun forward() {
        val next = intent.getParcelableExtra<Intent>("next") ?: return
        val target: ComponentName? = next.component
        if (target == null || target.packageName != packageName) return
        startActivity(next)
    }

    fun always(view: WebView) {
        var url = intent.getStringExtra("u")
        run { url = "https://example.com/home" }
        view.loadUrl(url)
    }
}
"""


ORIGINAL_INHERITED_SWIFT_URL_ALIAS = """
            class LinkHandler: UIViewController {
                private var browser: WKWebView!
                func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
                    let components = URLComponents(url: incoming, resolvingAgainstBaseURL: false)
                    let destination = components?.queryItems?.first?.value
                    browser.load(URLRequest(url: URL(string: destination!)!))
                    return true
                }
            }
            """


@pytest.mark.parametrize(
    "source,expected_original_lines",
    [(ORIGINAL_INHERITED_PATHS_KT, {20, 23, 29}), (ORIGINAL_INHERITED_FINAL_KT, {21})],
)
def test_original_inherited_path_controls_keep_existing_candidates_and_declare_type_uncertainty(
    source, expected_original_lines
):
    from mobile_audit.source_analysis import analyze_sources

    report = analyze_sources([("OriginalInherited.kt", source)])
    matches = findings(report)
    assert expected_original_lines <= {item["evidence"][0]["line"] for item in matches}, report
    assert all(item["status"] == "candidate" for item in matches), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "constructor field mapping unavailable" in report["metadata"]["native_flow"]["reasons"], report


def test_original_inherited_swift_url_alias_keeps_platform_input_candidate_and_declares_uncertainty():
    from mobile_audit.source_analysis import analyze_sources

    report = analyze_sources([("OriginalInherited.swift", ORIGINAL_INHERITED_SWIFT_URL_ALIAS)])
    candidate_and_partial(report)
    assert any(
        source["kind"].startswith("iOS application URL callback parameter")
        for item in findings(report, URL)
        for evidence in item["evidence"]
        for source in evidence["sources"]
    ), report


def test_unresolved_inherited_type_receiver_cannot_borrow_generic_uri_host_guard_safety():
    source = """class Handler extends ExternalParent {
    WebView web;
    void open(Intent input) {
        String destination = input.getStringExtra("url");
        Uri parsed = Uri.parse(destination);
        if ("https".equals(parsed.getScheme()) && "safe.example".equals(parsed.getHost())) {
            web.loadUrl(destination);
        }
    }
}
"""
    candidate_and_partial(scan(("App.java", source)))


@pytest.mark.parametrize("base_provided", [False, True])
@pytest.mark.parametrize("unknown_argument", [False, True])
@pytest.mark.parametrize("explicit_this", [False, True])
def test_inherited_java_overload_cannot_bind_private_same_arity_incompatible_sanitizer(
    base_provided, unknown_argument, explicit_this
):
    argument = "make(input)" if unknown_argument else "input"
    caller = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Handler extends Base {{
    private String route(String text) {{ return "https://safe.example/"; }}
    void open(Intent input, WebView web) {{
        web.loadUrl({"this." if explicit_this else ""}route({argument}));
    }}
}}
"""
    sources = [("app/Handler.java", caller)]
    if base_provided:
        sources.append(
            (
                "app/Base.java",
                """package app;
import android.content.Intent;
class Base {
    String route(Intent input) { return input.getDataString(); }
    Intent make(Intent input) { return input; }
}
""",
            )
        )
    report = scan(*sources)
    candidate_and_partial(report)
    flow = report["metadata"]["native_flow"]
    assert flow["evaluations"] == 0, report
    assert any(
        item["reason"] == "inherited overload signature unresolved" and item["call"] == "route"
        for item in flow["partial_details"]
    ), report


@pytest.mark.parametrize("suffix", ["kt", "swift"])
@pytest.mark.parametrize("base_provided", [False, True])
def test_inherited_native_overload_cannot_bind_private_same_arity_incompatible_sanitizer(
    suffix, base_provided
):
    if suffix == "kt":
        caller = """package app
import android.content.Intent
import android.webkit.WebView
class Handler: Base() {
    private fun route(text: String): String { return "https://safe.example/" }
    fun open(input: Intent, web: WebView) { web.loadUrl(route(input)) }
}
"""
        base = """package app
import android.content.Intent
open class Base {
    fun route(input: Intent): String { return input.getDataString() }
}
"""
    else:
        caller = """import WebKit
class Handler: Base {
    let web = WKWebView()
    private func route(_ text: String) -> URL { return URL(string: "https://safe.example/")! }
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
        web.load(URLRequest(url: route(incoming)))
        return true
    }
}
"""
        base = """import Foundation
class Base {
    func route(_ incoming: URL) -> URL { return incoming }
}
"""
    sources = [(f"App.{suffix}", caller)]
    if base_provided:
        sources.append((f"Base.{suffix}", base))
    report = scan(*sources)
    candidate_and_partial(report)
    assert "inherited overload signature unresolved" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("inherited", [False, True])
@pytest.mark.parametrize("explicit_this", [False, True])
def test_exact_private_string_signature_keeps_direct_summary(inherited, explicit_this):
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Handler{" extends Base" if inherited else ""} {{
    private String route(String text) {{ return "https://safe.example/"; }}
    void open(Intent input, WebView web) {{
        String text = input.getDataString();
        web.loadUrl({"this." if explicit_this else ""}route(text));
    }}
}}
"""
    report = scan(("App.java", source))
    assert not findings(report, URL), report
    flow = report["metadata"]["native_flow"]
    assert flow["evaluations"] == 1, report
    assert "inherited overload signature unresolved" not in flow["reasons"], report
    if not inherited:
        assert flow["state"] == "checked", report


@pytest.mark.parametrize("base_provided", [False, True])
@pytest.mark.parametrize("safe_overload", [False, True])
@pytest.mark.parametrize("receiver_kind", ["variable", "direct", "parameter"])
def test_qualified_inherited_overload_uses_shared_summary_admission(
    base_provided, safe_overload, receiver_kind
):
    overload = (
        'public final String route(String text) { return "https://safe.example/"; }' if safe_overload else ""
    )
    receiver = "new Handler()" if receiver_kind == "direct" else "helper"
    declaration = "Handler helper = new Handler();" if receiver_kind == "variable" else ""
    extra_parameter = ", Handler helper" if receiver_kind == "parameter" else ""
    caller = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Handler extends Base {{ {overload} }}
class Entry {{
    void open(Intent input, WebView web{extra_parameter}) {{
        {declaration}
        web.loadUrl({receiver}.route(input));
    }}
}}
"""
    sources = [("app/Entry.java", caller)]
    if base_provided:
        sources.append(
            (
                "app/Base.java",
                """package app;
import android.content.Intent;
public class Base {
    public String route(Intent input) { return input.getDataString(); }
}
""",
            )
        )
    report = scan(*sources)
    candidate_and_partial(report)
    flow = report["metadata"]["native_flow"]
    assert flow["evaluations"] == 0, report
    if safe_overload:
        assert "inherited overload signature unresolved" in flow["reasons"], report


@pytest.mark.parametrize("base_provided", [False, True])
@pytest.mark.parametrize("string_argument", [False, True])
def test_local_class_member_is_not_a_function_local_callable_for_signature_admission(
    base_provided, string_argument
):
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Outer {{
    void build() {{
        class Handler extends Base {{
            private String route(String text) {{ return "https://safe.example/"; }}
            void open(Intent input, WebView web) {{
                {"String text = input.getDataString();" if string_argument else ""}
                web.loadUrl(route({"text" if string_argument else "input"}));
            }}
        }}
    }}
}}
"""
    sources = [("app/Outer.java", source)]
    if base_provided:
        sources.append(
            (
                "app/Base.java",
                """package app;
import android.content.Intent;
class Base { String route(Intent input) { return input.getDataString(); } }
""",
            )
        )
    report = scan(*sources)
    flow = report["metadata"]["native_flow"]
    if string_argument:
        assert not findings(report, URL), report
        assert flow["evaluations"] == 1, report
        assert "inherited overload signature unresolved" not in flow["reasons"], report
    else:
        candidate_and_partial(report)
        assert flow["evaluations"] == 0, report
        assert "inherited overload signature unresolved" in flow["reasons"], report


@pytest.mark.parametrize("explicit_this", [False, True])
def test_member_string_argument_with_identical_lexical_type_binding_remains_supported(explicit_this):
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Handler extends Base {{
    public final String route(String text) {{ return "https://safe.example/"; }}
    void open(Intent input, WebView web, Handler helper) {{
        String text = input.getDataString();
        web.loadUrl({"this." if explicit_this else ""}route(text));
    }}
}}
"""
    report = scan(("app/Handler.java", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["evaluations"] == 1, report
    assert "inherited overload signature unresolved" not in report["metadata"]["native_flow"]["reasons"], (
        report
    )


def test_plain_receiver_private_string_positive_without_inherited_overload_set_remains_checked():
    source = """package app;
import android.content.Intent;
import android.webkit.WebView;
class Handler {
    public final String route(String text) { return "https://safe.example/"; }
}
class Entry {
    void open(Intent input, WebView web) {
        Handler helper = new Handler();
        web.loadUrl(helper.route(input.getDataString()));
    }
}
"""
    report = scan(("app/Entry.java", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["evaluations"] == 1, report


@pytest.mark.parametrize("helper_provided", [False, True])
def test_inapplicable_local_function_cannot_hide_imported_kotlin_overload(helper_provided):
    source = """package app
import android.content.Intent
import android.webkit.WebView
import external.route
class Handler {
    fun open(input: Intent, web: WebView) {
        fun route(text: String): String { return "https://safe.example/" }
        web.loadUrl(route(input))
    }
}
"""
    sources = [("app/Handler.kt", source)]
    if helper_provided:
        sources.append(
            (
                "external/Helpers.kt",
                """package external
import android.content.Intent
fun route(input: Intent): String { return input.getDataString() }
""",
            )
        )
    report = scan(*sources)
    candidate_and_partial(report)
    assert "lexical overload signature unresolved" in report["metadata"]["native_flow"]["reasons"], report
    assert report["metadata"]["native_flow"]["evaluations"] == 0, report


@pytest.mark.parametrize("container", ["interface", "enum", "record"])
@pytest.mark.parametrize("unused_present", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_unused_java_nominal_member_cannot_borrow_enclosing_entry_owner(container, unused_present, reverse):
    prefix = {
        "interface": "interface Unrelated {",
        "enum": "enum Unrelated { ONLY;",
        "record": "record Unrelated(int value) {",
    }[container]
    unused = prefix + ' static String route(String input) { return "https://safe.example/"; } }'
    caller = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
import static external.Helper.route;
class Entry {{
    {unused if unused_present else ""}
    void open(Intent input, WebView web) {{ web.loadUrl(route(input.getDataString())); }}
}}
"""
    sources = [
        ("app/Entry.java", caller),
        (
            "external/Helper.java",
            "package external; public class Helper { public static String route(String input) { return input; } }",
        ),
    ]
    report = scan(*(reversed(sources) if reverse else sources))
    assert findings(report, URL), report
    flow = report["metadata"]["native_flow"]
    assert flow["state"] == "checked", report
    assert flow["reasons"] == [], report
    assert flow["evaluations"] == 1, report


@pytest.mark.parametrize("container", ["interface", "enum", "record", "annotation"])
def test_qualified_java_nominal_owner_retains_explicit_static_summary(container):
    declaration = {
        "interface": "interface Unrelated {",
        "enum": "enum Unrelated { ONLY;",
        "record": "record Unrelated(int value) {",
        "annotation": "@interface Unrelated { class Nested {",
    }[container]
    receiver = "Entry.Unrelated.Nested" if container == "annotation" else "Entry.Unrelated"
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Entry {{
    {declaration}
        public static String route(String input) {{ return "https://safe.example/"; }}
    {"}" if container == "annotation" else ""}}}
    void open(Intent input, WebView web) {{ web.loadUrl({receiver}.route(input.getDataString())); }}
}}
"""
    report = scan(("app/Entry.java", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["evaluations"] == 1, report


def test_enum_constant_class_body_is_an_anonymous_ownership_fence():
    source = """package app;
import android.content.Intent;
import android.webkit.WebView;
import static external.Helper.route;
class Entry {
    enum Unrelated {
        ONLY { String route(String input) { return "https://safe.example/"; } };
    }
    void open(Intent input, WebView web) { web.loadUrl(route(input.getDataString())); }
}
"""
    report = scan(
        ("app/Entry.java", source),
        (
            "external/Helper.java",
            "package external; public class Helper { public static String route(String input) { return input; } }",
        ),
    )
    candidate_and_partial(report)
    assert "anonymous callable scope unavailable" in report["metadata"]["native_flow"]["reasons"], report
    assert report["metadata"]["native_flow"]["evaluations"] == 1, report


@pytest.mark.parametrize("container", ["interface", "enum", "annotation", "object"])
@pytest.mark.parametrize("unused_present", [False, True])
def test_unused_kotlin_nominal_scope_preserves_imported_input_helper(container, unused_present):
    declaration = {
        "interface": "interface Unrelated",
        "enum": "enum class Unrelated",
        "annotation": "annotation class Unrelated",
        "object": "object Unrelated",
    }[container]
    unused = declaration + ' {\nfun route(input: String): String { return "https://safe.example/" }\n}'
    caller = f"""package app
import android.content.Intent
import android.webkit.WebView
import external.route
class Entry {{
    {unused if unused_present else ""}
    fun open(input: Intent, web: WebView) {{ web.loadUrl(route(input.getDataString())) }}
}}
"""
    helper = "package external\nfun route(input: String): String { return input }"
    report = scan(("app/Entry.kt", caller), ("external/Helper.kt", helper))
    assert findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["evaluations"] == 1, report


def test_kotlin_interface_default_method_remains_open_with_nominal_ownership():
    source = """package app
import android.content.Intent
import android.webkit.WebView
interface Handler {
    fun route(input: String): String { return "https://safe.example/" }
    fun open(input: Intent, web: WebView) { web.loadUrl(route(input.getDataString())) }
}
class Unsafe: Handler {
    override fun route(input: String): String { return input }
}
"""
    report = scan(("app/Handler.kt", source))
    candidate_and_partial(report)
    assert "receiver runtime dispatch unresolved" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("container", ["struct", "enum", "actor"])
@pytest.mark.parametrize("unused_present", [False, True])
def test_unused_swift_nominal_scope_cannot_replace_visible_file_helper(container, unused_present):
    unused = f"""{container} Unrelated {{
        static func route(_ input: URL) -> URL {{ return URL(string: "https://safe.example/")! }}
    }}"""
    source = f"""import WebKit
class Entry {{
    let web = WKWebView()
    {unused if unused_present else ""}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        web.load(URLRequest(url: route(incoming)))
        return true
    }}
}}
func route(_ input: URL) -> URL {{ return input }}
"""
    report = scan(("app/Entry.swift", source))
    assert findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["evaluations"] == 1, report


@pytest.mark.parametrize("container", ["companion", "object-literal", "extension"])
def test_unsupported_nominal_container_stops_summary_lookup(container):
    if container == "extension":
        source = """import WebKit
class Entry {
    let web = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
        web.load(URLRequest(url: route(incoming)))
        return true
    }
}
class Unrelated {}
extension Unrelated {
    static func route(_ input: URL) -> URL { return URL(string: "https://safe.example/")! }
}
func route(_ input: URL) -> URL { return input }
"""
        suffix = "swift"
    else:
        unused = (
            'class Unrelated {\ncompanion object {\nfun route(input: String): String { return "https://safe.example/" }\n}\n}'
            if container == "companion"
            else 'val ignored = object {\nfun route(input: String): String { return "https://safe.example/" }\n}'
        )
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Entry {{
    {unused}
    fun open(input: Intent, web: WebView) {{ web.loadUrl(route(input.getDataString())) }}
}}
fun route(input: String): String {{ return input }}
"""
        suffix = "kt"
    report = scan((f"app/Entry.{suffix}", source))
    candidate_and_partial(report)
    assert any(
        reason in report["metadata"]["native_flow"]["reasons"]
        for reason in ["nominal callable scope unavailable", "anonymous callable scope unavailable"]
    ), report


@pytest.mark.parametrize("container", ["class", "enum"])
@pytest.mark.parametrize("explicit_this", [False, True])
@pytest.mark.parametrize("safe", [False, True])
def test_nominal_field_write_read_keeps_input_while_literal_return_remains_safe(
    container, explicit_this, safe
):
    field = "this.stash" if explicit_this else "stash"
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
{container} Holder {{
    {"ONE;" if container == "enum" else ""}
    String stash;
    private String route(String input) {{ {field} = input; return {'"https://safe.example/"' if safe else field}; }}
    static class Entry {{
        void open(Intent input, WebView web, Holder helper) {{ web.loadUrl(helper.route(input.getDataString())); }}
    }}
}}
"""
    report = scan(("app/Holder.java", source))
    assert bool(findings(report, URL)) is not safe, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("explicit_constructor", [False, True])
@pytest.mark.parametrize("access", ["value", "this.value", "generated", "literal"])
@pytest.mark.parametrize("tainted", [False, True])
def test_record_component_and_unknown_receiver_fields_survive_summary_admission(
    explicit_constructor, access, tainted
):
    constructor = "Holder(String value) { this.value = value; }" if explicit_constructor else ""
    body = '"https://safe.example/"' if access == "literal" else access
    method = "" if access == "generated" else f"private String route() {{ return {body}; }}"
    call = "value" if access == "generated" else "route"
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
record Holder(String value) {{
    {constructor}
    {method}
    static class Entry {{
        void open(Intent input, WebView web) {{
            Holder helper = new Holder({argument});
            web.loadUrl(helper.{call}());
        }}
    }}
}}
"""
    report = scan(("app/Holder.java", source))
    assert bool(findings(report, URL)) is (tainted and access != "literal"), report


@pytest.mark.parametrize("shadow", ["parameter", "local"])
def test_explicit_this_field_does_not_read_a_shadowing_safe_local(shadow):
    parameter = "String value" if shadow == "parameter" else ""
    local = 'String value = "https://safe.example/";' if shadow == "local" else ""
    argument = '"https://safe.example/"' if shadow == "parameter" else ""
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Holder {{
    String value;
    Holder(String value) {{ this.value = value; }}
    private String route({parameter}) {{ {local} return this.value; }}
    static class Entry {{
        void open(Intent input, WebView web) {{
            Holder helper = new Holder(input.getDataString());
            web.loadUrl(helper.route({argument}));
        }}
    }}
}}
"""
    report = scan(("app/Holder.java", source))
    assert findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


def test_explicit_this_write_cannot_overwrite_shadowing_parameter_provenance():
    source = """package app;
import android.content.Intent;
import android.webkit.WebView;
class Holder {
    String value;
    private String route(String value) { this.value = "https://safe.example/"; return value; }
    static class Entry {
        void open(Intent input, WebView web, Holder helper) { web.loadUrl(helper.route(input.getDataString())); }
    }
}
"""
    report = scan(("app/Holder.java", source))
    assert findings(report, URL), report


def test_unknown_constructor_multifield_state_keeps_sentinel_and_explicit_field_overrides():
    source = """package app
import android.content.Intent
import android.webkit.WebView
class Holder(var first: String, var second: String) {
    fun clear() { this.first = "https://safe.example/" }
    fun readFirst(): String { return first }
    fun readSecond(): String { return this.second }
}
class Entry {
    fun open(input: Intent, web: WebView) {
        val helper = Holder(input.getDataString(), input.getDataString())
        helper.clear()
        web.loadUrl(helper.readFirst())
        web.loadUrl(helper.readSecond())
        web.loadUrl(helper.readSecond())
    }
}
"""
    report = scan(("app/Entry.kt", source))
    assert {item["evidence"][0]["line"] for item in findings(report, URL)} == {14, 15}, report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize("static_write", ["bare", "this", "qualified"])
@pytest.mark.parametrize("tainted", [False, True])
def test_static_field_state_is_shared_across_receiver_instances(static_write, tainted):
    field = {"bare": "stash", "this": "this.stash", "qualified": "Holder.stash"}[static_write]
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Holder {{
    static String stash;
    private void put(String input) {{ {field} = input; }}
    private String read() {{ return {field}; }}
    static class Entry {{
        void open(Intent input, WebView web) {{
            Holder first = new Holder();
            Holder second = new Holder();
            first.put({argument});
            web.loadUrl(second.read());
        }}
    }}
}}
"""
    report = scan(("app/Holder.java", source))
    assert bool(findings(report, URL)) is tainted, report


@pytest.mark.parametrize("container", ["class", "interface", "record", "annotation"])
def test_static_field_taint_survives_distinct_entry_functions(container):
    declaration = {
        "class": "class Holder",
        "interface": "interface Holder",
        "record": "record Holder()",
        "annotation": "@interface Holder",
    }[container]
    # Java interface/annotation fields cannot be reassigned. A final array is
    # therefore not modeled as an ordinary mutable static scalar here.
    if container in {"interface", "annotation"}:
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
{declaration} {{
    static class Nested {{
        static String stash;
    }}
}}
class Entry {{
    void store(Intent input) {{ Holder.Nested.stash = input.getDataString(); }}
    void read(WebView web) {{ web.loadUrl(Holder.Nested.stash); }}
}}
"""
    else:
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
{declaration} {{ static String stash; }}
class Entry {{
    void store(Intent input) {{ Holder.stash = input.getDataString(); }}
    void read(WebView web) {{ web.loadUrl(Holder.stash); }}
}}
"""
    report = scan(("app/Entry.java", source))
    assert findings(report, URL), report


@pytest.mark.parametrize("explicit_this", [False, True])
@pytest.mark.parametrize("base_provided", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_unavailable_inherited_static_or_instance_fields_keep_provenance_across_receivers(
    explicit_this, base_provided, tainted
):
    field = "this.stash" if explicit_this else "stash"
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Holder extends Base {{
    private void put(String value) {{ {field} = value; }}
    private String read() {{ return {field}; }}
    void open(Intent input, WebView web, Holder other) {{
        String value = {argument};
        this.put(value);
        web.loadUrl(other.read());
    }}
}}
"""
    sources = [("app/Holder.java", source)]
    if base_provided:
        sources.append(("app/Base.java", "package app; class Base { protected static String stash; }"))
    report = scan(*sources)
    assert bool(findings(report, URL)) is tainted, report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "receiver field inventory unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("suffix", ["kt", "swift"])
@pytest.mark.parametrize("safe", [False, True])
def test_computed_property_mapping_abstains_without_tainting_literal_safe_returns(suffix, safe):
    if suffix == "kt":
        returned = '"https://safe.example/"' if safe else "this.computed"
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Holder {{
    var stash: String = ""
    val computed: String
        get() = stash
    fun route(input: String): String {{ this.stash = input; return {returned} }}
}}
class Entry {{
    fun open(input: Intent, web: WebView) {{ web.loadUrl(Holder().route(input.getDataString())) }}
}}
"""
    else:
        returned = 'URL(string: "https://safe.example/")!' if safe else "self.computed"
        source = f"""import WebKit
final class Holder {{
    var stash: URL = URL(string: "https://safe.example/")!
    var computed: URL {{ return stash }}
    func route(_ input: URL) -> URL {{ self.stash = input; return {returned} }}
}}
class Entry {{
    let web = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        web.load(URLRequest(url: Holder().route(incoming)))
        return true
    }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    assert bool(findings(report, URL)) is not safe, report
    if not safe:
        assert "receiver field inventory unavailable" in report["metadata"]["native_flow"]["reasons"], report


def test_static_field_changes_invalidate_nested_helper_call_cache():
    source = """package app;
import android.content.Intent;
import android.webkit.WebView;
class Holder {
    static String stash;
    private String read() { return stash; }
    private String forward() { return read(); }
    private void put(String value) { stash = value; }
    static class Entry {
        void open(Intent input, WebView web) {
            Holder first = new Holder();
            Holder second = new Holder();
            first.put("https://safe.example/");
            web.loadUrl(second.forward());
            first.put(input.getDataString());
            web.loadUrl(second.forward());
        }
    }
}
"""
    report = scan(("app/Holder.java", source))
    assert {item["evidence"][0]["line"] for item in findings(report, URL)} == {16}, report


@pytest.mark.parametrize("explicit_this", [False, True])
def test_user_field_named_unknown_fields_cannot_clear_internal_unknown_provenance(explicit_this):
    field = "this.__unknown_fields__" if explicit_this else "__unknown_fields__"
    source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Holder(var __unknown_fields__: String, var value: String) {{
    fun clear() {{ {field} = "https://safe.example/" }}
    fun named(): String {{ return {field} }}
    fun read(): String {{ return value }}
}}
class Entry {{
    fun open(input: Intent, web: WebView) {{
        val helper = Holder(input.getDataString(), input.getDataString())
        helper.clear()
        web.loadUrl(helper.named())
        web.loadUrl(helper.read())
    }}
}}
"""
    report = scan(("app/Entry.kt", source))
    assert {item["evidence"][0]["line"] for item in findings(report, URL)} == {14}, report


@pytest.mark.parametrize("field", ["stash", "Holder.stash", "Self.stash", "self.stash"])
@pytest.mark.parametrize("tainted", [False, True])
def test_swift_static_writer_and_reader_share_normalized_storage(field, tainted):
    argument = "incoming" if tainted else 'URL(string: "https://safe.example/")!'
    source = f"""import WebKit
import UIKit
final class Holder {{
    static var stash: URL = URL(string: "https://safe.example/")!
    static func put(_ input: URL) {{ {field} = input }}
    static func read() -> URL {{ return {field} }}
}}
class Entry {{
    let web = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        Holder.put({argument})
        web.load(URLRequest(url: Holder.read()))
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert bool(findings(report, URL)) is tainted, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["reasons"] == [], report


@pytest.mark.parametrize("suffix", ["java", "kt"])
@pytest.mark.parametrize("field", ["stash", "Holder.stash", "this.stash"])
@pytest.mark.parametrize("tainted", [False, True])
def test_java_kotlin_static_writer_reader_storage_matches_assignment_target(suffix, field, tainted):
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    if suffix == "java":
        # An instance call may refer to a Java static field through `this`.
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{
    static String stash = "https://safe.example/";
    final void put(String value) {{ {field} = value; }}
    final String read() {{ return {field}; }}
}}
class Entry {{
    void open(Intent input, WebView web) {{
        Holder holder = new Holder();
        holder.put({argument});
        web.loadUrl(holder.read());
    }}
}}
"""
    else:
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
object Holder {{
    var stash: String = "https://safe.example/"
    fun put(value: String) {{ {field} = value }}
    fun read(): String {{ return {field} }}
}}
class Entry {{
    fun open(input: Intent, web: WebView) {{
        Holder.put({argument})
        web.loadUrl(Holder.read())
    }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    assert bool(findings(report, URL)) is tainted, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("explicit_self", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_swift_instance_writer_reader_preserves_assignment_storage(explicit_self, tainted):
    field = "self.stash" if explicit_self else "stash"
    argument = "incoming" if tainted else 'URL(string: "https://safe.example/")!'
    source = f"""import WebKit
import UIKit
final class Holder {{
    let web = WKWebView()
    var stash: URL = URL(string: "https://safe.example/")!
    func put(_ input: URL) {{ {field} = input }}
    func read() -> URL {{ return {field} }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        put({argument})
        web.load(URLRequest(url: read()))
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert bool(findings(report, URL)) is tainted, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("shadow", ["parameter", "local"])
def test_swift_explicit_member_assignment_does_not_overwrite_tainted_shadow(shadow):
    parameter = "stash" if shadow == "parameter" else "input"
    local = "let stash = input" if shadow == "local" else ""
    source = f"""import WebKit
import UIKit
final class Holder {{
    let web = WKWebView()
    var stash: URL = URL(string: "https://safe.example/")!
    func route(_ {parameter}: URL) -> URL {{
        {local}
        self.stash = URL(string: "https://safe.example/")!
        return stash
    }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        web.load(URLRequest(url: route(incoming)))
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("shadow", ["parameter", "local"])
def test_swift_bare_assignment_to_shadow_does_not_write_receiver_field(shadow):
    parameter = "stash" if shadow == "parameter" else "input"
    local = 'var stash: URL = URL(string: "https://safe.example/")!' if shadow == "local" else ""
    # A parameter itself is immutable in Swift, so shadow it with an explicit
    # local before the assignment; neither declaration denotes the property.
    if shadow == "parameter":
        local = "var stash = stash"
    source = f"""import WebKit
import UIKit
final class Holder {{
    let web = WKWebView()
    var stash: URL = URL(string: "https://safe.example/")!
    func put(_ {parameter}: URL, _ value: URL) {{
        {local}
        stash = value
    }}
    func read() -> URL {{ return self.stash }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        put(URL(string: "https://safe.example/")!, incoming)
        web.load(URLRequest(url: read()))
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("kind", ["bodyless", "overridable", "final-mutating", "final-noop"])
@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("explicit_constructor", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_uncertain_mutator_weakly_updates_object_arguments_without_tainting_unrelated_objects(
    kind, alias, explicit_constructor, tainted
):
    declaration = {
        "bodyless": "abstract class Mutator { abstract void put(Holder h, String value); }",
        "overridable": "class Mutator { void put(Holder h, String value) {} }",
        "final-mutating": "final class Mutator { final void put(Holder h, String value) { h.stash = value; } }",
        "final-noop": "final class Mutator { final void put(Holder h, String value) {} }",
    }[kind]
    constructor = "Holder(String value) { stash = value; other = value; }" if explicit_constructor else ""
    allocation = 'new Holder("https://safe.example/")' if explicit_constructor else "new Holder()"
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{
    String stash = "https://safe.example/";
    String other = "https://safe.example/";
    {constructor}
    final String read() {{ return stash; }}
    final String readOther() {{ return other; }}
}}
{declaration}
class Entry {{
    void open(Intent input, WebView web, Mutator m) {{
        Holder h = {allocation};
        Holder unrelated = {allocation};
        {"Holder alias = h;" if alias else ""}
        m.put({"alias" if alias else "h"}, {argument});
        web.loadUrl(h.read());
        web.loadUrl(h.readOther());
        web.loadUrl(unrelated.read());
    }}
}}
"""
    report = scan(("app/Entry.java", source))
    expected = set()
    if tainted and kind != "final-noop":
        expected.add(18)
        if kind != "final-mutating":
            expected.add(19)
    assert {item["evidence"][0]["line"] for item in findings(report, URL)} == expected, report
    state = "partial" if kind in {"bodyless", "overridable"} else "checked"
    assert report["metadata"]["native_flow"]["state"] == state, report
    if kind == "bodyless":
        assert "callable body unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("suffix", ["java", "kt"])
@pytest.mark.parametrize("formal", ["target", "h"])
@pytest.mark.parametrize("binding", ["direct", "alias", "returned", "reassigned"])
@pytest.mark.parametrize("kind", ["closed", "bodyless", "noop"])
@pytest.mark.parametrize("tainted", [False, True])
def test_parameter_object_effects_are_invariant_under_formal_renaming_and_aliases(
    suffix, formal, binding, kind, tainted
):
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    alias = ""
    target = "h"
    if binding == "alias":
        alias, target = "Holder alias = h;", "alias"
    elif binding == "returned":
        target = "Identity.keep(h)"
    elif binding == "reassigned":
        alias, target = "Holder alias = h; alias = other;", "alias"
    if suffix == "java":
        mutator = (
            f"abstract class Mutator {{ abstract void put(Holder {formal}, String value); }}"
            if kind == "bodyless"
            else f"final class Mutator {{ static void put(Holder {formal}, String value) {{"
            + (f"{formal}.stash = value;" if kind == "closed" else "")
            + "} }"
        )
        operation = f"{'m' if kind == 'bodyless' else 'Mutator'}.put({target}, {argument});"
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{
    String stash = "https://safe.example/";
    final String read() {{ return stash; }}
}}
final class Identity {{ static Holder keep(Holder renamed) {{ return renamed; }} }}
{mutator}
class Entry {{
    void open(Intent input, WebView web, Holder h, Holder other, Mutator m) {{
        {alias}
        {operation}
        web.loadUrl(h.read());
        web.loadUrl(other.read());
    }}
}}
"""
    else:
        alias = alias.replace("Holder alias =", "var alias =").replace(";", "\n")
        mutator = (
            f"abstract class Mutator {{\n    abstract fun put({formal}: Holder, value: String)\n}}"
            if kind == "bodyless"
            else f"object Mutator {{\n    fun put({formal}: Holder, value: String) {{\n"
            + (f"{formal}.stash = value" if kind == "closed" else "")
            + "\n    }\n}"
        )
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Holder {{
    var stash: String = "https://safe.example/"
    fun read(): String {{ return stash }}
}}
object Identity {{
    fun keep(renamed: Holder): Holder {{ return renamed }}
}}
{mutator}
class Entry {{
    fun open(input: Intent, web: WebView, h: Holder, other: Holder, m: Mutator) {{
        {alias}
        {"m" if kind == "bodyless" else "Mutator"}.put({target}, {argument})
        web.loadUrl(h.read())
        web.loadUrl(other.read())
    }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    expected = "other.read()" if binding == "reassigned" else "h.read()"
    expected_lines = {
        index
        for index, line in enumerate(source.strip().splitlines(), 1)
        if "web.loadUrl(" + expected in line
    }
    assert {item["evidence"][0]["line"] for item in findings(report, URL)} == (
        expected_lines if tainted and kind != "noop" else set()
    ), report
    assert report["metadata"]["native_flow"]["state"] == ("partial" if kind == "bodyless" else "checked"), (
        report
    )
    assert "object alias identity unavailable" not in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("suffix", ["java", "kt"])
@pytest.mark.parametrize("formal", ["target", "h"])
def test_mutator_parameter_shadows_object_field_without_borrowing_its_storage(suffix, formal):
    if suffix == "java":
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{
    String stash = "https://safe.example/";
    final String read() {{ return stash; }}
}}
final class Mutator {{
    static Holder {formal} = new Holder();
    static void put(Holder {formal}, String value) {{ {formal}.stash = value; }}
    static String stored() {{ return {formal}.read(); }}
}}
class Entry {{
    void open(Intent input, WebView web, Holder h) {{
        Mutator.put(h, input.getDataString());
        web.loadUrl(h.read());
        web.loadUrl(Mutator.stored());
    }}
}}
"""
    else:
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Holder {{
    var stash: String = "https://safe.example/"
    fun read(): String {{ return stash }}
}}
object Mutator {{
    val {formal}: Holder = Holder()
    fun put({formal}: Holder, value: String) {{ {formal}.stash = value }}
    fun stored(): String {{ return {formal}.read() }}
}}
class Entry {{
    fun open(input: Intent, web: WebView, h: Holder) {{
        Mutator.put(h, input.getDataString())
        web.loadUrl(h.read())
        web.loadUrl(Mutator.stored())
    }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    assert len(findings(report, URL)) == 1, report
    assert findings(report, URL)[0]["evidence"][0]["line"] == 16, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("formal", ["target", "holder"])
@pytest.mark.parametrize("binding", ["self", "alias", "returned", "captured"])
@pytest.mark.parametrize("tainted", [False, True])
def test_swift_reference_receiver_identity_survives_aliases_returns_and_captures(formal, binding, tainted):
    argument = "incoming" if tainted else 'URL(string: "https://safe.example/")!'
    local, target = "", "self"
    if binding == "alias":
        local, target = "let alias = self", "alias"
    elif binding == "returned":
        target = "Mutator.keep(self)"
    elif binding == "captured":
        local = f"func apply() {{ Mutator.put(self, {argument}) }}"
    operation = "apply()" if binding == "captured" else f"Mutator.put({target}, {argument})"
    source = f"""import WebKit
import UIKit
final class Holder {{
    let web = WKWebView()
    var stash: URL = URL(string: "https://safe.example/")!
    func read() -> URL {{ return stash }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        {local}
        {operation}
        web.load(URLRequest(url: read()))
        return true
    }}
}}
final class Mutator {{
    static func put(_ {formal}: Holder, _ value: URL) {{ {formal}.stash = value }}
    static func keep(_ renamed: Holder) -> Holder {{ return renamed }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert bool(findings(report, URL)) is tainted, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["reasons"] == [], report


def test_factory_allocation_identity_uses_call_context_without_merging_distinct_objects():
    source = """package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {
    String stash = "https://safe.example/";
    final String read() { return stash; }
}
final class Helper {
    static Holder make() { return new Holder(); }
    static void put(Holder target, String value) { target.stash = value; }
}
class Entry {
    void open(Intent input, WebView web) {
        Holder first = Helper.make();
        Holder second = Helper.make();
        Helper.put(first, input.getDataString());
        Helper.put(second, "https://safe.example/");
        web.loadUrl(first.read());
        web.loadUrl(second.read());
    }
}
"""
    report = scan(("app/Entry.java", source))
    assert {item["evidence"][0]["line"] for item in findings(report, URL)} == {18}, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("formal", ["target", "h"])
@pytest.mark.parametrize("reverse", [False, True])
def test_object_argument_identity_is_carried_across_source_files(formal, reverse):
    sources = [
        (
            "app/Holder.java",
            'package app; final class Holder { String stash = "https://safe.example/"; final String read(){return stash;} }',
        ),
        (
            "app/Mutator.java",
            f"package app; final class Mutator {{ static void put(Holder {formal},String value){{{formal}.stash=value;}} }}",
        ),
        (
            "app/Entry.java",
            "package app; import android.content.Intent; import android.webkit.WebView; class Entry { void open(Intent input,WebView web,Holder h){Mutator.put(h,input.getDataString());web.loadUrl(h.read());} }",
        ),
    ]
    report = scan(*(list(reversed(sources)) if reverse else sources))
    assert len(findings(report, URL)) == 1, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("suffix", ["java", "kt", "swift"])
@pytest.mark.parametrize("storage", ["local", "member", "static", "shadow"])
@pytest.mark.parametrize("form", ["compound", "expanded", "replacement"])
@pytest.mark.parametrize("tainted", [False, True])
@pytest.mark.parametrize("direction", ["left", "right"])
def test_compound_assignment_matches_expanded_read_modify_write_and_keeps_replacement_strong(
    suffix, storage, form, tainted, direction
):
    field = {"local": "value", "member": "this.stash", "static": "Helper.stash", "shadow": "stash"}[storage]
    seed = "input" if direction == "left" else '"https://safe.example/"'
    right = '"?fixed=1"' if direction == "left" else "input"
    operation = {
        "compound": f"{field} += {right}",
        "expanded": f"{field} = {field} + {right}",
        "replacement": f'{field} = "https://safe.example/"',
    }[form]
    if suffix == "java":
        local = f"String {field} = {seed};" if storage in {"local", "shadow"} else f"{field} = {seed};"
        static = "" if storage == "member" else "static "
        argument = "input.getDataString()" if tainted else '"https://safe.example/"'
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Helper {{
    {static}String stash = "https://safe.example/";
    {static}String route(String input) {{
        {local}
        {operation};
        return {field};
    }}
    {static}String stored() {{ return stash; }}
}}
class Entry {{
    void open(Intent input, WebView web) {{
        web.loadUrl({"new Helper()" if storage == "member" else "Helper"}.route({argument}));
        {"web.loadUrl(Helper.stored());" if storage == "shadow" else ""}
    }}
}}
"""
    elif suffix == "kt":
        local = f"var {field}: String = {seed}" if storage in {"local", "shadow"} else f"{field} = {seed}"
        argument = "input.getDataString()" if tainted else '"https://safe.example/"'
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
{"class" if storage == "member" else "object"} Helper {{
    var stash: String = "https://safe.example/"
    fun route(input: String): String {{
        {local}
        {operation}
        return {field}
    }}
    fun stored(): String {{ return stash }}
}}
class Entry {{
    fun open(input: Intent, web: WebView) {{
        web.loadUrl({"Helper()" if storage == "member" else "Helper"}.route({argument}))
        {"web.loadUrl(Helper.stored())" if storage == "shadow" else ""}
    }}
}}
"""
    else:
        field = field.replace("this.", "self.")
        operation = operation.replace("this.", "self.")
        local = f"var {field}: String = {seed}" if storage in {"local", "shadow"} else f"{field} = {seed}"
        argument = "incoming.absoluteString" if tainted else '"https://safe.example/"'
        static = "" if storage == "member" else "static "
        source = f"""import WebKit
import UIKit
final class Helper {{
    let web = WKWebView()
    {static}var stash: String = "https://safe.example/"
    {static}func route(_ input: String) -> String {{
        {local}
        {operation}
        return {field}
    }}
    {static}func stored() -> String {{ return stash }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        web.load(URLRequest(url: URL(string: {"self" if storage == "member" else "Helper"}.route({argument}))!))
        {"web.load(URLRequest(url: URL(string: Helper.stored())!))" if storage == "shadow" else ""}
        return true
    }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    assert len(findings(report, URL)) == int(tainted and form != "replacement"), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
    assert report["metadata"]["native_flow"]["reasons"] == [], report


@pytest.mark.parametrize("tainted", [False, True])
def test_unmodeled_compound_operator_weakens_object_alias_and_declares_partial(tainted):
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Holder {{
    var stash: String = "https://safe.example/"
    operator fun plusAssign(value: String) {{ stash = value }}
    fun read(): String {{ return stash }}
}}
object Helper {{
    fun put(target: Holder, value: String) {{ target += value }}
}}
class Entry {{
    fun open(input: Intent, web: WebView, h: Holder) {{
        val alias = h
        Helper.put(alias, {argument})
        web.loadUrl(h.read())
    }}
}}
"""
    report = scan(("app/Entry.kt", source))
    assert bool(findings(report, URL)) is tainted, report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "compound assignment operator dispatch unavailable" in report["metadata"]["native_flow"]["reasons"]


SWIFT_STORAGE_PROBES = [
    pytest.param(
        "struct-inout",
        "c895a981ed6aa93bb902deae95122ba918982211720b627c52d7fbf0c3fcf6b6",
        """import WebKit
import UIKit
struct Holder {
 var stash: String = "https://safe.example/"
 func read() -> String { return stash }
}
final class Mutator {
 static func put(_ target: inout Holder, _ value: String) { target.stash = value }
}
class Entry {
 let web = WKWebView()
 var h: Holder = Holder()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  Mutator.put(&h, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: h.read())!))
  return true
 }
}
""",
        id="struct-inout",
    ),
    pytest.param(
        "scalar-inout",
        "0afedc19d71cb8e4f965d9cfbf7257a3b861456050a06f9caa43a6aff8caad27",
        """import WebKit
import UIKit
final class Mutator {
 static func put(_ target: inout String, _ value: String) { target = value }
}
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  Mutator.put(&text, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="scalar-inout",
    ),
    pytest.param(
        "struct-mutating",
        "d2d34beb00527db20f6e7901986d8119d75507380543fa5cabbbbfb03f8764ad",
        """import WebKit
import UIKit
struct Holder {
 var stash: String = "https://safe.example/"
 mutating func put(_ value: String) { self.stash = value }
 func read() -> String { return stash }
}
class Entry {
 let web = WKWebView()
 var h: Holder = Holder()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  h.put(incoming.absoluteString)
  web.load(URLRequest(url: URL(string: h.read())!))
  return true
 }
}
""",
        id="struct-mutating",
    ),
    pytest.param(
        "struct-member-compound",
        "98bc200385dcfc80579659f8f0be80db8be52506a217340f6fce1dbd8708e9c5",
        """import WebKit
import UIKit
struct Holder { var stash: String = "https://safe.example/" }
class Entry {
 let web = WKWebView()
 var h: Holder = Holder()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  h.stash += incoming.absoluteString
  web.load(URLRequest(url: URL(string: h.stash)!))
  return true
 }
}
""",
        id="struct-member-compound",
    ),
    pytest.param(
        "struct-member-plain",
        "399065d8fc965de02d159e8608ed4701e55c687333592b53fff6f3d0aa9427d1",
        """import WebKit
import UIKit
struct Holder { var stash: String = "https://safe.example/" }
class Entry {
 let web = WKWebView()
 var h: Holder = Holder()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  h.stash = incoming.absoluteString
  web.load(URLRequest(url: URL(string: h.stash)!))
  return true
 }
}
""",
        id="struct-member-plain",
    ),
    pytest.param(
        "class-member-compound",
        "96343087c867f2f9816f7f599a3c4cfd2bf3d056c2dec1b82efe4e63d27a3914",
        """import WebKit
import UIKit
final class Holder { var stash: String = "https://safe.example/" }
class Entry {
 let web = WKWebView()
 var h: Holder = Holder()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  h.stash += incoming.absoluteString
  web.load(URLRequest(url: URL(string: h.stash)!))
  return true
 }
}
""",
        id="class-member-compound",
    ),
    pytest.param(
        "class-inout-reference",
        "7f04b41915e0c3f0af83c0091c8a9c54d2f76ac707b1ce225cd2e60e1321f690",
        """import WebKit
import UIKit
final class Holder {
 var stash: String = "https://safe.example/"
 func read() -> String { return stash }
}
final class Mutator {
 static func put(_ target: inout Holder, _ value: String) { target.stash = value }
}
class Entry {
 let web = WKWebView()
 var h: Holder = Holder()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  Mutator.put(&h, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: h.read())!))
  return true
 }
}
""",
        id="class-inout-reference",
    ),
    pytest.param(
        "class-inout-rebind",
        "a3e4ed8d3107828315a97b149f437c430cc4d4b1a7eeeabca6c05235b4c2f91d",
        """import WebKit
import UIKit
final class Holder {
 var stash: String
 init(_ value: String) { stash = value }
 func read() -> String { return stash }
}
final class Mutator {
 static func put(_ target: inout Holder, _ value: String) { target = Holder(value) }
}
class Entry {
 let web = WKWebView()
 var h: Holder = Holder("https://safe.example/")
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  Mutator.put(&h, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: h.read())!))
  return true
 }
}
""",
        id="class-inout-rebind",
    ),
]


@pytest.mark.parametrize("name,source_sha256,source", SWIFT_STORAGE_PROBES)
@pytest.mark.parametrize("tainted", [False, True])
def test_swift_unsupported_storage_preserves_exact_adversarial_candidate_and_safe_pair(
    name, source_sha256, source, tainted
):
    import hashlib

    assert hashlib.sha256(source.encode()).hexdigest() == source_sha256
    if not tainted:
        source = source.replace("incoming.absoluteString", '"https://safe.example/"')
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    if name == "class-member-compound":
        assert report["metadata"]["native_flow"]["state"] == "checked", report
    else:
        assert report["metadata"]["native_flow"]["state"] == "partial", report
        assert report["metadata"]["native_flow"]["reasons"], report
    if "inout" in name:
        assert "Swift inout writeback unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("suffix", ["java", "kt"])
@pytest.mark.parametrize("owned_type", [False, True])
@pytest.mark.parametrize("binding", ["direct", "alias", "index", "index-alias", "variable-index"])
@pytest.mark.parametrize("tainted", [False, True])
def test_parameter_storage_is_stable_without_type_inventory_and_through_index_projection(
    suffix, owned_type, binding, tainted
):
    indexed = "index" in binding
    access = "holders[position]" if binding == "variable-index" else "holders[0]" if indexed else "h"
    target = "alias" if binding in {"alias", "index-alias"} else access
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    if suffix == "java":
        declaration = "final class Holder { String stash; }" if owned_type else ""
        parameters = "Holder[] holders" if indexed else "Holder h"
        alias = f"Holder alias = {access};" if target == "alias" else ""
        source = f"""package app;
{"import external.Holder;" if not owned_type else ""}
import android.content.Intent;
import android.webkit.WebView;
{declaration}
class Entry {{
    void open(Intent input, WebView web, {parameters}, Holder other, int position) {{
        {alias}
        {target}.stash = {argument};
        web.loadUrl({access}.stash);
        web.loadUrl(other.stash);
    }}
}}
"""
    else:
        declaration = 'class Holder {\nvar stash: String = "https://safe.example/"\n}' if owned_type else ""
        parameters = "holders: Array<Holder>" if indexed else "h: Holder"
        alias = f"val alias = {access}" if target == "alias" else ""
        source = f"""package app
{"import external.Holder" if not owned_type else ""}
import android.content.Intent
import android.webkit.WebView
{declaration}
class Entry {{
    fun open(input: Intent, web: WebView, {parameters}, other: Holder, position: Int) {{
        {alias}
        {target}.stash = {argument}
        web.loadUrl({access}.stash)
        web.loadUrl(other.stash)
    }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == (
        "partial" if indexed or not owned_type else "checked"
    ), report
    if indexed:
        assert "indexed object alias unavailable" in report["metadata"]["native_flow"]["reasons"], report
    if not owned_type:
        assert "receiver field inventory unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("binding", ["alias", "reassigned", "shadow"])
@pytest.mark.parametrize("tainted", [False, True])
def test_swift_uncertain_value_alias_storage_preserves_taint_without_touching_distinct_field(
    binding, tainted
):
    argument = "incoming.absoluteString" if tainted else '"https://safe.example/"'
    local = {
        "alias": "var alias = h",
        "reassigned": "var alias = h\n        alias = other",
        "shadow": "var h = other",
    }[binding]
    target = "h" if binding == "shadow" else "alias"
    affected = "h" if binding == "alias" else "other"
    untouched = "other" if binding == "alias" else "self.h"
    source = f"""import WebKit
import UIKit
struct Holder {{ var stash: String = "https://safe.example/" }}
class Entry {{
    let web = WKWebView()
    var h: Holder = Holder()
    var other: Holder = Holder()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        {local}
        {target}.stash = {argument}
        web.load(URLRequest(url: URL(string: {affected}.stash)!))
        web.load(URLRequest(url: URL(string: {untouched}.stash)!))
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "object storage alias unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("alias", [False, True])
@pytest.mark.parametrize("literal_return", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_swift_enum_inout_abstains_with_provenance_and_preserves_literal_return(
    alias, literal_return, tainted
):
    argument = "incoming.absoluteString" if tainted else '"https://safe.example/"'
    body = (
        'return "https://safe.example/"'
        if literal_return
        else "switch self { case .item(let value): return value }"
    )
    source = f"""import WebKit
import UIKit
enum Holder {{
    case item(String)
    func read() -> String {{ {body} }}
}}
final class Mutator {{
    static func put(_ target: inout Holder, _ value: String) {{ target = .item(value) }}
}}
class Entry {{
    let web = WKWebView()
    var h: Holder = .item("https://safe.example/")
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        {"var alias = h" if alias else ""}
        Mutator.put(&{"alias" if alias else "h"}, {argument})
        web.load(URLRequest(url: URL(string: {"alias" if alias else "h"}.read())!))
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert bool(findings(report, URL)) is (tainted and not literal_return), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "Swift inout writeback unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("tainted", [False, True])
def test_unmaterialized_receiver_uses_scoped_weak_storage_instead_of_occurrence_identity(tainted):
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    source = f"""package app;
import external.Holder;
import android.content.Intent;
import android.webkit.WebView;
class Entry {{
    native Holder unknown();
    void open(Intent input, WebView web, Holder other) {{
        unknown().stash = {argument};
        web.loadUrl(unknown().stash);
        web.loadUrl(other.stash);
    }}
}}
"""
    report = scan(("app/Entry.java", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "object alias identity unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("suffix", ["java", "kt"])
@pytest.mark.parametrize("binding", ["declaration", "assignment", "member"])
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_factory_result_materializes_unknown_fields_at_the_actual_typed_binding(
    suffix, binding, tainted
):
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    if suffix == "java":
        initialization = {
            "declaration": f"Holder h = Helper.make({argument});",
            "assignment": f"Holder h; h = Helper.make({argument});",
            "member": f"Box box = new Box(); box.child = Helper.make({argument});",
        }[binding]
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{
    String stash = "https://safe.example/";
    final String read() {{ return stash; }}
}}
final class Box {{ Holder child; }}
final class Helper {{ static native Holder make(String input); }}
class Entry {{
    void open(Intent input, WebView web) {{
        {initialization}
        web.loadUrl({"box.child" if binding == "member" else "h"}.read());
    }}
}}
"""
    else:
        initialization = {
            "declaration": f"val h: Holder = Helper.make({argument})",
            "assignment": f"var h: Holder\n        h = Helper.make({argument})",
            "member": f"val box = Box()\n        box.child = Helper.make({argument})",
        }[binding]
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Holder {{
    var stash: String = "https://safe.example/"
    fun read(): String {{ return stash }}
}}
class Box {{
    var child: Holder = Holder()
}}
object Helper {{
    external fun make(input: String): Holder
}}
class Entry {{
    fun open(input: Intent, web: WebView) {{
        {initialization}
        web.loadUrl({"box.child" if binding == "member" else "h"}.read())
    }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "callable body unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("suffix", ["java", "kt"])
@pytest.mark.parametrize("returned", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_declared_object_field_alias_uses_the_same_bound_storage_on_subsequent_read(
    suffix, returned, tainted
):
    argument = "input.getDataString()" if tainted else '"https://safe.example/"'
    target = "Helper.keep(box.child)" if returned else "box.child"
    if suffix == "java":
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{
    String stash = "https://safe.example/";
    final String read() {{ return stash; }}
}}
final class Box {{ Holder child = new Holder(); }}
final class Helper {{
    static Holder keep(Holder source) {{ return source; }}
    static void put(Holder renamed, String value) {{ renamed.stash = value; }}
}}
class Entry {{
    void open(Intent input, WebView web, Box box) {{
        Holder alias = {target};
        Helper.put(alias, {argument});
        web.loadUrl(box.child.read());
    }}
}}
"""
    else:
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Holder {{
    var stash: String = "https://safe.example/"
    fun read(): String {{ return stash }}
}}
class Box {{
    var child: Holder = Holder()
}}
object Helper {{
    fun keep(source: Holder): Holder {{ return source }}
    fun put(renamed: Holder, value: String) {{ renamed.stash = value }}
}}
class Entry {{
    fun open(input: Intent, web: WebView, box: Box) {{
        val alias = {target}
        Helper.put(alias, {argument})
        web.loadUrl(box.child.read())
    }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


SWIFT_EXTERNAL_INOUT_PROBES = [
    pytest.param(
        "external-qualified-scalar",
        "11e880fc850189c82e6ef3e265b3d157f6d27e58a347781555f8aa6a73db8527",
        True,
        """import WebKit
import UIKit
import External
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  ExternalMutator.put(&text, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="external-qualified-scalar",
    ),
    pytest.param(
        "known-qualified-scalar",
        "8c416ba974dbef42ea93fd8bb98f516995a61641c5c2ebaf660c0c53c4ff4d92",
        True,
        """import WebKit
import UIKit
import External
final class ExternalMutator {
 static func put(_ target: inout String, _ value: String) { target = value }
}
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  ExternalMutator.put(&text, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="known-qualified-scalar",
    ),
    pytest.param(
        "unknown-unqualified-scalar",
        "0a7ea57e119055d6df02cb79af84a0e40747709e62f3d8addb2d8dc7cac627e8",
        True,
        """import WebKit
import UIKit
import External
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  put(&text, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="unknown-unqualified-scalar",
    ),
    pytest.param(
        "unknown-qualified-struct",
        "68bb80a65c4aa4cc72de92d88a5aa91e958e590211487ffe635231dc1ba0adaa",
        True,
        """import WebKit
import UIKit
import External
struct Holder {
 var stash: String = "https://safe.example/"
 func read() -> String { return stash }
}
class Entry {
 let web = WKWebView()
 var h: Holder = Holder()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  ExternalMutator.put(&h, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: h.read())!))
  return true
 }
}
""",
        id="unknown-qualified-struct",
    ),
    pytest.param(
        "external-namespace-scalar",
        "a653dba66ff611deada45e0e8dad201061bb97dfc7769bcd8c51c8d2ccd83114",
        True,
        """import WebKit
import UIKit
import External
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  External.Mutator.put(&text, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="external-namespace-scalar",
    ),
    pytest.param(
        "unknown-qualified-literal",
        "0a8fa7f45fb6371a0fbd2fa2f97b97261cf4e79acd62c409f73b19ae68658df6",
        False,
        """import WebKit
import UIKit
import External
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  ExternalMutator.put(&text, "https://safe.example/")
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="unknown-qualified-literal",
    ),
    pytest.param(
        "unknown-unqualified-literal",
        "3c9d485ab73afc6dd949cac4d8d71b8410e013f66c55572d61baebfffa636dcc",
        False,
        """import WebKit
import UIKit
import External
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  put(&text, "https://safe.example/")
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="unknown-unqualified-literal",
    ),
    pytest.param(
        "known-inout-literal",
        "13c4dbdafea553d74684a06da22f6e639d85e4b9057a0be518c8c4174fcc8d25",
        False,
        """import WebKit
import UIKit
import External
final class ExternalMutator {
 static func put(_ target: inout String, _ value: String) { target = value }
}
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  ExternalMutator.put(&text, "https://safe.example/")
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="known-inout-literal",
    ),
    pytest.param(
        "known-inout-safe-body-with-tainted-unused-argument",
        "f48a671d904fcc8b10a655811bf22e97baccc558545dad62295992e0d1ae7662",
        True,
        """import WebKit
import UIKit
import External
final class ExternalMutator {
 static func put(_ target: inout String, _ value: String) { target = "https://safe.example/" }
}
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  ExternalMutator.put(&text, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="known-inout-safe-body-with-tainted-unused-argument",
    ),
    pytest.param(
        "known-byvalue-noop",
        "8f47dbc4b2bcb49f45f43f40484d6d4a1b7e1695852387ae08359f1a1cff975d",
        False,
        """import WebKit
import UIKit
import External
final class ExternalMutator {
 static func put(_ target: String, _ value: String) {  }
}
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  ExternalMutator.put(text, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="known-byvalue-noop",
    ),
    pytest.param(
        "unknown-qualified-unrelated-scalar",
        "7a2d3e514ee33b1f32ca8fb179f16f9adc1b74970a8cf0afb40f946b23d555f9",
        False,
        """import WebKit
import UIKit
import External
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 var other: String = "https://other.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  ExternalMutator.put(&other, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="unknown-qualified-unrelated-scalar",
    ),
    pytest.param(
        "known-inout-unrelated-scalar",
        "475434c696878e1eac0f9825069d8897cb8f801b0c2f8efbdde2021c3f31bebd",
        False,
        """import WebKit
import UIKit
import External
final class ExternalMutator {
 static func put(_ target: inout String, _ value: String) { target = value }
}
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 var other: String = "https://other.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  ExternalMutator.put(&other, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="known-inout-unrelated-scalar",
    ),
    pytest.param(
        "unknown-qualified-parameter-receiver",
        "9576e426eb777c9b0efe51250dada597492b74f4c7ab53e0b6fc37ecb3d1b2d8",
        True,
        """import WebKit
import UIKit
import External
class Entry {
 let web = WKWebView()
 var text: String = "https://safe.example/"
 var mutator: ExternalMutator
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
  mutator.put(&text, incoming.absoluteString)
  web.load(URLRequest(url: URL(string: text)!))
  return true
 }
}
""",
        id="unknown-qualified-parameter-receiver",
    ),
]


@pytest.mark.parametrize("name,source_sha256,unsafe,source", SWIFT_EXTERNAL_INOUT_PROBES)
def test_syntactic_inout_precedes_unknown_call_relevance_without_losing_known_controls(
    name, source_sha256, unsafe, source
):
    import hashlib

    assert hashlib.sha256(source.encode()).hexdigest() == source_sha256
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(unsafe), report
    if name == "known-byvalue-noop":
        assert report["metadata"]["native_flow"]["state"] == "checked", report
        assert report["metadata"]["native_flow"]["reasons"] == [], report
    else:
        assert report["metadata"]["native_flow"]["state"] == "partial", report
        assert "Swift inout writeback unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("dispatch", ["qualified", "namespace", "unqualified", "receiver", "callable"])
@pytest.mark.parametrize("lvalue", ["local", "self-field", "member"])
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_inout_syntax_updates_the_actual_local_or_field_storage(dispatch, lvalue, tainted):
    callee = {
        "qualified": "ExternalMutator.put",
        "namespace": "External.Mutator.put",
        "unqualified": "put",
        "receiver": "mutator.put",
        "callable": "writer",
    }[dispatch]
    target = {"local": "local", "self-field": "self.text", "member": "holder.text"}[lvalue]
    argument = "incoming.absoluteString" if tainted else '"https://safe.example/"'
    source = f"""import WebKit
import UIKit
import External
final class TextHolder {{ var text: String = "https://safe.example/" }}
class Entry {{
    let web = WKWebView()
    var text: String = "https://safe.example/"
    var holder: TextHolder = TextHolder()
    let mutator: ExternalMutator
    let writer: (inout String, String) -> Void
    init(_ mutator: ExternalMutator, _ writer: @escaping (inout String, String) -> Void) {{
        self.mutator = mutator
        self.writer = writer
    }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        var local: String = "https://safe.example/"
        {callee}(&{target}, {argument})
        web.load(URLRequest(url: URL(string: {target})!))
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "Swift inout writeback unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("inout_call", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_swift_inout_applicability_keeps_byvalue_noop_and_writeback_overloads_distinct(inout_call, tainted):
    argument = "incoming.absoluteString" if tainted else '"https://safe.example/"'
    source = f"""import WebKit
import UIKit
final class Mutator {{
    static func put(_ target: String, _ value: String) {{}}
    static func put(_ target: inout String, _ value: String) {{ target = value }}
}}
class Entry {{
    let web = WKWebView()
    var text: String = "https://safe.example/"
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        Mutator.put({"&" if inout_call else ""}text, {argument})
        web.load(URLRequest(url: URL(string: text)!))
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted and inout_call), report
    assert report["metadata"]["native_flow"]["state"] == ("partial" if inout_call else "checked"), report


def test_swift_ampersand_inside_a_literal_is_not_inout_syntax():
    source = """import WebKit
import UIKit
final class Helper {
    static func route(_ marker: String, _ input: String) -> String { return "https://safe.example/" }
}
class Entry {
    let web = WKWebView()
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {
        let text = Helper.route("&text", incoming.absoluteString)
        web.load(URLRequest(url: URL(string: text)!))
        return true
    }
}
"""
    report = scan(("app/Entry.swift", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("dispatch", ["qualified", "namespace", "unqualified", "receiver", "callable"])
@pytest.mark.parametrize("index", ["0", "position"])
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_inout_subscript_head_preserves_scalar_projection(dispatch, index, tainted):
    callee = {
        "qualified": "ExternalMutator.put",
        "namespace": "External.Mutator.put",
        "unqualified": "put",
        "receiver": "mutator.put",
        "callable": "writer",
    }[dispatch]
    argument = "incoming.absoluteString" if tainted else '"https://safe.example/"'
    unrelated = (
        f"web.load(URLRequest(url: URL(string: other[{index}])!))"
        if dispatch in {"qualified", "namespace", "receiver"}
        else ""
    )
    source = f"""import WebKit
import UIKit
import External
class Entry {{
    let web = WKWebView()
    var texts: [String] = ["https://safe.example/"]
    var other: [String] = ["https://safe.example/"]
    let mutator: ExternalMutator
    let writer: (inout String, String) -> Void
    init(_ mutator: ExternalMutator, _ writer: @escaping (inout String, String) -> Void) {{
        self.mutator = mutator
        self.writer = writer
    }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        let position = 0
        {callee}(&texts[{index}], {argument})
        web.load(URLRequest(url: URL(string: texts[{index}])!))
        {unrelated}
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "Swift inout writeback unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("dispatch", ["qualified", "namespace", "unqualified", "receiver", "callable"])
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_inout_nested_member_with_subscript_head_updates_the_actual_field(dispatch, tainted):
    callee = {
        "qualified": "ExternalMutator.put",
        "namespace": "External.Mutator.put",
        "unqualified": "put",
        "receiver": "mutator.put",
        "callable": "writer",
    }[dispatch]
    argument = "incoming.absoluteString" if tainted else '"https://safe.example/"'
    source = f"""import WebKit
import UIKit
import External
final class TextHolder {{ var text: String = "https://safe.example/" }}
class Entry {{
    let web = WKWebView()
    var holders: [TextHolder] = [TextHolder()]
    let mutator: ExternalMutator
    let writer: (inout String, String) -> Void
    init(_ mutator: ExternalMutator, _ writer: @escaping (inout String, String) -> Void) {{
        self.mutator = mutator
        self.writer = writer
    }}
    func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
        {callee}(&holders[0].text, {argument})
        web.load(URLRequest(url: URL(string: holders[0].text)!))
        return true
    }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "Swift inout writeback unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "callee", ["ExternalMutator.put", "External.ExternalMutator.put", "put", "operation"]
)
@pytest.mark.parametrize("binding", ["field", "alias", "member"])
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_swift_callable_preserves_possible_reference_argument_field_effects(callee, binding, tainted):
    argument = "incoming.absoluteString" if tainted else '"https://fresh-safe.example/"'
    target = {"field": "slot", "alias": "alias", "member": "box.child"}[binding]
    observed = "box.child" if binding == "member" else "slot"
    source = f"""import WebKit
import UIKit
import External
final class Holder {{
 var stash: String = "https://safe.example/"
 func read() -> String {{ return stash }}
}}
final class Box {{ let child: Holder = Holder() }}
final class Entry {{
 let web = WKWebView()
 let slot: Holder = Holder()
 let separate: Holder = Holder()
 let box: Box = Box()
 func application(_ app: UIApplication, open incoming: URL,
                  operation: (Holder, String) -> Void, options: [String: Any]) -> Bool {{
  let alias = slot
  {callee}({target}, {argument})
  web.load(URLRequest(url: URL(string: {observed}.read())!))
  web.load(URLRequest(url: URL(string: separate.read())!))
  return true
 }}
}}
"""
    report = scan(("Entry.swift", source))
    matches = findings(report, URL)
    assert len(matches) == int(tainted), report
    if tainted:
        assert observed + ".read()" in matches[0]["evidence"][0]["excerpt"], report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert not any(item.get("parse_errors") for item in report["metadata"]["files"]), report


@pytest.mark.parametrize("suffix", ["java", "kt"])
@pytest.mark.parametrize("callee", ["ExternalMutator.put", "vendor.ExternalMutator.put", "put"])
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_callable_reference_argument_mutation_is_independent_of_qualification(
    suffix, callee, tainted
):
    argument = "incoming.getDataString()" if tainted else '"https://fresh-safe.example/"'
    if suffix == "java":
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{
 String stash = "https://safe.example/";
 final String read() {{ return stash; }}
}}
class Entry {{
 void open(Intent incoming, WebView web) {{
  Holder slot = new Holder();
  Holder separate = new Holder();
  Holder alias = slot;
  {callee}(alias, {argument});
  web.loadUrl(slot.read());
  web.loadUrl(separate.read());
 }}
}}
"""
    else:
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Holder {{
 var stash: String = "https://safe.example/"
 fun read(): String {{ return stash }}
}}
class Entry {{
 fun open(incoming: Intent, web: WebView) {{
  val slot = Holder()
  val separate = Holder()
  val alias = slot
  {callee}(alias, {argument})
  web.loadUrl(slot.read())
  web.loadUrl(separate.read())
 }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    matches = findings(report, URL)
    assert len(matches) == int(tainted), report
    if tainted:
        assert "slot.read()" in matches[0]["evidence"][0]["excerpt"], report
    assert report["metadata"]["native_flow"]["state"] == "partial", report

    assert not any(item.get("parse_errors") for item in report["metadata"]["files"]), report


@pytest.mark.parametrize("kind", ["struct", "scalar"])
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_swift_byvalue_argument_does_not_gain_reference_writeback(kind, tainted):
    argument = "incoming.absoluteString" if tainted else '"https://fresh-safe.example/"'
    declaration = 'var slot: String = "https://safe.example/"'
    observed = "slot"
    if kind == "struct":
        declaration = "var slot: Holder = Holder()"
        observed = "slot.read()"
    source = f"""import WebKit
import UIKit
import External
struct Holder {{
 var stash: String = "https://safe.example/"
 func read() -> String {{ return stash }}
}}
final class Entry {{
 let web = WKWebView()
 {declaration}
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
  ExternalMutator.put(slot, {argument})
  web.load(URLRequest(url: URL(string: {observed})!))
  return true
 }}
}}
"""
    report = scan(("Entry.swift", source))
    assert not findings(report, URL), report


@pytest.mark.parametrize("mutates", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_source_known_swift_reference_summary_keeps_safe_and_separate_objects(mutates, tainted):
    argument = "incoming.absoluteString" if tainted else '"https://fresh-safe.example/"'
    body = "target.stash = value" if mutates else ""
    source = f"""import WebKit
import UIKit
final class Holder {{
 var stash: String = "https://safe.example/"
 func read() -> String {{ return stash }}
}}
final class Helper {{ static func put(_ target: Holder, _ value: String) {{ {body} }} }}
final class Entry {{
 let web = WKWebView()
 let slot: Holder = Holder()
 let separate: Holder = Holder()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
  Helper.put(slot, {argument})
  web.load(URLRequest(url: URL(string: slot.read())!))
  web.load(URLRequest(url: URL(string: separate.read())!))
  return true
 }}
}}
"""
    report = scan(("Entry.swift", source))
    assert len(findings(report, URL)) == int(mutates and tainted), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_swift_mixed_reference_and_value_arguments_only_weaken_reference_storage(tainted):
    argument = "incoming.absoluteString" if tainted else '"https://fresh-safe.example/"'
    source = f"""import WebKit
import UIKit
import External
final class Holder {{
 var stash: String = "https://safe.example/"
 func read() -> String {{ return stash }}
}}
struct ValueBox {{
 var stash: String = "https://safe.example/"
 func read() -> String {{ return stash }}
}}
final class Entry {{
 let web = WKWebView()
 let slot: Holder = Holder()
 var value: ValueBox = ValueBox()
 var scalar: String = "https://safe.example/"
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
  ExternalMutator.put(slot, value, scalar, {argument})
  web.load(URLRequest(url: URL(string: slot.read())!))
  web.load(URLRequest(url: URL(string: value.read())!))
  web.load(URLRequest(url: URL(string: scalar)!))
  return true
 }}
}}
"""
    report = scan(("Entry.swift", source))
    matches = findings(report, URL)
    assert len(matches) == int(tainted), report
    if tainted:
        assert "slot.read()" in matches[0]["evidence"][0]["excerpt"], report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


# Verbatim independent v20 source controls; only synthetic strings.
V20_VALUE_REFERENCE_SOURCE = 'import WebKit\nimport UIKit\nimport External\nfinal class Holder {\n var stash: String = "https://safe.example/"\n func read() -> String { return stash }\n}\nstruct Box {\n let child: Holder = Holder()\n func read() -> String { return child.read() }\n}\n\nfinal class Entry {\n let web = WKWebView()\n let box: Box = Box()\n let separate: Box = Box()\n func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {\n  ExternalMutator.put(box, incoming.absoluteString)\n  web.load(URLRequest(url: URL(string: box.read())!))\n  web.load(URLRequest(url: URL(string: separate.read())!))\n  return true\n }\n}\n'

V20_JAVA_ERASED_REFERENCE_SOURCE = 'package app;\nimport android.content.Intent;\nimport android.webkit.WebView;\nfinal class Holder { String stash="https://safe.example/"; final String read(){return stash;} }\n\nfinal class Entry { static void open(Intent incoming, WebView web) { Holder slot=new Holder(); Holder separate=new Holder(); Object alias=slot; ExternalMutator.put(alias,incoming.getDataString()); web.loadUrl(slot.read()); web.loadUrl(separate.read()); } }\n'

V20_SWIFT_ERASED_REFERENCE_SOURCE = 'import WebKit\nimport UIKit\nimport External\nfinal class Holder {\n var stash: String = "https://safe.example/"\n func read() -> String { return stash }\n}\n\nfinal class Entry {\n let web = WKWebView()\n let slot: Holder = Holder()\n let separate: Holder = Holder()\n func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {\n  let alias: Any = slot\n  ExternalMutator.put(alias, incoming.absoluteString)\n  web.load(URLRequest(url: URL(string: slot.read())!))\n  web.load(URLRequest(url: URL(string: separate.read())!))\n  return true\n }\n}'


@pytest.mark.parametrize("tainted", [False, True])
@pytest.mark.parametrize("binding", ["direct", "copy", "Any", "AnyObject"])
@pytest.mark.parametrize("nesting", ["value", "value-value", "value-reference"])
def test_unknown_swift_effect_reaches_shared_reference_children_of_copied_values(binding, nesting, tainted):
    source = V20_VALUE_REFERENCE_SOURCE
    if nesting != "value":
        nominal = "struct" if nesting == "value-value" else "final class"
        source = source.replace(
            "struct Box {",
            f"{nominal} Inner {{\n let child: Holder = Holder()\n}}\nstruct Box {{",
        ).replace("let child: Holder = Holder()\n func read()", "let inner: Inner = Inner()\n func read()")
        source = source.replace("return child.read()", "return inner.child.read()")
    if binding != "direct":
        # AnyObject erases the contained reference, not the value itself.
        expression = "box.child" if binding == "AnyObject" else "box"
        if nesting != "value" and binding == "AnyObject":
            expression = "box.inner.child"
        annotation = "" if binding == "copy" else f": {binding}"
        source = source.replace(
            "ExternalMutator.put(box,", f"let alias{annotation} = {expression}\n  ExternalMutator.put(alias,"
        )
    if not tainted:
        source = source.replace(
            "put(box, incoming.absoluteString)", 'put(box, "https://fresh-safe.example/")'
        )
        source = source.replace(
            "put(alias, incoming.absoluteString)", 'put(alias, "https://fresh-safe.example/")'
        )
    report = scan(("app/Entry.swift", source))
    matches = findings(report, URL)
    assert len(matches) == int(tainted), report
    if tainted:
        assert "box.read()" in matches[0]["evidence"][0]["excerpt"], report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert not any(item.get("parse_errors") for item in report["metadata"]["files"]), report


@pytest.mark.parametrize("suffix,erased", [("java", "Object"), ("swift", "Any"), ("swift", "AnyObject")])
@pytest.mark.parametrize("tainted", [False, True])
@pytest.mark.parametrize("binding", ["local", "field", "return"])
def test_unknown_effect_uses_materialized_identity_through_erased_reference_bindings(
    suffix, erased, tainted, binding
):
    source = V20_JAVA_ERASED_REFERENCE_SOURCE if suffix == "java" else V20_SWIFT_ERASED_REFERENCE_SOURCE
    source = source.replace("let alias: Any = slot", f"let alias: {erased} = slot")
    if binding == "field":
        if suffix == "java":
            source = source.replace("final class Entry {", "final class Entry { static Object erased;")
            source = source.replace("Object alias=slot;", "erased=slot; Object alias=erased;")
        else:
            source = source.replace("let web = WKWebView()", f"var erased: {erased}?\n let web = WKWebView()")
            source = source.replace(
                f"let alias: {erased} = slot", f"erased = slot\n  let alias: {erased} = erased!"
            )
    elif binding == "return":
        if suffix == "java":
            source = source.replace(
                "final class Entry {", "final class Entry { static Object erase(Holder value){return value;}"
            )
            source = source.replace("Object alias=slot;", "Object alias=erase(slot);")
        else:
            source = source.replace(
                "final class Entry {",
                f"final class Entry {{\n static func erase(_ value: Holder) -> {erased} {{ return value }}",
            )
            source = source.replace(f"let alias: {erased} = slot", f"let alias: {erased} = Entry.erase(slot)")
    if not tainted:
        source = source.replace("incoming.getDataString()", '"https://fresh-safe.example/"')
        source = source.replace(
            "put(alias, incoming.absoluteString)", 'put(alias, "https://fresh-safe.example/")'
        )
    if suffix == "java":
        source = source.replace("; ", ";\n")
    report = scan((f"app/Entry.{suffix}", source))
    matches = findings(report, URL)
    assert len(matches) == int(tainted), report
    if tainted:
        assert "slot.read()" in matches[0]["evidence"][0]["excerpt"], report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert not any(item.get("parse_errors") for item in report["metadata"]["files"]), report


@pytest.mark.parametrize("mutates", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_known_value_contained_reference_summary_retains_body_precision(mutates, tainted):
    body = "target.child.stash = value" if mutates else ""
    source = V20_VALUE_REFERENCE_SOURCE.replace(
        "final class Entry {",
        f"final class ExternalMutator {{ static func put(_ target: Box, _ value: String) {{ {body} }} }}\nfinal class Entry {{",
    )
    if not tainted:
        source = source.replace(
            "put(box, incoming.absoluteString)", 'put(box, "https://fresh-safe.example/")'
        )
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(mutates and tainted), report
    if mutates and tainted:
        assert "box.read()" in findings(report, URL)[0]["evidence"][0]["excerpt"], report


@pytest.mark.parametrize(
    "field", ["var opaque: ExternalHolder?", "var optional: ExternalHolder?", "var children: [Holder] = []"]
)
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_reachable_field_ownership_retains_affected_value_storage(field, tainted):
    # Unsupported container/optional/external ownership cannot imply read-only.
    source = V20_VALUE_REFERENCE_SOURCE.replace(
        "let child: Holder = Holder()", field + '\n var text: String = "https://safe.example/"'
    )
    source = source.replace("return child.read()", "return text")
    if not tainted:
        source = source.replace(
            "put(box, incoming.absoluteString)", 'put(box, "https://fresh-safe.example/")'
        )
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert "reachable field ownership unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("budget", ["MAX_EFFECT_DEPTH", "MAX_EFFECT_OBJECTS"])
@pytest.mark.parametrize("tainted", [False, True])
def test_reference_reachability_budget_retains_lazy_child_taint(monkeypatch, budget, tainted):
    from mobile_audit import native_flow

    monkeypatch.setattr(native_flow, budget, 1)
    source = V20_VALUE_REFERENCE_SOURCE
    if not tainted:
        source = source.replace(
            "put(box, incoming.absoluteString)", 'put(box, "https://fresh-safe.example/")'
        )
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert "reference effect inventory budget" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize(
    "source,expected",
    [
        (V20_VALUE_REFERENCE_SOURCE, "db39ad5d090332358bd762ff2dcc8e9d7e69ce5b39bc2c92825fa5a2c776e40e"),
        (
            V20_JAVA_ERASED_REFERENCE_SOURCE,
            "f9d07bd479ffc1345c74fcc9f1f45097cfc85a69c32eab842e2b9d7ae4a40d25",
        ),
        (
            V20_SWIFT_ERASED_REFERENCE_SOURCE,
            "3d860734305bdcc5cfd2cebe39448dd6e7b083b8a91b7d190e4428a5b22541cf",
        ),
    ],
)
def test_independent_v20_reachable_reference_sources_are_preserved(source, expected):
    assert hashlib.sha256(source.encode()).hexdigest() == expected


@pytest.mark.parametrize(
    "declaration", ['var stash = "https://safe.example/"', 'var stash: String = "https://safe.example/"']
)
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_copied_scalar_value_has_no_caller_writeback(declaration, tainted):
    argument = "incoming.absoluteString" if tainted else '"https://fresh-safe.example/"'
    source = f"""import WebKit
import UIKit
import External
struct Plain {{
 {declaration}
 func read() -> String {{ return stash }}
}}
final class Entry {{
 let web = WKWebView()
 let plain: Plain = Plain()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
  ExternalMutator.put(plain, {argument})
  web.load(URLRequest(url: URL(string: plain.read())!))
  return true
 }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("tainted", [False, True])
def test_static_reference_field_is_not_part_of_a_copied_value(tainted):
    source = V20_VALUE_REFERENCE_SOURCE.replace("let child: Holder", "static let child: Holder")
    source = source.replace("return child.read()", "return Box.child.read()")
    if not tainted:
        source = source.replace(
            "put(box, incoming.absoluteString)", 'put(box, "https://fresh-safe.example/")'
        )
    report = scan(("app/Entry.swift", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("tainted", [False, True])
def test_materialized_index_reference_survives_type_erasure(tainted):
    argument = "incoming.getDataString()" if tainted else '"https://fresh-safe.example/"'
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{ String stash = "https://safe.example/"; final String read() {{ return stash; }} }}
class Entry {{
 void open(Intent incoming, WebView web, Holder[] slots, Holder separate) {{
  Object alias = slots[0];
  ExternalMutator.put(alias, {argument});
  web.loadUrl(slots[0].read());
  web.loadUrl(separate.read());
 }}
}}
"""
    report = scan(("app/Entry.java", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize("tainted", [False, True])
def test_kotlin_any_alias_keeps_reference_effect_storage(tainted):
    argument = "incoming.getDataString()" if tainted else '"https://fresh-safe.example/"'
    source = f"""package app
import android.content.Intent
import android.webkit.WebView
class Holder {{
 var stash: String = "https://safe.example/"
 fun read(): String {{ return stash }}
}}
class Entry {{
 fun open(incoming: Intent, web: WebView, slot: Holder, separate: Holder) {{
  val alias: Any = slot
  ExternalMutator.put(alias, {argument})
  web.loadUrl(slot.read())
  web.loadUrl(separate.read())
 }}
}}
"""
    report = scan(("app/Entry.kt", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize("tainted", [False, True])
def test_cyclic_reference_inventory_is_bounded_and_retains_effects(tainted):
    argument = "incoming.getDataString()" if tainted else '"https://fresh-safe.example/"'
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{
 Holder next;
 String stash = "https://safe.example/";
 final String read() {{ return stash; }}
}}
class Entry {{
 void open(Intent incoming, WebView web) {{
  Holder slot = new Holder();
  slot.next = slot;
  Holder separate = new Holder();
  ExternalMutator.put(slot, {argument});
  web.loadUrl(slot.next.read());
  web.loadUrl(separate.read());
 }}
}}
"""
    report = scan(("app/Entry.java", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert "cyclic reference effect inventory" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_reference_field_replacement_does_not_reuse_old_allocation_dispatch_proof(tainted):
    argument = "incoming.getDataString()" if tainted else '"https://fresh-safe.example/"'
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
class Holder {{ String read() {{ return "https://safe.example/"; }} }}
class Attacker extends Holder {{ String read() {{ return "https://attacker.example/"; }} }}
final class Box {{ Holder child; }}
class Entry {{
 void open(Intent incoming, WebView web) {{
  Box box = new Box();
  box.child = new Holder();
  ExternalMutator.put(box, {argument});
  web.loadUrl(box.child.read());
 }}
}}
"""
    report = scan(("app/Entry.java", source))
    assert len(findings(report, URL)) == int(tainted), report
    if tainted:
        assert "receiver runtime dispatch unresolved" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("known", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_inferred_reference_field_inventory_uses_constructor_syntax_without_getter_execution(known, tainted):
    source = V20_VALUE_REFERENCE_SOURCE.replace("let child: Holder = Holder()", "let child = Holder()")
    if known:
        source = source.replace(
            "final class Entry {",
            "final class ExternalMutator { static func put(_ target: Box, _ value: String) {} }\nfinal class Entry {",
        )
    if not tainted:
        source = source.replace(
            "put(box, incoming.absoluteString)", 'put(box, "https://fresh-safe.example/")'
        )
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted and not known), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    if known:
        assert "unresolved reference argument effects" not in report["metadata"]["native_flow"]["reasons"], (
            report
        )


@pytest.mark.parametrize("kind", ["protocol", "enum-payload"])
@pytest.mark.parametrize("tainted", [False, True])
def test_unsupported_swift_payload_or_protocol_ownership_does_not_imply_readonly(kind, tainted):
    argument = "incoming.absoluteString" if tainted else '"https://fresh-safe.example/"'
    declaration = "protocol Box { func read() -> String }"
    if kind == "enum-payload":
        declaration = """enum Box {
 case child(Holder)
 func read() -> String {
  switch self { case let .child(value): return value.read() }
 }
}"""
    source = f"""import WebKit
import UIKit
import External
final class Holder {{ var stash: String = "https://safe.example/"; func read() -> String {{ return stash }} }}
{declaration}
final class Entry {{
 let web = WKWebView()
 func application(_ app: UIApplication, open incoming: URL, box: Box, options: [String: Any]) -> Bool {{
  ExternalMutator.put(box, {argument})
  web.load(URLRequest(url: URL(string: box.read())!))
  return true
 }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert "reachable field ownership unavailable" in report["metadata"]["native_flow"]["reasons"], report
    assert not any(item.get("parse_errors") for item in report["metadata"]["files"]), report


@pytest.mark.parametrize("erased", ["Any", "AnyObject"])
@pytest.mark.parametrize("tainted", [False, True])
@pytest.mark.parametrize("binding", ["parentheses", "forced-cast-write", "forced-cast-read"])
def test_swift_parenthesized_erased_reference_preserves_actual_storage_not_cast_dispatch_proof(
    erased, tainted, binding
):
    source = V20_SWIFT_ERASED_REFERENCE_SOURCE.replace("let alias: Any", f"let alias: {erased}")
    if binding == "parentheses":
        source = source.replace("= slot\n", "= (slot)\n")
    else:
        source = source.replace(
            "final class Entry {",
            f"final class ExternalMutator {{ static func put(_ target: {erased}, _ value: String) {{ (target as! Holder).stash = value }} }}\nfinal class Entry {{",
        )
        if binding == "forced-cast-read":
            source = source.replace("URL(string: slot.read())", "URL(string: (alias as! Holder).read())")
    if not tainted:
        source = source.replace(
            "put(alias, incoming.absoluteString)", 'put(alias, "https://fresh-safe.example/")'
        )
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


def test_swift_parentheses_normalization_does_not_flatten_real_tuple_storage():
    import tree_sitter
    import tree_sitter_swift

    from mobile_audit.source_analysis import Analyzer

    parser = tree_sitter.Parser(tree_sitter.Language(tree_sitter_swift.language()))
    source = b"let a = (slot)\nlet b = (slot,)\nlet c = (slot, other)\nlet d = (label: slot)"
    root = parser.parse(source).root_node
    analyzer = Analyzer("fresh/Entry.swift", source.decode(), "swift")
    nodes = [declaration.named_children[-1] for declaration in root.named_children]
    assert analyzer.text(analyzer.unwrap(nodes[0])) == "slot"
    for node in nodes[1:]:
        assert analyzer.unwrap(node) == node


V21_TUPLE_REFERENCE_SOURCE = 'import WebKit\nimport UIKit\nimport External\nfinal class Holder {\n var stash: String = "https://safe.example/"\n func read() -> String { return stash }\n}\n\nfinal class Entry {\n let web = WKWebView()\n let slot: Holder = Holder()\n let separate: Holder = Holder()\n func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {\n  let values: (Holder, Int) = (slot, 1)\n  ExternalMutator.put(values, incoming.absoluteString)\n  web.load(URLRequest(url: URL(string: slot.read())!))\n  web.load(URLRequest(url: URL(string: separate.read())!))\n  return true\n }\n}\n'


V21_ARRAY_REFERENCE_SOURCE = 'import WebKit\nimport UIKit\nimport External\nfinal class Holder {\n var stash: String = "https://safe.example/"\n func read() -> String { return stash }\n}\n\nfinal class Entry {\n let web = WKWebView()\n let slot: Holder = Holder()\n let separate: Holder = Holder()\n func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {\n  let values: [Holder] = [slot, separate]\n  ExternalMutator.put(values, incoming.absoluteString)\n  web.load(URLRequest(url: URL(string: slot.read())!))\n  web.load(URLRequest(url: URL(string: separate.read())!))\n  return true\n }\n}\n'


@pytest.mark.parametrize("kind", ["tuple", "array"])
@pytest.mark.parametrize("binding", ["explicit", "inferred", "alias", "erased", "nested", "field"])
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_swift_aggregate_argument_reaches_all_exposed_references(kind, binding, tainted):
    source = V21_TUPLE_REFERENCE_SOURCE if kind == "tuple" else V21_ARRAY_REFERENCE_SOURCE
    # Keep a genuinely unexposed object outside the argument graph.
    source = source.replace(
        "let separate: Holder = Holder()", "let separate: Holder = Holder()\n let outside: Holder = Holder()"
    )
    source = source.replace(
        "  return true", "  web.load(URLRequest(url: URL(string: outside.read())!))\n  return true"
    )
    declaration = (
        "let values: (Holder, Int) = (slot, 1)"
        if kind == "tuple"
        else "let values: [Holder] = [slot, separate]"
    )
    if binding == "inferred":
        source = source.replace(
            declaration, declaration.replace(": (Holder, Int)", "").replace(": [Holder]", "")
        )
    elif binding in {"alias", "erased"}:
        source = source.replace(
            "  ExternalMutator.put(values,",
            f"  let alias{': Any' if binding == 'erased' else ''} = values\n  ExternalMutator.put(alias,",
        )
    elif binding == "nested":
        source = source.replace(declaration, "let values = ([((slot, 1), separate)], 2)")
    elif binding == "field":
        source = source.replace("let web = WKWebView()", "var stored: Any\n let web = WKWebView()")
        source = source.replace(
            "  ExternalMutator.put(values,", "  stored = values\n  ExternalMutator.put(stored,"
        )
    if not tainted:
        source = source.replace("incoming.absoluteString)", '"https://fresh-safe.example/")')
    report = scan(("app/Entry.swift", source))
    matches = findings(report, URL)
    expected = 2 if kind == "array" or binding == "nested" else 1
    assert len(matches) == (expected if tainted else 0), report
    if tainted:
        assert all("outside.read()" not in row["evidence"][0]["excerpt"] for row in matches), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), report


@pytest.mark.parametrize("kind", ["tuple", "array"])
@pytest.mark.parametrize("tainted", [False, True])
def test_known_swift_aggregate_noop_keeps_body_precision(kind, tainted):
    source = V21_TUPLE_REFERENCE_SOURCE if kind == "tuple" else V21_ARRAY_REFERENCE_SOURCE
    declared = "(Holder, Int)" if kind == "tuple" else "[Holder]"
    source = source.replace(
        "final class Entry {",
        f"final class ExternalMutator {{ static func put(_ values: {declared}, _ input: String) {{}} }}\nfinal class Entry {{",
    )
    if not tainted:
        source = source.replace("incoming.absoluteString)", '"https://fresh-safe.example/")')
    report = scan(("app/Entry.swift", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize(
    "literal",
    ['(1, "safe")', '["safe", "also-safe"]', '(label: "safe", number: 1)', '[(1, "safe"), (2, "also-safe")]'],
)
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_scalar_only_swift_aggregate_has_no_caller_reference_effects(literal, tainted):
    source = V21_TUPLE_REFERENCE_SOURCE.replace(
        "let values: (Holder, Int) = (slot, 1)", f"let values = {literal}"
    )
    if not tainted:
        source = source.replace("incoming.absoluteString)", '"https://fresh-safe.example/")')
    report = scan(("app/Entry.swift", source))
    assert not findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "checked", report


@pytest.mark.parametrize("declared", ["[Holder]", "(Holder, Int)", "[String: Holder]", "Array<Holder>"])
@pytest.mark.parametrize("binding", ["parameter", "factory"])
@pytest.mark.parametrize("tainted", [False, True])
def test_opaque_swift_aggregate_root_reports_unavailable_ownership(declared, binding, tainted):
    source = V21_TUPLE_REFERENCE_SOURCE
    if binding == "parameter":
        source = source.replace("options: [String: Any])", f"values: {declared}, options: [String: Any])")
        source = source.replace("  let values: (Holder, Int) = (slot, 1)\n", "")
    else:
        source = source.replace(
            "let values: (Holder, Int) = (slot, 1)", f"let values: {declared} = ExternalFactory.make()"
        )
    if not tainted:
        source = source.replace("incoming.absoluteString)", '"https://fresh-safe.example/")')
    report = scan(("app/Entry.swift", source))
    assert not findings(report, URL), report
    assert "aggregate reference ownership unavailable" in report["metadata"]["native_flow"]["reasons"], report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize(
    "source,expected",
    [
        (V21_TUPLE_REFERENCE_SOURCE, "0c7859ced5044290f014eeee2549b39d3014edcecc300ec85c08e962d549237c"),
        (V21_ARRAY_REFERENCE_SOURCE, "5de7d97a376fe4cab385bb48347b395326fe914996322fe519e1d8189cefb130"),
    ],
)
def test_independent_v21_aggregate_sources_are_preserved(source, expected):
    assert hashlib.sha256(source.encode()).hexdigest() == expected


@pytest.mark.parametrize(
    "expression,exposed",
    [("(slot, 1)", 1), ("[slot, separate]", 2), ('["child": slot]', 1), ("(items: [slot], count: 1)", 1)],
)
@pytest.mark.parametrize("tainted", [False, True])
def test_unknown_direct_swift_container_expression_retains_reference_edges(expression, exposed, tainted):
    source = V21_TUPLE_REFERENCE_SOURCE.replace("  let values: (Holder, Int) = (slot, 1)\n", "")
    source = source.replace("put(values,", f"put({expression},")
    if not tainted:
        source = source.replace("incoming.absoluteString)", '"https://fresh-safe.example/")')
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == (exposed if tainted else 0), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize("copy", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_swift_container_reassignment_replaces_edges_without_rebinding_existing_copy(copy, tainted):
    source = V21_TUPLE_REFERENCE_SOURCE.replace(
        "let values: (Holder, Int) = (slot, 1)", "var values = [slot]"
    )
    replacement = (
        "let alias: Any = values\n  values = [separate]\n  ExternalMutator.put(alias,"
        if copy
        else "values = [separate]\n  ExternalMutator.put(values,"
    )
    source = source.replace("ExternalMutator.put(values,", replacement)
    if not tainted:
        source = source.replace("incoming.absoluteString)", '"https://fresh-safe.example/")')
    report = scan(("app/Entry.swift", source))
    matches = findings(report, URL)
    assert len(matches) == int(tainted), report
    if tainted:
        expected = "slot.read()" if copy else "separate.read()"
        assert expected in matches[0]["evidence"][0]["excerpt"], report


@pytest.mark.parametrize("tainted", [False, True])
def test_swift_mixed_aggregate_keeps_value_only_member_storage_separate(tainted):
    source = V21_TUPLE_REFERENCE_SOURCE.replace(
        "final class Entry {",
        'struct Plain { var text: String = "https://safe.example/"; func read() -> String { return text } }\nfinal class Entry {',
    )
    source = source.replace(
        "let values: (Holder, Int) = (slot, 1)", "let plain = Plain()\n  let values = (plain, [slot])"
    )
    source = source.replace(
        "  return true", "  web.load(URLRequest(url: URL(string: plain.read())!))\n  return true"
    )
    if not tainted:
        source = source.replace("incoming.absoluteString)", '"https://fresh-safe.example/")')
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report


@pytest.mark.parametrize(
    "suffix,declared", [("java", "String[]"), ("kt", "Array<String>"), ("kt", "MutableList<String>")]
)
@pytest.mark.parametrize("known", [False, True])
@pytest.mark.parametrize("tainted", [False, True])
def test_scalar_java_kotlin_reference_containers_are_not_swift_value_copies(suffix, declared, known, tainted):
    argument = "incoming.getDataString()" if tainted else '"https://fresh-safe.example/"'
    if suffix == "java":
        helper = (
            "final class ExternalMutator { static void put(String[] values, String input) {} }"
            if known
            else ""
        )
        source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
{helper}
class Entry {{
 void open(Intent incoming, WebView web, String[] values, String[] outside) {{
  ExternalMutator.put(values, {argument});
  web.loadUrl(values[0]);
  web.loadUrl(outside[0]);
 }}
}}
"""
    else:
        helper = (
            f"object ExternalMutator {{ fun put(values: {declared}, input: String) {{}} }}" if known else ""
        )
        source = f"""package app
import android.content.Intent
import android.webkit.WebView
{helper}
class Entry {{
 fun open(incoming: Intent, web: WebView, values: {declared}, outside: {declared}) {{
  ExternalMutator.put(values, {argument})
  web.loadUrl(values[0])
  web.loadUrl(outside[0])
 }}
}}
"""
    report = scan((f"app/Entry.{suffix}", source))
    assert len(findings(report, URL)) == int(tainted and not known), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    if known:
        assert "unresolved reference argument effects" not in report["metadata"]["native_flow"]["reasons"], (
            report
        )


@pytest.mark.parametrize("tainted", [False, True])
def test_java_array_literal_retains_contained_reference_identities(tainted):
    argument = "incoming.getDataString()" if tainted else '"https://fresh-safe.example/"'
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{ String text = "https://safe.example/"; final String read() {{ return text; }} }}
class Entry {{
 void open(Intent incoming, WebView web) {{
  Holder slot = new Holder();
  Holder outside = new Holder();
  Object values = new Holder[] {{slot}};
  ExternalMutator.put(values, {argument});
  web.loadUrl(slot.read());
  web.loadUrl(outside.read());
 }}
}}
"""
    report = scan(("app/Entry.java", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize("kind", ["tuple", "array"])
def test_aggregate_effect_edges_never_become_nominal_or_dispatch_evidence(monkeypatch, kind):
    from mobile_audit.native_flow import NativeFlow, StorageKey

    original = NativeFlow.call
    captures = []

    def capture(self, analyzer, call, frame, receiver, args):
        if call.name == "put" and args and args[0].identity in self.effect_aggregates:
            aggregate = args[0]
            assert aggregate.identity not in self.effect_nominals
            assert aggregate.identity not in self.allocations
            assert aggregate.type_name in {"(Holder, Int)", "[Holder]"}
            elements = [
                value.identity
                for key, value in frame.object_fields[aggregate.identity].items()
                if isinstance(key, tuple) and key[0] is StorageKey.AGGREGATE_ELEMENT
            ]
            assert frame.values["slot"].identity in elements
            captures.append(aggregate.identity)
        return original(self, analyzer, call, frame, receiver, args)

    monkeypatch.setattr(NativeFlow, "call", capture)
    source = V21_TUPLE_REFERENCE_SOURCE if kind == "tuple" else V21_ARRAY_REFERENCE_SOURCE
    scan(("app/Entry.swift", source))
    assert captures


@pytest.mark.parametrize("budget", ["MAX_EFFECT_DEPTH", "MAX_EFFECT_OBJECTS"])
def test_aggregate_inventory_limit_retains_explicit_partial_boundary(monkeypatch, budget):
    from mobile_audit import native_flow

    monkeypatch.setattr(native_flow, budget, 1)
    report = scan(("app/Entry.swift", V21_TUPLE_REFERENCE_SOURCE))
    assert findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert "reference effect inventory budget" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("second_tainted", [False, True])
def test_reference_container_unknown_write_does_not_erase_possible_old_element_aliases(second_tainted):
    argument = 'incoming.getStringExtra("next")' if second_tainted else '"https://fresh-safe.example/"'
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
final class Holder {{ String text = "https://safe.example/"; final String read() {{ return text; }} }}
class Entry {{
 void open(Intent incoming, WebView web) {{
  Holder slot = new Holder();
  Holder[] values = new Holder[] {{slot}};
  ExternalMutator.put(values, incoming.getDataString());
  slot.text = "https://reset-safe.example/";
  ExternalMutator.put(values, {argument});
  web.loadUrl(slot.read());
 }}
}}
"""
    report = scan(("app/Entry.java", source))
    # Even a literal second argument may transfer previously stored uncertain
    # container state; neither unknown call proves the old alias was removed.
    assert findings(report, URL), report
    assert report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize(
    "declared,projection",
    [
        ("[String]", "values[0]"),
        ("Array<String>", "values[0]"),
        ("[String: String]", 'values["key"]!'),
        ("(String, Int)", "values.0"),
        ("[(String, Int)]", "values[0].0"),
    ],
)
@pytest.mark.parametrize("tainted", [False, True])
def test_opaque_typed_swift_scalar_aggregate_remains_a_value_copy(declared, projection, tainted):
    argument = "incoming.absoluteString" if tainted else '"https://fresh-safe.example/"'
    source = f"""import WebKit
import UIKit
import External
final class Entry {{
 let web = WKWebView()
 func application(_ app: UIApplication, open incoming: URL, values: {declared}, options: [String: Any]) -> Bool {{
  ExternalMutator.put(values, {argument})
  web.load(URLRequest(url: URL(string: {projection})!))
  return true
 }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert not findings(report, URL), report
    assert "unresolved reference argument effects" not in report["metadata"]["native_flow"]["reasons"], report
    assert "aggregate reference ownership unavailable" not in report["metadata"]["native_flow"]["reasons"], (
        report
    )


def test_scalar_aggregate_type_proof_refuses_shadowed_builtin_names():
    source = """import WebKit
import UIKit
import External
final class String { var stash: Swift.String = "https://safe.example/" }
final class Entry {
 let web = WKWebView()
 func application(_ app: UIApplication, open incoming: URL, values: [String], options: [Swift.String: Any]) -> Bool {
  ExternalMutator.put(values, incoming.absoluteString)
  return true
 }
}
"""
    report = scan(("app/Entry.swift", source))
    assert "aggregate reference ownership unavailable" in report["metadata"]["native_flow"]["reasons"], report


@pytest.mark.parametrize("declared", ["Any", "AnyObject"])
@pytest.mark.parametrize("tainted", [False, True])
def test_source_bound_opaque_swift_erased_root_keeps_unavailable_reference_effects(declared, tainted):
    argument = "incoming.absoluteString" if tainted else '"https://fresh-safe.example/"'
    source = f"""import WebKit
import UIKit
import External
final class Holder {{ var stash: String = "https://safe.example/"; func read() -> String {{ return stash }} }}
final class Entry {{
 let web = WKWebView()
 func application(_ app: UIApplication, open incoming: URL, value: {declared}, outside: {declared}, options: [String: Any]) -> Bool {{
  ExternalMutator.put(value, {argument})
  web.load(URLRequest(url: URL(string: (value as! Holder).stash)!))
  web.load(URLRequest(url: URL(string: (outside as! Holder).stash)!))
  return true
 }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert "aggregate reference ownership unavailable" in report["metadata"]["native_flow"]["reasons"], report


V22_CANONICAL_FRONTIER_SOURCE = 'import WebKit\nimport UIKit\nfinal class Entry {\n let web = WKWebView()\n func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {\n  let values: [String] = ["","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",incoming.absoluteString]\n  web.load(URLRequest(url: URL(string: values.joined())!))\n  return true\n }\n}\n'


V22_CANONICAL_SHORT_SOURCE = 'import WebKit\nimport UIKit\nfinal class Entry {\n let web = WKWebView()\n func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {\n  let values: [String] = ["",incoming.absoluteString]\n  web.load(URLRequest(url: URL(string: values.joined())!))\n  return true\n }\n}\n'


V22_CANONICAL_LITERAL_SOURCE = 'import WebKit\nimport UIKit\nfinal class Entry {\n let web = WKWebView()\n func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {\n  let values: [String] = ["","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","https://safe.example/"]\n  web.load(URLRequest(url: URL(string: values.joined())!))\n  return true\n }\n}\n'


@pytest.mark.parametrize("count", [127, 128, 129])
@pytest.mark.parametrize("tainted", [False, True])
@pytest.mark.parametrize("sink", ["joined", "description", "interpolation"])
@pytest.mark.parametrize("binding", ["typed", "inferred", "copy"])
def test_swift_aggregate_edge_limit_does_not_limit_ordinary_tail_value_flow(count, tainted, sink, binding):
    tail = "incoming.absoluteString" if tainted else '"https://safe.example/"'
    elements = ",".join(['""'] * (count - 1) + [tail])
    annotation = "" if binding == "inferred" else ": [String]"
    copy = "let copied = values" if binding == "copy" else ""
    observed = "copied" if binding == "copy" else "values"
    expression = {
        "joined": f"{observed}.joined()",
        "description": f"String(describing: {observed})",
        "interpolation": '"\\(' + observed + ')"',
    }[sink]
    source = f"""import WebKit
import UIKit
final class Entry {{
 let web = WKWebView()
 func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{
  let values{annotation} = [{elements}]
  {copy}
  web.load(URLRequest(url: URL(string: {expression})!))
  return true
 }}
}}
"""
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == ("partial" if count > 128 else "checked"), report
    assert ("aggregate element inventory budget" in report["metadata"]["native_flow"]["reasons"]) == (
        count > 128
    ), report
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), report


@pytest.mark.parametrize("count", [127, 128, 129])
@pytest.mark.parametrize("tainted", [False, True])
@pytest.mark.parametrize("binding", ["String[]", "var"])
@pytest.mark.parametrize("sink", ["join", "description"])
def test_java_reference_array_edge_limit_keeps_tail_value_provenance(count, tainted, binding, sink):
    tail = "incoming.getDataString()" if tainted else '"https://safe.example/"'
    elements = ",".join(['""'] * (count - 1) + [tail])
    expression = 'String.join("", values)' if sink == "join" else "Arrays.toString(values)"
    source = f"""package app;
import android.content.Intent;
import android.webkit.WebView;
import java.util.Arrays;
class Entry {{
 void open(Intent incoming, WebView web) {{
  {binding} values = new String[] {{{elements}}};
  web.loadUrl({expression});
 }}
}}
"""
    report = scan(("app/Entry.java", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert ("aggregate element inventory budget" in report["metadata"]["native_flow"]["reasons"]) == (
        count > 128
    ), report
    assert not any(row.get("parse_errors") for row in report["metadata"]["files"]), report


@pytest.mark.parametrize(
    "source,expected,tainted,truncated",
    [
        (
            V22_CANONICAL_FRONTIER_SOURCE,
            "f3b7eb7f687ffd40f20cce3ee2a5d584c1a2cf51f543e1662aebb165e12a1290",
            True,
            True,
        ),
        (
            V22_CANONICAL_SHORT_SOURCE,
            "a06b12e1821f7a620e256f7adbeba13bb0924f16aacde7488bcfc10cad8cb99d",
            True,
            False,
        ),
        (
            V22_CANONICAL_LITERAL_SOURCE,
            "fa716a5d22af301daa0889902d489cfc55007606107391f3011a76c8b57ac79e",
            False,
            True,
        ),
    ],
)
def test_exact_independent_empty_prefix_frontier_pair(source, expected, tainted, truncated):
    assert hashlib.sha256(source.encode()).hexdigest() == expected
    report = scan(("app/Entry.swift", source))
    assert len(findings(report, URL)) == int(tainted), report
    assert report["metadata"]["native_flow"]["state"] == ("partial" if truncated else "checked"), report
