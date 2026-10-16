"""Fresh source-only fixtures: unrelated symbol inventories cannot establish safety."""

from __future__ import annotations

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
