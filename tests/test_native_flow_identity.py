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
