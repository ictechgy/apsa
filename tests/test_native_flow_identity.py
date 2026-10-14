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
    assert findings(baseline, URL), baseline
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
