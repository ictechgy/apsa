from __future__ import annotations

import textwrap
import time

import pytest

from mobile_audit.source_analysis import analyze_sources

PATH = "AST-PATH-TRAVERSAL"
URL = "AST-WEBVIEW-UNTRUSTED-URL"


def scan(*sources: tuple[str, str]) -> dict:
    return analyze_sources([(path, textwrap.dedent(text).strip()) for path, text in sources])


def findings(report: dict, rule: str = PATH) -> list[dict]:
    return [item for item in report["findings"] if item["rule_id"] == rule]


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "java",
            """class Handler {
                WebView browser;
                void open(Intent input) {
                    idle();
                    browser.loadUrl(input.getStringExtra("url"));
                }
                void idle() {}
            }""",
        ),
        (
            "kt",
            """class Handler {
                val browser: WebView = WebView(context)
                fun open(input: Intent) {
                    idle()
                    browser.loadUrl(input.getStringExtra("url"))
                }
                fun idle() {}
            }""",
        ),
        (
            "swift",
            """import WebKit
            class Handler {
                let browser = WKWebView()
                func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) {
                    idle()
                    browser.load(URLRequest(url: incoming))
                }
                func idle() {}
            }""",
        ),
    ],
)
def test_noop_native_helper_preserves_typed_webview_field(suffix, source):
    report = scan((f"New.{suffix}", source))
    matches = findings(report, URL)
    assert len(matches) == 1, report
    assert matches[0]["status"] == "candidate"
    assert report["metadata"]["native_flow"]["evaluations"] == 1


def test_noop_native_helper_preserves_constructed_path_category():
    report = scan(
        (
            "New.java",
            """class Handler {
                File output;
                void open(Intent input, File root) {
                    output = new File(root, input.getStringExtra("name"));
                    idle();
                    if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
                    new FileOutputStream(output);
                }
                private void idle() {}
            }""",
        )
    )
    assert not findings(report), report


def test_noop_native_helper_preserves_receiver_allocation_identity():
    report = scan(
        (
            "New.java",
            """class Box {
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
                private void idle() {}
            }""",
        )
    )
    assert findings(report), report
    assert "receiver runtime dispatch unresolved" not in report["metadata"]["native_flow"]["reasons"]


def test_native_field_merge_keeps_only_shared_metadata():
    from mobile_audit.native_flow import NativeFlow
    from mobile_audit.source_analysis import Value

    path = Value(category="path", type_name="File", identity="New.java:32")
    assert NativeFlow.merge([path, path]) == path
    incompatible = Value(category="text", type_name="String", identity="New.java:64")
    assert NativeFlow.merge([path, incompatible]) == Value()
    assert NativeFlow.merge([path, Value()]) == Value()


@pytest.mark.parametrize("suffix", ["java", "kt"])
@pytest.mark.parametrize("guard", ["unrelated", "after", "optional", "dead", "partial-exit", "slash-only"])
def test_path_irrelevant_or_nondominating_checks_keep_candidate(suffix, guard):
    java = {
        "unrelated": 'if (other.contains("..")) return;',
        "after": "",
        "optional": 'if (flag) { if (name.contains("..")) return; }',
        "dead": 'if (false) { if (name.contains("..")) return; }',
        "partial-exit": 'if (name.contains("..")) { if (flag) return; }',
        "slash-only": 'if (name.contains("../")) return;',
    }
    check = java[guard]
    after = 'if (name.contains("..")) return;' if guard == "after" else ""
    if suffix == "java":
        source = f"""class Handler {{
            void open(Intent input, String other, boolean flag) {{
                String name = input.getStringExtra("name");
                {check}
                new FileOutputStream(name);
                {after}
            }}
        }}"""
    else:
        source = f"""class Handler {{
            fun open(input: Intent, other: String, flag: Boolean) {{
                val name = input.getStringExtra("name")!!
                {check.replace(";", "")}
                FileOutputStream(name)
                {after.replace(";", "")}
            }}
        }}"""
    report = scan((f"New.{suffix}", source))
    assert findings(report), report
    assert all(item["status"] == "candidate" for item in findings(report))


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "java",
            """class Handler {
        void open(Intent input) {
            String name = input.getStringExtra("name");
            if (name.contains("..")) return;
            new FileOutputStream(name);
        }
    }""",
        ),
        (
            "kt",
            """class Handler {
        fun open(input: Intent) {
            val name = input.getStringExtra("name")!!
            if (".." in name) return
            FileOutputStream(name)
        }
    }""",
        ),
        (
            "swift",
            """class Handler {
        func application(_ app: UIApplication, open input: URL, options: [String: Any]) -> Bool {
            let name = input.query
            guard !name!.contains("..") else { return false }
            let output = URL(fileURLWithPath: name!)
            return true
        }
    }""",
        ),
    ],
)
def test_same_value_rejecting_guard_dominates_path_operation(suffix, source):
    report = scan((f"New.{suffix}", source))
    assert not findings(report), report


@pytest.mark.parametrize("prefix", ["root.getCanonicalPath()", "root.getCanonicalPath() + File.separator"])
def test_canonical_containment_requires_directory_boundary(prefix):
    report = scan(
        (
            "New.java",
            f"""class Handler {{
        void open(Intent input, File root) {{
            String name = input.getStringExtra("name");
            File path = new File(root, name);
            if (!path.getCanonicalPath().startsWith({prefix})) throw new SecurityException();
            new FileOutputStream(path);
        }}
    }}""",
        )
    )
    assert bool(findings(report)) == (prefix == "root.getCanonicalPath()"), report


def test_same_path_check_after_real_file_io_never_suppresses():
    report = scan(
        (
            "New.kt",
            """class Handler {
        fun open(input: Intent, root: File) {
            val name = input.getStringExtra("name")!!
            val path = File(root, name)
            FileOutputStream(path)
            if (!path.canonicalPath.startsWith(root.canonicalPath + File.separator)) return
        }
    }""",
        )
    )
    assert findings(report), report


def test_guard_for_original_value_cannot_bless_changed_name():
    report = scan(
        (
            "New.java",
            """class Handler {
        void open(Intent input) {
            String name = input.getStringExtra("name");
            if (name.contains("..")) return;
            name = name + "../other";
            new FileOutputStream(name);
        }
    }""",
        )
    )
    assert findings(report)


@pytest.mark.parametrize("reverse", [False, True])
def test_cross_file_argument_return_and_sink_paths_ignore_file_order(reverse):
    sources = [
        (
            "entry/Handler.java",
            """package example;
            class Handler {
                WebView browser;
                void entry(Intent input) {
                    String name = Helper.read(input);
                    Helper.write(name);
                    browser.loadUrl(Helper.identity(name));
                }
            }""",
        ),
        (
            "helpers/Helper.java",
            """package example;
            class Helper {
                static String read(Intent input) { return input.getStringExtra("name"); }
                static String identity(String name) { return name; }
                static void write(String name) { new FileOutputStream(name); }
            }""",
        ),
    ]
    report = scan(*(list(reversed(sources)) if reverse else sources))
    assert findings(report)
    item = findings(report)[0]
    assert item["evidence"][0]["path"] == "helpers/Helper.java"
    flow_paths = {step["path"] for step in item["evidence"][0]["flow"]}
    assert flow_paths == {"entry/Handler.java", "helpers/Helper.java"}
    assert all(step["line"] >= 1 for step in item["evidence"][0]["flow"])
    assert findings(report, URL)
    assert report["metadata"]["native_flow"]["state"] == "checked"


def test_direct_helper_guard_preserves_positive_and_rejects_unrelated_check():
    for guard, expected in [
        ('if (name.contains("..")) return;', False),
        ('if (other.contains("..")) return;', True),
    ]:
        report = scan(
            (
                "New.java",
                f"""class Handler {{
            void entry(Intent input) {{ write(input.getStringExtra("name"), "safe"); }}
            void write(String name, String other) {{ {guard} new FileOutputStream(name); }}
        }}""",
            )
        )
        assert bool(findings(report)) is expected, report


def test_caller_guard_dominates_resolved_helper_sink():
    report = scan(
        (
            "New.kt",
            """class Handler {
        fun entry(input: Intent) {
            val name = input.getStringExtra("name")!!
            if (name.contains("..")) return
            write(name)
        }
        fun write(name: String) { FileOutputStream(name) }
    }""",
        )
    )
    assert not findings(report), report


def test_same_instance_field_store_return_and_sink():
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input) {
            Helper first = new Helper();
            Helper second = new Helper();
            first.store(input.getStringExtra("name"));
            second.store("safe");
            new FileOutputStream(first.read());
            new FileOutputStream(second.read());
        }
    }
    class Helper {
        String name;
        void store(String input) { this.name = input; }
        String read() { return this.name; }
    }""",
        )
    )
    assert len(findings(report)) == 1, report
    assert findings(report)[0]["evidence"][0]["line"] == 7


@pytest.mark.parametrize("reverse", [False, True])
def test_field_summary_from_separate_methods_is_order_independent(reverse):
    setter = 'void entry(Intent input) { this.name = input.getStringExtra("name"); }'
    sink = "void later() { new FileOutputStream(name); }"
    methods = [setter, sink]
    if reverse:
        methods.reverse()
    report = scan(("New.java", "class Handler { String name; " + " ".join(methods) + " }"))
    assert findings(report), report
    assert findings(report)[0]["evidence"][0]["function"] == "later"


def test_imports_and_receiver_class_prevent_unrelated_same_name_dispatch():
    report = scan(
        (
            "Main.java",
            """package entry;
            import good.Helper;
            class Handler {
                void entry(Intent input) { Helper.write(input.getStringExtra("name")); }
            }""",
        ),
        (
            "Good.java",
            """package good;
            class Helper { static void write(String name) {} }""",
        ),
        (
            "Bad.java",
            """package bad;
            class Helper { static void write(String name) { new FileOutputStream(name); } }""",
        ),
    )
    assert not findings(report), report


def test_ambiguous_overload_is_partial_and_never_establishes_safety():
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input) { write(input.getStringExtra("name")); }
        void write(String name) { if (name.contains("..")) return; new FileOutputStream(name); }
        void write(Object name) { new FileOutputStream(name); }
    }""",
        )
    )
    assert findings(report), report
    assert report["metadata"]["native_flow"]["state"] == "partial"
    assert "ambiguous direct call" in report["metadata"]["native_flow"]["reasons"]


def test_recursion_is_partial_and_retains_taint_to_sink():
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input) { new FileOutputStream(loop(input.getStringExtra("name"))); }
        String loop(String name) { return loop(name); }
    }""",
        )
    )
    assert findings(report), report
    assert report["metadata"]["native_flow"]["state"] == "partial"
    assert "recursion or call evaluation budget" in report["metadata"]["native_flow"]["reasons"]


def test_call_budget_is_explicit_partial_and_retains_unknown_flow(monkeypatch):
    from mobile_audit import native_flow

    monkeypatch.setattr(native_flow, "MAX_CALL_EVALUATIONS", 0)
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input) { new FileOutputStream(identity(input.getStringExtra("name"))); }
        String identity(String name) { return name; }
    }""",
        )
    )
    assert findings(report), report
    assert all(item["state"] == "partial" for item in report["coverage"])


@pytest.mark.parametrize(
    "source",
    [
        """class Handler {
        void entry(Intent input) {
            Helper helper = new Helper(input.getStringExtra("name"));
            new FileOutputStream(helper.read());
        }
    }
    class Helper {
        String name;
        Helper(String input) { this.name = input; }
        String read() { return this.name; }
    }""",
        """class Handler {
        void entry(Intent input) { new Helper(input.getStringExtra("name")); }
    }
    class Helper {
        Helper(String name) { new FileOutputStream(name); }
    }""",
    ],
)
def test_constructor_arguments_reach_fields_and_sinks(source):
    report = scan(("New.java", source))
    assert findings(report), report
    assert report["metadata"]["native_flow"]["state"] == "checked"


@pytest.mark.parametrize(
    "suffix,source",
    [
        (
            "kt",
            """class Handler {
        fun entry(input: Intent) { FileOutputStream(identity(input.getStringExtra("name")!!)) }
        fun identity(name: String) = name
    }""",
        ),
        (
            "swift",
            """class Handler {
        func application(_ app: UIApplication, open input: URL, options: [String: Any]) -> Bool {
            let path = identity(input.absoluteString)
            let output = URL(fileURLWithPath: path)
            return true
        }
        func identity(_ name: String) -> String { return name }
    }""",
        ),
    ],
)
def test_kotlin_and_swift_helper_returns_keep_platform_provenance(suffix, source):
    report = scan((f"New.{suffix}", source))
    assert findings(report), report


@pytest.mark.parametrize("location", ["before", "after"])
def test_dead_or_optional_guard_does_not_hide_unconsumed_path_construction(location):
    check = 'if (false) { if (name.contains("..")) return; }'
    statements = [check, "new File(name);"] if location == "before" else ["new File(name);", check]
    report = scan(
        (
            "New.java",
            'class Handler { void entry(Intent input) { String name = input.getStringExtra("name"); '
            + " ".join(statements)
            + " } }",
        )
    )
    assert findings(report), report


def test_branch_with_safe_io_and_unchecked_io_keeps_path_candidate():
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input, boolean condition, File root) {
            File output = new File(root, input.getStringExtra("name"));
            if (condition) {
                if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
                new FileOutputStream(output);
            } else {
                new FileOutputStream(output);
            }
        }
    }""",
        )
    )
    assert findings(report), report


def test_trace_budget_cannot_turn_a_union_into_a_safe_guarded_result():
    declarations = "\n".join(f'String n{index} = input.getStringExtra("name{index}");' for index in range(10))
    expression = " + ".join(f"n{index}" for index in range(10))
    report = scan(
        (
            "New.java",
            f"""class Handler {{
        void entry(Intent input) {{
            {declarations}
            String name = {expression};
            if (name.contains("..")) return;
            new FileOutputStream(name);
        }}
    }}""",
        )
    )
    assert findings(report), report
    assert report["metadata"]["native_flow"]["state"] == "partial"
    assert "source trace budget" in report["metadata"]["native_flow"]["reasons"]


def test_field_fixed_point_budget_is_explicit(monkeypatch):
    from mobile_audit import native_flow

    monkeypatch.setattr(native_flow, "MAX_FIELD_ROUNDS", 1)
    report = scan(
        (
            "New.java",
            """class Handler {
        String name;
        void entry(Intent input) { this.name = input.getStringExtra("name"); }
        void later() { new FileOutputStream(name); }
    }""",
        )
    )
    assert report["metadata"]["native_flow"]["state"] == "partial"
    assert "field summary fixed-point budget" in report["metadata"]["native_flow"]["reasons"]


def test_unknown_receiver_dispatch_does_not_promote_return_to_safe():
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input, Helper helper) {
            new FileOutputStream(helper.identity(input.getStringExtra("name")));
        }
    }
    class Helper { String identity(String name) { return "safe"; } }""",
        )
    )
    assert findings(report), report
    assert "receiver runtime dispatch unresolved" in report["metadata"]["native_flow"]["reasons"]


def test_primary_constructor_unknown_field_mapping_stays_partial_and_tainted():
    report = scan(
        (
            "New.kt",
            """class Handler {
        fun entry(input: Intent) {
            val helper = Helper(input.getStringExtra("name")!!)
            FileOutputStream(helper.name)
        }
    }
    class Helper(val name: String)""",
        )
    )
    assert findings(report), report
    assert report["metadata"]["native_flow"]["state"] == "partial"
    assert "constructor field mapping unavailable" in report["metadata"]["native_flow"]["reasons"]


def test_direct_helper_containment_can_validate_provisional_path_construction():
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input, File root) {
            File output = new File(root, input.getStringExtra("name"));
            write(output, root);
        }
        private void write(File output, File root) {
            if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
            new FileOutputStream(output);
        }
    }""",
        )
    )
    assert not findings(report), report


def test_optional_helper_containment_does_not_validate_other_routes():
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input, File root, boolean condition) {
            File output = new File(root, input.getStringExtra("name"));
            if (condition) write(output, root);
            new FileOutputStream(output);
        }
        void write(File output, File root) {
            if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
            new FileOutputStream(output);
        }
    }""",
        )
    )
    assert findings(report), report


@pytest.mark.parametrize("guard_before", [False, True])
def test_kotlin_file_extension_checks_guard_before_real_write(guard_before):
    check = "if (!output.canonicalPath.startsWith(root.canonicalPath + File.separator)) return"
    operations = (
        [check, 'output.writeText("synthetic")'] if guard_before else ['output.writeText("synthetic")', check]
    )
    report = scan(
        (
            "New.kt",
            """class Handler {
        fun entry(input: Intent, root: File) {
            val output = File(root, input.getStringExtra("name")!!)
            """
            + "\n".join(operations)
            + """
        }
    }""",
        )
    )
    assert bool(findings(report)) is not guard_before, report


@pytest.mark.parametrize("guard_before", [False, True])
def test_swift_file_write_checks_guard_before_real_write(guard_before):
    check = 'guard output.resolvingSymlinksInPath().path.hasPrefix(root.resolvingSymlinksInPath().path + "/") else { return false }'
    operations = [check, "bytes.write(to: output)"] if guard_before else ["bytes.write(to: output)", check]
    report = scan(
        (
            "New.swift",
            """class Handler {
        func application(_ app: UIApplication, open input: URL, options: [String: Any]) -> Bool {
            let root = URL(fileURLWithPath: "/synthetic")
            let output = URL(fileURLWithPath: input.absoluteString)
            let bytes: Data = Data()
            """
            + "\n".join(operations)
            + """
            return true
        }
    }""",
        )
    )
    assert bool(findings(report)) is not guard_before, report


@pytest.mark.parametrize("suffix", ["java", "kt", "swift"])
@pytest.mark.parametrize("guarded", [False, True])
def test_rooted_constant_prefix_preserves_only_same_input_path_guard(suffix, guarded):
    guard = 'if (name.contains("..")) return;' if guarded else ""
    if suffix == "java":
        source = (
            'class Handler { void entry(Intent input) { String name = input.getStringExtra("name"); '
            + guard
            + ' new FileOutputStream("/synthetic/root/" + name); } }'
        )
    elif suffix == "kt":
        source = (
            'class Handler { fun entry(input: Intent) { val name = input.getStringExtra("name")!!\n'
            + guard.replace(";", "")
            + '\nFileOutputStream("/synthetic/root/" + name) } }'
        )
    else:
        guard = 'if name.contains("..") { return false }' if guarded else ""
        source = (
            "class Handler { func application(_ app: UIApplication, open input: URL, options: [String: Any]) -> Bool { let name = input.query!\n"
            + guard
            + '\nlet path = URL(fileURLWithPath: "/synthetic/root/" + name)\nreturn true } }'
        )
    report = scan((f"New.{suffix}", source))
    assert bool(findings(report)) is not guarded, report


@pytest.mark.parametrize(
    "path_expression",
    [
        '"/synthetic/root/../" + name',
        '"/synthetic/root/" + transform(name)',
        '"/synthetic/root/" + name + "../escape"',
        '"/synthetic/root/" + other',
    ],
)
def test_rooted_prefix_cannot_bless_transforms_or_different_input(path_expression):
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input) {
            String name = input.getStringExtra("name");
            String other = input.getStringExtra("other");
            if (name.contains("..")) return;
            new FileOutputStream("""
            + path_expression
            + """);
        }
    }""",
        )
    )
    assert findings(report), report


def test_unknown_transform_cannot_inherit_basename_safety():
    report = scan(
        (
            "New.java",
            """class Handler {
        void entry(Intent input) {
            String name = new File(input.getStringExtra("name")).getName();
            new FileOutputStream(transform(name));
        }
    }""",
        )
    )
    assert findings(report), report


@pytest.mark.parametrize("safe", [False, True])
def test_returned_file_construction_is_validated_by_exact_caller_invocation(safe):
    guard = (
        "if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;"
        if safe
        else ""
    )
    report = scan(
        (
            "Caller.java",
            """class Handler {
            void entry(Intent input, File root) {
                File output = Helper.path(root, input.getStringExtra("name"));
                """
            + guard
            + """
                new FileOutputStream(output);
            }
        }""",
        ),
        (
            "Helper.java",
            """class Helper {
            static File path(File root, String name) { return new File(root, name); }
        }""",
        ),
    )
    assert bool(findings(report)) is not safe, report


def test_safe_returned_path_use_cannot_erase_a_prior_unchecked_helper_invocation():
    report = scan(
        (
            "Caller.java",
            """class Handler {
            void unchecked(Intent input, File root) {
                File output = Helper.path(root, input.getStringExtra("name"));
                new FileOutputStream(output);
            }
            void checked(Intent input, File root) {
                File output = Helper.path(root, input.getStringExtra("other"));
                if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
                new FileOutputStream(output);
            }
        }""",
        ),
        (
            "Helper.java",
            """class Helper {
            static File path(File root, String name) { return new File(root, name); }
        }""",
        ),
    )
    assert findings(report), report


def test_native_flow_preserves_bounded_parser_and_scope_cache_performance():
    declarations = "\n".join(f"val local{index} = {index}" for index in range(3000))
    blocks = "\n".join(f"local{index}.let {{ value -> log(value) }}" for index in range(800))
    unrelated = "\n".join(f"Calendar.getInstance(zone{index})" for index in range(4000))
    started = time.monotonic()
    report = scan(
        ("FreshScopes.kt", "class FreshScopes { fun inspect() {\n" + declarations + "\n" + blocks + "\n} }"),
        ("FreshCalls.kt", "class FreshCalls { fun inspect() {\n" + unrelated + "\n} }"),
    )
    assert time.monotonic() - started < 10
    assert report["metadata"]["functions"]["analyzed"] == 2
    assert not report["findings"]


def test_parser_node_budget_remains_partial_with_new_flow_registry(monkeypatch):
    from mobile_audit import source_analysis

    monkeypatch.setattr(source_analysis, "MAX_AST_NODES", 10)
    report = scan(
        (
            "Fresh.java",
            'class Fresh { void inspect(Intent input) { new FileOutputStream(input.getStringExtra("name")); } }',
        )
    )
    assert any("AST node budget exceeded" in warning for warning in report["warnings"])
    assert report["metadata"]["native_flow"]["state"] == "not-run"
    assert all(item["state"] == "not-run" for item in report["coverage"])


def test_duplicate_trace_merge_cannot_erase_unsafe_or_incomplete_state():
    from mobile_audit.source_analysis import TRACE_PARTIAL, Trace, Value, _union

    safe = Value((Trace(1, None, "synthetic source", (), True),))
    incomplete = Value((Trace(1, None, "synthetic source" + TRACE_PARTIAL),))
    for values in ([safe, incomplete], [incomplete, safe]):
        merged = _union(values)
        assert not merged.traces[0].path_safe
        assert TRACE_PARTIAL in merged.traces[0].description


def test_package_extraction_occurs_once_per_file_including_negative_result(monkeypatch):
    from mobile_audit import source_analysis

    original = source_analysis._package_name
    calls = []

    def observed(text):
        calls.append(len(text))
        return original(text)

    monkeypatch.setattr(source_analysis, "_package_name", observed)
    methods = "\n".join(f"void safe{index}() {{}}" for index in range(800))
    padding = "/*" + "synthetic " * 50000 + "*/"
    report = scan(
        ("NoPackage.java", "class First {\n" + methods + "\n}\n" + padding),
        ("WithPackage.java", "package separate.namespace;\nclass Second {\n" + methods + "\n}\n" + padding),
    )
    assert len(calls) == 2
    assert report["metadata"]["functions"]["analyzed"] == 1600
    assert not report["findings"]


def test_cached_owners_keep_nested_classes_and_separate_packages_distinct(monkeypatch):
    from mobile_audit.native_flow import NativeFlow

    observed = {}
    original = NativeFlow.owner

    def owner(self, analyzer, node):
        value = original(self, analyzer, node)
        observed.setdefault(analyzer.path, set()).add(value)
        return value

    monkeypatch.setattr(NativeFlow, "owner", owner)
    report = scan(
        ("One.java", "package one.scope; class Same { void safe() {} class Nested { void safe() {} } }"),
        ("Two.java", "package two.scope; class Same { void safe() {} }"),
        ("None.java", "class Same { void safe() {} }"),
    )
    assert report["metadata"]["functions"]["analyzed"] == 4
    assert observed["One.java"] == {"one.scope.Same", "one.scope.Same.Nested"}
    assert observed["Two.java"] == {"two.scope.Same"}
    assert observed["None.java"] == {"Same"}


def test_package_detection_never_crosses_a_newline():
    from mobile_audit.source_analysis import _package_name

    assert _package_name("  package valid.scope;\nclass Fresh {}") == "valid.scope"
    assert _package_name("package\nclass Fresh {}") == ""


@pytest.mark.parametrize("suffix", ["java", "kt", "swift"])
@pytest.mark.parametrize("unsafe_io", [False, True])
def test_canonical_guard_closes_only_exact_same_origin_construction(suffix, unsafe_io):
    if suffix == "java":
        source = (
            """class Handler {
            void entry(Intent input, File root) {
                String name = input.getStringExtra("name");
                File unconsumed = new File(name);
                File output = new File(root, name);
                if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
                new FileOutputStream(output);
                """
            + ("new FileOutputStream(unconsumed);" if unsafe_io else "")
            + """
            }
        }"""
        )
    elif suffix == "kt":
        source = (
            """class Handler {
            fun entry(input: Intent, root: File) {
                val name = input.getStringExtra("name")!!
                val unconsumed = File(name)
                val output = File(root, name)
                if (!output.canonicalPath.startsWith(root.canonicalPath + File.separator)) return
                FileOutputStream(output)
                """
            + ("FileOutputStream(unconsumed)" if unsafe_io else "")
            + """
            }
        }"""
        )
    else:
        source = (
            """class Handler {
            func application(_ app: UIApplication, open input: URL, options: [String: Any]) -> Bool {
                let name = input.query!
                let unconsumed = URL(fileURLWithPath: name)
                let output = URL(fileURLWithPath: "/synthetic/root/" + name)
                let root = URL(fileURLWithPath: "/synthetic/root")
                let bytes: Data = Data()
                guard output.resolvingSymlinksInPath().path.hasPrefix(root.resolvingSymlinksInPath().path + "/") else { return false }
                bytes.write(to: output)
                """
            + ("bytes.write(to: unconsumed)" if unsafe_io else "")
            + """
                return true
            }
        }"""
        )
    report = scan((f"Fresh.{suffix}", source))
    assert findings(report), report
    assert len(findings(report)) == 1
    assert "unconsumed" in findings(report)[0]["evidence"][0]["excerpt"]


@pytest.mark.parametrize("safe_first", [False, True])
@pytest.mark.parametrize("unsafe_io", [False, True])
def test_cross_file_same_origin_helper_routes_survive_both_call_orders(safe_first, unsafe_io):
    safe = "File output = Helper.path(root, name);"
    unsafe = "File unconsumed = Helper.path(root, name);"
    statements = [safe, unsafe] if safe_first else [unsafe, safe]
    report = scan(
        (
            "Caller.java",
            """class Handler {
            void entry(Intent input, File root) {
                String name = input.getStringExtra("name");
                """
            + "\n".join(statements)
            + """
                if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
                new FileOutputStream(output);
                """
            + ("new FileOutputStream(unconsumed);" if unsafe_io else "")
            + """
            }
        }""",
        ),
        (
            "Helper.java",
            """class Helper {
            static File path(File root, String name) { return new File(root, name); }
        }""",
        ),
    )
    assert findings(report), report
    expected_call_line = 5 if safe_first else 4
    assert any(
        step["path"] == "Caller.java" and step["line"] == expected_call_line
        for entry in findings(report)[0]["evidence"]
        for step in entry["flow"]
    )
    assert not any("modeled_routes" in entry for item in report["findings"] for entry in item["evidence"])


def test_canonical_guard_cannot_bless_unknown_constructed_path_transform():
    report = scan(
        (
            "Fresh.java",
            """class Handler {
        void entry(Intent input, File root) {
            File output = new File(root, input.getStringExtra("name"));
            if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
            new FileOutputStream(transform(output));
        }
    }""",
        )
    )
    assert findings(report), report
    assert findings(report)[0]["evidence"][0]["path_operation"] == "file-io"


@pytest.mark.parametrize("expression", ['URLDecoder.decode(name, "UTF-8")', "transform(name)"])
def test_lexical_guard_cannot_bless_decoded_or_changed_name(expression):
    report = scan(
        (
            "Fresh.java",
            """class Handler {
        void entry(Intent input) {
            String name = input.getStringExtra("name");
            if (name.contains("..")) return;
            new FileOutputStream("/synthetic/root/" + """
            + expression
            + """);
        }
    }""",
        )
    )
    assert findings(report), report


def test_duplicate_source_origin_retains_distinct_construction_routes():
    from mobile_audit.source_analysis import Trace, Value, _union

    values = [
        Value((Trace(1, None, "fresh source", path_route="Caller.java:10"),)),
        Value((Trace(1, None, "fresh source", path_route="Caller.java:20"),)),
    ]
    merged = _union(values)
    assert len(merged.traces) == 2
    assert {trace.path_route for trace in merged.traces} == {"Caller.java:10", "Caller.java:20"}


def test_route_evidence_budget_keeps_untracked_route_conservative(monkeypatch):
    from mobile_audit import source_analysis

    monkeypatch.setattr(source_analysis, "MAX_PATH_ROUTE_EVIDENCE", 1)
    report = scan(
        (
            "Caller.java",
            """class Handler {
            void entry(Intent input, File root) {
                String name = input.getStringExtra("name");
                File output = Helper.path(root, name);
                File unconsumed = Helper.path(root, name);
                if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
                new FileOutputStream(output);
            }
        }""",
        ),
        (
            "Helper.java",
            """class Helper { static File path(File root, String name) { return new File(root, name); } }""",
        ),
    )
    assert findings(report), report
    assert "path route evidence budget" in report["metadata"]["native_flow"]["reasons"]
    assert report["metadata"]["native_flow"]["state"] == "partial"


def test_rejecting_parent_segments_after_canonicalization_does_not_prove_containment():
    report = scan(
        (
            "Fresh.java",
            """class Handler {
        void entry(Intent input, File root) {
            String name = input.getStringExtra("name");
            File unchecked = new File(name);
            File output = new File(root, name);
            if (output.getCanonicalPath().contains("..")) return;
            new FileOutputStream(unchecked);
            new FileOutputStream(output);
        }
    }""",
        )
    )
    assert len(findings(report)) == 2, report


def test_unchanged_constructed_string_lexical_guard_is_route_bound():
    report = scan(
        (
            "Fresh.java",
            """class Handler {
        void entry(Intent input, File root) {
            String name = input.getStringExtra("name");
            File unchecked = new File(name);
            File output = new File(root, name);
            if (output.toString().contains("..")) return;
            new FileOutputStream(unchecked);
        }
    }""",
        )
    )
    assert findings(report), report
    assert any("unchecked" in entry["excerpt"] for item in findings(report) for entry in item["evidence"])


@pytest.mark.parametrize("suffix", ["java", "kt", "swift"])
def test_canonical_prefix_from_observed_external_root_cannot_bless_output(suffix):
    if suffix == "java":
        source = """class Handler {
            void entry(Intent input) {
                File root = new File(input.getStringExtra("root"));
                File output = new File(root, input.getStringExtra("name"));
                if (!output.getCanonicalPath().startsWith(root.getCanonicalPath() + File.separator)) return;
                new FileOutputStream(output);
            }
        }"""
    elif suffix == "kt":
        source = """class Handler {
            fun entry(input: Intent) {
                val root = File(input.getStringExtra("root")!!)
                val output = File(root, input.getStringExtra("name")!!)
                if (!output.canonicalPath.startsWith(root.canonicalPath + File.separator)) return
                FileOutputStream(output)
            }
        }"""
    else:
        source = """class Handler {
            func application(_ app: UIApplication, open input: URL, options: [String: Any]) -> Bool {
                let root = URL(fileURLWithPath: input.query!)
                let output = root.appendingPathComponent(input.absoluteString)
                guard output.resolvingSymlinksInPath().path.hasPrefix(root.resolvingSymlinksInPath().path + "/") else { return false }
                let bytes: Data = Data()
                bytes.write(to: output)
                return true
            }
        }"""
    report = scan((f"Fresh.{suffix}", source))
    assert any("output" in entry["excerpt"] for item in findings(report) for entry in item["evidence"]), (
        report
    )
