"""Pure Swift implicit-conformance lookup controls; no SDK/compiler/process.

The WebView allocation is local in every variant so a no-payload enum has no
invalid stored property. These are parser/full-engine regressions, separate from
Foundation-only hosted Swift semantic probes and actor UI-isolation semantics.
"""

import pytest

from mobile_audit.source_analysis import analyze_sources
from tests.test_swift_extension_types import APP, FAKE

RULE = "AST-WEBVIEW-UNTRUSTED-URL"


def inputs(kind, target, layout, control):
    app = APP.replace(" let web = WKWebView()\n", "").replace(
        "  let parsed =", "  let web = WKWebView()\n  let parsed ="
    )
    app = app.replace(
        "class Handler {", "actor Handler {" if kind == "actor" else "enum Handler {\n case main"
    )
    app = app.replace("{constructor}", "Foundation.URL" if control == "qualified" else "URL")
    if control == "unguarded":
        app = app.replace(
            '  guard parsed.scheme == "https", parsed.host == "guide.example.test" else { return false }\n',
            "",
        )
    extra = FAKE.replace("{name}", "FakeURL")
    if control != "no-extension":
        owner = "Other" if control == "unrelated" else target
        if control == "unrelated":
            extra += "class Other {}\n"
        if control == "source-protocol":
            owner = "P"
            extra += "protocol P {}\n"
        extra += "extension " + owner + " { typealias URL = FakeURL }\n"
    if layout == "same-before":
        return [("App.swift", extra + app)]
    if layout == "same-after":
        return [("App.swift", app + extra)]
    if layout == "split-before":
        return [("ZCaller.swift", app), ("AMembers.swift", extra)]
    return [("ACaller.swift", app), ("ZMembers.swift", extra)]


LAYOUTS = [
    ("same-before", False),
    ("same-after", False),
    ("split-before", False),
    ("split-before", True),
    ("split-after", False),
    ("split-after", True),
]


@pytest.mark.parametrize("kind,target", [("actor", "Actor"), ("enum", "Equatable"), ("enum", "Hashable")])
@pytest.mark.parametrize("layout,reverse", LAYOUTS)
@pytest.mark.parametrize(
    "control", ["affected", "unguarded", "unrelated", "no-extension", "qualified", "source-protocol"]
)
def test_implicit_protocol_member_alias_cannot_supply_sdk_url_safety(kind, target, layout, reverse, control):
    sources = inputs(kind, target, layout, control)
    if reverse:
        sources.reverse()
    report = analyze_sources(sources)
    assert all(
        not item["parse_errors"] and not item["native_parse_errors"] for item in report["metadata"]["files"]
    ), report
    matches = [item for item in report["findings"] if item["rule_id"] == RULE]
    states = {item["state"] for item in report["coverage"] if item["rule_id"] == RULE}
    if control == "affected":
        assert matches and all(item["status"] == "candidate" for item in matches), report
        assert states == {"partial"}, report
        assert report["metadata"]["native_flow"]["state"] == "partial", report
    elif control == "unguarded":
        assert matches and all(item["status"] == "candidate" for item in matches), report
    else:
        # Direct URL member aliases do not shadow the Foundation root. Exact
        # represented Other/P owners supply no implicit Handler conformance.
        assert not matches and states == {"checked"}, report
        assert report["metadata"]["native_flow"]["state"] == "checked", report


SPLIT_LAYOUTS = [
    ("split-before", False),
    ("split-before", True),
    ("split-after", False),
    ("split-after", True),
]
SHADOW_DEFINITIONS = [
    ("private", "class"),
    ("fileprivate", "class"),
    ("private", "protocol"),
    ("fileprivate", "protocol"),
    ("", "class"),
    ("public", "class"),
]


def assert_candidate_partial(report):
    assert all(
        not item["parse_errors"] and not item["native_parse_errors"] for item in report["metadata"]["files"]
    ), report
    matches = [item for item in report["findings"] if item["rule_id"] == RULE]
    states = {item["state"] for item in report["coverage"] if item["rule_id"] == RULE}
    assert matches and all(item["status"] == "candidate" for item in matches), report
    assert states == {"partial"} and report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize("kind,target", [("actor", "Actor"), ("enum", "Equatable"), ("enum", "Hashable")])
@pytest.mark.parametrize("layout,reverse", SPLIT_LAYOUTS)
@pytest.mark.parametrize("visibility,declaration", SHADOW_DEFINITIONS)
def test_another_file_definition_does_not_prove_extension_protocol_target(
    kind, target, layout, reverse, visibility, declaration
):
    sources = inputs(kind, target, layout, "affected")
    sources.append(("Shadow.swift", f"{visibility} {declaration} {target} {{}}\n"))
    if reverse:
        sources.reverse()
    # Private/fileprivate declarations are inaccessible to the extension. For
    # public/internal cross-file declarations supplied module membership is
    # unresolved, so they likewise cannot prove the extension's SDK identity.
    assert_candidate_partial(analyze_sources(sources))


@pytest.mark.parametrize("kind,target", [("actor", "Actor"), ("enum", "Equatable"), ("enum", "Hashable")])
@pytest.mark.parametrize("layout,reverse", SPLIT_LAYOUTS)
@pytest.mark.parametrize("visibility", ["private", "fileprivate"])
def test_private_enclosing_nominal_cannot_prove_qualified_protocol_target(
    kind, target, layout, reverse, visibility
):
    sources = inputs(kind, "Swift." + target, layout, "affected")
    sources.append(("Shadow.swift", f"{visibility} class Swift {{ class {target} {{}} }}\n"))
    if reverse:
        sources.reverse()
    assert_candidate_partial(analyze_sources(sources))


@pytest.mark.parametrize("known_first", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_repeated_member_owner_keeps_uncertain_extension_file_context(known_first, reverse):
    caller = inputs("actor", "Actor", "split-before", "no-extension")[0][1]
    safe = "class Actor {}\nextension Actor { typealias URL = FakeURL }\n"
    unknown = FAKE.replace("{name}", "FakeURL") + "extension Actor { typealias URL = FakeURL }\n"
    first, last = (safe, unknown) if known_first else (unknown, safe)
    sources = [("MCaller.swift", caller), ("AExtension.swift", first), ("ZExtension.swift", last)]
    if reverse:
        sources.reverse()
    # One member+owner key must retain uncertainty from both extension files;
    # the first represented same-file target cannot erase the other context.
    assert_candidate_partial(analyze_sources(sources))


@pytest.mark.parametrize("kind,target", [("actor", "Actor"), ("enum", "Equatable"), ("enum", "Hashable")])
@pytest.mark.parametrize("scope", ["function-local", "control-flow-local", "inactive-conditional"])
def test_non_module_or_conditional_definition_cannot_prove_top_level_extension_target(kind, target, scope):
    snippets = {
        "function-local": f"func hidden() {{ class {target} {{}} }}\n",
        "control-flow-local": f"if true {{ class {target} {{}} }}\n",
        "inactive-conditional": f"#if false\nclass {target} {{}}\n#endif\n",
    }
    sources = inputs(kind, target, "split-after", "affected")
    sources = [
        (path, snippets[scope] + text if "extension " + target in text else text) for path, text in sources
    ]
    # A declaration under function/control-flow ancestry is not a top-level
    # extension target. Conditional compilation may be flat in the AST, so an
    # inactive nominal cannot establish representation merely by parent type.
    assert_candidate_partial(analyze_sources(sources))


@pytest.mark.parametrize("kind,target", [("actor", "Actor"), ("enum", "Equatable"), ("enum", "Hashable")])
@pytest.mark.parametrize("layout", ["same-before", "same-after"])
@pytest.mark.parametrize("wrapper", ["function", "control-flow", "conditional"])
def test_nonmodule_or_conditionally_present_definition_cannot_prove_extension_target(
    kind, target, layout, wrapper
):
    declaration = f"class {target} {{}}\n"
    prefix = {
        "function": "func localTypes() {\n" + declaration + "}\n",
        "control-flow": "if false {\n" + declaration + "}\n",
        "conditional": "#if false\n" + declaration + "#endif\n",
    }[wrapper]
    sources = [(path, prefix + text) for path, text in inputs(kind, target, layout, "affected")]
    assert_candidate_partial(analyze_sources(sources))
