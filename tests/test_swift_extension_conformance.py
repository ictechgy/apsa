"""New pure extension-conformance regressions; no SDK/compiler/network/process.

Unknown conformance fences every root; qualified Foundation is therefore partial
for the affected Handler. Unrelated owners retain the SDK positive. Private
aliases are interpreted from extension context, not caller visibility.
"""

import pytest

from mobile_audit.source_analysis import analyze_sources
from tests.test_swift_extension_types import APP, FAKE
from tests.test_swift_extension_types import source as member_source

RULE = "AST-WEBVIEW-UNTRUSTED-URL"


def sources(kind, layout, qualified=False, unrelated=False, unguarded=False):
    app = APP.replace("{constructor}", "Foundation.URL" if qualified else "URL")
    if unguarded:
        app = app.replace(
            '  guard parsed.scheme == "https", parsed.host == "guide.example.test" else { return false }\n',
            "",
        )
    fake = FAKE.replace("{name}", "FakeURL")
    protocol = {
        "protocol-alias": "protocol P { typealias URL = FakeURL }\n",
        "extension-alias": "protocol P {}\nextension P { typealias URL = FakeURL }\n",
        "empty": "protocol P {}\n",
    }[kind]
    owner = "Other" if unrelated else "Handler"
    declarations = (
        fake + protocol + ("class Other {}\n" if unrelated else "") + "extension " + owner + ": P {}\n"
    )
    if layout == "same-before":
        return [("App.swift", declarations + app)]
    if layout == "same-after":
        return [("App.swift", app + declarations)]
    if layout == "split-before":
        return [("ZCaller.swift", app), ("AMembers.swift", declarations)]
    return [("ACaller.swift", app), ("ZMembers.swift", declarations)]


LAYOUTS = [
    ("same-before", False),
    ("same-after", False),
    ("split-before", False),
    ("split-before", True),
    ("split-after", False),
    ("split-after", True),
]


def checked_inputs(report):
    assert all(
        not item["parse_errors"] and not item["native_parse_errors"] for item in report["metadata"]["files"]
    )
    return [item for item in report["findings"] if item["rule_id"] == RULE], {
        item["state"] for item in report["coverage"] if item["rule_id"] == RULE
    }


@pytest.mark.parametrize("kind", ["protocol-alias", "extension-alias", "empty"])
@pytest.mark.parametrize("layout,reverse", LAYOUTS)
@pytest.mark.parametrize("control", ["affected", "qualified", "unrelated", "unguarded"])
def test_extension_conformance_is_lookup_uncertainty(kind, layout, reverse, control):
    inputs = sources(
        kind,
        layout,
        qualified=control == "qualified",
        unrelated=control == "unrelated",
        unguarded=control == "unguarded",
    )
    if reverse:
        inputs.reverse()
    report = analyze_sources(inputs)
    matches, states = checked_inputs(report)
    if control == "unrelated":
        assert not matches and states == {"checked"}, report
        assert report["metadata"]["native_flow"]["state"] == "checked", report
    elif control == "unguarded":
        assert matches and all(item["status"] == "candidate" for item in matches), report
    else:
        # Unknown protocol membership can supply any root, including Foundation.
        assert report["metadata"]["native_flow"]["state"] == "partial", report
        assert states == {"partial"}, report
        if control == "affected" and kind != "empty":
            assert matches and all(item["status"] == "candidate" for item in matches), report


@pytest.mark.parametrize("kind", ["protocol-alias", "extension-alias"])
@pytest.mark.parametrize("layout", ["split-before", "split-after"])
@pytest.mark.parametrize("alias", ["module-private", "member-private"])
def test_private_alias_in_extension_file_still_affects_other_caller_file(kind, layout, alias):
    inputs = sources(kind, layout)
    prefix, replacement = (
        ("private typealias H = Handler\n", "extension H: P")
        if alias == "module-private"
        else ("class Holder { fileprivate typealias H = Handler }\n", "extension Holder.H: P")
    )
    inputs = [
        (
            path,
            prefix + text.replace("extension Handler: P", replacement)
            if "extension Handler: P" in text
            else text,
        )
        for path, text in inputs
    ]
    report = analyze_sources(inputs)
    matches, states = checked_inputs(report)
    assert matches and all(item["status"] == "candidate" for item in matches), report
    assert states == {"partial"} and report["metadata"]["native_flow"]["state"] == "partial", report


@pytest.mark.parametrize("limit", [0, 1])
def test_empty_conformance_records_share_bounded_inventory(monkeypatch, limit):
    from mobile_audit import native_flow

    monkeypatch.setattr(native_flow, "MAX_EXTENSION_TYPES", limit)
    extra = (
        "protocol P {}\nclass OtherA {}\nclass OtherB {}\nextension OtherA: P {}\nextension OtherB: P {}\n"
    )
    report = analyze_sources([("App.swift", APP.replace("{constructor}", "URL")), ("Members.swift", extra)])
    _, states = checked_inputs(report)
    assert report["metadata"]["native_flow"]["state"] == "partial", report
    assert states == {"partial"}, report


@pytest.mark.parametrize("alias", [None, "Different", "H"])
def test_kotlin_alias_cannot_make_unrelated_swift_extension_target_ambiguous(alias):
    inputs = [
        (path, text.replace("Other", "H"))
        for path, text in member_source("nominal", "split-after", unrelated=True)
    ]
    if alias:
        inputs.append(("Alias.kt", f"package unrelated\ntypealias {alias} = String\n"))
    report = analyze_sources(inputs)
    matches, states = checked_inputs(report)
    assert not matches and states == {"checked"}, report
    assert report["metadata"]["native_flow"]["state"] == "checked", report
