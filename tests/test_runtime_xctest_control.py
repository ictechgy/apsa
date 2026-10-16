"""Pure controls only; never collect a compiler, SDK or device fixture."""

import copy
import json
import plistlib
from xml.etree import ElementTree

import pytest

from mobile_audit.core import digest
from scripts import validate_runtime_xctest_control as control

PACKAGE = "org.apsa.synthetic.p" + "1" * 32
SCHEME = "a" + "2" * 32
NONCES = ("3" * 64, "4" * 64)


def receipt():
    urls = (f"{SCHEME}://callback?nonce={NONCES[0]}", f"{SCHEME}://callback?nonce={NONCES[1]}")
    build = {"executable_sha256": "5" * 64, "info_plist_sha256": "6" * 64}
    value = {
        "schema_version": 1,
        "package": PACKAGE,
        "epoch_sha256": "7" * 64,
        **build,
        "receipts": [
            {
                "uri_sha256": digest(url.encode()),
                "nonce_sha256": digest(nonce.encode()),
                "lifecycle": lifecycle,
            }
            for url, nonce, lifecycle in zip(
                urls, NONCES, ("cold-url-context", "warm-url-context"), strict=True
            )
        ],
    }
    return value, urls, build


@pytest.mark.parametrize("initial_state", ["prelaunched", "fresh-install"])
@pytest.mark.parametrize("url_driver", ["app-open", "system-open"])
def test_project_keeps_exact_new_identity_and_real_ui_callback_assertions(
    tmp_path, initial_state, url_driver
):
    root = tmp_path / "new"
    result = control.write_project(root, PACKAGE, SCHEME, NONCES, initial_state, url_driver)
    info = plistlib.loads((root / "Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == PACKAGE
    assert info["CFBundleURLTypes"][0]["CFBundleURLSchemes"] == [SCHEME]
    scheme = ElementTree.parse(root / "Callback.xcodeproj/xcshareddata/xcschemes/Callback.xcscheme")
    testable = scheme.find(".//TestableReference")
    assert testable is not None
    assert testable.get("parallelizable") == "NO"
    test = (root / "CallbackTests.swift").read_text()
    dispatch = (
        "app.open(URL(string:" if url_driver == "app-open" else "XCUIDevice.shared.system.open(URL(string:"
    )
    assert test.count(dispatch) == 2
    assert test.count("waitForExpectations(timeout: 30)") == 2
    assert "app.terminate()" in test
    assert ("if true {" if initial_state == "prelaunched" else "if false {") in test
    assert all(url in test for url in result["urls"])
    assert all(
        digest((root / name).read_bytes()) == checksum
        for name, checksum in result["generated_source_sha256"].items()
    )
    assert len(result["generated_source_sha256"]) == 5


def test_callback_receipt_requires_both_bound_lifecycles_and_installed_build():
    value, urls, build = receipt()
    result = control.verify_receipt(json.dumps(value).encode(), PACKAGE, urls, NONCES, build)
    assert result["state"] == "verified"
    assert [r["lifecycle"] for r in result["receipts"]] == ["cold-url-context", "warm-url-context"]


@pytest.mark.parametrize("mutation", ["none", "executable", "plist", "outside", "package"])
def test_installed_target_is_bound_before_url_dispatch(tmp_path, monkeypatch, mutation):
    device = "new-device"
    default_set = tmp_path / "new-simulators"
    container = default_set / device / "new-app"
    container.mkdir(parents=True)
    (container / "Callback").write_bytes(b"new-synthetic-executable")
    (container / "Info.plist").write_bytes(b"new-synthetic-plist")
    expected = {
        "executable_sha256": digest((container / "Callback").read_bytes()),
        "info_plist_sha256": digest((container / "Info.plist").read_bytes()),
    }
    returned = container
    package = PACKAGE
    if mutation in {"executable", "plist"}:
        (container / ("Callback" if mutation == "executable" else "Info.plist")).write_bytes(b"changed")
    elif mutation == "outside":
        returned = tmp_path / "unowned-app"
    elif mutation == "package":
        package = "existing.app"
    calls = []

    class NewCommands:
        env = {}

        def run(self, argv):
            calls.append(argv)
            return str(returned).encode()

    monkeypatch.setattr(control.transport, "ios_default_set", lambda env: default_set)
    if mutation == "none":
        assert control.installed_owned_build(NewCommands(), device, package, expected) == {
            "state": "verified",
            "build": expected,
        }
    else:
        with pytest.raises(ValueError):
            control.installed_owned_build(NewCommands(), device, package, expected)
    assert calls == (
        []
        if mutation == "package"
        else [["/usr/bin/xcrun", "simctl", "get_app_container", device, PACKAGE, "app"]]
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "package",
        "executable_sha256",
        "info_plist_sha256",
        "epoch_sha256",
        "schema_version",
        "nonce",
        "uri",
        "lifecycle",
        "missing",
        "extra",
        "reorder",
    ],
)
def test_unbound_or_incomplete_receipt_cannot_pass(mutation):
    value, urls, build = receipt()
    value = copy.deepcopy(value)
    if mutation in {"package", "executable_sha256", "info_plist_sha256", "epoch_sha256"}:
        value[mutation] = "unbound"
    elif mutation == "schema_version":
        value[mutation] = True
    elif mutation == "nonce":
        value["receipts"][0]["nonce_sha256"] = "8" * 64
    elif mutation == "uri":
        value["receipts"][1]["uri_sha256"] = "8" * 64
    elif mutation == "lifecycle":
        value["receipts"][0]["lifecycle"] = "warm-url-context"
    elif mutation == "missing":
        value["receipts"].pop()
    elif mutation == "extra":
        value["receipts"].append(value["receipts"][0])
    else:
        value["receipts"].reverse()
    with pytest.raises(ValueError):
        control.verify_receipt(json.dumps(value).encode(), PACKAGE, urls, NONCES, build)


def test_duplicate_or_oversized_receipts_fail_closed():
    value, urls, build = receipt()
    raw = json.dumps(value)
    duplicate = raw[:-1] + ', "schema_version": 1}'
    for raw in (duplicate.encode(), b" " * 8193):
        with pytest.raises(ValueError):
            control.verify_receipt(raw, PACKAGE, urls, NONCES, build)


@pytest.mark.parametrize(
    "package,scheme,nonces",
    [
        (PACKAGE + "/../other", SCHEME, NONCES),
        (PACKAGE, "https", NONCES),
        (PACKAGE, SCHEME, (NONCES[0], NONCES[0])),
        (PACKAGE, SCHEME, ("not-a-nonce", NONCES[1])),
    ],
)
def test_generation_rejects_external_identity_before_any_file_write(tmp_path, package, scheme, nonces):
    with pytest.raises(ValueError):
        control.write_project(tmp_path / "new", package, scheme, nonces)
    assert list(tmp_path.iterdir()) == []


def test_xcode_failure_projection_exposes_only_fixed_labels_and_own_line_numbers():
    waits = [
        n for n, line in enumerate(control.TEST_SOURCE.splitlines(), 1) if "waitForExpectations(" in line
    ]
    raw = (
        f'/new/CallbackTests.swift:{waits[0]}: error: Asynchronous wait failed: unfulfilled expectations: "synthetic-private-canary"\n'
        + f'/new/CallbackTests.swift:{waits[1]}: error: XCTAssertTrue failed "synthetic-private-canary"\n'
        + "/other/Existing.swift:1: error: synthetic-private-canary\n"
        + "arbitrary prompt synthetic-private-canary\n"
    ).encode()
    result = control.xcode_diagnostic(raw, "test-without-building", 65)
    assert result["own_test_issues"] == [
        {"source_line": waits[0], "category": "expectation-timeout", "probe": "cold"},
        {"source_line": waits[1], "category": "assertion-failed", "probe": "warm"},
    ]
    assert "synthetic-private-canary" not in json.dumps(result)
    assert "/new" not in json.dumps(result)
    assert result["exit_status"] == 65 and result["state"] == "diagnostic-only"


def test_xcode_diagnostic_cannot_turn_success_into_callback_acceptance():
    result = control.xcode_diagnostic(b"", "test-without-building", 0)
    assert result["state"] == "diagnostic-only"
    assert "r02_acceptance" not in result
    with pytest.raises(ValueError):
        control.xcode_diagnostic(b"", "install-other-app", 0)


def test_partial_callback_observation_keeps_wrong_origin_separate_from_absence():
    value, urls, build = receipt()
    value["receipts"] = [value["receipts"][0]]
    value["receipts"][0]["lifecycle"] = "warm-url-context"
    result = control.callback_diagnostic(json.dumps(value).encode(), PACKAGE, urls, NONCES, build)
    assert result["state"] == "diagnostic-only"
    assert result["package_matches"] is True and result["build_matches"] is True
    assert result["receipts"] == [{"lifecycle": "warm-url-context", "expected_probe": "cold"}]
    assert (
        control.callback_diagnostic(b"", PACKAGE, urls, NONCES, build)["receipt_state"]
        == "absent-or-over-bound"
    )
    with pytest.raises(ValueError):
        control.verify_receipt(json.dumps(value).encode(), PACKAGE, urls, NONCES, build)


@pytest.mark.parametrize(
    "raw", [b"arbitrary synthetic prompt", b'{"unexpected":"synthetic-private-canary"}', b"x" * 8193]
)
def test_callback_diagnostic_rejects_unexpected_data_without_context_leak(raw):
    _value, urls, build = receipt()
    result = control.callback_diagnostic(raw, PACKAGE, urls, NONCES, build)
    assert result["state"] == "diagnostic-only"
    assert result["receipt_state"] in {"malformed", "absent-or-over-bound"}
    assert "synthetic-private-canary" not in json.dumps(result)


def test_unknown_initial_state_does_not_generate_a_project(tmp_path):
    with pytest.raises(ValueError):
        control.write_project(tmp_path / "new", PACKAGE, SCHEME, NONCES, "existing-user-app")
    assert list(tmp_path.iterdir()) == []


def test_unknown_url_driver_does_not_generate_a_project(tmp_path):
    with pytest.raises(ValueError):
        control.write_project(tmp_path / "new", PACKAGE, SCHEME, NONCES, "fresh-install", "external-browser")
    assert list(tmp_path.iterdir()) == []
