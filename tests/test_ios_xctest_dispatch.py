"""Pure generated-source, manifest and mocked dispatch controls; no SDK/device."""

from __future__ import annotations

import copy
import json
import plistlib
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
import yaml

from mobile_audit.core import digest
from scripts import ios_xctest_dispatch as bridge
from scripts import validate_runtime_transport as transport

DEVICE = "11111111-2222-4333-8444-555555555555"
PACKAGE = "apsa.fixture.c" + "1" * 32 + ".case0"
SCHEME = "a" + "2" * 32
URI = SCHEME + "://fixture?action=capture&session=" + "3" * 64 + "&nonce=" + "4" * 64


def manifest():
    return {
        "__xctestrun_metadata__": {"FormatVersion": 1},
        "CallbackTests": {
            "TestBundlePath": "__TESTROOT__/CallbackTests-Runner.app/PlugIns/CallbackTests.xctest",
            "TestHostPath": "__TESTROOT__/CallbackTests-Runner.app",
            "UITargetAppPath": "__TESTROOT__/Debug-iphonesimulator/Callback.app",
            "UITargetAppBundleIdentifier": "org.apsa.synthetic.p" + "5" * 32,
            "EnvironmentVariables": {"NEW_EXISTING_TEST_SETTING": "kept"},
            "TestingEnvironmentVariables": {"NEW_TEST_HOST_SETTING": "__TESTROOT__/kept"},
        },
    }


def test_manifest_changes_only_exact_test_host_environment():
    value = manifest()
    original = copy.deepcopy(value)
    raw = plistlib.dumps(value)
    result = plistlib.loads(bridge.dispatch_manifest(raw, URI, SCHEME))
    actual = result["CallbackTests"].pop("EnvironmentVariables")
    expected = original["CallbackTests"].pop("EnvironmentVariables")
    assert result == original
    assert actual == {
        **expected,
        "APSA_DISPATCH_URI": URI,
        "APSA_DISPATCH_URI_SHA256": digest(URI.encode()),
        "APSA_DISPATCH_SCHEME": SCHEME,
    }
    assert plistlib.loads(raw) == value


@pytest.mark.parametrize(
    "url,scheme",
    [
        (URI.replace(SCHEME, "other", 1), SCHEME),
        (URI.replace("fixture", "existing", 1), SCHEME),
        (URI + "#fragment", SCHEME),
        (URI.replace("fixture?", "fixture/path?"), SCHEME),
        (URI.replace("fixture?", "fixture:80?"), SCHEME),
        (URI + "\n", SCHEME),
        (URI + "é", SCHEME),
        (URI + "x" * bridge.MAX_URI_BYTES, SCHEME),
        (SCHEME + "://fixture", SCHEME),
        (URI, "existing"),
    ],
)
def test_owned_uri_shape_rejects_other_origin_and_unbounded_input(url, scheme):
    with pytest.raises(ValueError, match="dispatch URI differs"):
        bridge.dispatch_manifest(plistlib.dumps(manifest()), url, scheme)


@pytest.mark.parametrize(
    "mutation",
    ["other-target", "v2", "missing-target", "missing-host", "bad-env", "reserved-env", "over-bound"],
)
def test_manifest_unknown_target_or_conflicting_environment_fails_closed(mutation):
    value = manifest()
    if mutation == "other-target":
        value["ExistingTests"] = value.pop("CallbackTests")
    elif mutation == "v2":
        value["__xctestrun_metadata__"]["FormatVersion"] = 2
    elif mutation == "missing-target":
        del value["CallbackTests"]
    elif mutation == "missing-host":
        del value["CallbackTests"]["TestHostPath"]
    elif mutation == "bad-env":
        value["CallbackTests"]["EnvironmentVariables"] = []
    elif mutation == "reserved-env":
        value["CallbackTests"]["EnvironmentVariables"]["APSA_DISPATCH_URI"] = "old"
    raw = plistlib.dumps(value)
    if mutation == "over-bound":
        raw = b"x" * (bridge.MAX_MANIFEST_BYTES + 1)
    with pytest.raises(ValueError, match="dispatch (manifest|environment) differs"):
        bridge.dispatch_manifest(raw, URI, SCHEME)


def test_generated_ui_test_dispatches_without_target_lifecycle_or_injected_response(tmp_path):
    root = tmp_path / "new-project"
    generated = bridge.write_project(root, "org.apsa.synthetic.p" + "5" * 32, "a" + "6" * 32)
    source = (root / "CallbackTests.swift").read_text()
    assert source.count("XCUIDevice.shared.system.open(url)") == 1
    assert all(
        forbidden not in source
        for forbidden in (
            "XCUIApplication(",
            ".launch(",
            ".terminate(",
            "UIApplication.shared",
            "response.json",
            "URLSession",
            URI,
        )
    )
    assert "APSA_DISPATCH_URI_SHA256" in source
    assert "SHA256.hash(data: Data(raw.utf8))" in source
    assert len(generated) == 5
    assert all(digest((root / name).read_bytes()) == checksum for name, checksum in generated.items())


class NewCommands:
    def __init__(self, root: Path):
        self.root, self.env = root, {"NEW_SYNTHETIC_TEST": "true"}
        self.resources = SimpleNamespace(value={"ios": {DEVICE: {"deleted": False, "selector": "default"}}})
        self.calls: list[tuple[list[str], dict]] = []
        self.dispatch_error: Exception | None = None
        self.dispatch_status: int | None = 0
        self.last_status: int | None = None

    def run(self, argv: list[str], **kwargs):
        self.calls.append((argv, kwargs))
        if "build-for-testing" in argv:
            derived = Path(argv[argv.index("-derivedDataPath") + 1])
            products = derived / "Build/Products"
            products.mkdir(parents=True)
            (products / "Callback_iphonesimulator.xctestrun").write_bytes(plistlib.dumps(manifest()))
            self.last_status = 0
        elif self.dispatch_error is not None:
            raise self.dispatch_error
        else:
            self.last_status = self.dispatch_status
        return b"NEW synthetic compiler output; never execute a compiler"


def new_dispatcher(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge.control.transport, "ios_default_set", lambda env: tmp_path / "new-set")
    commands = NewCommands(tmp_path)
    dispatcher = bridge.IosXCTestDispatcher(tmp_path / "new-helper", commands, DEVICE, PACKAGE, SCHEME)
    return dispatcher, commands


def test_one_build_reused_for_four_exact_owned_url_dispatches(tmp_path, monkeypatch):
    dispatcher, commands = new_dispatcher(tmp_path, monkeypatch)
    for number in range(4):
        url = URI + "&newSequence=" + str(number)
        observed = dispatcher.dispatch(url)
        assert observed["state"] == "diagnostic-only"
        assert observed["acquisition"] == "unsupported"
        assert observed["xctest_exit_success"] is True
        assert observed["uri_sha256"] == digest(url.encode())
        assert observed["invocation"] == number + 1
        path = Path(commands.calls[-1][0][commands.calls[-1][0].index("-xctestrun") + 1])
        value = plistlib.loads(path.read_bytes())
        assert value["CallbackTests"]["EnvironmentVariables"]["APSA_DISPATCH_URI"] == url
        assert path.parent == dispatcher.manifest.parent
        assert url not in json.dumps(observed)
    assert sum("build-for-testing" in argv for argv, _ in commands.calls) == 1
    assert sum("test-without-building" in argv for argv, _ in commands.calls) == 4
    assert all("platform=iOS Simulator,id=" + DEVICE in argv for argv, _ in commands.calls)
    assert all(0 < kwargs["timeout"] <= 600 for _, kwargs in commands.calls)
    assert dispatcher.helper_package != PACKAGE
    assert bridge.ENV_KEYS.isdisjoint(
        plistlib.loads(dispatcher.raw_manifest)["CallbackTests"]["EnvironmentVariables"]
    )


@pytest.mark.parametrize("mutation", ["not-journaled", "deleted", "custom", "package", "device", "outside"])
def test_ownership_rejected_before_source_generation_or_sdk_command(tmp_path, monkeypatch, mutation):
    monkeypatch.setattr(bridge.control.transport, "ios_default_set", lambda env: tmp_path / "new-set")
    monkeypatch.setattr(bridge, "write_project", lambda *args: pytest.fail("No generation before ownership"))
    commands = NewCommands(tmp_path)
    package, device, root = PACKAGE, DEVICE, tmp_path / "new-helper"
    if mutation == "not-journaled":
        commands.resources.value["ios"] = {}
    elif mutation == "deleted":
        commands.resources.value["ios"][DEVICE]["deleted"] = True
    elif mutation == "custom":
        commands.resources.value["ios"][DEVICE]["selector"] = "custom"
    elif mutation == "package":
        package = "existing.application"
    elif mutation == "device":
        device = "booted"
    else:
        root = tmp_path.parent / "new-outside"
    with pytest.raises(ValueError):
        bridge.IosXCTestDispatcher(root, commands, device, package, SCHEME)
    assert commands.calls == []


@pytest.mark.parametrize(
    "reason", ["unknown-startup", "command-nonzero-status", "command-timeout", "command-spawn-os-error"]
)
def test_failure_and_revoked_journal_never_become_success_or_retry(tmp_path, monkeypatch, reason):
    dispatcher, commands = new_dispatcher(tmp_path, monkeypatch)
    commands.dispatch_error = (
        ValueError("NEW synthetic XCTest startup failure")
        if reason == "unknown-startup"
        else transport.CommandFailure(reason, {"status": 65 if reason == "command-nonzero-status" else None})
    )
    with pytest.raises(ValueError):
        dispatcher.dispatch(URI)
    assert dispatcher.latest["xctest_exit_success"] is False
    assert dispatcher.latest["acquisition"] == "unsupported"
    assert len(commands.calls) == 2
    commands.resources.value["ios"][DEVICE]["deleted"] = True
    with pytest.raises(ValueError, match="dispatch ownership differs"):
        dispatcher.dispatch(URI)
    assert len(commands.calls) == 2


def test_dispatch_count_is_bounded_without_an_extra_sdk_startup(tmp_path, monkeypatch):
    dispatcher, commands = new_dispatcher(tmp_path, monkeypatch)
    for _ in range(bridge.MAX_DISPATCHES):
        dispatcher.dispatch(URI)
    with pytest.raises(ValueError, match="dispatch limit exceeded"):
        dispatcher.dispatch(URI)
    assert len(commands.calls) == bridge.MAX_DISPATCHES + 1


@pytest.mark.parametrize("status", [None, 65, -15])
def test_only_explicit_zero_exit_is_a_completed_diagnostic_dispatch(tmp_path, monkeypatch, status):
    dispatcher, commands = new_dispatcher(tmp_path, monkeypatch)
    commands.dispatch_status = status
    with pytest.raises(ValueError, match="dispatch completion unverified"):
        dispatcher.dispatch(URI)
    assert dispatcher.latest["xctest_exit_success"] is False
    assert dispatcher.latest["acquisition"] == "unsupported"
    assert len(commands.calls) == 2


def test_target_driver_requires_build_identity_before_xctest_dispatch(monkeypatch):
    target = object.__new__(transport.IosTarget)
    target.device, target.url_driver = DEVICE, "xctest"
    target.build = {"executable_sha256": "a" * 64, "info_plist_sha256": "b" * 64}
    calls = []
    monkeypatch.setattr(target, "require_installed_contract", lambda: calls.append("contract"))
    target.installed_build = lambda: {**target.build, "executable_sha256": "c" * 64}
    monkeypatch.setattr(
        target, "xctest_dispatcher", SimpleNamespace(dispatch=lambda uri: calls.append(uri)), raising=False
    )
    with pytest.raises(ValueError, match="installed iOS executable differs"):
        target.dispatch(URI)
    assert calls == ["contract"]
    target.installed_build = lambda: target.build.copy()
    target.dispatch(URI)
    assert calls == ["contract", "contract", URI]


def test_successful_xctest_exit_cannot_replace_authoritative_target_response(tmp_path, monkeypatch):
    target = object.__new__(transport.IosTarget)
    target.device, target.scheme = DEVICE, SCHEME
    target.response = tmp_path / "new-missing-response.json"
    dispatched = []
    target.dispatch = lambda url: dispatched.append(url)
    target.lifecycle_observation = lambda: {"dispatcher": {"xctest_exit_success": True}}
    clock = iter((0, 100))
    monkeypatch.setattr(transport.time, "monotonic", lambda: next(clock))
    with pytest.raises(transport.FixtureFailure, match="response challenge timed out"):
        target.deliver(
            URI.replace(SCHEME, "apsatransport", 1),
            {"action": "capture", "session": "3" * 64, "nonce": "4" * 64},
        )
    assert dispatched == [URI]


def test_xctest_custom_device_set_rejected_before_any_tool_or_source_write(tmp_path):
    commands = NewCommands(tmp_path)
    with pytest.raises(ValueError, match="owned default-set target"):
        transport.IosTarget(
            tmp_path / "new",
            PACKAGE,
            cast(transport.Commands, commands),
            None,
            "new-device",
            url_driver="xctest",
        )
    assert commands.calls == []
    assert not (tmp_path / "new").exists()


def test_hosted_workflow_keeps_all_six_cases_and_independent_owned_cleanup():
    source = Path(__file__).resolve().parents[1] / ".github/workflows/runtime-transport.yml"
    jobs = yaml.safe_load(source.read_text())["jobs"]
    job = jobs["ios-xctest"]
    assert job["runs-on"] == "macos-15" and job["timeout-minutes"] == 90
    assert "continue-on-error" not in job
    primary = next(step for step in job["steps"] if "--ios-url-driver xctest" in step.get("run", ""))
    assert "--ios-device-set default" in primary["run"]
    assert "--ios-runtime " + transport.IOS_PINNED_RUNTIME in primary["run"]
    assert "--ios-device-type " + transport.IOS_PINNED_DEVICE_TYPE in primary["run"]
    assert "--ios-os-url-control" not in primary["run"]
    assert "continue-on-error" not in primary
    cleanup = next(step for step in job["steps"] if "--cleanup-only" in step.get("run", ""))
    assert cleanup["if"] == "always()" and cleanup["timeout-minutes"] == 5
    assert '--work "$RUNNER_TEMP/runtime-new-xctest"' in primary["run"]
    assert '--work "$RUNNER_TEMP/runtime-new-xctest"' in cleanup["run"]
    uploads = [step for step in job["steps"] if "upload-artifact" in step.get("uses", "")]
    assert len(uploads) == 2 and all(step["if"] == "always()" for step in uploads)
    assert all("case-" not in step["with"]["path"] for step in uploads)
    assert {"ios", "ios-app-to-app", "ios-default-set", "ios-app-to-app-default-set"} <= set(jobs)
    assert all(
        "simctl list" not in step.get("run", "") and "booted" not in step.get("run", "")
        for step in job["steps"]
    )


def test_xctest_cli_binds_bridge_and_generator_sources_even_when_new_target_fails(
    tmp_path, monkeypatch, capsys
):
    root = tmp_path / "new-owned-driver"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "new-runtime",
            "--platform",
            "ios",
            "--ios-device-set",
            "default",
            "--ios-url-driver",
            "xctest",
            "--work",
            str(root),
        ],
    )

    def fail_new_target(*args, **kwargs):
        raise ValueError("NEW synthetic target build failure")

    monkeypatch.setattr(transport, "IosTarget", fail_new_target)
    with pytest.raises(SystemExit) as caught:
        transport.main()
    assert caught.value.code == 1
    value = json.loads((root / "evidence.json").read_text())
    for name in ("ios_xctest_dispatch.py", "validate_runtime_xctest_control.py"):
        path = Path(__file__).resolve().parents[1] / "scripts" / name
        assert value["source_sha256"][name] == digest(path.read_bytes())
    assert value["state"] == "inconclusive" and value["terminal"] is True
    assert value["cases"] == []
    assert value["cleanup"]["state"] == "confirmed"
    assert "NEW synthetic target build failure" not in capsys.readouterr().out
