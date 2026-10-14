"""Fresh synthetic journals with mocked commands/Popen only; no GUI or SDK."""

import json
import subprocess
import sys
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import MappingProxyType
from typing import cast

import pytest
import yaml

from scripts import validate_runtime_gui_control as control
from scripts import validate_runtime_transport as transport

DEVICE = "12345678-1234-4234-8234-1234567890AB"
OTHER_DEVICE = "87654321-4321-4321-8321-BA0987654321"
GUI_SELECTIONS = [
    pytest.param("legacy", "custom", "legacy", id="legacy-custom"),
    pytest.param("legacy", "default", "legacy", id="legacy-default"),
    pytest.param("modern", "custom", "modern", id="modern-custom"),
]
CUSTOM_TOOLCHAINS = [("legacy", "legacy"), ("modern", "modern")]


@pytest.fixture
def hosted(tmp_path, monkeypatch, request):
    config = control.selected_toolchain(getattr(request, "param", "legacy"))
    env = {
        "GITHUB_ACTIONS": "true",
        "CI": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS",
        "HOME": "/Users/runner",
        "DEVELOPER_DIR": config.developer_dir,
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_RUN_ID": "new-synthetic-run",
        "GITHUB_SHA": "a" * 40,
    }
    monkeypatch.setattr(control.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(control.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(control.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(control.os, "environ", env)
    return env


class Process:
    def __init__(self, *, exited=None, reap_failure=False):
        self.status = exited
        self.reap_failure = reap_failure
        self.calls = []

    def poll(self):
        self.calls.append("poll")
        return self.status

    def terminate(self):
        self.calls.append("terminate")

    def wait(self, *, timeout):
        self.calls.append(("wait", timeout))
        if self.reap_failure:
            raise subprocess.TimeoutExpired("NEW synthetic secret never exposed", timeout)
        self.status = 0
        return 0


def synthetic_commands(root, hosted, monkeypatch, *, process=None, selector="custom", toolchain="legacy"):
    root.mkdir()
    commands = control.GuiCommands(root, env=hosted, selector=selector, toolchain=toolchain)
    commands.resources = transport.OwnedResources(root)
    sdk_calls, gui_calls = [], []
    process = process or Process()

    def run(self, argv, **kwargs):
        sdk_calls.append((argv, kwargs))
        self.last_status = 0
        return (DEVICE + "\n").encode() if "create" in argv else b""

    def popen(argv, **kwargs):
        gui_calls.append((argv, kwargs))
        return process

    monkeypatch.setattr(transport.Commands, "run", run)
    monkeypatch.setattr(control.subprocess, "Popen", popen)
    return commands, sdk_calls, gui_calls, process


def create_and_boot(commands):
    prefix, _ = transport.ios_selector(commands.root, commands.selector, commands.env)
    commands.run(
        prefix + ["create", "APSA-NEW-synthetic", commands.config.device_type, commands.config.runtime]
    )
    commands.resources.ios(DEVICE, selector=commands.selector)
    commands.run(prefix + ["boot", DEVICE])
    return prefix


@pytest.mark.parametrize(
    "change",
    [
        {"GITHUB_ACTIONS": "false"},
        {"CI": "false"},
        {"RUNNER_ENVIRONMENT": "self-hosted"},
        {"RUNNER_OS": "Linux"},
        {"HOME": "/new-other-home"},
        {"DEVELOPER_DIR": "/new-other-xcode"},
        {"RUNNER_TEMP": ""},
        {"SIMULATOR_DEVICE_SET_PATH": ""},
        {"SIMCTL_DEVICE_SET_PATH": "/new-other-set"},
        {"CORE_SIMULATOR_DEVICE_SET_PATH": ""},
        {"CFFIXED_USER_HOME": "/new-other-home"},
        {"SIMULATOR_ROOT": ""},
        {"SIMULATOR_HOME": ""},
        {"SIMULATOR_UDID": "booted"},
        {"SIMCTL_CHILD_NEW_VARIABLE": "new-value"},
    ],
)
@pytest.mark.parametrize("selector", ["custom", "default"])
def test_guard_rejects_non_hosted_or_namespace_override_before_gui(
    tmp_path, hosted, monkeypatch, change, selector
):
    monkeypatch.setattr(control.subprocess, "Popen", lambda *_a, **_k: pytest.fail("unexpected GUI"))
    with pytest.raises(ValueError, match="pinned disposable hosted"):
        control.GuiCommands(tmp_path / "new-work", env={**hosted, **change}, selector=selector)


@pytest.mark.parametrize("failure", ["os", "architecture", "runner-temp-root", "outside-runner-temp"])
def test_guard_rejects_host_and_work_boundary(tmp_path, hosted, monkeypatch, failure):
    root = tmp_path / "new-work"
    if failure == "os":
        monkeypatch.setattr(control.platform, "system", lambda: "Linux")
    elif failure == "architecture":
        monkeypatch.setattr(control.platform, "machine", lambda: "x86_64")
    elif failure == "runner-temp-root":
        root = tmp_path
    else:
        root = tmp_path.parent / "new-outside-work"
    monkeypatch.setattr(control.subprocess, "Popen", lambda *_a, **_k: pytest.fail("unexpected GUI"))
    with pytest.raises(ValueError):
        control.GuiCommands(root, env=hosted)


@pytest.mark.parametrize("hosted,selector,toolchain", GUI_SELECTIONS, indirect=["hosted"])
def test_gui_starts_only_after_fresh_create_journal_boot_and_bootstatus(
    tmp_path, hosted, monkeypatch, selector, toolchain
):
    commands, sdk_calls, gui_calls, process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector=selector, toolchain=toolchain
    )
    prefix = create_and_boot(commands)
    assert gui_calls == []
    commands.run(prefix + ["bootstatus", DEVICE, "-b"], timeout=180)
    argv, options = gui_calls[0]
    assert argv == [
        commands.config.developer_dir + "/Applications/Simulator.app/Contents/MacOS/Simulator",
        "-CurrentDeviceUDID",
        DEVICE,
        "-DeviceSetPath",
        str(commands.root / "simulator-set")
        if selector == "custom"
        else "/Users/runner/Library/Developer/CoreSimulator/Devices",
    ]
    assert options == {
        "cwd": commands.root,
        "env": hosted,
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    assert sdk_calls[-1][0] == prefix + ["bootstatus", DEVICE, "-b"]
    assert sdk_calls[-1][1]["timeout"] == control.GUI_BOOTSTATUS_SECONDS == 600
    assert commands.gui_records[0]["selector"] == selector
    assert commands.gui_records[0]["state"] == "live-after-settle"
    assert commands.gui_records[0]["delivery"] == "unsupported"
    assert commands.gui_records[0]["foreground"] == "unmeasured"
    assert commands.gui_records[0]["toolchain"] == toolchain
    assert commands.gui_records[0]["ios_runtime"] == commands.config.runtime
    assert commands.gui_records[0]["developer_dir"] == commands.config.developer_dir
    assert all("argv" not in item for item in json.loads((commands.root / "commands.json").read_text()))
    commands.run(prefix + ["shutdown", DEVICE])
    assert process.calls[-2:] == ["terminate", ("wait", control.GUI_WAIT_SECONDS)]
    assert commands.close_all_gui()["state"] == "confirmed"
    assert commands.gui_cleanup[DEVICE]["selector"] == selector
    assert process.calls.count("terminate") == 1


@pytest.mark.parametrize(
    "failure",
    [
        "unjournaled",
        "default-journal",
        "other-uuid",
        "not-created",
        "no-boot",
        "other-set",
        "default-set",
        "booted",
        "symlink",
        "wrong-root",
        "wrong-root-journal",
        "deleted",
        "lowercase",
    ],
)
@pytest.mark.parametrize("hosted,toolchain", CUSTOM_TOOLCHAINS, indirect=["hosted"])
def test_non_owned_boot_never_starts_gui(tmp_path, hosted, monkeypatch, failure, toolchain):
    commands, _sdk, gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, toolchain=toolchain
    )
    assert commands.resources is not None
    prefix = create_and_boot(commands)
    device = DEVICE
    if failure == "unjournaled":
        commands.resources.value["ios"] = {}
    elif failure == "default-journal":
        commands.resources.ios(DEVICE, selector="default")
    elif failure == "other-uuid":
        device = OTHER_DEVICE
        commands.resources.ios(device, selector="custom")
    elif failure == "not-created":
        commands.created.clear()
    elif failure == "no-boot":
        commands.booted.clear()
    elif failure == "other-set":
        prefix[-1] = str(tmp_path / "new-neighbor-set")
    elif failure == "default-set":
        prefix = ["/usr/bin/xcrun", "simctl"]
    elif failure == "booted":
        device = "booted"
    elif failure == "symlink":
        (commands.root / "simulator-set").symlink_to(tmp_path / "new-neighbor-set")
    elif failure == "wrong-root":
        commands.resources.root = tmp_path / "new-other-root"
    elif failure == "wrong-root-journal":
        commands.resources.value["root"] = str(tmp_path / "new-other-root")
    elif failure == "deleted":
        commands.resources.value["ios"][DEVICE]["deleted"] = True
    else:
        device = DEVICE.lower()
        commands.resources.ios(device, selector="custom")
    with pytest.raises(ValueError):
        commands.run(prefix + ["bootstatus", device, "-b"])
    assert gui_calls == []


@pytest.mark.parametrize("hosted,selector,toolchain", GUI_SELECTIONS, indirect=["hosted"])
@pytest.mark.parametrize(
    "failure",
    ["foreign-uuid", "wrong-journal", "wrong-prefix", "booted", "default-device", "foreign-cleanup"],
)
def test_both_selectors_refuse_foreign_or_ambiguous_device_before_sdk(
    tmp_path,
    hosted,
    monkeypatch,
    selector,
    failure,
    toolchain,
):
    commands, sdk_calls, gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector=selector, toolchain=toolchain
    )
    assert commands.resources is not None
    prefix = create_and_boot(commands)
    device, operation = DEVICE, "bootstatus"
    if failure in {"foreign-uuid", "foreign-cleanup"}:
        device = OTHER_DEVICE
        commands.resources.ios(device, selector=selector)
        if failure == "foreign-cleanup":
            operation = "delete"
    elif failure == "wrong-journal":
        commands.resources.ios(DEVICE, selector="custom" if selector == "default" else "default")
    elif failure == "wrong-prefix":
        prefix = (
            ["/usr/bin/xcrun", "simctl"]
            if selector == "custom"
            else [
                "/usr/bin/xcrun",
                "simctl",
                "--set",
                str(tmp_path / "new-other-set"),
            ]
        )
    else:
        device = "booted" if failure == "booted" else "default"
    previous_calls = len(sdk_calls)
    with pytest.raises(ValueError):
        commands.run(prefix + [operation, device] + (["-b"] if operation == "bootstatus" else []))
    assert len(sdk_calls) == previous_calls and gui_calls == []


@pytest.mark.parametrize("hosted,selector,toolchain", GUI_SELECTIONS, indirect=["hosted"])
@pytest.mark.parametrize("failure", ["already-journaled", "duplicate-create"])
def test_create_returned_uuid_must_be_new_to_this_invocation(
    tmp_path, hosted, monkeypatch, selector, failure, toolchain
):
    commands, sdk_calls, gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector=selector, toolchain=toolchain
    )
    assert commands.resources is not None
    prefix, _ = transport.ios_selector(commands.root, selector, hosted)
    create = prefix + [
        "create",
        "APSA-NEW-synthetic",
        commands.config.device_type,
        commands.config.runtime,
    ]
    if failure == "already-journaled":
        commands.resources.ios(DEVICE, selector=selector)
    else:
        commands.run(create)
    with pytest.raises(ValueError, match="UUID is not fresh"):
        commands.run(create)
    assert gui_calls == [] and all(call[0] == create for call in sdk_calls)


def test_default_factory_never_inspects_default_namespace(tmp_path, hosted, monkeypatch):
    default_set = Path("/Users/runner/Library/Developer/CoreSimulator/Devices")
    original_symlink, original_resolve = Path.is_symlink, Path.resolve

    def no_default_symlink(path):
        assert not path.is_relative_to(default_set), "must not inspect default-set paths"
        return original_symlink(path)

    def no_default_resolve(path, *args, **kwargs):
        assert not path.is_relative_to(default_set), "must not resolve default-set paths"
        return original_resolve(path, *args, **kwargs)

    monkeypatch.setattr(Path, "is_symlink", no_default_symlink)
    monkeypatch.setattr(Path, "resolve", no_default_resolve)
    commands, sdk_calls, gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector="default"
    )
    prefix = create_and_boot(commands)
    commands.run(prefix + ["bootstatus", DEVICE, "-b"], timeout=180)
    assert gui_calls[0][0][-1] == str(default_set)
    assert [call[0][2] for call in sdk_calls] == ["create", "boot", "bootstatus"]
    assert all(call[0][3] == DEVICE for call in sdk_calls[1:])
    commands.close_all_gui()


@pytest.mark.parametrize("hosted,toolchain", CUSTOM_TOOLCHAINS, indirect=["hosted"])
def test_bootstatus_budget_change_does_not_change_any_other_command_deadline(
    tmp_path, hosted, monkeypatch, toolchain
):
    commands, sdk_calls, _gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, toolchain=toolchain
    )
    prefix = create_and_boot(commands)
    commands.run(prefix + ["bootstatus", DEVICE, "-b"], timeout=180)
    commands.run(prefix + ["openurl", DEVICE, "new-synthetic-owned-url"], timeout=15)
    assert sdk_calls[-2][1]["timeout"] == 600
    assert sdk_calls[-1][1]["timeout"] == 15
    commands.close_all_gui()


@pytest.mark.parametrize("hosted,selector,toolchain", GUI_SELECTIONS, indirect=["hosted"])
def test_failed_bootstatus_preserves_command_failure_and_never_starts_gui(
    tmp_path, hosted, monkeypatch, selector, toolchain
):
    commands, _sdk, gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector=selector, toolchain=toolchain
    )
    prefix = create_and_boot(commands)
    original = transport.CommandFailure("command-timeout", {"status": None})

    calls = []

    def fail(_self, argv, **kwargs):
        calls.append((argv, kwargs))
        assert kwargs["timeout"] == 600
        raise original

    monkeypatch.setattr(transport.Commands, "run", fail)
    with pytest.raises(transport.CommandFailure) as caught:
        commands.run(prefix + ["bootstatus", DEVICE, "-b"])
    assert caught.value is original and gui_calls == []
    assert len(calls) == 1


@pytest.mark.parametrize("failure", ["spawn", "exited", "reap-timeout"])
@pytest.mark.parametrize("hosted,toolchain", CUSTOM_TOOLCHAINS, indirect=["hosted"])
def test_gui_failure_is_redacted_and_cleanup_never_claims_unreaped_child(
    tmp_path, hosted, monkeypatch, failure, toolchain
):
    process = Process(exited=3 if failure == "exited" else None, reap_failure=failure == "reap-timeout")
    commands, _sdk, _gui_calls, process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, process=process, toolchain=toolchain
    )
    prefix = create_and_boot(commands)
    if failure == "spawn":

        def spawn_failure(*_a, **_k):
            raise OSError(13, "NEW synthetic secret never exposed")

        monkeypatch.setattr(control.subprocess, "Popen", spawn_failure)
    if failure == "reap-timeout":
        commands.run(prefix + ["bootstatus", DEVICE, "-b"])
    else:
        with pytest.raises(ValueError):
            commands.run(prefix + ["bootstatus", DEVICE, "-b"])
    cleanup = commands.close_all_gui()
    assert cleanup["state"] == ("unconfirmed" if failure == "reap-timeout" else "confirmed")
    if failure == "reap-timeout":
        assert cleanup["results"][0]["reaped"] is False
    assert "secret" not in json.dumps(commands.gui_records + [cleanup])


@pytest.mark.parametrize("failure", ["none", "nonzero", "exception", "cleanup"])
@pytest.mark.parametrize("hosted,selector,toolchain", GUI_SELECTIONS, indirect=["hosted"])
def test_wrapper_keeps_driver_contract_and_failure_separate(
    tmp_path, hosted, monkeypatch, failure, selector, toolchain
):
    root = tmp_path / "new-control"
    original_commands, original_argv = transport.Commands, sys.argv
    driver_error = ValueError("NEW synthetic driver failed")
    process = Process(reap_failure=failure == "cleanup")
    config = control.selected_toolchain(toolchain)

    def mock_run(self, argv, **_kwargs):
        self.last_status = 0
        return (DEVICE + "\n").encode() if "create" in argv else b""

    monkeypatch.setattr(original_commands, "run", mock_run)
    monkeypatch.setattr(control.subprocess, "Popen", lambda *_a, **_k: process)

    def driver():
        assert sys.argv[1:] == [
            "--platform",
            "ios",
            "--ios-device-set",
            selector,
            "--ios-runtime",
            config.runtime,
            "--ios-device-type",
            config.device_type,
            "--ios-url-driver",
            "companion",
            "--work",
            str(root),
        ]
        assert "--ios-os-url-control" not in sys.argv
        root.mkdir()
        commands = transport.Commands(root)
        commands.resources = transport.OwnedResources(root)
        prefix = create_and_boot(commands)
        commands.run(prefix + ["bootstatus", DEVICE, "-b"])
        checkpoint = json.loads((root / "gui-control.json").read_text())
        assert checkpoint["terminal"] is False
        assert checkpoint["gui_cleanup"]["state"] == "unconfirmed"
        assert checkpoint["gui"][0]["state"] == "live-after-settle"
        if failure == "nonzero":
            raise SystemExit(7)
        if failure == "exception":
            raise driver_error

    monkeypatch.setattr(transport, "main", driver)
    if failure == "none":
        control.run_control(root, "companion", selector, toolchain)
    elif failure == "exception":
        with pytest.raises(ValueError) as caught:
            control.run_control(root, "companion", selector, toolchain)
        assert caught.value is driver_error
    else:
        with pytest.raises(SystemExit) as caught:
            control.run_control(root, "companion", selector, toolchain)
        assert caught.value.code == (7 if failure == "nonzero" else 1)
    result = json.loads((root / "gui-control.json").read_text())
    assert result["terminal"] is True
    assert result["ios_device_set"] == selector and result["source_version"] == 2
    assert all(result[key] == value for key, value in config.evidence().items())
    assert result["bootstatus_timeout_seconds"] == 600
    assert result["primary_bootstatus_timeout_seconds"] == 180
    assert result["state"] == ("passed-setup-specific" if failure == "none" else "inconclusive")
    assert result["driver_exit_status"] == (
        7 if failure == "nonzero" else None if failure == "exception" else 0
    )
    assert result["gui_cleanup"]["state"] == ("unconfirmed" if failure == "cleanup" else "confirmed")
    assert transport.Commands is original_commands and sys.argv is original_argv


def test_wrapper_rejects_existing_work_without_driver_or_gui(tmp_path, hosted, monkeypatch):
    root = tmp_path / "new-existing"
    root.mkdir()
    monkeypatch.setattr(transport, "main", lambda: pytest.fail("unexpected driver"))
    monkeypatch.setattr(control.subprocess, "Popen", lambda *_a, **_k: pytest.fail("unexpected GUI"))
    with pytest.raises(ValueError, match="NEW work"):
        control.run_control(root, "simctl")


def test_toolchain_allowlist_is_immutable_and_exact():
    assert set(control.GUI_TOOLCHAINS) == {"legacy", "modern"}
    assert control.selected_toolchain("legacy") == control.GuiToolchain(
        "legacy",
        "/Applications/Xcode_16.4.app/Contents/Developer",
        "com.apple.CoreSimulator.SimRuntime.iOS-18-5",
        "com.apple.CoreSimulator.SimDeviceType.iPhone-16",
    )
    modern = control.selected_toolchain("modern")
    assert modern == control.GuiToolchain(
        "modern",
        "/Applications/Xcode_26.3.app/Contents/Developer",
        "com.apple.CoreSimulator.SimRuntime.iOS-26-2",
        "com.apple.CoreSimulator.SimDeviceType.iPhone-16",
    )
    for field in ("key", "developer_dir", "runtime", "device_type"):
        with pytest.raises(FrozenInstanceError):
            setattr(modern, field, "new-synthetic-value")
    with pytest.raises(TypeError):
        cast(dict[str, control.GuiToolchain], control.GUI_TOOLCHAINS)["new-other"] = modern
    assert transport.IOS_PINNED_RUNTIME == "com.apple.CoreSimulator.SimRuntime.iOS-18-5"


@pytest.mark.parametrize("toolchain", ["new-unknown", "/Applications/Xcode_26.3.app", "", None])
def test_unknown_toolchain_rejected_before_device_work(tmp_path, hosted, monkeypatch, toolchain):
    monkeypatch.setattr(transport, "ios_selector", lambda *_a: pytest.fail("unexpected selector"))
    monkeypatch.setattr(transport, "main", lambda: pytest.fail("unexpected driver"))
    monkeypatch.setattr(transport.Commands, "__init__", lambda *_a, **_k: pytest.fail("unexpected commands"))
    with pytest.raises(ValueError, match="toolchain must be"):
        control.GuiCommands(tmp_path / "new-work", env=hosted, toolchain=toolchain)
    with pytest.raises(ValueError, match="toolchain must be"):
        control.run_control(tmp_path / "new-work", "simctl", toolchain=toolchain)


@pytest.mark.parametrize("hosted", ["modern"], indirect=True)
def test_modern_default_rejected_before_device_work(tmp_path, hosted, monkeypatch):
    monkeypatch.setattr(transport, "ios_selector", lambda *_a: pytest.fail("unexpected selector"))
    monkeypatch.setattr(transport, "main", lambda: pytest.fail("unexpected driver"))
    monkeypatch.setattr(transport.Commands, "__init__", lambda *_a, **_k: pytest.fail("unexpected commands"))
    with pytest.raises(ValueError, match="modern toolchain requires custom"):
        control.GuiCommands(tmp_path / "new-work", env=hosted, selector="default", toolchain="modern")
    with pytest.raises(ValueError, match="modern toolchain requires custom"):
        control.run_control(tmp_path / "new-work", "simctl", "default", "modern")


@pytest.mark.parametrize("hosted,toolchain", CUSTOM_TOOLCHAINS, indirect=["hosted"])
@pytest.mark.parametrize("developer_dir", ["other-toolchain", "arbitrary", "trailing-slash"])
def test_selected_toolchain_rejects_other_developer_dir(
    tmp_path, hosted, monkeypatch, toolchain, developer_dir
):
    config = control.selected_toolchain(toolchain)
    path = (
        control.selected_toolchain("modern" if toolchain == "legacy" else "legacy").developer_dir
        if developer_dir == "other-toolchain"
        else "/Applications/Xcode_NEW.app/Contents/Developer"
        if developer_dir == "arbitrary"
        else config.developer_dir + "/"
    )
    monkeypatch.setattr(transport, "ios_selector", lambda *_a: pytest.fail("unexpected selector"))
    with pytest.raises(ValueError, match="pinned disposable hosted"):
        control.GuiCommands(tmp_path / "new-work", env={**hosted, "DEVELOPER_DIR": path}, toolchain=toolchain)


@pytest.mark.parametrize("hosted,selector,toolchain", GUI_SELECTIONS, indirect=["hosted"])
@pytest.mark.parametrize("field", ["runtime", "device-type", "name"])
def test_create_inputs_are_closed_to_selected_toolchain(
    tmp_path, hosted, monkeypatch, selector, toolchain, field
):
    commands, sdk_calls, gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector=selector, toolchain=toolchain
    )
    prefix, _ = commands._selected()
    tail = ["create", "APSA-NEW-synthetic", commands.config.device_type, commands.config.runtime]
    if field == "runtime":
        tail[3] = control.selected_toolchain("modern" if toolchain == "legacy" else "legacy").runtime
    elif field == "device-type":
        tail[2] = "com.apple.CoreSimulator.SimDeviceType.iPhone-NEW"
    else:
        tail[1] = "APSA-existing-synthetic"
    with pytest.raises(ValueError, match="fresh CREATE inputs differ"):
        commands.run(prefix + tail)
    assert sdk_calls == [] and gui_calls == []


@pytest.mark.parametrize("hosted,toolchain", CUSTOM_TOOLCHAINS, indirect=["hosted"])
def test_guard_and_commands_accept_typed_mapping_copy(tmp_path, hosted, monkeypatch, toolchain):
    root = tmp_path / "new-work"
    immutable_env = MappingProxyType(hosted)
    config = control.selected_toolchain(toolchain)
    assert control.hosted_gui_guard(root, immutable_env, toolchain) == Path(config.developer_dir) / (
        "Applications/Simulator.app/Contents/MacOS/Simulator"
    )
    commands = control.GuiCommands(root, env=immutable_env, toolchain=toolchain)
    assert type(commands.env) is dict and commands.env == hosted


@pytest.mark.parametrize(
    "options",
    [
        ["--ios-toolchain", "new-unknown"],
        ["--ios-toolchain", "/Applications/Xcode_26.3.app"],
        ["--ios-runtime", "com.apple.CoreSimulator.SimRuntime.iOS-NEW"],
        ["--developer-dir", "/Applications/Xcode_NEW.app/Contents/Developer"],
    ],
)
def test_cli_never_accepts_arbitrary_toolchain_runtime_or_path(tmp_path, monkeypatch, options):
    monkeypatch.setattr(sys, "argv", ["new-control", "--work", str(tmp_path / "new-work"), *options])
    monkeypatch.setattr(control, "run_control", lambda *_a: pytest.fail("unexpected driver"))
    with pytest.raises(SystemExit) as caught:
        control.main()
    assert caught.value.code == 2


@pytest.mark.parametrize("toolchain", [None, "legacy", "modern"])
def test_cli_defaults_to_legacy_and_forwards_only_allowlisted_selection(tmp_path, monkeypatch, toolchain):
    options = [] if toolchain is None else ["--ios-toolchain", toolchain]
    root = tmp_path / "new-work"
    monkeypatch.setattr(sys, "argv", ["new-control", "--work", str(root), *options])
    calls = []
    monkeypatch.setattr(control, "run_control", lambda *args: calls.append(args))
    control.main()
    assert calls == [(root, "simctl", "custom", toolchain or "legacy")]


def test_workflow_is_bounded_setup_control_with_independent_cleanup():
    path = Path(__file__).parents[1] / ".github/workflows/runtime-gui-control.yml"
    workflow = yaml.safe_load(path.read_text())
    trigger = workflow.get("on", workflow.get(True))
    assert trigger["push"]["branches"] == ["validation/apsa-final-*"]
    assert set(trigger["push"]["paths"]) == {
        "scripts/validate_runtime_gui_control.py",
        "tests/test_runtime_gui_control.py",
        ".github/workflows/runtime-gui-control.yml",
    }
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["ios-gui-setup-control"]
    assert job["runs-on"] == "macos-15" and job["timeout-minutes"] == 45
    assert job["strategy"]["matrix"]["driver"] == ["simctl", "companion"]
    assert job["strategy"]["matrix"]["selector"] == ["custom", "default"]
    step = next(
        item for item in job["steps"] if "scripts.validate_runtime_gui_control" in item.get("run", "")
    )
    assert '--work "$RUNNER_TEMP/runtime-new-gui-' in step["run"]
    assert "--ios-device-set ${{ matrix.selector }}" in step["run"]
    cleanup = next(item for item in job["steps"] if "--cleanup-only" in item.get("run", ""))
    assert cleanup["if"] == "always()" and cleanup["timeout-minutes"] == 5
    for item in job["steps"]:
        if "upload-artifact" in item.get("uses", ""):
            assert item["if"] == "always()"
            assert all(line.endswith(".json") for line in item["with"]["path"].splitlines())


def test_modern_workflow_is_bounded_custom_set_control_with_independent_cleanup():
    path = Path(__file__).parents[1] / ".github/workflows/runtime-modern-control.yml"
    workflow = yaml.safe_load(path.read_text())
    trigger = workflow.get("on", workflow.get(True))
    assert trigger["push"]["branches"] == ["validation/apsa-final-*"]
    assert set(trigger["push"]["paths"]) == {
        "scripts/validate_runtime_gui_control.py",
        "tests/test_runtime_gui_control.py",
        ".github/workflows/runtime-modern-control.yml",
    }
    assert "workflow_dispatch" in trigger
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["ios-modern-setup-control"]
    assert job["runs-on"] == "macos-15" and job["timeout-minutes"] == 45
    assert job["env"] == {"DEVELOPER_DIR": "/Applications/Xcode_26.3.app/Contents/Developer"}
    assert job["strategy"] == {"fail-fast": False, "matrix": {"driver": ["simctl", "companion"]}}
    step = next(
        item for item in job["steps"] if "scripts.validate_runtime_gui_control" in item.get("run", "")
    )
    assert '--work "$RUNNER_TEMP/runtime-new-modern-' in step["run"]
    assert "--ios-toolchain modern" in step["run"]
    assert "--ios-device-set custom" in step["run"]
    assert "--ios-url-driver ${{ matrix.driver }}" in step["run"]
    assert "--ios-os-url-control" not in step["run"]
    assert all("xcode-select" not in item.get("run", "") for item in job["steps"])
    cleanup = next(item for item in job["steps"] if "--cleanup-only" in item.get("run", ""))
    assert cleanup["if"] == "always()" and cleanup["timeout-minutes"] == 5
    assert '--work "$RUNNER_TEMP/runtime-new-modern-' in cleanup["run"]
    for item in job["steps"]:
        if "upload-artifact" in item.get("uses", ""):
            assert item["if"] == "always()"
            assert all(line.endswith(".json") for line in item["with"]["path"].splitlines())
