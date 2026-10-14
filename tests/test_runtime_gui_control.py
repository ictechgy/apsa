"""Fresh synthetic journals with mocked commands/Popen only; no GUI or SDK."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts import validate_runtime_gui_control as control
from scripts import validate_runtime_transport as transport

DEVICE = "12345678-1234-4234-8234-1234567890AB"
OTHER_DEVICE = "87654321-4321-4321-8321-BA0987654321"


@pytest.fixture
def hosted(tmp_path, monkeypatch):
    env = {
        "GITHUB_ACTIONS": "true",
        "CI": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS",
        "HOME": "/Users/runner",
        "DEVELOPER_DIR": control.PINNED_DEVELOPER_DIR,
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


def synthetic_commands(root, hosted, monkeypatch, *, process=None, selector="custom"):
    root.mkdir()
    commands = control.GuiCommands(root, env=hosted, selector=selector)
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
        prefix
        + ["create", "APSA-NEW-synthetic", transport.IOS_PINNED_DEVICE_TYPE, transport.IOS_PINNED_RUNTIME]
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


@pytest.mark.parametrize("selector", ["custom", "default"])
def test_gui_starts_only_after_fresh_create_journal_boot_and_bootstatus(
    tmp_path, hosted, monkeypatch, selector
):
    commands, sdk_calls, gui_calls, process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector=selector
    )
    prefix = create_and_boot(commands)
    assert gui_calls == []
    commands.run(prefix + ["bootstatus", DEVICE, "-b"], timeout=180)
    argv, options = gui_calls[0]
    assert argv == [
        control.PINNED_DEVELOPER_DIR + "/Applications/Simulator.app/Contents/MacOS/Simulator",
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
    ],
)
def test_non_owned_boot_never_starts_gui(tmp_path, hosted, monkeypatch, failure):
    commands, _sdk, gui_calls, _process = synthetic_commands(tmp_path / "new-work", hosted, monkeypatch)
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
    else:
        (commands.root / "simulator-set").symlink_to(tmp_path / "new-neighbor-set")
    with pytest.raises(ValueError):
        commands.run(prefix + ["bootstatus", device, "-b"])
    assert gui_calls == []


@pytest.mark.parametrize("selector", ["custom", "default"])
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
):
    commands, sdk_calls, gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector=selector
    )
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


@pytest.mark.parametrize("selector", ["custom", "default"])
@pytest.mark.parametrize("failure", ["already-journaled", "duplicate-create"])
def test_create_returned_uuid_must_be_new_to_this_invocation(
    tmp_path, hosted, monkeypatch, selector, failure
):
    commands, sdk_calls, gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector=selector
    )
    prefix, _ = transport.ios_selector(commands.root, selector, hosted)
    create = prefix + [
        "create",
        "APSA-NEW-synthetic",
        transport.IOS_PINNED_DEVICE_TYPE,
        transport.IOS_PINNED_RUNTIME,
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


def test_bootstatus_budget_change_does_not_change_any_other_command_deadline(tmp_path, hosted, monkeypatch):
    commands, sdk_calls, _gui_calls, _process = synthetic_commands(tmp_path / "new-work", hosted, monkeypatch)
    prefix = create_and_boot(commands)
    commands.run(prefix + ["bootstatus", DEVICE, "-b"], timeout=180)
    commands.run(prefix + ["openurl", DEVICE, "new-synthetic-owned-url"], timeout=15)
    assert sdk_calls[-2][1]["timeout"] == 600
    assert sdk_calls[-1][1]["timeout"] == 15
    commands.close_all_gui()


@pytest.mark.parametrize("selector", ["custom", "default"])
def test_failed_bootstatus_preserves_command_failure_and_never_starts_gui(
    tmp_path, hosted, monkeypatch, selector
):
    commands, _sdk, gui_calls, _process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, selector=selector
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
def test_gui_failure_is_redacted_and_cleanup_never_claims_unreaped_child(
    tmp_path, hosted, monkeypatch, failure
):
    process = Process(exited=3 if failure == "exited" else None, reap_failure=failure == "reap-timeout")
    commands, _sdk, _gui_calls, process = synthetic_commands(
        tmp_path / "new-work", hosted, monkeypatch, process=process
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
@pytest.mark.parametrize("selector", ["custom", "default"])
def test_wrapper_keeps_driver_contract_and_failure_separate(tmp_path, hosted, monkeypatch, failure, selector):
    root = tmp_path / "new-control"
    original_commands, original_argv = transport.Commands, sys.argv
    driver_error = ValueError("NEW synthetic driver failed")
    process = Process(reap_failure=failure == "cleanup")

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
            transport.IOS_PINNED_RUNTIME,
            "--ios-device-type",
            transport.IOS_PINNED_DEVICE_TYPE,
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
        control.run_control(root, "companion", selector)
    elif failure == "exception":
        with pytest.raises(ValueError) as caught:
            control.run_control(root, "companion", selector)
        assert caught.value is driver_error
    else:
        with pytest.raises(SystemExit) as caught:
            control.run_control(root, "companion", selector)
        assert caught.value.code == (7 if failure == "nonzero" else 1)
    result = json.loads((root / "gui-control.json").read_text())
    assert result["terminal"] is True
    assert result["ios_device_set"] == selector and result["source_version"] == 2
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
