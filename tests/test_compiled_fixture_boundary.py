"""Mocked simulator control; no installed SDK, device set or simulator is inspected."""

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
from typing import TypedDict

import pytest

from tests.support.runtime_compiled import FreshIosSimulatorAdapter, command_evidence, resolve_jdk
from tests.test_runtime_evidence import scenario

DEVICE_TYPE = "com.apple.CoreSimulator.SimDeviceType.Synthetic-iPhone"
RUNTIME = "com.apple.CoreSimulator.SimRuntime.iOS-99-0"
DEVICE = "12345678-1234-4234-8234-123456789ABC"


class SimulatorOptions(TypedDict, total=False):
    device_type: str
    runtime: str
    architecture: str


CONFIG: SimulatorOptions = {"device_type": DEVICE_TYPE, "runtime": RUNTIME, "architecture": "arm64"}


class SimulatorHarness:
    def __init__(self, monkeypatch, root):
        self.root = root
        self.calls = []
        self.errors = {}
        self.container = "owned"
        self.created_device = DEVICE
        monkeypatch.setattr("tests.support.runtime_compiled.subprocess.run", self.run)
        monkeypatch.setattr(FreshIosSimulatorAdapter, "_response", self.response)

    def response(self, expected):
        app = self.root / "InstrumentedFixture.app"
        from mobile_audit.core import digest

        return {
            **expected,
            "package": "com.synthetic.app",
            "executable_sha256": digest((app / "InstrumentedFixture").read_bytes()),
            "info_plist_sha256": digest((app / "Info.plist").read_bytes()),
        }

    def run(self, argv, *, capture_output, timeout, check):
        assert capture_output is True and check is False
        self.calls.append((list(argv), timeout))
        stdout = b"synthetic raw output /Users/operator/private\n"
        stderr = b"synthetic stderr must not be journaled\n"
        if argv[:2] == ["/usr/bin/xcrun", "simctl"]:
            assert argv[2:4] == ["--set", str(self.root / "device-set")]
            action = argv[4]
            if action in self.errors:
                error = self.errors[action]
                if error == "timeout":
                    raise subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr)
                raise error
            if action == "create":
                assert argv[-2:] == [DEVICE_TYPE, RUNTIME]
                stdout = self.created_device.encode()
            else:
                assert argv[5] == DEVICE
                assert action in {
                    "boot",
                    "bootstatus",
                    "install",
                    "get_app_container",
                    "launch",
                    "shutdown",
                    "delete",
                }
                if action == "get_app_container":
                    container_type = argv[-1]
                    owned = self.root / "device-set" / DEVICE
                    if self.container == "outside":
                        directory = self.root / "unowned" / container_type
                    elif self.container == "wrong-device":
                        directory = (
                            self.root / "device-set" / "87654321-4321-4321-8321-123456789ABC" / container_type
                        )
                    elif self.container == "sibling-prefix":
                        directory = self.root / "device-set" / (DEVICE + "-unowned") / container_type
                    else:
                        directory = owned / container_type
                        directory.mkdir(parents=True, exist_ok=True)
                        if self.container == "symlink":
                            directory.rmdir()
                            outside = self.root / "unowned" / container_type
                            outside.mkdir(parents=True, exist_ok=True)
                            directory.symlink_to(outside, target_is_directory=True)
                        if container_type == "app":
                            for name in ("InstrumentedFixture", "Info.plist"):
                                shutil.copyfile(
                                    self.root / "InstrumentedFixture.app" / name, directory / name
                                )
                    stdout = str(directory).encode()
        elif "--show-sdk-path" in argv:
            stdout = b"/synthetic/SDK-only"
        elif "swiftc" in argv and "-o" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"new mock simulator executable")
            assert argv[argv.index("-target") + 1] == "arm64-apple-ios18.0-simulator"
        else:
            assert "swiftc" in argv or argv[0] == "/usr/bin/codesign"
        return subprocess.CompletedProcess(argv, 0, stdout, stderr)


@pytest.mark.parametrize("missing", ["device_type", "runtime", "architecture"])
def test_missing_simulator_configuration_fails_before_any_sdk_call(tmp_path, monkeypatch, missing):
    def unavailable(*args, **kwargs):
        pytest.fail("Missing explicit configuration must not invoke SDK/device commands")

    monkeypatch.setattr("tests.support.runtime_compiled.subprocess.run", unavailable)
    config = CONFIG.copy()
    del config[missing]
    root = tmp_path / "new-owned"
    with pytest.raises(ValueError, match="explicit device type"):
        FreshIosSimulatorAdapter(scenario("ios"), root, **config)
    assert not root.exists()


@pytest.mark.parametrize(
    "field,value",
    [
        ("device_type", "booted"),
        ("runtime", "latest"),
        ("architecture", "host"),
    ],
)
def test_unknown_simulator_selection_is_rejected_before_sdk(tmp_path, monkeypatch, field, value):
    config = {**CONFIG, field: value}
    monkeypatch.setattr(
        "tests.support.runtime_compiled.subprocess.run", lambda *a, **k: pytest.fail("SDK command")
    )
    with pytest.raises(ValueError, match="explicit device type"):
        FreshIosSimulatorAdapter(scenario("ios"), tmp_path / "new-owned", **config)


def test_every_mocked_simulator_command_routes_to_exact_custom_set(tmp_path, monkeypatch):
    root = tmp_path / "new-owned"
    harness = SimulatorHarness(monkeypatch, root)
    adapter = FreshIosSimulatorAdapter(scenario("ios"), root, **CONFIG)
    assert adapter.manifest["installed"] and adapter.device == DEVICE
    cleanup = adapter.close()
    assert cleanup["state"] == "completed"
    assert cleanup["scope"] == "fresh-owned-simulator-only"
    assert adapter.device is None
    simulator_calls = [(argv, timeout) for argv, timeout in harness.calls if "simctl" in argv]
    assert [argv[4] for argv, _ in simulator_calls] == [
        "create",
        "boot",
        "bootstatus",
        "install",
        "get_app_container",
        "get_app_container",
        "launch",
        "shutdown",
        "delete",
    ]
    assert simulator_calls[-2:][0][1] == simulator_calls[-1][1] == 15
    for argv, _ in simulator_calls:
        assert argv[2:4] == ["--set", str(root / "device-set")]
        assert "list" not in argv and "booted" not in argv and "all" not in argv
    count = len(harness.calls)
    assert adapter.close()["state"] == "completed"
    assert len(harness.calls) == count
    encoded = (root / "commands.json").read_text()
    assert "synthetic raw output" not in encoded and "synthetic stderr" not in encoded
    assert str(root) not in encoded and "/Users/operator" not in encoded
    assert all(
        set(record)
        == {"argv_sha256", "status", "stdout_sha256", "stdout_bytes", "stderr_sha256", "stderr_bytes"}
        for record in json.loads(encoded)
    )


@pytest.mark.parametrize("container", ["outside", "wrong-device", "sibling-prefix", "symlink"])
def test_installed_container_must_resolve_inside_exact_new_device(tmp_path, monkeypatch, container):
    root = tmp_path / "new-owned"
    harness = SimulatorHarness(monkeypatch, root)
    harness.container = container
    with pytest.raises(ValueError, match="container identity differs"):
        FreshIosSimulatorAdapter(scenario("ios"), root, **CONFIG)
    assert [argv[4] for argv, _ in harness.calls if "simctl" in argv][-2:] == ["shutdown", "delete"]
    assert json.loads((root / "manifest.json").read_text())["capture_state"] == "inconclusive"


def test_shutdown_timeout_still_deletes_owned_simulator_and_reports_inconclusive(tmp_path, monkeypatch):
    root = tmp_path / "new-owned"
    harness = SimulatorHarness(monkeypatch, root)
    adapter = FreshIosSimulatorAdapter(scenario("ios"), root, **CONFIG)
    harness.errors["shutdown"] = "timeout"
    cleanup = adapter.close()
    assert cleanup["state"] == "inconclusive"
    assert cleanup["operations"] == [
        {"operation": "shutdown", "state": "inconclusive", "error_type": "TimeoutExpired"},
        {"operation": "delete", "state": "completed"},
    ]
    assert adapter.device is None
    assert harness.calls[-2:][0][1] == harness.calls[-1][1] == 15
    assert harness.calls[-1][0][-2:] == ["delete", DEVICE]
    encoded = json.dumps(cleanup)
    assert '"status": "timeout"' in encoded
    assert "synthetic raw output" not in encoded and "/Users/operator" not in encoded
    assert adapter.close()["state"] == "inconclusive"


def test_original_constructor_failure_survives_cleanup_failure(tmp_path, monkeypatch):
    root = tmp_path / "new-owned"
    harness = SimulatorHarness(monkeypatch, root)
    original = OSError("new synthetic boot failure")
    harness.errors.update(boot=original, shutdown="timeout", delete="timeout")
    with pytest.raises(OSError) as raised:
        FreshIosSimulatorAdapter(scenario("ios"), root, **CONFIG)
    assert raised.value is original
    assert [argv[4] for argv, _ in harness.calls if "simctl" in argv] == [
        "create",
        "boot",
        "shutdown",
        "delete",
    ]
    cleanup = json.loads((root / "cleanup.json").read_text())
    assert cleanup["state"] == "inconclusive"
    assert all(item["state"] == "inconclusive" for item in cleanup["operations"])
    assert json.loads((root / "manifest.json").read_text())["cleanup_state"] == "inconclusive"


def test_unknown_created_device_identity_never_triggers_global_cleanup(tmp_path, monkeypatch):
    root = tmp_path / "new-owned"
    harness = SimulatorHarness(monkeypatch, root)
    harness.created_device = "not-a-device-uuid"
    with pytest.raises(ValueError):
        FreshIosSimulatorAdapter(scenario("ios"), root, **CONFIG)
    assert [argv[4] for argv, _ in harness.calls if "simctl" in argv] == ["create"]
    cleanup = json.loads((root / "cleanup.json").read_text())
    assert cleanup["state"] == "inconclusive" and cleanup["identity"] == "unavailable"
    assert cleanup["operations"] == []


def test_owned_set_cannot_be_overridden(tmp_path, monkeypatch):
    root = tmp_path / "new-owned"
    harness = SimulatorHarness(monkeypatch, root)
    adapter = FreshIosSimulatorAdapter(scenario("ios"), root, **CONFIG)
    count = len(harness.calls)
    with pytest.raises(ValueError, match="override the owned device set"):
        adapter._command(["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "other"), "shutdown", DEVICE])
    assert len(harness.calls) == count
    adapter.close()


def test_command_journal_contains_only_digest_status_and_lengths():
    argv = ["/Users/synthetic/operator/java", "private-synthetic-token"]
    result = subprocess.CompletedProcess(argv, 7, b"new synthetic stdout", b"new synthetic stderr")
    evidence = command_evidence(argv, result)
    assert evidence["status"] == 7 and evidence["stdout_bytes"] == 20
    encoded = json.dumps(evidence)
    assert "/Users" not in encoded and "private-synthetic-token" not in encoded
    assert "synthetic stdout" not in encoded and "synthetic stderr" not in encoded
    assert all(len(value) == 64 for key, value in evidence.items() if key.endswith("sha256"))


def load_driver():
    path = Path(__file__).parent / "fixtures/runtime/acquire_compiled.py"
    spec = importlib.util.spec_from_file_location("new_acquisition_fixture_driver", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_driver_requires_all_explicit_simulator_flags_before_creating_output(tmp_path, monkeypatch):
    driver = load_driver()
    monkeypatch.setattr(driver, "execute", lambda *a, **k: pytest.fail("No fixture commands expected"))
    root = tmp_path / "new-output"
    with pytest.raises(SystemExit) as raised:
        driver.main(["--out", str(root), "--simulator"])
    assert raised.value.code == 2 and not root.exists()


def test_driver_forwards_explicit_simulator_configuration(tmp_path, monkeypatch):
    driver = load_driver()
    calls = []

    def execute(root, platform, kind, simulator, **kwargs):
        calls.append((root, platform, kind, simulator, kwargs))
        return {"state": "mocked"}

    monkeypatch.setattr(driver, "execute", execute)
    driver.main(
        [
            "--out",
            str(tmp_path / "new-output"),
            "--simulator",
            "--simulator-device-type",
            DEVICE_TYPE,
            "--simulator-runtime",
            RUNTIME,
            "--simulator-architecture",
            "arm64",
        ]
    )
    assert len(calls) == 3
    assert all(
        platform == "ios" and simulator and kwargs == {**CONFIG, "jdk": None}
        for _, platform, _, simulator, kwargs in calls
    )


def test_execute_passes_explicit_selection_to_adapter_constructor(tmp_path, monkeypatch):
    driver = load_driver()
    calls = []
    stop = ValueError("new mocked constructor stop")

    def create(value, root, **kwargs):
        calls.append((value, root, kwargs))
        raise stop

    monkeypatch.setattr(driver, "FreshIosSimulatorAdapter", create)
    with pytest.raises(ValueError) as raised:
        driver.execute(tmp_path / "new-output", "ios", "logout", True, **CONFIG)
    assert raised.value is stop
    assert calls[0][2] == CONFIG


def test_explicit_jdk_configuration_does_not_search_home_or_path(tmp_path, monkeypatch):
    home = tmp_path / "new-jdk-home"
    binaries = home / "bin"
    binaries.mkdir(parents=True)
    for name in ("java", "javac"):
        (binaries / name).write_text("new synthetic executable placeholder")
    monkeypatch.setenv("APSA_TEST_JAVA_HOME", str(home))
    monkeypatch.setattr(
        "tests.support.runtime_compiled.shutil.which", lambda *a: pytest.fail("No PATH search needed")
    )
    assert resolve_jdk() == binaries
