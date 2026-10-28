from __future__ import annotations

import asyncio
import hashlib
import json
import plistlib
import subprocess
import sys
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from scripts import acquire_benchmark_dependencies as acquisition
from scripts import ios_xctest_dispatch as dispatch
from scripts import served_mcp_manifest as served
from scripts import synthetic_artifact_oracles as oracle
from scripts import validate_bundletool as bundletool
from scripts import validate_runtime_gui_control as gui
from scripts import validate_source_context as context

DEVICE = "11111111-2222-4333-8444-555555555555"
PACKAGE = "apsa.fixture.c" + "1" * 32 + ".case0"
SCHEME = "a" + "2" * 32
URI = SCHEME + "://fixture?action=capture&session=" + "3" * 64


def test_served_manifest_contains_only_portable_evidence_not_app_state(tmp_path, monkeypatch):
    import mcp
    from mcp.client import stdio

    from mobile_audit.mcp_server import manifest_sha256

    root = tmp_path / "evidence"
    root.mkdir()
    contract = tmp_path / "contract.json"
    contract.write_text(
        json.dumps({name: {"sha256": manifest_sha256([])} for name in ("default", "runtime")})
    )
    homes = []

    @asynccontextmanager
    async def client(parameters):
        args = parameters.args
        home = Path(args[args.index("--home") + 1])
        home.mkdir()
        (home / "mutable-state.db").write_text("NEW synthetic state")
        homes.append(home)
        yield (None, None)

    class Result:
        tools = []

        def model_dump_json(self, **kwargs):
            return '{"tools": []}'

    class Session:
        def __init__(self, *args):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def initialize(self):
            return Result()

        async def list_tools(self):
            return Result()

    monkeypatch.setattr(mcp, "ClientSession", Session)
    monkeypatch.setattr(stdio, "stdio_client", client)
    observed = asyncio.run(served.capture(root, contract))
    assert {path.name for path in root.iterdir()} == {
        "default-initialize.json",
        "default-tools-list.json",
        "runtime-initialize.json",
        "runtime-tools-list.json",
        "served-observation.json",
    }
    assert all(not home.is_relative_to(root) and not home.exists() for home in homes)
    serialized = json.dumps(observed)
    assert str(tmp_path) not in serialized and sys.executable not in serialized
    for name in ("default", "runtime"):
        row = observed[name]
        assert (
            row["argv_sha256"]
            == hashlib.sha256(json.dumps(row["argv"], separators=(",", ":")).encode()).hexdigest()
        )
        assert row["argv"][0] == "<python>"


class DispatchCommands:
    def __init__(self, root):
        self.root = root
        self.env = {}
        self.last_status = None
        self.resources = SimpleNamespace(value={"ios": {DEVICE: {"deleted": False, "selector": "default"}}})
        self.failure = "status"
        self.calls = []

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if "build-for-testing" in argv:
            products = Path(argv[argv.index("-derivedDataPath") + 1]) / "Build/Products"
            products.mkdir(parents=True)
            (products / "synthetic.xctestrun").write_bytes(
                plistlib.dumps(
                    {
                        "CallbackTests": {
                            "TestBundlePath": "__TESTROOT__/Test.xctest",
                            "TestHostPath": "__TESTROOT__/Host.app",
                        }
                    }
                )
            )
            self.last_status = 0
        elif self.failure == "exception":
            raise ValueError("NEW synthetic command failure")
        else:
            self.last_status = 65
        return b""


@pytest.mark.parametrize("failure", ["status", "exception"])
def test_failed_dispatch_persists_unconfirmed_observation(tmp_path, monkeypatch, failure):
    monkeypatch.setattr(dispatch.control.transport, "ios_default_set", lambda env: tmp_path / "set")
    commands = DispatchCommands(tmp_path)
    commands.failure = failure
    driver = dispatch.IosXCTestDispatcher(tmp_path / "fresh-helper", commands, DEVICE, PACKAGE, SCHEME)
    with pytest.raises(ValueError):
        driver.dispatch(URI)
    observed = json.loads((driver.root / "dispatch-diagnostics.json").read_text())
    assert observed["dispatches"][-1]["xctest_exit_success"] is False
    assert observed["dispatches"][-1]["phase"] == "os-open-requested"
    assert URI not in json.dumps(observed)


@pytest.mark.parametrize("shared", [False, True])
def test_dispatch_generation_requires_new_strict_subdirectory(tmp_path, monkeypatch, shared):
    monkeypatch.setattr(dispatch.control.transport, "ios_default_set", lambda env: tmp_path / "set")
    commands = DispatchCommands(tmp_path)
    root = tmp_path if shared else tmp_path / "existing"
    root.mkdir(exist_ok=True)
    retained = root / "retained.json"
    retained.write_text("NEW unrelated case evidence")
    with pytest.raises(ValueError, match="ownership"):
        dispatch.IosXCTestDispatcher(root, commands, DEVICE, PACKAGE, SCHEME)
    assert retained.read_text() == "NEW unrelated case evidence" and not commands.calls


@pytest.mark.parametrize("kill_wait_fails", [False, True])
def test_gui_cleanup_escalates_only_the_owned_popen_after_terminate_timeout(kill_wait_fails):
    calls = []

    class Process:
        def poll(self):
            return None

        def terminate(self):
            calls.append("terminate")

        def kill(self):
            calls.append("kill")

        def wait(self, timeout):
            calls.append("wait")
            if calls.count("wait") == 1 or kill_wait_fails:
                raise subprocess.TimeoutExpired("synthetic-owned-child", timeout)
            return -9

    driver = object.__new__(gui.GuiCommands)
    # A deterministic double of the owned Popen lifecycle methods used below.
    driver.gui = {DEVICE: cast(subprocess.Popen[bytes], Process())}
    driver.selector = "custom"
    driver.gui_cleanup = {}
    driver._record = lambda *args, **kwargs: None
    result = driver.close_gui(DEVICE)
    assert calls == ["terminate", "wait", "kill", "wait"]
    assert result["escalated"] is True
    assert result["reaped"] is not kill_wait_fails
    assert result["state"] == ("unconfirmed" if kill_wait_fails else "confirmed")


class Pipe:
    def __init__(self, fd):
        self.fd = fd

    def fileno(self):
        return self.fd

    def close(self):
        pass


def capture_double(module, monkeypatch, stdout=b"complete", *, exited=True):
    calls = []
    chunks = {
        10: [stdout[index : index + 65536] for index in range(0, len(stdout), 65536)] + [b""],
        11: [b""],
    }

    class Process:
        pid = 77
        returncode = None
        stdout = Pipe(10)
        stderr = Pipe(11)
        reaped = False

        def wait(self, *args, **kwargs):
            calls.append("wait")
            self.reaped = True
            self.returncode = 0 if exited else -9
            return self.returncode

    process = Process()

    class Selector:
        def __init__(self):
            self.rows = {}

        def register(self, fileobj, events, data):
            self.rows[fileobj.fd] = SimpleNamespace(fd=fileobj.fd, fileobj=fileobj, data=data)

        def get_map(self):
            return self.rows

        def select(self, timeout):
            return [(key, None) for key in list(self.rows.values())]

        def unregister(self, fileobj):
            del self.rows[fileobj.fd]

        def close(self):
            pass

    def signal_group(pid, sig):
        assert pid == process.pid and not process.reaped, (
            "group signaling after reaping can target a reused PID"
        )
        calls.append("killpg")

    monkeypatch.setattr(module.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(module.selectors, "DefaultSelector", Selector, raising=False)
    monkeypatch.setattr(module.os, "read", lambda fd, size: chunks[fd].pop(0))
    monkeypatch.setattr(module.os, "killpg", signal_group)
    monkeypatch.setattr(module, "_wait_unreaped", lambda *args: exited, raising=False)
    return process, calls


@pytest.mark.parametrize("module", [oracle, bundletool])
def test_capture_signals_owned_group_before_reaping(module, tmp_path, monkeypatch):
    _, calls = capture_double(module, monkeypatch)
    if module is oracle:
        result = module.capture(["synthetic-tool"], tmp_path)
        assert result["returncode"] == 0 and not result["timed_out"]
    else:
        assert module.Commands(tmp_path).run(["synthetic-tool"]) == "complete"
    assert calls == ["killpg", "wait"]


@pytest.mark.parametrize("module", [oracle, bundletool, context])
@pytest.mark.parametrize("exited", [False, True])
def test_denied_group_signal_is_only_tolerated_after_observed_unreaped_exit(
    module, exited, tmp_path, monkeypatch
):
    process, calls = capture_double(module, monkeypatch, exited=exited)

    def denied(pid, sig):
        assert pid == process.pid and not process.reaped
        calls.append("denied-killpg")
        raise PermissionError("NEW synthetic Darwin zombie-group denial")

    monkeypatch.setattr(module.os, "killpg", denied)

    def invoke():
        if module is oracle:
            return module.capture(["synthetic-tool"], tmp_path)
        if module is context:
            return module.run(["synthetic-compiler"])
        commands = module.Commands(tmp_path)
        assert commands.run(["synthetic-tool"]) == "complete"
        return commands.records[-1]

    if not exited:
        with pytest.raises(PermissionError):
            invoke()
        assert calls == ["denied-killpg"]
    else:
        result = invoke()
        assert result["process_group_cleanup"] == "unconfirmed"
        assert calls == ["denied-killpg", "wait"]


@pytest.mark.parametrize("temp_base", [None, "/tmp"])
def test_oracle_cleanup_diagnostic_preserves_strict_observation_schema(monkeypatch, temp_base):
    # Fresh inert files satisfy identity checks; no signing tool is executed.
    from mobile_audit.artifact_oracle import record_digest

    with tempfile.TemporaryDirectory(prefix="apsa-new-oracle-", dir=temp_base) as temporary:
        root = Path(temporary).resolve()
        artifact, source, tool, record = (
            root / name for name in ("new.apk", "New.java", "apksigner", "result.json")
        )
        artifact.write_bytes(b"NEW inert artifact")
        source.write_text("class New {}")
        tool.write_text("NEW inert tool identity")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "synthetic-oracle",
                "--new-root",
                str(root),
                "--artifact",
                str(artifact),
                "--source",
                str(source),
                "--compiler",
                str(tool),
                "--oracle",
                "apksigner_signature",
                "--tool",
                str(tool),
                "--record",
                str(record),
            ],
        )

        def capture(argv, cwd, **kwargs):
            return {
                "argv": argv,
                "environment": {"PATH": "/usr/bin:/bin", "TMPDIR": str(cwd)},
                "returncode": 0,
                "timed_out": False,
                "output_truncated": False,
                "process_group_cleanup": "unconfirmed",
                "stdout_base64": "",
                "stderr_base64": "",
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
            }

        monkeypatch.setattr(oracle, "capture", capture)
        oracle.main()
        value = json.loads(record.read_text())
        assert value["capture_diagnostics"] == {"process_group_cleanup": "unconfirmed"}
        assert "process_group_cleanup" not in value["observation"]
        assert value["observation"]["record_sha256"] == record_digest(value["observation"])
        assert value["summary"]["state"] == "reported-pass"


@pytest.mark.parametrize("root_kind", ["default-temp", "portable-temp", "outside", "file"])
def test_oracle_rejects_nonfixture_roots_before_reading_inputs(tmp_path, monkeypatch, root_kind):
    fresh_file = tmp_path / "NEW-not-a-directory"
    fresh_file.write_text("NEW synthetic fixture only")
    root = {
        "default-temp": Path(tempfile.gettempdir()).resolve(),
        "portable-temp": Path("/tmp").resolve(),
        "outside": Path("/"),
        "file": fresh_file,
    }[root_kind]
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "synthetic-oracle",
            "--new-root",
            str(root),
            "--artifact",
            str(tmp_path / "NEW.apk"),
            "--source",
            str(tmp_path / "NEW.java"),
            "--compiler",
            str(tmp_path / "NEW-compiler"),
            "--oracle",
            "apksigner_signature",
            "--tool",
            str(tmp_path / "NEW-tool"),
            "--record",
            str(tmp_path / "NEW-result.json"),
        ],
    )

    def forbidden(*args, **kwargs):
        pytest.fail("Rejected roots must not read fixture contents or invoke a tool")

    monkeypatch.setattr(oracle, "sha", forbidden)
    monkeypatch.setattr(oracle, "capture", forbidden)
    with pytest.raises(ValueError, match="explicitly created subdirectory of a system temp directory"):
        oracle.main()
    assert not (tmp_path / "NEW-result.json").exists()


@pytest.mark.parametrize("mode", ["timeout", "invalid-utf8", "oversized", "complete"])
def test_compiler_capture_is_bounded_and_preserves_failure_diagnostics(monkeypatch, mode):
    # Legacy subprocess.run is a concrete operational failure/oversize control;
    # repaired byte capture uses only the synthetic Popen/selector doubles.
    output = (
        b"\xff"
        if mode == "invalid-utf8"
        else b"x" * (1024 * 1024 + 65536)
        if mode == "oversized"
        else b"complete"
    )

    def legacy(*args, **kwargs):
        if mode == "timeout":
            raise subprocess.TimeoutExpired(args[0], 180, output=b"partial")
        return SimpleNamespace(returncode=0, stdout=output.decode("utf-8"), stderr="")

    monkeypatch.setattr(context.subprocess, "run", legacy)
    # Baseline did not import selectors/signal/time; install only harmless
    # interface modules so its actual subprocess.run failure remains observable.
    import selectors

    monkeypatch.setattr(context, "selectors", selectors, raising=False)
    capture_double(context, monkeypatch, output, exited=mode != "timeout")
    result = context.run(["synthetic-compiler"])
    assert len(result["stdout"].encode()) <= 1024 * 1024 + 3
    if mode == "timeout":
        assert result["exit_code"] is None and result["timed_out"] is True
    elif mode == "invalid-utf8":
        assert result["output_decode_error"] is True and "\ufffd" in result["stdout"]
    elif mode == "oversized":
        assert result["output_truncated"] is True
    else:
        assert result["exit_code"] == 0 and result["stdout"] == "complete"


@pytest.mark.parametrize("fault", ["outside", "reused", "runner-temp", "metadata", "mkdir"])
def test_acquisition_setup_failure_always_emits_fixed_marker(tmp_path, monkeypatch, capsys, fault):
    runner = tmp_path / "runner"
    runner.mkdir()
    work = runner / "new-work"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setenv("RUNNER_TEMP", str(runner))
    for key, value in {
        "GITHUB_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123",
        "GITHUB_REPOSITORY": "synthetic/project",
    }.items():
        monkeypatch.setenv(key, value)
    if fault == "outside":
        work = tmp_path / "outside"
    elif fault == "reused":
        work.mkdir()
        (work / "acquisition.json").write_text("NEW retained evidence")
    elif fault == "runner-temp":
        monkeypatch.delenv("RUNNER_TEMP")
    elif fault == "metadata":
        monkeypatch.delenv("GITHUB_SHA")
    else:
        original = Path.mkdir

        def denied(path, *args, **kwargs):
            if path == work:
                raise PermissionError("NEW synthetic permission failure")
            return original(path, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", denied)
    monkeypatch.setattr(sys, "argv", ["synthetic-acquisition", "--work", str(work)])
    monkeypatch.setattr(
        acquisition.urllib.request, "build_opener", lambda *args: pytest.fail("no network for setup failure")
    )
    assert acquisition.main() == 1
    output = capsys.readouterr().out
    assert output.startswith(acquisition.MARKER)
    observed = json.loads(output.removeprefix(acquisition.MARKER))
    assert observed["status"] == "failed" and observed["reason"]
    if fault == "reused":
        assert (work / "acquisition.json").read_text() == "NEW retained evidence"
    elif fault == "metadata":
        assert json.loads((work / "acquisition.json").read_text())["status"] == "failed"


@pytest.mark.parametrize("module", [oracle, bundletool, context])
@pytest.mark.parametrize("backend", ["waitid", "darwin-status"])
def test_exit_observer_keeps_owned_child_unreaped(module, backend, monkeypatch):
    calls = []
    process = SimpleNamespace(pid=77)
    if backend == "waitid":

        def waitid(kind, pid, flags):
            assert kind == module.os.P_PID and pid == process.pid
            assert flags & module.os.WNOWAIT
            calls.append("nonreaping-waitid")
            return SimpleNamespace(si_pid=pid)

        monkeypatch.setattr(module.os, "waitid", waitid, raising=False)
    else:
        monkeypatch.delattr(module.os, "waitid", raising=False)

        def owned(pid):
            assert pid == process.pid
            calls.append("owned-status")
            return SimpleNamespace(status=lambda: "zombie")

        monkeypatch.setitem(
            sys.modules,
            "psutil",
            SimpleNamespace(Process=owned, STATUS_ZOMBIE="zombie", NoSuchProcess=ChildProcessError),
        )
    assert module._wait_unreaped(process, 100) is True
    assert len(calls) == 1


@pytest.mark.parametrize("module", [oracle, bundletool])
def test_lost_child_custody_never_signals_a_reused_group(module, tmp_path, monkeypatch):
    _, calls = capture_double(module, monkeypatch)

    def lost(*args):
        raise ChildProcessError("NEW synthetic already-reaped child")

    monkeypatch.setattr(module, "_wait_unreaped", lost, raising=False)
    with pytest.raises(ChildProcessError):
        if module is oracle:
            module.capture(["synthetic-tool"], tmp_path)
        else:
            module.Commands(tmp_path).run(["synthetic-tool"])
    assert calls == ["wait"]


@pytest.mark.parametrize(
    "flag", [None, "output_truncated", "output_decode_error", "child_custody_lost", "timed_out"]
)
def test_compiler_report_never_scores_incomplete_capture_as_pass(tmp_path, monkeypatch, flag):
    source = tmp_path / "New.swift"
    source.write_text("func fresh() {}")
    out = tmp_path / "fresh-evidence"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "synthetic-source-context",
            "--language",
            "swift",
            "--sdk",
            str(tmp_path / "unused-sdk"),
            "--out",
            str(out),
        ],
    )
    monkeypatch.setattr(context, "inputs", lambda *args: [("swift-url-fixed", source, "a" * 64)])
    monkeypatch.setattr(context, "swift_extension_type_probes", lambda: {})
    monkeypatch.setattr(
        context,
        "run",
        lambda argv: {
            "argv": argv,
            "exit_code": 0,
            "stdout": "bounded",
            "stderr": "",
            **({flag: True} if flag else {}),
        },
    )
    if flag:
        with pytest.raises(SystemExit) as caught:
            context.main()
        assert caught.value.code == 1
    else:
        context.main()
    assert json.loads((out / "result.json").read_text())["passed"] is (flag is None)
