"""New in-memory synthetic protocol tests. No sockets, devices or user files."""

import io
import json
import plistlib
import subprocess
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlparse

import pytest

from mobile_audit.core import digest
from mobile_audit.runtime_acquisition import AcquisitionRecorder, evaluate_backend_invalidation
from mobile_audit.runtime_evidence import build_binding, evaluate_workflow, validate_workflow
from mobile_audit.runtime_transport import AuthorityServer, InstalledTransportAdapter, OwnedAuthority
from scripts.validate_runtime_transport import (
    CommandFailure,
    Commands,
    FixtureFailure,
    IosTarget,
    OwnedResources,
    cleanup_owned,
    failure_observation,
    ios_delivery_complete,
    main,
    scenario,
)


class Response(io.BytesIO):
    def __init__(self, raw, status):
        super().__init__(raw)
        self.status = status


def server_without_socket(authority, monkeypatch, *, alter=None):
    server = AuthorityServer.__new__(AuthorityServer)
    server.authority = authority
    server.port = 31591
    server.endpoint = "http://127.0.0.1:31591"

    class Opener:
        def open(self, request, timeout):
            status, raw = authority.handle(
                urlparse(request.full_url).path, request.get_header("Authorization", ""), request.data
            )
            if alter:
                status, raw = alter(status, raw)
            if status >= 400:
                raise HTTPError(request.full_url, status, "synthetic", Message(), io.BytesIO(raw))
            return Response(raw, status)

    monkeypatch.setattr("mobile_audit.runtime_transport.build_opener", lambda *_args: Opener())
    return server


class NewMemoryTarget:
    """Tests only: cannot establish installed acquisition or HTTP evidence."""

    def __init__(self, platform, authority):
        self.platform, self.package, self.authority = platform, authority.package, authority
        key = "apk_sha256" if platform == "android" else "executable_sha256"
        self.build = {key: authority.build}
        if platform == "ios":
            self.build["info_plist_sha256"] = "2" * 64
        self.after = False
        self.retained = False
        self.credential = ""
        self.change = None

    def installed_build(self):
        return self.build.copy()

    def deliver(self, url, expected):
        fields = {
            key: value[0] for key, value in parse_qs(urlparse(url).query, keep_blank_values=True).items()
        }
        action = fields["action"]
        body = json.dumps(
            {"session": fields["session"], "package": self.package, "build": self.authority.build}
        ).encode()
        if action == "session":
            self.retained = fields["retain"] == "true"
            status, raw = self.authority.handle("/issue", "", body)
            assert status == 200
            self.credential = json.loads(raw)["credential"]
        elif action == "transition":
            assert self.authority.handle("/logout", "Bearer " + self.credential, body)[0] == 200
            self.after = True
        response = {
            **fields,
            **self.build,
            "package": self.package,
            "delivery_transport": "android-os-intent" if self.platform == "android" else "ios-os-url-context",
            "account": "" if self.after else "a",
            "state": "logged_out" if self.after else "authenticated",
            "delivery": "target-observed" if self.after else "baseline",
            "fresh_store": True,
            "completeness": "complete",
            "storage": (
                "synthetic-unique-state synthetic-unique-delivery"
                + (" synthetic-unique-a" if self.retained else "")
            )
            if self.after
            else "synthetic-unique-a synthetic-unique-login_a",
        }
        if self.change:
            response[self.change] = "mismatch"
        return response


@pytest.mark.parametrize("platform", ["android", "ios"])
@pytest.mark.parametrize("invalidate,retain", [(True, False), (True, True), (False, False), (False, True)])
def test_independent_backend_replay_not_local_store(platform, invalidate, retain, monkeypatch):
    authority = OwnedAuthority("apsa.fixture.new", "1" * 64, invalidate=invalidate)
    target = NewMemoryTarget(platform, authority)
    server = server_without_socket(authority, monkeypatch)
    adapter = InstalledTransportAdapter(target, server, retain=retain)
    value = scenario(platform, target.package)
    validate_workflow(value, {"before": 0, "after": 2})
    recorder = AcquisitionRecorder(
        adapter, build_binding(platform, target.package, target.build), value["markers"]
    )
    before = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    adapter.open_url("synthetic://transition")
    after = recorder.capture("after", {"account": None, "state": "logged_out"}, "logout")
    snapshots = {"before": before, "after": after}
    assert evaluate_backend_invalidation(value, snapshots)[0]["state"] == (
        "passed" if invalidate else "failed"
    )
    assert evaluate_workflow(value, snapshots, recorder.binding)[0]["state"] == "passed"
    assert any(m["marker_label"] == "a" for m in after["matches"]) is retain
    assert before["backend_probe"]["credential_sha256"] == after["backend_probe"]["credential_sha256"]
    assert before["backend_probe"]["authority_sha256"] == after["backend_probe"]["authority_sha256"]
    assert before["backend_probe"]["request_sha256"] != after["backend_probe"]["request_sha256"]
    assert [event["route"] for event in authority.events] == ["/issue", "/protected", "/logout", "/protected"]
    assert after["surfaces"]["logs"]["completeness"] == "unsupported"
    assert after["surfaces"]["ui"]["completeness"] == "unsupported"
    persisted = json.dumps({"snapshots": snapshots, "events": authority.events})
    assert authority.credential not in persisted
    assert authority.session not in persisted
    assert all(marker not in persisted for marker in value["markers"].values())


@pytest.mark.parametrize(
    "field",
    [
        "package",
        "session",
        "apk_sha256",
        "nonce",
        "snapshot",
        "account",
        "state",
        "transition",
        "delivery",
        "delivery_transport",
        "completeness",
    ],
)
def test_forged_capture_response_fails_closed(field, monkeypatch):
    authority = OwnedAuthority("apsa.fixture.new", "1" * 64, invalidate=True)
    target = NewMemoryTarget("android", authority)
    adapter = InstalledTransportAdapter(target, server_without_socket(authority, monkeypatch), retain=False)
    recorder = AcquisitionRecorder(
        adapter,
        build_binding("android", target.package, target.build),
        scenario("android", target.package)["markers"],
    )
    target.change = field
    capture = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    assert capture["files"] == []
    assert capture["acquisition"]["capture_errors"] is True
    assert len(authority.events) == 1  # Never issue replay for a rejected app observation.


def test_installed_build_change_prevents_replay(monkeypatch):
    authority = OwnedAuthority("apsa.fixture.new", "1" * 64, invalidate=True)
    target = NewMemoryTarget("android", authority)
    adapter = InstalledTransportAdapter(target, server_without_socket(authority, monkeypatch), retain=False)
    recorder = AcquisitionRecorder(
        adapter,
        build_binding("android", target.package, target.build),
        scenario("android", target.package)["markers"],
    )
    monkeypatch.setattr(target, "installed_build", lambda: {"apk_sha256": "3" * 64})
    capture = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    assert capture["files"] == []
    assert capture["acquisition"]["capture_errors"] is True


@pytest.mark.parametrize("field", ["session", "package", "build"])
def test_authority_rejects_unbound_issue_logout_and_replay(field):
    authority = OwnedAuthority("apsa.fixture.new", "1" * 64, invalidate=True)
    authority.bind("a" * 64)
    body = {"session": authority.session, "package": authority.package, "build": authority.build}
    assert authority.handle("/issue", "", json.dumps(body).encode())[0] == 200
    body[field] = "wrong"
    body["nonce"] = "b" * 64
    for route in ("/issue", "/logout", "/protected"):
        assert authority.handle(route, "Bearer " + authority.credential, json.dumps(body).encode())[0] == 403
    assert authority.active
    assert not authority.logged_out


@pytest.mark.parametrize(
    "alter",
    [
        lambda status, raw: (status, json.dumps({"outcome": "accepted", "nonce": "bad"}).encode()),
        lambda status, raw: (401, raw),
    ],
)
def test_http_status_and_response_challenge_must_match(alter, monkeypatch):
    authority = OwnedAuthority("apsa.fixture.new", "1" * 64, invalidate=True)
    authority.bind("a" * 64)
    body = json.dumps(
        {"session": authority.session, "package": authority.package, "build": authority.build}
    ).encode()
    authority.handle("/issue", "", body)
    server = server_without_socket(authority, monkeypatch, alter=alter)
    with pytest.raises(ValueError, match="challenge/status"):
        server.replay("b" * 64)


def test_old_credential_is_not_accepted_by_new_authority():
    first = OwnedAuthority("apsa.fixture.new", digest(b"build"), invalidate=False)
    second = OwnedAuthority("apsa.fixture.new", digest(b"build"), invalidate=False)
    for authority in (first, second):
        authority.bind("a" * 64)
        authority.handle(
            "/issue",
            "",
            json.dumps(
                {"session": authority.session, "package": authority.package, "build": authority.build}
            ).encode(),
        )
    request = json.dumps(
        {"session": second.session, "package": second.package, "build": second.build, "nonce": "b" * 64}
    ).encode()
    assert second.handle("/protected", "Bearer " + first.credential, request)[0] == 403


class MemoryOutputRoot:
    """Output recorder only; no filesystem operation or subprocess is performed."""

    def __init__(self):
        self.value = ""

    def __truediv__(self, name):
        assert name == "commands.json"
        return self

    def write_text(self, value):
        self.value = value


@pytest.mark.parametrize("kind", ["nonzero", "timeout", "spawn"])
def test_command_failure_text_contains_only_metadata_and_digests(kind, monkeypatch, capsys):
    secret = "new-synthetic-credential-never-printed"
    root = MemoryOutputRoot()
    # This intentional test double records writes in memory; it never touches a path.
    commands = Commands(cast(Path, root), env={})

    def run(*args, **kwargs):
        if kind == "timeout":
            raise subprocess.TimeoutExpired(args[0], 10, output=secret.encode(), stderr=secret.encode())
        if kind == "spawn":
            raise FileNotFoundError(2, secret)
        return SimpleNamespace(returncode=1, stdout=secret.encode(), stderr=secret.encode())

    monkeypatch.setattr("scripts.validate_runtime_transport.subprocess.run", run)
    with pytest.raises(CommandFailure) as caught:
        commands.run(
            [
                "/new-public-sdk/platform-tools/adb",
                "shell",
                "am start -d 'apsatransport://fixture?session=" + secret + "'",
            ]
        )
    observation = failure_observation(caught.value, "android-avd-create-and-boot", commands.records)
    emitted = json.dumps(observation) + root.value + capsys.readouterr().out
    assert secret not in emitted
    assert "apsatransport://" not in emitted
    assert (
        observation["reason"]
        == {
            "nonzero": "command-nonzero-status",
            "timeout": "command-timeout",
            "spawn": "command-spawn-os-error",
        }[kind]
    )
    assert observation["recent_commands"][0]["operation"] == "android-os-url-delivery"
    assert "argv" not in observation["recent_commands"][0]


def test_unknown_exception_text_and_arbitrary_reason_are_withheld():
    secret = "new-synthetic-authorization-material"
    for error in (ValueError(secret), CommandFailure(secret, {})):
        observation = failure_observation(error, "initialization", [])
        assert observation["reason"] == "fixture-validation-unclassified"
        assert secret not in json.dumps(observation)


def test_emulator_exit_observation_survives_bounded_recent_command_window():
    records = [
        {"operation": "android-emulator-launch", "process_status": 3, "output": "discarded-no-raw-logs"}
    ]
    records += [{"operation": "android-boot-status", "status": 1} for _ in range(20)]
    observation = failure_observation(
        ValueError("NEW emulator exited before boot"), "android-avd-create-and-boot", records
    )
    assert observation["reason"] == "android-emulator-exited-before-boot"
    assert len(observation["recent_commands"]) == 16
    assert observation["owned_processes"][0]["process_status"] == 3


def test_cleanup_is_idempotent_and_scoped_to_journaled_new_resources(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "new-synthetic-run")
    monkeypatch.setenv("GITHUB_SHA", "1" * 40)
    journal = OwnedResources(tmp_path)
    journal.android(avd="apsa-new-" + "a" * 32, sdk="/new-public-sdk", emulator=True, adb=True)
    device = "11111111-2222-3333-4444-555555555555"
    journal.ios(device)
    owned = tmp_path / "case-0"
    owned.mkdir()
    (owned / "synthetic-token").write_text("new-only")
    evidence = tmp_path / "evidence.json"
    evidence.write_text("synthetic-evidence-preserved")
    unowned = tmp_path / "unowned-synthetic-sentinel"
    unowned.mkdir()
    commands = Commands(tmp_path, env={})
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        commands.last_status = 0
        return b""

    monkeypatch.setattr(commands, "run", run)
    assert cleanup_owned(tmp_path, commands, journal)["state"] == "confirmed"
    assert calls == [
        ["/new-public-sdk/platform-tools/adb", "-P", "5049", "-s", "emulator-5580", "emu", "kill"],
        ["/new-public-sdk/platform-tools/adb", "-P", "5049", "kill-server"],
        ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "simulator-set"), "shutdown", device],
        ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "simulator-set"), "delete", device],
    ]
    assert not owned.exists()
    assert evidence.read_text() == "synthetic-evidence-preserved"
    assert unowned.exists()
    loaded = OwnedResources(tmp_path, load=True)
    assert cleanup_owned(tmp_path, commands, loaded)["state"] == "confirmed"
    assert len(calls) == 4
    monkeypatch.setenv("GITHUB_RUN_ID", "different-run")
    with pytest.raises(ValueError, match="identity"):
        OwnedResources(tmp_path, load=True)


def test_cleanup_failure_retains_new_evidence_and_state_for_retry(tmp_path, monkeypatch):
    journal = OwnedResources(tmp_path)
    journal.android(avd="apsa-new-" + "a" * 32, sdk="/new-public-sdk", emulator=True)
    owned = tmp_path / "case-0"
    owned.mkdir()
    commands = Commands(tmp_path, env={})

    def run(*args, **kwargs):
        commands.last_status = 1
        return b""

    monkeypatch.setattr(commands, "run", run)
    assert cleanup_owned(tmp_path, commands, journal)["state"] == "unconfirmed"
    assert owned.exists()
    assert not journal.value["android"].get("emulator_closed")


@pytest.mark.parametrize(
    "stage",
    [
        "startup-app",
        "startup-scene",
        "scene-active",
        "os-url-context-received",
        "url-processing",
        "failure-url-shape",
        "failure-http-issue",
        "http-issue",
        "new-synthetic-secret",
    ],
)
def test_ios_lifecycle_diagnostics_retain_fixed_labels_only(stage, tmp_path):
    target = IosTarget.__new__(IosTarget)
    target.response = tmp_path / "new-response.json"
    target.stage_path = tmp_path / "new-stage.txt"
    target.stage_path.write_text(stage)
    result = target.lifecycle_observation()
    assert result["lifecycle_stage"] == (stage if stage != "new-synthetic-secret" else "not-observed")
    assert result["stage_sha256"] == digest(stage.encode())
    observation = failure_observation(
        FixtureFailure("NEW iOS fixture launch timed out", result), "ios-create-install", []
    )
    assert observation["reason"] == "ios-fixture-launch-deadline"
    assert "new-synthetic-secret" not in json.dumps(observation)


def test_workflow_cleanup_writes_terminal_inconclusive_after_driver_interruption(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    root = tmp_path / "new-run"
    root.mkdir()
    OwnedResources(root)
    (root / "evidence.json").write_text(json.dumps({"terminal": False, "state": "passed"}))
    preserved = root / "commands.json"
    preserved.write_text("new-command-digests-preserved")
    monkeypatch.setattr(
        "sys.argv", ["validator", "--platform", "backend", "--cleanup-only", "--work", str(root)]
    )
    main()
    evidence = json.loads((root / "evidence.json").read_text())
    assert evidence["terminal"] is True
    assert evidence["state"] == "inconclusive"
    assert evidence["failure_observation"]["reason"] == "driver-terminal-evidence-unavailable"
    assert evidence["workflow_cleanup"]["state"] == "confirmed"
    assert preserved.read_text() == "new-command-digests-preserved"


def test_unexpected_driver_error_records_terminal_failure_without_raw_text(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    root = tmp_path / "new-run"
    monkeypatch.setattr("sys.argv", ["validator", "--platform", "backend", "--work", str(root)])

    def fail():
        raise TypeError("new-synthetic-token-private-error-text")

    monkeypatch.setattr("scripts.validate_runtime_transport.execute_backend_cases", fail)
    with pytest.raises(SystemExit) as stopped:
        main()
    assert stopped.value.code == 1
    raw = (root / "evidence.json").read_text()
    evidence = json.loads(raw)
    assert evidence["terminal"] is True
    assert evidence["state"] == "inconclusive"
    assert evidence["failure_observation"]["exception_type"] == "other-validation-error"
    assert "new-synthetic-token-private-error-text" not in raw + capsys.readouterr().out


def test_generated_ios_registration_has_required_role_and_target_identifier(tmp_path, monkeypatch):
    commands = Commands(tmp_path, env={})
    package = "apsa.fixture.new.case0"
    root = tmp_path / "new-app-build"
    calls = []

    def public_build_double(argv, **kwargs):
        calls.append(argv)
        if "--show-sdk-path" in argv:
            return b"/new-public-sdk"
        if "swiftc" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"NEW synthetic executable stand-in")
        if "create" in argv:
            raise ValueError("stop-before-new-device-creation")
        return b""

    monkeypatch.setattr(commands, "run", public_build_double)
    with pytest.raises(ValueError, match="stop-before-new-device-creation"):
        IosTarget(root, package, commands, "new-runtime", "new-device-type")
    value = plistlib.loads((root / "TransportFixture.app/Info.plist").read_bytes())
    assert value["CFBundleIdentifier"] == package
    assert value["CFBundleURLTypes"] == [
        {
            "CFBundleTypeRole": "Editor",
            "CFBundleURLName": package + ".transport",
            "CFBundleURLSchemes": ["apsatransport"],
        }
    ]
    assert calls[-1][:4] == ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "simulator-set")]
    assert not any("boot" in argv or "openurl" in argv for argv in calls)


@pytest.mark.parametrize(
    "action,lifecycle,accepted",
    [
        ("session", "cold-url-context", True),
        ("session", "warm-url-context", False),
        ("capture", "warm-url-context", True),
        ("capture", "cold-url-context", False),
        ("transition", "warm-url-context", True),
        ("transition", "application-url-callback", False),
    ],
)
def test_ios_delivery_requires_observed_cold_or_warm_callback_binding(
    action, lifecycle, accepted, tmp_path, monkeypatch
):
    target = IosTarget.__new__(IosTarget)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.commands = Commands(tmp_path, env={})
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "new-set")]
    target.response = tmp_path / "new-response.json"
    target.stage_path = tmp_path / "new-stage.txt"
    target.delivery_observations = []
    expected = {"action": action, "session": "a" * 64}
    if action == "capture":
        expected["nonce"] = "b" * 64
    raw = json.dumps({**expected, "delivery_lifecycle": lifecycle}).encode()
    target.response.write_bytes(raw)
    monkeypatch.setattr(target.commands, "run", lambda *args, **kwargs: b"")
    if not accepted:
        with pytest.raises(FixtureFailure, match="URL lifecycle differs"):
            target.deliver("synthetic-url-never-opened", expected)
        assert target.delivery_observations == []
        return
    target.deliver("synthetic-url-never-opened", expected)
    observed = target.delivery_observations[0]
    assert observed["lifecycle"] == lifecycle
    assert observed["session_sha256"] == digest(expected["session"].encode())
    assert observed["capture_nonce_sha256"] == (
        digest(expected["nonce"].encode()) if action == "capture" else None
    )
    assert observed["response_sha256"] == digest(raw)
    assert "a" * 64 not in json.dumps(observed)
    assert "b" * 64 not in json.dumps(observed)


@pytest.mark.parametrize(
    "mutation",
    [None, "warm-session", "wrong-session", "wrong-capture", "missing-transition", "missing-capture-binding"],
)
def test_ios_case_requires_complete_callback_sequence_bound_to_acquisition(mutation):
    before = {"acquisition": {"session_sha256": "1" * 64, "capture_sha256": "2" * 64}}
    after = {"acquisition": {"session_sha256": "1" * 64, "capture_sha256": "3" * 64}}
    observations = [
        {
            "action": action,
            "lifecycle": lifecycle,
            "session_sha256": "1" * 64,
            "capture_nonce_sha256": nonce,
            "response_sha256": "4" * 64,
            "response_bytes": 100,
        }
        for action, lifecycle, nonce in [
            ("session", "cold-url-context", None),
            ("capture", "warm-url-context", "2" * 64),
            ("transition", "warm-url-context", None),
            ("capture", "warm-url-context", "3" * 64),
        ]
    ]
    if mutation == "warm-session":
        observations[0]["lifecycle"] = "warm-url-context"
    elif mutation == "wrong-session":
        observations[2]["session_sha256"] = "5" * 64
    elif mutation == "wrong-capture":
        observations[3]["capture_nonce_sha256"] = "6" * 64
    elif mutation == "missing-transition":
        observations.pop(2)
    elif mutation == "missing-capture-binding":
        del after["acquisition"]["capture_sha256"]
    assert ios_delivery_complete(observations, before, after) is (mutation is None)
