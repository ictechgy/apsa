"""New in-memory synthetic protocol tests. No sockets, devices or user files."""

import ctypes
import io
import json
import plistlib
import subprocess
import sys
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import cast
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlparse

import pytest
import yaml

from mobile_audit.core import digest
from mobile_audit.runtime_acquisition import AcquisitionRecorder, evaluate_backend_invalidation
from mobile_audit.runtime_evidence import build_binding, evaluate_workflow, validate_workflow
from scripts.validate_runtime_transport import (
    ANDROID_ERROR_CATEGORIES,
    ANDROID_ERROR_PHASES,
    IOS_PINNED_DEVICE_TYPE,
    IOS_PINNED_RUNTIME,
    AndroidTarget,
    CommandFailure,
    Commands,
    FixtureFailure,
    IosTarget,
    NewAndroidDevice,
    OwnedResources,
    cleanup_owned,
    execute_case,
    failure_observation,
    ios_default_set,
    ios_delivery_complete,
    ios_launch_pid,
    ios_process_identity,
    ios_url_diagnostic_projection,
    main,
    owned_ios_url,
    runtime_projection,
    safe_android_error,
    safe_ios_appinfo,
    safe_ios_dispatcher,
    safe_ios_entry,
    safe_ios_events,
    safe_ios_installed_contract,
    scenario,
)
from tests.support.runtime_transport import AuthorityServer, InstalledTransportAdapter, OwnedAuthority


def synthetic_android_error(phase="binding", category="argument"):
    return {
        "action": "fixture-error",
        "code": "binding-or-transport",
        "diagnostic": {"schema_version": 1, "phase": phase, "category": category},
        "package": "apsa.fixture.new",
        "apk_sha256": "a" * 64,
        "session": "synthetic-private-session",
        "account": "synthetic-private-account",
        "state": "authenticated",
        "delivery": "baseline",
        "delivery_transport": "android-os-intent",
    }


@pytest.mark.parametrize("phase", sorted(ANDROID_ERROR_PHASES))
@pytest.mark.parametrize("category", sorted(ANDROID_ERROR_CATEGORIES))
def test_android_error_diagnostics_project_only_fixed_phase_and_category(phase, category):
    raw = json.dumps(synthetic_android_error(phase, category)).encode()
    result = safe_android_error(raw)
    assert result == {
        "state": "diagnostic-only",
        "sha256": digest(raw),
        "bytes": len(raw),
        "schema_version": 1,
        "phase": phase,
        "category": category,
    }
    assert "synthetic-private" not in json.dumps(result)


def malformed_android_error(case):
    value = synthetic_android_error()
    diagnostic = value["diagnostic"]
    if case == "legacy":
        value.pop("diagnostic")
    elif case == "top-secret":
        value["message"] = "synthetic-private-token"
    elif case == "nested-secret":
        diagnostic["message"] = "synthetic-private-token"
    elif case == "unknown-phase":
        diagnostic["phase"] = "synthetic-private-token"
    elif case == "escaped-phase":
        diagnostic["phase"] = "binding\nsynthetic-private-token"
    elif case == "unknown-category":
        diagnostic["category"] = "java.net.synthetic-private-token"
    elif case == "category-list":
        diagnostic["category"] = ["io"]
    elif case == "phase-object":
        diagnostic["phase"] = {"binding": True}
    elif case == "schema-bool":
        diagnostic["schema_version"] = True
    elif case == "schema-string":
        diagnostic["schema_version"] = "1"
    elif case == "diagnostic-list":
        value["diagnostic"] = [diagnostic]
    elif case == "wrong-code":
        value["code"] = "synthetic-private-token"
    raw = json.dumps(value).encode()
    if case == "duplicate-phase":
        raw = raw.replace(b'"phase": "binding"', b'"phase": "io", "phase": "binding"')
    elif case == "duplicate-top":
        raw = raw.replace(b'"code":', b'"code": "synthetic-private-token", "code":', 1)
    elif case == "oversize":
        raw += b" " * 4096
    return raw


ANDROID_ERROR_BAD_CASES = [
    "legacy",
    "top-secret",
    "nested-secret",
    "unknown-phase",
    "escaped-phase",
    "unknown-category",
    "category-list",
    "phase-object",
    "schema-bool",
    "schema-string",
    "diagnostic-list",
    "wrong-code",
    "duplicate-phase",
    "duplicate-top",
    "oversize",
]


@pytest.mark.parametrize("case", ANDROID_ERROR_BAD_CASES)
def test_android_error_diagnostics_fail_unmeasured_without_echoing_untrusted_fields(case):
    raw = malformed_android_error(case)
    assert safe_android_error(raw) == {"state": "unmeasured", "sha256": digest(raw), "bytes": len(raw)}


@pytest.mark.parametrize("raw", [b"", b"[]", b"null", b'{"diagnostic":', b"\xff", b"x" * 4097])
def test_android_error_diagnostics_bound_malformed_inputs(raw):
    assert safe_android_error(raw) == {"state": "unmeasured", "sha256": digest(raw), "bytes": len(raw)}


@pytest.mark.parametrize("case", ["valid-binding", "valid-http"] + ANDROID_ERROR_BAD_CASES)
def test_android_fixture_error_always_refuses_primary_without_retry(case, tmp_path, monkeypatch):
    raw = (
        json.dumps(synthetic_android_error("binding", "argument")).encode()
        if case == "valid-binding"
        else json.dumps(synthetic_android_error("http-issue", "socket-timeout")).encode()
        if case == "valid-http"
        else malformed_android_error(case)
    )
    target = AndroidTarget.__new__(AndroidTarget)
    target.package = "apsa.fixture.new"
    target.commands = Commands(tmp_path, env={})
    target.device = NewAndroidDevice.__new__(NewAndroidDevice)
    target.device.adb_prefix = ["new-mocked-adb", "-s", "new-owned-device"]
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert len(calls) <= 2, "fixture errors must not trigger a second response read or dispatch"
        return b"" if len(calls) == 1 else raw

    monkeypatch.setattr(target.commands, "run", run)
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.time.sleep", lambda *_: pytest.fail("unexpected retry")
    )
    with pytest.raises(FixtureFailure, match="fixture rejected binding or transport") as caught:
        target.deliver("apsatransport://fixture?new-synthetic-uri", {"action": "session"})
    observation = failure_observation(caught.value, "android-case-0-session-delivery-capture-http", [])
    assert observation["reason"] == "android-fixture-binding-or-http"
    assert observation["fixture"] == safe_android_error(raw)
    assert "synthetic-private" not in json.dumps(observation)
    assert len(calls) == 2
    assert calls[1][-2:] == ["cat", "files/response.json"]


def test_android_java_error_diagnostics_have_no_raw_exception_or_retry_channel():
    source = (Path(__file__).parent / "fixtures/runtime/transport/TransportActivity.java").read_text()
    assert '"fixture-error"' in source and '"binding-or-transport"' in source
    assert 'String phase = "binding";' in source
    for phase in ANDROID_ERROR_PHASES - {"binding"}:
        assert f'phase = "{phase}";' in source
    for category in ANDROID_ERROR_CATEGORIES:
        assert f'return "{category}";' in source
    assert all(
        forbidden not in source
        for forbidden in ["getMessage(", "getClass(", "printStackTrace(", "System.out", "System.err"]
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
    server.pid_sha256 = digest(b"NEW synthetic PID")
    server.instance_sha256 = digest(authority.identity.encode())

    class Opener:
        def open(self, request, timeout):
            route = urlparse(request.full_url).path
            status, raw = (
                server.health_response(request.data)
                if route == "/health"
                else authority.handle(route, request.get_header("Authorization", ""), request.data)
            )
            if alter:
                status, raw = alter(status, raw)
            if status >= 400:
                raise HTTPError(request.full_url, status, "synthetic", Message(), io.BytesIO(raw))
            return Response(raw, status)

    monkeypatch.setattr("tests.support.runtime_transport.build_opener", lambda *_args: Opener())
    return server


@pytest.mark.parametrize(
    "mutation", [None, "nonce", "pid_sha256", "instance_sha256", "extra", "oversize", "status", "timeout"]
)
def test_owned_health_binds_fresh_nonce_pid_instance_without_auth_mutation(monkeypatch, mutation):
    authority = OwnedAuthority("apsa.fixture.health", "1" * 64, invalidate=True)

    def alter(status, raw):
        if mutation == "timeout":
            raise TimeoutError("NEW synthetic secret must stay private")
        if mutation == "oversize":
            return status, b"x" * 4097
        value = json.loads(raw)
        if mutation in {"nonce", "pid_sha256", "instance_sha256"}:
            value[mutation] = "0" * 64
        elif mutation == "extra":
            value["secret"] = "NEW synthetic private sentinel"
        return (201 if mutation == "status" else status), json.dumps(value).encode()

    server = server_without_socket(authority, monkeypatch, alter=alter)
    first, second = server.health(), server.health()
    assert first["state"] == ("verified" if mutation is None else "unconfirmed")
    assert first["nonce_sha256"] != second["nonce_sha256"]
    assert authority.events == [] and authority.session == authority.credential == ""
    assert authority.active is False and authority.logged_out is False
    assert "private" not in json.dumps(first)


@pytest.mark.parametrize("raw", [b"{}", b"[]", b'{"nonce":false}', b'{"nonce":"short"}', b"\xff"])
def test_health_rejects_invalid_challenges_without_auth_events(raw, monkeypatch):
    authority = OwnedAuthority("apsa.fixture.health", "1" * 64, invalidate=True)
    server = server_without_socket(authority, monkeypatch)
    assert server.health_response(raw) == (400, b'{"state":"rejected"}')
    assert server.event_counts() == {
        "/issue": 0,
        "/logout": 0,
        "/switch": 0,
        "/protected": 0,
        "unsupported": 0,
    }


@pytest.mark.parametrize("diagnostic_failure", [False, True])
@pytest.mark.parametrize("cleanup_failure", [False, True])
def test_failed_acquisition_keeps_original_deadline_and_persists_health_counts(
    monkeypatch, diagnostic_failure, cleanup_failure
):
    original = subprocess.TimeoutExpired(["NEW synthetic deadline"], 7)
    record = {}
    servers = []

    def factory(authority):
        server = server_without_socket(authority, monkeypatch)
        health = server.health
        calls = []

        def probe():
            calls.append(True)
            if len(calls) > 1 and diagnostic_failure:
                raise ValueError("NEW secret diagnostic failure")
            return health()

        def close():
            if cleanup_failure:
                raise ValueError("NEW secret cleanup failure")

        server.health, server.close = probe, close
        servers.append(server)
        return server

    def fail_recorder(*args):
        authority = servers[0].authority
        authority.bind("a" * 64)
        authority.handle(
            "/issue",
            "",
            json.dumps(
                {"session": authority.session, "package": authority.package, "build": authority.build}
            ).encode(),
        )
        raise original

    monkeypatch.setattr("scripts.validate_runtime_transport.AuthorityServer", factory)
    monkeypatch.setattr("scripts.validate_runtime_transport.AcquisitionRecorder", fail_recorder)
    target = SimpleNamespace(
        platform="ios",
        package="apsa.fixture.new",
        build={"executable_sha256": "a" * 64, "info_plist_sha256": "b" * 64},
    )
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        execute_case(target, invalidate=True, retain=False, evidence=record)
    assert caught.value is original and caught.value.timeout == 7
    assert record["state"] == "inconclusive"
    assert record["authority_event_counts"] == {
        "/issue": 1,
        "/logout": 0,
        "/switch": 0,
        "/protected": 0,
        "unsupported": 0,
    }
    assert [entry["phase"] for entry in record["authority_health"]] == ["before-session", "after-failure"]
    assert record["authority_health"][-1]["state"] == ("unconfirmed" if diagnostic_failure else "verified")
    assert record["authority_cleanup"] == ("unconfirmed" if cleanup_failure else "confirmed")
    assert "secret" not in json.dumps(record) and "authority_events" not in record


def test_public_runtime_projection_excludes_raw_fields_and_binds_only_known_sources():
    secret = "NEW synthetic secret URL response credential"
    evidence = {
        "state": "inconclusive",
        "platform": "ios",
        "measurement": "installed-acquisition",
        "terminal": True,
        "commit": "a" * 40,
        "source_sha256": {"runtime_transport.py": "b" * 64, secret: "c" * 64},
        "cases": [
            {
                "state": "inconclusive",
                "url": secret,
                "authority_health": [
                    {"phase": "after-failure", "state": "verified", "nonce_sha256": "d" * 64, "raw": secret}
                ],
                "authority_event_counts": {"/issue": 1, secret: 5},
                "verified_fields": {"bound_os_delivery": False, secret: True},
                "authority_cleanup": "confirmed",
            }
        ],
        "cleanup": {"state": "confirmed"},
        "workflow_cleanup": {"state": "confirmed"},
        "error": secret,
    }
    output = runtime_projection(evidence)
    assert secret not in json.dumps(output)
    assert output["source_sha256"] == {"runtime_transport.py": "b" * 64}
    assert output["cases"][0]["verified_fields"] == {"bound_os_delivery": False}
    assert output["workflow_cleanup"] == "confirmed" and output["case_count"] == 1
    assert output["physical_device_verified"] is False


def test_runtime_cli_persists_failed_case_source_binding_and_terminal_projection(
    tmp_path, monkeypatch, capsys
):
    work = tmp_path / "NEW-failed-runtime"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setattr(sys, "argv", ["runtime", "--platform", "ios", "--work", str(work)])

    class Target:
        device = "NEW-synthetic-target"

        def __init__(self, *args, **kwargs):
            pass

        def close(self):
            return {"state": "confirmed", "scope": "NEW target"}

    def fail_case(target, *, invalidate, retain, evidence, transition_kind="logout"):
        evidence.update(
            state="inconclusive",
            authority_event_counts={"/issue": 0, "/logout": 0, "/protected": 0, "unsupported": 0},
            authority_health=[{"phase": "after-failure", "state": "verified", "pid_sha256": "b" * 64}],
            verified_fields={},
        )
        raise subprocess.TimeoutExpired(["NEW secret command"], 7)

    monkeypatch.setattr("scripts.validate_runtime_transport.IosTarget", Target)
    monkeypatch.setattr("scripts.validate_runtime_transport.execute_case", fail_case)
    with pytest.raises(SystemExit) as caught:
        main()
    assert caught.value.code == 1
    value = json.loads((work / "evidence.json").read_text())
    assert value["terminal"] is True and value["state"] == "inconclusive"
    assert len(value["cases"]) == 1 and len(value["source_sha256"]) == 7
    assert value["cases"][0]["authority_event_counts"]["/issue"] == 0
    assert value["failure_observation"]["exception_type"] == "TimeoutExpired"
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    terminal = next(record["runtime_validation"] for record in records if "runtime_validation" in record)
    assert terminal["commit"] == "a" * 40 and terminal["source_sha256"] == value["source_sha256"]
    assert terminal["case_count"] == 1 and terminal["cleanup"] == "confirmed"
    assert "NEW secret" not in json.dumps(value) + json.dumps(records)


def test_unconfirmed_authority_health_cannot_start_acquisition(monkeypatch):
    record = {}
    calls = []

    class Server:
        def __init__(self, authority):
            pass

        def health(self):
            return {"state": "unconfirmed"}

        def event_counts(self):
            return {}

        def close(self):
            calls.append("closed")

    monkeypatch.setattr("scripts.validate_runtime_transport.AuthorityServer", Server)
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.AcquisitionRecorder",
        lambda *_args: pytest.fail("unverified authority must not start acquisition"),
    )
    target = SimpleNamespace(
        platform="android", package="apsa.fixture.health", build={"apk_sha256": "a" * 64}
    )
    with pytest.raises(ValueError, match="readiness/identity unconfirmed"):
        execute_case(target, invalidate=True, retain=False, evidence=record)
    assert record["state"] == "inconclusive" and calls == ["closed"]


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


def synthetic_hosted_ios_env():
    return {
        "GITHUB_ACTIONS": "true",
        "CI": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS",
        "HOME": "/Users/runner",
        "DEVELOPER_DIR": "/Applications/Xcode_16.4.app/Contents/Developer",
    }


@pytest.mark.parametrize(
    "change",
    [
        {"GITHUB_ACTIONS": "false"},
        {"CI": "false"},
        {"RUNNER_ENVIRONMENT": "self-hosted"},
        {"RUNNER_OS": "Linux"},
        {"HOME": "/new-other-home"},
        {"DEVELOPER_DIR": "/new-other-sdk"},
        {"SIMULATOR_DEVICE_SET_PATH": ""},
        {"SIMCTL_DEVICE_SET_PATH": "/new-other-set"},
        {"CORE_SIMULATOR_DEVICE_SET_PATH": ""},
        {"CFFIXED_USER_HOME": "/new-other-home"},
        {"SIMULATOR_ROOT": ""},
        {"SIMULATOR_HOME": ""},
        {"SIMULATOR_UDID": "booted"},
        {"SIMCTL_CHILD_HOME": "/new-other-home"},
    ],
)
def test_ios_default_set_operational_guard_rejects_before_any_sdk_call(tmp_path, monkeypatch, change):
    monkeypatch.setattr("scripts.validate_runtime_transport.platform.system", lambda: "Darwin")
    commands = Commands(tmp_path, env={**synthetic_hosted_ios_env(), **change})
    commands.resources = OwnedResources(tmp_path)
    monkeypatch.setattr(commands, "run", lambda *a, **kw: pytest.fail("SDK operation before hosted guard"))
    with pytest.raises(ValueError, match="pinned hosted macOS namespace"):
        IosTarget(
            tmp_path / "new-build",
            "apsa.fixture.new",
            commands,
            IOS_PINNED_RUNTIME,
            IOS_PINNED_DEVICE_TYPE,
            device_set_mode="default",
        )
    assert not (tmp_path / "new-build").exists()


@pytest.mark.parametrize(
    "failure",
    ["platform", "missing-env", "missing-runtime", "unsupported-runtime", "wrong-device-type", "no-journal"],
)
def test_ios_default_set_requires_explicit_pinned_inputs_and_journal_before_sdk(
    tmp_path, monkeypatch, failure
):
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.platform.system",
        lambda: "Linux" if failure == "platform" else "Darwin",
    )
    env = synthetic_hosted_ios_env()
    if failure == "missing-env":
        del env["RUNNER_ENVIRONMENT"]
    commands = Commands(tmp_path, env=env)
    if failure != "no-journal":
        commands.resources = OwnedResources(tmp_path)
    runtime = (
        None
        if failure == "missing-runtime"
        else "unsupported-runtime"
        if failure == "unsupported-runtime"
        else IOS_PINNED_RUNTIME
    )
    device_type = "other-device" if failure == "wrong-device-type" else IOS_PINNED_DEVICE_TYPE
    monkeypatch.setattr(commands, "run", lambda *a, **kw: pytest.fail("SDK operation before input guard"))
    with pytest.raises(ValueError):
        IosTarget(
            tmp_path / "new-build",
            "apsa.fixture.new",
            commands,
            runtime,
            device_type,
            device_set_mode="default",
        )
    assert not (tmp_path / "new-build").exists()


@pytest.mark.parametrize("selector", ["custom", "default"])
@pytest.mark.parametrize(
    "failure", ["journal-save", "delete-nonzero", "shutdown-timeout", "malformed-create"]
)
def test_ios_journal_io_failure_cleans_only_create_returned_uuid_with_bounded_commands(
    tmp_path, monkeypatch, selector, failure
):
    device = "11111111-2222-3333-4444-555555555555"
    commands = Commands(tmp_path, env={})
    commands.resources = OwnedResources(tmp_path)
    calls = []

    def save_unavailable():
        raise OSError("new-synthetic-private-journal-error")

    monkeypatch.setattr(commands.resources, "save", save_unavailable)
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.ios_default_set", lambda env: tmp_path / "new-default-stand-in"
    )

    def public_tools(argv, **kwargs):
        calls.append((argv, kwargs["timeout"]))
        if "--show-sdk-path" in argv:
            raw = b"/new-public-sdk"
        elif "swiftc" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"new target executable")
            raw = b""
        elif "create" in argv:
            raw = b"booted" if failure == "malformed-create" else device.encode()
        elif "shutdown" in argv:
            assert kwargs["timeout"] == 15 and argv[-1] == device
            if failure == "shutdown-timeout":
                raise subprocess.TimeoutExpired(argv, 15, output=b"", stderr=b"")
            raw = b""
        elif "delete" in argv:
            assert kwargs["timeout"] == 15 and argv[-1] == device
            return SimpleNamespace(returncode=1 if failure == "delete-nonzero" else 0, stdout=b"", stderr=b"")
        else:
            raw = b""
        return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")

    monkeypatch.setattr(subprocess, "run", public_tools)
    with pytest.raises(ValueError if failure == "malformed-create" else OSError):
        IosTarget(
            tmp_path / "new-build",
            "apsa.fixture.new",
            commands,
            IOS_PINNED_RUNTIME,
            IOS_PINNED_DEVICE_TYPE,
            device_set_mode=selector,
        )
    device_calls = [(argv, timeout) for argv, timeout in calls if "simctl" in argv and "create" not in argv]
    if failure == "malformed-create":
        assert device_calls == [] and commands.pre_cleanup_failure is None
    else:
        assert len(device_calls) == 2
        assert all(argv[-1] == device and timeout == 15 for argv, timeout in device_calls)
        assert "shutdown" in device_calls[0][0] and "delete" in device_calls[1][0]
        assert commands.pre_cleanup_failure is not None
        cleanup = commands.pre_cleanup_failure["constructor_cleanup"]
        assert cleanup["state"] == ("unconfirmed" if failure == "delete-nonzero" else "confirmed")
        assert cleanup["selector"] == selector and cleanup["uuid_sha256"] == digest(device.encode())
        assert "new-synthetic-private-journal-error" not in json.dumps(commands.pre_cleanup_failure)
    assert all(("--set" in argv) is (selector == "custom") for argv, _ in calls if "simctl" in argv)


def test_ios_default_set_guard_derives_fixed_path_without_local_parent_metadata(monkeypatch):
    monkeypatch.setattr("scripts.validate_runtime_transport.platform.system", lambda: "Darwin")
    monkeypatch.setattr(Path, "stat", lambda *a, **kw: pytest.fail("default parent metadata forbidden"))
    assert (
        str(ios_default_set(synthetic_hosted_ios_env()))
        == "/Users/runner/Library/Developer/CoreSimulator/Devices"
    )


def test_default_set_cleanup_persists_selector_and_never_removes_parent_or_neighbor(tmp_path, monkeypatch):
    root = tmp_path / "new-work"
    root.mkdir()
    default = tmp_path / "new-host-default-stand-in"
    default.mkdir()
    device = "11111111-2222-3333-4444-555555555555"
    own = default / device
    own.mkdir()
    neighbor = default / "22222222-3333-4444-5555-666666666666"
    neighbor.mkdir()
    sentinel = neighbor / "new-unowned-synthetic-sentinel"
    sentinel.write_text("preserved")
    journal = OwnedResources(root)
    journal.ios(device, selector="default")
    commands = Commands(root, env={})
    monkeypatch.setattr("scripts.validate_runtime_transport.ios_default_set", lambda env: default)
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        commands.last_status = 0
        assert argv == ["/usr/bin/xcrun", "simctl", argv[2], device]
        assert argv[2] in {"shutdown", "delete"}
        if argv[2] == "delete":
            own.rmdir()
        return b""

    monkeypatch.setattr(commands, "run", run)
    loaded = OwnedResources(root, load=True)
    result = cleanup_owned(root, commands, loaded)
    assert result["state"] == "confirmed" and result["results"][0]["selector"] == "default"
    assert default.is_dir() and sentinel.read_text() == "preserved"
    assert loaded.value["ios"][device] == {"selector": "default", "deleted": True}
    assert cleanup_owned(root, commands, OwnedResources(root, load=True))["state"] == "confirmed"
    assert len(calls) == 2


@pytest.mark.parametrize(
    "failure",
    [
        "unknown-selector",
        "missing-selector",
        "deleted-type",
        "extra-record",
        "bad-uuid",
        "ios-shape",
        "extra-root",
        "duplicate-json",
    ],
)
def test_unknown_or_malformed_ios_journal_fails_closed_before_any_sdk_operation(
    tmp_path, monkeypatch, failure
):
    journal = OwnedResources(tmp_path)
    journal.android(avd="apsa-new-" + "a" * 32, sdk="/new-public-sdk", emulator=True)
    device = "11111111-2222-3333-4444-555555555555"
    journal.ios(device)
    record = journal.value["ios"][device]
    if failure == "unknown-selector":
        record["selector"] = "other"
    elif failure == "missing-selector":
        del record["selector"]
    elif failure == "deleted-type":
        record["deleted"] = "false"
    elif failure == "extra-record":
        record["unowned_namespace"] = "/new-other-set"
    elif failure == "bad-uuid":
        journal.value["ios"] = {"booted": record}
    elif failure == "ios-shape":
        journal.value["ios"] = []
    elif failure == "extra-root":
        journal.value["new_extra_root"] = "unsupported"
    journal.save()
    if failure == "duplicate-json":
        raw = journal.path.read_text().replace('"ios":', '"ios": {}, "ios":', 1)
        journal.path.write_text(raw)
    commands = Commands(tmp_path, env={})
    monkeypatch.setattr(commands, "run", lambda *a, **kw: pytest.fail("malformed journal SDK operation"))
    with pytest.raises(ValueError):
        loaded = OwnedResources(tmp_path, load=True)
        cleanup_owned(tmp_path, commands, loaded)


def test_default_set_cleanup_rechecks_host_guard_before_sdk(tmp_path, monkeypatch):
    journal = OwnedResources(tmp_path)
    journal.ios("11111111-2222-3333-4444-555555555555", selector="default")
    commands = Commands(tmp_path, env={})
    monkeypatch.setattr(
        commands, "run", lambda *a, **kw: pytest.fail("unguarded default cleanup SDK operation")
    )
    with pytest.raises(ValueError, match="pinned hosted macOS namespace"):
        cleanup_owned(tmp_path, commands, journal)


def test_default_set_workflow_controls_are_explicit_separate_required_and_never_list_devices():
    source = Path(__file__).resolve().parents[1] / ".github/workflows/runtime-transport.yml"
    jobs = yaml.safe_load(source.read_text())["jobs"]
    assert {
        "backend",
        "android",
        "ios",
        "ios-app-to-app",
        "ios-default-set",
        "ios-app-to-app-default-set",
    } <= set(jobs)
    artifact_names = []
    for name in ("ios-default-set", "ios-app-to-app-default-set"):
        job = jobs[name]
        assert job["runs-on"] == "macos-15" and job["timeout-minutes"] == 30
        assert "continue-on-error" not in job
        primary = next(step for step in job["steps"] if "--ios-device-set default" in step.get("run", ""))
        assert "--ios-runtime " + IOS_PINNED_RUNTIME in primary["run"]
        assert "--ios-device-type " + IOS_PINNED_DEVICE_TYPE in primary["run"]
        assert ("--ios-url-driver companion" in primary["run"]) is (name == "ios-app-to-app-default-set")
        assert "continue-on-error" not in primary
        assert all(
            "simctl list" not in step.get("run", "") and "booted" not in step.get("run", "")
            for step in job["steps"]
        )
        uploads = [step for step in job["steps"] if "upload-artifact" in step.get("uses", "")]
        assert len(uploads) == 2 and all(step["if"] == "always()" for step in uploads)
        artifact_names.extend(step["with"]["name"] for step in uploads)
        cleanup = next(step for step in job["steps"] if "--cleanup-only" in step.get("run", ""))
        assert cleanup["if"] == "always()" and cleanup["timeout-minutes"] == 5
        assert '--work "$RUNNER_TEMP/runtime-new-default-' in cleanup["run"]
    assert len(set(artifact_names)) == 4
    for name in ("ios", "ios-app-to-app"):
        assert all("--ios-device-set default" not in step.get("run", "") for step in jobs[name]["steps"])


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
            "CFBundleURLSchemes": [value["APSAFixtureScheme"]],
        }
    ]
    assert value["APSAFixtureScheme"].startswith("a") and len(value["APSAFixtureScheme"]) == 33
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
    monkeypatch.setattr(target, "require_installed_contract", lambda **kwargs: None)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.url_driver = "simctl"
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
    value = synthetic_ios_events()
    value["events"][1].update(
        {
            "action": action,
            "lifecycle": lifecycle,
            "uri_sha256": digest(b"synthetic-url-never-opened"),
            "session_sha256": digest(expected["session"].encode()),
            "nonce_sha256": digest(expected["nonce"].encode()) if "nonce" in expected else None,
        }
    )
    target.events_path = tmp_path / "events.json"
    target.events_path.write_text(json.dumps(value))
    target.readiness_epoch = digest(b"new synthetic earlier readiness")
    target.process_observations = {"after_terminate": {"state": "exited"}}
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


def synthetic_ios_events(*, complete=True):
    receipt = {
        "sequence": 2,
        "phase": "os-dispatch",
        "main_thread": True,
        "lifecycle": "cold-url-context",
        "action": "session",
        "uri_sha256": digest(b"new synthetic URI"),
        "session_sha256": digest(b"new synthetic session"),
        "nonce_sha256": None,
    }
    return {
        "schema_version": 1,
        "complete": complete,
        "launch_epoch_sha256": digest(b"new synthetic process"),
        "events": [
            {"sequence": 1, "phase": "scene-connect-url-present", "main_thread": True},
            receipt,
            {"sequence": 3, "phase": "scene-active", "main_thread": True},
        ],
    }


@pytest.mark.parametrize(
    "field", [None, "lifecycle", "action", "uri_sha256", "session_sha256", "nonce_sha256"]
)
def test_ios_callback_receipts_survive_later_activation_and_bind_exact_dispatch(field):
    value = synthetic_ios_events()
    receipt = value["events"][1]
    expected = {
        key: receipt[key] for key in ("lifecycle", "action", "uri_sha256", "session_sha256", "nonce_sha256")
    }
    if field:
        expected[field] = "new mismatching synthetic identity"
    result = safe_ios_events(json.dumps(value).encode(), expected, digest(b"new synthetic readiness process"))
    assert result["state"] == "complete"
    assert result["process_epoch_relation"] == "new-since-readiness"
    assert result["counters"] == {"scene-connect-url-present": 1, "os-dispatch": 1, "scene-active": 1}
    assert len(result["receipts"]) == 1
    assert result["receipts"][0]["matches_expected_dispatch"] is (field is None)


@pytest.mark.parametrize(
    "change",
    [
        "raw-url",
        "raw-token",
        "unknown-phase",
        "bad-hash",
        "bad-sequence",
        "bad-thread",
        "too-many",
        "too-large",
    ],
)
def test_ios_callback_diagnostics_reject_unbounded_or_private_fields(change):
    value = synthetic_ios_events()
    if change in {"raw-url", "raw-token"}:
        value["events"][1][change] = "new-synthetic-private-value"
    elif change == "unknown-phase":
        value["events"][0]["phase"] = "new-synthetic-private-value"
    elif change == "bad-hash":
        value["events"][1]["uri_sha256"] = "new-synthetic-private-value"
    elif change == "bad-sequence":
        value["events"][1]["sequence"] = 1
    elif change == "bad-thread":
        value["events"][0]["main_thread"] = 1
    elif change == "too-many":
        value["events"] = [
            {"sequence": i + 1, "phase": "scene-active", "main_thread": True} for i in range(129)
        ]
    else:
        value["extra"] = "new-synthetic-private-value" * 10000
    raw = json.dumps(value).encode()
    result = safe_ios_events(raw)
    assert result == {"state": "malformed-or-over-bound", "sha256": digest(raw), "bytes": len(raw)}
    assert "new-synthetic-private-value" not in json.dumps(result)


def test_ios_diagnostics_record_caps_and_stale_prelaunch_epoch_without_promoting_os_proof():
    value = synthetic_ios_events(complete=False)
    value["events"] = [{"sequence": i + 1, "phase": "scene-active", "main_thread": True} for i in range(128)]
    result = safe_ios_events(json.dumps(value).encode(), readiness_epoch=value["launch_epoch_sha256"])
    assert result["state"] == "capped"
    assert result["process_epoch_relation"] == "same-as-readiness"
    assert result["counters"] == {"scene-active": 128}
    assert result["receipts"] == []


def test_ios_driver_persists_safe_callback_diagnostics_on_deadline(tmp_path):
    target = IosTarget.__new__(IosTarget)
    target.response = tmp_path / "new-response.json"
    target.stage_path = tmp_path / "new-stage.txt"
    target.stage_path.write_text("scene-active")
    (tmp_path / "events.json").write_text(json.dumps(synthetic_ios_events()))
    result = target.lifecycle_observation()
    assert result["callback_events"]["receipts"][0]["lifecycle"] == "cold-url-context"
    assert result["callback_events"]["receipts"][0]["matches_expected_dispatch"] is False
    assert result["lifecycle_stage"] == "scene-active"


@pytest.mark.parametrize(
    "raw,pid",
    [
        (b"apsa.fixture.new: 321\n", 321),
        (b"apsa.fixture.other: 321\n", None),
        (b"apsa.fixture.new: -321\n", None),
        (b"apsa.fixture.new: 0\n", None),
        (b"apsa.fixture.new: 2147483648\n", None),
        (b"apsa.fixture.new: 321 extra\n", None),
    ],
)
def test_ios_launch_pid_only_accepts_exact_new_package_and_positive_pid(raw, pid):
    assert ios_launch_pid(raw, "apsa.fixture.new") == pid


@pytest.mark.parametrize("state", ["live-verified", "identity-mismatch", "exited", "unmeasured"])
def test_ios_known_pid_identity_never_enumerates_or_sends_a_real_signal(state, tmp_path, monkeypatch):
    executable = tmp_path / "new-set/new-uuid/new-app/TransportFixture"
    expected = str(executable.resolve()).encode()
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr("scripts.validate_runtime_transport.platform.system", lambda: "Darwin")
    calls = []

    def existence(pid, signal):
        calls.append((pid, signal))
        if state == "exited":
            raise ProcessLookupError()
        if state == "unmeasured":
            raise PermissionError()

    def pidpath(pid, buffer, size):
        assert pid == 321 and size == 4096
        buffer.value = expected if state == "live-verified" else b"/new-synthetic-reused-process"
        return len(buffer.value)

    monkeypatch.setattr("scripts.validate_runtime_transport.os.kill", existence)
    monkeypatch.setattr(ctypes, "CDLL", lambda *a, **kw: SimpleNamespace(proc_pidpath=pidpath))
    result = ios_process_identity(321, executable)
    assert result["state"] == state
    assert calls == [(321, 0)]
    assert "/new-synthetic-reused-process" not in json.dumps(result)
    assert str(executable) not in json.dumps(result)


def test_ios_pid_probe_is_unmeasured_outside_disposable_ci_and_for_nonpositive_pid(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.os.kill", lambda *a: pytest.fail("PID operation forbidden")
    )
    for pid in (None, -1, 0, True, 321):
        assert ios_process_identity(pid, tmp_path / "new-app") == {"state": "unmeasured"}


def synthetic_ios_entry(data: Path, *, epoch="1" * 64, pid=321, write_status="confirmed"):
    documents = data / "Documents"
    return {
        "schema_version": 1,
        "phase": "before-uiapplication-main",
        "process_epoch_sha256": epoch,
        "pid_sha256": digest(str(pid).encode()),
        "home_path_sha256": digest(str(data.resolve()).encode()),
        "documents_path_sha256": digest(str(documents.resolve()).encode()),
        "entry_path_sha256": digest(str((documents / "process-entry.json").resolve()).encode()),
        "write_status": write_status,
    }


def new_entry_target(tmp_path):
    target = IosTarget.__new__(IosTarget)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.url_driver = "simctl"
    target.device_set = tmp_path / "new-set"
    data = target.device_set / target.device / "new-data"
    (data / "Documents").mkdir(parents=True)
    target.response = data / "Documents/response.json"
    target.stage_path = target.response.with_name("stage.txt")
    target.stage_path.write_text("scene-active")
    target.events_path = target.response.with_name("events.json")
    return target, data


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": True},
        {"phase": "new-private-phase"},
        {"pid_sha256": 321},
        {"home_path_sha256": "/new-synthetic-private-path"},
        {"documents_path_sha256": None},
        {"process_epoch_sha256": "F" * 64},
        {"entry_path_sha256": ["1" * 64]},
        {"write_status": "new-private-error"},
        {"raw_path": "/new-synthetic-private-path"},
    ],
)
def test_ios_entry_rejects_untrusted_fields_without_echoing_raw_metadata(tmp_path, change):
    value = {**synthetic_ios_entry(tmp_path), **change}
    result = safe_ios_entry(json.dumps(value).encode())
    assert result["state"] == "unmeasured" and result["write_status"] == "unknown"
    assert result["acquisition"] == "unsupported"
    assert "new-private" not in json.dumps(result) and "/new-synthetic" not in json.dumps(result)


@pytest.mark.parametrize("raw", [b"", b"not-json", b"[]", b"\xff", b"x" * 4097])
def test_ios_entry_absent_malformed_or_over_bound_leaves_write_outcome_unknown(raw):
    result = safe_ios_entry(raw)
    assert result["state"] == ("absent" if not raw else "unmeasured")
    assert result["write_status"] == "unknown" and result["acquisition"] == "unsupported"


@pytest.mark.parametrize(
    ("process_state", "pid", "relation"),
    [
        ("live-verified", 321, "matches-live-verified"),
        ("exited", 321, "matches-exited-owner"),
        ("unmeasured", 321, "unmeasured"),
        ("live-verified", 322, "differs-known-owner"),
    ],
)
def test_ios_entry_new_epoch_path_binding_and_known_pid_are_independent(
    tmp_path, process_state, pid, relation
):
    value = synthetic_ios_entry(tmp_path, epoch="2" * 64, pid=pid)
    paths = {key: value[key] for key in ("home_path_sha256", "documents_path_sha256", "entry_path_sha256")}
    result = safe_ios_entry(
        json.dumps(value).encode(),
        expected_paths=paths,
        process={"state": process_state, "pid_sha256": digest(b"321")},
        readiness_epoch="1" * 64,
        callback_epoch="1" * 64,
    )
    assert result["state"] == "diagnostic-only" and result["acquisition"] == "unsupported"
    assert result["expected_paths_match"] is True and result["pid_identity_relation"] == relation
    assert result["process_epoch_relation"] == "new-since-readiness"
    assert result["callback_epoch_relation"] == "differs-callback"
    paths["documents_path_sha256"] = "3" * 64
    mismatch = safe_ios_entry(json.dumps(value).encode(), expected_paths=paths)
    assert mismatch["expected_paths_match"] is False and mismatch["state"] == "unmeasured"


@pytest.mark.parametrize("write_status", ["attempted", "confirmed"])
def test_ios_entry_reader_reads_only_exact_owned_path_and_preserves_write_status(tmp_path, write_status):
    target, data = new_entry_target(tmp_path)
    value = synthetic_ios_entry(data, write_status=write_status)
    target.readiness_entry_epoch = value["process_epoch_sha256"]
    target.process_observations = {"after_terminate": {"state": "exited", "pid_sha256": value["pid_sha256"]}}
    events = synthetic_ios_events()
    events["launch_epoch_sha256"] = value["process_epoch_sha256"]
    target.events_path.write_text(json.dumps(events))
    target.response.with_name("process-entry.json").write_text(json.dumps(value))
    result = target.entry_observation()
    assert result["expected_paths_match"] is True and result["write_status"] == write_status
    assert result["pid_identity_relation"] == "matches-exited-owner"
    assert result["process_epoch_relation"] == "same-as-readiness"
    assert result["callback_epoch_relation"] == "same-as-callback"
    assert str(data) not in json.dumps(result)


@pytest.mark.parametrize("escape", ["entry-symlink", "documents-symlink", "wrong-uuid", "over-bound"])
def test_ios_entry_reader_rejects_scope_escape_and_oversize_before_open(tmp_path, monkeypatch, escape):
    target, data = new_entry_target(tmp_path)
    outside = tmp_path / "new-outside"
    outside.mkdir()
    other = outside / "process-entry.json"
    other.write_text(json.dumps(synthetic_ios_entry(outside)))
    path = target.response.with_name("process-entry.json")
    if escape == "entry-symlink":
        path.symlink_to(other)
    elif escape == "documents-symlink":
        target.stage_path.unlink()
        path.parent.rmdir()
        path.parent.symlink_to(outside, target_is_directory=True)
    elif escape == "wrong-uuid":
        target.response = other.with_name("response.json")
    else:
        path.write_bytes(b"x" * 4097)
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.os.open", lambda *a: pytest.fail("unsafe entry read")
    )
    result = target.entry_observation()
    assert result["state"] == "unmeasured" and result["write_status"] == "unknown"
    assert result["acquisition"] == "unsupported"


def test_ios_entry_new_process_diagnostic_never_promotes_original_cold_failure(tmp_path, monkeypatch):
    target, data = new_entry_target(tmp_path)
    value = synthetic_ios_entry(data)
    path = target.response.with_name("process-entry.json")
    path.write_text(json.dumps(value))
    events = synthetic_ios_events()
    events["launch_epoch_sha256"] = value["process_epoch_sha256"]
    events["events"] = [{"sequence": 1, "phase": "scene-active", "main_thread": True}]
    monkeypatch.setattr(target, "require_installed_contract", lambda **kwargs: None)
    target.events_path.write_text(json.dumps(events))
    target.readiness_epoch = target.readiness_entry_epoch = value["process_epoch_sha256"]
    process = {"state": "exited", "pid_sha256": value["pid_sha256"]}
    target.process_observations = {"after_terminate": process}
    target.readiness_entry = target.entry_observation(process={**process, "state": "live-verified"})
    target.delivery_observations = []
    target.commands = Commands(tmp_path, env={})
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(target.device_set)]
    monkeypatch.setattr(target.commands, "run", lambda *a, **kw: b"")
    times = iter([0, 91])
    monkeypatch.setattr("scripts.validate_runtime_transport.time.monotonic", lambda: next(times))

    def tail():
        changed = synthetic_ios_entry(data, epoch="2" * 64, pid=322)
        path.write_text(json.dumps(changed))
        return {
            "state": "diagnostic-only",
            "process_entry_after_launch": target.entry_observation(
                process={"state": "live-verified", "pid_sha256": changed["pid_sha256"]}
            ),
        }

    monkeypatch.setattr(target, "cold_timeout_diagnostic", tail)
    with pytest.raises(FixtureFailure, match="response challenge timed out") as caught:
        target.deliver("new-synthetic-primary-url", {"action": "session", "session": "a" * 64})
    primary = caught.value.observation
    assert primary["process_entry"]["process_epoch_relation"] == "same-as-readiness"
    assert primary["process_entry_readiness"]["pid_identity_relation"] == "matches-live-verified"
    assert (
        primary["diagnostic_tail"]["process_entry_after_launch"]["process_epoch_relation"]
        == "new-since-readiness"
    )
    assert primary["callback_events"]["receipts"] == [] and target.delivery_observations == []
    assert target.dispatch_expectation["action"] == "session"


@pytest.mark.parametrize("failure", ["entry-read", "callback-read"])
def test_ios_entry_diagnostic_io_failure_does_not_escape_or_echo_private_error(
    tmp_path, monkeypatch, failure
):
    target, data = new_entry_target(tmp_path)
    target.response.with_name("process-entry.json").write_text(json.dumps(synthetic_ios_entry(data)))

    def unavailable(*args):
        raise PermissionError("new-synthetic-private-path-and-error")

    if failure == "entry-read":
        monkeypatch.setattr("scripts.validate_runtime_transport.os.open", unavailable)
    else:
        monkeypatch.setattr(target, "events_observation", unavailable)
    result = target.entry_observation()
    assert result["state"] == ("unmeasured" if failure == "entry-read" else "diagnostic-only")
    assert result["acquisition"] == "unsupported" and "new-synthetic-private" not in json.dumps(result)
    if failure == "callback-read":
        assert result["callback_epoch_relation"] == "unknown"


@pytest.mark.parametrize("entry_state", ["absent", "malformed", "path-mismatch"])
def test_ios_entry_diagnostic_is_not_required_for_otherwise_strict_callback_acceptance(tmp_path, entry_state):
    target, data = new_entry_target(tmp_path)
    path = target.response.with_name("process-entry.json")
    if entry_state == "malformed":
        path.write_bytes(b"new malformed diagnostic")
    elif entry_state == "path-mismatch":
        value = synthetic_ios_entry(data)
        value["documents_path_sha256"] = "3" * 64
        path.write_text(json.dumps(value))
    events = synthetic_ios_events()
    target.events_path.write_text(json.dumps(events))
    target.readiness_epoch = digest(b"previous NEW process")
    receipt = events["events"][1]
    target.dispatch_expectation = {
        key: receipt[key] for key in ("lifecycle", "action", "uri_sha256", "session_sha256", "nonce_sha256")
    }
    target.process_observations = {"after_terminate": {"state": "exited"}}
    target.delivery_observations = []
    assert target.entry_observation()["state"] == ("absent" if entry_state == "absent" else "unmeasured")
    target.record_delivery(
        {"delivery_lifecycle": "cold-url-context"},
        {"action": "session", "session": "new synthetic session"},
        raw=b"new response",
    )
    assert len(target.delivery_observations) == 1
    assert (
        target.delivery_observations[0]["callback_events"]["receipts"][0]["matches_expected_dispatch"] is True
    )


def test_ios_appinfo_projects_only_new_identity_and_registration_booleans():
    package = "apsa.fixture.new"
    value = {
        "CFBundleIdentifier": package,
        "CFBundleURLTypes": [
            {
                "CFBundleTypeRole": "Editor",
                "CFBundleURLName": package + ".transport",
                "CFBundleURLSchemes": ["apsatransport"],
            }
        ],
        "EnvironmentVariables": {"NEW_SECRET": "new-synthetic-private-metadata"},
    }
    result = safe_ios_appinfo(json.dumps(value).encode(), package)
    assert result["package_matches"] is True and result["url_types_match"] is True
    assert "new-synthetic-private-metadata" not in json.dumps(result)
    assert "EnvironmentVariables" not in result
    assert safe_ios_appinfo(plistlib.dumps(value), package)["package_matches"] is True
    assert safe_ios_appinfo(b"unsupported-new-format", package)["state"] == "unmeasured"
    assert (
        safe_ios_appinfo(json.dumps({"CFBundleIdentifier": "apsa.fixture.other"}).encode(), package)[
            "package_matches"
        ]
        is False
    )


@pytest.mark.parametrize("escape", ["outside", "wrong-uuid", "symlink", "set-root"])
@pytest.mark.parametrize("selector", ["custom", "default"])
def test_ios_container_resolution_stays_under_owned_new_set_uuid(escape, selector, tmp_path, monkeypatch):
    target = IosTarget.__new__(IosTarget)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.package = "apsa.fixture.new"
    target.device_set = tmp_path / "new-set"
    target.device_set_mode = selector
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(target.device_set)]
    target.commands = Commands(tmp_path, env={})
    owned = target.device_set / target.device
    owned.mkdir(parents=True)
    outside = tmp_path / "new-synthetic-outside"
    outside.mkdir()
    if escape == "symlink":
        path = owned / "data"
        path.symlink_to(outside, target_is_directory=True)
    elif escape == "wrong-uuid":
        path = target.device_set / "22222222-3333-4444-5555-666666666666/data"
    elif escape == "set-root":
        path = target.device_set
    else:
        path = outside / target.device
    monkeypatch.setattr(target.commands, "run", lambda *a, **kw: str(path).encode())
    with pytest.raises(ValueError, match="container UUID differs"):
        target.container("data")


@pytest.mark.parametrize("tail_failure", [False, True])
def test_ios_cold_timeout_retains_primary_failure_even_when_tail_observes_warm_callback(
    tmp_path, monkeypatch, tail_failure
):
    target = IosTarget.__new__(IosTarget)
    monkeypatch.setattr(target, "require_installed_contract", lambda **kwargs: None)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.url_driver = "simctl"
    target.commands = Commands(tmp_path, env={})
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "new-set")]
    target.response = tmp_path / "new-response.json"
    target.stage_path = tmp_path / "new-stage.txt"
    target.stage_path.write_text("scene-active")
    target.delivery_observations = []
    value = synthetic_ios_events()
    value["events"] = [{"sequence": 1, "phase": "scene-active", "main_thread": True}]
    target.events_path = tmp_path / "events.json"
    target.events_path.write_text(json.dumps(value))
    target.readiness_epoch = value["launch_epoch_sha256"]
    monkeypatch.setattr(target.commands, "run", lambda *a, **kw: b"")
    times = iter([0, 91])
    monkeypatch.setattr("scripts.validate_runtime_transport.time.monotonic", lambda: next(times))

    def diagnostic():
        target.cold_diagnostic_progress.update(
            process_epoch_observed=True, scene_active_observed=False, warm_probe_attempted=False
        )
        target.stage_path.write_text("os-url-context-received")
        target.events_path.write_text(json.dumps(synthetic_ios_events()))
        if tail_failure:
            raise ValueError("new-synthetic-private-error")
        return {"state": "diagnostic-only", "warm_receipt_bound": True}

    monkeypatch.setattr(target, "cold_timeout_diagnostic", diagnostic)
    expected = {"action": "session", "session": "a" * 64}
    with pytest.raises(FixtureFailure, match="response challenge timed out") as caught:
        target.deliver("new-synthetic-primary-url", expected)
    assert caught.value.observation["lifecycle_stage"] == "scene-active"
    assert caught.value.observation["callback_events"]["receipts"] == []
    assert target.delivery_observations == []
    assert target.dispatch_expectation["action"] == "session"
    assert target.dispatch_expectation["uri_sha256"] == digest(b"new-synthetic-primary-url")
    assert "new-synthetic-private-error" not in json.dumps(caught.value.observation)
    assert caught.value.observation["diagnostic_tail"]["process_epoch_observed"] is True
    assert caught.value.observation["diagnostic_tail"]["scene_active_observed"] is False
    assert caught.value.observation["diagnostic_tail"]["warm_probe_attempted"] is False


@pytest.mark.parametrize("launch_creates_epoch", [True, False])
@pytest.mark.parametrize(
    "outcome",
    [
        "ready",
        "inactive",
        "same-epoch",
        "unavailable",
        "before-identity",
        "after-identity",
        "launch-error",
        "openurl-error",
    ],
)
def test_ios_diagnostic_tail_requires_fresh_ready_epoch_and_exact_warm_noncredential_receipt(
    tmp_path, monkeypatch, launch_creates_epoch, outcome
):
    target = IosTarget.__new__(IosTarget)
    monkeypatch.setattr(target, "require_installed_contract", lambda **kwargs: None)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.package = "apsa.fixture.new"
    app, data = tmp_path / "new-app", tmp_path / "new-data"
    app.mkdir()
    (data / "Documents").mkdir(parents=True)
    (app / "TransportFixture").write_bytes(b"new executable")
    (app / "Info.plist").write_bytes(b"new plist")
    target.installed = app
    target.response = data / "Documents/response.json"
    target.events_path = target.response.with_name("events.json")
    target.build = {"executable_sha256": digest(b"new executable"), "info_plist_sha256": digest(b"new plist")}
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "new-set")]
    target.commands = Commands(tmp_path, env={})
    target.scheme = "a" + "1" * 32
    target.dispatch_expectation = {"primary": "unchanged"}
    target.delivery_observations = []
    old = synthetic_ios_events()
    old["events"] = [{"sequence": 1, "phase": "scene-active", "main_thread": True}]
    target.events_path.write_text(json.dumps(old))
    # A cold attempt may already have created this process; diagnostic launch reuses it.
    target.readiness_epoch = (
        old["launch_epoch_sha256"] if launch_creates_epoch else digest(b"earlier readiness")
    )
    monkeypatch.setattr(target, "container", lambda kind: app if kind == "app" else data)
    monkeypatch.setattr(
        target,
        "appinfo",
        lambda: {"package_matches": False} if outcome == "before-identity" else {"state": "unmeasured"},
    )
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.ios_process_identity",
        lambda *a: {"state": "identity-mismatch" if outcome == "after-identity" else "unmeasured"},
    )
    times = iter([0, 1, 16])
    monkeypatch.setattr("scripts.validate_runtime_transport.time.monotonic", lambda: next(times))
    calls = []

    def control(argv, **kwargs):
        calls.append(argv)
        if "launch" in argv:
            if outcome == "launch-error":
                raise ValueError("new synthetic launch failure")
            value = synthetic_ios_events()
            value["launch_epoch_sha256"] = (
                digest(b"new direct-launch process") if launch_creates_epoch else old["launch_epoch_sha256"]
            )
            if outcome == "same-epoch":
                value["launch_epoch_sha256"] = target.readiness_epoch
            value["events"] = [
                {
                    "sequence": 1,
                    "phase": "startup-scene" if outcome == "inactive" else "scene-active",
                    "main_thread": True,
                }
            ]
            target.events_path.write_text(json.dumps(value))
            if outcome == "unavailable":
                target.events_path.unlink()
            return b"apsa.fixture.new: 321\n"
        if "openurl" in argv:
            if outcome == "openurl-error":
                raise ValueError("new synthetic openurl failure")
            fields = parse_qs(urlparse(argv[-1]).query)
            assert set(fields) == {"action", "session", "nonce"}
            assert fields["action"] == ["capture"]
            assert "backend" not in fields and "retain" not in fields
            value = json.loads(target.events_path.read_text())
            value["events"].append(
                {
                    "sequence": 2,
                    "phase": "os-dispatch",
                    "main_thread": True,
                    "lifecycle": "warm-url-context",
                    "action": "capture",
                    "uri_sha256": digest(argv[-1].encode()),
                    "session_sha256": digest(fields["session"][0].encode()),
                    "nonce_sha256": digest(fields["nonce"][0].encode()),
                }
            )
            target.events_path.write_text(json.dumps(value))
        return b""

    monkeypatch.setattr(target.commands, "run", control)
    if outcome in {"launch-error", "openurl-error"}:
        with pytest.raises(ValueError, match="new synthetic"):
            target.cold_timeout_diagnostic()
        progress = target.cold_diagnostic_progress
        assert progress == {
            "process_epoch_observed": True if outcome == "openurl-error" else None,
            "scene_active_observed": True if outcome == "openurl-error" else None,
            "warm_probe_attempted": outcome == "openurl-error",
        }
        assert target.delivery_observations == []
        return
    result = target.cold_timeout_diagnostic()
    if outcome in {"before-identity", "after-identity"}:
        assert result["state"] == "identity-mismatch"
        assert result["process_epoch_observed"] is None and result["scene_active_observed"] is None
        assert result["warm_probe_attempted"] is False
    else:
        assert result["fresh_epoch"] is (outcome == "ready")
        assert result["warm_receipt_bound"] is (outcome == "ready")
        assert result["process_epoch_observed"] is (
            None if outcome == "unavailable" else outcome != "same-epoch"
        )
        assert result["scene_active_observed"] is (
            None if outcome == "unavailable" else outcome != "inactive"
        )
        assert result["warm_probe_attempted"] is (outcome == "ready")
        if outcome in {"ready", "inactive"}:
            assert result["diagnostic_launch_created_fresh_epoch"] is launch_creates_epoch
        assert result["state"] == "diagnostic-only"
    assert target.dispatch_expectation == {"primary": "unchanged"}
    assert target.delivery_observations == []
    assert sum("openurl" in call for call in calls) == (1 if outcome == "ready" else 0)


@pytest.mark.parametrize(
    "url",
    [
        "https://fixture?x=y",
        "apsatransport://other?x=y",
        "apsatransport://fixture/path",
        "apsatransport://fixture?x=y#fragment",
        "apsatransport://user@fixture?x=y",
        "apsatransport://fixture:123?x=y",
        "apsatransport://fixture?x=" + "a" * 4096,
    ],
)
def test_ios_registered_scheme_rewrite_rejects_arbitrary_origins(url):
    with pytest.raises(ValueError, match="URL origin differs"):
        owned_ios_url(url, "a" + "1" * 32)


def test_ios_registered_scheme_rewrite_preserves_only_exact_synthetic_query():
    query = "action=session&session=" + "1" * 64 + "&backend=http%3A%2F%2F127.0.0.1%3A1234&retain=false"
    assert (
        owned_ios_url("apsatransport://fixture?" + query, "a" + "2" * 32)
        == "a" + "2" * 32 + "://fixture?" + query
    )
    with pytest.raises(ValueError):
        owned_ios_url("apsatransport://fixture?" + query, "https")


@pytest.mark.parametrize(
    "mutation",
    ["missing-receipt", "wrong-uri", "wrong-session", "wrong-nonce", "stale-epoch", "capped", "unterminated"],
)
def test_ios_companion_never_accepts_completion_without_bound_target_cold_receipt(mutation, tmp_path):
    target = IosTarget.__new__(IosTarget)
    target.url_driver = "companion"
    target.response = tmp_path / "response.json"
    target.stage_path = tmp_path / "stage.txt"
    target.events_path = tmp_path / "events.json"
    target.delivery_observations = []
    expected = {"action": "session", "session": "1" * 64}
    target.dispatch_expectation = {
        "action": "session",
        "lifecycle": "cold-url-context",
        "uri_sha256": digest(b"new owned uri"),
        "session_sha256": digest(expected["session"].encode()),
        "nonce_sha256": None,
    }
    value = synthetic_ios_events()
    value["events"][1].update(target.dispatch_expectation)
    target.readiness_epoch = digest(b"new earlier readiness")
    target.process_observations = {"after_terminate": {"state": "exited"}}
    if mutation == "missing-receipt":
        value["events"] = [{"sequence": 1, "phase": "scene-active", "main_thread": True}]
    elif mutation == "wrong-uri":
        value["events"][1]["uri_sha256"] = digest(b"new wrong uri")
    elif mutation == "wrong-session":
        value["events"][1]["session_sha256"] = digest(b"new wrong session")
    elif mutation == "wrong-nonce":
        value["events"][1]["nonce_sha256"] = digest(b"new unexpected nonce")
    elif mutation == "stale-epoch":
        target.readiness_epoch = value["launch_epoch_sha256"]
    elif mutation == "capped":
        value["complete"] = False
    else:
        target.process_observations["after_terminate"]["state"] = "unmeasured"
    target.events_path.write_text(json.dumps(value))
    with pytest.raises(FixtureFailure):
        target.record_delivery({"delivery_lifecycle": "cold-url-context"}, expected, raw=b"new response")
    assert target.delivery_observations == []


@pytest.mark.parametrize("identity", ["identity-mismatch", "unmeasured"])
def test_ios_companion_launch_rejects_unverified_helper_pid_and_retains_primary_acquisition(
    tmp_path, monkeypatch, identity
):
    target = IosTarget.__new__(IosTarget)
    monkeypatch.setattr(target, "require_installed_contract", lambda **kwargs: None)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.url_driver = "companion"
    target.helper_package = "apsa.fixture.new.dispatcher"
    target.helper_installed = tmp_path / "new-helper"
    target.helper_build = {"synthetic": "digest"}
    target.delivery_observations = []
    target.commands = Commands(tmp_path, env={})
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "new-set")]
    calls = []
    monkeypatch.setattr(target, "helper_installed_build", lambda: target.helper_build)
    monkeypatch.setattr(
        target.commands, "run", lambda argv, **kw: calls.append(argv) or b"apsa.fixture.new.dispatcher: 321\n"
    )
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.ios_process_identity", lambda *a: {"state": identity}
    )
    with pytest.raises(FixtureFailure, match="owned PID identity differs"):
        target.dispatch("new-synthetic-owned-uri")
    assert len(calls) == 2 and "terminate" in calls[0] and "launch" in calls[1]
    assert all(target.device in call and target.helper_package in call for call in calls)
    assert not any("openurl" in call for call in calls)
    assert target.delivery_observations == []


@pytest.mark.parametrize("phase", ["os-open-requested", "os-open-completed"])
@pytest.mark.parametrize("wrong_uri", [False, True])
@pytest.mark.parametrize("can_open", [True, False, None])
def test_ios_companion_binds_rewritten_dispatch_uri_without_promoting_helper_receipt(
    tmp_path, monkeypatch, phase, wrong_uri, can_open
):
    target, data = new_entry_target(tmp_path)
    monkeypatch.setattr(target, "require_installed_contract", lambda **kwargs: None)
    target.url_driver = "companion"
    target.scheme = "a" + "1" * 32
    target.helper_package = "apsa.fixture.new.dispatcher"
    target.helper_installed = tmp_path / "new-helper-app"
    target.helper_build = {"synthetic": "digest"}
    target.helper_receipt = data / "Documents/dispatch.json"
    target.delivery_observations = []
    target.process_observations = {"after_terminate": {"state": "exited"}}
    target.commands = Commands(tmp_path, env={})
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(target.device_set)]
    events = synthetic_ios_events()
    events["events"] = [{"sequence": 1, "phase": "scene-active", "main_thread": True}]
    target.events_path.write_text(json.dumps(events))
    target.readiness_epoch = events["launch_epoch_sha256"]
    fields = {"action": "session", "session": "b" * 64, "backend": "http://127.0.0.1:1234", "retain": "false"}
    original = "apsatransport://fixture?" + urlencode(fields)
    actual = owned_ios_url(original, target.scheme)
    calls = []

    def fixture_command(argv, **kwargs):
        calls.append(argv)
        assert target.helper_uri_sha256 == digest(actual.encode())
        if "launch" in argv:
            assert argv[-1] == actual
            value = {
                "phase": phase,
                "uri_sha256": digest(b"new different URI") if wrong_uri else digest(actual.encode()),
            }
            if can_open is not None:
                value["can_open_url"] = can_open
            if phase == "os-open-completed":
                value["open_completion"] = True
            target.helper_receipt.write_text(json.dumps(value))
            return (target.helper_package + ": 321\n").encode()
        return b""

    monkeypatch.setattr(target, "helper_installed_build", lambda: target.helper_build)
    monkeypatch.setattr(target.commands, "run", fixture_command)
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.ios_process_identity", lambda *a: {"state": "live-verified"}
    )
    monkeypatch.setattr(
        target, "cold_timeout_diagnostic", lambda: {"state": "diagnostic-only", "warm_receipt_bound": True}
    )
    times = iter([0, 91])
    monkeypatch.setattr("scripts.validate_runtime_transport.time.monotonic", lambda: next(times))
    with pytest.raises(FixtureFailure, match="response challenge timed out") as caught:
        target.deliver(original, fields)
    diagnostic = caught.value.observation["dispatcher"]
    assert diagnostic["state"] == "diagnostic-only" and diagnostic["uri_matches"] is (not wrong_uri)
    assert diagnostic.get("can_open_url") is can_open
    assert target.helper_uri_sha256 == target.dispatch_expectation["uri_sha256"] == digest(actual.encode())
    assert target.helper_uri_sha256 != digest(original.encode())
    assert (
        target.delivery_observations == [] and caught.value.observation["callback_events"]["receipts"] == []
    )
    assert target.dispatch_expectation["action"] == "session"
    assert not any("openurl" in call for call in calls)
    assert original not in json.dumps(caught.value.observation) and actual not in json.dumps(
        caught.value.observation
    )


def test_ios_companion_and_simctl_workflow_jobs_remain_separate_strict_gates():
    source = Path(__file__).resolve().parents[1] / ".github/workflows/runtime-transport.yml"
    raw = source.read_text()
    simctl = raw.split("  ios:\n", 1)[1].split("  ios-app-to-app:\n", 1)[0]
    companion = raw.split("  ios-app-to-app:\n", 1)[1].split("  ios-default-set:\n", 1)[0]
    assert "--ios-url-driver companion" not in simctl
    assert "--ios-url-driver companion" in companion
    assert "continue-on-error" not in simctl + companion
    assert "timeout-minutes: 30" in companion
    assert companion.count("if: always()") == 3
    assert "new-ios-app-to-app-runtime-digests" in companion


@pytest.mark.parametrize("change", [None, "raw-uri", "wrong-uri", "nonbool-completion"])
def test_companion_open_completion_is_allowlisted_diagnostic_only(change):
    value = {"phase": "os-open-completed", "uri_sha256": digest(b"new-uri"), "open_completion": True}
    if change == "raw-uri":
        value["raw_uri"] = "new-synthetic-private-uri"
    elif change == "wrong-uri":
        value["uri_sha256"] = digest(b"new-other-uri")
    elif change == "nonbool-completion":
        value["open_completion"] = 1
    result = safe_ios_dispatcher(json.dumps(value).encode(), digest(b"new-uri"))
    assert result["state"] == (
        "unmeasured" if change in {"raw-uri", "nonbool-completion"} else "diagnostic-only"
    )
    if result["state"] == "diagnostic-only":
        assert result["uri_matches"] is (change is None)
    assert "new-synthetic-private-uri" not in json.dumps(result)
    assert "passed" not in json.dumps(result)


@pytest.mark.skipif(sys.platform != "darwin", reason="requires public local Swift compiler; no simulator")
def test_actual_swift_dispatcher_parser_accepts_only_bound_synthetic_uri_fields(tmp_path):
    from urllib.parse import urlencode

    source = Path(__file__).resolve().parent / "fixtures/runtime/transport/UrlDispatcher.swift"
    function = source.read_text().split("func validatedDispatcherURL", 1)[1].split("@main", 1)[0]
    scheme = "a" + "1" * 32
    session = {
        "action": "session",
        "session": "b" * 64,
        "backend": "http://127.0.0.1:1234",
        "retain": "false",
    }
    capture = {
        "action": "capture",
        "session": "b" * 64,
        "nonce": "c" * 64,
        "snapshot": "before",
        "account": "a",
        "state": "authenticated",
        "transition": "",
    }
    transition = {"action": "transition", "session": "b" * 64, "kind": "logout"}

    def make(fields):
        return scheme + "://fixture?" + urlencode(fields)

    valid = [
        make(session),
        make(capture),
        make(transition),
        make({**capture, "snapshot": "after", "account": "", "state": "logged_out", "transition": "logout"}),
    ]
    invalid = [
        make({**session, "backend": "http://example.invalid:1234"}),
        make({**session, "backend": "https://127.0.0.1:1234"}),
        make({**session, "session": "g" * 64}),
        make({**session, "retain": "TRUE"}),
        make({**session, "token": "new-synthetic-private-token"}),
        make({**session, "unknown": "x"}),
        make(session) + "&action=session",
        make(session) + "#fragment",
        make(session).replace("://fixture?", "://fixture/path?"),
        make(session).replace("://fixture?", "://user@fixture?"),
        make(session).replace("://fixture?", "://fixture:1234?"),
        make(session).replace("://fixture?", "://other?"),
        make(session).replace(scheme, "https", 1),
        make(session).replace(scheme, "a" + "2" * 32, 1),
        make({**capture, "nonce": ""}),
        make({**capture, "snapshot": "unsupported"}),
        make({**capture, "account": "other"}),
        make({**transition, "kind": "other"}),
        make({**session, "session": "b" * 513}),
        make(session) + "&x=" + "x" * 4096,
        make({key: value for key, value in capture.items() if key != "nonce"}),
    ]
    cases = [
        {"url": url, "expected": expected}
        for expected, urls in [(True, valid), (False, invalid)]
        for url in urls
    ]
    fixture = tmp_path / "new-dispatcher-boundaries.json"
    fixture.write_text(json.dumps(cases))
    program = tmp_path / "new-parser.swift"
    program.write_text(
        "import Foundation\nfunc validatedDispatcherURL"
        + function
        + "\nlet cases = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))) as! [[String: Any]]\n"
        + "var passed = 0\nfor value in cases {\n"
        + 'let accepted = validatedDispatcherURL(value["url"] as! String, scheme: "'
        + scheme
        + '") != nil\n'
        + 'if accepted != value["expected"] as! Bool { exit(1) }; passed += 1\n}\nprint(passed)\n'
    )
    binary = tmp_path / "new-parser"
    compiled = subprocess.run(
        [
            "/usr/bin/xcrun",
            "swiftc",
            "-swift-version",
            "6",
            "-strict-concurrency=complete",
            str(program),
            "-o",
            str(binary),
            "-module-cache-path",
            str(tmp_path / "new-module-cache"),
        ],
        capture_output=True,
        timeout=60,
    )
    assert compiled.returncode == 0, compiled.stderr.decode(errors="replace")
    result = subprocess.run([str(binary), str(fixture)], capture_output=True, timeout=10)
    assert result.returncode == 0 and result.stdout.strip() == str(len(cases)).encode()


def test_ios_unsupported_libproc_cannot_be_reported_as_owned_process_exit(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setattr("scripts.validate_runtime_transport.platform.system", lambda: "Darwin")
    monkeypatch.setattr("scripts.validate_runtime_transport.os.kill", lambda *a: None)

    def unsupported(*a, **kw):
        raise ProcessLookupError("new synthetic unsupported libproc")

    monkeypatch.setattr(ctypes, "CDLL", unsupported)
    assert ios_process_identity(321, tmp_path / "new-app")["state"] == "unmeasured"


def test_generated_companion_registers_no_scheme_and_verifies_installed_bytes(tmp_path, monkeypatch):
    target = IosTarget.__new__(IosTarget)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.package = "apsa.fixture.new"
    target.url_driver = "companion"
    target.scheme = "a" + "1" * 32
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "new-set")]
    target.commands = Commands(tmp_path, env={})
    calls = []
    monkeypatch.setattr(target, "require_installed_contract", lambda **kwargs: None)

    def fixture_build(argv, **kw):
        calls.append(argv)
        if "swiftc" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"new synthetic helper executable")
        return b""

    monkeypatch.setattr(target.commands, "run", fixture_build)
    monkeypatch.setattr(target, "container", lambda kind, **kw: tmp_path / "UrlDispatcher.app")
    target.install_dispatcher(tmp_path, "/new-public-sdk", "arm64")
    value = plistlib.loads((tmp_path / "UrlDispatcher.app/Info.plist").read_bytes())
    assert value["CFBundleIdentifier"] == target.package + ".dispatcher"
    assert value["APSAFixtureScheme"] == target.scheme
    assert "CFBundleURLTypes" not in value
    assert value["LSApplicationQueriesSchemes"] == [target.scheme]
    assert (
        safe_ios_installed_contract(plistlib.dumps(value), target.helper_package, target.scheme, helper=True)[
            "state"
        ]
        == "verified"
    )
    install = next(call for call in calls if "install" in call)
    assert target.device in install and install[:4] == target.simctl
    assert target.helper_installed_build() == target.helper_build
    (tmp_path / "UrlDispatcher.app/UrlDispatcher").write_bytes(b"new synthetic wrong installed bytes")
    with pytest.raises(ValueError, match="installed iOS dispatcher differs"):
        target.dispatch("new owned URI")


@pytest.mark.parametrize("diagnostic", ["help-timeout", "help-os-error", "appinfo-timeout", "plutil-timeout"])
@pytest.mark.parametrize("primary_timeout", [False, True, "launch"])
@pytest.mark.parametrize("selector", ["custom", "default"])
def test_ios_constructor_proceeds_past_only_noncritical_diagnostic_failure(
    tmp_path, monkeypatch, diagnostic, primary_timeout, selector
):
    commands = Commands(tmp_path, env={})
    commands.resources = OwnedResources(tmp_path)
    device = "11111111-2222-3333-4444-555555555555"
    package = "apsa.fixture.new.case0"
    device_set = tmp_path / ("simulator-set" if selector == "custom" else "new-default-set-stand-in")
    owned = device_set / device
    app, data = owned / "new-app/TransportFixture.app", owned / "new-data"
    calls = []
    terminated = False

    def process_identity(*args):
        return {"state": "exited" if terminated else "live-verified"}

    def new_public_tool(argv, **kwargs):
        nonlocal terminated
        calls.append(argv)
        if "simctl" in argv:
            assert ("--set" in argv) is (selector == "custom")
            assert "list" not in argv and "booted" not in argv
            if "create" not in argv and "help" not in argv:
                assert device in argv
                assert commands.resources is not None
                assert commands.resources.value["ios"][device]["selector"] == selector
        if "--show-sdk-path" in argv:
            raw = b"/new-public-sdk"
        elif "swiftc" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"new target executable")
            raw = b""
        elif "create" in argv:
            raw = device.encode()
        elif "install" in argv:
            app.mkdir(parents=True)
            (data / "Documents").mkdir(parents=True)
            source = Path(argv[-1])
            for name in ("TransportFixture", "Info.plist"):
                (app / name).write_bytes((source / name).read_bytes())
            raw = b""
        elif "get_app_container" in argv:
            raw = str(app if argv[-1] == "app" else data).encode()
        elif "help" in argv:
            if diagnostic == "help-timeout":
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"", stderr=b"")
            if diagnostic == "help-os-error":
                raise FileNotFoundError("new synthetic public tool unavailable")
            raw = b"new public command help"
        elif "appinfo" in argv:
            if diagnostic == "appinfo-timeout":
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"", stderr=b"")
            raw = (
                b"new unsupported OpenStep stand-in"
                if diagnostic == "plutil-timeout"
                else json.dumps({"CFBundleIdentifier": package}).encode()
            )
        elif argv[0] == "/usr/bin/plutil":
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"", stderr=b"")
        elif "launch" in argv:
            if primary_timeout == "launch":
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"", stderr=b"")
            value = synthetic_ios_events()
            value["events"] = [{"sequence": 1, "phase": "scene-active", "main_thread": True}]
            (data / "Documents/events.json").write_text(json.dumps(value))
            (data / "Documents/stage.txt").write_text("scene-active")
            raw = (package + ": 321\n").encode()
        elif "terminate" in argv:
            terminated = True
            raw = b""
        elif "openurl" in argv:
            if primary_timeout:
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"", stderr=b"")
            fields = {key: values[0] for key, values in parse_qs(urlparse(argv[-1]).query).items()}
            response = {**fields, "delivery_lifecycle": "cold-url-context"}
            (data / "Documents/response.json").write_text(json.dumps(response))
            value = synthetic_ios_events()
            value["launch_epoch_sha256"] = digest(b"new post-termination process")
            value["events"][1].update(
                {
                    "action": "session",
                    "lifecycle": "cold-url-context",
                    "uri_sha256": digest(argv[-1].encode()),
                    "session_sha256": digest(fields["session"].encode()),
                    "nonce_sha256": None,
                }
            )
            (data / "Documents/events.json").write_text(json.dumps(value))
            raw = b""
        else:
            raw = b""
        return SimpleNamespace(returncode=0, stdout=raw, stderr=b"")

    monkeypatch.setattr(subprocess, "run", new_public_tool)
    monkeypatch.setattr("scripts.validate_runtime_transport.ios_process_identity", process_identity)
    monkeypatch.setattr("scripts.validate_runtime_transport.ios_default_set", lambda env: device_set)
    runtime = IOS_PINNED_RUNTIME if selector == "default" else "new-runtime"
    device_type = IOS_PINNED_DEVICE_TYPE if selector == "default" else "new-device-type"
    if primary_timeout == "launch":
        with pytest.raises(CommandFailure) as caught:
            IosTarget(
                tmp_path / "new-build", package, commands, runtime, device_type, device_set_mode=selector
            )
        assert caught.value.reason == "command-timeout"
        assert commands.pre_cleanup_failure is not None
        assert commands.pre_cleanup_failure["reason"] == "command-timeout"
        assert commands.pre_cleanup_failure["process_entry"]["state"] == "absent"
        assert not any(("openurl" in call or "terminate" in call) and "help" not in call for call in calls)
        return
    target = IosTarget(
        tmp_path / "new-build", package, commands, runtime, device_type, device_set_mode=selector
    )
    assert target.process_observations["after_terminate"]["state"] == "exited"
    assert any("launch" in call for call in calls)
    if diagnostic.startswith("help"):
        assert sum("help" in call for call in calls) == 1
        assert target.tool_help["launch"]["state"] == "unmeasured"
        assert target.tool_help["terminate"]["reason"] == "not-attempted-after-diagnostic-failure"
    elif diagnostic == "appinfo-timeout":
        assert target.registration["state"] == "unmeasured" and target.registration["timed_out"] is True
    else:
        assert target.registration["conversion"]["state"] == "unmeasured"
    if diagnostic.endswith("timeout"):
        record = next(record for record in commands.records if record.get("timed_out"))
        assert (
            record["status"] is None
            and record["stdout_sha256"] == digest(b"")
            and record["stderr_sha256"] == digest(b"")
        )
    expected = {
        "action": "session",
        "session": "1" * 64,
        "backend": "http://127.0.0.1:1234",
        "retain": "false",
    }
    url = "apsatransport://fixture?" + urlencode(expected)
    if primary_timeout:
        with pytest.raises(CommandFailure) as caught:
            target.deliver(url, expected)
        assert caught.value.reason == "command-timeout"
        assert target.delivery_observations == []
        assert commands.records[-1]["operation"] == "ios-simctl-openurl"
    else:
        target.deliver(url, expected)
        assert len(target.delivery_observations) == 1
        assert (
            target.delivery_observations[0]["callback_events"]["receipts"][0]["matches_expected_dispatch"]
            is True
        )


def test_ios_diagnostic_wrapper_cannot_swallow_primary_command_or_arbitrary_metadata(tmp_path, monkeypatch):
    target = IosTarget.__new__(IosTarget)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.package = "apsa.fixture.new"
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "new-set")]
    target.commands = Commands(tmp_path, env={})
    monkeypatch.setattr(target.commands, "run", lambda *a, **kw: pytest.fail("forbidden diagnostic command"))
    for tail in [
        ["launch", target.device, target.package],
        ["openurl", target.device, "new-uri"],
        ["appinfo", target.device, "other-package"],
    ]:
        with pytest.raises(ValueError, match="diagnostic command scope differs"):
            target.diagnostic_command(target.simctl + tail, timeout=10)


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "missing-receipt",
        "missing-warm-receipt",
        "wrong-nonce",
        "stale-cold",
        "http-event",
        "wrong-rejection",
        "wrong-build",
        "unverified-exit",
    ],
)
def test_ios_noncredential_control_requires_bound_warm_then_fresh_cold_rejection(
    tmp_path, monkeypatch, mutation
):
    target = IosTarget.__new__(IosTarget)
    target.device = "11111111-2222-3333-4444-555555555555"
    target.package = "apsa.fixture.new.control"
    target.scheme = "a" + "1" * 32
    target.readiness_only = True
    target.url_driver, target.device_set_mode = "simctl", "custom"
    target.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(tmp_path / "new-set")]
    target.commands = Commands(tmp_path, env={})
    target.installed = tmp_path / "new-app"
    target.response = tmp_path / "response.json"
    target.events_path = tmp_path / "events.json"
    target.stage_path = tmp_path / "stage.txt"
    target.build = {"executable_sha256": digest(b"new executable"), "info_plist_sha256": digest(b"new plist")}
    target.readiness_epoch = digest(b"initial NEW process")
    target.owned_pid = 321
    target.process_observations = {"initial": {"state": "live-verified"}}
    target.delivery_observations = []
    target.events_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "complete": True,
                "launch_epoch_sha256": target.readiness_epoch,
                "events": [{"sequence": 1, "phase": "scene-active", "main_thread": True}],
            }
        )
    )
    target.stage_path.write_text("scene-active")
    monkeypatch.setattr(target, "installed_build", lambda: target.build)
    monkeypatch.setattr(target, "entry_observation", lambda **kwargs: {"state": "unmeasured"})
    clock = [0]
    monkeypatch.setattr("scripts.validate_runtime_transport.time.monotonic", lambda: clock[0])
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.time.sleep", lambda seconds: clock.__setitem__(0, clock[0] + 100)
    )
    terminated = [False]
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.ios_process_identity",
        lambda pid, path: {
            "state": "exited" if terminated[0] and mutation != "unverified-exit" else "live-verified",
        },
    )
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        assert argv == target.simctl + ["terminate", target.device, target.package]
        terminated[0] = True
        return b""

    monkeypatch.setattr(target.commands, "run", command)
    urls = []

    def dispatch(url):
        urls.append(url)
        fields = {
            key: values[0] for key, values in parse_qs(urlparse(url).query, keep_blank_values=True).items()
        }
        assert set(fields) == {"action", "session", "nonce", "snapshot", "account", "state", "transition"}
        assert fields["action"] == "capture" and "backend" not in fields
        cold = len(urls) == 2
        lifecycle = "cold-url-context" if cold else "warm-url-context"
        value = synthetic_ios_events()
        value["launch_epoch_sha256"] = (
            digest(b"NEW cold process") if cold and mutation != "stale-cold" else target.readiness_epoch
        )
        value["events"][1].update(
            {
                "action": "capture",
                "lifecycle": lifecycle,
                "uri_sha256": digest(url.encode()),
                "session_sha256": digest(fields["session"].encode()),
                "nonce_sha256": digest(fields["nonce"].encode()),
            }
        )
        value["events"].append({"sequence": 4, "phase": "failure-session-binding", "main_thread": False})
        if (cold and mutation == "missing-receipt") or (not cold and mutation == "missing-warm-receipt"):
            value["events"][1] = {"sequence": 2, "phase": "url-received", "main_thread": True}
        if cold and mutation == "wrong-nonce":
            value["events"][1]["nonce_sha256"] = digest(b"different nonce")
        if cold and mutation == "http-event":
            value["events"].append({"sequence": 5, "phase": "http-issue", "main_thread": False})
        target.events_path.write_text(json.dumps(value))
        response = {
            "action": "fixture-error",
            "code": "failure-session-binding",
            "package": target.package,
            **target.build,
            "session": "",
            "account": "",
            "state": "logged_out",
            "delivery": "baseline",
            "delivery_transport": "ios-os-url-context",
            "delivery_lifecycle": lifecycle,
        }
        if cold and mutation == "wrong-rejection":
            response["code"] = "failure-http-issue"
        if cold and mutation == "wrong-build":
            response["executable_sha256"] = digest(b"other executable")
        target.response.write_text(json.dumps(response))

    monkeypatch.setattr(target, "dispatch", dispatch)
    if mutation is None:
        result = target.url_control()
        assert result["state"] == "passed"
        assert [row["lifecycle"] for row in result["control_observations"]] == [
            "warm-url-context",
            "cold-url-context",
        ]
        assert result["acquisition"] == result["backend"] == result["storage"] == "unsupported"
        assert all(
            row["http_events_absent"] and row["session_rejection_observed"]
            for row in result["control_observations"]
        )
        raw = json.dumps(result)
        for url in urls:
            fields = parse_qs(urlparse(url).query)
            assert fields["session"][0] not in raw and fields["nonce"][0] not in raw and url not in raw
    else:
        with pytest.raises(FixtureFailure) as caught:
            target.url_control()
        assert len(caught.value.observation["control_observations"]) == (
            0 if mutation == "missing-warm-receipt" else 1
        )
        assert len(urls) == (1 if mutation in {"unverified-exit", "missing-warm-receipt"} else 2)
    assert calls == (
        []
        if mutation == "missing-warm-receipt"
        else [target.simctl + ["terminate", target.device, target.package]]
    )
    assert target.delivery_observations == []


@pytest.mark.parametrize("platform_name", ["android", "backend"])
def test_ios_url_control_cli_rejects_other_platforms_before_any_work(tmp_path, monkeypatch, platform_name):
    work = tmp_path / "never-created"
    monkeypatch.setattr(
        sys, "argv", ["validator", "--platform", platform_name, "--ios-os-url-control", "--work", str(work)]
    )
    with pytest.raises(SystemExit):
        main()
    assert not work.exists()


@pytest.mark.parametrize("driver", ["simctl", "companion"])
@pytest.mark.parametrize("control_failure", [False, True])
def test_ios_url_control_cli_owns_one_readiness_target_and_skips_acquisition(
    tmp_path, monkeypatch, capsys, driver, control_failure
):
    work = tmp_path / "new-control-work"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "validator",
            "--platform",
            "ios",
            "--ios-os-url-control",
            "--ios-url-driver",
            driver,
            "--work",
            str(work),
        ],
    )
    instances = []

    class NewTargetDouble:
        def __init__(self, root, package, commands, runtime, device_type, **kwargs):
            assert kwargs == {"url_driver": driver, "device_set_mode": "custom", "readiness_only": True}
            assert commands.resources is not None
            assert runtime == IOS_PINNED_RUNTIME and device_type == IOS_PINNED_DEVICE_TYPE
            assert root == work / "case-0"
            self.device = "11111111-2222-3333-4444-555555555555"
            instances.append(self)

        def url_control(self):
            if control_failure:
                raise FixtureFailure(
                    "NEW iOS diagnostic URL control timed out",
                    {
                        "expected_lifecycle": "warm-url-context",
                        "control_observations": [],
                    },
                )
            return {"state": "passed", "acquisition": "unsupported", "backend": "unsupported"}

        def url_contract_diagnostics(self):
            return {}

        def close(self):
            return {"state": "confirmed", "scope": "NEW target double only"}

    monkeypatch.setattr("scripts.validate_runtime_transport.IosTarget", NewTargetDouble)
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.execute_case",
        lambda *args, **kwargs: pytest.fail("acquisition forbidden"),
    )
    monkeypatch.setattr(
        "scripts.validate_runtime_transport.AuthorityServer",
        lambda *args, **kwargs: pytest.fail("HTTP forbidden"),
    )
    if control_failure:
        with pytest.raises(SystemExit) as caught:
            main()
        assert caught.value.code == 1
    else:
        main()
    value = json.loads((work / "evidence.json").read_text())
    assert len(instances) == 1 and len(value["cases"]) == (0 if control_failure else 1)
    assert value["measurement"] == "os-url-diagnostic-control"
    assert value["state"] == ("inconclusive" if control_failure else "passed") and value["terminal"] is True
    if not control_failure:
        assert value["cases"][0]["acquisition"] == "unsupported"
    assert value["cleanup"]["state"] == "confirmed"
    records = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    terminal = next(
        record["runtime_url_control_diagnostic"]
        for record in records
        if "runtime_url_control_diagnostic" in record
    )
    assert terminal["state"] == value["state"] and terminal["terminal"] is True
    assert set(terminal) == {"measurement", "state", "terminal", "cases", "failure_observation", "cleanup"}


def test_ios_url_control_workflow_is_separate_custom_owned_matrix_without_primary_relaxation():
    source = Path(__file__).resolve().parents[1] / ".github/workflows/runtime-transport.yml"
    jobs = yaml.safe_load(source.read_text())["jobs"]
    job = jobs["ios-os-url-control"]
    assert job["runs-on"] == "macos-15"
    assert set(job["strategy"]["matrix"]["driver"]) == {"simctl", "companion"}
    assert "continue-on-error" not in job
    control = next(
        step
        for step in job["steps"]
        if "--ios-os-url-control" in step.get("run", "") and "--cleanup-only" not in step["run"]
    )
    assert "--ios-url-driver" in control["run"] and "--platform ios" in control["run"]
    assert "--ios-runtime " + IOS_PINNED_RUNTIME in control["run"]
    assert "--ios-device-type " + IOS_PINNED_DEVICE_TYPE in control["run"]
    assert "continue-on-error" not in control
    assert all(
        "--ios-device-set default" not in step.get("run", "")
        and "simctl list" not in step.get("run", "")
        and "booted" not in step.get("run", "")
        for step in job["steps"]
    )
    cleanup = next(step for step in job["steps"] if "--cleanup-only" in step.get("run", ""))
    assert cleanup["if"] == "always()" and cleanup["timeout-minutes"] == 5
    for name in ("ios", "ios-app-to-app", "ios-default-set", "ios-app-to-app-default-set"):
        assert all(
            "--ios-os-url-control" not in step.get("run", "") and "continue-on-error" not in step
            for step in jobs[name]["steps"]
        )


def synthetic_installed_ios_contract(package="apsa.fixture.new", scheme="a" + "1" * 32, *, helper=False):
    value = {
        "CFBundleIdentifier": package,
        "CFBundleExecutable": "UrlDispatcher" if helper else "TransportFixture",
        "APSAFixtureScheme": scheme,
        "UIApplicationSceneManifest": {
            "UIApplicationSupportsMultipleScenes": False,
            "UISceneConfigurations": {
                "UIWindowSceneSessionRoleApplication": [
                    {
                        "UISceneConfigurationName": "Default",
                        "UISceneDelegateClassName": "UrlDispatcherFixture.DispatcherScene"
                        if helper
                        else "TransportFixture.SceneDelegate",
                    }
                ]
            },
        },
    }
    if helper:
        value["LSApplicationQueriesSchemes"] = [scheme]
    else:
        value["CFBundleURLTypes"] = [
            {
                "CFBundleTypeRole": "Editor",
                "CFBundleURLName": package + ".transport",
                "CFBundleURLSchemes": [scheme],
            }
        ]
    return value


@pytest.mark.parametrize("helper", [False, True])
@pytest.mark.parametrize("fmt", [plistlib.FMT_XML, plistlib.FMT_BINARY])
def test_installed_ios_contract_validates_exact_typed_package_scheme_scene(helper, fmt):
    package, scheme = "apsa.fixture.new", "a" + "1" * 32
    raw = plistlib.dumps(synthetic_installed_ios_contract(package, scheme, helper=helper), fmt=fmt)
    result = safe_ios_installed_contract(raw, package, scheme, helper=helper)
    assert result["state"] == "verified"
    assert all(
        value is True for key, value in result.items() if key.endswith("matches") or key.endswith("match")
    )
    assert result["sha256"] == digest(raw)
    assert package not in json.dumps(result) and scheme not in json.dumps(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "package",
        "scheme",
        "extra-scheme",
        "url-shape",
        "scene-class",
        "scene-bool",
        "executable",
        "query-scheme",
    ],
)
def test_installed_ios_contract_rejects_mismatched_types_and_registration(mutation):
    value = synthetic_installed_ios_contract()
    if mutation == "package":
        value["CFBundleIdentifier"] = ["apsa.fixture.new"]
    elif mutation == "scheme":
        value["APSAFixtureScheme"] = "new-other-scheme"
    elif mutation == "extra-scheme":
        value["CFBundleURLTypes"][0]["CFBundleURLSchemes"].append("new-other-scheme")
    elif mutation == "url-shape":
        value["CFBundleURLTypes"] = {}
    elif mutation == "scene-class":
        value["UIApplicationSceneManifest"]["UISceneConfigurations"]["UIWindowSceneSessionRoleApplication"][
            0
        ]["UISceneDelegateClassName"] = "New.Other"
    elif mutation == "scene-bool":
        value["UIApplicationSceneManifest"]["UIApplicationSupportsMultipleScenes"] = 0
    elif mutation == "executable":
        value["CFBundleExecutable"] = "new-other-executable"
    else:
        value["LSApplicationQueriesSchemes"] = ["new-other-scheme"]
    assert (
        safe_ios_installed_contract(plistlib.dumps(value), "apsa.fixture.new", "a" + "1" * 32)["state"]
        == "mismatch"
    )


@pytest.mark.parametrize("key", ["APSAFixtureScheme", "UISceneConfigurationName"])
def test_installed_ios_contract_rejects_duplicate_keys_at_any_depth(key):
    raw = plistlib.dumps(synthetic_installed_ios_contract())
    marker = ("<key>" + key + "</key>").encode()
    raw = raw.replace(marker, marker + b"<string>new duplicate</string>" + marker, 1)
    assert (
        safe_ios_installed_contract(raw, "apsa.fixture.new", "a" + "1" * 32)["state"]
        == "malformed-or-over-bound"
    )


@pytest.mark.parametrize(
    "raw", [b"", b"<plist><dict><key>unterminated", b"x" * (65536 + 1), plistlib.dumps([])]
)
def test_installed_ios_contract_rejects_malformed_and_oversized_bytes(raw):
    assert (
        safe_ios_installed_contract(raw, "apsa.fixture.new", "a" + "1" * 32)["state"]
        == "malformed-or-over-bound"
    )


def test_appinfo_omission_is_unreported_and_duplicate_keys_are_unmeasured():
    result = safe_ios_appinfo(b'{"CFBundleIdentifier":"apsa.fixture.new"}', "apsa.fixture.new")
    assert result["url_types_state"] == "unreported"
    assert result["url_types_present"] is None and result["url_types_match"] is None
    assert (
        safe_ios_appinfo(
            b'{"CFBundleIdentifier":"wrong","CFBundleIdentifier":"apsa.fixture.new"}', "apsa.fixture.new"
        )["state"]
        == "unmeasured"
    )


@pytest.mark.parametrize("escape", [None, "symlink", "directory-symlink", "outside", "oversize", "missing"])
def test_installed_contract_reads_only_bounded_exact_owned_plist(tmp_path, monkeypatch, escape):
    target, _ = new_entry_target(tmp_path)
    target.package, target.scheme = "apsa.fixture.new", "a" + "1" * 32
    assert target.device is not None
    target.installed = target.device_set / target.device / "new-app"
    target.installed.mkdir()
    path = target.installed / "Info.plist"
    raw = plistlib.dumps(synthetic_installed_ios_contract())
    path.write_bytes(raw)
    if escape == "symlink":
        outside = tmp_path / "new-outside.plist"
        outside.write_bytes(raw)
        path.unlink()
        path.symlink_to(outside)
    elif escape == "directory-symlink":
        path.unlink()
        target.installed.rmdir()
        outside = tmp_path / "new-outside-app"
        outside.mkdir()
        (outside / "Info.plist").write_bytes(raw)
        target.installed.symlink_to(outside, target_is_directory=True)
    elif escape == "outside":
        target.installed = tmp_path / "new-outside-app"
    elif escape == "oversize":
        path.write_bytes(b"x" * 65537)
    elif escape == "missing":
        path.unlink()
    if escape:
        monkeypatch.setattr(
            "scripts.validate_runtime_transport.os.open", lambda *a: pytest.fail("unsafe read")
        )
    result = target.installed_contract_observation()
    assert result["state"] == (
        "verified"
        if escape is None
        else "malformed-or-over-bound"
        if escape == "oversize"
        else "unavailable"
        if escape == "missing"
        else "owned-path-mismatch"
    )


@pytest.mark.parametrize("state", ["mismatch", "unavailable", "malformed-or-over-bound"])
def test_installed_contract_failure_blocks_dispatch_before_any_os_command(tmp_path, monkeypatch, state):
    target, _ = new_entry_target(tmp_path)
    target.commands = Commands(tmp_path, env={})
    monkeypatch.setattr(target, "installed_contract_observation", lambda **kwargs: {"state": state})
    monkeypatch.setattr(target.commands, "run", lambda *a, **kw: pytest.fail("OS dispatch before contract"))
    with pytest.raises(FixtureFailure, match="installed URL contract differs") as caught:
        target.dispatch("new-synthetic-uri")
    assert caught.value.observation["installed_url_contract"]["state"] == state


@pytest.mark.parametrize("can_open", [True, False, None])
def test_public_runtime_marker_keeps_only_typed_contract_and_dispatch_diagnostics(can_open):
    diagnostic = {
        "installed_url_contract": {
            "state": "verified",
            "sha256": "1" * 64,
            "package_matches": True,
            "scene_matches": 1,
            "raw_path": "new-private-path",
        },
        "dispatcher": {
            "state": "diagnostic-only",
            "phase": "os-open-completed",
            "can_open_url": can_open,
            "open_completion": True,
            "uri_matches": True,
            "raw_uri": "new-private-uri",
        },
        "registration": {"url_types_state": "unreported"},
    }
    projected = ios_url_diagnostic_projection(diagnostic)
    assert projected["dispatcher"].get("can_open_url") is can_open
    assert projected["registration"]["url_types_state"] == "unreported"
    assert "scene_matches" not in projected["installed_url_contract"]
    output = runtime_projection({"state": "inconclusive", "failure_observation": diagnostic})
    assert output["ios_url_diagnostics"] == projected and output["state"] == "inconclusive"
    assert "new-private" not in json.dumps(output)
