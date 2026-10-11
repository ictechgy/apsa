"""New in-memory synthetic protocol tests. No sockets, devices or user files."""

import io
import json
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
from scripts.validate_runtime_transport import CommandFailure, Commands, failure_observation, scenario


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
