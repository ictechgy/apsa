"""Fresh synthetic controls for release evidence and owned resource cleanup."""

import json
import subprocess
from http.client import HTTPMessage
from io import BytesIO
from pathlib import Path
from typing import cast

import pytest

from mobile_audit.output import sarif
from scripts import release, verify_publication
from scripts import validate_runtime_transport as transport
from scripts.action_summary import threshold_exceeded
from scripts.check_sarif import problems


def report(identifier="first", findings=None):
    return {
        "id": identifier,
        "created": identifier,
        "target": "/synthetic/app",
        "tool_version": "same",
        "rule_version": "same",
        "inventory": {
            "input_kind": "source",
            "platforms": ["android"],
            "source_selection": {"module": "app"},
        },
        "coverage": [
            {"rule_id": "ANDROID-CONFIG", "state": "checked"},
            {"rule_id": "AST-SQL-CONCAT", "state": "checked"},
        ],
        "findings": findings or [],
        "summary": {},
        "scope": "synthetic",
        "intel_snapshot": {},
    }


def finding(status="candidate", rule="ANDROID-DEBUG", identifier="F-synthetic"):
    return {
        "id": identifier,
        "rule_id": rule,
        "status": status,
        "severity": "high",
        "title": "Synthetic finding",
        "remediation": "Review evidence",
        "masvs": "MASVS-CODE",
        "evidence": [{"path": "App.java", "line": 1}],
        "references": [],
    }


@pytest.mark.parametrize("threshold", ["High", "hgih", "critical ", "none"])
def test_typo_threshold_is_never_silently_disabled(tmp_path, threshold):
    value = tmp_path / "result.json"
    value.write_text(json.dumps({"data": report(findings=[finding("configuration-confirmed")])}))
    with pytest.raises(SystemExit, match="unsupported fail-on"):
        threshold_exceeded(str(value), threshold)


@pytest.mark.parametrize(
    "uri",
    [
        "../outside.java",
        "file:x",
        "%2e%2e/x",
        "x/%2e%2e/y",
        "//outside/x",
        "./x",
        "https://example.invalid/x",
    ],
)
def test_sarif_checker_rejects_repository_escaping_or_noncanonical_uri(uri):
    document = sarif(report(findings=[finding()]))
    document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri
    assert any("repository-relative" in p for p in problems(json.dumps(document).encode()))


@pytest.mark.parametrize(
    "document", [[], None, {}, {"runs": [None]}, {"version": "2.1.0", "runs": [{"tool": None}]}]
)
def test_sarif_structural_errors_return_diagnostics(document):
    assert problems(json.dumps(document).encode())


@pytest.mark.parametrize("mutation", ["state", "failures", "checked", "empty", "bool", "ok"])
def test_smoke_integrity_payload_must_demonstrate_success(mutation):
    value = {"ok": True, "data": {"state": "passed", "failures": [], "checked": 1}}
    if mutation == "state":
        value["data"]["state"] = "failed"
    elif mutation == "failures":
        value["data"]["failures"] = ["synthetic mismatch"]
    elif mutation == "checked":
        value["data"]["checked"] = 0
    elif mutation == "empty":
        value["data"] = {}
    elif mutation == "bool":
        value["data"]["checked"] = True
    else:
        value["ok"] = False
    with pytest.raises(RuntimeError, match="integrity"):
        release.smoke_report_verification(value)


def test_smoke_offline_claim_is_derived_from_both_reports():
    offline = {"online_query": {"requested": False}}
    assert release.smoke_network_requested(offline, offline) is False
    for value in ({}, {"online_query": {"requested": True}}, {"online_query": {}}):
        with pytest.raises(RuntimeError, match="offline"):
            release.smoke_network_requested(offline, value)


@pytest.mark.parametrize("actual,expected", [(3, None), (1, 3), (2, 3), (0, 3), (4, 3)])
def test_release_run_rejects_every_unexpected_process_exit(tmp_path, monkeypatch, actual, expected):
    monkeypatch.setattr(
        release.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], actual, "synthetic output", ""),
    )
    kwargs = {} if expected is None else {"expected_exit_code": expected}
    with pytest.raises(RuntimeError, match="Command failed"):
        release.run(["synthetic-command"], tmp_path, {}, **kwargs)


@pytest.mark.parametrize("expected", [0, 3])
def test_release_run_requires_the_exact_requested_process_exit(tmp_path, monkeypatch, expected):
    monkeypatch.setattr(
        release.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args[0], expected, "synthetic output", ""),
    )
    assert release.run(["synthetic-command"], tmp_path, {}, expected_exit_code=expected) == "synthetic output"


def binary_smoke_payload():
    return {
        "ok": False,
        "exit_code": 3,
        "data": {
            "summary": {"incomplete": True, "partial": 1},
            "inventory": {
                "input_kind": "apk",
                "partial": True,
                "credential_text": {"collection_enabled": True, "partial": True, "omitted_files": 1},
            },
            "coverage": [{"rule_id": "PACKAGED-CREDENTIAL-TEXT", "state": "partial"}],
            "findings": [],
        },
    }


def test_binary_smoke_keeps_explicit_incomplete_credential_coverage():
    value = binary_smoke_payload()
    assert release.smoke_binary_report(value) is value["data"]
    assert value["exit_code"] == 3 and value["data"]["summary"]["incomplete"] is True


@pytest.mark.parametrize(
    "section,key,value",
    [
        ("envelope", "exit_code", 0),
        ("envelope", "exit_code", True),
        ("envelope", "ok", True),
        ("envelope", "data", []),
        ("report", "summary", []),
        ("summary", "incomplete", False),
        ("summary", "partial", True),
        ("summary", "partial", 0),
        ("summary", "partial", 2),
        ("report", "inventory", []),
        ("inventory", "input_kind", "source"),
        ("inventory", "partial", False),
        ("inventory", "credential_text", []),
        ("credential", "collection_enabled", False),
        ("credential", "partial", False),
        ("credential", "omitted_files", 0),
        ("credential", "omitted_files", True),
        ("report", "coverage", {}),
        ("report", "coverage", [None]),
        ("report", "coverage", []),
        ("report", "coverage", [{"rule_id": "PACKAGED-CREDENTIAL-TEXT", "state": "checked"}]),
        ("report", "coverage", [{"rule_id": "UNRELATED-RULE", "state": "partial"}]),
        (
            "report",
            "coverage",
            [
                {"rule_id": "PACKAGED-CREDENTIAL-TEXT", "state": "partial"},
                {"rule_id": "UNRELATED-RULE", "state": "partial"},
            ],
        ),
        ("report", "findings", {}),
    ],
)
def test_binary_smoke_rejects_wrong_exit_schema_or_partial_reason(section, key, value):
    payload = binary_smoke_payload()
    report = payload["data"]
    target = {
        "envelope": payload,
        "report": report,
        "summary": report["summary"],
        "inventory": report["inventory"],
        "credential": report["inventory"]["credential_text"],
    }[section]
    target[key] = value
    with pytest.raises(RuntimeError, match="partial credential-text evidence"):
        release.smoke_binary_report(payload)


@pytest.mark.parametrize("value", [None, [], {}, {"exit_code": 3, "ok": False}])
def test_binary_smoke_rejects_missing_report_envelope(value):
    with pytest.raises(RuntimeError, match="partial credential-text evidence"):
        release.smoke_binary_report(value)


@pytest.mark.parametrize("failure", ["timeout", "invalid-uuid"])
def test_create_failure_survives_empty_journal_and_cannot_confirm_cleanup(tmp_path, monkeypatch, failure):
    commands = transport.Commands(tmp_path, env={})
    resources = transport.OwnedResources(tmp_path)
    commands.resources = resources

    def run(argv, **kwargs):
        if "--show-sdk-path" in argv:
            return b"/fresh/synthetic-sdk"
        if "swiftc" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"fresh synthetic executable")
        if "create" in argv:
            if failure == "timeout":
                raise transport.CommandFailure("command-timeout", {})
            return b"not-a-uuid"
        return b""

    monkeypatch.setattr(commands, "run", run)
    with pytest.raises((ValueError, transport.CommandFailure)):
        transport.IosTarget(
            tmp_path / "generated", "apsa.fixture.new.case0", commands, "synthetic-runtime", "synthetic-type"
        )
    assert resources.value["ios"] == {}
    cleanup = transport.cleanup_owned(tmp_path, commands, resources)
    assert cleanup["state"] == "unconfirmed"
    assert transport.acquisition_cleanup_state(resources.value, [cleanup])["state"] == "unconfirmed"
    assert commands.pre_cleanup_failure is not None
    assert commands.pre_cleanup_failure["constructor_cleanup"]["state"] == "unconfirmed"


def test_pending_creation_remains_unconfirmed_after_journal_reload(tmp_path):
    resources = transport.OwnedResources(tmp_path)
    (tmp_path / "ios-create-pending.json").write_text('{"state":"unconfirmed"}')
    reloaded = transport.OwnedResources(tmp_path, load=True)
    commands = transport.Commands(tmp_path, env={})
    assert transport.cleanup_owned(tmp_path, commands, reloaded)["state"] == "unconfirmed"
    assert resources.value["ios"] == {}


def test_shutdown_timeout_does_not_skip_owned_delete(tmp_path, monkeypatch):
    resources = transport.OwnedResources(tmp_path)
    device = "11111111-2222-4333-8444-555555555555"
    resources.ios(device)
    commands = transport.Commands(tmp_path, env={})
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if "shutdown" in argv:
            raise transport.CommandFailure("command-timeout", {})
        commands.last_status = 0
        return b""

    monkeypatch.setattr(commands, "run", run)
    result = transport.cleanup_owned(tmp_path, commands, resources)
    assert any("delete" in argv for argv in calls)
    assert result["state"] == "confirmed"
    assert resources.value["ios"][device]["deleted"] is True


def test_duplicate_ios_event_keys_never_become_valid_diagnostics():
    from tests.test_runtime_transport import safe_ios_events

    raw = (
        b'{"schema_version":1,"complete":false,"complete":true,"events":[],"launch_epoch_sha256":"'
        + b"a" * 64
        + b'"}'
    )
    assert safe_ios_events(raw)["state"] == "malformed-or-over-bound"


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/x",
        "https://example.invalid/x",
        "https://user@github.com/x",
        "https://github.com:444/x",
    ],
)
def test_publication_redirect_revalidates_origin(url):
    from urllib.request import Request

    request = Request(
        "https://api.github.com/repos/synthetic",
        headers={"Authorization": "Bearer synthetic-not-a-credential"},
    )
    with pytest.raises(ValueError, match="origin"):
        verify_publication.PublicRedirect().redirect_request(request, BytesIO(), 302, "", HTTPMessage(), url)


def test_publication_redirect_drops_authorization_across_allowed_hosts():
    from urllib.request import Request

    request = Request(
        "https://api.github.com/repos/synthetic",
        headers={"Authorization": "Bearer synthetic-not-a-credential"},
    )
    redirect = verify_publication.PublicRedirect().redirect_request(
        request, BytesIO(), 302, "", HTTPMessage(), "https://release-assets.githubusercontent.com/synthetic"
    )
    assert redirect is not None
    assert redirect.get_header("Authorization") is None
    assert redirect.full_url == "https://release-assets.githubusercontent.com/synthetic"


@pytest.mark.parametrize("stop_status", [0, 1])
def test_android_cleanup_requires_owned_emulator_stop_not_only_launcher_exit(
    tmp_path, monkeypatch, stop_status
):
    from types import SimpleNamespace

    commands = transport.Commands(tmp_path, env={})
    resources = transport.OwnedResources(tmp_path)
    commands.resources = resources
    name = "apsa-new-" + "a" * 32
    resources.android(avd=name, sdk=str(tmp_path / "sdk"), emulator=True)

    def run(argv, **kwargs):
        commands.last_status = stop_status if "emu" in argv else 0
        return b""

    monkeypatch.setattr(commands, "run", run)
    device = transport.NewAndroidDevice.__new__(transport.NewAndroidDevice)
    device.sdk, device.commands, device.name = tmp_path / "sdk", commands, name
    device.adb_prefix = ["synthetic-adb", "-s", "owned"]
    # This successful owned-process control exercises only Popen.wait; no OS
    # process is launched and the timeout/escalation controls are separate.
    device.process = cast(subprocess.Popen[bytes], SimpleNamespace(wait=lambda **kwargs: 0))
    device.adb_started = False
    result = device.close()
    assert resources.value["android"]["emulator_closed"] is (stop_status == 0)
    assert result["state"] == ("confirmed" if stop_status == 0 else "unconfirmed")


def test_delete_timeout_still_attempts_other_owned_simulators(tmp_path, monkeypatch):
    resources = transport.OwnedResources(tmp_path)
    devices = ["11111111-2222-4333-8444-555555555555", "66666666-2222-4333-8444-555555555555"]
    for device in devices:
        resources.ios(device)
    commands = transport.Commands(tmp_path, env={})
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if "delete" in argv and argv[-1] == devices[0]:
            raise transport.CommandFailure("command-timeout", {})
        commands.last_status = 0
        return b""

    monkeypatch.setattr(commands, "run", run)
    result = transport.cleanup_owned(tmp_path, commands, resources)
    assert [argv[-1] for argv in calls if "delete" in argv] == devices
    assert result["state"] == "unconfirmed"
    assert resources.value["ios"][devices[0]]["deleted"] is False
    assert resources.value["ios"][devices[1]]["deleted"] is True
