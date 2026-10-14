"""Bound account-switch protocol controls; new in-memory fixtures, no sockets/SDK/UI."""

import copy
import json
import sys
from urllib.parse import parse_qs, urlparse

import pytest

from mobile_audit.core import digest
from mobile_audit.runtime_acquisition import (
    AcquisitionRecorder,
    CaptureRequest,
    evaluate_backend_invalidation,
)
from mobile_audit.runtime_evidence import build_binding, evaluate_workflow, validate_workflow
from scripts import validate_runtime_transport as driver
from tests.support.runtime_transport import InstalledTransportAdapter, OwnedAuthority
from tests.test_runtime_transport import NewMemoryTarget, server_without_socket


class NewSwitchTarget(NewMemoryTarget):
    """Model native fixture requests in memory; HTTP authority decides credentials."""

    def __init__(self, platform, authority):
        super().__init__(platform, authority)
        self.delivery_observations = []
        self.change_receipt = None
        self.no_b_authentication = False
        self.ambiguous = False
        self.partial = False

    def deliver(self, url, expected):
        fields = {
            key: value[0] for key, value in parse_qs(urlparse(url).query, keep_blank_values=True).items()
        }
        if fields["action"] == "session" or (fields["action"] == "capture" and not self.after):
            response = super().deliver(url, expected)
        else:
            body = {"session": fields["session"], "package": self.package, "build": self.authority.build}
            if fields["action"] == "transition":
                assert fields["kind"] == "account_switch"
                body["to_account"] = "b"
                status, raw = self.authority.handle(
                    "/switch", "Bearer " + self.credential, json.dumps(body).encode()
                )
                assert status == 200
                self.credential = json.loads(raw)["credential"]
                self.after = True
                body.pop("to_account")
            nonce = fields.get("nonce", "e" * 64)
            body.update(account="b", nonce=nonce)
            if not self.no_b_authentication:
                status, raw = self.authority.handle(
                    "/protected", "Bearer " + self.credential, json.dumps(body).encode()
                )
                assert status == 200 and json.loads(raw) == {
                    "outcome": "accepted",
                    "account": "b",
                    "nonce": nonce,
                }
            response = {
                **fields,
                **self.build,
                "package": self.package,
                "account": "b",
                "state": "authenticated",
                "delivery": "target-observed",
                "delivery_transport": "android-os-intent"
                if self.platform == "android"
                else "ios-os-url-context",
                "completeness": "partial" if self.partial else "complete",
                "storage": "synthetic-unique-b synthetic-unique-login_b synthetic-unique-state synthetic-unique-delivery"
                + (" synthetic-unique-a" if self.retained else "")
                + (" synthetic-unique-login_a" if self.ambiguous else ""),
                "account_authentication": {
                    "account": "b",
                    "credential_sha256": digest(self.credential.encode()),
                    "nonce_sha256": digest(nonce.encode()),
                },
            }
        if self.change_receipt:
            self.change_receipt(response)
        if self.platform == "ios":
            self.delivery_observations.append(
                {
                    "action": fields["action"],
                    "lifecycle": "cold-url-context" if fields["action"] == "session" else "warm-url-context",
                    "session_sha256": digest(fields["session"].encode()),
                    "capture_nonce_sha256": digest(fields["nonce"].encode()) if "nonce" in fields else None,
                    "response_sha256": digest(json.dumps(response).encode()),
                    "response_bytes": 1,
                }
            )
        return response


def new_switch(platform, retain, monkeypatch):
    authority = OwnedAuthority("apsa.fixture.newswitch", "1" * 64, invalidate=True)
    target = NewSwitchTarget(platform, authority)
    server = server_without_socket(authority, monkeypatch)
    adapter = InstalledTransportAdapter(target, server, retain=retain, transition_kind="account_switch")
    scenario = driver.scenario(platform, target.package, "account_switch")
    validate_workflow(scenario, {"before": 0, "after": 2})
    recorder = AcquisitionRecorder(
        adapter, build_binding(platform, target.package, target.build), scenario["markers"]
    )
    return authority, target, adapter, recorder, scenario


@pytest.mark.parametrize("platform", ["android", "ios"])
@pytest.mark.parametrize("retain", [False, True])
def test_switch_is_authenticated_b_with_old_a_replay_and_unambiguous_markers(platform, retain, monkeypatch):
    authority, target, adapter, recorder, scenario = new_switch(platform, retain, monkeypatch)
    before = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    old_credential = authority.credential
    adapter.open_url("synthetic://transition")
    after = recorder.capture("after", {"account": "b", "state": "authenticated"}, "account_switch")
    snapshots = {"before": before, "after": after}
    assert evaluate_workflow(scenario, snapshots, recorder.binding)[0]["state"] == "passed"
    assert evaluate_backend_invalidation(scenario, snapshots) == []
    assert driver.old_account_switch_replay(before, after)[0]["state"] == "passed"
    assert authority.credential == old_credential and authority.b_credential != old_credential
    assert authority.switched and authority.b_active and not authority.active and not authority.logged_out
    assert (
        before["backend_probe"]["credential_sha256"]
        == after["backend_probe"]["credential_sha256"]
        == digest(old_credential.encode())
    )
    assert (
        before["backend_probe"]["outcome"] == "accepted" and after["backend_probe"]["outcome"] == "rejected"
    )
    labels = {match["marker_label"] for match in after["matches"]}
    assert {"b", "login_b", "state", "delivery"}.issubset(labels)
    assert "login_a" not in labels and ("a" in labels) is retain
    assert after["surfaces"]["storage"]["completeness"] == "complete"
    assert len(authority.b_authentication_nonces) == 2
    assert [event["route"] for event in authority.events] == [
        "/issue",
        "/protected",
        "/switch",
        "/protected",
        "/protected",
        "/protected",
    ]
    if platform == "ios":
        assert driver.ios_delivery_complete(target.delivery_observations, before, after)
    persisted = json.dumps({"before": before, "after": after, "events": authority.events})
    assert (
        old_credential not in persisted
        and authority.b_credential not in persisted
        and authority.session not in persisted
    )
    assert all(marker not in persisted for marker in scenario["markers"].values())


@pytest.mark.parametrize("platform", ["android", "ios"])
@pytest.mark.parametrize("retain", [False, True])
def test_installed_case_records_switch_separately_without_backend_or_storage_confusion(
    platform, retain, monkeypatch
):
    targets = []

    def factory(authority):
        target = targets[0]
        target.authority = authority
        server = server_without_socket(authority, monkeypatch)
        server.close = lambda: None
        return server

    placeholder = OwnedAuthority("apsa.fixture.newswitch", "1" * 64, invalidate=True)
    target = NewSwitchTarget(platform, placeholder)
    targets.append(target)
    monkeypatch.setattr(driver, "AuthorityServer", factory)
    evidence = driver.execute_case(target, invalidate=True, retain=retain, transition_kind="account_switch")
    assert evidence["state"] == "passed" and evidence["authority_cleanup"] == "confirmed"
    assert evidence["source_version"] == driver.RUNTIME_CONTROL_SOURCE_VERSION
    assert evidence["transition_kind"] == "account_switch"
    assert all(evidence["verified_fields"].values())
    assert evidence["storage"][0]["state"] == ("failed" if retain else "passed")
    assert evidence["backend"][0]["state"] == "passed"
    assert evidence["authority_event_counts"]["/switch"] == 1
    assert evidence["authority_event_counts"]["/logout"] == 0


@pytest.mark.parametrize("field", ["session", "package", "build", "to_account", "extra", "authorization"])
def test_switch_rejects_unbound_or_wrong_account_issuance(field):
    authority = OwnedAuthority("apsa.fixture.newswitch", "1" * 64, invalidate=True)
    authority.bind("a" * 64)
    body = {"session": authority.session, "package": authority.package, "build": authority.build}
    assert authority.handle("/issue", "", json.dumps(body).encode())[0] == 200
    body["to_account"] = "b"
    authorization = "Bearer " + authority.credential
    if field == "authorization":
        authorization = "Bearer NEW-wrong-token"
    elif field == "extra":
        body["extra"] = "new-value"
    else:
        body[field] = "wrong"
    assert authority.handle("/switch", authorization, json.dumps(body).encode())[0] == 403
    assert not authority.switched and not authority.b_credential and authority.active


def test_switch_cannot_reuse_or_replace_old_a_replay_credential():
    authority = OwnedAuthority("apsa.fixture.newswitch", "1" * 64, invalidate=True)
    authority.bind("a" * 64)
    body = {"session": authority.session, "package": authority.package, "build": authority.build}
    authority.handle("/issue", "", json.dumps(body).encode())
    old_credential = authority.credential
    switching = json.dumps({**body, "to_account": "b"}).encode()
    assert authority.handle("/switch", "Bearer " + old_credential, switching)[0] == 200
    for token in (old_credential, authority.b_credential):
        assert authority.handle("/switch", "Bearer " + token, switching)[0] == 403
    assert authority.credential == old_credential and not authority.logged_out
    challenge = json.dumps({**body, "nonce": "c" * 64}).encode()
    assert authority.handle("/protected", "Bearer " + old_credential, challenge)[0] == 401
    assert authority.handle("/protected", "Bearer " + authority.b_credential, challenge)[0] == 401
    b_challenge = json.dumps({**body, "account": "b", "nonce": "d" * 64}).encode()
    assert authority.handle("/protected", "Bearer " + authority.b_credential, b_challenge)[0] == 200
    assert authority.handle("/protected", "Bearer " + authority.b_credential, b_challenge)[0] == 401


@pytest.mark.parametrize(
    "change",
    [
        lambda response: response.update(kind="logout"),
        lambda response: response.update(account="a"),
        lambda response: response.update(state="logged_out"),
        lambda response: response.update(session="0" * 64),
        lambda response: response.update(package="apsa.fixture.other"),
        lambda response: response.update(delivery="baseline"),
        lambda response: response.update(delivery_transport="manual"),
        lambda response: response.update(apk_sha256="f" * 64),
        lambda response: response.pop("account_authentication"),
        lambda response: response["account_authentication"].update(account="a"),
        lambda response: response["account_authentication"].update(credential_sha256="f" * 64),
        lambda response: response["account_authentication"].update(nonce_sha256=[]),
        lambda response: response["account_authentication"].update(nonce_sha256="f" * 64),
        lambda response: response["account_authentication"].update(extra="new-value"),
    ],
)
def test_forged_switch_receipt_never_confirms_b_or_transition(change, monkeypatch):
    _authority, target, adapter, recorder, _scenario = new_switch("android", False, monkeypatch)
    recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    target.change_receipt = change
    with pytest.raises(ValueError):
        adapter.open_url("synthetic://transition")
    assert not adapter.after and adapter.account_b_authentication is None


def test_declared_b_state_without_actual_b_protected_request_is_not_authentication(monkeypatch):
    _authority, target, adapter, recorder, _scenario = new_switch("android", False, monkeypatch)
    recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    target.no_b_authentication = True
    with pytest.raises(ValueError, match="account B authentication"):
        adapter.open_url("synthetic://transition")
    assert not adapter.after


@pytest.mark.parametrize("failure", ["partial", "ambiguous-login", "stale-proof", "wrong-transition"])
def test_incomplete_or_ambiguous_switch_capture_stays_inconclusive(failure, monkeypatch):
    _authority, target, adapter, recorder, scenario = new_switch("android", True, monkeypatch)
    before = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    adapter.open_url("synthetic://transition")
    if failure == "partial":
        target.partial = True
    elif failure == "ambiguous-login":
        target.ambiguous = True
    elif failure == "stale-proof":
        target.change_receipt = lambda response: response["account_authentication"].update(
            adapter.account_b_authentication
        )
    else:
        target.change_receipt = lambda response: response.update(transition="logout")
    after = recorder.capture("after", {"account": "b", "state": "authenticated"}, "account_switch")
    assert (
        evaluate_workflow(scenario, {"before": before, "after": after}, recorder.binding)[0]["state"]
        == "inconclusive"
    )
    if failure != "ambiguous-login":
        assert after["acquisition"]["capture_errors"] is True


@pytest.mark.parametrize("kind", ["login", "switch", "account-switch", "", None])
def test_transition_kind_enum_has_no_fallback(kind, monkeypatch):
    authority = OwnedAuthority("apsa.fixture.newswitch", "1" * 64, invalidate=True)
    with pytest.raises(ValueError, match="kind unsupported"):
        InstalledTransportAdapter(
            NewSwitchTarget("android", authority),
            server_without_socket(authority, monkeypatch),
            retain=False,
            transition_kind=kind,
        )


@pytest.mark.parametrize(
    "failure", ["session-reuse", "capture-reuse", "wrong-kind-before", "wrong-kind-after"]
)
def test_nonce_and_transition_state_binding_rejects_before_target_delivery(failure, monkeypatch):
    _authority, target, adapter, recorder, _scenario = new_switch("android", False, monkeypatch)
    nonce = "d" * 64
    request = CaptureRequest(recorder.session, nonce, "before", "a", "authenticated", None)
    adapter.capture(request)
    if failure == "session-reuse":
        request = CaptureRequest(
            recorder.session, recorder.session.nonce, "before", "a", "authenticated", None
        )
    elif failure == "capture-reuse":
        pass
    elif failure == "wrong-kind-before":
        request = CaptureRequest(recorder.session, "c" * 64, "after", "b", "authenticated", "account_switch")
    else:
        adapter.open_url("synthetic://transition")
        request = CaptureRequest(recorder.session, "c" * 64, "after", None, "logged_out", "logout")
    target.deliver = lambda *_args: pytest.fail("rejected capture must not reach target")
    with pytest.raises(ValueError):
        adapter.capture(request)


@pytest.mark.parametrize("field", ["credential", "authority", "nonce", "provenance", "network", "account"])
def test_old_a_backend_probe_cannot_be_replaced_by_b_or_incomplete_data(field, monkeypatch):
    _authority, _target, adapter, recorder, _scenario = new_switch("android", False, monkeypatch)
    before = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    adapter.open_url("synthetic://transition")
    after = copy.deepcopy(
        recorder.capture("after", {"account": "b", "state": "authenticated"}, "account_switch")
    )
    if field == "credential":
        after["backend_probe"]["credential_sha256"] = adapter.account_b_authentication["credential_sha256"]
    elif field == "authority":
        after["backend_probe"]["authority_sha256"] = "f" * 64
    elif field == "nonce":
        after["acquisition"]["capture_sha256"] = before["acquisition"]["capture_sha256"]
    elif field == "provenance":
        after["backend_probe"]["provenance"]["session_sha256"] = "f" * 64
    elif field == "network":
        after["surfaces"]["network"]["state"] = "inconclusive"
    else:
        after["acquisition"]["account"] = "a"
    assert driver.old_account_switch_replay(before, after)[0]["state"] == "inconclusive"


@pytest.mark.parametrize("platform", ["android", "ios"])
def test_main_keeps_four_logout_policies_and_adds_two_new_switch_cases(platform, tmp_path, monkeypatch):
    work = tmp_path / "new-account-switch-driver"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    args = ["new-driver", "--platform", platform, "--work", str(work)]
    if platform == "android":
        args += ["--sdk", str(tmp_path / "new-sdk"), "--jdk", str(tmp_path / "new-jdk")]
    monkeypatch.setattr(sys, "argv", args)
    calls, closed = [], []

    class Target:
        device = "new-synthetic-UUID"

        def __init__(self, *args, **kwargs):
            pass

        def close(self):
            closed.append(True)
            return {"state": "confirmed"}

        def url_contract_diagnostics(self):
            return {}

    class Device:
        name, serial = "new-owned", "new-serial"

        def __init__(self, *_args):
            pass

        def start(self):
            pass

        def close(self):
            return {"state": "confirmed"}

    def execute(_target, *, invalidate, retain, evidence, transition_kind="logout"):
        calls.append((transition_kind, invalidate, retain))
        evidence.update(state="passed", transition_kind=transition_kind)

    monkeypatch.setattr(driver, "IosTarget", Target)
    monkeypatch.setattr(driver, "AndroidTarget", Target)
    monkeypatch.setattr(driver, "NewAndroidDevice", Device)
    monkeypatch.setattr(driver, "build_android", lambda *_a, **_kw: tmp_path / "new.apk")
    monkeypatch.setattr(driver, "execute_case", execute)
    driver.main()
    value = json.loads((work / "evidence.json").read_text())
    assert calls == [
        ("logout", True, False),
        ("logout", True, True),
        ("logout", False, False),
        ("logout", False, True),
        ("account_switch", True, False),
        ("account_switch", True, True),
    ]
    assert len(closed) == len(value["cases"]) == 6
    assert value["cleanup"]["state"] == "confirmed" and value["terminal"] is True
    assert len(driver.runtime_projection(value)["cases"]) == 6
