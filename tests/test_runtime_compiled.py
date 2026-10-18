"""Fresh compiled processes and fixture stores only; no device or network reads."""

import json
from dataclasses import replace

import pytest

from mobile_audit.runtime_acquisition import AcquisitionRecorder
from mobile_audit.runtime_evidence import build_binding, evaluate_workflow
from tests.support.runtime_compiled import CompiledSyntheticAdapter, resolve_jdk
from tests.test_runtime_evidence import scenario


@pytest.fixture
def owned_adapter(tmp_path):
    try:
        jdk = resolve_jdk()
    except ValueError:
        pytest.skip("Explicit local JDK unavailable")
    adapters = []

    def create(value, **options):
        adapter = CompiledSyntheticAdapter(
            value, tmp_path / ("compiled-" + str(len(adapters))), jdk=jdk, **options
        )
        adapters.append(adapter)
        return adapter

    yield create
    for adapter in adapters:
        assert adapter.close()["status"] == 0


def storage_scenario(platform, kind):
    value = scenario(platform, kind)
    for account in value["workflow"]["accounts"].values():
        account.update(canary_surface="storage", login_surface="storage")
    value["workflow"]["transitions"][0]["surface"] = "storage"
    return value


def acquire(value, adapter):
    binding = build_binding(value["platform"], value["package"], adapter.environment()["app"])
    recorder = AcquisitionRecorder(adapter, binding, value["markers"])
    transition = value["workflow"]["transitions"][0]
    account = transition["from_account"]
    before = recorder.capture(
        "before", {"account": account, "state": "authenticated" if account else "logged_out"}, None
    )
    adapter.open_url("synthetic://transition")
    account = transition["to_account"]
    after = recorder.capture(
        "after",
        {"account": account, "state": "authenticated" if account else "logged_out"},
        transition["kind"],
    )
    return recorder, recorder.binding, {"before": before, "after": after}


@pytest.mark.parametrize("platform", ["android", "ios"])
@pytest.mark.parametrize("kind", ["login", "account_switch", "logout"])
def test_fresh_compiled_bound_storage_workflows(owned_adapter, platform, kind, tmp_path):
    value = storage_scenario(platform, kind)
    adapter = owned_adapter(value)
    recorder, binding, snapshots = acquire(value, adapter)
    assert evaluate_workflow(value, snapshots, binding)[0]["state"] == "passed"
    before, after = snapshots["before"], snapshots["after"]
    assert recorder.metadata()["mode"] == "synthetic"
    assert recorder.metadata()["live_device_verified"] is False
    assert adapter.manifest["compile_target"] == "JVM-17-host-process"
    assert adapter.manifest["installed"] is False
    assert before["acquisition"]["session_sha256"] == after["acquisition"]["session_sha256"]
    assert before["acquisition"]["capture_sha256"] != after["acquisition"]["capture_sha256"]
    assert after["surfaces"]["storage"]["completeness"] == "complete"
    assert after["surfaces"]["network"]["completeness"] == "partial"
    assert after["surfaces"]["ui"]["completeness"] == "unsupported"
    assert adapter.manifest["source_sha256"] != adapter.manifest["model_sha256"]
    command_journal = json.dumps(adapter.manifest["commands"])
    assert str(adapter.root) not in command_journal
    assert (
        '"argv"' not in command_journal
        and '"stdout"' not in command_journal
        and '"stderr"' not in command_journal
    )
    encoded = json.dumps(snapshots)
    assert all(marker not in encoded for marker in value["markers"].values())
    assert "IPC replay credential=" not in encoded
    (tmp_path / "digest-only.json").write_text(encoded)


@pytest.mark.parametrize("invalidate,residual", [(True, False), (True, True), (False, False), (False, True)])
def test_compiled_backend_authority_is_separate_from_store(owned_adapter, invalidate, residual):
    from mobile_audit.runtime_acquisition import evaluate_backend_invalidation

    value = storage_scenario("android", "logout")
    adapter = owned_adapter(value, invalidate_backend=invalidate, local_residual=residual)
    _, binding, snapshots = acquire(value, adapter)
    before, after = snapshots["before"], snapshots["after"]
    assert before["backend_probe"]["outcome"] == "accepted"
    assert after["backend_probe"]["outcome"] == ("rejected" if invalidate else "accepted")
    assert before["backend_probe"]["credential_sha256"] == after["backend_probe"]["credential_sha256"]
    assert before["backend_probe"]["authority_sha256"] == after["backend_probe"]["authority_sha256"]
    assert (
        any(match["marker_label"] == "a" and match["surface"] == "storage" for match in after["matches"])
        is residual
    )
    assert evaluate_backend_invalidation(value, snapshots, binding)[0]["state"] == "inconclusive"


@pytest.mark.parametrize("index", [1, 2, 3, 4, 5, 6, 7, 8])
def test_compiled_response_binding_mismatch_fails_closed(owned_adapter, monkeypatch, index):
    value = storage_scenario("android", "logout")
    adapter = owned_adapter(value)
    binding = build_binding(value["platform"], value["package"], adapter.environment()["app"])
    recorder = AcquisitionRecorder(adapter, binding, value["markers"])
    exchange = adapter._exchange

    def changed(fields):
        response = exchange(fields)
        if fields[0] == "capture":
            response[index] = "wrong"
        return response

    monkeypatch.setattr(adapter, "_exchange", changed)
    result = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    assert result["files"] == []
    assert result["acquisition"]["capture_errors"] is True
    assert result["binding"]["state"] == "unavailable"
    assert recorder.metadata()["state"] == "inconclusive"


def test_compiled_process_rejects_wrong_account_and_repeated_delivery(owned_adapter):
    value = storage_scenario("android", "logout")
    adapter = owned_adapter(value)
    binding = build_binding(value["platform"], value["package"], adapter.environment()["app"])
    recorder = AcquisitionRecorder(adapter, binding, value["markers"])
    assert recorder.session
    from mobile_audit.runtime_acquisition import CaptureRequest

    # Invalid caller request is rejected by the app before an observation is emitted.
    request = CaptureRequest(
        replace(recorder.session, nonce="wrong"), "a" * 64, "before", "a", "authenticated", None
    )
    with pytest.raises(ValueError, match="session differs"):
        adapter.capture(request)
    adapter.open_url("synthetic://transition")
    with pytest.raises(ValueError, match="unsupported"):
        adapter.open_url("synthetic://transition")


def test_fresh_fixture_directory_must_not_exist(owned_adapter, tmp_path):
    value = storage_scenario("android", "logout")
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(FileExistsError):
        CompiledSyntheticAdapter(value, existing)


def test_host_model_hash_cannot_claim_instrumented_acquisition(owned_adapter, monkeypatch):
    value = storage_scenario("android", "logout")
    adapter = owned_adapter(value)
    start = adapter.start_session
    monkeypatch.setattr(
        adapter, "start_session", lambda binding, nonce: replace(start(binding, nonce), mode="instrumented")
    )
    binding = build_binding(value["platform"], value["package"], adapter.environment()["app"])
    assert binding["build"] == {"runtime_model_sha256": adapter.build_hash}
    recorder = AcquisitionRecorder(adapter, binding, value["markers"])
    assert recorder.metadata()["state"] == "inconclusive"
    assert recorder.binding["state"] == "unavailable"


def test_compiled_helper_evaluates_final_revoked_binding(owned_adapter, monkeypatch):
    value = storage_scenario("android", "logout")
    adapter = owned_adapter(value)
    capture = adapter.capture

    def broken_after(request):
        if adapter.after:
            raise ValueError("Fresh compiled capture error")
        return capture(request)

    monkeypatch.setattr(adapter, "capture", broken_after)
    recorder, binding, snapshots = acquire(value, adapter)
    assert binding is recorder.binding
    assert binding["state"] == "unavailable"
    assert evaluate_workflow(value, snapshots, binding)[0]["state"] == "inconclusive"
