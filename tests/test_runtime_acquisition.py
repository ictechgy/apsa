"""New generated app and mocked network evidence; no device/UI/network access."""

import copy
import json
from dataclasses import replace
from typing import cast

import pytest

from mobile_audit.runtime import plan, run
from mobile_audit.runtime_acquisition import (
    AcquiredCapture,
    AcquisitionRecorder,
    AcquisitionSession,
    RawObservation,
    SurfaceCapture,
    acquisition_plan,
)
from mobile_audit.runtime_evidence import build_binding
from mobile_audit.store import Store
from tests.support.runtime_synthetic import SyntheticTestAppAdapter, generate_synthetic_sources
from tests.test_runtime_evidence import SyntheticAdapter, SyntheticStore, capture, report, scenario


@pytest.fixture
def execution(monkeypatch, tmp_path):
    monkeypatch.setenv("APSA_DEVICE_LOCK_DIR", str(tmp_path / "locks"))
    monkeypatch.setattr("mobile_audit.runtime.correlate", lambda *args: ([], []))
    monkeypatch.setattr("mobile_audit.runtime.source_health", lambda *args: {})
    monkeypatch.setattr("mobile_audit.runtime.summarize", lambda *args: {})
    store = SyntheticStore(tmp_path / "reports")

    def execute(value, adapter, *, acquisition=True):
        return run(
            cast(Store, store),
            tmp_path / "unused.json",
            scenario=value,
            adapter=adapter,
            acquisition_adapter=adapter if acquisition else None,
        )

    return execute


def network_scenario(platform="android", kind="logout"):
    value = scenario(platform, kind)
    for account in value["workflow"]["accounts"].values():
        account.update(canary_surface="network", login_surface="network")
    value["workflow"]["transitions"][0]["surface"] = "network"
    value["assertions"][0]["surface"] = "network"
    if kind == "login":
        value["assertions"][0].update(expect="present", purpose="authentication")
    return value


@pytest.mark.parametrize("platform", ["android", "ios"])
@pytest.mark.parametrize("kind", ["login", "account_switch", "logout"])
def test_executable_synthetic_bound_workflows(execution, tmp_path, platform, kind):
    value = network_scenario(platform, kind)
    result = execution(value, SyntheticTestAppAdapter(value))
    record = result["runtime"][-1]
    assert record["acquisition"]["mode"] == "synthetic"
    assert record["acquisition"]["live_device_verified"] is False
    assert record["build_verification"] == "synthetic-app-model-build"
    assert record["workflow"][0]["state"] == "passed"
    assert record["assertions"][0]["state"] == "passed"
    before, after = record["snapshots"]["before"], record["snapshots"]["after"]
    assert before["acquisition"]["session_sha256"] == after["acquisition"]["session_sha256"]
    assert before["acquisition"]["capture_sha256"] != after["acquisition"]["capture_sha256"]
    assert after["surfaces"]["network"]["completeness"] == "complete"
    assert after["surfaces"]["logs"]["completeness"] == "unsupported"
    encoded = json.dumps(record)
    assert all(marker not in encoded for marker in value["markers"].values())
    assert "new-synthetic-credential" not in encoded
    assert "synthetic://" not in encoded
    assert "response_sha256" in encoded if kind != "login" else True
    (tmp_path / "digest-only-report.json").write_text(json.dumps(result, indent=2))


@pytest.mark.parametrize(
    "invalidate,local_residual", [(True, False), (True, True), (False, False), (False, True)]
)
def test_backend_replay_is_independent_of_local_residual(execution, invalidate, local_residual):
    value = network_scenario()
    value["assertions"][0]["surface"] = "storage"
    result = execution(
        value, SyntheticTestAppAdapter(value, invalidate_backend=invalidate, local_residual=local_residual)
    )
    record = result["runtime"][-1]
    assert record["backend_invalidation"][0]["state"] == ("passed" if invalidate else "failed")
    assert record["assertions"][0]["state"] == ("failed" if local_residual else "passed")
    # A backend replay failure is separate evidence, never synthesized from local storage.
    assert record["backend_invalidation"][0]["mode"] == "synthetic"


@pytest.mark.parametrize("field", ["account", "state", "nonce", "snapshot", "session", "transition"])
def test_replayed_or_changed_request_cannot_establish_workflow(execution, field):
    value = network_scenario()

    class Changed(SyntheticTestAppAdapter):
        def capture(self, request):
            captured = super().capture(request)
            changed = {
                "account": "wrong",
                "state": "wrong",
                "nonce": "0" * 64,
                "snapshot": "wrong",
                "session": replace(request.session, nonce="1" * 64),
                "transition": "wrong",
            }[field]
            return replace(captured, request=replace(request, **{field: changed}))

    record = execution(value, Changed(value))["runtime"][-1]
    assert record["workflow"][0]["state"] == "inconclusive"
    assert record["assertions"][0]["state"] == "inconclusive"
    assert record["backend_invalidation"][0]["state"] == "inconclusive"


@pytest.mark.parametrize("field", ["platform", "package", "build", "nonce", "adapter_id", "mode"])
def test_session_provenance_must_match_observed_app(execution, field):
    value = network_scenario()

    class Changed(SyntheticTestAppAdapter):
        def start_session(self, binding, nonce):
            session = super().start_session(binding, nonce)
            changed = {
                "platform": "wrong",
                "package": "com.wrong.app",
                "build": {"apk_sha256": "0" * 64},
                "nonce": "0" * 64,
                "adapter_id": "https://private.invalid/token",
                "mode": "operator",
            }[field]
            return replace(session, **{field: changed})

    record = execution(value, Changed(value))["runtime"][-1]
    assert record["acquisition"]["state"] == "inconclusive"
    assert record["workflow"][0]["state"] == "inconclusive"
    assert "private.invalid" not in json.dumps(record)


@pytest.mark.parametrize(
    "change",
    [
        "partial",
        "missing",
        "duplicate",
        "raw-label",
        "untyped",
        "state",
        "delivery",
        "probe-credential",
        "probe-authority",
    ],
)
def test_incomplete_malformed_and_misbound_surface_evidence(execution, change):
    value = network_scenario()

    class Changed(SyntheticTestAppAdapter):
        def capture(self, request):
            captured = super().capture(request)
            if not self.after:
                return captured
            surfaces = captured.surfaces
            if change == "partial":
                return replace(
                    captured, surfaces=(replace(surfaces[0], completeness="partial"), *surfaces[1:])
                )
            if change == "missing":
                return replace(captured, surfaces=surfaces[1:])
            if change == "duplicate":
                return replace(captured, surfaces=(*surfaces, surfaces[0]))
            if change == "raw-label":
                return replace(
                    captured,
                    surfaces=(
                        SurfaceCapture(
                            "network",
                            "complete",
                            (RawObservation("https://private.invalid/auth", b"secret"),),
                        ),
                    ),
                )
            if change == "untyped":
                return cast(AcquiredCapture, {"trusted": True})
            if change == "state":
                return replace(captured, observed_account="a", observed_state="authenticated")
            if change == "delivery":
                return replace(captured, delivery="unconfirmed")
            assert captured.backend_probe
            key = "credential_sha256" if change == "probe-credential" else "authority_sha256"
            return replace(captured, backend_probe=replace(captured.backend_probe, **{key: "0" * 64}))

    record = execution(value, Changed(value))["runtime"][-1]
    if change in {"probe-credential", "probe-authority"}:
        assert record["workflow"][0]["state"] == "passed"
    else:
        assert record["workflow"][0]["state"] == "inconclusive"
        assert record["assertions"][0]["state"] == "inconclusive"
    assert record["backend_invalidation"][0]["state"] == "inconclusive"
    assert "private.invalid" not in json.dumps(record)


def test_two_recorders_cannot_reuse_acquisition_session():
    value = network_scenario()
    adapter = SyntheticTestAppAdapter(value)
    binding = build_binding(value["platform"], value["package"], adapter.environment()["app"])
    first = AcquisitionRecorder(adapter, binding, value["markers"])
    assert first.session is not None
    session = copy.deepcopy(first.session)

    class Replay(SyntheticTestAppAdapter):
        def start_session(self, binding, nonce):
            return session

    second = AcquisitionRecorder(Replay(value), binding, value["markers"])
    assert second.metadata()["state"] == "inconclusive"
    assert first.metadata()["session_sha256"] != second.metadata()["session_sha256"]


@pytest.mark.parametrize("stage", ["session", "capture"])
@pytest.mark.parametrize("error_type", [RuntimeError, ArithmeticError])
def test_ordinary_adapter_errors_are_redacted_and_remain_inconclusive(stage, error_type, capsys):
    value = network_scenario()
    body = "NEW_SYNTHETIC_CREDENTIAL_BODY_MUST_NOT_ESCAPE"

    class Broken(SyntheticTestAppAdapter):
        def start_session(self, binding, nonce):
            if stage == "session":
                raise error_type(body)
            return super().start_session(binding, nonce)

        def capture(self, request):
            raise error_type(body)

    adapter = Broken(value)
    binding = build_binding(value["platform"], value["package"], adapter.environment()["app"])
    recorder = AcquisitionRecorder(adapter, binding, value["markers"])
    snapshot = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
    assert snapshot["acquisition"]["capture_errors"] is True
    assert all(surface["state"] == "inconclusive" for surface in snapshot["surfaces"].values())
    assert body not in json.dumps(snapshot)
    captured = capsys.readouterr()
    assert body not in captured.out + captured.err


@pytest.mark.parametrize("stage", ["session", "capture"])
def test_adapter_cancellation_is_not_converted_to_an_observation(stage):
    value = network_scenario()

    class Interrupted(SyntheticTestAppAdapter):
        def start_session(self, binding, nonce):
            if stage == "session":
                raise KeyboardInterrupt()
            return super().start_session(binding, nonce)

        def capture(self, request):
            raise KeyboardInterrupt()

    adapter = Interrupted(value)
    binding = build_binding(value["platform"], value["package"], adapter.environment()["app"])
    with pytest.raises(KeyboardInterrupt):
        recorder = AcquisitionRecorder(adapter, binding, value["markers"])
        recorder.capture("before", {"account": "a", "state": "authenticated"}, None)


def test_live_gate_and_new_source_models(tmp_path):
    gate = acquisition_plan("ios", "com.synthetic.app")
    assert gate["live_acquisition"] == "unsupported"
    assert plan(report())["acquisition_plan"]["injection"] == "constructor-only"
    metadata = generate_synthetic_sources(tmp_path / "source-models")
    assert metadata["compiled"] is False and metadata["installed"] is False
    assert len(metadata["sources"]) == 2
    for entry in metadata["sources"]:
        assert (tmp_path / "source-models" / entry["label"]).stat().st_size == entry["bytes"]


def test_capture_error_does_not_persist_body_headers_or_url(execution):
    value = network_scenario()

    class Error(SyntheticTestAppAdapter):
        def capture(self, request):
            raise ValueError("https://private.invalid Authorization: secret-body")

    record = execution(value, Error(value))["runtime"][-1]
    assert "private.invalid" not in json.dumps(record)
    assert "secret-body" not in json.dumps(record)
    assert record["workflow"][0]["state"] == "inconclusive"


@pytest.mark.parametrize("limit", ["MAX_BYTES", "MAX_ENTRIES"])
def test_recorder_total_budget_fails_closed(monkeypatch, execution, limit):
    value = network_scenario()
    monkeypatch.setattr("mobile_audit.runtime_acquisition." + limit, 1)
    record = execution(value, SyntheticTestAppAdapter(value))["runtime"][-1]
    assert record["workflow"][0]["state"] == "inconclusive"
    assert record["acquisition"]["capture_errors"] is True
    assert record["snapshots"]["before"]["files"] == []
    assert record["snapshots"]["after"]["matches"] == []


def test_operator_json_cannot_overwrite_acquisition_provenance(execution):
    value = network_scenario()
    adapter = SyntheticTestAppAdapter(value)
    value["operator_captures"] = [
        {
            "schema_version": 1,
            "snapshot": "after",
            "platform": value["platform"],
            "package": value["package"],
            "build": {"apk_sha256": "0" * 64},
            "account": None,
            "state": "logged_out",
            "surface": "network",
            "observations": [{"label": "operator", "sha256": "0" * 64, "bytes": 1, "marker_labels": ["a"]}],
        }
    ]
    record = execution(value, adapter)["runtime"][-1]
    assert record["workflow"][0]["state"] == "passed"
    assert record["assertions"][0]["state"] == "passed"
    assert record["snapshots"]["after"]["surfaces"]["network"]["acquisition"] == "adapter-acquired"
    assert all(entry["origin"] == "adapter-acquired" for entry in record["snapshots"]["after"]["files"])


def test_changed_observed_platform_stops_before_trusted_capture(execution):
    value = network_scenario()

    class Wrong(SyntheticTestAppAdapter):
        def environment(self):
            result = super().environment()
            if self.after:
                result["platform"] = "ios"
            return result

    record = execution(value, Wrong(value))["runtime"][-1]
    assert record["workflow"][0]["state"] == "inconclusive"
    assert "after" not in record["snapshots"]


def test_synthetic_residual_finding_preserves_acquisition_mode(execution):
    value = network_scenario()
    value["assertions"][0]["surface"] = "storage"
    result = execution(value, SyntheticTestAppAdapter(value, local_residual=True))
    confirmed = [finding for finding in result["findings"] if finding["status"] == "runtime-confirmed"]
    assert confirmed
    assert confirmed[0]["evidence"][0]["acquisition"]["mode"] == "synthetic"
    assert confirmed[0]["evidence"][0]["acquisition"]["live_device_verified"] is False


def test_acquisition_cannot_trigger_implicit_device_discovery(monkeypatch, tmp_path):
    value = network_scenario()

    def forbidden():
        raise AssertionError("Device enumeration must not occur")

    monkeypatch.setattr("mobile_audit.runtime.devices", forbidden)
    with pytest.raises(ValueError, match="explicit runtime action adapter"):
        run(
            cast(Store, SyntheticStore(tmp_path)),
            tmp_path / "unused.json",
            scenario=value,
            acquisition_adapter=SyntheticTestAppAdapter(value),
        )


def test_synthetic_observation_cannot_clear_instrumented_evidence(execution):
    value = network_scenario()
    value["assertions"][0]["surface"] = "storage"

    class OtherMode(SyntheticTestAppAdapter):
        def start_session(self, binding, nonce):
            original = super().start_session(binding, nonce)
            self.session = replace(original, mode="instrumented")
            return self.session

    first = execution(value, OtherMode(value, local_residual=True))
    confirmed = [finding for finding in first["findings"] if finding["status"] == "runtime-confirmed"]
    assert confirmed
    second = execution(value, SyntheticTestAppAdapter(value))
    assert confirmed[0] in second["findings"]
    assert first["runtime"][-1]["scenario_scope"] != second["runtime"][-1]["scenario_scope"]
    assert first["runtime"][-1]["scenario_identity"] != second["runtime"][-1]["scenario_identity"]


class ModelIdentityAdapter(SyntheticTestAppAdapter):
    """Owned in-memory seam fixture; the compiled tests exercise the real JAR."""

    def environment(self):
        return {
            "platform": self.scenario["platform"],
            "synthetic": True,
            "app": {"package": self.scenario["package"], "runtime_model_sha256": "c" * 64},
        }


@pytest.mark.parametrize("platform", ["android", "ios"])
def test_model_identity_needs_explicit_synthetic_capability(platform):
    app = {
        "runtime_model_sha256": "c" * 64,
        "allow_synthetic_model": True,
        "synthetic": True,
        "mode": "synthetic",
    }
    normal = build_binding(platform, "com.synthetic.app", app)
    permitted = build_binding(platform, "com.synthetic.app", app, allow_synthetic_model=True)
    assert normal["state"] == "unavailable"
    assert permitted["state"] == "bound"
    assert normal["identity"] == permitted["identity"]


@pytest.mark.parametrize("platform", ["android", "ios"])
def test_operator_and_legacy_model_hashes_do_not_bind_runtime(execution, platform):
    value = scenario(platform)
    value["allow_synthetic_model"] = True
    operators = [capture(value), capture(value)]
    operators[0].update(snapshot="before", account="a", state="authenticated")
    for operator in operators:
        operator.update(platform=platform, build={"runtime_model_sha256": "c" * 64})
    value["operator_captures"] = operators

    class LegacyModel(SyntheticAdapter):
        def environment(self):
            return {
                "platform": platform,
                "synthetic": True,
                "app": {
                    "package": value["package"],
                    "runtime_model_sha256": "c" * 64,
                    "allow_synthetic_model": True,
                },
            }

    record = execution(value, LegacyModel(value), acquisition=False)["runtime"][-1]
    assert record["app_binding"]["state"] == "unavailable"
    assert record["build_verification"] == "synthetic-model-binding-unavailable"
    assert record["workflow"][0]["state"] == "inconclusive"
    assert record["assertions"][0]["state"] == "inconclusive"
    assert all(snapshot["binding"]["state"] == "unavailable" for snapshot in record["snapshots"].values())
    assert all(
        snapshot["surfaces"]["network"]["state"] == "inconclusive"
        for snapshot in record["snapshots"].values()
    )


def test_model_binding_is_promoted_only_after_valid_synthetic_session(execution):
    value = network_scenario()
    record = execution(value, ModelIdentityAdapter(value))["runtime"][-1]
    assert record["app_binding"]["state"] == "bound"
    assert record["app_binding"]["build"] == {"runtime_model_sha256": "c" * 64}
    assert record["acquisition"]["mode"] == "synthetic"
    assert record["workflow"][0]["state"] == "passed"


def test_revoked_model_binding_also_revokes_prior_backend_verdict(execution):
    value = network_scenario()
    value["steps"].append({"action": "snapshot", "label": "extra"})
    record = execution(value, ModelIdentityAdapter(value))["runtime"][-1]
    assert record["app_binding"]["state"] == "unavailable"
    assert record["workflow"][0]["state"] == "inconclusive"
    assert record["backend_invalidation"][0]["state"] == "inconclusive"


@pytest.mark.parametrize(
    "defect", ["binding-state", "binding-identity", "capture-identity", "capture-replay"]
)
def test_backend_probe_requires_current_binding_and_fresh_capture_proof(execution, defect):
    from mobile_audit.runtime_acquisition import evaluate_backend_invalidation

    value = network_scenario()
    record = execution(value, ModelIdentityAdapter(value))["runtime"][-1]
    binding, snapshots = copy.deepcopy(record["app_binding"]), copy.deepcopy(record["snapshots"])
    assert evaluate_backend_invalidation(value, snapshots, binding)[0]["state"] == "passed"
    if defect == "binding-state":
        binding["state"] = "unavailable"
    elif defect == "binding-identity":
        binding["identity"] = "0" * 64
    elif defect == "capture-identity":
        snapshots["after"]["acquisition"] = {**snapshots["after"]["acquisition"], "capture_sha256": "0" * 64}
    else:
        replayed = snapshots["before"]["acquisition"]["capture_sha256"]
        snapshots["after"]["acquisition"] = {**snapshots["after"]["acquisition"], "capture_sha256": replayed}
        snapshots["after"]["backend_probe"]["provenance"] = {
            **snapshots["after"]["backend_probe"]["provenance"],
            "capture_sha256": replayed,
        }
    assert evaluate_backend_invalidation(value, snapshots, binding)[0]["state"] == "inconclusive"


@pytest.mark.parametrize("failure", ["instrumented", "untyped", "nonce", "error"])
def test_inconclusive_model_session_cannot_promote_runtime_binding(execution, failure):
    value = network_scenario()

    class Rejected(ModelIdentityAdapter):
        def start_session(self, binding, nonce):
            session = super().start_session(binding, nonce)
            if failure == "instrumented":
                return replace(session, mode="instrumented")
            if failure == "untyped":
                return cast(AcquisitionSession, {"mode": "synthetic", "trusted": True})
            if failure == "nonce":
                return replace(session, nonce="0" * 64)
            raise ValueError("Fresh synthetic session error")

    record = execution(value, Rejected(value))["runtime"][-1]
    assert record["app_binding"]["state"] == "unavailable"
    assert record["acquisition"]["state"] == "inconclusive"
    assert record["build_verification"] == "synthetic-model-binding-unavailable"
    assert record["workflow"][0]["state"] == "inconclusive"
    assert all(snapshot["binding"]["state"] == "unavailable" for snapshot in record["snapshots"].values())


def test_prepromoted_model_binding_is_not_accepted_as_constructor_proof():
    value = network_scenario()
    adapter = ModelIdentityAdapter(value)
    prepromoted = build_binding(
        value["platform"], value["package"], adapter.environment()["app"], allow_synthetic_model=True
    )
    recorder = AcquisitionRecorder(adapter, prepromoted, value["markers"])
    assert recorder.session is None
    assert recorder.metadata()["state"] == "inconclusive"
    assert recorder.binding["state"] == "unavailable"


def test_model_capture_error_revokes_promotion_in_every_runtime_snapshot(execution):
    value = network_scenario()

    class BrokenCapture(ModelIdentityAdapter):
        def capture(self, request):
            if self.after:
                raise ValueError("Fresh synthetic capture error")
            return super().capture(request)

    record = execution(value, BrokenCapture(value))["runtime"][-1]
    assert record["app_binding"]["state"] == "unavailable"
    assert record["acquisition"]["state"] == "inconclusive"
    assert record["build_verification"] == "synthetic-model-binding-unavailable"
    assert record["workflow"][0]["state"] == "inconclusive"
    assert record["assertions"][0]["state"] == "inconclusive"
    assert all(snapshot["binding"]["state"] == "unavailable" for snapshot in record["snapshots"].values())
