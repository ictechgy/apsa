"""New synthetic runtime fixtures; no live devices or pre-existing artifacts."""

import copy
import json

import pytest

from mobile_audit.runtime import plan, run, validate_scenario
from mobile_audit.runtime_evidence import attach_operator_captures, build_binding
from mobile_audit.verify import compare_reports


def report():
    return {
        "id": "before",
        "target": "/synthetic/app",
        "inventory": {
            "platforms": ["android", "ios"],
            "package": "com.synthetic.app",
            "apps": [{"platform": p, "package": "com.synthetic.app"} for p in ("android", "ios")],
            "input_kind": "source",
            "fingerprint": "source-before",
            "deep_links": [],
        },
        "findings": [
            {
                "id": "F-static",
                "rule_id": "AST-PATH-TRAVERSAL",
                "status": "candidate",
                "severity": "medium",
                "evidence": [{"path": "Auth.kt", "line": 12, "source": "intent", "sink": "file"}],
            }
        ],
        "coverage": [{"rule_id": "RUNTIME-RESIDUAL", "state": "not-run"}],
        "runtime": [],
    }


def scenario(platform="android", kind="logout"):
    accounts = {"a": {"canary": "a", "login_marker": "login_a"}}
    from_account, to_account = "a", None
    if kind == "login":
        from_account, to_account = None, "a"
    if kind == "account_switch":
        accounts["b"] = {"canary": "b", "login_marker": "login_b"}
        to_account = "b"
    return {
        "schema_version": 2,
        "platform": platform,
        "package": "com.synthetic.app",
        "precondition": "Owned synthetic test accounts are prepared",
        "markers": {
            label: "synthetic-unique-" + label
            for label in ("a", "b", "login_a", "login_b", "state", "delivery", "baseline")
        },
        "workflow": {
            "accounts": accounts,
            "transitions": [
                {
                    "kind": kind,
                    "baseline": "before",
                    "snapshot": "after",
                    "from_account": from_account,
                    "to_account": to_account,
                    "state_marker": "state",
                    "delivery_marker": "delivery",
                    "baseline_marker": "baseline",
                }
            ],
        },
        "steps": [
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": "synthetic://transition"},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            {
                "baseline": "before",
                "snapshot": "after",
                "marker": "a",
                "surface": "storage",
                "finding_id": "F-static",
                "rule_id": "AST-PATH-TRAVERSAL",
            }
        ],
    }


class SyntheticStore:
    def __init__(self, home):
        self.home = home
        self.previous = report()

    def report(self, identifier):
        return copy.deepcopy(self.previous)

    def intelligence(self, **kwargs):
        return []

    def save_report(self, value):
        self.previous = copy.deepcopy(value)
        return value


class SyntheticAdapter:
    def __init__(self, value, missing=None, remains=False):
        self.value, self.missing, self.remains = value, missing, remains
        self.after = False
        self.storage_calls = 0

    def environment(self):
        key = "apk_sha256" if self.value["platform"] == "android" else "executable_sha256"
        app = {"package": self.value["package"], key: "1" * 64}
        if self.missing == "build":
            del app[key]
        return {"platform": self.value["platform"], "app": app}

    def labels(self):
        t = self.value["workflow"]["transitions"][0]
        account = t["to_account"] if self.after else t["from_account"]
        labels = [account, "login_" + account] if account else ["baseline"]
        if self.after:
            labels += ["state", "delivery"]
            if self.remains:
                labels += ["a"]
        return [label for label in labels if label != self.missing]

    def storage(self):
        self.storage_calls += 1
        return [
            (
                "synthetic.dat",
                " ".join(self.value["markers"][m] for m in self.labels() if m in {"a", "b"}).encode(),
            )
        ]

    def ui(self):
        return " ".join(self.value["markers"][m] for m in self.labels() if m not in {"a", "b"}).encode()

    def logs(self):
        return b"synthetic empty logs"

    def open_url(self, url):
        assert url == "synthetic://transition"
        self.after = True
        return {"delivery": "requested-not-confirmed"}


@pytest.fixture
def synthetic_run(monkeypatch, tmp_path):
    monkeypatch.setenv("APSA_DEVICE_LOCK_DIR", str(tmp_path / "locks"))
    monkeypatch.setattr("mobile_audit.runtime.correlate", lambda *args: ([], []))
    monkeypatch.setattr("mobile_audit.runtime.source_health", lambda *args: {})
    monkeypatch.setattr("mobile_audit.runtime.summarize", lambda *args: {})
    return SyntheticStore(tmp_path / "home")


@pytest.mark.parametrize("platform", ["android", "ios"])
@pytest.mark.parametrize("kind", ["login", "account_switch", "logout"])
def test_authenticated_transition_contract(synthetic_run, tmp_path, platform, kind):
    value = scenario(platform, kind)
    result = run(synthetic_run, tmp_path / "unused.json", scenario=value, adapter=SyntheticAdapter(value))
    record = result["runtime"][-1]
    assert record["workflow"][0]["state"] == "passed"
    assert record["app_binding"]["state"] == "bound"
    assert record["delivery_verification"] == "marker-observed"
    assert record["transition_verification"] == "marker-observed"
    assert record["static_links"][0]["source_traces"][0]["sink"] == "file"
    assert record["static_links"][0]["observations"]
    assert all(marker not in json.dumps(result) for marker in value["markers"].values())
    assert result["findings"][0]["status"] == "candidate"


@pytest.mark.parametrize("missing", ["login_a", "delivery", "state", "a", "build"])
def test_missing_required_evidence_is_inconclusive(synthetic_run, tmp_path, missing):
    value = scenario()
    result = run(
        synthetic_run,
        tmp_path / "unused.json",
        scenario=value,
        adapter=SyntheticAdapter(value, missing, remains=True),
    )
    record = result["runtime"][-1]
    assert record["partial"] is True
    assert record["workflow"][0]["state"] == "inconclusive"
    assert record["assertions"][0]["state"] == "inconclusive"
    assert not any(f["status"] == "runtime-confirmed" for f in result["findings"])


def test_changed_installed_build_stops_before_second_capture(synthetic_run, tmp_path):
    value = scenario()

    class Changed(SyntheticAdapter):
        def environment(self):
            result = super().environment()
            if self.after:
                result["app"]["apk_sha256"] = "2" * 64
            return result

    adapter = Changed(value)
    result = run(synthetic_run, tmp_path / "unused.json", scenario=value, adapter=adapter)
    assert adapter.storage_calls == 1
    assert result["runtime"][-1]["partial"] is True
    assert result["runtime"][-1]["assertions"][0]["state"] == "inconclusive"


def capture(value):
    return {
        "schema_version": 1,
        "snapshot": "after",
        "platform": value["platform"],
        "package": value["package"],
        "build": {"apk_sha256": "1" * 64},
        "account": None,
        "state": "logged_out",
        "surface": "network",
        "observations": [
            {"label": "synthetic-request", "sha256": "3" * 64, "bytes": 20, "marker_labels": ["a"]}
        ],
    }


@pytest.mark.parametrize("unsupported", ["command", "headers", "body", "url", "authorization"])
def test_operator_capture_allowlist_rejects_raw_or_executable_fields(unsupported):
    value = scenario()
    observed = capture(value)
    observed[unsupported] = "synthetic secret"
    value["operator_captures"] = [observed]
    with pytest.raises(ValueError, match="unsupported"):
        validate_scenario(value)


@pytest.mark.parametrize("platform", ["android", "ios"])
@pytest.mark.parametrize("surface", ["network", "artifact"])
def test_operator_capture_cannot_confirm_exposure(synthetic_run, tmp_path, platform, surface):
    value = scenario(platform)
    before = capture(value)
    before.update(snapshot="before", account="a", state="authenticated")
    value["operator_captures"] = [before, capture(value)]
    for observation in value["operator_captures"]:
        observation["surface"] = surface
        if platform == "ios":
            observation["build"] = {"executable_sha256": "1" * 64}
    value["assertions"][0]["surface"] = surface
    result = run(synthetic_run, tmp_path / "unused.json", scenario=value, adapter=SyntheticAdapter(value))
    record = result["runtime"][-1]
    assert record["snapshots"]["after"]["surfaces"][surface]["acquisition"] == "unverified"
    assert record["assertions"][0]["state"] == "inconclusive"
    assert not any(f["status"] == "runtime-confirmed" for f in result["findings"])


def test_operator_binding_mismatch_is_inconclusive():
    value = scenario()
    value["operator_captures"] = [capture(value)]
    snapshots = {"after": {"surfaces": {}, "files": [], "matches": []}}
    binding = build_binding("android", value["package"], {"apk_sha256": "2" * 64})
    attach_operator_captures(value, snapshots, binding)
    assert snapshots["after"]["surfaces"]["network"]["state"] == "inconclusive"
    assert snapshots["after"]["matches"] == []


def test_generated_plan_has_required_workflow_and_static_linkage():
    value = plan(report(), "ios")
    validate_scenario(value)
    assert value["schema_version"] == 2
    assert value["workflow"]["transitions"][0]["kind"] == "logout"
    assert value["static_links"][0]["finding_id"] == "F-static"


def test_compare_keeps_explicit_scope_build_pair_and_disappearance():
    before = report()
    after = copy.deepcopy(before)
    after.update(id="after", findings=[])
    after["inventory"]["fingerprint"] = "source-after"
    comparison = compare_reports(before, after)
    assert comparison["scope_pairing"]["state"] == "unchanged"
    assert comparison["build_pairing"] == {
        "state": "different-builds",
        "before": "source-before",
        "after": "source-after",
    }
    assert comparison["finding_transitions"][0]["observation"] == "no-longer-observed"
    after["target"] = "/synthetic/other-app"
    assert compare_reports(before, after)["finding_transitions"][0]["verification"] == "inconclusive"


def test_rerun_pairs_exact_scope_and_build(synthetic_run, tmp_path):
    value = scenario()
    before = run(
        synthetic_run, tmp_path / "unused.json", scenario=value, adapter=SyntheticAdapter(value, remains=True)
    )
    after = run(synthetic_run, tmp_path / "unused.json", scenario=value, adapter=SyntheticAdapter(value))
    comparison = compare_reports(before, after)
    assert comparison["runtime_pairs"][0]["verification"] == "comparable-observation"
    assert any(c["observation"] == "no-longer-observed" for c in comparison["finding_transitions"])
    changed = copy.deepcopy(after)
    changed["runtime"][-1]["app_binding"]["identity"] = "2" * 64
    assert compare_reports(before, changed)["runtime_pairs"][0]["verification"] == "inconclusive"


def test_different_build_cannot_clear_prior_runtime_evidence(synthetic_run, tmp_path):
    value = scenario()
    before = run(
        synthetic_run, tmp_path / "unused.json", scenario=value, adapter=SyntheticAdapter(value, remains=True)
    )

    class OtherBuild(SyntheticAdapter):
        def environment(self):
            result = super().environment()
            result["app"]["apk_sha256"] = "2" * 64
            return result

    after = run(synthetic_run, tmp_path / "unused.json", scenario=value, adapter=OtherBuild(value))
    assert any(f["status"] == "runtime-confirmed" for f in after["findings"])
    assert compare_reports(before, after)["runtime_pairs"][0]["verification"] == "inconclusive"


def test_legacy_scenario_keeps_scoped_observation_semantics(synthetic_run, tmp_path):
    value = scenario()
    legacy = copy.deepcopy(value)
    legacy.pop("workflow")
    legacy.pop("schema_version")

    class Legacy(SyntheticAdapter):
        def environment(self):
            return {"platform": "android"}

    after = run(synthetic_run, tmp_path / "unused.json", scenario=legacy, adapter=Legacy(value))
    record = after["runtime"][-1]
    assert record["schema_version"] == 1
    assert record["assertions"][0]["state"] == "passed"
    assert record["app_binding"]["state"] == "unavailable"
    assert record["partial"] is False


def test_runtime_errors_and_assertion_prose_scrub_canaries_and_secrets(synthetic_run, tmp_path):
    value = scenario()
    value["assertions"][0]["policy"] = (
        value["markers"]["a"] + " password=synthetic-secret bearer synthetic-secret-token"
    )
    after = run(
        synthetic_run, tmp_path / "unused.json", scenario=value, adapter=SyntheticAdapter(value, remains=True)
    )
    assert "synthetic-secret" not in json.dumps(after)
    assert value["markers"]["a"] not in json.dumps(after)

    class Error(SyntheticAdapter):
        def open_url(self, url):
            raise ValueError(value["markers"]["a"] + " password=synthetic-secret")

    failure = run(synthetic_run, tmp_path / "unused.json", scenario=value, adapter=Error(value))
    assert "synthetic-secret" not in json.dumps(failure)
    assert value["markers"]["a"] not in json.dumps(failure)


@pytest.mark.parametrize(
    "field",
    [
        "from_account",
        "to_account",
        "kind",
        "baseline",
        "snapshot",
        "state_marker",
        "delivery_marker",
        "surface",
    ],
)
def test_malformed_workflow_values_fail_validation(field):
    value = scenario()
    value["workflow"]["transitions"][0][field] = []
    with pytest.raises(ValueError):
        validate_scenario(value)


def test_changed_assertion_contract_is_not_comparable(synthetic_run, tmp_path):
    value = scenario()
    before = run(
        synthetic_run, tmp_path / "unused.json", scenario=value, adapter=SyntheticAdapter(value, remains=True)
    )
    value["assertions"][0]["expect"] = "present"
    after = run(
        synthetic_run, tmp_path / "unused.json", scenario=value, adapter=SyntheticAdapter(value, remains=True)
    )
    pair = compare_reports(before, after)["runtime_pairs"][0]
    assert pair["assertion_pairing"] == "unavailable-or-changed"
    assert pair["verification"] == "inconclusive"


@pytest.mark.parametrize("field", ["source_selection", "project_specification"])
def test_changed_scan_selection_retains_inconclusive_pairing(field):
    before = report()
    after = copy.deepcopy(before)
    after["inventory"][field] = {"sha256": "2" * 64, "module": "other"}
    comparison = compare_reports(before, after)
    assert comparison["scope_pairing"]["state"] == "changed"
    assert comparison["finding_transitions"][0]["verification"] == "inconclusive"


def test_contradictory_login_markers_cannot_establish_logout(synthetic_run, tmp_path):
    value = scenario()

    class Ambiguous(SyntheticAdapter):
        def ui(self):
            result = super().ui()
            return result + b" " + self.value["markers"]["login_a"].encode()

    after = run(synthetic_run, tmp_path / "unused.json", scenario=value, adapter=Ambiguous(value))
    assert after["runtime"][-1]["assertions"][0]["state"] == "inconclusive"
    assert "after-ambiguous-account-state" in after["runtime"][-1]["workflow"][0]["missing_evidence"]
