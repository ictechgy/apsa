from __future__ import annotations

import copy
import json
from datetime import datetime, timezone

import pytest

from mobile_audit import policy as policy_module
from mobile_audit.core import finding
from mobile_audit.policy import evaluate, load_policy, template


@pytest.fixture(autouse=True)
def stable_clock(monkeypatch):
    monkeypatch.setattr(policy_module, "_now", lambda: datetime(2026, 10, 4, 12, tzinfo=timezone.utc))


def item(severity="high", status="configuration-confirmed", rule="TEST", line=2, **metadata):
    return finding(rule, "Example", severity, status, [{"path": "App.java", "line": line, **metadata}], "Fix")


def report(*items, **extra):
    return {
        "id": "audit_current",
        "schema_version": 2,
        "findings": list(items),
        "coverage": [
            {"rule_id": "TEST", "state": "checked"},
            {"rule_id": "RUNTIME-RESIDUAL", "state": "not-run"},
        ],
        "runtime": [],
        "intel_snapshot": [],
        **extra,
    }


def config(**extra):
    return {"schema_version": 1, **extra}


def waiver(finding_id, expires="2026-10-10", reason="Reviewed exception; owner tracks remediation"):
    return {"finding_id": finding_id, "reason": reason, "expires": expires}


def test_template_loads_and_defaults_gate_confirmed_evidence(tmp_path):
    path = tmp_path / "mobile-audit.toml"
    path.write_text(template())
    loaded = load_policy(path)
    assert "candidate" not in loaded["allowed_statuses"]
    assert evaluate(report(item()), loaded)["state"] == "failed"
    result = evaluate(report(item(status="candidate"), item(severity="medium", line=3)), loaded)
    assert result["state"] == "passed"
    assert result["exit_code"] == 0
    assert result["counts"]["status_excluded"] == 1


def test_candidate_status_is_an_explicit_opt_in():
    candidate = item(status="candidate")
    assert evaluate(report(candidate), config())["state"] == "passed"
    result = evaluate(report(candidate), config(allowed_statuses=["candidate"]))
    assert result["state"] == "failed"
    assert result["gate_findings"] == [candidate["id"]]
    assert result["exit_code"] == 4


def test_severity_count_budget_allows_exact_limit_and_fails_above():
    first, second = item(), item(line=3)
    policy = config(thresholds={"high": 1, "medium": 0})
    assert evaluate(report(first), policy)["state"] == "passed"
    result = evaluate(report(first, second, item(severity="medium", line=4)), policy)
    assert result["state"] == "failed"
    assert result["counts"]["by_severity"]["high"] == 2
    assert len(result["gate_findings"]) == 3
    assert {reason["severity"] for reason in result["reasons"]} == {"high", "medium"}


@pytest.mark.parametrize(
    "expires,expected", [("2026-10-03", "incomplete"), ("2026-10-04", "passed"), ("2026-10-05", "passed")]
)
def test_waiver_expiry_is_inclusive_and_never_silently_ignored(expires, expected):
    current = item()
    policy = config(waivers=[waiver(current["id"], expires)])
    before = copy.deepcopy((current, policy))
    result = evaluate(report(current), policy)
    assert result["state"] == expected
    if expected == "incomplete":
        assert result["exit_code"] == 3
        assert result["expired_waivers"][0]["matched"] is True
        assert result["counts"]["waived"] == 0
        assert current["id"] in result["gate_findings"]
    else:
        assert result["active_waivers"][0]["matched"] is True
        assert result["waived_findings"] == [current["id"]]
    assert (current, policy) == before


def test_expired_unmatched_waiver_still_rejects_policy_gate():
    result = evaluate(report(), config(waivers=[waiver("F-unused", "2026-10-03")]))
    assert result["state"] == "incomplete"
    assert result["expired_waivers"][0]["matched"] is False
    assert result["reasons"][0]["code"] == "expired-waiver"


def test_loaded_policy_rechecks_expiry_on_every_evaluation(tmp_path, monkeypatch):
    current = item()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(config(waivers=[waiver(current["id"], "2026-10-04")])))
    policy = load_policy(path)
    assert evaluate(report(current), policy)["state"] == "passed"
    monkeypatch.setattr(policy_module, "_now", lambda: datetime(2026, 10, 5, 0, tzinfo=timezone.utc))
    assert evaluate(report(current), policy)["state"] == "incomplete"


def test_only_new_baseline_ignores_ids_timestamps_and_intelligence_snapshots():
    before = item(intel_hash="old", runtime_id="old", fetched="2026-01-01")
    before["id"] = "F-legacy"
    after = item(intel_hash="new", runtime_id="new", fetched="2026-10-04")
    result = evaluate(report(after), config(only_new=True), report(before, id="audit_before"))
    assert result["state"] == "passed"
    assert result["counts"]["baseline_existing"] == 1
    assert result["baseline_report_id"] == "audit_before"


def test_only_new_rejects_a_baseline_from_another_app():
    current = report(item(), inventory={"apps": [{"platform": "android", "package": "team.current"}]})
    unrelated = report(item(), inventory={"apps": [{"platform": "android", "package": "team.other"}]})
    gate = evaluate(current, config(only_new=True), unrelated)
    assert gate["exit_code"] == 3
    assert gate["counts"]["baseline_existing"] == 0
    assert any(reason["code"] == "baseline-target-mismatch" for reason in gate["reasons"])


def test_same_app_builds_can_use_a_baseline_from_another_artifact_path():
    identity = {"apps": [{"platform": "ios", "package": "team.app"}]}
    gate = evaluate(
        report(item(), target="/build/new.ipa", inventory=identity),
        config(only_new=True),
        report(item(), target="/build/old.ipa", inventory=identity),
    )
    assert gate["exit_code"] == 0 and gate["counts"]["baseline_existing"] == 1


@pytest.mark.parametrize(
    "old_severity,old_status,new_severity,new_status",
    [
        ("medium", "configuration-confirmed", "high", "configuration-confirmed"),
        ("high", "candidate", "high", "configuration-confirmed"),
        ("high", "version-affected", "high", "runtime-confirmed"),
    ],
)
def test_baseline_severity_or_evidence_escalation_reopens_gate(
    old_severity, old_status, new_severity, new_status
):
    before = item(old_severity, old_status)
    after = item(new_severity, new_status)
    assert before["id"] == after["id"]
    result = evaluate(report(after), config(only_new=True), report(before))
    assert result["state"] == "failed"
    assert result["counts"]["escalated"] == 1
    assert result["gate_findings"] == [after["id"]]


def test_baseline_does_not_hide_new_locations_and_allows_deescalation():
    before = item("critical", "runtime-confirmed")
    after = item("high", "configuration-confirmed")
    new = item(line=3)
    result = evaluate(report(after, new), config(only_new=True), report(before))
    assert result["state"] == "failed"
    assert result["gate_findings"] == [new["id"]]
    assert result["counts"]["baseline_existing"] == 1


def test_missing_or_invalid_baseline_prevents_passing():
    assert evaluate(report(), config(only_new=True))["state"] == "incomplete"
    result = evaluate(report(), config(only_new=True), {"findings": [{}]})
    assert result["state"] == "incomplete"
    assert result["reasons"][0]["code"] == "invalid-finding"


@pytest.mark.parametrize("state", ["not-run", "partial", "inconclusive", "observed"])
def test_required_rule_coverage_cannot_pass_when_incomplete(state):
    current = report(coverage=[{"rule_id": "REQUIRED", "state": state}])
    result = evaluate(current, config(required_rules=["REQUIRED"], fail_on_partial=False))
    assert result["state"] == "incomplete"
    assert result["reasons"][0]["code"] == "required-rule-incomplete"


def test_expected_not_run_runtime_is_not_universally_a_partial_scan():
    assert evaluate(report(), config())["state"] == "passed"
    assert evaluate(report(), config(required_rules=["RUNTIME-RESIDUAL"]))["state"] == "incomplete"
    assert evaluate(report(), config(required_rules=["MISSING"]))["state"] == "incomplete"


@pytest.mark.parametrize(
    "current",
    [
        report(partial=True),
        report(inventory={"partial": True}),
        report(coverage=[{"rule_id": "TEST", "state": "partial"}]),
        report(runtime=[{"partial": True}]),
    ],
)
def test_explicit_partial_evidence_blocks_default_gate(current):
    assert evaluate(current, config())["state"] == "incomplete"
    assert evaluate(current, config(fail_on_partial=False))["state"] == "passed"


def test_latest_complete_runtime_supersedes_old_partial_execution():
    current = report(runtime=[{"partial": True}, {"partial": False}])
    assert evaluate(current, config())["state"] == "passed"


def test_fresh_intelligence_requires_each_explicit_feed_and_valid_timestamp():
    policy = config(require_fresh_intel=True, required_feeds=["apple", "android"], intel_max_age_hours=24)
    current = report(
        intel_snapshot=[
            {"source": "apple", "status": "ok", "stale": False, "succeeded": "2026-10-04T11:00:00+00:00"},
            {"source": "android", "status": "ok", "stale": False, "succeeded": "2026-10-04T11:00:00+00:00"},
        ]
    )
    assert evaluate(current, policy)["state"] == "passed"
    current["intel_snapshot"].pop()
    result = evaluate(current, policy)
    assert result["state"] == "incomplete"
    assert result["reasons"][0]["source"] == "android"


@pytest.mark.parametrize(
    "feed",
    [
        {"status": "failed", "succeeded": "2026-10-04T11:00:00+00:00"},
        {"status": "ok", "succeeded": "2026-10-02T11:00:00+00:00"},
        {"status": "ok", "stale": True, "succeeded": "2026-10-02T11:00:00+00:00"},
        {"status": "ok", "succeeded": "2026-10-04T11:00:00"},
        {"status": "ok", "succeeded": "2026-10-05T11:00:00+00:00"},
    ],
)
def test_failed_stale_naive_or_future_intelligence_cannot_pass(feed):
    current = report(intel_snapshot=[{"source": "kev", **feed}])
    assert (
        evaluate(current, config(require_fresh_intel=True, required_feeds=["kev"]))["state"] == "incomplete"
    )


@pytest.mark.parametrize(
    "bad",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"schema_version": 1, "fail_on_parital": True},
        config(thresholds={"critical": True}),
        config(thresholds={"high": -2}),
        config(thresholds={"urgent": 0}),
        config(allowed_statuses=[]),
        config(allowed_statuses=["confirmed"]),
        config(only_new="true"),
        config(required_rules=[""]),
        config(required_feeds=["kev", "kev"]),
        config(require_fresh_intel=True),
        config(intel_max_age_hours=0),
        config(waivers=[waiver("F-test", reason="   ")]),
        config(waivers=[waiver("F-test", expires="2026-02-30")]),
        config(waivers=[waiver("F-test", expires="tomorrow")]),
        config(waivers=[waiver("F-test"), waiver("F-test")]),
        config(waivers=[{**waiver("F-test"), "owner": "unknown-field"}]),
    ],
)
def test_malformed_unknown_config_and_waivers_are_rejected(tmp_path, bad):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        load_policy(path)
    with pytest.raises(ValueError):
        evaluate(report(), bad)


def test_duplicate_json_fields_are_rejected(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text('{"schema_version": 1, "only_new": true, "only_new": false}')
    with pytest.raises(ValueError, match="Duplicate"):
        load_policy(path)


def test_invalid_report_and_coverage_do_not_look_like_a_clean_gate():
    assert evaluate({}, config())["state"] == "incomplete"
    assert evaluate(report({}, coverage=[{}]), config())["state"] == "incomplete"
    duplicate = item()
    assert evaluate(report(duplicate, duplicate), config())["state"] == "incomplete"


def test_gate_is_json_serializable_and_preserves_report_policy_and_baseline():
    current = report(item())
    previous = report(item(), id="audit_baseline")
    policy = config(only_new=True)
    before = copy.deepcopy((current, policy, previous))
    result = evaluate(current, policy, previous)
    assert json.loads(json.dumps(result)) == result
    assert (current, policy, previous) == before


def test_unmatched_active_waiver_does_not_suppress_another_finding():
    current = item()
    result = evaluate(report(current), config(waivers=[waiver("F-unmatched")]))
    assert result["state"] == "failed"
    assert result["active_waivers"][0]["matched"] is False
    assert result["counts"]["waived"] == 0
    assert result["gate_findings"] == [current["id"]]


def test_nonboolean_intelligence_staleness_is_invalid_freshness_evidence():
    current = report(
        intel_snapshot=[
            {
                "source": "kev",
                "status": "ok",
                "stale": "false",
                "succeeded": "2026-10-04T11:00:00+00:00",
            }
        ]
    )
    result = evaluate(current, config(require_fresh_intel=True, required_feeds=["kev"]))
    assert result["state"] == "incomplete"


def test_toml_native_date_is_normalized_to_serializable_waiver(tmp_path):
    current = item()
    path = tmp_path / "policy.toml"
    path.write_text(f'''schema_version = 1
[[waivers]]
finding_id = "{current["id"]}"
reason = "Reviewed exception"
expires = 2026-10-04
''')
    loaded = load_policy(path)
    assert loaded["waivers"][0]["expires"] == "2026-10-04"
    assert evaluate(report(current), loaded)["state"] == "passed"
