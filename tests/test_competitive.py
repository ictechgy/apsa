from __future__ import annotations

import copy
import json

import pytest

from benchmarks.competitive import (
    MobSF,
    apsa_observation,
    measurement_state,
    mobsf_observation,
    observation_signature,
    read_manifest,
    score,
)
from benchmarks.competitive_cases import generate


def test_generated_ground_truth_and_source_bytes_are_deterministic_and_not_overwritten(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    assert generate(first) == generate(second)
    assert len(read_manifest(first)["cases"]) == 40
    with pytest.raises(FileExistsError):
        generate(first)


@pytest.mark.parametrize("mutation", ["label", "missing", "input", "mapping"])
def test_ground_truth_or_input_drift_is_rejected_before_scanning(tmp_path, mutation):
    root = tmp_path / "fixtures"
    manifest = generate(root)
    if mutation == "label":
        manifest["cases"][0]["risky"] = False
    elif mutation == "missing":
        manifest["cases"].pop()
    elif mutation == "input":
        (root / manifest["cases"][0]["input"]).write_bytes(b"changed source")
    else:
        manifest["mapping"]["url"]["mobsf"] = ["a_result_seen_after_running"]
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        read_manifest(root)


def test_failed_risky_scan_is_not_silently_excluded_from_end_to_end_recall():
    positive = {
        "input_kind": "source-zip",
        "category": "ssl",
        "risky": True,
        "tools": {"apsa": {"state": "completed", "matched": ["AST-WEBVIEW-SSL-BYPASS"], "seconds": [1.0]}},
    }
    failed = copy.deepcopy(positive)
    failed["tools"]["apsa"] = {"state": "failed", "matched": [], "seconds": []}
    negative = copy.deepcopy(positive)
    negative["risky"] = False
    negative["tools"]["apsa"]["matched"] = []
    result = score([positive, failed, negative], "apsa", "source-zip")
    assert result["completed_case_recall"] == 1
    assert result["end_to_end_recall"] == 0.5
    assert result["failed"] == result["failed_risky"] == 1
    assert result["tn"] == 1
    assert score([negative], "apsa")["alert_precision"] is None


@pytest.mark.parametrize("state", ["partial", "unsupported", "unmeasured"])
def test_abstained_report_is_neither_false_negative_nor_true_negative(state):
    record = {
        "input_kind": "source-zip",
        "category": "ssl",
        "risky": True,
        "tools": {"apsa": {"state": state, "matched": [], "seconds": [0.1]}},
    }
    result = score([record], "apsa")
    assert result[state] == 1
    assert result["fn"] == result["tn"] == result["failed"] == 0
    assert result["completed_case_recall"] is None
    assert result["median_elapsed_seconds"] == 0.1


def test_report_completion_requires_explicit_coverage_not_only_successful_process():
    partial = apsa_observation(
        {
            "findings": [],
            "coverage": [{"rule_id": "AST-CRYPTO-WEAK-HASH", "state": "partial"}],
            "summary": {"incomplete": True},
        }
    )
    assert measurement_state([partial], "apsa", "md5") == "partial"
    unknown = mobsf_observation({"file_name": "new.zip", "code_analysis": {"findings": {}}})
    assert measurement_state([unknown], "mobsf", "md5") == "unmeasured"
    assert measurement_state([unknown], "mobsf", "url") == "unsupported"
    complete = apsa_observation({"findings": [], "coverage": [], "summary": {"incomplete": False}})
    assert measurement_state([complete], "apsa", "md5") == "completed"


@pytest.mark.parametrize("mutation", ["extra", "kind", "rehashed"])
def test_sampling_unit_and_source_truth_cannot_be_rewritten_with_a_matching_hash(tmp_path, mutation):
    import hashlib

    root = tmp_path / "fixtures"
    manifest = generate(root)
    case = manifest["cases"][0]
    if mutation == "extra":
        manifest["cases"].append(case | {"id": "extra", "source_case": case["id"]})
    elif mutation == "kind":
        case["input_kind"] = "apk"
    else:
        path = root / case["input"]
        path.write_bytes(b"replaced")
        case["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    (root / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises((ValueError, __import__("zipfile").BadZipFile)):
        read_manifest(root)


def test_same_rules_with_different_completion_state_are_not_stable():
    observed = apsa_observation({"findings": [], "coverage": [], "summary": {"incomplete": False}})
    changed = copy.deepcopy(observed)
    changed["audit_incomplete"] = True
    assert observation_signature(observed) != observation_signature(changed)


def test_report_normalizers_keep_coverage_unknown_and_broad_alerts_visible():
    report = {
        "file_name": "synthetic.zip",
        "code_analysis": {"findings": {"android_logging": {"files": {"Probe.java": "7"}}}},
        "manifest_analysis": [{"rule": "app_is_debuggable"}],
    }
    observed = mobsf_observation(report)
    assert set(observed["rules"]) == {"android_logging", "manifest:app_is_debuggable"}
    assert observed["coverage"] is observed["audit_incomplete"] is None
    apsa = apsa_observation(
        {
            "findings": [],
            "coverage": [{"rule_id": "AST-WEBVIEW-SSL-BYPASS", "state": "partial"}],
            "summary": {"incomplete": True},
        }
    )
    assert apsa["audit_incomplete"] is True
    with pytest.raises(ValueError):
        mobsf_observation({"file_name": "synthetic.zip"})


@pytest.mark.parametrize(
    "url", ["https://example.test", "http://example.test", "http://127.0.0.1.example.test"]
)
def test_benchmark_does_not_accept_remote_upload_services(url):
    with pytest.raises(ValueError, match="fresh local"):
        MobSF(url, "synthetic-only")


@pytest.mark.parametrize(
    "url,ip",
    [
        ("http://169.254.169.254:8000", "169.254.169.254"),
        ("http://1.1.1.1:8000", "1.1.1.1"),
        ("http://172.18.0.3:8000", "172.18.0.2"),
        ("http://172.18.0.2:8001", "172.18.0.2"),
    ],
)
def test_inspected_container_override_rejects_non_private_or_mismatched_targets(url, ip):
    with pytest.raises(ValueError, match="inspected fresh"):
        MobSF(url, "synthetic-only", ip)


def test_exact_inspected_private_container_can_be_used_without_port_publication():
    service = MobSF("http://172.18.0.2:8000", "synthetic-only", "172.18.0.2")
    service.client.close()


def test_http_success_with_failed_decompiler_is_not_a_clean_code_scan():
    report = {
        "file_name": "generated.apk",
        "code_analysis": {"findings": {}},
        "manifest_analysis": [{"rule": "app_is_debuggable"}],
        "logs": [{"status": "Decompiling with JADX failed", "exception": "FileNotFoundError"}],
    }
    with pytest.raises(ValueError, match="incomplete"):
        mobsf_observation(report, "ssl")
    assert "manifest:app_is_debuggable" in mobsf_observation(report, "debug")["rules"]


def test_successful_dex_fallback_after_an_apk_warning_is_not_treated_as_failure():
    report = {
        "file_name": "generated.apk",
        "code_analysis": {"findings": {}},
        "logs": [{"status": "Decompiling with JADX failed, attempting on all DEX files", "exception": None}],
    }
    assert mobsf_observation(report, "ssl")["rules"] == []


def _synthetic_metric_record(state, risky=True, detected=False, tool="apsa"):
    result = {"matched": ["synthetic-alert"] if detected else [], "seconds": [0.1]}
    if state is not None:
        result["state"] = state
    return {"input_kind": "source-zip", "category": "ssl", "risky": risky, "tools": {tool: result}}


def test_metric_denominators_keep_completion_penalty_and_observations_separate():
    records = [
        _synthetic_metric_record("completed", True, True),
        _synthetic_metric_record("completed", True, False),
        _synthetic_metric_record("completed", False, True),
        _synthetic_metric_record("completed", False, False),
        *[
            _synthetic_metric_record(state, risky, detected)
            for state in ("partial", "unmeasured")
            for risky in (True, False)
            for detected in (True, False)
        ],
        _synthetic_metric_record("unsupported"),
        _synthetic_metric_record("failed"),
        _synthetic_metric_record(None),
    ]
    observed = score(records, "apsa")
    assert observed["completed"] == observed["scored_cases"] == 4
    assert [observed[key] for key in ("tp", "fp", "fn", "tn")] == [1, 1, 1, 1]
    assert observed["cases"] == 15 and observed["eligible_cases"] == 14
    assert observed["completion_rate"] == 4 / 15
    assert observed["eligible_completion_rate"] == 4 / 14
    assert observed["coverage_measurement_rate"] == 8 / 14
    assert observed["end_to_end_recall"] == observed["eligible_risky_completed_detection_rate"] == 1 / 8
    assert observed["denominators"]["end_to_end_recall"] == 8
    assert observed["completed_case_recall"] == observed["completed_alert_precision"] == 0.5
    assert observed["missing_state"] == 1 and observed["failed_risky"] == 2
    for state in ("partial", "unmeasured"):
        for suffix in ("detected_risk", "silent_risk", "safe_alert", "safe_silent"):
            assert observed[f"{state}_{suffix}"] == 1
    assert observed["coverage_unmeasured_cases"] == observed["unmeasured"] == 4


def test_metric_no_eligible_cases_and_absent_tool_results_have_explicit_denominators():
    record = _synthetic_metric_record("unsupported")
    absent = {**record, "tools": {}}
    observed = score([record, absent], "apsa")
    assert observed["selected_cases"] == 2 and observed["missing_tool_cases"] == 1
    assert observed["eligible_cases"] == observed["completed"] == 0
    assert observed["eligible_completion_rate"] is observed["coverage_measurement_rate"] is None
    assert observed["completed_case_recall"] is observed["end_to_end_recall"] is None
    assert observed["completion_rate"] == 0
    assert score([], "apsa")["completion_rate"] is None


@pytest.mark.parametrize(
    "observation",
    [
        {"coverage": None, "audit_incomplete": None},
        {"coverage": [], "audit_incomplete": None},
        {"coverage": [{}], "audit_incomplete": False},
        {"coverage": [{"state": "unknown"}], "audit_incomplete": False},
    ],
)
def test_absent_or_missing_coverage_state_is_unmeasured_not_analyzer_failure(observation):
    assert measurement_state([observation], "apsa", "ssl") == "unmeasured"
    assert measurement_state([], "apsa", "ssl") == "unmeasured"


def test_explicit_partial_evidence_survives_other_unmeasured_observations():
    unknown = {"coverage": None, "audit_incomplete": None}
    partial = {"coverage": [{"state": "partial"}], "audit_incomplete": False}
    assert measurement_state([unknown, partial], "apsa", "ssl") == "partial"
    assert measurement_state([unknown], "mobsf", "url") == "unsupported"


@pytest.mark.parametrize(
    "extra",
    [
        {"runtime": [{"partial": True}]},
        {"online_query": {"requested": True, "errors": ["synthetic failure"]}},
        {"inventory": {"input_snapshot": {"app_scope_complete": False}}},
    ],
)
def test_benchmark_observation_cannot_hide_explicit_partial_work_behind_summary(extra):
    observed = apsa_observation({"findings": [], "coverage": [], "summary": {"incomplete": False}, **extra})
    assert observed["audit_incomplete"] is True
    assert measurement_state([observed], "apsa", "ssl") == "partial"
