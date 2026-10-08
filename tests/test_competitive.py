from __future__ import annotations

import copy
import json

import pytest

from benchmarks.competitive import (
    MobSF,
    apsa_observation,
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
