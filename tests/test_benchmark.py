from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "mobile_audit_benchmark", Path(__file__).parents[1] / "benchmarks" / "run.py"
)
assert SPEC is not None and SPEC.loader is not None
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)

URL_RULE = "AST-WEBVIEW-UNTRUSTED-URL"
HOST_RULE = "AST-WEBVIEW-HOST-ALLOWLIST"


def test_committed_corpus_runs_actual_engines_and_is_reproducible():
    first = benchmark.run()
    second = benchmark.run()
    assert first == second
    assert first["summary"]["cases"] == 31
    assert first["passed"] is True, first["disagreements"]
    assert first["summary"]["fp"] == first["summary"]["fn"] == 0
    assert any(case["kind"] == "binary" and case["observed"] for case in first["cases"])
    assert first["parser_versions"]["tree-sitter"]
    assert set(first["engine_sha256"]) == {"source_analysis", "binary_analysis"}
    assert json.loads(json.dumps(first)) == first


def test_false_negative_and_false_positive_are_detected_and_counted(monkeypatch):
    monkeypatch.setattr(
        benchmark.source_analysis,
        "analyze_sources",
        lambda _: {
            "findings": [{"rule_id": HOST_RULE, "status": "candidate"}],
            "coverage": [],
            "warnings": [],
        },
    )
    result = benchmark.run(case_ids=["java-intent-vulnerable"])
    assert result["passed"] is False
    assert result["exit_code"] == 1
    assert result["metrics"][URL_RULE]["fn"] == 1
    assert result["metrics"][HOST_RULE]["fp"] == 1
    assert result["metrics"][HOST_RULE]["recall"]["value"] is None
    assert result["metrics"][URL_RULE]["precision"]["value"] is None
    disagreement = result["disagreements"][0]
    assert disagreement["false_negatives"] == [{"rule_id": URL_RULE, "status": "candidate"}]
    assert disagreement["false_positives"] == [{"rule_id": HOST_RULE, "status": "candidate"}]


def test_overstated_evidence_status_is_a_disagreement(monkeypatch):
    monkeypatch.setattr(
        benchmark.source_analysis,
        "analyze_sources",
        lambda _: {
            "findings": [{"rule_id": URL_RULE, "status": "runtime-confirmed"}],
            "coverage": [],
            "warnings": [],
        },
    )
    result = benchmark.run(case_ids=["java-intent-vulnerable"])
    assert result["passed"] is False
    assert result["metrics"][URL_RULE]["tp"] == 0
    assert result["metrics"][URL_RULE]["fp"] == result["metrics"][URL_RULE]["fn"] == 1


def test_empty_positive_denominators_are_undefined_not_perfect():
    result = benchmark.run(case_ids=["java-intent-fixed"])
    assert result["passed"] is True
    assert all(
        metric["precision"]["value"] is None and metric["recall"]["value"] is None
        for metric in result["metrics"].values()
    )
    assert result["metrics"][URL_RULE]["precision"]["state"].startswith("undefined")


def test_repeated_findings_do_not_inflate_case_label_support(monkeypatch):
    monkeypatch.setattr(
        benchmark.source_analysis,
        "analyze_sources",
        lambda _: {
            "findings": [{"rule_id": URL_RULE, "status": "candidate"}] * 8,
            "coverage": [],
            "warnings": [],
        },
    )
    result = benchmark.run(case_ids=["java-intent-vulnerable"])
    assert result["passed"] is True
    assert result["metrics"][URL_RULE]["tp"] == 1


@pytest.mark.parametrize(
    "analysis",
    [
        {"findings": [], "warnings": ["parser recovered unsupported syntax"], "coverage": []},
        {"findings": [], "warnings": [], "coverage": [{"rule_id": URL_RULE, "state": "not-run"}]},
    ],
)
def test_empty_findings_with_incomplete_analysis_cannot_pass(monkeypatch, analysis):
    monkeypatch.setattr(benchmark.source_analysis, "analyze_sources", lambda _: analysis)
    result = benchmark.run(case_ids=["java-intent-fixed"])
    assert result["passed"] is False
    assert result["disagreements"]


def test_binary_fixture_drift_requires_relabeling_before_analysis(tmp_path, monkeypatch):
    manifest = json.loads(benchmark.DEFAULT_MANIFEST.read_text())
    case = copy.deepcopy(next(case for case in manifest["cases"] if case["id"] == "dex-unsafe"))
    case["path"] = str((benchmark.DEFAULT_MANIFEST.parent / case["path"]).resolve())
    case["sha256"] = "0" * 64
    manifest["cases"] = [case]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    monkeypatch.setattr(
        benchmark.binary_analysis, "analyze_binary", lambda *_: pytest.fail("changed bytes reached parser")
    )
    result = benchmark.run(path)
    assert result["passed"] is False
    assert "Fixture SHA-256 differs" in result["disagreements"][0]["error"]
    assert result["summary"]["fn"] == 6


def test_cli_writes_same_json_and_returns_nonzero_for_genuine_disagreement(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        benchmark.source_analysis,
        "analyze_sources",
        lambda _: {"findings": [], "coverage": [], "warnings": []},
    )
    output = tmp_path / "result.json"
    assert benchmark.main(["--case", "java-intent-vulnerable", "--out", str(output)]) == 1
    stdout = json.loads(capsys.readouterr().out)
    assert json.loads(output.read_text()) == stdout
    assert stdout["summary"]["fn"] == 1


def test_unknown_case_and_invalid_ground_truth_are_rejected(tmp_path):
    with pytest.raises(ValueError, match="Unknown benchmark"):
        benchmark.run(case_ids=["unlabeled"])
    manifest = json.loads(benchmark.DEFAULT_MANIFEST.read_text())
    manifest["cases"][0]["expected"][0]["status"] = "runtime-confirmed"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="only candidate"):
        benchmark.run(path)


def test_fixture_hashes_bind_expected_bytes():
    manifest = json.loads(benchmark.DEFAULT_MANIFEST.read_text())
    for case in manifest["cases"]:
        if case["kind"] == "binary":
            assert (
                benchmark._hash((benchmark.DEFAULT_MANIFEST.parent / case["path"]).read_bytes())
                == case["sha256"]
            )
