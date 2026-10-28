"""Synthetic benchmark-completeness controls; no downloads or upstream execution."""

import copy
import http.client
import json
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest

from benchmarks import component_compare, fpfn_eval, mastg_demos, next_holdout, real_world, semgrep_compare
from benchmarks import run as regression
from scripts import collect_holdout_reports as collector
from scripts import verify_aab
from tests import test_collect_holdout_reports as collection_controls


def report(*, state="checked", partial=False, hit=False, rule_state=None):
    return {
        "findings": [
            {
                "rule_id": "AST-PATH-TRAVERSAL",
                "status": "candidate",
                "evidence": [{"path": "A.java", "line": 10}],
            }
        ]
        if hit
        else [],
        "inventory": {
            "partial": partial,
            "warnings": [],
            "dependencies": [],
            "android_config": [{"path": "AndroidManifest.xml", "cleartext": "false"}],
            "ios_config": [],
            "files_scanned": 1,
            "bytes_scanned": 10,
            "source_analysis": {
                "files": [{"path": "A.java", "state": state}],
                "functions": 0,
                "function_inventory_complete": True,
                "remaining_source_records": 0,
            },
        },
        "coverage": [
            {"rule_id": "AST-PATH-TRAVERSAL", "state": rule_state or ("partial" if partial else "checked")}
        ],
        "warnings": [],
        "summary": {"incomplete": partial},
    }


def install_pair(monkeypatch, reports, failure=None):
    pair = {
        "id": "new-pair",
        "repository": "example/synthetic",
        "platform": "android",
        "vulnerable_commit": "a" * 40,
        "fixed_commit": "b" * 40,
        "expected_rules": ["AST-PATH-TRAVERSAL"],
        "vulnerable_locations": [{"path": "app/A.java", "start_line": 10, "end_line": 10}],
        "fixed_locations": [{"path": "app/A.java"}],
    }

    def fetch(repository, commit, out):
        if failure and failure[0] == "fetch" and commit == pair["vulnerable_commit"]:
            raise failure[1]
        out.write_bytes(commit.encode())
        return {"url": "synthetic", "sha256": fpfn_eval.sha(commit.encode()), "bytes": len(commit)}

    def extract(archive, destination):
        if failure and failure[0] == "extract" and archive.parent.name == "vulnerable":
            raise failure[1]
        (destination / "app").mkdir(parents=True)
        (destination / "app/A.java").write_text("// fresh source\n")
        return destination

    def scan(target, output):
        if failure and failure[0] == "scan" and output.parent.name == "vulnerable":
            raise failure[1]
        return copy.deepcopy(reports[output.parent.name]), {}

    monkeypatch.setattr(fpfn_eval, "fetch", fetch)
    monkeypatch.setattr(fpfn_eval, "extract", extract)
    monkeypatch.setattr(fpfn_eval, "scan", scan)
    monkeypatch.setattr(fpfn_eval, "provenance", lambda: {})
    return pair


@pytest.mark.parametrize("state", ["checked", "skipped", "partial", "not-analyzed-as-source"])
@pytest.mark.parametrize("side", ["vulnerable", "fixed"])
@pytest.mark.parametrize("hit", [False, True])
def test_holdout_silence_requires_checked_labeled_scope_but_partial_hits_survive(
    tmp_path, monkeypatch, state, side, hit
):
    reports = {"vulnerable": report(hit=True), "fixed": report()}
    # This partial flag concerns unrelated global scope; the labeled rule itself
    # ran completely. Same-rule partial/not-run controls live in rule_scope.
    reports[side] = report(state=state, partial=True, hit=hit, rule_state="checked")
    pair = install_pair(monkeypatch, reports)
    result = fpfn_eval.evaluate(pair, tmp_path)
    expected = (
        ("tp" if side == "vulnerable" else "fp")
        if hit
        else "unscored"
        if state != "checked"
        else "fn"
        if side == "vulnerable"
        else "tn"
    )
    assert result["outcome"][side] == expected
    if side == "fixed" and state != "checked":
        assert result["outcome"]["discriminating_tp"] is False


@pytest.mark.parametrize(
    "failure",
    [
        ("extract", zipfile.BadZipFile("fresh bad zip")),
        ("fetch", http.client.IncompleteRead(b"fresh", 10)),
        ("scan", RecursionError("fresh nesting")),
    ],
)
def test_common_holdout_errors_are_independent_and_summary_is_saved(tmp_path, monkeypatch, failure):
    pair = install_pair(monkeypatch, {"vulnerable": report(hit=True), "fixed": report()}, failure)
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({"pairs": [pair]}))
    out = tmp_path / "results.json"
    monkeypatch.setattr(
        sys, "argv", ["fpfn", "--truth", str(truth), "--work", str(tmp_path / "work"), "--out", str(out)]
    )
    with pytest.raises(SystemExit) as caught:
        fpfn_eval.main()
    assert caught.value.code == 1
    result = json.loads(out.read_text())
    measured = result["pairs"][0]
    assert measured["vulnerable"]["error_phase"] == failure[0]
    assert measured["fixed"]["report_returned"] is True
    assert measured["outcome"]["vulnerable"] == "unscored"
    assert result["totals"]["errors"] == 1


@pytest.mark.parametrize("side", ["vulnerable", "fixed"])
def test_collector_rejects_scored_silence_from_skipped_scope(tmp_path, side):
    run = cast(Any, collection_controls.run).__wrapped__(tmp_path)
    pair = collection_controls.upgrade_v4(run)
    pair[side]["labeled_file_states"] = {"A.java": "skipped"}
    pair[side]["audit_incomplete"] = True
    pair["outcome"][side] = "fn" if side == "vulnerable" else "tn"
    pair["outcome"]["discriminating_tp"] = False
    pair["outcome"]["vulnerable_line_level"] = False
    run["summary"]["totals"] = collector.totals([pair], v4=True)
    run["summary"]["in_scope_totals"] = dict(run["summary"]["totals"])
    with pytest.raises(ValueError, match="scope|checked"):
        collector.successful_ids(
            run["summary"], collector.truth_pairs(run["truth"]), run["summary"]["truth_sha256"]
        )


def test_collector_accepts_partial_observed_positive_without_false_discrimination(tmp_path):
    run = cast(Any, collection_controls.run).__wrapped__(tmp_path)
    pair = collection_controls.upgrade_v4(run)
    pair["fixed"]["labeled_file_states"] = {"A.java": "partial"}
    pair["fixed"]["audit_incomplete"] = True
    pair["outcome"]["fixed"] = "fp"
    pair["outcome"]["discriminating_tp"] = False
    pair["fixed"]["hits"] = [{"rule_id": "AST-PATH-TRAVERSAL", "status": "candidate", "line": 10}]
    run["summary"]["totals"] = collector.totals([pair], v4=True)
    run["summary"]["in_scope_totals"] = dict(run["summary"]["totals"])
    assert collector.successful_ids(
        run["summary"], collector.truth_pairs(run["truth"]), run["summary"]["truth_sha256"]
    ) == {pair["id"]}


@pytest.mark.parametrize(
    "partial,hit,expected", [(True, False, "unscored"), (True, True, "tp"), (False, False, "fn")]
)
def test_mastg_partial_silence_is_unscored_and_positive_is_observational(
    tmp_path, monkeypatch, partial, hit, expected
):
    import mobile_audit.audit
    import mobile_audit.maswe

    source = tmp_path / "demo"
    source.mkdir()
    (source / "A.java").write_text("class A {}")
    monkeypatch.setattr(mobile_audit.audit, "scan", lambda *a: report(partial=partial, hit=hit))
    monkeypatch.setattr(mobile_audit.maswe, "from_beta", lambda value: {"MASWE-0050"})
    entry = {
        "id": "MASTG-DEMO-9001",
        "test": "TEST",
        "weakness_beta": "synthetic",
        "label": "fail",
        "directory": source,
    }
    measured = mastg_demos.evaluate([entry], tmp_path / "work")
    assert measured["demos"][0]["outcome"] == expected
    assert measured["summary"].get("fn", 0) == int(expected == "fn")


def test_mastg_bad_demo_metadata_is_an_error_row_and_main_returns_nonzero(tmp_path, monkeypatch):
    source = tmp_path / "source"
    demo = source / "demos/android/group/MASTG-DEMO-9001"
    demo.mkdir(parents=True)
    (demo / "MASTG-DEMO-9001.md").write_text("fresh malformed front matter")
    entries = mastg_demos.demos(source)
    assert len(entries) == 1 and entries[0].get("error")
    monkeypatch.setattr(mastg_demos, "fetch", lambda *a: source)
    out = tmp_path / "summary.json"
    monkeypatch.setattr(sys, "argv", ["mastg", "--work", str(tmp_path / "work"), "--out", str(out)])
    assert mastg_demos.main() == 1
    assert json.loads(out.read_text())["summary"]["error"] == 1


@pytest.mark.parametrize("kind", ["failed", "ambiguous"])
def test_component_query_partial_does_not_hide_validation_failure(monkeypatch, kind):
    coordinate = {"ecosystem": "Maven", "name": "synthetic:lib", "version": "1"}
    monkeypatch.setattr(
        component_compare, "_record_observation", lambda *a, **k: {"state": kind, "detected": None}
    )
    assert (
        component_compare.parse_apsa_osv({"coordinate": coordinate}, [], ["synthetic failure"], [])["state"]
        == kind
    )


@pytest.mark.parametrize("reason", ["error", "partial"])
def test_regression_execution_and_partial_are_not_false_negatives(tmp_path, monkeypatch, reason):
    source = tmp_path / "A.java"
    source.write_text("class A {}")
    rule = "AST-PATH-TRAVERSAL"
    case = {
        "id": "new",
        "path": "A.java",
        "kind": "source",
        "variant": "vulnerable",
        "pair": "p",
        "rationale": "fresh synthetic",
        "expected": [{"rule_id": rule, "status": "candidate"}],
    }
    if reason == "error":
        case["sha256"] = "0" * 64
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": 1, "rules": [rule], "cases": [case]}))
    monkeypatch.setattr(
        regression.source_analysis,
        "analyze_sources",
        lambda *a: {"findings": [], "coverage": [{"rule_id": rule, "state": "not-run"}], "warnings": []},
    )
    result = regression.run(manifest)
    assert result["metrics"][rule]["fn"] == 0
    assert result["metrics"][rule]["errored" if reason == "error" else "incomplete"] == 1


def test_semgrep_comparison_not_run_is_not_completed_tn(tmp_path, monkeypatch):
    case = {
        "id": "new",
        "category": "md5",
        "risky": False,
        "sha256": "0" * 64,
        "input_kind": "source-zip",
        "language": "java",
    }
    (tmp_path / "manifest.json").write_text("{}")
    monkeypatch.setattr(semgrep_compare, "read_manifest", lambda root: {"cases": [case]})
    monkeypatch.setattr(semgrep_compare, "cases", lambda: [case])
    monkeypatch.setattr(semgrep_compare, "project_files", lambda base: {"A.java": b"class A {}"})
    monkeypatch.setattr(
        semgrep_compare,
        "analyze_sources",
        lambda *a: {
            "findings": [],
            "warnings": [],
            "coverage": [{"rule_id": "AST-CRYPTO-MD5", "state": "not-run"}],
        },
    )
    result = semgrep_compare.run(tmp_path, tmp_path / "result", None, None)
    assert result["summary"]["apsa"]["partial"] == 1 and result["summary"]["apsa"]["tn"] == 0


@pytest.mark.parametrize("problem", ["summary", "coverage", "mobsf"])
def test_real_world_stable_partial_or_unmeasured_report_is_not_scored(tmp_path, monkeypatch, problem):
    app = {
        "id": "tusky",
        "repository": "example/synthetic",
        "commit": "0" * 40,
        "platform": "android",
        "config_label": {"path": "AndroidManifest.xml", "rule": "ANDROID-CLEARTEXT", "expected": False},
        "dependencies": [],
    }
    observed = report()
    if problem == "summary":
        observed["summary"]["incomplete"] = True
    elif problem == "coverage":
        observed["coverage"][0]["state"] = "not-run"
    monkeypatch.setattr(
        real_world, "load_spec", lambda: {"apps": [app], "dependency_cases": [], "limits": {}}
    )
    monkeypatch.setattr(
        real_world,
        "read_prepared",
        lambda root: {"apps": [{"input": "app.zip", "sha256": "x", "source_entries": 1}]},
    )
    monkeypatch.setattr(real_world, "apsa_report", lambda *a: (copy.deepcopy(observed), 0.01))
    monkeypatch.setattr(real_world, "engine_metadata", lambda *a: {})
    monkeypatch.setattr(real_world, "evaluate_os", lambda *a: [])
    monkeypatch.setattr(real_world, "mobsf_observation", lambda *a: {"rules": [], "warnings": []})
    monkeypatch.setattr(real_world, "OSVTransport", lambda *a, **k: SimpleNamespace(close=lambda: None))
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    monkeypatch.setattr(real_world, "SPEC", spec)
    (tmp_path / "manifest.json").write_text("{}")
    (tmp_path / "osv").mkdir()
    (tmp_path / "osv/manifest.json").write_text("{}")
    mobsf = SimpleNamespace(wait=lambda: None, scan=lambda *a: ({}, 0.01)) if problem == "mobsf" else None
    result = real_world.run(tmp_path, tmp_path / "result", "python", 1, cast(Any, mobsf), False)
    item = result["apps"][0]
    if problem == "mobsf":
        assert item["tools"]["mobsf"]["state"] == "unmeasured"
    else:
        assert item["tools"]["apsa"]["state"] == "partial"
        assert item["config_label"]["correct"] is False


@pytest.mark.parametrize("problem", ["symlink", "oversized"])
def test_frozen_osv_rejects_unsafe_response_before_read(tmp_path, monkeypatch, problem):
    payload = {"package": {"ecosystem": "Maven", "name": "synthetic:lib"}, "version": "1"}
    key = real_world.sha(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    body = b"x" * 16
    target = tmp_path / f"{key}.json"
    if problem == "symlink":
        destination = tmp_path / "fresh-target.json"
        destination.write_bytes(body)
        target.symlink_to(destination)
    else:
        target.write_bytes(body)
        monkeypatch.setattr(real_world, "MAX_RESPONSE", 8)
    (tmp_path / "manifest.json").write_text(
        json.dumps({"responses": [{"key": key, "sha256": real_world.sha(body), "status": 200}]})
    )
    original = Path.read_bytes

    def guarded(path):
        if path == target:
            pytest.fail("unsafe frozen response was read before bounds validation")
        return original(path)

    monkeypatch.setattr(Path, "read_bytes", guarded)
    transport = real_world.OSVTransport(tmp_path, capture=False)
    try:
        with pytest.raises((OSError, ValueError)):
            transport.handle(httpx.Request("POST", "https://api.osv.dev/v1/query", json=payload))
    finally:
        transport.close()


@pytest.mark.parametrize("condition", ["partial", "unstable", "completed"])
def test_next_holdout_scores_only_stable_complete_selected_facts(tmp_path, monkeypatch, condition):
    dep = {"ecosystem": "Maven", "name": "synthetic:lib", "version": "1", "path": "build.gradle"}
    app = {"id": "tusky", "dependencies": [dep], "config_label": {"path": "AndroidManifest.xml"}}
    truth = tmp_path / "truth.json"
    truth.write_text(json.dumps({"documents": [], "apps": [app]}))
    captured = tmp_path / "captured"
    captured.mkdir()
    raw = b"new synthetic source placeholder"
    (captured / "tusky.zip").write_bytes(raw)
    prior = {
        "vendor_captures": [],
        "apps": [{"id": "tusky", "upstream": {}, "config": {}, "input": {"sha256": next_holdout.sha(raw)}}],
    }
    (captured / "summary.json").write_text(json.dumps(prior))
    monkeypatch.setattr(next_holdout, "TRUTH", truth)
    monkeypatch.setattr(next_holdout, "TRUTH_SHA", next_holdout.sha(truth.read_bytes()))
    monkeypatch.setattr(next_holdout, "FIRST_SHA", next_holdout.sha((captured / "summary.json").read_bytes()))
    monkeypatch.setattr(next_holdout, "evaluate_cves", lambda *a: [])
    monkeypatch.setattr(next_holdout, "engine_metadata", lambda *a: {})
    monkeypatch.setattr(next_holdout.subprocess, "check_output", lambda *a, **k: "synthetic-revision")
    calls = []

    def scan(*args):
        value = report(partial=condition == "partial")
        value["inventory"]["dependencies"] = [{**dep, "confidence": "exact"}]
        if calls and condition == "unstable":
            value["inventory"]["android_config"][0]["cleartext"] = "true"
        calls.append(1)
        return value, 0.01

    monkeypatch.setattr(next_holdout, "apsa_report", scan)
    result = next_holdout.run(tmp_path / "work", captured)
    measured = result["apps"][0]
    assert measured["state"] == condition
    assert measured["config"]["scored"] is (condition == "completed")
    assert measured["config"]["correct"] is (condition == "completed")
    assert measured["dependencies_scored"][0]["extracted"] is (condition == "completed")
    assert measured["dependency_observations"][0]["extracted"] is True


@pytest.mark.parametrize("partial,warnings", [(True, ["Synthetic scope warning"]), (True, []), (False, [])])
def test_generated_aab_result_keeps_inspection_limits_explicit(tmp_path, monkeypatch, partial, warnings):
    aapt = tmp_path / "aapt2"
    android = tmp_path / "android.jar"
    aapt.write_bytes(b"fresh synthetic executable placeholder")
    android.write_bytes(b"fresh synthetic android placeholder")
    dump = "\n".join(
        f' A: {name}="{value}" (Raw: "{value}")'
        for name, value in [
            ("package", "audit.generated"),
            ("android:debuggable", "true"),
            ("android:usesCleartextTraffic", "false"),
            ("android:minSdkVersion", "21"),
            ("android:targetSdkVersion", "35"),
        ]
    )

    def command(argv):
        if "link" in argv:
            with zipfile.ZipFile(argv[argv.index("-o") + 1], "w") as archive:
                archive.writestr("AndroidManifest.xml", b"fresh synthetic protobuf placeholder")
        return "synthetic aapt2" if "version" in argv else dump

    monkeypatch.setattr(verify_aab, "command", command)
    monkeypatch.setattr(verify_aab, "decode_manifest", lambda raw: (b"audit.generated", []))
    monkeypatch.setattr(
        verify_aab,
        "inspect_target",
        lambda bundle: (
            {
                "package": "audit.generated",
                "android_config": [{"debuggable": "true", "cleartext": "false"}],
                "android_sdk": {"min": "21", "target": "35"},
                "android_modules": ["base"],
                "partial": partial,
                "warnings": warnings,
            },
            [],
        ),
    )
    work = tmp_path / "work"
    monkeypatch.setattr(
        sys, "argv", ["aab", "--aapt2", str(aapt), "--android", str(android), "--work", str(work)]
    )
    verify_aab.main()
    result = json.loads((work / "summary.json").read_text())
    assert result["inspection_partial"] is partial and result["inspection_warnings"] == warnings
    assert result["declarations_verified"] is True
    assert "no whole-bundle" in result["verification_scope"]


def test_nested_report_failure_retains_scan_execution_metadata(tmp_path, monkeypatch):
    output = tmp_path / "scan"

    def process(*args, **kwargs):
        (output / "report.json").write_bytes(b"[" * 20000 + b"0" + b"]" * 20000)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(fpfn_eval.subprocess, "run", process)
    with pytest.raises(fpfn_eval.ScanError) as caught:
        fpfn_eval.scan(tmp_path / "source", output)
    assert caught.value.execution["exit_code"] == 0
    assert caught.value.execution["timed_out"] is False
