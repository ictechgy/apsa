"""Checked syntax cannot prove silence from an unchecked labeled security rule."""

import json
from typing import Any, cast

import pytest

from benchmarks import fpfn_eval, fresh
from mobile_audit.source_analysis import analyze_sources
from mobile_audit.verify import COVERAGE_ALIASES
from scripts import collect_holdout_reports as collector
from tests import test_collect_holdout_reports as collection
from tests.test_external_benchmark_review import install_pair, report


def required_checks(pair):
    rules = pair.get("expected_rules", []) or [
        rule["id"]
        for rule in fpfn_eval.source_rules()
        if set(rule.get("maswe", [])) & set(pair.get("weaknesses", []))
    ]
    return sorted({COVERAGE_ALIASES.get(rule) or rule for rule in rules})


@pytest.mark.parametrize("state", ["partial", "not-run", "not-applicable", "missing", "checked"])
@pytest.mark.parametrize("side", ["vulnerable", "fixed"])
def test_checked_file_requires_its_expected_rule_for_silent_score(tmp_path, monkeypatch, state, side):
    reports = {"vulnerable": report(hit=True), "fixed": report()}
    reports[side] = report(partial=True)
    reports[side]["coverage"] = (
        [] if state == "missing" else [{"rule_id": "AST-PATH-TRAVERSAL", "state": state}]
    )
    pair = install_pair(monkeypatch, reports)
    result = fpfn_eval.evaluate(pair, tmp_path)
    assert result["outcome"][side] == (
        ("fn" if side == "vulnerable" else "tn") if state == "checked" else "unscored"
    )
    assert result[side]["labeled_rule_states"] == {
        "AST-PATH-TRAVERSAL": "not-run" if state == "missing" else state
    }
    if side == "fixed":
        assert result["outcome"]["discriminating_tp"] is (state == "checked")


@pytest.mark.parametrize("rule", ["AST-CRYPTO-ECB", "AST-CRYPTO-WEAK-CIPHER", "AST-SQL-CONCAT"])
def test_actual_checked_swift_syntax_cannot_score_unimplemented_rule(tmp_path, monkeypatch, rule):
    source = "func harmless() { let value = 1 }"
    analyzed = analyze_sources([{"path": "A.swift", "text": source}])
    assert analyzed["metadata"]["files"][0]["state"] == "checked"
    assert next(row for row in analyzed["coverage"] if row["rule_id"] == rule)["state"] == "not-run"
    observed = report()
    observed["inventory"]["source_analysis"] = analyzed["metadata"]
    observed["coverage"] = analyzed["coverage"]
    observed["findings"] = analyzed["findings"]
    pair = install_pair(monkeypatch, {"vulnerable": observed, "fixed": observed})
    pair["expected_rules"] = [rule]
    pair["vulnerable_locations"] = [{"path": "app/A.swift", "start_line": 1, "end_line": 1}]
    pair["fixed_locations"] = [{"path": "app/A.swift"}]

    def extract(archive, destination):
        (destination / "app").mkdir(parents=True)
        (destination / "app/A.swift").write_text(source)
        return destination

    monkeypatch.setattr(fpfn_eval, "extract", extract)
    result = fpfn_eval.evaluate(pair, tmp_path)
    assert result["fixed"]["labeled_file_states"] == {"A.swift": "checked"}
    assert result["outcome"]["vulnerable"] == result["outcome"]["fixed"] == "unscored"


@pytest.mark.parametrize("side", ["vulnerable", "fixed"])
def test_observed_partial_rule_hit_remains_positive(tmp_path, monkeypatch, side):
    reports = {"vulnerable": report(), "fixed": report()}
    reports[side] = report(partial=True, hit=True)
    result = fpfn_eval.evaluate(install_pair(monkeypatch, reports), tmp_path)
    assert result["outcome"][side] == ("tp" if side == "vulnerable" else "fp")
    assert result[side]["labeled_rule_states"] == {"AST-PATH-TRAVERSAL": "partial"}


def test_unrelated_rule_partial_does_not_hide_checked_labeled_scope(tmp_path, monkeypatch):
    reports = {"vulnerable": report(hit=True), "fixed": report(partial=True)}
    reports["fixed"]["coverage"] = [
        {"rule_id": "AST-PATH-TRAVERSAL", "state": "checked"},
        {"rule_id": "AST-CRYPTO-ECB", "state": "not-run"},
    ]
    result = fpfn_eval.evaluate(install_pair(monkeypatch, reports), tmp_path)
    assert result["fixed"]["audit_incomplete"] is True
    assert result["outcome"]["fixed"] == "tn"
    assert result["outcome"]["discriminating_tp"] is True


def test_weakness_scope_requires_every_related_source_rule(tmp_path, monkeypatch):
    reports = {"vulnerable": report(hit=True), "fixed": report()}
    pair = install_pair(monkeypatch, reports)
    pair["expected_rules"] = []
    pair["weaknesses"] = ["MASWE-0050"]
    checks = required_checks(pair)
    assert "AST-PATH-TRAVERSAL" in checks and "AST-SQL-CONCAT" in checks
    for side in reports:
        reports[side]["coverage"] = [{"rule_id": rule, "state": "checked"} for rule in checks]
    reports["fixed"]["coverage"] = [
        {"rule_id": rule, "state": "not-run" if rule == "AST-SQL-CONCAT" else "checked"} for rule in checks
    ]
    result = fpfn_eval.evaluate(pair, tmp_path)
    assert result["outcome"]["vulnerable"] == "tp"
    assert result["outcome"]["fixed"] == "unscored"
    assert result["outcome"]["discriminating_tp"] is False
    assert set(result["fixed"]["labeled_rule_states"]) == set(checks)


@pytest.mark.parametrize("state,expected", [("checked", "tn"), ("not-run", "unscored")])
def test_configuration_finding_uses_its_shared_coverage_alias(tmp_path, monkeypatch, state, expected):
    reports = {side: report() for side in ("vulnerable", "fixed")}
    pair = install_pair(monkeypatch, reports)
    pair["expected_rules"] = ["ANDROID-DEBUG"]
    for observed in reports.values():
        observed["coverage"] = [{"rule_id": "ANDROID-CONFIG", "state": state}]
    result = fpfn_eval.evaluate(pair, tmp_path)
    assert result["outcome"]["fixed"] == expected
    assert result["fixed"]["labeled_rule_states"] == {"ANDROID-CONFIG": state}


def test_conflicting_duplicate_coverage_never_counts_as_fully_checked(tmp_path, monkeypatch):
    reports = {"vulnerable": report(hit=True), "fixed": report()}
    reports["fixed"]["coverage"].append({"rule_id": "AST-PATH-TRAVERSAL", "state": "not-run"})
    result = fpfn_eval.evaluate(install_pair(monkeypatch, reports), tmp_path)
    assert result["outcome"]["fixed"] == "unscored"
    assert result["fixed"]["labeled_rule_states"] == {"AST-PATH-TRAVERSAL": "partial"}


def collector_case(tmp_path):
    run = cast(Any, collection.run).__wrapped__(tmp_path)
    pair = collection.upgrade_v4(run)
    checks = required_checks(pair)
    for side in ("vulnerable", "fixed"):
        pair[side]["labeled_rule_states"] = {rule: "checked" for rule in checks}
        collection.report(run, side).write_text(
            json.dumps(
                {
                    "report": {
                        "findings": [],
                        "inventory": {"partial": True},
                        "coverage": [{"rule_id": rule, "state": "checked"} for rule in checks],
                    }
                }
            )
        )
    return run, pair, checks


@pytest.mark.parametrize("state", ["not-run", "partial", "missing"])
def test_collector_rejects_silent_or_discriminating_scores_from_unchecked_rules(tmp_path, state):
    run, pair, checks = collector_case(tmp_path)
    rule = checks[0]
    if state == "missing":
        del pair["fixed"]["labeled_rule_states"][rule]
    else:
        pair["fixed"]["labeled_rule_states"][rule] = state
    with pytest.raises(ValueError, match="rule|coverage|checked"):
        collector.successful_ids(
            run["summary"], collector.truth_pairs(run["truth"]), run["summary"]["truth_sha256"]
        )


@pytest.mark.parametrize("tamper", [False, True])
def test_collector_independently_checks_raw_rule_coverage(tmp_path, tamper):
    run, _, checks = collector_case(tmp_path)
    raw_path = collection.report(run, "fixed")
    raw = json.loads(raw_path.read_text())
    raw["report"]["coverage"].append({"rule_id": "AST-CRYPTO-ECB", "state": "not-run"})
    if tamper:
        raw["report"]["coverage"][0]["state"] = "not-run"
    raw_path.write_text(json.dumps(raw))
    collection.save_results(run)
    manifest = collection.collect(run)
    assert manifest["status"] == ("incomplete" if tamper else "complete")
    assert bool(manifest["errors"]) is tamper
    assert checks


def test_fresh_known_partial_cases_name_exactly_the_eight_unsupported_swift_cases():
    assert fresh.EXPECTED_PARTIAL_CASES == {
        "java-cross-function-irrelevant",
        "swift-url-vulnerable",
        "swift-url-fixed",
        "swift-documentation-irrelevant",
        "swift-navigation-vulnerable",
        "swift-navigation-fixed",
        "swift-query-javascript-vulnerable",
        "swift-query-javascript-fixed",
        "swift-unrelated-shadow",
    }
