"""Partial controls retain frozen supported observations without accuracy claims."""

import copy
import json
from pathlib import Path

import pytest

from benchmarks import fresh

SWIFT = {
    "swift-url-vulnerable",
    "swift-url-fixed",
    "swift-documentation-irrelevant",
    "swift-navigation-vulnerable",
    "swift-navigation-fixed",
    "swift-query-javascript-vulnerable",
    "swift-query-javascript-fixed",
    "swift-unrelated-shadow",
}
SWIFT_RULES = ["AST-CRYPTO-ECB", "AST-CRYPTO-WEAK-CIPHER", "AST-SQL-CONCAT"]
JAVA_RULES = [
    "AST-CRYPTO-ECB",
    "AST-CRYPTO-HARDCODED-KEY",
    "AST-CRYPTO-STATIC-IV",
    "AST-CRYPTO-WEAK-CIPHER",
    "AST-CRYPTO-WEAK-HASH",
    "AST-IMPLICIT-INTENT",
    "AST-INTENT-REDIRECTION",
    "AST-PATH-TRAVERSAL",
    "AST-PENDINGINTENT-MUTABLE",
    "AST-SQL-CONCAT",
    "AST-WEBVIEW-HOST-ALLOWLIST",
    "AST-WEBVIEW-JS-BRIDGE",
    "AST-WEBVIEW-SSL-BYPASS",
    "AST-WEBVIEW-UNTRUSTED-URL",
]
JAVA_WARNING = "Native flow remains partial: object alias identity unavailable; unresolved callable identity or argument signature."


def synthetic_result():
    """Use independently frozen labels only; never open any corpus binary path."""
    manifest = json.loads((Path(__file__).parents[1] / "benchmarks/corpus.json").read_text())
    cases = []
    for label in manifest["cases"]:
        if label["kind"] != "source" and label["id"] not in {"dex-safe", "dex-unsafe"}:
            continue
        name = label["id"]
        partial = name in SWIFT or name == "java-cross-function-irrelevant"
        cases.append(
            {
                "id": name,
                "expected": copy.deepcopy(label["expected"]),
                "observed": copy.deepcopy(label["expected"]),
                "warnings": [JAVA_WARNING] if name == "java-cross-function-irrelevant" else [],
                "incomplete_rules": JAVA_RULES.copy()
                if name == "java-cross-function-irrelevant"
                else SWIFT_RULES.copy()
                if name in SWIFT
                else [],
                "error": None,
                "scored": not partial,
            }
        )
    return {
        "passed": False,
        "published_baseline_approved": False,
        "summary": {"cases": len(cases), "fp": 0, "fn": 0},
        "cases": cases,
        "disagreements": [{"case_id": name} for name in sorted(SWIFT | {"java-cross-function-irrelevant"})],
    }


def case(result, name="swift-url-vulnerable"):
    return next(row for row in result["cases"] if row["id"] == name)


def test_faithful_partial_controls_pass_only_the_regression_contract():
    result = synthetic_result()
    assert fresh.regression_contract(result)
    assert result["passed"] is result["published_baseline_approved"] is False


@pytest.mark.parametrize("name", sorted(name for name in SWIFT if name.endswith("-vulnerable")))
def test_lost_supported_swift_positive_is_not_hidden_by_unsupported_rules(name):
    result = synthetic_result()
    case(result, name)["observed"] = []
    assert not fresh.regression_contract(result)


@pytest.mark.parametrize("name", sorted(name for name in SWIFT if not name.endswith("-vulnerable")))
def test_extra_supported_swift_positive_is_not_hidden_by_unsupported_rules(name):
    result = synthetic_result()
    case(result, name)["observed"] = [{"rule_id": "AST-WEBVIEW-UNTRUSTED-URL", "status": "candidate"}]
    assert not fresh.regression_contract(result)


@pytest.mark.parametrize("mutation", ["status", "duplicate", "unknown", "missing-field", "relabel-both"])
def test_observation_identity_status_duplicates_and_frozen_labels_are_checked(mutation):
    result = synthetic_result()
    row = case(result)
    if mutation == "status":
        row["observed"][0]["status"] = "configuration-confirmed"
    elif mutation == "duplicate":
        row["observed"] *= 2
    elif mutation == "unknown":
        row["observed"].append({"rule_id": "UNKNOWN-RULE", "status": "candidate"})
    elif mutation == "missing-field":
        del row["observed"]
    else:
        row["expected"] = row["observed"] = []
    assert not fresh.regression_contract(result)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "duplicate", "duplicate-partial", "duplicate-disagreement", "unknown-partial"],
)
def test_missing_extra_duplicate_or_unknown_control_cases_fail(mutation):
    result = synthetic_result()
    complete = next(row for row in result["cases"] if row["scored"])
    if mutation == "missing":
        result["cases"].remove(complete)
    elif mutation in {"extra", "unknown-partial"}:
        extra = copy.deepcopy(complete)
        extra["id"] = "unknown-control"
        if mutation == "unknown-partial":
            extra["warnings"] = ["new failure"]
        result["cases"].append(extra)
    elif mutation == "duplicate":
        result["cases"].append(copy.deepcopy(complete))
    elif mutation == "duplicate-partial":
        result["cases"].append(copy.deepcopy(case(result)))
    else:
        result["disagreements"].append(copy.deepcopy(result["disagreements"][0]))
    assert not fresh.regression_contract(result)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing-rule",
        "extra-rule",
        "duplicate-rule",
        "new-warning",
        "missing-warning",
        "changed-reason",
        "java-rule-missing",
        "java-rule-extra",
        "promoted-scoring",
        "promoted-approval",
    ],
)
def test_known_incompleteness_rules_and_semantic_reasons_cannot_drift(mutation):
    result = synthetic_result()
    row = case(result)
    java = case(result, "java-cross-function-irrelevant")
    if mutation == "missing-rule":
        row["incomplete_rules"].pop()
    elif mutation == "extra-rule":
        row["incomplete_rules"].append("AST-PATH-TRAVERSAL")
    elif mutation == "duplicate-rule":
        row["incomplete_rules"].append(row["incomplete_rules"][0])
    elif mutation == "new-warning":
        row["warnings"] = ["unsupported supported URL analysis"]
    elif mutation == "missing-warning":
        java["warnings"] = []
    elif mutation == "changed-reason":
        java["warnings"] = ["Native flow remains partial: entirely different reason."]
    elif mutation == "java-rule-missing":
        java["incomplete_rules"].pop()
    elif mutation == "java-rule-extra":
        java["incomplete_rules"].append("UNKNOWN-RULE")
    elif mutation == "promoted-scoring":
        row["scored"] = True
    else:
        result["published_baseline_approved"] = True
    assert not fresh.regression_contract(result)


def test_observation_order_is_irrelevant_without_duplicate_labels():
    result = synthetic_result()
    for row in result["cases"]:
        row["observed"].reverse()
    assert fresh.regression_contract(result)
