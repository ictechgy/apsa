"""Fresh report histories never treat changed taint specs as remediation."""

from __future__ import annotations

from copy import deepcopy

import pytest

from mobile_audit.checklists import timeline
from mobile_audit.verify import compare_reports

RULE = "AST-SQL-CONCAT"
FIELDS = [
    (False, "spec_hash"),
    (False, "specs"),
    (False, "analysis_specs"),
    (True, "project_specification"),
    (True, "analysis_specs"),
]


class History:
    def __init__(self, reports: list[dict]):
        self.reports = reports

    def target_reports(self, target: str, limit: int = 200) -> list[dict]:
        return [{"id": report["id"]} for report in reversed(self.reports[-limit:])]

    def report(self, identifier: str) -> dict:
        return next(report for report in self.reports if report["id"] == identifier)


def _pair() -> tuple[dict, dict]:
    before = {
        "id": "fresh-before",
        "created": "2026-10-24T00:00:00Z",
        "target": "/fresh/spec-scope",
        "tool_version": "same",
        "rule_version": "same",
        "partial": False,
        "inventory": {
            "input_kind": "source",
            "platforms": ["android"],
            "source_selection": {"module": "app"},
        },
        "coverage": [{"rule_id": RULE, "state": "checked"}],
        "findings": [
            {
                "id": "fresh-sql-wrapper",
                "rule_id": RULE,
                "title": "Custom SQL wrapper input",
                "severity": "high",
                "status": "candidate",
                "evidence": [{"path": "Fresh.kt", "line": 4}],
            }
        ],
    }
    after = deepcopy(before)
    after.update(id="fresh-after", created="2026-10-24T00:01:00Z", findings=[])
    return before, after


def _value(key: str, version: str = "one"):
    return (
        version if key == "spec_hash" else {"sha256": version, "sink": [{"id": "sql-wrapper", "args": [0]}]}
    )


def _assert_open(before: dict, after: dict) -> None:
    original = deepcopy((before, after))
    result = timeline(History([before, after]), before["target"])
    assert result["resolved"] == 0 and result["open"] == 1, result
    assert result["findings"][0]["inconclusive_in"] == after["id"]
    assert "resolved_in" not in result["findings"][0]
    assert (before, after) == original


@pytest.mark.parametrize(("nested", "key"), FIELDS)
@pytest.mark.parametrize("change", ["added", "removed", "changed", "present-null", "present-empty"])
def test_spec_scope_changes_cannot_resolve_absence(nested: bool, key: str, change: str) -> None:
    before, after = _pair()
    left, right = (before["inventory"], after["inventory"]) if nested else (before, after)
    if change == "added":
        right[key] = _value(key)
    elif change == "removed":
        left[key] = _value(key)
    elif change == "changed":
        left[key], right[key] = _value(key), _value(key, "two")
    elif change == "present-null":
        right[key] = None
    else:
        right[key] = "" if key == "spec_hash" else {}
    _assert_open(before, after)


@pytest.mark.parametrize(("nested", "key"), FIELDS)
def test_equal_declared_spec_scope_still_allows_complete_resolution(nested: bool, key: str) -> None:
    before, after = _pair()
    left, right = (before["inventory"], after["inventory"]) if nested else (before, after)
    left[key], right[key] = _value(key), deepcopy(_value(key))
    result = timeline(History([before, after]), before["target"])
    assert result["resolved"] == 1 and result["findings"][0]["resolved_in"] == after["id"]


def test_absent_specs_on_both_reports_still_allow_resolution() -> None:
    before, after = _pair()
    assert timeline(History([before, after]), before["target"])["resolved"] == 1


def test_spec_summary_change_matches_public_compare_scope_result() -> None:
    before, after = _pair()
    before["inventory"]["project_specification"] = _value("project_specification")
    after["inventory"]["project_specification"] = _value("project_specification", "two")
    assert compare_reports(before, after)["scope_pairing"]["state"] == "changed"
    _assert_open(before, after)


def test_secondary_declaration_cannot_hide_behind_equal_effective_spec() -> None:
    before, after = _pair()
    for report in (before, after):
        report["inventory"]["project_specification"] = {"sha256": "same-effective"}
    before["specs"] = {"sink": [{"id": "original-wrapper"}]}
    after["specs"] = {"sink": []}
    _assert_open(before, after)


def test_nested_spec_change_cannot_hide_behind_equal_hash() -> None:
    before, after = _pair()
    for report in (before, after):
        report["inventory"]["project_specification"] = _value("project_specification")
    after["inventory"]["project_specification"]["sink"][0]["args"] = [1]
    _assert_open(before, after)


@pytest.mark.parametrize("state", ["partial", "not-run", "missing", "report-partial", "source-partial"])
def test_equal_specs_do_not_bypass_existing_execution_safeguards(state: str) -> None:
    before, after = _pair()
    for report in (before, after):
        report["inventory"]["project_specification"] = {"sha256": "same"}
    if state == "missing":
        after["coverage"] = []
    elif state == "report-partial":
        after["partial"] = True
    elif state == "source-partial":
        after["inventory"]["source_analysis"] = {"state": "partial"}
    else:
        after["coverage"][0]["state"] = state
    _assert_open(before, after)
