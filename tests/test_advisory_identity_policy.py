"""Advisory display-ID changes keep matching; waivers record the severity they approved.

Synthetic OSV records and in-memory reports only: no network, store, app input or device.
"""

from __future__ import annotations

import copy
import itertools
import json
from datetime import datetime, timezone
from typing import cast

import pytest

from mobile_audit import policy as policy_module
from mobile_audit.audit import compare, correlate
from mobile_audit.core import (
    MAX_ADVISORY_IDS,
    advisory_ids,
    bounded_advisory_ids,
    finding,
    finding_identities,
    finding_identity,
)
from mobile_audit.followup import assess_finding_followup
from mobile_audit.intel import _normalize_osv
from mobile_audit.output import markdown, sarif
from mobile_audit.policy import evaluate, load_policy, template
from mobile_audit.sbom import cyclonedx
from mobile_audit.store import Store
from mobile_audit.verify import compare_reports
from scripts.action_summary import gate_reasons, summary, threshold_exceeded

DEP = {
    "ecosystem": "npm",
    "name": "webview-lib",
    "version": "1.0.0",
    "confidence": "exact",
    "path": "package-lock.json",
}
INVENTORY = {"dependencies": [DEP], "platforms": []}
GHSA = "GHSA-aaaa-bbbb-cccc"
OTHER = "GHSA-dddd-eeee-ffff"
_IDS = itertools.count(1)


@pytest.fixture(autouse=True)
def stable_clock(monkeypatch):
    monkeypatch.setattr(policy_module, "_now", lambda: datetime(2026, 10, 4, 12, tzinfo=timezone.utc))


def advisory(osv_id=GHSA, aliases=(), severity="MODERATE", **extra):
    value = {
        "id": osv_id,
        "aliases": list(aliases),
        "summary": f"Synthetic advisory {osv_id}",
        "modified": "2026-10-01T00:00:00Z",
        "database_specific": {"severity": severity},
        **extra,
    }
    return _normalize_osv(value, DEP)


def rejected(identifier):
    return {"id": identifier, "source": "cve", "state": "REJECTED", "title": "REJECTED", "affected": []}


def kev(identifier):
    return {"id": identifier, "source": "kev", "title": "KEV", "known_exploited": True, "affected": []}


def correlated(*records):
    return correlate(copy.deepcopy(INVENTORY), [copy.deepcopy(record) for record in records])[0]


def legacy(item):
    """A 1.6.4 report finding: identical except that it never recorded advisory_ids."""
    return {key: value for key, value in item.items() if key != "advisory_ids"}


def report(*items, **extra):
    return {
        "id": f"audit_{next(_IDS)}",
        "schema_version": 2,
        "target": "/synthetic/app",
        "findings": list(items),
        "coverage": [{"rule_id": "DEPENDENCY-CVE", "state": "checked"}],
        "runtime": [],
        "intel_snapshot": [],
        "inventory": {},
        **extra,
    }


def config(**extra):
    return {"schema_version": 1, "allowed_statuses": ["version-affected"], **extra}


def waiver(finding_id, **extra):
    return {"finding_id": finding_id, "reason": "Reviewed exception", "expires": "2026-10-10", **extra}


def notices(gate, code):
    return [notice for notice in gate["notices"] if notice["code"] == code]


# Advisory identities recorded on dependency findings


def test_dependency_finding_records_sorted_equivalent_ids_without_changing_its_id():
    [item] = correlated(advisory(aliases=("CVE-2026-2000", "CVE-2026-1000", "PYSEC-2026-1")))
    assert item["rule_id"] == "CVE-2026-1000"
    assert item["id"] == finding_identity("CVE-2026-1000", item["evidence"])
    assert item["advisory_ids"] == ["CVE-2026-1000", "CVE-2026-2000", GHSA, "PYSEC-2026-1"]


def test_rejected_aliases_and_withdrawn_member_ids_are_not_equivalent_ids():
    live = advisory(aliases=("CVE-2026-1000", "CVE-2026-2000"))
    withdrawn = advisory(OTHER, aliases=("CVE-2026-1000",), withdrawn="2026-10-02T00:00:00Z")
    grouped = {
        **live,
        "osv_ids": [GHSA, OTHER],
        "osv_records": [live, withdrawn],
        "aliases": sorted({*live["aliases"], *withdrawn["aliases"]}),
    }
    [item] = correlated(rejected("CVE-2026-1000"), grouped)
    assert item["rule_id"] == "CVE-2026-2000"
    assert item["advisory_ids"] == ["CVE-2026-2000", GHSA]


def test_equivalent_ids_are_bounded_and_always_keep_the_display_id():
    aliases = [f"ZZZ-{index:03d}" for index in range(MAX_ADVISORY_IDS + 8)]
    [item] = correlated(advisory("ZZZZ-display", aliases=aliases))
    assert len(item["advisory_ids"]) == MAX_ADVISORY_IDS
    assert "ZZZZ-display" in item["advisory_ids"]
    assert bounded_advisory_ids("CVE-1", ["bad id", "", 7, None, "CVE-1", "A"]) == ["A", "CVE-1"]


def test_malformed_or_non_dependency_advisory_ids_add_no_identity():
    [item] = correlated(advisory(aliases=("CVE-2026-1000",)))
    tampered = {**item, "advisory_ids": [["nested"], "x" * 500, "has space", GHSA]}
    assert advisory_ids(tampered) == [GHSA]
    source = finding(
        "CVE-2026-1000", "x", "high", "candidate", [{"path": "A.kt"}], "Fix", advisory_ids=[GHSA]
    )
    assert advisory_ids(source) == []
    assert finding_identities(source) == {source["id"]}


# GHSA -> CVE display-ID flips keep waivers, baselines and comparisons


def test_display_id_flip_still_matches_a_waiver_written_against_the_old_id():
    [old] = correlated(advisory())
    [new] = correlated(advisory(aliases=("CVE-2026-1000",)))
    assert (old["rule_id"], new["rule_id"]) == (GHSA, "CVE-2026-1000")
    assert old["id"] != new["id"]
    gate = evaluate(report(new), config(waivers=[waiver(old["id"], severity="medium")]))
    assert gate["state"] == "passed" and gate["exit_code"] == 0
    assert gate["waived_findings"] == [new["id"]]
    assert gate["active_waivers"][0]["matched"] is True
    assert "escalated" not in gate["active_waivers"][0]


@pytest.mark.parametrize("baseline_shape", ["1.6.4", "current"])
def test_display_id_flip_is_not_new_for_an_only_new_baseline(baseline_shape):
    [old] = correlated(advisory())
    [new] = correlated(advisory(aliases=("CVE-2026-1000",)))
    previous = legacy(old) if baseline_shape == "1.6.4" else old
    gate = evaluate(report(new), config(only_new=True), report(previous))
    assert gate["state"] == "passed"
    assert gate["counts"]["baseline_existing"] == 1 and gate["counts"]["escalated"] == 0


def test_rejected_cve_flips_back_to_ghsa_and_still_matches_a_current_baseline():
    [before] = correlated(advisory(aliases=("CVE-2026-1000",)))
    [after] = correlated(rejected("CVE-2026-1000"), advisory(aliases=("CVE-2026-1000",)))
    assert after["rule_id"] == GHSA and "CVE-2026-1000" not in after["advisory_ids"]
    gate = evaluate(report(after), config(only_new=True), report(before))
    assert gate["counts"]["baseline_existing"] == 1


def test_alias_matched_baseline_still_reopens_on_severity_escalation():
    [old] = correlated(advisory())
    [new] = correlated(advisory(aliases=("CVE-2026-1000",), severity="HIGH"))
    gate = evaluate(report(new), config(only_new=True), report(legacy(old)))
    assert gate["state"] == "failed"
    assert gate["counts"]["escalated"] == 1 and gate["gate_findings"] == [new["id"]]


def test_two_different_advisories_on_one_dependency_never_cross_match():
    [old] = correlated(advisory())
    current = correlated(advisory(aliases=("CVE-2026-1000",)), advisory(OTHER, aliases=("CVE-2026-2000",)))
    other = next(item for item in current if item["rule_id"] == "CVE-2026-2000")
    gated = {"medium": 0}
    gate = evaluate(report(*current), config(thresholds=gated, only_new=True), report(legacy(old)))
    assert gate["counts"]["baseline_existing"] == 1
    assert gate["gate_findings"] == [other["id"]]
    waived = evaluate(report(*current), config(thresholds=gated, waivers=[waiver(old["id"])]))
    assert waived["gate_findings"] == [other["id"]]


def test_a_shared_alias_never_lets_one_baseline_item_or_waiver_cover_two_findings():
    # A legacy finding displayed as PYSEC-2026-1; two distinct current advisories now list it.
    [old] = correlated(advisory("PYSEC-2026-1"))
    current = correlated(
        advisory(aliases=("CVE-2026-1000", "PYSEC-2026-1")),
        advisory(OTHER, aliases=("CVE-2026-2000", "PYSEC-2026-1")),
    )
    assert [item["rule_id"] for item in current] == ["CVE-2026-1000", "CVE-2026-2000"]
    assert all("PYSEC-2026-1" in item["advisory_ids"] for item in current)
    gated = {"medium": 0}
    gate = evaluate(report(*current), config(thresholds=gated, only_new=True), report(legacy(old)))
    assert gate["counts"]["baseline_existing"] == 0
    assert sorted(gate["gate_findings"]) == sorted(item["id"] for item in current)
    waived = evaluate(report(*current), config(thresholds=gated, waivers=[waiver(old["id"])]))
    assert waived["counts"]["waived"] == 0 and waived["active_waivers"][0]["matched"] is False
    # Either advisory alone is unambiguous and keeps matching.
    single = evaluate(report(current[0]), config(thresholds=gated, waivers=[waiver(old["id"])]))
    assert single["waived_findings"] == [current[0]["id"]]


def test_a_split_advisory_group_does_not_cover_both_parts_through_one_baseline_item():
    grouped = advisory(aliases=("CVE-2026-0001", GHSA, OTHER))
    [old] = correlated({**grouped, "aliases": ["CVE-2026-0001", OTHER]})
    assert set(old["advisory_ids"]) >= {GHSA, OTHER}
    current = correlated(
        advisory(aliases=("CVE-2026-1000",)),
        advisory(OTHER, aliases=("CVE-2026-2000",)),
    )
    gate = evaluate(report(*current), config(thresholds={"medium": 0}, only_new=True), report(old))
    assert gate["counts"]["baseline_existing"] == 0 and len(gate["gate_findings"]) == 2


def test_merged_advisories_are_covered_by_either_legacy_finding():
    old = correlated(advisory(), advisory(OTHER))
    assert len(old) == 2
    merged = advisory(aliases=("CVE-2026-1000",))
    merged = {
        **merged,
        "osv_ids": [GHSA, OTHER],
        "osv_records": [merged, advisory(OTHER, aliases=("CVE-2026-1000",))],
    }
    [new] = correlated(merged)
    assert {GHSA, OTHER} <= set(new["advisory_ids"])
    gate = evaluate(report(new), config(only_new=True), report(*map(legacy, old)))
    assert gate["counts"]["baseline_existing"] == 1


class Reports:
    """The two saved reports that ``compare`` reads; no store or database is opened."""

    def __init__(self, *reports):
        self.reports = {item["id"]: item for item in reports}

    def report(self, identifier):
        return self.reports[identifier]


def stored(*reports) -> Store:
    return cast(Store, Reports(*reports))


def test_reports_compare_pairs_a_display_id_flip_instead_of_resolved_and_new():
    [old] = correlated(advisory())
    [new] = correlated(advisory(aliases=("CVE-2026-1000",)))
    [unrelated] = correlated(advisory(OTHER, aliases=("CVE-2026-2000",)))
    before, after = report(legacy(old)), report(new, unrelated)
    result = compare(stored(before, after), before["id"], after["id"])
    assert result["no_longer_observed"] == []
    assert [item["id"] for item in result["added"]] == [unrelated["id"]]
    assert result["unchanged"] == 0
    assert [(pair["before"]["id"], pair["after"]["id"]) for pair in result["changed"]] == [
        (old["id"], new["id"])
    ]
    transitions = compare_reports(before, after)["finding_transitions"]
    assert sorted((item["finding_id"], item["observation"]) for item in transitions) == sorted(
        [(new["id"], "still-observed"), (unrelated["id"], "newly-observed")]
    )
    renamed = next(item for item in transitions if item["finding_id"] == new["id"])
    assert renamed["before_finding_id"] == old["id"]
    assert renamed["before_status"] == renamed["after_status"] == "version-affected"


def test_reports_compare_keeps_unchanged_findings_unchanged():
    [item] = correlated(advisory(aliases=("CVE-2026-1000",)))
    before, after = report(item), report(copy.deepcopy(item))
    result = compare(stored(before, after), before["id"], after["id"])
    assert (result["added"], result["no_longer_observed"], result["changed"], result["unchanged"]) == (
        [],
        [],
        [],
        1,
    )


def test_followup_reports_a_display_id_flip_as_an_alias_continuation():
    [old] = correlated(advisory())
    [new] = correlated(advisory(aliases=("CVE-2026-1000",)))
    result = assess_finding_followup(report(legacy(old)), report(new), old["id"])
    assert result["observation"]["state"] == "possible-continuation"
    assert [(item["id"], item["match_basis"]) for item in result["observation"]["candidates"]] == [
        (new["id"], "advisory-alias")
    ]
    assert result["comparability"]["state"] == "unsupported"


def test_outputs_list_equivalent_advisory_ids_without_changing_fingerprints():
    [item] = correlated(advisory(aliases=("CVE-2026-1000",)))
    full = report(
        item,
        created="2026-10-04T00:00:00+00:00",
        rule_version="test",
        scope="synthetic",
        summary={},
        warnings=[],
        inventory={"fingerprint": "0" * 64, "dependencies": [DEP], "platforms": []},
    )
    assert f"Advisory IDs: `CVE-2026-1000`, `{GHSA}`" in markdown(full)
    [result] = sarif(full)["runs"][0]["results"]
    assert result["partialFingerprints"] == {"apsaFindingIdentity/v1": item["id"]}
    assert result["properties"]["advisoryIds"] == ["CVE-2026-1000", GHSA]
    [vulnerability] = cyclonedx(full)["vulnerabilities"]
    assert {"name": "apsa:advisory-id", "value": GHSA} in vulnerability["properties"]


# Waivers record the approved severity


def high_finding(**extra):
    [item] = correlated(advisory(aliases=("CVE-2026-1000",), severity="HIGH", **extra))
    return item


@pytest.mark.parametrize("thresholds,state", [({}, "failed"), ({"high": -1}, "passed")])
def test_severity_escalation_reopens_a_waived_finding_without_its_own_gate_reason(thresholds, state):
    item = high_finding()
    gate = evaluate(
        report(item), config(thresholds=thresholds, waivers=[waiver(item["id"], severity="medium")])
    )
    assert gate["state"] == state and gate["exit_code"] == {"failed": 4, "passed": 0}[state]
    assert gate["counts"]["waived"] == 0 and gate["waived_findings"] == []
    assert {reason["code"] for reason in gate["reasons"]} <= {"severity-threshold"}
    record = gate["active_waivers"][0]
    assert record["matched"] is True
    assert record["escalated"] == {
        "waived_severity": "medium",
        "waived_known_exploited": False,
        "current_severity": "high",
        "known_exploited": False,
        "findings": [item["id"]],
    }
    [notice] = notices(gate, "waiver-severity-escalated")
    assert notice["finding_id"] == item["id"] and notice["current_severity"] == "high"
    assert not notices(gate, "waiver-severity-unrecorded")


@pytest.mark.parametrize("approved", ["high", "critical"])
def test_waiver_at_or_above_current_severity_still_suppresses(approved):
    item = high_finding()
    gate = evaluate(report(item), config(waivers=[waiver(item["id"], severity=approved)]))
    assert gate["state"] == "passed" and gate["waived_findings"] == [item["id"]]
    assert gate["notices"] == [] and "escalated" not in gate["active_waivers"][0]


def test_newly_known_exploited_finding_reopens_unless_the_waiver_approved_it():
    [item] = correlated(kev("CVE-2026-1000"), advisory(aliases=("CVE-2026-1000",), severity="HIGH"))
    assert item["known_exploited"] is True and item["severity"] == "high"
    reopened = evaluate(report(item), config(waivers=[waiver(item["id"], severity="high")]))
    assert reopened["state"] == "failed" and reopened["gate_findings"] == [item["id"]]
    escalation = reopened["active_waivers"][0]["escalated"]
    assert escalation["known_exploited"] is True and escalation["waived_known_exploited"] is False
    assert notices(reopened, "waiver-severity-escalated")
    explicit = evaluate(
        report(item), config(waivers=[waiver(item["id"], severity="high", known_exploited=True)])
    )
    assert explicit["state"] == "passed" and explicit["waived_findings"] == [item["id"]]
    assert explicit["notices"] == []


def test_legacy_waiver_still_suppresses_with_a_non_blocking_notice():
    [item] = correlated(kev("CVE-2026-1000"), advisory(aliases=("CVE-2026-1000",), severity="CRITICAL"))
    gate = evaluate(report(item), config(waivers=[waiver(item["id"])]))
    assert gate["state"] == "passed" and gate["exit_code"] == 0
    assert gate["waived_findings"] == [item["id"]] and gate["reasons"] == []
    [notice] = notices(gate, "waiver-severity-unrecorded")
    assert notice["finding_id"] == item["id"]
    assert "escalated" not in gate["active_waivers"][0]


def test_expired_waiver_with_severity_is_still_incomplete_and_never_suppresses():
    item = high_finding()
    gate = evaluate(report(item), config(waivers=[waiver(item["id"], severity="high", expires="2026-10-03")]))
    # The unsuppressed high finding exceeds the threshold; failure (4) takes
    # precedence over incompleteness (3), which remains among the reasons.
    assert gate["state"] == "failed" and gate["exit_code"] == 4
    assert "expired-waiver" in {reason["code"] for reason in gate["reasons"]}
    gate = evaluate(
        report(item),
        config(
            thresholds={"critical": 0, "high": -1, "medium": -1, "low": -1, "info": -1},
            waivers=[waiver(item["id"], severity="high", expires="2026-10-03")],
        ),
    )
    assert gate["state"] == "incomplete" and gate["exit_code"] == 3
    assert gate["expired_waivers"][0]["severity"] == "high"
    assert gate["counts"]["waived"] == 0 and gate["notices"] == []


def test_gate_with_notices_is_json_serializable_and_leaves_inputs_unchanged():
    item = high_finding()
    policy = config(waivers=[waiver(item["id"], severity="low"), waiver("F-legacy")])
    current = report(item)
    before = copy.deepcopy((current, policy))
    gate = evaluate(current, policy)
    assert json.loads(json.dumps(gate)) == gate
    assert (current, policy) == before
    assert {notice["code"] for notice in gate["notices"]} == {
        "waiver-severity-escalated",
        "waiver-severity-unrecorded",
    }


@pytest.mark.parametrize(
    "extra",
    [
        {"severity": "severe"},
        {"severity": "HIGH"},
        {"severity": 3},
        {"severity": None},
        {"severity": ["high"]},
        {"severity": "high", "known_exploited": "true"},
        {"severity": "high", "known_exploited": 1},
        {"known_exploited": True},
        {"severity": "high", "owner": "unknown-field"},
    ],
)
def test_waiver_severity_validation_rejects_bad_values(tmp_path, extra):
    bad = config(waivers=[waiver("F-test", **extra)])
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        load_policy(path)
    with pytest.raises(ValueError):
        evaluate(report(), bad)


def test_toml_waiver_records_severity_and_template_documents_it(tmp_path):
    item = high_finding()
    assert '# severity = "medium"' in template() and "# known_exploited = false" in template()
    path = tmp_path / "policy.toml"
    path.write_text(f'''schema_version = 1
[[waivers]]
finding_id = "{item["id"]}"
reason = "Reviewed exception"
expires = 2026-10-04
severity = "high"
known_exploited = false
''')
    loaded = load_policy(path)
    assert loaded["waivers"][0] == {
        "finding_id": item["id"],
        "reason": "Reviewed exception",
        "expires": "2026-10-04",
        "severity": "high",
        "known_exploited": False,
    }
    assert evaluate(report(item), loaded)["waived_findings"] == [item["id"]]


def test_action_treats_waiver_notices_as_non_blocking(tmp_path):
    item = high_finding()
    gate = evaluate(
        report(item),
        config(thresholds={"high": -1}, waivers=[waiver(item["id"], severity="low"), waiver("F-legacy")]),
    )
    assert gate["state"] == "passed" and gate["reasons"] == []
    envelope = tmp_path / "result.json"
    envelope.write_text(
        json.dumps({"ok": True, "exit_code": 0, "data": {"report": report(item), "gate": gate}})
    )
    assert threshold_exceeded(str(envelope), "") is False
    assert gate_reasons(str(envelope)) == []
    text = summary(str(envelope), "0")
    assert "Policy notices (non-blocking): waiver-severity-escalated 1, waiver-severity-unrecorded 1" in text
