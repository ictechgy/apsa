"""1.7.0 release review: one-to-one advisory alias matching through display IDs,
waiver escalation precedence, ``only_new`` baseline ordering with naive timestamps,
``scan --format`` without ``--out`` and the IOS-ATS-EXCEPTION identity.

Synthetic OSV records, Info.plist inventories and in-memory reports only; the CLI
cases scan the bundled demo target into a temporary home. No network or device.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from mobile_audit import policy as policy_module
from mobile_audit.audit import compare
from mobile_audit.cli import main
from mobile_audit.core import finding, finding_identity, match_identities
from mobile_audit.followup import assess_finding_followup
from mobile_audit.platform_checks import platform_checks
from mobile_audit.policy import evaluate
from mobile_audit.verify import compare_reports
from tests.test_advisory_identity_policy import (
    GHSA,
    OTHER,
    advisory,
    config,
    correlated,
    legacy,
    notices,
    report,
    stored,
    waiver,
)

PYSEC = "PYSEC-2026-1"


@pytest.fixture(autouse=True)
def stable_clock(monkeypatch):
    monkeypatch.setattr(policy_module, "_now", lambda: datetime(2026, 10, 4, 12, tzinfo=timezone.utc))


def transitions(before, after):
    return compare_reports(before, after)["finding_transitions"]


# --- Advisory aliases match only one-to-one ------------------------------------------------


@pytest.mark.parametrize(
    "current,previous,expected",
    [
        # Identity matches are unchanged, including many-to-many.
        ([({"a"}, {"a"})], [({"a"}, {"a"})], [{0: "identity"}]),
        # A display-ID flip: one current entry, one previous entry, nothing else reaches it.
        ([({"c"}, {"c", "g"})], [({"g"}, {"g"})], [{0: "advisory-alias"}]),
        # The previous entry records the alias (a 1.7.0 baseline), the current one does not.
        ([({"g"}, {"g"})], [({"c"}, {"c", "g"})], [{0: "advisory-alias"}]),
        # An identity match never gains a second previous entry through an alias.
        ([({"a"}, {"a", "g"})], [({"a"}, {"a"}), ({"g"}, {"g"})], [{0: "identity"}]),
        # One current entry reaching two previous entries (merged advisories) matches neither.
        ([({"c"}, {"c", "g", "h"})], [({"g"}, {"g"}), ({"h"}, {"h"})], [{}]),
        # Two current entries reaching one previous entry: neither matches it.
        ([({"c"}, {"c", "g"}), ({"d"}, {"d", "g"})], [({"g"}, {"g"})], [{}, {}]),
        # A previous entry matched by identity is not also an alias match for another entry.
        ([({"g"}, {"g"}), ({"c"}, {"c", "g"})], [({"g"}, {"g"})], [{0: "identity"}, {}]),
        # Nor when the other reacher holds its own identity match elsewhere.
        (
            [({"a"}, {"a", "g"}), ({"c"}, {"c", "g"})],
            [({"a"}, {"a"}), ({"g"}, {"g"})],
            [{0: "identity"}, {}],
        ),
        # A shared umbrella alias that is neither entry's display ID never matches.
        ([({"a"}, {"a", "p"})], [({"b"}, {"b", "p"})], [{}]),
        # Nor does it count as reaching: the display-ID match beside it stays one-to-one.
        ([({"c"}, {"c", "g", "p"}), ({"d"}, {"d", "p"})], [({"g"}, {"g", "p"})], [{0: "advisory-alias"}, {}]),
    ],
)
def test_alias_matches_are_one_to_one_and_never_added_to_an_identity_match(current, previous, expected):
    assert match_identities(current, previous) == expected


def shared_alias_pair():
    """CVE-A (medium) and CVE-B (high) on one package, both listing the same PYSEC alias."""
    before = correlated(
        advisory(aliases=("CVE-2026-1000", PYSEC), severity="MODERATE"),
        advisory(OTHER, aliases=("CVE-2026-2000", PYSEC), severity="HIGH"),
    )
    by_rule = {item["rule_id"]: item for item in before}
    first, second = by_rule["CVE-2026-1000"], by_rule["CVE-2026-2000"]
    assert (first["severity"], second["severity"]) == ("medium", "high")
    assert PYSEC in first["advisory_ids"] and PYSEC in second["advisory_ids"]
    # CVE-B is gone and CVE-A escalated to high.
    [escalated] = correlated(advisory(aliases=("CVE-2026-1000", PYSEC), severity="HIGH"))
    assert escalated["id"] == first["id"] and escalated["severity"] == "high"
    return first, second, escalated


def test_an_escalated_finding_is_not_covered_by_another_baseline_finding_through_a_shared_alias():
    first, second, escalated = shared_alias_pair()
    gate = evaluate(report(escalated), config(only_new=True), report(first, second))
    assert gate["state"] == "failed" and gate["exit_code"] == 4
    assert gate["counts"]["baseline_existing"] == 0 and gate["counts"]["escalated"] == 1
    assert gate["gate_findings"] == [escalated["id"]]


def test_compare_reports_a_removed_finding_that_shares_an_alias_with_a_remaining_one():
    first, second, escalated = shared_alias_pair()
    before, after = report(first, second), report(escalated)
    result = compare(stored(before, after), before["id"], after["id"])
    assert result["added"] == []
    assert [item["id"] for item in result["no_longer_observed"]] == [second["id"]]
    assert [(pair["before"]["id"], pair["after"]["id"]) for pair in result["changed"]] == [
        (first["id"], escalated["id"])
    ]
    assert result["changed"][0]["before"]["severity"] == "medium"
    assert sorted((item["finding_id"], item["observation"]) for item in transitions(before, after)) == sorted(
        [(escalated["id"], "still-observed"), (second["id"], "no-longer-observed")]
    )


def merged_pair():
    old = correlated(advisory(), advisory(OTHER))
    merged = advisory(aliases=("CVE-2026-1000",))
    merged = {
        **merged,
        "osv_ids": [GHSA, OTHER],
        "osv_records": [merged, advisory(OTHER, aliases=("CVE-2026-1000",))],
    }
    [new] = correlated(merged)
    assert {GHSA, OTHER} <= set(new["advisory_ids"])
    return [legacy(item) for item in old], new


def test_merged_advisories_are_not_paired_twice_by_compare_or_verification():
    old, new = merged_pair()
    before, after = report(*old), report(new)
    result = compare(stored(before, after), before["id"], after["id"])
    assert result["changed"] == [] and result["unchanged"] == 0
    assert [item["id"] for item in result["added"]] == [new["id"]]
    assert sorted(item["id"] for item in result["no_longer_observed"]) == sorted(item["id"] for item in old)
    changes = transitions(before, after)
    ids = [item["finding_id"] for item in changes]
    assert len(ids) == len(set(ids)) == 3
    assert all("before_finding_id" not in item for item in changes)
    assert {item["finding_id"]: item["observation"] for item in changes} == {
        new["id"]: "newly-observed",
        **{item["id"]: "no-longer-observed" for item in old},
    }


@pytest.mark.parametrize("baseline_shape", ["1.6.4", "current"])
def test_display_id_flip_still_matches_beside_an_unchanged_advisory_on_the_same_dependency(baseline_shape):
    old_flip, old_other = correlated(advisory(), advisory(OTHER, aliases=("CVE-2026-2000",)))
    new_flip, new_other = correlated(
        advisory(aliases=("CVE-2026-1000",)), advisory(OTHER, aliases=("CVE-2026-2000",))
    )
    assert (old_flip["rule_id"], new_flip["rule_id"]) == (GHSA, "CVE-2026-1000")
    assert old_other["id"] == new_other["id"]
    shape = legacy if baseline_shape == "1.6.4" else (lambda item: item)
    before, after = report(shape(old_flip), shape(old_other)), report(new_flip, new_other)
    gate = evaluate(after, config(thresholds={"medium": 0}, only_new=True), before)
    assert gate["state"] == "passed" and gate["counts"]["baseline_existing"] == 2
    waived = evaluate(
        after,
        config(
            thresholds={"medium": 0},
            waivers=[waiver(old_flip["id"], severity="medium"), waiver(old_other["id"], severity="medium")],
        ),
    )
    assert sorted(waived["waived_findings"]) == sorted([new_flip["id"], new_other["id"]])
    result = compare(stored(before, after), before["id"], after["id"])
    assert (result["added"], result["no_longer_observed"], result["unchanged"]) == ([], [], 1)
    assert [(pair["before"]["id"], pair["after"]["id"]) for pair in result["changed"]] == [
        (old_flip["id"], new_flip["id"])
    ]
    renamed = {item["finding_id"]: item.get("before_finding_id") for item in transitions(before, after)}
    assert renamed == {new_flip["id"]: old_flip["id"], new_other["id"]: None}
    followup = assess_finding_followup(before, after, old_flip["id"])
    assert [(item["id"], item["match_basis"]) for item in followup["observation"]["candidates"]] == [
        (new_flip["id"], "advisory-alias")
    ]


# --- An alias matches only through a display ID ------------------------------------------


def test_two_advisories_sharing_only_an_umbrella_alias_are_different_findings():
    # CVE-A was reported; now only CVE-B is, and the two share nothing but a PYSEC record.
    [before] = correlated(advisory(aliases=("CVE-2026-1000", PYSEC), severity="HIGH"))
    [after] = correlated(advisory(OTHER, aliases=("CVE-2026-2000", PYSEC), severity="HIGH"))
    assert set(before["advisory_ids"]) & set(after["advisory_ids"]) == {PYSEC}
    for shape in (legacy, lambda item: item):
        previous = report(shape(before))
        gate = evaluate(report(after), config(only_new=True), previous)
        assert gate["state"] == "failed" and gate["counts"]["baseline_existing"] == 0
        assert gate["counts"]["escalated"] == 0 and gate["gate_findings"] == [after["id"]]
    waived = evaluate(report(after), config(waivers=[waiver(before["id"], severity="high")]))
    assert waived["waived_findings"] == [] and waived["active_waivers"][0]["matched"] is False
    before_report, after_report = report(before), report(after)
    result = compare(stored(before_report, after_report), before_report["id"], after_report["id"])
    assert [item["id"] for item in result["added"]] == [after["id"]]
    assert [item["id"] for item in result["no_longer_observed"]] == [before["id"]]
    assert result["changed"] == []
    assert all("before_finding_id" not in item for item in transitions(before_report, after_report))
    followup = assess_finding_followup(before_report, after_report, before["id"])
    assert all(item["match_basis"] != "advisory-alias" for item in followup["observation"]["candidates"])


def test_a_legacy_waiver_matches_only_when_its_display_id_is_an_equivalent_id():
    [item] = correlated(advisory(OTHER, aliases=("CVE-2026-2000", PYSEC), severity="HIGH"))
    location = item["evidence"]
    for display, matched in ((PYSEC, True), (OTHER, True), ("CVE-2026-1000", False), (GHSA, False)):
        gate = evaluate(
            report(item), config(waivers=[waiver(finding_identity(display, location), severity="high")])
        )
        assert (gate["waived_findings"] == [item["id"]]) is matched, display


@pytest.mark.parametrize("baseline_shape", ["1.6.4", "current"])
def test_a_lower_cve_display_id_flip_still_matches(baseline_shape):
    [old] = correlated(advisory(aliases=("CVE-2026-2000",)))
    [new] = correlated(advisory(aliases=("CVE-2026-2000", "CVE-2026-1000")))
    assert (old["rule_id"], new["rule_id"]) == ("CVE-2026-2000", "CVE-2026-1000")
    previous = legacy(old) if baseline_shape == "1.6.4" else old
    gate = evaluate(report(new), config(thresholds={"medium": 0}, only_new=True), report(previous))
    assert gate["state"] == "passed" and gate["counts"]["baseline_existing"] == 1
    waived = evaluate(report(new), config(thresholds={"medium": 0}, waivers=[waiver(old["id"])]))
    assert waived["waived_findings"] == [new["id"]]
    before, after = report(previous), report(new)
    result = compare(stored(before, after), before["id"], after["id"])
    assert [(pair["before"]["id"], pair["after"]["id"]) for pair in result["changed"]] == [
        (old["id"], new["id"])
    ]


# --- only_new baseline ordering with naive timestamps -------------------------------------


@pytest.mark.parametrize(
    "report_created,baseline_created,later",
    [
        ("2026-11-01T00:00:00", "2026-12-01T00:00:00", True),
        ("2026-11-01T00:00:00+00:00", "2026-11-01T01:00:00", True),
        ("2026-11-01T00:00:00", "2026-11-01T01:00:00Z", True),
        ("2026-11-01T00:00:00", "2026-10-01T00:00:00", False),
        # 02:00+02:00 is 00:00 UTC: a naive 01:00 is read as UTC, so it is later.
        ("2026-11-01T02:00:00+02:00", "2026-11-01T01:00:00", True),
        ("2026-11-01T02:00:00+02:00", "2026-10-31T23:30:00", False),
    ],
)
def test_a_baseline_with_a_naive_creation_time_is_ordered_as_utc(report_created, baseline_created, later):
    [item] = correlated(advisory(aliases=("CVE-2026-1000",)))
    gate = evaluate(
        report(item, created=report_created),
        config(thresholds={"medium": 0}, only_new=True),
        report(item, created=baseline_created),
    )
    codes = {reason["code"] for reason in gate["reasons"]}
    assert ("baseline-not-earlier" in codes) is later
    assert gate["counts"]["baseline_existing"] == (0 if later else 1)


# --- Any escalated waiver reopens its finding --------------------------------------------


def assert_notices_agree_with_waived(gate):
    reopened = {item for notice in notices(gate, "waiver-severity-escalated") for item in notice["findings"]}
    assert reopened and not reopened & set(gate["waived_findings"])


def test_a_legacy_waiver_on_the_old_advisory_id_does_not_keep_an_escalated_finding_waived():
    [item] = correlated(advisory(aliases=("CVE-2026-1000",), severity="HIGH"))
    old_id = finding_identity(GHSA, item["evidence"])
    gate = evaluate(report(item), config(waivers=[waiver(item["id"], severity="low"), waiver(old_id)]))
    assert gate["state"] == "failed" and gate["exit_code"] == 4
    assert gate["waived_findings"] == [] and gate["gate_findings"] == [item["id"]]
    assert_notices_agree_with_waived(gate)
    matched = {record["finding_id"]: record["matched"] for record in gate["active_waivers"]}
    # The finding's own ID matches, so the old ID is no longer an alias match for it.
    assert matched == {item["id"]: True, old_id: False}


@pytest.mark.parametrize("escalated_first", [True, False])
def test_one_escalated_waiver_reopens_a_finding_that_another_waiver_matches(escalated_first):
    # A reported ID that differs from the rule/location identity (as for a multi-domain
    # IOS-ATS-EXCEPTION finding) lets two waivers match the same finding exactly.
    base = finding(
        "SYNTHETIC-RULE", "Synthetic", "high", "configuration-confirmed", [{"path": "A.plist"}], "Fix"
    )
    item = {**base, "id": "F-reported-0001"}
    location = finding_identity("SYNTHETIC-RULE", item["evidence"])
    assert location != item["id"]
    waivers = [waiver(item["id"], severity="low"), waiver(location)]
    policy = {
        "schema_version": 1,
        "allowed_statuses": ["configuration-confirmed"],
        "waivers": waivers if escalated_first else waivers[::-1],
    }
    gate = evaluate(report(item), policy)
    assert all(record["matched"] for record in gate["active_waivers"])
    assert gate["state"] == "failed" and gate["counts"]["waived"] == 0
    assert gate["gate_findings"] == [item["id"]]
    assert_notices_agree_with_waived(gate)
    # Without the escalated waiver the legacy waiver alone still suppresses it.
    alone = evaluate(report(item), {**policy, "waivers": [waiver(location)]})
    assert alone["state"] == "passed" and alone["waived_findings"] == [item["id"]]


# --- scan --format without --out ---------------------------------------------------------


def test_scan_format_without_out_is_ignored_with_a_warning_as_in_1_6_4(tmp_path, demo, capsys):
    home = str(tmp_path / "new-home")
    args = ["--json", "--home", home, "scan", str(demo), "--fail-on", "high"]
    expected = main(args)
    plain = json.loads(capsys.readouterr().out)
    for format_ in ("json", "sarif", "markdown", "maswe"):
        assert main([*args, "--format", format_]) == expected
        output = capsys.readouterr()
        envelope = json.loads(output.out)
        assert envelope["exit_code"] == expected and envelope["data"]["summary"] == plain["data"]["summary"]
        assert f"--format {format_} is ignored without --out" in output.err
    assert sorted(path.name for path in tmp_path.iterdir()) == ["demo", "new-home"]
    # Text output: the summary still prints and the warning goes to stderr.
    assert main(["--home", home, "scan", str(demo), "--format", "sarif"]) in {0, 3}
    output = capsys.readouterr()
    assert "Details: apsa reports get" in output.out and "ignored without --out" in output.err
    # Options that need the output file stay usage errors.
    assert main([*args, "--format", "sarif", "--sarif-root", "app"]) == 2
    assert "--sarif-root requires --out" in json.loads(capsys.readouterr().out)["error"]["message"]
    contradictory = tmp_path / "new-contradiction.md"
    assert main([*args, "--format", "sarif", "--out", str(contradictory)]) == 2
    assert "contradicts" in json.loads(capsys.readouterr().out)["error"]["message"]
    assert not contradictory.exists()


def test_reports_export_still_requires_out_and_rejects_a_contradicting_format(tmp_path, demo, capsys):
    home = str(tmp_path / "new-home")
    assert main(["--json", "--home", home, "scan", str(demo)]) in {0, 3}
    export = ["--json", "--home", home, "reports", "export", "latest"]
    capsys.readouterr()
    assert main([*export, "--format", "json"]) == 2
    assert "required: --out" in json.loads(capsys.readouterr().out)["error"]["message"]
    assert main([*export, "--format", "sarif", "--out", str(tmp_path / "r.md")]) == 2
    assert "contradicts" in json.loads(capsys.readouterr().out)["error"]["message"]
    assert not (tmp_path / "r.md").exists()


# --- IOS-ATS-EXCEPTION keeps the 1.6.4 file identity -------------------------------------

# The 1.6.4 ID of an IOS-ATS-EXCEPTION finding for App/Info.plist (rule plus file path).
ATS_164_ID = "F-a6784a5dcf3ddf0d1ba3"
ATS_DOMAINS = {
    "a.example.com": {"NSExceptionAllowsInsecureHTTPLoads": True},
    "b.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.0"},
    "c.example.com": {"NSExceptionRequiresForwardSecrecy": False},
}


def ats_finding(*domains, media=False):
    ats: dict = {"NSExceptionDomains": {domain: ATS_DOMAINS[domain] for domain in domains}}
    if media:
        ats["NSAllowsArbitraryLoadsForMedia"] = True
    inventory = {
        "platforms": ["ios"],
        "ios_config": [{"path": "App/Info.plist", "ats": ats}],
        "warnings": [],
    }
    [item] = [item for item in platform_checks(inventory, [])[0] if item["rule_id"] == "IOS-ATS-EXCEPTION"]
    return item


@pytest.mark.parametrize(
    "domains,media",
    [
        (("a.example.com",), False),
        (("a.example.com", "b.example.com"), False),
        (("a.example.com", "b.example.com", "c.example.com"), False),
        (("b.example.com", "c.example.com"), True),
    ],
)
def test_ats_exception_id_is_the_1_6_4_file_identity_whatever_the_domains(domains, media):
    item = ats_finding(*domains, media=media)
    assert item["id"] == ATS_164_ID == finding_identity("IOS-ATS-EXCEPTION", [{"path": "App/Info.plist"}])
    # Every weakened domain is still its own evidence row.
    assert [row["domain"] for row in item["evidence"]] == sorted([*domains, *(["(media)"] if media else [])])
    assert {row["path"] for row in item["evidence"]} == {"App/Info.plist"}


def test_1_6_4_waivers_baselines_and_comparisons_match_a_multi_domain_ats_finding():
    current = ats_finding("a.example.com", "b.example.com")
    # 1.6.4 reported one finding per file (the first domain) under the file identity.
    previous = {**current, "evidence": current["evidence"][:1]}
    assert previous["id"] == finding_identity("IOS-ATS-EXCEPTION", previous["evidence"])
    statuses = ["configuration-confirmed"]
    policy = {"schema_version": 1, "allowed_statuses": statuses, "thresholds": {"medium": 0}}
    waived = evaluate(report(current), {**policy, "waivers": [waiver(ATS_164_ID, severity="medium")]})
    assert waived["state"] == "passed" and waived["waived_findings"] == [ATS_164_ID]
    before, after = report(previous), report(current)
    gate = evaluate(after, {**policy, "only_new": True}, before)
    assert gate["state"] == "passed" and gate["counts"]["baseline_existing"] == 1
    result = compare(stored(before, after), before["id"], after["id"])
    assert (result["added"], result["no_longer_observed"], result["changed"], result["unchanged"]) == (
        [],
        [],
        [],
        1,
    )
    assert [(item["finding_id"], item["observation"]) for item in transitions(before, after)] == [
        (ATS_164_ID, "still-observed")
    ]
    # Adding a domain later keeps the same finding.
    wider = report(ats_finding("a.example.com", "b.example.com", "c.example.com"))
    assert evaluate(wider, {**policy, "only_new": True}, after)["counts"]["baseline_existing"] == 1
