"""Operation success and candidate identity are independent of audit completion."""

import json
from copy import deepcopy

import pytest

from mobile_audit import cli
from mobile_audit.output import sarif
from tests.test_external_report_review import finding, report


@pytest.mark.parametrize("state", ["cancelled", "running", "failed", "interrupted", "completed"])
def test_successfully_processed_cancel_request_is_success_not_audit_status(
    tmp_path, monkeypatch, capsys, state
):
    calls = []

    def cancel(*args):
        calls.append(args[-1])
        return {"id": "fresh-synthetic-job", "state": state, "report_id": None}

    monkeypatch.setattr(cli.jobs, "cancel", cancel)
    code = cli.main(["--json", "--home", str(tmp_path / "home"), "jobs", "cancel", "fresh-synthetic-job"])
    response = json.loads(capsys.readouterr().out)
    assert code == 0 and response["ok"] is True
    assert response["data"]["state"] == state
    assert calls == ["fresh-synthetic-job"]


@pytest.mark.parametrize("state", ["cancelled", "failed", "interrupted"])
def test_unsuccessful_audit_status_remains_nonzero(tmp_path, monkeypatch, capsys, state):
    monkeypatch.setattr(cli.jobs, "get", lambda *args: {"id": "fresh-synthetic-job", "state": state})
    code = cli.main(["--json", "--home", str(tmp_path / "home"), "jobs", "status", "fresh-synthetic-job"])
    response = json.loads(capsys.readouterr().out)
    assert code == 3 and response["ok"] is False
    assert response["data"]["state"] == state


@pytest.mark.parametrize(
    "sibling_status", ["configuration-confirmed", "runtime-confirmed", "version-affected"]
)
@pytest.mark.parametrize("reverse", [False, True])
def test_candidate_sarif_descriptor_and_fingerprint_survive_stronger_sibling(sibling_status, reverse):
    candidate = finding(identifier="F-fresh-candidate")
    strong = finding(sibling_status, identifier="F-fresh-strong")
    alone = sarif(report(findings=[candidate]))["runs"][0]
    findings = [candidate, strong]
    if reverse:
        findings.reverse()
    value = report(findings=findings)
    before = deepcopy(value)
    mixed = sarif(value)["runs"][0]
    original = alone["results"][0]
    current = next(row for row in mixed["results"] if row["properties"]["status"] == "candidate")
    assert original["ruleId"] == current["ruleId"] == "ANDROID-DEBUG/candidate"
    assert original["partialFingerprints"] == current["partialFingerprints"]
    descriptors = {row["id"]: row for row in mixed["tool"]["driver"]["rules"]}
    assert "security-severity" not in descriptors[current["ruleId"]]["properties"]
    assert current["properties"]["apsaRuleId"] == "ANDROID-DEBUG"
    assert value == before


def test_candidate_descriptor_keeps_existing_collision_avoidance():
    value = report(
        findings=[finding(identifier="F-one"), finding(rule="ANDROID-DEBUG/candidate", identifier="F-two")]
    )
    run = sarif(value)["runs"][0]
    assert len({row["id"] for row in run["tool"]["driver"]["rules"]}) == 2
    assert len({row["ruleId"] for row in run["results"]}) == 2
