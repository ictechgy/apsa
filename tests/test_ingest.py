"""Imported SARIF results as candidate external evidence (1.4)."""

from __future__ import annotations

import copy
import json

import pytest

from mobile_audit.audit import scan
from mobile_audit.cli import main
from mobile_audit.ingest import external_findings, ingest
from mobile_audit.maswe import coverage_matrix
from mobile_audit.verify import verify_claim


def test_raw_rule_identity_cannot_borrow_another_rules_baseline_or_waiver():
    from mobile_audit.policy import evaluate

    def imported(rule_name):
        return external_findings(
            json.dumps(document([result("Entry.java", rule=rule_name)])).encode(), "owned"
        )[0]

    def report(findings):
        return {
            "id": "owned-current",
            "target": "/synthetic/owned",
            "findings": findings,
            "coverage": [{"rule_id": "EXTERNAL-owned", "state": "not-applicable"}],
        }

    policy = {"schema_version": 1, "allowed_statuses": ["candidate"], "thresholds": {"medium": 0}}
    first = imported("tls/check")
    second = imported("tls?check")
    assert first[0]["rule_id"] != second[0]["rule_id"]
    assert first[0]["id"] != second[0]["id"]
    assert evaluate(report(second), {**policy, "only_new": True}, report(first))["state"] == "failed"
    waived = {
        **policy,
        "waivers": [
            {"finding_id": first[0]["id"], "reason": "Owned first rule only", "expires": "2099-01-01"}
        ],
    }
    assert evaluate(report(second), waived)["state"] == "failed"


def test_long_rule_names_and_driver_names_remain_distinct():
    first = document([result("Entry.java", rule="x" * 60 + "a"), result("Entry.java", rule="x" * 60 + "b")])
    findings, _ = external_findings(json.dumps(first).encode(), "owned")
    assert len({item["id"] for item in findings}) == 2
    second = copy.deepcopy(first["runs"][0])
    second["tool"]["driver"]["name"] = "OtherDriver"
    first["runs"].append(second)
    findings, _ = external_findings(json.dumps(first).encode(), "owned")
    assert len({item["id"] for item in findings}) == 4


@pytest.mark.parametrize("indexed", [False, True])
def test_duplicate_rule_descriptors_cannot_downgrade_selected_severity(indexed):
    raw = document([result("Entry.java")])
    driver = raw["runs"][0]["tool"]["driver"]
    duplicate = copy.deepcopy(driver["rules"][0])
    duplicate["properties"] = {"security-severity": "1.0", "tags": ["CWE-79"]}
    driver["rules"].append(duplicate)
    if indexed:
        raw["runs"][0]["results"][0]["ruleIndex"] = 0
    with pytest.raises(ValueError, match="duplicate rule ID"):
        external_findings(json.dumps(raw).encode(), "owned")


def test_duplicate_sarif_results_merge_without_losing_severity_or_provenance():
    raw = document([result("Entry.java")])
    low = raw["runs"][0]
    low["tool"]["driver"]["rules"][0]["properties"] = {"security-severity": "3.0", "tags": ["CWE-79"]}
    high = copy.deepcopy(low)
    high["tool"]["driver"]["version"] = "10.0"
    high["tool"]["driver"]["rules"][0]["properties"] = {"security-severity": "9.8", "tags": ["CWE-295"]}
    high["results"][0]["message"]["text"] = "Owned critical observation"
    raw["runs"].append(high)
    findings, record = external_findings(json.dumps(raw).encode(), "owned")
    assert len(findings) == 1 and record["deduplicated"] == 1
    item = findings[0]
    assert item["severity"] == "critical"
    assert item["cwe"] == ["CWE-295", "CWE-79"]
    evidence = item["evidence"][0]
    assert evidence["external_observation_count"] == 2
    assert {row["severity"] for row in evidence["external_observations"]} == {"low", "critical"}
    assert {row["driver"]["version"] for row in evidence["external_observations"]} == {"9.9", "10.0"}
    raw["runs"].reverse()
    reversed_findings, _ = external_findings(json.dumps(raw).encode(), "owned")
    assert reversed_findings[0]["id"] == item["id"]
    assert reversed_findings[0]["severity"] == item["severity"]
    assert reversed_findings[0]["cwe"] == item["cwe"]


def test_sarif_duplicate_observations_are_bounded_and_locations_stay_distinct():
    rows = [result("Entry.java", message=f"Owned observation {index}") for index in range(25)]
    rows.append(result("Entry.java", line=12))
    findings, record = external_findings(json.dumps(document(rows)).encode(), "owned")
    assert len(findings) == 2 and len({item["id"] for item in findings}) == 2
    assert record["results"] == 26 and record["imported"] == 2 and record["deduplicated"] == 24
    evidence = findings[0]["evidence"][0]
    assert evidence["external_observation_count"] == 25
    assert len(evidence["external_observations"]) == 20 and evidence["external_observations_truncated"]


def test_unidentified_results_use_exact_payload_identity_without_aliasing_named_unknown():
    unnamed = result("Entry.java", rule="unknown", message="Owned first observation")
    unnamed.pop("ruleId")
    other = copy.deepcopy(unnamed)
    other["message"]["text"] = "Owned other observation"
    named = result("Entry.java", rule="unknown", message="Owned first observation")
    findings, record = external_findings(
        json.dumps(document([unnamed, unnamed, other, named])).encode(), "owned"
    )
    assert len(findings) == len({item["id"] for item in findings}) == 3
    assert record["deduplicated"] == 1


def document(results: list[dict]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OtherScanner",
                        "version": "9.9",
                        "rules": [
                            {
                                "id": "tls/accept-all",
                                "shortDescription": {"text": "TLS errors ignored"},
                                "helpUri": "https://example.com/tls",
                                "properties": {
                                    "tags": ["security", "external/cwe/cwe-295"],
                                    "security-severity": "8.1",
                                },
                            },
                            {"id": "style/naming", "properties": {"tags": ["maintainability"]}},
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


def result(
    uri: str, line: int | None = 11, rule: str = "tls/accept-all", message: str = "proceed() called"
) -> dict:
    region = {"startLine": line} if line else {}
    return {
        "ruleId": rule,
        "level": "error",
        "message": {"text": message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}],
    }


def test_parsing_is_bounded_sanitized_and_mapped():
    raw = json.dumps(
        document(
            [
                result("app/MainActivity.kt", message="token=abc123 leaked"),
                result("/etc/passwd"),
                result("../outside.kt"),
                result("app/Other.kt", rule="style/naming"),
            ]
        )
    ).encode()
    findings, record = external_findings(raw, "other scanner", root="app")
    assert record["results"] == 4 and record["imported"] == 2 and record["skipped"] == 2
    tls = findings[0]
    assert tls["rule_id"].startswith("EXT-other-scanner-tls-accept-all-")
    assert tls["status"] == "candidate"
    assert tls["severity"] == "high" and "MASWE-0027" in tls["maswe"] and tls["cwe"] == ["CWE-295"]
    assert tls["evidence"][0]["path"] == "MainActivity.kt" and "abc123" not in json.dumps(tls)
    assert findings[1]["severity"] == "medium" and findings[1]["maswe"] == []
    with pytest.raises(ValueError):
        external_findings(b'{"version": "2.0.0"}', "x")


def test_ingest_links_corroboration_and_replaces_reimports(store, demo, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    base = scan(store, demo)
    sarif = tmp_path / "other.sarif"
    sarif.write_text(json.dumps(document([result("MainActivity.kt"), result("Demo.swift", line=None)])))
    derived = ingest(store, base["id"], sarif, "other")
    assert derived["parent_report"] == base["id"]
    external = [f for f in derived["findings"] if f.get("origin") == "external"]
    assert len(external) == 2
    linked = external[0]["evidence"][0]["corroborated_by"]
    native = {f["id"]: f for f in derived["findings"] if f.get("origin") != "external"}
    assert linked and all(native[i]["rule_id"].endswith("SSL-BYPASS") for i in linked)
    assert native[linked[0]]["external_corroboration"][0]["tool"] == "other"
    coverage = {c["rule_id"]: c for c in derived["coverage"]}
    assert coverage["EXTERNAL-other"]["state"] == "not-applicable"
    assert derived["external_inputs"][-1]["imported"] == 2
    again = ingest(store, derived["id"], sarif, "other")
    assert sum(f.get("origin") == "external" for f in again["findings"]) == 2
    assert len(native[linked[0]].get("external_corroboration", [])) == 1
    rows = {r["id"]: r for r in coverage_matrix(again)["weaknesses"]}
    assert set(f["id"] for f in external) & set(rows["MASWE-0027"]["findings"])
    assert (
        verify_claim(again, weakness="CWE-295", path="MainActivity.kt", line=11)["verdict"] == "corroborated"
    )


def test_cli_ingest_reports_errors(store, demo, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    home = str(store.home)
    assert main(["--json", "--home", home, "scan", str(demo)]) == 0
    capsys.readouterr()
    good = tmp_path / "ok.sarif"
    good.write_text(json.dumps(document([result("MainActivity.kt")])))
    assert (
        main(
            [
                "--json",
                "--home",
                home,
                "reports",
                "ingest",
                "latest",
                "--sarif",
                str(good),
                "--tool",
                "codeql",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["data"]["external_input"]["imported"] == 1
    bad = tmp_path / "bad.sarif"
    bad.write_text("{}")
    assert (
        main(["--json", "--home", home, "reports", "ingest", "latest", "--sarif", str(bad), "--tool", "x"])
        == 2
    )


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("runs",), {}),
        (("runs", 0), 1),
        (("runs", 0, "tool"), "scanner"),
        (("runs", 0, "tool", "driver"), 1),
        (("runs", 0, "tool", "driver", "name"), ["scanner"]),
        (("runs", 0, "tool", "driver", "rules"), {}),
        (("runs", 0, "tool", "driver", "rules", 0, "properties"), ["cwe-295"]),
        (("runs", 0, "tool", "driver", "rules", 0, "shortDescription"), "description"),
        (("runs", 0, "results"), {}),
        (("runs", 0, "results", 0, "message"), "message"),
        (("runs", 0, "results", 0, "message", "text"), {"text": "nested"}),
        (("runs", 0, "results", 0, "ruleId"), ["tls/accept-all"]),
        (("runs", 0, "results", 0, "level"), ["error"]),
        (("runs", 0, "results", 0, "locations"), {}),
        (("runs", 0, "results", 0, "locations", 0), 1),
        (("runs", 0, "results", 0, "locations", 0, "physicalLocation"), "physical"),
        (("runs", 0, "results", 0, "locations", 0, "physicalLocation", "artifactLocation"), []),
        (("runs", 0, "results", 0, "locations", 0, "physicalLocation", "region"), []),
    ],
)
def test_malformed_sarif_shapes_are_controlled_errors(path, value):
    value_document = document([result("MainActivity.kt")])
    node = value_document
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises(ValueError, match="Invalid SARIF"):
        external_findings(json.dumps(value_document).encode(), "synthetic")


def test_deep_sarif_json_is_a_controlled_error():
    raw = b'{"version":"2.1.0","runs":' + b"[" * 4096 + b"]" * 4096 + b"}"
    # JSON parser depth limits differ by Python version; either decoding or shape
    # validation must reject this through the same public ValueError boundary.
    with pytest.raises(ValueError, match="SARIF"):
        external_findings(raw, "synthetic")


@pytest.mark.parametrize(("index", "expected_cwes"), [(0, []), (1, ["CWE-295"]), (True, [])])
def test_rule_index_keeps_original_positions(index, expected_cwes):
    item = result("MainActivity.kt")
    item.pop("ruleId")
    item["ruleIndex"] = index
    value = document([item])
    driver = value["runs"][0]["tool"]["driver"]
    driver["rules"] = [None, driver["rules"][0]]
    findings, record = external_findings(json.dumps(value).encode(), "synthetic")
    assert record["imported"] == 1
    assert findings[0]["cwe"] == expected_cwes
    if expected_cwes:
        assert "MASWE-0027" in findings[0]["maswe"]
    else:
        assert findings[0]["maswe"] == []
    label = "tls-accept-all" if expected_cwes else "unknown"
    assert findings[0]["rule_id"].startswith(f"EXT-synthetic-{label}-")


def test_conflicting_rule_id_and_index_cannot_supply_another_rules_cwe():
    item = result("MainActivity.kt", rule="style/naming")
    item["ruleIndex"] = 0
    with pytest.raises(ValueError, match="rule ID and index disagree"):
        external_findings(json.dumps(document([item])).encode(), "synthetic")


def test_invalid_sarif_cli_does_not_write_a_derived_report(store, tmp_path, capsys):
    # A new minimal synthetic report avoids parser/device work in this input-validation check.
    base = store.save_report(
        {
            "id": "audit_synthetic_ingest",
            "created": "2026-10-13T00:00:00Z",
            "target": str(tmp_path / "source"),
        }
    )
    bad = tmp_path / "bad.sarif"
    bad.write_text('{"version":"2.1.0","runs":[1]}')
    assert (
        main(
            [
                "--json",
                "--home",
                str(store.home),
                "reports",
                "ingest",
                base["id"],
                "--sarif",
                str(bad),
                "--tool",
                "synthetic",
            ]
        )
        == 2
    )
    output = json.loads(capsys.readouterr().out)
    assert "Invalid SARIF run" in str(output)
    assert len(store.reports()) == 1
