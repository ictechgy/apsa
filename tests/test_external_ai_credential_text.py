"""Fresh synthetic resource-only packages; no installed app, service or credential validation."""

from __future__ import annotations

import codecs
import inspect
import json
import plistlib
import stat
import zipfile
from pathlib import Path

import pytest

from mobile_audit import _parser_worker, inputs, platform_checks
from mobile_audit.audit import scan
from mobile_audit.input_snapshot import stage_input
from mobile_audit.maswe import weaknesses_for
from mobile_audit.model_context import finding_context, report_context
from mobile_audit.output import assistant_context, markdown, sarif
from mobile_audit.rules import rules

AWS = "AKIA" + "SYNTHETIC123456X"
OPENAI = "sk-proj-" + "A" * 24 + "T3BlbkFJ" + "B" * 24
GOOGLE = "AIza" + "C" * 35
PRIVATE_HEADER = "-----BEGIN PRIVATE KEY-----"
# Synthetic base64-shaped material; no real key is embedded or validated.
PRIVATE_MATERIAL = PRIVATE_HEADER + "\n" + "QUJD" * 24 + "\n-----END PRIVATE KEY-----"
MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="org.synthetic.credentials"><application/></manifest>'
).encode()
PLIST = plistlib.dumps({"CFBundleIdentifier": "org.synthetic.credentials"})
RULE = "PACKAGED-CREDENTIAL-TEXT"


def _package(tmp_path: Path, kind: str, members: dict[str, bytes]) -> Path:
    target = tmp_path / ("fresh." + kind)
    identity = {"AndroidManifest.xml": MANIFEST} if kind == "apk" else {"Payload/New.app/Info.plist": PLIST}
    with zipfile.ZipFile(target, "w") as archive:
        for name, raw in {**identity, **members}.items():
            archive.writestr(name, raw)
    return target


def _inspect(target: Path) -> tuple[dict, list, list]:
    text: list[tuple[str, str]] = []
    # Keep the same regression executable against immutable R11 for before/fixed proof.
    if "credential_text" in inspect.signature(inputs.inspect_target).parameters:
        inventory, sources = inputs.inspect_target(target, credential_text=text)
    else:
        inventory, sources = inputs.inspect_target(target)
    return inventory, sources, text


def _checks(target: Path) -> tuple[dict, list, list]:
    inventory, sources, text = _inspect(target)
    kwargs = (
        {"credential_text": text}
        if "credential_text" in inspect.signature(platform_checks.platform_checks).parameters
        else {}
    )
    findings, coverage = platform_checks.platform_checks(inventory, sources, **kwargs)
    return inventory, findings, coverage


def _credential_findings(findings: list[dict], rule: str = RULE) -> list[dict]:
    return [row for row in findings if row["rule_id"] == rule]


def _coverage(coverage: list[dict], rule: str = RULE) -> dict:
    return next(row for row in coverage if row["rule_id"] == rule)


def test_imports_are_from_this_exact_source_tree() -> None:
    root = Path(__file__).resolve().parents[1]
    for module in (inputs, platform_checks, _parser_worker):
        assert module.__file__ is not None
        assert Path(module.__file__).resolve().is_relative_to(root / "src")


@pytest.mark.parametrize("kind", ["apk", "ipa"])
@pytest.mark.parametrize(
    "suffix", [".json", ".plist", ".jsbundle", ".bundle", ".properties", ".strings", ".pem", ".key"]
)
def test_packaged_text_candidates_have_member_scope_without_other_platform_checks(tmp_path, kind, suffix):
    prefix = "assets/" if kind == "apk" else "Payload/New.app/Resources/"
    path = prefix + "credentials" + suffix
    inventory, findings, coverage = _checks(_package(tmp_path, kind, {path: OPENAI.encode()}))
    found = _credential_findings(findings)
    assert len(found) == 1
    assert found[0]["status"] == "candidate" and found[0]["severity"] == "high"
    evidence = found[0]["evidence"][0]
    assert evidence["path"] == path and evidence["scope"] == "packaged text member only"
    assert evidence["credential_type"] == "openai-api-key" and "excerpt" not in evidence
    assert evidence["masked_value"] == "[REDACTED]"
    assert OPENAI not in json.dumps({"inventory": inventory, "findings": findings, "coverage": coverage})
    assert {row["rule_id"] for row in coverage} == {RULE}
    assert _coverage(coverage)["state"] == "checked"


@pytest.mark.parametrize("kind", ["apk", "ipa"])
def test_resource_only_package_negatives_do_not_invent_credentials(tmp_path, kind):
    prefix = "assets/" if kind == "apk" else "Payload/New.app/"
    _, findings, coverage = _checks(
        _package(
            tmp_path,
            kind,
            {prefix + "config.json": b'{"token":"public-demo-identifier","api":"https://example.test"}'},
        )
    )
    assert not _credential_findings(findings)
    assert _coverage(coverage)["state"] == "checked"


def test_public_google_api_key_and_private_key_material_are_candidates(tmp_path):
    _, findings, _ = _checks(
        _package(
            tmp_path,
            "apk",
            {"assets/config.json": GOOGLE.encode(), "assets/client.pem": PRIVATE_MATERIAL.encode()},
        )
    )
    found = {row["evidence"][0]["credential_type"]: row for row in _credential_findings(findings)}
    assert found["google-api-key"]["severity"] == "low"
    assert found["private-key"]["status"] == "candidate"
    assert "restrictions" in found["google-api-key"]["remediation"]
    assert all("validity and scope are not checked" in row["evidence"][0]["basis"] for row in found.values())


@pytest.mark.parametrize("raw", [codecs.BOM_UTF8 + AWS.encode(), AWS.encode("utf-16")])
def test_bom_plaintext_is_strictly_decoded_for_credential_only_files(tmp_path, raw):
    _, findings, coverage = _checks(_package(tmp_path, "apk", {"assets/Localizable.strings": raw}))
    assert len(_credential_findings(findings)) == 1
    assert _coverage(coverage)["state"] == "checked"


@pytest.mark.parametrize(
    "raw", [b"bplist00binary", b"\x00\x01" + AWS.encode(), b"\xffbad" + AWS.encode(), AWS.encode("utf-32")]
)
def test_binary_or_unsupported_text_never_proves_credential_absence(tmp_path, raw):
    inventory, findings, coverage = _checks(_package(tmp_path, "apk", {"assets/config.key": raw}))
    assert not _credential_findings(findings)
    assert _coverage(coverage)["state"] == "partial"
    assert inventory["credential_text"]["omitted_files"] == 1
    assert inventory["partial"] is True


def test_ipa_credential_members_are_scoped_to_the_declared_main_app(tmp_path):
    _, findings, coverage = _checks(_package(tmp_path, "ipa", {"Unrelated/config.json": OPENAI.encode()}))
    assert not _credential_findings(findings)
    assert _coverage(coverage)["state"] == "checked"
    assert "declared main IPA app" in _coverage(coverage)["scope"]


@pytest.mark.parametrize("kind", ["apk", "ipa"])
def test_many_binary_resources_have_one_counted_warning_without_losing_candidates(tmp_path, kind):
    prefix = "assets/" if kind == "apk" else "Payload/New.app/Resources/"
    members = {f"{prefix}binary-{index}.xml": b"\x03\x00binary" for index in range(200)}
    members[prefix + "config.json"] = OPENAI.encode()
    inventory, findings, coverage = _checks(_package(tmp_path, kind, members))
    assert len(_credential_findings(findings)) == 1
    assert _coverage(coverage)["state"] == "partial"
    assert inventory["credential_text"]["eligible_files"] == 202
    assert inventory["credential_text"]["decoded_files"] == 2
    assert inventory["credential_text"]["omitted_files"] == 200
    assert inventory["credential_text"]["partial"] and inventory["partial"]
    warnings = [w for w in inventory["warnings"] if "credential-text members omitted" in w]
    assert warnings == [
        "Non-text/unsupported credential-text members omitted: 200; credential coverage incomplete"
    ]
    assert OPENAI not in json.dumps(inventory)


@pytest.mark.parametrize("kind", ["apk", "ipa"])
@pytest.mark.parametrize("credential", [AWS, OPENAI, OPENAI + "Z" * 12, GOOGLE, PRIVATE_MATERIAL])
def test_credential_mask_never_discloses_a_prefix_length_or_value_fingerprint(tmp_path, kind, credential):
    prefix = "assets/" if kind == "apk" else "Payload/New.app/Resources/"
    _, findings, _ = _checks(_package(tmp_path, kind, {prefix + "config.key": credential.encode()}))
    assert _credential_findings(findings)
    for row in _credential_findings(findings):
        evidence = row["evidence"][0]
        assert evidence["masked_value"] == "[REDACTED]"
        assert set(evidence) == {
            "path",
            "line",
            "offset",
            "credential_type",
            "masked_value",
            "basis",
            "scope",
        }


def test_new_source_formats_are_staged_and_credential_only(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "AndroidManifest.xml").write_bytes(MANIFEST)
    for suffix in (".properties", ".strings", ".pem", ".key"):
        (source / ("config" + suffix)).write_text(OPENAI)
    (source / ".env").write_text(OPENAI)
    (source / "node_modules").mkdir()
    (source / "node_modules/private.properties").write_text(OPENAI)
    staged = tmp_path / "staged"
    snapshot = stage_input(source, staged)
    assert snapshot["files"] == 5
    inventory, sources, text = _inspect(staged)
    assert {path for path, _ in sources} == {"AndroidManifest.xml"}
    assert {path for path, _ in text} == {
        "AndroidManifest.xml",
        "config.properties",
        "config.strings",
        "config.pem",
        "config.key",
    }
    findings, coverage = platform_checks.platform_checks(inventory, sources, credential_text=text)
    assert len(_credential_findings(findings, "SOURCE-HARDCODED-SECRET")) == 4
    assert _coverage(coverage, "SOURCE-HARDCODED-SECRET")["state"] == "checked"
    assert OPENAI not in json.dumps(inventory)


def test_disabled_direct_api_collection_cannot_claim_checked_absence(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "config.properties").write_text(OPENAI)
    inventory, sources = inputs.inspect_target(source)
    assert inventory["credential_text"]["collection_enabled"] is False
    findings, coverage = platform_checks.platform_checks(inventory, sources)
    assert not findings
    assert _coverage(coverage, "SOURCE-HARDCODED-SECRET")["state"] == "partial"


def test_direct_packaged_api_without_input_inventory_stays_partial():
    findings, coverage = platform_checks.platform_checks({"input_kind": "apk"}, [("assets/new.json", OPENAI)])
    assert len(_credential_findings(findings)) == 1
    assert _coverage(coverage)["state"] == "partial"


@pytest.mark.parametrize("cap", ["MAX_FILE", "MAX_SOURCE_TOTAL"])
def test_existing_byte_caps_also_bound_new_credential_text(tmp_path, monkeypatch, cap):
    target = _package(tmp_path, "apk", {"assets/new.key": ("x" * 500 + OPENAI).encode()})
    monkeypatch.setattr(inputs, cap, 400 if cap == "MAX_FILE" else len(MANIFEST) + 10)
    inventory, findings, coverage = _checks(target)
    assert not _credential_findings(findings)
    assert _coverage(coverage)["state"] == "partial"
    assert inventory["bytes_scanned"] <= len(MANIFEST)


def test_finding_cap_reports_partial_and_keeps_distinct_offsets(tmp_path, monkeypatch):
    monkeypatch.setattr(platform_checks, "MAX_SECRET_FINDINGS", 2)
    _, findings, coverage = _checks(
        _package(tmp_path, "apk", {"assets/new.key": (OPENAI + " " + OPENAI + " " + OPENAI).encode()})
    )
    found = _credential_findings(findings)
    assert len(found) == len({row["id"] for row in found}) == 2
    assert _coverage(coverage)["state"] == "partial"


def test_new_credential_files_share_the_existing_file_count_limit(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    for index in range(3):
        (source / f"config{index}.key").write_text(OPENAI)
    monkeypatch.setattr(inputs, "MAX_FILES", 2)
    inventory, _, coverage = _checks(source)
    assert inventory["files_scanned"] == 2
    assert inventory["fingerprint_complete"] is False
    assert _coverage(coverage, "SOURCE-HARDCODED-SECRET")["state"] == "partial"


def test_source_and_archive_symlinks_are_never_credential_text(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "AndroidManifest.xml").write_bytes(MANIFEST)
    private = tmp_path / "synthetic-outside.key"
    private.write_text(OPENAI)
    (source / "linked.key").symlink_to(private)
    inventory, findings, coverage = _checks(source)
    assert not findings and inventory["partial"] is True
    assert _coverage(coverage, "SOURCE-HARDCODED-SECRET")["state"] == "partial"
    staged = tmp_path / "staged"
    stage_input(source, staged)
    assert not (staged / "linked.key").exists()
    target = _package(tmp_path, "apk", {})
    entry = zipfile.ZipInfo("assets/linked.key")
    entry.create_system = 3
    entry.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(target, "a") as archive:
        archive.writestr(entry, OPENAI)
    _, findings, coverage = _checks(target)
    assert not _credential_findings(findings)
    assert _coverage(coverage)["state"] == "partial"


def test_rule_catalog_and_maswe_mapping_are_registered():
    rule = next(row for row in rules() if row["id"] == RULE)
    assert rule["mode"] == "packaged-text" and rule["maswe"] == ["MASWE-0004"]
    assert weaknesses_for(RULE) == ("MASWE-0004",)


@pytest.mark.parametrize("kind", ["apk", "ipa"])
def test_actual_worker_pipeline_and_all_exports_keep_credentials_masked(tmp_path, monkeypatch, store, kind):
    # This is a resource-only functional fixture, not proof of binary/OS isolation or a real app build.
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    monkeypatch.setenv("APSA_PARSER_LOCK_DIR", str(tmp_path / "parser-locks"))
    prefix = "assets/" if kind == "apk" else "Payload/New.app/"
    target = _package(tmp_path, kind, {prefix + "config.json": OPENAI.encode()})
    report = scan(store, target, online=False)
    found = _credential_findings(report["findings"])
    assert len(found) == 1
    exports = [
        report,
        sarif(report),
        markdown(report),
        assistant_context(report),
        report_context(report),
        finding_context(found[0]),
    ]
    assert all(OPENAI not in json.dumps(export) for export in exports)
    assert report["inventory"]["credential_text"]["collection_enabled"] is True
    assert _coverage(report["coverage"])["state"] == "checked"
