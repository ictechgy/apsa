"""Fresh synthetic admitted-text fixtures; no credential validity or app/device access."""

from __future__ import annotations

import codecs
import json
import plistlib
import zipfile
from pathlib import Path

import pytest

from mobile_audit import _parser_worker, credential_text, inputs, platform_checks, rules
from mobile_audit.audit import scan
from mobile_audit.input_snapshot import stage_input

RULE = "PACKAGED-CREDENTIAL-TEXT"
SOURCE_RULE = "SOURCE-HARDCODED-SECRET"
ADMITTED_SUFFIXES = [
    ".h",
    ".yaml",
    ".yml",
    ".toml",
    ".lock",
    ".lockfile",
    ".resolved",
    ".pbxproj",
    ".xcprivacy",
]
OPENAI = "sk-proj-" + "A" * 24 + "T3BlbkFJ" + "B" * 24
AWS = "AKIA" + "SYNTHETIC123456X"
GOOGLE = "AIza" + "C" * 35
PRIVATE_HEADER = "-----BEGIN PRIVATE KEY-----"
PAYLOAD = "\n".join((OPENAI, AWS, GOOGLE, PRIVATE_HEADER))
TYPES = {"openai-api-key", "aws-access-key-id", "google-api-key", "private-key"}
MANIFEST = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="org.synthetic.suffixes"><application/></manifest>'
).encode()
PLIST = plistlib.dumps({"CFBundleIdentifier": "org.synthetic.suffixes"})


def _package(tmp_path: Path, kind: str, members: dict[str, bytes]) -> Path:
    target = tmp_path / ("fresh." + kind)
    identity = {"AndroidManifest.xml": MANIFEST} if kind == "apk" else {"Payload/New.app/Info.plist": PLIST}
    with zipfile.ZipFile(target, "x") as archive:
        for name, raw in {**identity, **members}.items():
            archive.writestr(name, raw)
    return target


def _inspect(target: Path) -> tuple[dict, list, list]:
    text: list[tuple[str, str]] = []
    inventory, sources = inputs.inspect_target(target, credential_text=text)
    return inventory, sources, text


def _checks(target: Path) -> tuple[dict, list, list, list, list]:
    inventory, sources, text = _inspect(target)
    findings, coverage = platform_checks.platform_checks(inventory, sources, credential_text=text)
    return inventory, sources, text, findings, coverage


def _found(findings: list[dict], rule: str = RULE) -> list[dict]:
    return [row for row in findings if row["rule_id"] == rule]


def _coverage(coverage: list[dict], rule: str = RULE) -> dict:
    rows = [row for row in coverage if row["rule_id"] == rule]
    assert len(rows) == 1
    return rows[0]


def test_imports_are_from_this_exact_source_tree():
    root = Path(__file__).resolve().parents[1]
    for module in (_parser_worker, credential_text, inputs, platform_checks, rules):
        assert module.__file__ is not None
        assert Path(module.__file__).resolve().is_relative_to(root / "src")


def test_every_generally_admitted_text_suffix_has_credential_coverage():
    assert inputs.TEXT_SUFFIXES <= credential_text.CREDENTIAL_TEXT_SUFFIXES
    assert credential_text.CREDENTIAL_ONLY_SUFFIXES == {".properties", ".strings", ".pem", ".key"}


@pytest.mark.parametrize("kind", ["apk", "ipa"])
@pytest.mark.parametrize("suffix", ADMITTED_SUFFIXES)
def test_admitted_packaged_text_has_masked_typed_candidates(tmp_path, kind, suffix):
    prefix = "assets/" if kind == "apk" else "Payload/New.app/Frameworks/Fresh.framework/Headers/"
    path = prefix + "Keys" + suffix
    inventory, sources, text, findings, coverage = _checks(_package(tmp_path, kind, {path: PAYLOAD.encode()}))
    assert path in {name for name, _ in sources}
    assert path in {name for name, _ in text}
    metadata = inventory["credential_text"]
    assert metadata["eligible_files"] == metadata["decoded_files"] == 2
    assert metadata["omitted_files"] == 0 and metadata["partial"] is False
    found = _found(findings)
    assert len(found) == 4
    assert {row["evidence"][0]["credential_type"] for row in found} == TYPES
    for row in found:
        evidence = row["evidence"][0]
        assert row["status"] == "candidate"
        assert evidence["path"] == path
        assert evidence["scope"] == "packaged text member only"
        assert evidence["masked_value"] == "[REDACTED]"
        assert "validity and scope are not checked" in evidence["basis"]
        assert "excerpt" not in evidence
    assert not _found(findings, SOURCE_RULE)
    assert _coverage(coverage)["state"] == "checked"
    assert {row["rule_id"] for row in coverage} == {RULE}
    exported = json.dumps({"inventory": inventory, "findings": findings, "coverage": coverage})
    assert all(value not in exported for value in (OPENAI, AWS, GOOGLE, PRIVATE_HEADER))
    _, static_coverage = rules.static_checks(inventory, sources)
    assert not any(row["rule_id"] == RULE for row in static_coverage)


@pytest.mark.parametrize("kind", ["source", "apk", "ipa"])
@pytest.mark.parametrize("name", ["Podfile.lock", "Package.resolved"])
def test_lock_and_resolved_names_use_the_existing_suffix_admission(tmp_path, kind, name):
    raw = (
        ("# " + OPENAI + "\nPODS:\nDEPENDENCIES:\n").encode()
        if name == "Podfile.lock"
        else json.dumps({"pins": [], "note": OPENAI}).encode()
    )
    if kind == "source":
        target = tmp_path / "source"
        target.mkdir()
        (target / name).write_bytes(raw)
        path = name
    else:
        path = ("assets/" if kind == "apk" else "Payload/New.app/") + name
        target = _package(tmp_path, kind, {path: raw})
    assert Path(name).suffix in inputs.TEXT_SUFFIXES
    inventory, sources, text, findings, coverage = _checks(target)
    assert path in {member for member, _ in sources}
    assert path in {member for member, _ in text}
    rule = SOURCE_RULE if kind == "source" else RULE
    assert len(_found(findings, rule)) == 1
    assert _found(findings, rule)[0]["evidence"][0]["path"] == path
    assert _coverage(coverage, rule)["state"] == "checked"
    assert inventory["credential_text"]["omitted_files"] == 0


def test_source_header_and_jsbundle_keep_source_rule_and_distinct_identities(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Keys.h").write_text('static char *key = "' + OPENAI + '";\n')
    (source / "main.jsbundle").write_text('const key = "' + OPENAI + '";\n')
    inventory, sources, text, findings, coverage = _checks(source)
    assert {name for name, _ in sources} == {"Keys.h", "main.jsbundle"}
    assert {name for name, _ in text} == {"Keys.h", "main.jsbundle"}
    found = _found(findings, SOURCE_RULE)
    assert len(found) == len({row["id"] for row in found}) == 2
    assert {row["evidence"][0]["path"] for row in found} == {"Keys.h", "main.jsbundle"}
    assert all(row["evidence"][0]["masked_value"] == "[REDACTED]" for row in found)
    assert not _found(findings)
    assert _coverage(coverage, SOURCE_RULE)["state"] == "checked"
    assert inventory["credential_text"]["decoded_files"] == 2


@pytest.mark.parametrize("kind,suffix", [("apk", ".yaml"), ("ipa", ".h")])
@pytest.mark.parametrize(
    "raw,decoded",
    [
        (codecs.BOM_UTF8 + OPENAI.encode(), True),
        (OPENAI.encode("utf-16"), True),
        (b"\xff" + OPENAI.encode(), False),
        (b"\x00" + OPENAI.encode(), False),
        (b"bplist00" + OPENAI.encode(), False),
        (OPENAI.encode("utf-32"), False),
    ],
    ids=["utf8-bom", "utf16-bom", "invalid-utf8", "nul-binary", "binary-plist", "utf32"],
)
def test_newly_covered_suffixes_preserve_strict_decoding_and_unknowns(tmp_path, kind, suffix, raw, decoded):
    path = ("assets/" if kind == "apk" else "Payload/New.app/") + "Keys" + suffix
    inventory, _, text, findings, coverage = _checks(_package(tmp_path, kind, {path: raw}))
    metadata = inventory["credential_text"]
    assert metadata["eligible_files"] == 2
    assert (path in {name for name, _ in text}) is decoded
    assert len(_found(findings)) == int(decoded)
    assert metadata["decoded_files"] == 1 + int(decoded)
    assert metadata["omitted_files"] == int(not decoded)
    assert metadata["partial"] is (not decoded)
    assert _coverage(coverage)["state"] == ("checked" if decoded else "partial")


@pytest.mark.parametrize("kind", ["source", "apk", "ipa"])
def test_unsupported_private_and_uppercase_suffixes_do_not_broaden_admission(tmp_path, kind):
    names = [".env", "Keys.txt", "Keys.cfg", "Keys.html", "Keys.H", "Keys.YAML", "Keys.TOML"]
    for name in names:
        assert not credential_text.credential_text_input(name)
    if kind == "source":
        source = tmp_path / "source"
        source.mkdir()
        (source / "AndroidManifest.xml").write_bytes(MANIFEST)
        for name in names:
            (source / name).write_text(OPENAI)
        target = tmp_path / "staged"
        snapshot = stage_input(source, target)
        assert snapshot["files"] == 1
        rule = SOURCE_RULE
    else:
        prefix = "assets/" if kind == "apk" else "Payload/New.app/"
        target = _package(tmp_path, kind, {prefix + name: OPENAI.encode() for name in names})
        rule = RULE
    inventory, _, text, findings, coverage = _checks(target)
    assert inventory["credential_text"]["eligible_files"] == 1
    assert len(text) == 1
    assert not _found(findings, rule)
    assert _coverage(coverage, rule)["state"] == "checked"


@pytest.mark.parametrize("kind", ["apk", "ipa"])
def test_actual_worker_has_one_packaged_credential_row_and_no_native_source_flow(tmp_path, kind):
    prefix = "assets/" if kind == "apk" else "Payload/New.app/Frameworks/Fresh.framework/Headers/"
    target = _package(tmp_path, kind, {prefix + "Keys.h": OPENAI.encode()})
    report = _parser_worker.analyze(target, None)
    found = _found(report["findings"])
    assert len(found) == 1 and found[0]["status"] == "candidate"
    assert not _found(report["findings"], SOURCE_RULE)
    assert _coverage(report["coverage"])["state"] == "checked"
    source_flow = [row for row in report["coverage"] if row.get("method") == "source-ast-local-flow"]
    assert source_flow and all(row["state"] in {"not-run", "not-applicable"} for row in source_flow)


@pytest.mark.parametrize("kind", ["apk", "ipa"])
def test_os_parser_pipeline_keeps_newly_covered_credentials_masked(tmp_path, monkeypatch, store, kind):
    # Preserve normal OS parser isolation; this functional fixture is not a real app build.
    monkeypatch.delenv("APSA_PARSER_SANDBOX", raising=False)
    monkeypatch.setenv("APSA_PARSER_LOCK_DIR", str(tmp_path / "fresh-parser-locks"))
    path = (
        "assets/config.yaml" if kind == "apk" else "Payload/New.app/Frameworks/Fresh.framework/Headers/Keys.h"
    )
    report = scan(store, _package(tmp_path, kind, {path: OPENAI.encode()}), online=False)
    assert len(_found(report["findings"])) == 1
    assert _coverage(report["coverage"])["state"] == "checked"
    assert OPENAI not in json.dumps(report)
