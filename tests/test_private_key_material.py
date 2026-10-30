"""Fresh synthetic PEM-shape regressions; no real key, service, or account access."""

from __future__ import annotations

import base64
import json
import plistlib
import zipfile
from pathlib import Path

import pytest

from mobile_audit import inputs, platform_checks
from mobile_audit.core import finding_identity

LABELS = [
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "PGP PRIVATE KEY",
    "PGP PRIVATE KEY BLOCK",
]
SOURCE_RULE = "SOURCE-HARDCODED-SECRET"
PACKAGED_RULE = "PACKAGED-CREDENTIAL-TEXT"


def _body(seed: int = 0, size: int = 144) -> str:
    # Deterministic arbitrary bytes resemble an encoded payload, never a usable generated key.
    raw = bytes((index + seed) % 256 for index in range(size))
    encoded = base64.b64encode(raw).decode("ascii")
    return "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))


def _pem(label: str = "PRIVATE KEY", *, seed: int = 0, size: int = 144) -> str:
    return f"-----BEGIN {label}-----\n{_body(seed, size)}\n-----END {label}-----"


def _check(text: str, *, packaged: bool = False, path: str | None = None, metadata: dict | None = None):
    if path is None:
        path = "assets/client.key" if packaged else "src/client.ts"
    if metadata is None:
        metadata = {"collection_enabled": True, "partial": False}
    findings, coverage = platform_checks._secrets([(path, text)], packaged=packaged, metadata=metadata)
    assert len(coverage) == 1
    return findings, coverage[0]


def _private(findings: list[dict]) -> list[dict]:
    return [row for row in findings if row["evidence"][0]["credential_type"] == "private-key"]


def test_imports_are_from_this_exact_checkout():
    root = Path(__file__).resolve().parents[1]
    assert platform_checks.__file__ is not None and inputs.__file__ is not None
    assert Path(platform_checks.__file__).resolve() == root / "src/mobile_audit/platform_checks.py"
    assert Path(inputs.__file__).resolve() == root / "src/mobile_audit/inputs.py"


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "packaged"])
@pytest.mark.parametrize(
    "separator", ["\n", "\r\n", "\\n", "\\r\\n"], ids=["lf", "crlf", "escaped-lf", "escaped-crlf"]
)
@pytest.mark.parametrize("label", LABELS)
def test_matching_envelopes_with_plausible_bodies_are_candidates(packaged, separator, label):
    findings, coverage = _check(_pem(label).replace("\n", separator), packaged=packaged)
    assert len(_private(findings)) == 1
    assert findings[0]["status"] == "candidate" and findings[0]["severity"] == "high"
    assert findings[0]["evidence"][0]["masked_value"] == "[REDACTED]"
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "packaged"])
@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\n \n\t\n-----END PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----",
        _pem().replace("END PRIVATE KEY", "END RSA PRIVATE KEY"),
        _pem().split("-----END")[0],
        _pem().replace("-----END PRIVATE KEY-----", "-----END PRIVATE KEY------"),
        _pem().replace("-----END PRIVATE KEY-----", "-----END PRIVATE KEY-----invalid"),
        _pem().replace("AAEC", "?AEC"),
        _pem().replace("AAEC", "AEC"),
        _pem().replace("AAEC", "AA=C"),
    ],
    ids=[
        "header-only",
        "footer-only",
        "empty",
        "whitespace",
        "tiny-body",
        "mismatched-footer",
        "truncated",
        "malformed-footer",
        "footer-junk",
        "invalid-alphabet",
        "invalid-length",
        "bad-padding",
    ],
)
def test_incomplete_or_malformed_material_is_not_a_private_key_candidate(packaged, text):
    findings, coverage = _check(text, packaged=packaged)
    assert not _private(findings)
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "packaged"])
def test_header_footer_recognizer_constants_do_not_join_unrelated_source_fragments(packaged):
    headers = [f"-----BEGIN {label}-----" for label in LABELS]
    footers = [f"-----END {label}-----" for label in LABELS]
    text = (
        "export const PRIVATE_KEY_HEADERS = " + json.dumps(headers) + ";\n"
        "export const PRIVATE_KEY_FOOTERS = " + json.dumps(footers) + ";\n"
        'const prefix = "-----BEGIN PRIVATE KEY-----\\n";\n'
        + json.dumps(_body())
        + ';\nconst suffix = "-----END PRIVATE KEY-----";\n'
    )
    findings, coverage = _check(text, packaged=packaged)
    assert not _private(findings)
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "packaged"])
@pytest.mark.parametrize("form", ["concatenated", "margin", "json-escaped-slash"])
def test_recognized_unreconstructed_literal_forms_are_partial_without_candidates(packaged, form):
    header, footer = "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"
    if form == "concatenated":
        text = " +\n".join(json.dumps(part) for part in (header + "\n", _body() + "\n", footer))
    elif form == "margin":
        text = '"""|' + _pem().replace("\n", "\n|") + '""".trimMargin()'
    else:
        # Arbitrary all-ones bytes produce slashes, without generating a real key.
        body = base64.b64encode(b"\xff" * 96).decode("ascii")
        text = json.dumps(header + "\n" + body + "\n" + footer).replace("/", r"\/")
    findings, coverage = _check(text, packaged=packaged)
    assert not _private(findings)
    assert coverage["state"] == "partial"
    assert "concatenated literals, margin-prefixed bodies and JSON-escaped slashes" in coverage["note"]


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "packaged"])
@pytest.mark.parametrize(
    "suffix",
    [
        '" + "ordinary identifier";',
        '"; const body = "' + _body() + '";',
        "|ordinary words without a body",
        r"AA\/BB",
    ],
)
def test_reconstruction_uncertainty_needs_adjacent_body_shaped_syntax(packaged, suffix):
    text = 'const header = "-----BEGIN PRIVATE KEY-----\\n' + suffix
    findings, coverage = _check(text, packaged=packaged)
    assert not _private(findings)
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "packaged"])
@pytest.mark.parametrize("wrapper", ["json", "javascript", "template", "xml"])
def test_literal_encoded_and_multiline_embedded_material_keeps_header_offsets(packaged, wrapper):
    pem = _pem()
    if wrapper == "json":
        text = json.dumps({"tls": pem})
    elif wrapper == "javascript":
        text = "const tls = " + json.dumps(pem) + ";"
    elif wrapper == "template":
        text = "// synthetic fixture\nconst tls = `" + pem + "`;"
    else:
        text = '<resources>\n<string name="tls">' + pem.replace("\n", "\n    ") + "</string>\n</resources>"
    findings, _ = _check(text, packaged=packaged)
    assert len(_private(findings)) == 1
    evidence = findings[0]["evidence"][0]
    offset = text.index("-----BEGIN")
    assert evidence["offset"] == offset
    assert evidence["line"] == text.count("\n", 0, offset) + 1


@pytest.mark.parametrize("label", ["RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"])
def test_legacy_encrypted_pem_metadata_is_retained(label):
    text = _pem(label).replace(
        f"-----BEGIN {label}-----\n",
        f"-----BEGIN {label}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"
        + "0123456789ABCDEF" * 2
        + "\n\n",
    )
    findings, _ = _check(text)
    assert len(_private(findings)) == 1


@pytest.mark.parametrize("label", ["PGP PRIVATE KEY", "PGP PRIVATE KEY BLOCK"])
def test_pgp_armor_metadata_and_optional_checksum_are_retained(label):
    text = (
        _pem(label)
        .replace(
            f"-----BEGIN {label}-----\n",
            f"-----BEGIN {label}-----\nVersion: Synthetic fixture\nComment: no key\nMessageID: synthetic\n\n",
        )
        .replace(f"\n-----END {label}-----", f"\n=AAAA\n-----END {label}-----")
    )
    findings, _ = _check(text)
    assert len(_private(findings)) == 1


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "packaged"])
def test_retained_locations_ids_and_fixed_redaction_do_not_depend_on_body_value(packaged):
    prefix = "// synthetic\nconst value = `"
    text = prefix + _pem() + "`; const second = `" + _pem(seed=17) + "`;"
    findings, _ = _check(text, packaged=packaged)
    assert len(_private(findings)) == 2
    assert len({row["id"] for row in findings}) == 2
    for row in findings:
        evidence = row["evidence"][0]
        expected_keys = {"path", "line", "offset", "credential_type", "masked_value", "basis"}
        if packaged:
            expected_keys.add("scope")
        assert set(evidence) == expected_keys
        assert evidence["masked_value"] == "[REDACTED]"
        assert row["id"] == finding_identity(
            row["rule_id"], [{key: evidence[key] for key in ("path", "line", "offset")}]
        )
    first, _ = _check(prefix + _pem(), packaged=packaged)
    changed, _ = _check(prefix + _pem(seed=91, size=192), packaged=packaged)
    assert first == changed
    exported = json.dumps(findings)
    assert _body().splitlines()[0] not in exported
    assert "-----BEGIN" not in exported


def test_test_or_loopback_fixture_names_do_not_suppress_key_shaped_candidates():
    for path in ("tests/fixtures/localhost.key", "test/127.0.0.1.pem", "fixtures/fake-client.pem"):
        findings, coverage = _check(_pem(), path=path)
        assert len(_private(findings)) == 1 and coverage["state"] == "checked"
        assert findings[0]["status"] == "candidate"
        assert "validity and scope are not checked" in findings[0]["evidence"][0]["basis"]
        assert "production" not in json.dumps(findings)


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "packaged"])
def test_other_known_credential_kinds_are_preserved_when_headers_are_rejected(packaged):
    credentials = {
        "aws-access-key-id": "AKIA" + "A" * 16,
        "github-token": "ghp_" + "B" * 36,
        "slack-token": "xoxb-" + "C" * 20,
        "stripe-live-key": "sk_live_" + "D" * 24,
        "openai-api-key": "sk-proj-" + "E" * 24 + "T3BlbkFJ" + "F" * 24,
        "anthropic-api-key": "sk-ant-api03-" + "G" * 80,
        "google-api-key": "AIza" + "H" * 35,
    }
    text = "-----BEGIN PRIVATE KEY-----\n" + "\n".join(credentials.values())
    findings, coverage = _check(text, packaged=packaged)
    assert {row["evidence"][0]["credential_type"] for row in findings} == set(credentials)
    assert coverage["state"] == "checked"
    assert all(value not in json.dumps(findings) for value in credentials.values())


@pytest.mark.parametrize("packaged", [False, True], ids=["source", "packaged"])
def test_bound_stops_a_large_envelope_with_partial_coverage_and_keeps_later_keys(monkeypatch, packaged):
    monkeypatch.setattr(platform_checks, "MAX_PRIVATE_KEY_ENVELOPE", 256)
    text = _pem(size=768) + "\n" + _pem()
    findings, coverage = _check(text, packaged=packaged)
    assert len(_private(findings)) == 1 and coverage["state"] == "partial"
    assert findings[0]["evidence"][0]["offset"] == text.rindex("-----BEGIN")


def test_footer_at_the_screening_boundary_is_admitted_and_crossing_it_is_partial(monkeypatch):
    text = _pem()
    monkeypatch.setattr(platform_checks, "MAX_PRIVATE_KEY_ENVELOPE", len(text))
    findings, coverage = _check(text)
    assert len(_private(findings)) == 1 and coverage["state"] == "checked"
    monkeypatch.setattr(platform_checks, "MAX_PRIVATE_KEY_ENVELOPE", len(text) - 1)
    findings, coverage = _check(text)
    assert not _private(findings) and coverage["state"] == "partial"


def test_finding_cap_and_collection_partial_contracts_are_preserved(monkeypatch):
    monkeypatch.setattr(platform_checks, "MAX_SECRET_FINDINGS", 2)
    findings, coverage = _check("\n".join(_pem(seed=index) for index in range(3)))
    assert len(_private(findings)) == 2 and coverage["state"] == "partial"
    findings, coverage_rows = platform_checks._secrets([("assets/key.pem", _pem())], packaged=True)
    assert len(_private(findings)) == 1 and coverage_rows[0]["state"] == "partial"
    for metadata in ({"partial": True, "collection_enabled": True}, {"collection_enabled": False}):
        findings, coverage = _check(_pem(), metadata=metadata)
        assert len(_private(findings)) == 1 and coverage["state"] == "partial"
    findings, coverage_rows = platform_checks._secrets([("unsupported.txt", _pem())])
    assert not findings and coverage_rows[0]["state"] == "not-run"


def test_many_header_constants_and_large_nonmatching_lines_stay_bounded():
    text = ('"-----BEGIN PRIVATE KEY-----",\n' * 10_000) + "A" * 1_000_000
    findings, coverage = _check(text)
    assert not _private(findings) and coverage["state"] == "checked"


def test_repeated_newline_headers_do_not_copy_a_screening_window_per_header():
    class NoLargeSlices(str):
        def __getitem__(self, key):
            value = super().__getitem__(key)
            if isinstance(key, slice):
                # A dense recognizer input must not allocate a 64 KiB window for every header.
                assert len(value) <= 64
            return value

    text = NoLargeSlices("-----BEGIN PRIVATE KEY-----\n" * 5_000)
    findings, coverage = _check(text)
    assert not _private(findings)
    assert coverage["state"] == "checked"


@pytest.mark.parametrize("kind", ["source", "apk", "ipa"])
def test_fresh_input_collection_matches_material_and_rejects_header_constants(tmp_path, kind):
    manifest = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="org.synthetic.pem"><application/></manifest>'
    ).encode()
    pem = _pem()
    constants = 'const begin = "-----BEGIN PRIVATE KEY-----"; const end = "-----END PRIVATE KEY-----";'
    if kind == "source":
        target = tmp_path / "source"
        target.mkdir()
        (target / "AndroidManifest.xml").write_bytes(manifest)
        (target / "loopback-test.key").write_text(pem)
        (target / "recognizer.ts").write_text(constants)
        key_path = "loopback-test.key"
        rule = SOURCE_RULE
    else:
        target = tmp_path / f"fresh.{kind}"
        prefix = "assets/" if kind == "apk" else "Payload/New.app/Resources/"
        identity = (
            {"AndroidManifest.xml": manifest}
            if kind == "apk"
            else {"Payload/New.app/Info.plist": plistlib.dumps({"CFBundleIdentifier": "org.synthetic.pem"})}
        )
        key_path = prefix + "loopback-test.key"
        with zipfile.ZipFile(target, "x") as archive:
            for name, raw in {
                **identity,
                key_path: pem.encode(),
                prefix + "recognizer.ts": constants.encode(),
            }.items():
                archive.writestr(name, raw)
        rule = PACKAGED_RULE
    credential_text: list[tuple[str, str]] = []
    inventory, sources = inputs.inspect_target(target, credential_text=credential_text)
    findings, coverage = platform_checks.platform_checks(inventory, sources, credential_text=credential_text)
    found = [row for row in findings if row["rule_id"] == rule]
    assert len(found) == 1
    assert found[0]["evidence"][0]["path"] == key_path
    assert found[0]["evidence"][0]["masked_value"] == "[REDACTED]"
    assert next(row for row in coverage if row["rule_id"] == rule)["state"] == "checked"
    exported = json.dumps({"inventory": inventory, "findings": findings, "coverage": coverage})
    assert _body().splitlines()[0] not in exported
