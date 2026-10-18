"""Generated structures + CMS mocks; no SDK, signing process or network."""

import struct
import zipfile

import pytest

from mobile_audit.binary_analysis import analyze_binary, inspect_macho
from mobile_audit.inputs import inspect_target
from tests.test_code_signature_scope import DER_BLOB, INFO, XML_BLOB, superblob
from tests.test_ipa_trust import directory_fixture

RESOURCE = b"new synthetic sealed resources"
NORMAL = {1: INFO, 3: RESOURCE, 5: XML_BLOB, 7: DER_BLOB}
NAMES = {1: "info_plist", 3: "resource_envelope", 5: "entitlements", 7: "der_entitlements"}


def fixture(slot, kind, mismatch, mixed):
    expected = dict(NORMAL)
    provided = dict(NORMAL)
    if kind in {"missing", "absent"}:
        provided.pop(slot)
    if kind == "absent":
        expected.pop(slot)
    if kind == "mismatch":
        if slot in {1, 3}:
            provided[slot] = b"new synthetic different metadata"
        elif slot == 5:
            v = XML_BLOB.replace(b"<true/>", b"<false/>")
            provided[slot] = struct.pack(">II", 0xFADE7171, len(v)) + v[8:]
        else:
            provided[slot] = struct.pack(">II", 0xFADE7172, 13) + b"\x30\x03\x02\x01\x00"

    def directory(code, special, defective):
        d = bytearray(directory_fixture(code, pages=(0, 1), special=special))
        if defective and kind == "zero":
            pos = struct.unpack_from(">I", d, 16)[0] - slot * 32
            d[pos : pos + 32] = bytes(32)
        elif defective and kind == "malformed-directory":
            struct.pack_into(">I", d, 16, len(d) + 99)
        elif defective and kind == "unsupported-hash":
            d[37] = 99
        return bytes(d)

    def signature(code):
        dirs = [(0, directory(code, expected, True))]
        if mixed:
            dirs = [(0, directory(code, provided, False)), (0x1000, directory(code, expected, True))]
        return superblob(
            dirs
            + [(s, provided[s]) for s in (5, 7) if s in provided]
            + [(0x10000, struct.pack(">II", 0xFADE0B01, 12) + b"MOCK")]
        )

    code = bytearray(b"x" * 8192)
    sigsize = len(signature(code))
    commands = (
        struct.pack("<II16sQQQQiiII", 0x19, 72, b"__TEXT", 0, 8192, 0, 8192, 7, 5, 0, 0)
        + struct.pack("<IIII", 0x1D, 16, 8192, sigsize)
        + struct.pack("<IIIIII", 0x2C, 24, 4096, 4096, 1, 0)
    )
    struct.pack_into("<IIIIIIII", code, 0, 0xFEEDFACF, 0x01000007, 3, 2, 3, len(commands), 0, 0)
    code[32 : 32 + len(commands)] = commands
    raw = bytearray(bytes(code) + signature(code))
    if mismatch:
        raw[5000] ^= 1
    return bytes(raw), {s: v for s, v in provided.items() if s in (1, 3)}


@pytest.fixture(autouse=True)
def mock_cms(monkeypatch):
    monkeypatch.setattr(
        "mobile_audit.binary_analysis.verify_cms_code_directory",
        lambda *a: {
            "state": "verified",
            "cryptographic_signature_verified": True,
            "certificate_chain_verified": False,
            "explicit_anchor_chain_verified": False,
            "chain_scope": "synthetic-mock-no-trust",
            "chain_anchor_origin": "not-supplied",
            "verification_time_basis": "not-measured",
        },
    )


def report_for(tmp_path, raw, bundle):
    path = tmp_path / "new-synthetic.ipa"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", INFO)
        archive.writestr("Payload/App.app/App", raw)
        if 3 in bundle:
            archive.writestr("Payload/App.app/_CodeSignature/CodeResources", bundle[3])
    return analyze_binary(path, inspect_target(path)[0])


@pytest.mark.parametrize("slot", [1, 3, 5, 7])
@pytest.mark.parametrize(
    "kind", ["consistent", "mismatch", "missing", "zero", "absent", "malformed-directory", "unsupported-hash"]
)
@pytest.mark.parametrize("mismatch", [False, True])
@pytest.mark.parametrize("mixed", [False, True])
def test_encryption_preserves_independent_metadata_uncertainty(tmp_path, slot, kind, mismatch, mixed):
    raw, bundle = fixture(slot, kind, mismatch, mixed)
    signature = inspect_macho(raw, bundle_blobs=bundle)[0]["code_signature"]
    unavailable = kind in {"missing", "malformed-directory", "unsupported-hash"}
    modified = kind == "mismatch" or kind == "zero" and slot in {5, 7}
    if unavailable:
        assert signature["integrity"] == "unverifiable", signature
        assert any(
            row["integrity"] != "unverifiable-encrypted-pages" for row in signature["code_directories"]
        ), signature
    elif modified:
        assert signature["integrity"] == "modified", signature
    elif mismatch:
        assert all(
            row["integrity"] == "unverifiable-encrypted-pages" for row in signature["code_directories"]
        ), signature
    else:
        assert signature["integrity"] == "consistent", signature
    # The IPA producer necessarily supplies its Info.plist: omission/mismatch of
    # that external blob is a direct inspect_macho contract test only.
    if slot == 1 and kind in {"missing", "mismatch"}:
        return
    report = report_for(tmp_path, raw, bundle)
    state = next(row["state"] for row in report["coverage"] if row["rule_id"] == "BINARY-IOS-CODE-INTEGRITY")
    assert state == ("partial" if unavailable else "checked" if modified or not mismatch else "not-run"), (
        report
    )


@pytest.mark.parametrize(
    "kind,expected", [("consistent", "partial"), ("missing", "partial"), ("absent", "checked")]
)
@pytest.mark.parametrize("mismatch", [False, True])
@pytest.mark.parametrize("mixed", [False, True])
def test_known_sealed_der_absence_is_not_a_complete_xml_only_entitlements_check(
    tmp_path, kind, expected, mismatch, mixed
):
    raw, bundle = fixture(7, kind, mismatch, mixed)
    report = report_for(tmp_path, raw, bundle)
    state = next(row["state"] for row in report["coverage"] if row["rule_id"] == "BINARY-IOS-ENTITLEMENTS")
    assert state == expected, report
