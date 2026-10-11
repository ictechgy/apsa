"""New synthetic certificates, pages and archives; no retained application input."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import plistlib
import struct
import zipfile

import pytest

from mobile_audit.apple_trust import pinned_apple_anchors, trust_policy_summary, validate_trust_policy
from mobile_audit.binary_analysis import _code_directory, analyze_binary
from mobile_audit.cms_verification import verify_cms_code_directory
from mobile_audit.code_directory_sparse import scatter_pages
from mobile_audit.ipa_resource_seal import verify_resource_seal
from mobile_audit.processes import command


def directory_fixture(code=b"x" * 8192, pages=(0, 1), scatter=False, special=None):
    special = special or {}
    count = max(special, default=0)
    header = 48 if scatter else 44
    vector = b"".join(struct.pack(">IIQQ", 1, page, 0, 0) for page in pages) + bytes(24) if scatter else b""
    hashes = b"".join(hashlib.sha256(code[p * 4096 : min((p + 1) * 4096, len(code))]).digest() for p in pages)
    offset = header + len(vector) + count * 32
    blob = bytearray(
        struct.pack(
            ">IIIIIIIIIBBBBI",
            0xFADE0C02,
            offset + len(hashes),
            0x20100 if scatter else 0x20001,
            0,
            offset,
            0,
            count,
            len(pages),
            len(code),
            32,
            2,
            0,
            12,
            0,
        )
    )
    if scatter:
        blob += struct.pack(">I", header)
    blob += vector
    blob += b"".join(
        hashlib.sha256(special[slot]).digest() if slot in special else bytes(32)
        for slot in range(count, 0, -1)
    )
    return bytes(blob) + hashes


@pytest.fixture(scope="module")
def chain_fixture(tmp_path_factory):
    scratch = tmp_path_factory.mktemp("synthetic-chain")
    env = {"PATH": "/usr/bin:/bin", "OPENSSL_CONF": "/dev/null", "TMPDIR": str(scratch)}

    def run(args):
        return command(["/usr/bin/openssl", *args], cwd=scratch, env=env, timeout=20, max_bytes=65536)

    root_config = scratch / "root.cnf"
    root_config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n"
        "[dn]\nCN=Synthetic anchor\n[ca]\nbasicConstraints=critical,CA:TRUE\n"
        "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
    )
    root, key = scratch / "root.pem", scratch / "root.key"
    run(
        [
            "req",
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "3",
            "-config",
            str(root_config),
            "-keyout",
            str(key),
            "-out",
            str(root),
        ]
    )
    ext = scratch / "extensions.cnf"
    ext.write_text(
        "[intermediate]\nbasicConstraints=critical,CA:TRUE,pathlen:0\n"
        "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
        "authorityKeyIdentifier=keyid,issuer\n[leaf]\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n"
        "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
    )
    intermediate = scratch / "intermediate.pem"
    interkey = scratch / "intermediate.key"
    leaf, leafkey = scratch / "leaf.pem", scratch / "leaf.key"
    for name, cert, private, issuer, issuerkey in [
        ("intermediate", intermediate, interkey, root, key),
        ("leaf", leaf, leafkey, intermediate, interkey),
    ]:
        request = scratch / (name + ".csr")
        run(
            [
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-config",
                str(root_config),
                "-subj",
                "/CN=Synthetic Apple signer claim/OU=Apple",
                "-keyout",
                str(private),
                "-out",
                str(request),
            ]
        )
        run(
            [
                "x509",
                "-req",
                "-in",
                str(request),
                "-CA",
                str(issuer),
                "-CAkey",
                str(issuerkey),
                "-CAcreateserial",
                "-days",
                "2",
                "-extfile",
                str(ext),
                "-extensions",
                name,
                "-out",
                str(cert),
            ]
        )
    for private in (key, interkey, leafkey):
        private.chmod(0o600)
    directory = directory_fixture()
    content, cms = scratch / "directory.bin", scratch / "signature.der"
    content.write_bytes(directory)
    run(
        [
            "cms",
            "-sign",
            "-binary",
            "-in",
            str(content),
            "-signer",
            str(leaf),
            "-inkey",
            str(leafkey),
            "-certfile",
            str(intermediate),
            "-outform",
            "DER",
            "-out",
            str(cms),
            "-md",
            "sha256",
        ]
    )
    der = run(["x509", "-in", str(root), "-outform", "DER"])
    policy = {
        "schema_version": 1,
        "anchors": [
            {"der_base64": base64.b64encode(der).decode(), "sha256": hashlib.sha256(der).hexdigest()}
        ],
    }
    (scratch / "public-policy.json").write_text(json.dumps(policy))
    return directory, cms.read_bytes(), policy, scratch, run


def test_explicit_chain_is_not_apple_identity(chain_fixture):
    directory, cms, policy, _, _ = chain_fixture
    result = verify_cms_code_directory(cms, directory, policy)
    assert result["cryptographic_signature_verified"] is True
    assert result["chain_trust"] == "verified-explicit-anchor"
    assert result["certificate_chain_verified"] is True
    assert result["apple_signer_trust"] == "unverified"
    assert not result["apple_root_anchor_chain_verified"] and not pinned_apple_anchors(policy)
    assert result["app_authenticity_verified"] is False
    assert "der_base64" not in json.dumps(result)
    assert verify_cms_code_directory(cms, directory)["chain_trust"] == "unverified"


def test_expired_chain_keeps_cms_consistency(chain_fixture):
    directory, cms, policy, _, _ = chain_fixture
    result = verify_cms_code_directory(cms, directory, {**policy, "verification_time": 4102444800})
    assert result["cryptographic_signature_verified"] is True
    assert result["certificate_chain_verified"] is False
    assert result["chain_trust"] == "invalid-or-unsupported"


def test_wrong_anchor_and_missing_intermediate(chain_fixture):
    directory, cms, policy, scratch, run = chain_fixture
    wrong_der = run(["x509", "-in", str(scratch / "leaf.pem"), "-outform", "DER"])
    wrong = {
        "schema_version": 1,
        "anchors": [
            {
                "der_base64": base64.b64encode(wrong_der).decode(),
                "sha256": hashlib.sha256(wrong_der).hexdigest(),
            }
        ],
    }
    assert not verify_cms_code_directory(cms, directory, wrong)["certificate_chain_verified"]
    no_intermediate = scratch / "missing-intermediate.der"
    run(
        [
            "cms",
            "-sign",
            "-binary",
            "-in",
            str(scratch / "directory.bin"),
            "-signer",
            str(scratch / "leaf.pem"),
            "-inkey",
            str(scratch / "leaf.key"),
            "-outform",
            "DER",
            "-out",
            str(no_intermediate),
            "-md",
            "sha256",
        ]
    )
    result = verify_cms_code_directory(no_intermediate.read_bytes(), directory, policy)
    assert result["cryptographic_signature_verified"] and not result["certificate_chain_verified"]


def test_mixed_anchor_success_cannot_promote_failed_isolated_pin(chain_fixture, monkeypatch):
    import mobile_audit.cms_verification as verification

    directory, cms, policy, scratch, run = chain_fixture
    wrong_der = run(["x509", "-in", str(scratch / "leaf.pem"), "-outform", "DER"])
    wrong = {
        "der_base64": base64.b64encode(wrong_der).decode(),
        "sha256": hashlib.sha256(wrong_der).hexdigest(),
    }
    mixed = {**policy, "anchors": [*policy["anchors"], wrong]}
    # Exercise isolation with a test-only candidate; no synthetic certificate is a real Apple pin.
    monkeypatch.setattr(verification, "pinned_apple_anchors", lambda policy: [wrong])
    result = verify_cms_code_directory(cms, directory, mixed)
    assert result["certificate_chain_verified"] and not result["apple_root_anchor_chain_verified"]
    assert result["apple_signer_trust"] == "unverified" and not result["app_authenticity_verified"]


def test_resource_rule_boolean_types_are_not_coerced():
    result = resources({}, {}, {"^.*": 1})
    assert result["rules_state"] == "unsupported" and result["state"] == "partial"


def test_policy_binding_schema_and_budget(chain_fixture):
    _, _, policy, _, _ = chain_fixture
    normalized = validate_trust_policy(policy)
    assert validate_trust_policy(normalized) == normalized
    assert "der_base64" not in json.dumps(trust_policy_summary(normalized))
    bad = [
        {**policy, "unknown": True},
        {**policy, "verification_time": True},
        {**policy, "anchors": policy["anchors"] * 5},
        {**policy, "anchors": [{**policy["anchors"][0], "sha256": "0" * 64}]},
        {**policy, "policy_sha256": "0" * 64},
        {**policy, "anchors": []},
    ]
    for value in bad:
        with pytest.raises(ValueError):
            validate_trust_policy(value)


def test_sparse_pages_and_unsealed_gap():
    code = b"a" * 4096 + b"b" * 4096 + b"c" * 4096
    blob = directory_fixture(code, (0, 2), True)
    result = _code_directory(blob, code, {})
    assert result["mapped_integrity"] == "consistent" and result["integrity"] == "unverifiable"
    assert result["full_page_coverage"] is False
    changed = _code_directory(blob, code[:-1] + b"d", {})
    assert changed["integrity"] == "modified" and changed["mismatched_pages"] == [2]
    full = _code_directory(directory_fixture(code, (0, 1, 2), True), code, {})
    assert full["integrity"] == "consistent" and full["full_page_coverage"]


@pytest.mark.parametrize("offset,value", [(48, 65537), (52, 10), (56, 1), (68, 1), (76, 0)])
def test_sparse_bad_ranges_and_sentinel(offset, value):
    blob = bytearray(directory_fixture(scatter=True))
    struct.pack_into(">I", blob, offset, value)
    assert _code_directory(bytes(blob), b"x" * 8192, {})["integrity"] == "unverifiable"


def test_scatter_entry_budget(monkeypatch):
    import mobile_audit.code_directory_sparse as sparse

    monkeypatch.setattr(sparse, "MAX_SCATTER_ENTRIES", 1)
    blob = directory_fixture(scatter=True)
    with pytest.raises(ValueError, match="entry budget"):
        scatter_pages(blob, 48, 48, len(blob) - 64, 2, 12, 8192)


def resources(files, seal, rules=None):
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        for name, value in files.items():
            archive.writestr("Payload/App.app/" + name, value)
    raw.seek(0)
    envelope = plistlib.dumps({"files2": seal, "rules2": rules if rules is not None else {"^.*": True}})
    with zipfile.ZipFile(raw) as archive:
        return verify_resource_seal(archive, "Payload/App.app", "App", envelope)


def test_resource_hash_missing_modified_optional_and_unsealed():
    seal = {"asset.txt": {"hash2": hashlib.sha256(b"synthetic").digest()}}
    assert resources({"asset.txt": b"synthetic"}, seal)["state"] == "consistent"
    assert resources({"asset.txt": b"changed"}, seal)["state"] == "modified"
    assert resources({}, seal)["missing_files"] == 1
    assert resources({}, {"asset.txt": {**seal["asset.txt"], "optional": True}})["state"] == "consistent"
    assert resources({"asset.txt": b"synthetic", "extra.txt": b"new"}, seal)["state"] == "modified"


@pytest.mark.parametrize(
    "seal,rules",
    [
        ({"x": {"symlink": "y"}}, None),
        ({"x": {"requirement": "anchor apple", "cdhash": bytes(20)}}, None),
        ({"../x": bytes(20)}, None),
        ({"x": {"hash2": bytes(31)}}, None),
        ({}, {"^.*": True, "^omit/": {"omit": True}}),
    ],
)
def test_unsupported_resource_seals_and_rules(seal, rules):
    result = resources({}, seal, rules)
    assert result["state"] == "partial" and not result["app_authenticity_verified"]


def test_resource_envelope_binding_and_tamper():
    info, envelope = b"synthetic info", b"synthetic envelope"
    directory = directory_fixture(special={1: info, 3: envelope})
    good = _code_directory(directory, b"x" * 8192, {1: info, 3: envelope})
    assert good["info_plist_bound"] and good["resource_envelope_bound"]
    assert _code_directory(directory, b"x" * 8192, {1: info, 3: envelope + b"!"})["integrity"] == "modified"
    missing = _code_directory(directory, b"x" * 8192, {1: info})
    assert missing["resource_envelope_state"] == "missing" and missing["integrity"] == "unverifiable"


def test_resource_missing_envelope_and_byte_budget(monkeypatch):
    import mobile_audit.ipa_resource_seal as sealing

    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w"):
        pass
    raw.seek(0)
    with zipfile.ZipFile(raw) as archive:
        assert verify_resource_seal(archive, "Payload/App.app", "App", None)["state"] == "missing"
    monkeypatch.setattr(sealing, "MAX_RESOURCE_BYTES", 1)
    result = resources({"asset": b"two"}, {"asset": hashlib.sha1(b"two").digest()})
    assert result["state"] == "partial" and not result["hashes_verified"]


def test_resource_duplicate_dictionary_keys_are_unsupported():
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w"):
        pass
    raw.seek(0)
    envelope = (
        b'<?xml version="1.0"?><plist version="1.0"><dict>'
        b"<key>files2</key><dict/><key>files2</key><dict/>"
        b"<key>rules2</key><dict><key>^.*</key><true/></dict></dict></plist>"
    )
    with zipfile.ZipFile(raw) as archive:
        assert verify_resource_seal(archive, "Payload/App.app", "App", envelope)["state"] == "unsupported"


def signed_archive_fixture(chain_fixture, tmp_path):
    _, _, policy, scratch, run = chain_fixture
    info = plistlib.dumps({"CFBundleIdentifier": "synthetic.test", "CFBundleExecutable": "App"})
    envelope = plistlib.dumps(
        {"files2": {"asset": {"hash2": hashlib.sha256(b"asset").digest()}}, "rules2": {"^.*": True}}
    )
    # Signature is outside covered code; bind CodeResources and Info.plist exact bytes.
    unsigned = bytearray(4096)
    struct.pack_into("<IiiIIIII", unsigned, 0, 0xFEEDFACF, 0x100000C, 0, 2, 1, 16, 0x200000, 0)
    # CMS length depends on content, so use a padded fixed signature allocation.
    struct.pack_into("<IIII", unsigned, 32, 0x1D, 16, 4096, 16384)
    directory = directory_fixture(bytes(unsigned), (0,), special={1: info, 3: envelope})
    content, cms = scratch / "integration-directory.bin", scratch / "integration-signature.der"
    content.write_bytes(directory)
    run(
        [
            "cms",
            "-sign",
            "-binary",
            "-in",
            str(content),
            "-signer",
            str(scratch / "leaf.pem"),
            "-inkey",
            str(scratch / "leaf.key"),
            "-certfile",
            str(scratch / "intermediate.pem"),
            "-outform",
            "DER",
            "-out",
            str(cms),
            "-md",
            "sha256",
        ]
    )
    wrapper = struct.pack(">II", 0xFADE0B01, len(cms.read_bytes()) + 8) + cms.read_bytes()
    length = 28 + len(directory) + len(wrapper)
    signature = (
        struct.pack(">IIIIIII", 0xFADE0CC0, length, 2, 0, 28, 0x10000, 28 + len(directory))
        + directory
        + wrapper
    )
    macho = bytes(unsigned) + signature + bytes(16384 - len(signature))
    target = tmp_path / "synthetic.ipa"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", info)
        archive.writestr("Payload/App.app/App", macho)
        archive.writestr("Payload/App.app/asset", b"asset")
        archive.writestr("Payload/App.app/_CodeSignature/CodeResources", envelope)
    return target, policy


def test_archive_resources_and_policy_reach_signature_metadata(chain_fixture, tmp_path):
    target, policy = signed_archive_fixture(chain_fixture, tmp_path)
    result = analyze_binary(target, {"package": "synthetic.test", "ipa_trust_policy": policy})
    app = result["metadata"]["apps"][0]
    assert app["complete"] and app["resource_seal"]["signed_resources_verified"]
    sig = app["slices"][0]["code_signature"]
    assert sig["certificate_chain_verified"] and sig["integrity"] == "consistent"
    assert not app["app_authenticity_verified"] and not sig["apple_signer_trust_verified"]
    assert "der_base64" not in json.dumps(result)


def test_real_staged_parser_preserves_ipa_trust_and_removes_der(chain_fixture, tmp_path):
    from mobile_audit.engine import analyze_target

    target, policy = signed_archive_fixture(chain_fixture, tmp_path)
    result = analyze_target(target, ipa_trust_policy=policy, report_home=tmp_path / "fresh-report-home")
    inventory = result["inventory"]
    assert inventory["target"] == str(target.resolve())
    assert inventory["input_snapshot"]["files"] == 1
    app = inventory["binary"]["apps"][0]
    signature = app["slices"][0]["code_signature"]
    assert signature["certificate_chain_verified"] and signature["integrity"] == "consistent"
    assert app["resource_seal"]["signed_resources_verified"]
    assert not app["app_authenticity_verified"] and not signature["apple_signer_trust_verified"]
    normalized = validate_trust_policy(policy)
    assert inventory["ipa_trust_policy"] == trust_policy_summary(normalized)
    serialized = json.dumps(result, sort_keys=True)
    assert "der_base64" not in serialized
    assert all(anchor["der_base64"] not in serialized for anchor in policy["anchors"])
