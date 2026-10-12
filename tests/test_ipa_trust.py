"""New synthetic certificates, pages and archives; no retained application input."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import plistlib
import struct
import zipfile

import pytest

from mobile_audit.apple_trust import pinned_apple_anchors, trust_policy_summary, validate_trust_policy
from mobile_audit.binary_analysis import _code_directory, _code_signature, analyze_binary, inspect_macho
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
    try:
        result = analyze_target(target, ipa_trust_policy=policy, report_home=tmp_path / "fresh-report-home")
    except ValueError as error:
        if str(error) != "RSS inspection unavailable; resource-limited execution refused":
            raise
        if os.environ.get("GITHUB_ACTIONS") == "true":
            pytest.fail("Disposable CI must measure actual IPA parser staging and RSS")
        pytest.skip("Host privacy guard denies child RSS; actual IPA parser staging remains unmeasured here")
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


def _definite_cms_node(node):
    body = bytes(node.body)
    size = len(body)
    length = (
        bytes([size])
        if size < 128
        else bytes([0x80 | ((size.bit_length() + 7) // 8)])
        + size.to_bytes((size.bit_length() + 7) // 8, "big")
    )
    return bytes([node.tag]) + length + body


def _ber_cms_envelopes(cms):
    """Change only synthetic CMS envelopes; preserve certificates and signed attributes."""
    from mobile_audit.cms_verification import _cms_nodes

    def indefinite(tag, body):
        return bytes([tag, 0x80]) + body + b"\x00\x00"

    info = _cms_nodes(cms)[0].children
    signed = info[1].children[0].children
    values = [_definite_cms_node(node) for node in signed]
    values[2] = indefinite(0x30, bytes(signed[2].body))
    return indefinite(
        0x30,
        _definite_cms_node(info[0]) + indefinite(0xA0, indefinite(0x30, b"".join(values))),
    )


def test_synthetic_ber_cms_preserves_signature_and_explicit_chain(chain_fixture):
    directory, cms, policy, _, _ = chain_fixture
    result = verify_cms_code_directory(_ber_cms_envelopes(cms), directory, policy)
    assert result["state"] == "verified" and result["cryptographic_signature_verified"]
    assert result["certificate_chain_verified"] and result["chain_trust"] == "verified-explicit-anchor"
    assert not result["apple_root_anchor_chain_verified"]
    assert result["apple_signer_trust"] == "unverified" and not result["app_authenticity_verified"]


def test_ber_cms_rejects_changed_content_and_signed_attributes(chain_fixture):
    directory, cms, _, _, _ = chain_fixture
    ber = _ber_cms_envelopes(cms)
    changed = bytearray(directory)
    changed[-1] ^= 1
    result = verify_cms_code_directory(ber, bytes(changed))
    assert result["state"] == "invalid" and not result["cryptographic_signature_verified"]
    digest = hashlib.sha256(directory).digest()
    assert ber.count(digest) == 1
    changed = bytearray(ber)
    changed[ber.index(digest)] ^= 1
    result = verify_cms_code_directory(bytes(changed), directory)
    assert result["state"] == "invalid" and not result["cryptographic_signature_verified"]
    changed = bytearray(cms)
    changed[-1] ^= 1
    result = verify_cms_code_directory(_ber_cms_envelopes(bytes(changed)), directory)
    assert result["state"] == "invalid" and not result["cryptographic_signature_verified"]


@pytest.mark.parametrize(
    "raw",
    [
        b"\x04\x80\x00\x00",  # Primitive indefinite value.
        b"\x30\x80\x05\x00",  # Unterminated constructed value.
        b"\x30\x80\x00\x01\x00",  # Malformed EOC length.
        b"\x30\x80\x00",  # Truncated EOC/header.
        b"\x00\x00",  # EOC outside an indefinite value.
        b"\x30\x02\x00\x00",  # EOC in definite constructed content.
        b"\x30\x80\x00\x00\x00\x00",  # Extra EOC after root.
        b"\x30\x02\x30\x80\x00\x00",  # Child must end within definite parent.
        b"\x30\x80\x30\x80\x00\x00",  # Only the child has an EOC.
        b"\x30\x80\x04\x03\x00\x00\x00",  # Primitive zero bytes are not EOC.
        b"\x30\x81\x00",  # Noncanonical definite length stays unsupported.
        b"\x30\x82\x00\x80" + bytes(128),
        b"\x30\x85" + bytes(5),  # Length width exceeds supported bounds.
        b"\x3f\x80\x00\x00",  # Unsupported high-tag encoding.
    ],
)
def test_ber_malformed_encodings_fail_closed(raw):
    from mobile_audit.cms_verification import _cms_nodes

    with pytest.raises(ValueError):
        _cms_nodes(raw)


def test_ber_mixed_lengths_preserve_primitive_zero_bytes():
    from mobile_audit.cms_verification import _cms_nodes

    nodes = _cms_nodes(b"\x30\x08\x30\x80\x04\x02\x00\x00\x00\x00")
    assert nodes[0].children[0].children[0].body == b"\x00\x00"


def test_ber_shared_depth_node_and_byte_budgets():
    from mobile_audit.cms_verification import MAX_CMS_BYTES, MAX_DER_DEPTH, MAX_DER_NODES, _cms_nodes

    with pytest.raises(ValueError, match="depth budget"):
        _cms_nodes(b"\x30\x80" * (MAX_DER_DEPTH + 1) + b"\x00\x00" * (MAX_DER_DEPTH + 1))
    with pytest.raises(ValueError, match="node budget"):
        _cms_nodes(b"\x30\x80" + b"\x05\x00" * MAX_DER_NODES + b"\x00\x00")
    with pytest.raises(ValueError, match="byte budget"):
        _cms_nodes(bytes(MAX_CMS_BYTES + 1))


def test_ber_detached_structure_rejects_trailing_and_attached_content(chain_fixture, monkeypatch):
    import mobile_audit.cms_verification as verification
    from mobile_audit.cms_verification import _cms_nodes, _detached_signed_data

    directory, cms, _, _, _ = chain_fixture
    ber = _ber_cms_envelopes(cms)
    with pytest.raises(ValueError, match="one sequence"):
        _detached_signed_data(ber + b"\x05\x00")
    # Inject an attached OCTET STRING into the indefinite eContentInfo envelope.
    content = _cms_nodes(cms)[0].children[1].children[0].children[2]
    encoded = b"\x30\x80" + bytes(content.body) + b"\x00\x00"
    attached = ber.replace(encoded, encoded[:-2] + b"\xa0\x02\x04\x00\x00\x00", 1)
    assert attached != ber
    with pytest.raises(ValueError, match="Only detached"):
        _detached_signed_data(attached)

    def unexpected_command(*args, **kwargs):
        raise AssertionError("Invalid structure must be rejected before external verification")

    monkeypatch.setattr(verification, "command", unexpected_command)
    for raw in (ber + b"\x05\x00", attached, ber[:-2]):
        result = verify_cms_code_directory(raw, directory)
        assert result["state"] == "unsupported" and not result["cryptographic_signature_verified"]


@pytest.mark.parametrize(
    "when,basis", [(None, "verifier-current-time"), (4102444800, "explicit-policy-epoch")]
)
def test_chain_evidence_alias_origin_and_time_basis_are_explicit(chain_fixture, when, basis):
    directory, cms, policy, _, _ = chain_fixture
    policy = {**policy, **({"verification_time": when} if when is not None else {})}
    result = verify_cms_code_directory(cms, directory, policy)
    assert result["explicit_anchor_chain_verified"] is result["certificate_chain_verified"]
    assert result["certificate_chain_verified_alias"] == "explicit_anchor_chain_verified"
    assert result["chain_anchor_origin"] == "explicit-policy-anchors"
    assert result["chain_scope"] == "explicit-anchor-cryptographic-chain-only"
    assert result["verification_time_basis"] == basis
    assert result["verification_time"] == (when if when is not None else "current-time")
    assert result["trust_policy"]["verification_time_basis"] == basis
    assert result["trust_policy"]["anchor_origin"] == "explicit-policy-anchors"
    assert result["trust_policy"]["openssl_purpose"] == "any"
    assert result["trust_policy"]["apple_critical_extensions"] == "not-validated"
    assert not result["apple_critical_extensions_verified"]
    assert not result["signer_purpose_policy_verified"] and not result["revocation_checked"]
    assert result["cryptographic_signature_verified"]
    assert result["apple_signer_trust"] == "unverified" and not result["app_authenticity_verified"]


@pytest.mark.parametrize(
    "policy,origin,trust",
    [
        (None, "none", "unverified"),
        ({"schema_version": 99}, "unsupported-policy", "unsupported-policy"),
    ],
)
def test_absent_and_invalid_anchor_policy_never_promote_chain_evidence(chain_fixture, policy, origin, trust):
    directory, cms, _, _, _ = chain_fixture
    result = verify_cms_code_directory(cms, directory, policy)
    assert result["cryptographic_signature_verified"]
    assert not result["explicit_anchor_chain_verified"] and not result["certificate_chain_verified"]
    assert result["chain_anchor_origin"] == origin and result["chain_trust"] == trust
    assert result["verification_time_basis"] == "not-run"
    assert not result["apple_critical_extensions_verified"] and not result["revocation_checked"]
    assert not result["app_authenticity_verified"]


def _signature_superblob(entries):
    header_size = 12 + 8 * len(entries)
    table, payload = [], bytearray()
    for slot, blob in entries:
        table.append(struct.pack(">II", slot, header_size + len(payload)))
        payload += blob
    return (
        struct.pack(">III", 0xFADE0CC0, header_size + len(payload), len(entries)) + b"".join(table) + payload
    )


def _synthetic_cms_wrapper(cms):
    return struct.pack(">II", 0xFADE0B01, len(cms) + 8) + cms


def _directory_with_identifier(directory, identifier):
    # Page hashes stay identical; only unsigned alternate metadata is changed.
    blob = bytearray(directory)
    struct.pack_into(">I", blob, 20, len(blob))
    blob += identifier.encode("ascii") + b"\0"
    struct.pack_into(">I", blob, 4, len(blob))
    return bytes(blob)


@pytest.mark.parametrize("mutation", ["identifier", "ad-hoc-flag"])
def test_alternate_metadata_mutation_keeps_primary_cms_but_never_binds_alternate(chain_fixture, mutation):
    directory, cms, policy, _, _ = chain_fixture
    alternate = _directory_with_identifier(directory, "synthetic.one")
    changed = bytearray(alternate)
    if mutation == "identifier":
        changed = changed.replace(b"synthetic.one", b"synthetic.two")
    else:
        struct.pack_into(">I", changed, 12, 2)
    changed = bytes(changed)
    cms_digest = hashlib.sha256(cms).hexdigest()
    outputs = []
    for value in (alternate, changed):
        raw = _signature_superblob([(0, directory), (0x1000, value), (0x10000, _synthetic_cms_wrapper(cms))])
        result = _code_signature(raw, b"x" * 8192, policy)
        outputs.append(result)
        assert result["cryptographic_signature_verified"] and result["explicit_anchor_chain_verified"]
        assert result["integrity"] == "consistent" and result["signature_integrity"] == "partial"
        assert not result["cms_binding_complete"] and result["cms_binding_state"] == "partial"
        primary, alt = result["code_directories"]
        assert primary["slot"] == 0 and primary["cms_bound"]
        assert primary["cms_binding_state"] == "verified-exact-primary"
        assert alt["slot"] == 0x1000 and alt["directory_role"] == "alternate"
        assert not alt["cms_bound"] and alt["cms_binding_state"] == "unverified-signed-cdhashes-attributes"
        assert not result["apple_signer_trust_verified"] and not result["app_authenticity_verified"]
        assert result["cms_verification"]["signed_content_sha256"] == hashlib.sha256(directory).hexdigest()
    assert hashlib.sha256(cms).hexdigest() == cms_digest
    assert outputs[0]["code_directories"][0] == outputs[1]["code_directories"][0]
    assert (
        outputs[0]["code_directories"][1]["directory_sha256"]
        != outputs[1]["code_directories"][1]["directory_sha256"]
    )
    key = "identifier" if mutation == "identifier" else "ad_hoc"
    assert outputs[0]["code_directories"][1][key] != outputs[1]["code_directories"][1][key]


def test_primary_only_exact_binding_is_complete_but_not_app_authenticity(chain_fixture):
    directory, cms, policy, _, _ = chain_fixture
    raw = _signature_superblob([(0, directory), (0x10000, _synthetic_cms_wrapper(cms))])
    result = _code_signature(raw, b"x" * 8192, policy)
    assert result["cryptographic_signature_verified"] and result["cms_binding_complete"]
    assert (
        result["cms_binding_state"] == "complete"
        and result["signature_integrity"] == "cms-and-code-consistent"
    )
    assert result["code_directories"][0]["cms_bound"]
    assert result["explicit_anchor_chain_verified"] is result["certificate_chain_verified"]
    assert result["chain_anchor_origin"] == "explicit-policy-anchors"
    assert not result["apple_signer_trust_verified"] and not result["app_authenticity_verified"]


@pytest.mark.parametrize("slot", [0x1004, 0x1005, 0x2000])
def test_extra_directory_slots_are_visible_and_never_promoted(chain_fixture, slot):
    directory, cms, policy, _, _ = chain_fixture
    raw = _signature_superblob([(0, directory), (slot, directory), (0x10000, _synthetic_cms_wrapper(cms))])
    result = _code_signature(raw, b"x" * 8192, policy)
    assert result["cryptographic_signature_verified"]
    assert len(result["code_directories"]) == 2
    primary, extra = result["code_directories"]
    assert primary["cms_bound"] and not extra["cms_bound"]
    assert extra["slot"] == slot
    assert not result["cms_binding_complete"] and result["signature_integrity"] == "partial"
    if slot >= 0x1005:
        assert extra["directory_role"] == "unsupported-slot" and extra["integrity"] == "unverifiable"


def test_alternate_without_primary_is_never_promoted_even_if_cms_content_matches(chain_fixture):
    directory, cms, policy, _, _ = chain_fixture
    raw = _signature_superblob([(0x1000, directory), (0x10000, _synthetic_cms_wrapper(cms))])
    result = _code_signature(raw, b"x" * 8192, policy)
    assert not result["cryptographic_signature_verified"]
    assert not result["code_directories"][0]["cms_bound"] and not result["cms_binding_complete"]
    assert result["signature_integrity"] == "partial"


def test_malformed_declared_alternate_slot_cannot_be_ignored(chain_fixture):
    directory, cms, policy, _, _ = chain_fixture
    wrong_magic = struct.pack(">II", 0xFADE0C01, 8)
    raw = _signature_superblob(
        [(0, directory), (0x1000, wrong_magic), (0x10000, _synthetic_cms_wrapper(cms))]
    )
    result = _code_signature(raw, b"x" * 8192, policy)
    assert result["cryptographic_signature_verified"]
    assert result["code_directories"][1]["integrity"] == "unverifiable"
    assert not result["code_directories"][1]["cms_bound"]
    assert not result["cms_binding_complete"] and result["signature_integrity"] == "partial"


def test_primary_metadata_mutation_invalidates_unchanged_cms(chain_fixture):
    directory, cms, policy, _, _ = chain_fixture
    changed = bytearray(directory)
    struct.pack_into(">I", changed, 12, 2)
    raw = _signature_superblob([(0, bytes(changed)), (0x10000, _synthetic_cms_wrapper(cms))])
    result = _code_signature(raw, b"x" * 8192, policy)
    assert result["integrity"] == "consistent"
    assert not result["cryptographic_signature_verified"] and not result["cms_binding_complete"]
    assert not result["code_directories"][0]["cms_bound"]
    assert result["signature_integrity"] == "invalid-cms"


def test_macho_postprocessing_does_not_promote_alternate_binding(chain_fixture, tmp_path):
    target, policy = signed_archive_fixture(chain_fixture, tmp_path)
    with zipfile.ZipFile(target) as archive:
        macho = archive.read("Payload/App.app/App")
        info = archive.read("Payload/App.app/Info.plist")
        envelope = archive.read("Payload/App.app/_CodeSignature/CodeResources")
    signature_region = macho[4096:]
    _, _, count = struct.unpack_from(">III", signature_region)
    assert count == 2
    primary_offset = struct.unpack_from(">I", signature_region, 16)[0]
    cms_offset = struct.unpack_from(">I", signature_region, 24)[0]
    primary_size = struct.unpack_from(">I", signature_region, primary_offset + 4)[0]
    cms_size = struct.unpack_from(">I", signature_region, cms_offset + 4)[0]
    directory = signature_region[primary_offset : primary_offset + primary_size]
    wrapper = signature_region[cms_offset : cms_offset + cms_size]
    raw = _signature_superblob([(0, directory), (0x1000, directory), (0x10000, wrapper)])
    changed_macho = macho[:4096] + raw + bytes(16384 - len(raw))
    signature = inspect_macho(changed_macho, policy, {1: info, 3: envelope})[0]["code_signature"]
    assert signature["integrity"] == "consistent" and signature["cryptographic_signature_verified"]
    assert not signature["cms_binding_complete"] and signature["signature_integrity"] == "partial"
    assert signature["code_directories"][0]["cms_bound"] and not signature["code_directories"][1]["cms_bound"]


def test_all_directory_rows_remain_visible_under_superblob_entry_budget(chain_fixture):
    directory, cms, policy, _, _ = chain_fixture
    entries = [(0, directory)]
    entries += [(0x1000 + index, directory) for index in range(5)]
    entries += [(0x2000 + index, directory) for index in range(121)]
    entries += [(0x10000, _synthetic_cms_wrapper(cms))]
    result = _code_signature(_signature_superblob(entries), b"x" * 8192, policy)
    assert len(result["code_directories"]) == 127
    assert sum(row["cms_bound"] for row in result["code_directories"]) == 1
    assert result["code_directories"][-1]["slot"] == 0x2000 + 120
    assert not result["cms_binding_complete"] and result["signature_integrity"] == "partial"
    # Exceeding the entry budget still fails before CMS verification.
    from mobile_audit.binary_analysis import BinaryFormatError

    entries.insert(-1, (0x3000, directory))
    with pytest.raises(BinaryFormatError, match="index table"):
        _code_signature(_signature_superblob(entries), b"x" * 8192, policy)


def test_duplicate_directory_slots_remain_fail_closed(chain_fixture):
    from mobile_audit.binary_analysis import BinaryFormatError

    directory, cms, policy, _, _ = chain_fixture
    raw = _signature_superblob([(0, directory), (0, directory), (0x10000, _synthetic_cms_wrapper(cms))])
    with pytest.raises(BinaryFormatError, match="duplicate code signature slot"):
        _code_signature(raw, b"x" * 8192, policy)
