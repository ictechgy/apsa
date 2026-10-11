"""Generated protobuf/CMS fixtures only; no retained app data or signing keys."""

import hashlib
import struct
from pathlib import Path
from xml.etree import ElementTree as XML

import pytest

from mobile_audit.aab_manifest import decode_manifest
from mobile_audit.aab_resources import build_resources
from mobile_audit.binary_analysis import BinaryFormatError, _code_directory, _code_signature
from mobile_audit.cms_verification import verify_cms_code_directory
from mobile_audit.processes import command


def integer(number):
    output = bytearray()
    while number >= 128:
        output.append((number & 127) | 128)
        number >>= 7
    output.append(number)
    return bytes(output)


def message(number, value):
    return integer(number << 3 | 2) + integer(len(value)) + value


def scalar(number, value):
    return integer(number << 3) + integer(value)


def string_item(value):
    return message(2, message(1, value.encode()))


def primitive(field, value):
    return message(7, scalar(field, value))


def reference(identifier):
    return message(1, scalar(2, identifier))


def resource_table(entries, *, package_id=127):
    encoded = []
    for identifier, name, values in entries:
        configs = b"".join(
            message(6, (message(1, config) if config else b"") + message(2, message(4, item)))
            for item, config in values
        )
        encoded.append(message(3, message(1, scalar(1, identifier)) + message(2, name.encode()) + configs))
    type_ = message(1, scalar(1, 1)) + message(2, b"scalar") + b"".join(encoded)
    package = message(1, scalar(1, package_id)) + message(2, b"synthetic.app") + message(3, type_)
    return message(2, package)


def manifest(item, declared=None):
    attr = message(1, b"http://schemas.android.com/apk/res/android") + message(2, b"debuggable")
    if declared is not None:
        attr += message(3, declared.encode())
    attr += message(6, item)
    return message(1, message(3, b"manifest") + message(4, attr))


@pytest.mark.parametrize(
    "item,expected",
    [
        (string_item("synthetic"), "synthetic"),
        (message(3, message(1, b"raw")), "raw"),
        (primitive(6, 42), "42"),
        (primitive(6, (1 << 64) - 7), "-7"),
        (primitive(7, 255), "255"),
        (primitive(8, 0), "false"),
        (primitive(8, 1), "true"),
        (message(5, message(1, b"res/xml/synthetic.xml") + scalar(2, 3)), "res/xml/synthetic.xml"),
    ],
)
def test_scalar_resource_values_resolve_with_provenance(item, expected):
    resolver = build_resources({"base": resource_table([(1, "value", [(item, b"")])])})
    xml, warnings = decode_manifest(manifest(reference(0x7F010001), "@scalar/value"), resources=resolver)
    assert XML.fromstring(xml).get("{http://schemas.android.com/apk/res/android}debuggable") == expected
    assert not warnings
    assert resolver.evidence[0]["state"] == "resolved"
    assert resolver.evidence[0]["candidates"][0]["module"] == "base"


def test_matching_module_values_and_aliases_resolve():
    entries = [(1, "value", [(primitive(8, 1), b"")]), (2, "alias", [(reference(0x7F010001), b"")])]
    resolver = build_resources({"base": resource_table(entries), "feature": resource_table(entries)})
    assert resolver.resolve_item(reference(0x7F010002)) == "true"
    assert {c["module"] for c in resolver.evidence[-1]["candidates"]} == {"base", "feature"}


def test_module_conflicts_and_device_qualified_variants_stay_unresolved():
    tables = {
        "base": resource_table([(1, "value", [(primitive(8, 0), b"")])]),
        "feature": resource_table([(1, "value", [(primitive(8, 1), b"")])]),
    }
    resolver = build_resources(tables)
    assert resolver.resolve_item(reference(0x7F010001)) is None
    assert "conflict" in resolver.evidence[-1]["reason"]
    resolver = build_resources({"base": resource_table([(1, "value", [(primitive(8, 1), scalar(1, 1))])])})
    assert resolver.resolve_item(reference(0x7F010001)) is None
    assert resolver.evidence[-1]["candidates"][0]["qualified"]


@pytest.mark.parametrize(
    "item",
    [
        reference(0x7F010001),  # self cycle
        reference(0x7F010001) + scalar(8, 1),  # gated by flag
        message(1, scalar(2, 0x7F010001) + message(5, scalar(1, 1))),  # dynamic
        message(1, scalar(2, 0x7F010001) + scalar(1, 1)),  # theme reference
        primitive(8, 2),  # noncanonical boolean
        message(5, message(1, b"../outside")),
        string_item("synthetic") + scalar(99, 1),
    ],
)
def test_unknown_flags_dynamic_cycles_and_malformed_scalars_are_unresolved(item):
    resolver = build_resources({"base": resource_table([(1, "value", [(item, b"")])])})
    assert resolver.resolve_item(reference(0x7F010001)) is None
    assert resolver.warnings and resolver.evidence[-1]["state"] == "unresolved"


def test_resource_budgets_and_partial_table_never_establish_value():
    table = resource_table([(1, "value", [(primitive(8, 1), b"")])])
    with pytest.raises(ValueError, match="byte budget"):
        build_resources({"base": table, "feature": table}, max_bytes=len(table))
    resolver = build_resources({"base": table}, max_entries=3)
    assert resolver.partial and resolver.resolve_item(reference(0x7F010001)) is None
    resolver = build_resources({"base": table, "feature": b"\x12\x80"})
    assert resolver.partial and resolver.resolve_item(reference(0x7F010001)) is None


def test_alias_depth_budget_and_resolution_work_budget():
    entries = [
        (index, f"value{index}", [(reference(0x7F010000 | (index + 1)), b"")]) for index in range(1, 10)
    ]
    entries.append((10, "value10", [(primitive(8, 1), b"")]))
    resolver = build_resources({"base": resource_table(entries)}, max_depth=2)
    assert resolver.resolve_item(reference(0x7F010001)) is None
    assert "budget" in resolver.evidence[-1]["reason"]
    resolver = build_resources({"base": resource_table(entries)})
    resolver.resolution_remaining = 1
    assert resolver.resolve_item(reference(0x7F010001)) is None


def directory_fixture():
    code = b"new synthetic code pages"
    ident = b"synthetic.app\0"
    offset = 44 + len(ident)
    length = offset + 32
    directory = (
        struct.pack(
            ">IIIIIIIIIBBBBI", 0xFADE0C02, length, 0x20001, 0, offset, 44, 0, 1, len(code), 32, 2, 0, 12, 0
        )
        + ident
        + hashlib.sha256(code).digest()
    )
    return code, directory


@pytest.fixture(scope="module")
def signed_fixture(tmp_path_factory):
    if not Path("/usr/bin/openssl").is_file():
        pytest.skip("System OpenSSL unavailable")
    scratch = tmp_path_factory.mktemp("new-synthetic-signing")
    env = {"PATH": "/usr/bin:/bin", "OPENSSL_CONF": "/dev/null", "TMPDIR": str(scratch)}
    code, directory = directory_fixture()
    config = scratch / "synthetic-openssl.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\nCN=SyntheticOnly\n")
    data = scratch / "directory.bin"
    data.write_bytes(directory)
    key, certificate, cms = scratch / "new-key.pem", scratch / "new-cert.pem", scratch / "new-signature.der"
    command(
        [
            "/usr/bin/openssl",
            "req",
            "-config",
            str(config),
            "-new",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            "/CN=SyntheticOnly",
        ],
        timeout=10,
        max_bytes=64 * 1024,
        cwd=scratch,
        env=env,
    )
    command(
        [
            "/usr/bin/openssl",
            "cms",
            "-sign",
            "-binary",
            "-in",
            str(data),
            "-signer",
            str(certificate),
            "-inkey",
            str(key),
            "-outform",
            "DER",
            "-out",
            str(cms),
        ],
        timeout=10,
        max_bytes=64 * 1024,
        cwd=scratch,
        env=env,
    )
    yield code, directory, cms.read_bytes()
    key.unlink()


def superblob(directory, cms):
    wrapper = struct.pack(">II", 0xFADE0B01, len(cms) + 8) + cms
    length = 28 + len(directory) + len(wrapper)
    return (
        struct.pack(">III", 0xFADE0CC0, length, 2)
        + struct.pack(">II", 0, 28)
        + struct.pack(">II", 0x10000, 28 + len(directory))
        + directory
        + wrapper
    )


def test_cms_verifies_exact_directory_but_self_signed_does_not_establish_trust(signed_fixture):
    code, directory, cms = signed_fixture
    result = _code_signature(superblob(directory, cms), code)
    verification = result["cms_verification"]
    assert verification["state"] == "verified"
    assert result["integrity"] == "consistent" and result["cryptographic_signature_verified"]
    assert not result["signature_verified"] and not result["app_authenticity_verified"]
    assert verification["apple_signer_trust"] == verification["chain_trust"] == "unverified"


def test_changed_directory_or_cms_does_not_verify(signed_fixture):
    code, directory, cms = signed_fixture
    modified = directory[:-1] + bytes([directory[-1] ^ 1])
    assert verify_cms_code_directory(cms, modified)["state"] == "invalid"
    changed_cms = cms[:-1] + bytes([cms[-1] ^ 1])
    result = verify_cms_code_directory(changed_cms, directory)
    assert not result["cryptographic_signature_verified"]
    signature = _code_signature(superblob(directory, changed_cms), code)
    assert signature["integrity"] == "consistent"
    assert signature["signature_integrity"] == "invalid-cms"
    assert signature["cms_verification"]["state"] == "invalid"


def test_missing_malformed_unsupported_and_tool_denied_remain_unverified(signed_fixture, monkeypatch):
    import mobile_audit.cms_verification as verification

    _, directory, cms = signed_fixture
    assert verify_cms_code_directory(b"", directory)["state"] == "not-run"
    assert verify_cms_code_directory(b"not-der", directory)["state"] == "unsupported"
    monkeypatch.setattr(
        verification, "command", lambda *args, **kwargs: (_ for _ in ()).throw(PermissionError())
    )
    assert verify_cms_code_directory(cms, directory)["state"] == "not-run"


def test_scatter_and_versioned_header_limits_remain_unverifiable():
    code, old = directory_fixture()
    directory = bytearray(old)
    struct.pack_into(">I", directory, 8, 0x20600)
    with pytest.raises(BinaryFormatError, match="versioned"):
        _code_directory(bytes(directory), code, {})
    directory = bytearray(96)
    struct.pack_into(">III", directory, 0, 0xFADE0C02, len(directory), 0x20100)
    struct.pack_into(">I", directory, 44, 64)
    result = _code_directory(bytes(directory), code, {})
    assert result["integrity"] == "unverifiable" and "scatter" in result["reason"]
    struct.pack_into(">I", directory, 44, 4096)
    with pytest.raises(BinaryFormatError, match="scatter"):
        _code_directory(bytes(directory), code, {})


def test_duplicate_signature_slots_fail_closed(signed_fixture):
    code, directory, cms = signed_fixture
    raw = bytearray(superblob(directory, cms))
    struct.pack_into(">I", raw, 20, 0)
    with pytest.raises(BinaryFormatError, match="duplicate"):
        _code_signature(bytes(raw), code)
