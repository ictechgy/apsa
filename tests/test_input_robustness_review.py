"""Input-handling regressions from the parser robustness/isolation review.

One malformed or amplifying member must become a partial result, never an
aborted audit, and nothing may read as cleanly checked when it was not.
"""

from __future__ import annotations

import io
import itertools
import json
import os
import plistlib
import re
import signal
import struct
import sys
import zipfile
from contextlib import contextmanager, nullcontext

import pytest

from mobile_audit import engine, ingest, inputs, parser_sandbox
from mobile_audit.ingest import _text
from mobile_audit.processes import CommandFailure
from quaygate.apk import MAX_ZIP_ENTRIES, Apk
from quaygate.axml import AxmlError, parse_axml
from tests.helpers import add_v2_block, axml_document, build_apk, manifest_tree

MANIFEST = b'<manifest package="com.example.app"><application android:allowBackup="false" xmlns:android="http://schemas.android.com/apk/res/android"/></manifest>'


def _inventory():
    return {
        "platforms": [],
        "apps": [],
        "android_config": [],
        "components": [],
        "deep_links": [],
        "warnings": [],
        "ios_config": [],
        "partial": False,
    }


@contextmanager
def _deadline(seconds):
    """Fail instead of hanging when a regression restores super-linear work."""

    class Deadline(Exception):
        pass

    def expire(*_):
        raise Deadline

    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    except Deadline:
        pytest.fail(f"Work exceeded {seconds}s; amplification is unbounded")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


# 1. Binary plist shared references -------------------------------------------------


def _dag_plist(depth):
    node: list = ["x"]
    for _ in range(depth):
        node = [node, node]
    value = {
        "CFBundleIdentifier": "com.example.dag",
        "NSAppTransportSecurity": {"NSExceptionDomains": {}, "Extra": node},
    }
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY)


def test_shared_reference_ats_is_rejected_before_serialization():
    # Depth 20 keeps an unbounded implementation finite (one million leaves).
    raw = _dag_plist(20)
    assert len(raw) < 1024
    inventory = _inventory()
    with pytest.raises(ValueError, match="logical size budget"):
        inputs.ios_plist(raw, "Info.plist", inventory)
    assert inventory["ios_config"] == [] and inventory["platforms"] == []


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="POSIX interval timer")
def test_plist_budget_counts_every_shared_reference_without_expanding():
    node: list = ["x"]
    for _ in range(64):
        node = [node, node]
    with _deadline(5), pytest.raises(ValueError, match="logical size budget"):
        inputs._plist_within_budget([{"Extra": node}, []])
    inputs._plist_within_budget([{"key": "x" * 1024}, [{"CFBundleURLSchemes": ["a"] * 100}] * 100])


def test_shared_url_types_cannot_multiply_deep_links():
    entry = {"CFBundleURLSchemes": ["app"] * 300}
    raw = plistlib.dumps(
        {"CFBundleIdentifier": "com.example.urls", "CFBundleURLTypes": [entry] * 300},
        fmt=plistlib.FMT_BINARY,
    )
    inventory = _inventory()
    with pytest.raises(ValueError, match="logical size budget"):
        inputs.ios_plist(raw, "Info.plist", inventory)
    assert inventory["deep_links"] == []


def test_vendor_shared_reference_plist_leaves_source_audit_partial(tmp_path):
    (tmp_path / "app/src/main").mkdir(parents=True)
    (tmp_path / "app/src/main/AndroidManifest.xml").write_bytes(MANIFEST)
    (tmp_path / "app/src/main/A.java").write_text("class A {}")
    (tmp_path / "vendor/Example/App").mkdir(parents=True)
    (tmp_path / "vendor/Example/App/Info.plist").write_bytes(_dag_plist(22))
    inventory, sources = inputs.inspect_target(tmp_path)
    assert len(json.dumps(inventory, allow_nan=False)) < 64 * 1024
    assert inventory["partial"] is True
    assert "Could not parse vendor/Example/App/Info.plist: ValueError" in inventory["warnings"]
    assert inventory["ios_config"] == []
    assert inventory["package"] == "com.example.app"
    assert [name for name, _ in sources] == ["app/src/main/A.java", "app/src/main/AndroidManifest.xml"]


@pytest.mark.parametrize("fmt", [plistlib.FMT_XML, plistlib.FMT_BINARY])
def test_ordinary_plist_with_shared_strings_is_unchanged(fmt):
    domains = {
        f"api{index}.example.com": {
            "NSIncludesSubdomains": True,
            "NSExceptionAllowsInsecureHTTPLoads": index % 2 == 0,
            "NSExceptionMinimumTLSVersion": "TLSv1.2",
        }
        for index in range(500)
    }
    value = {
        "CFBundleIdentifier": "com.example.ordinary",
        "CFBundleShortVersionString": "1.0",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False, "NSExceptionDomains": domains},
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["example", "example-dev"]}] * 3,
    }
    inventory = _inventory()
    inputs.ios_plist(plistlib.dumps(value, fmt=fmt), "Info.plist", inventory)
    assert inventory["ios_config"][0]["ats"] == value["NSAppTransportSecurity"]
    assert [link["scheme"] for link in inventory["deep_links"]] == ["example", "example-dev"] * 3
    assert inventory["package"] == "com.example.ordinary"


# 2. Third-party binary manifest parser --------------------------------------------


def _mutated_manifest(offset, value):
    raw = bytearray(axml_document(manifest_tree()))
    struct.pack_into("<I", raw, offset, value)
    return bytes(raw)


# Deterministic mutations that made androguard raise struct.error / IndexError.
MALFORMED_MANIFESTS = [_mutated_manifest(18, 0xFFFFFFFF), _mutated_manifest(22, 0)]


@pytest.mark.parametrize("raw", MALFORMED_MANIFESTS, ids=["struct-error", "index-error"])
def test_androguard_failures_become_invalid_manifest(raw):
    with pytest.raises(ValueError, match="Invalid binary AndroidManifest.xml"):
        inputs.android_manifest(raw, "AndroidManifest.xml", _inventory())


@pytest.mark.parametrize("raw", MALFORMED_MANIFESTS, ids=["struct-error", "index-error"])
def test_malformed_third_party_manifest_leaves_source_audit_partial(tmp_path, raw):
    (tmp_path / "app/src/main").mkdir(parents=True)
    (tmp_path / "app/src/main/AndroidManifest.xml").write_bytes(MANIFEST)
    (tmp_path / "app/src/main/A.java").write_text("class A {}")
    (tmp_path / "third_party/sample").mkdir(parents=True)
    (tmp_path / "third_party/sample/AndroidManifest.xml").write_bytes(raw)
    inventory, _ = inputs.inspect_target(tmp_path)
    assert inventory["partial"] is True
    assert "Could not parse third_party/sample/AndroidManifest.xml: ValueError" in inventory["warnings"]
    assert inventory["package"] == "com.example.app"


def test_malformed_apk_manifest_is_a_controlled_input_error(tmp_path):
    target = tmp_path / "broken.apk"
    build_apk(target, MALFORMED_MANIFESTS[0])
    with pytest.raises(ValueError, match="no readable Android manifest"):
        inputs.inspect_target(target)


def test_valid_binary_manifest_is_unchanged():
    tree = manifest_tree(components=[("activity", {"name": ".Main", "exported": "true"}, [])])
    inventory = _inventory()
    inputs.android_manifest(axml_document(tree), "AndroidManifest.xml", inventory)
    assert inventory["package"] == "com.example"
    assert inventory["platforms"] == ["android"] and inventory["warnings"] == []
    assert inventory["android_config"][0]["debuggable"] == "false"
    assert [c["type"] for c in inventory["components"]] == ["activity"]


# 3. SARIF text sanitizer --------------------------------------------------------------

ORIGINAL_LITERAL = re.compile(r"""(["'`])(?:\\.|(?!\1).)*?\1""")


@pytest.mark.skipif(not hasattr(signal, "setitimer"), reason="POSIX interval timer")
@pytest.mark.parametrize("tail", ["x", "", "\n", '"'])
def test_backslash_run_in_untrusted_text_is_linear(tail):
    value = '"' + "\\" * 2400 + tail
    with _deadline(2):
        assert len(_text(value)) <= 300
        _text('"' + "\\" * 44 + "x")


def _previous_text(value, limit=300):
    text = ORIGINAL_LITERAL.sub('"…"', value[: limit * 8])
    return ingest.redact(ingest.CREDENTIAL.sub(r"\1[REDACTED]", text)).replace("\n", " ")[:limit]


def test_literal_masking_matches_previous_sanitizer_output():
    alphabet = ['"', "'", "`", "\\", "a", "\n"]
    for length in range(7):
        for chars in itertools.product(alphabet, repeat=length):
            text = "".join(chars)
            assert _text(text) == _previous_text(text), repr(text)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ('Hard-coded key "sk-live-123" in Config', 'Hard-coded key "…" in Config'),
        ("SQL built with 'SELECT * FROM t' and `id`", 'SQL built with "…" and "…"'),
        ('Escaped "a \\"quoted\\" value" kept masked', 'Escaped "…" kept masked'),
        ('Path "C:\\temp\\" ends here', 'Path "…" ends here'),
        ("password=hunter2 near 'x'", 'password=[REDACTED] near "…"'),
    ],
)
def test_ordinary_sarif_text_is_unchanged(value, expected):
    assert _text(value) == expected


# 4. Legacy text XML DTD guard ---------------------------------------------------------


@pytest.mark.parametrize("declaration", ["", '<?xml version="1.0" encoding="UTF-16"?>'])
def test_utf16le_text_xml_cannot_declare_entities(declaration):
    document = (declaration + '<!DOCTYPE m [<!ENTITY p "com.injected">]><manifest package="&p;"/>').encode(
        "utf-16-le"
    )
    # Without a byte order mark this still takes the text-XML path.
    assert document.startswith(b"<") and b"<!DOCTYPE" not in document
    with pytest.raises(AxmlError, match="DTD"):
        parse_axml(document)


@pytest.mark.parametrize("encoding", ["utf-8", "utf-16-le"])
def test_text_xml_without_dtd_still_parses(encoding):
    document = '<manifest package="com.example"><application/></manifest>'.encode(encoding)
    events = parse_axml(document)
    assert events[0] == ("start", "manifest", {"package": "com.example"})
    assert [event for event, _, _ in events] == ["start", "start", "end", "end"]


# 5. Archive entry budget --------------------------------------------------------------


def test_resource_heavy_apk_above_previous_cap_is_audited(tmp_path):
    target = tmp_path / "many.apk"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        for index in range(inputs.MAX_FILES):
            archive.writestr(f"res/drawable/i{index}.png", b"")
    inventory, _ = inputs.inspect_target(target)
    assert inventory["package"] == "com.example.app"
    assert inventory["partial"] is False
    assert inventory["files_scanned"] == 1
    # Binary analysis applies the same central-directory bound instead of the source file cap.
    from mobile_audit.binary_analysis import analyze_binary

    binary = analyze_binary(target, inventory)
    assert "size/file-count" not in " ".join(binary["warnings"])


def _aliased_archive(count, *, declared=None, zip64=False, comment=b""):
    """Directory records alias one empty stored member; nothing decompresses."""
    name = b"a.txt"
    local = struct.pack("<4s5H3I2H", b"PK\x03\x04", 20, 0, 0, 0, 0, 0, 0, 0, len(name), 0) + name
    central = (
        struct.pack("<4s6H3I5H2I", b"PK\x01\x02", 20, 20, 0, 0, 0, 0, 0, 0, 0, len(name), 0, 0, 0, 0, 0, 0)
        + name
    )
    directory = central * count
    trailer = b""
    if zip64:
        trailer = struct.pack(
            "<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, len(directory), len(local)
        ) + struct.pack("<4sIQI", b"PK\x06\x07", 0, len(local) + len(directory), 1)
    declared = count if declared is None else declared
    end = struct.pack(
        "<4s4H2IH",
        b"PK\x05\x06",
        0,
        0,
        declared,
        declared,
        len(central) if zip64 else len(directory),
        len(local),
        len(comment),
    )
    return local + directory + trailer + end + comment


@pytest.fixture
def no_zipfile(monkeypatch):
    def unexpected(*args, **kwargs):
        pytest.fail("ZipFile allocated entries before the directory budget was checked")

    monkeypatch.setattr(inputs.zipfile, "ZipFile", unexpected)


@pytest.mark.parametrize(
    "raw",
    [
        _aliased_archive(MAX_ZIP_ENTRIES + 1),
        _aliased_archive(MAX_ZIP_ENTRIES + 1, declared=1, zip64=True),
        _aliased_archive(MAX_ZIP_ENTRIES + 1, comment=b"c" * 65535),
        _aliased_archive(1)[:-10] + struct.pack("<IIH", 9 * 1024 * 1024, 35, 0),
    ],
    ids=["count", "zip64-hidden", "max-comment", "directory-bytes"],
)
def test_directory_bomb_is_refused_before_entry_allocation(tmp_path, no_zipfile, raw):
    target = tmp_path / "bomb.zip"
    target.write_bytes(raw)
    with pytest.raises(ValueError, match="safe size/file-count"):
        inputs.inspect_target(target)


def test_directory_bytes_field_inside_final_record_cannot_hide_the_end_record(tmp_path, no_zipfile):
    # A directory size spelling the end signature must not redirect the search.
    raw = bytearray(_aliased_archive(1))
    struct.pack_into("<4s", raw, len(raw) - 10, b"PK\x05\x06")
    target = tmp_path / "spelled.zip"
    target.write_bytes(bytes(raw))
    with pytest.raises(ValueError, match="safe size/file-count"):
        inputs.inspect_target(target)


def _with_zip64_end(raw: bytes) -> bytes:
    end = raw.rfind(b"PK\x05\x06")
    entries, size, offset = struct.unpack_from("<HII", raw, end + 10)
    record = struct.pack("<4sQ2H2I4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, entries, entries, size, offset)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, end, 1)
    return raw[:end] + record + locator + raw[end:]


def test_small_zip64_archive_remains_supported(tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("AndroidManifest.xml", MANIFEST)
        archive.writestr("res/raw/config.json", b'{"a": 1}')
    target = tmp_path / "zip64.apk"
    target.write_bytes(_with_zip64_end(buffer.getvalue()))
    with zipfile.ZipFile(target) as archive:
        assert len(archive.infolist()) == 2
    inventory, _ = inputs.inspect_target(target)
    assert inventory["package"] == "com.example.app"
    assert inventory["files_scanned"] == 2


# 6/7. Parser isolation disclosure and failure advice ---------------------------------


@pytest.fixture
def parser_boundary(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "A.java").write_text("class A {}")
    response = {
        "inventory": {
            "dependencies": [],
            "warnings": [],
            "platforms": [],
            "fingerprint": "0" * 64,
            "partial": False,
            "fingerprint_complete": True,
        },
        "findings": [],
        "coverage": [{"rule_id": "SYNTHETIC", "state": "checked"}],
    }
    monkeypatch.setattr(engine, "parser_lease", lambda: nullcontext())
    monkeypatch.setattr(engine, "command", lambda *a, **k: json.dumps(response))
    return source, response


@pytest.mark.parametrize(
    ("mode", "backend", "expected"),
    [
        ("auto", None, "Parser OS isolation unavailable; parsed with resource limits only: no supported"),
        ("off", "/usr/bin/sandbox-exec", "Parser OS isolation disabled; parsed with resource limits only"),
    ],
)
def test_parsing_without_os_isolation_is_disclosed(parser_boundary, monkeypatch, mode, backend, expected):
    source, _ = parser_boundary
    monkeypatch.setenv("APSA_PARSER_SANDBOX", mode)
    monkeypatch.setattr(parser_sandbox, "backend", lambda: backend)
    result = engine.analyze_target(source)
    assert result["inventory"]["parser_isolation"]["state"] in {"unavailable", "disabled"}
    assert [w for w in result["inventory"]["warnings"] if w.startswith(expected)]
    # A disclosure, not an incomplete-analysis signal.
    assert result["inventory"]["partial"] is False
    assert result["coverage"] == [{"rule_id": "SYNTHETIC", "state": "checked"}]


def test_enforced_isolation_adds_no_disclosure(parser_boundary, monkeypatch):
    source, _ = parser_boundary
    isolation = {"state": "enforced", "backend": "seatbelt", "activation_probe": "passed"}
    monkeypatch.setattr(parser_sandbox, "sandbox_command", lambda args, *a, **k: (args, isolation))
    monkeypatch.setattr(parser_sandbox, "activate", lambda wrapped, args, state, scratch: (wrapped, state))
    assert engine.analyze_target(source)["inventory"]["warnings"] == []


@pytest.mark.parametrize("returncode", [1, -signal.SIGKILL])
def test_input_induced_sandboxed_failure_does_not_advise_disabling_isolation(
    parser_boundary, monkeypatch, returncode
):
    source, _ = parser_boundary
    isolation = {"state": "enforced", "backend": "seatbelt", "activation_probe": "passed"}
    monkeypatch.setattr(parser_sandbox, "sandbox_command", lambda args, *a, **k: (args, isolation))
    monkeypatch.setattr(parser_sandbox, "activate", lambda wrapped, args, state, scratch: (wrapped, state))

    def failed(*args, **kwargs):
        raise CommandFailure(sys.executable, returncode)

    monkeypatch.setattr(engine, "command", failed)
    with pytest.raises(ValueError) as caught:
        engine.analyze_target(source)
    message = str(caught.value)
    assert "APSA_PARSER_SANDBOX=off" not in message and "incompatible" not in message
    assert "not retried without OS isolation" in message
    assert "while analyzing this input" in message
    assert f"exit {returncode}" in message
    assert ("(SIGKILL)" in message) is (returncode < 0)


def test_required_mode_probe_failure_still_offers_resource_limit_modes(tmp_path, monkeypatch):
    monkeypatch.setattr(
        parser_sandbox.subprocess,
        "run",
        lambda *a, **k: type("Result", (), {"returncode": 71, "stderr": b"synthetic denial"})(),
    )
    metadata = {"state": "enforced", "backend": "seatbelt", "mode": "required"}
    with pytest.raises(ValueError, match="APSA_PARSER_SANDBOX=auto or off"):
        parser_sandbox.activate(["sandbox", "python"], ["python"], metadata, tmp_path)


# 8. Legacy signature check reads the snapshot -----------------------------------------


@pytest.mark.parametrize("signed_snapshot", [True, False])
def test_v2_signature_check_uses_the_preflighted_snapshot(tmp_path, signed_snapshot):
    path = tmp_path / "app.apk"
    other = tmp_path / "other.apk"
    build_apk(path, axml_document(manifest_tree()))
    build_apk(other, axml_document(manifest_tree()))
    add_v2_block(path if signed_snapshot else other)
    apk = Apk(str(path))
    try:
        # The original path changes after preflight; the snapshot must decide.
        os.replace(other, path)
        assert apk.has_v2_plus_signature() is signed_snapshot
        path.unlink()
        assert apk.has_v2_plus_signature() is signed_snapshot
    finally:
        apk.close()


def test_v2_signature_check_keeps_member_reads_working(tmp_path):
    path = tmp_path / "app.apk"
    build_apk(path, axml_document(manifest_tree()), extra={"res/raw/a.txt": b"payload" * 100})
    add_v2_block(path)
    with Apk(str(path)) as apk:
        with apk.zipf.open("res/raw/a.txt") as handle:
            first = handle.read(10)
            assert apk.has_v2_plus_signature() is True
            rest = handle.read()
        assert first + rest == b"payload" * 100
        assert apk.read("AndroidManifest.xml") == axml_document(manifest_tree())
