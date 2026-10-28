"""Public replay regression: explicit DEX failure is partial, not optional abstention."""

import struct
from pathlib import Path

import pytest

from mobile_audit import quaygate_analysis as lint
from mobile_audit.completeness import report_incomplete
from quaygate import ipa as ipa_module
from quaygate.checks import Finding
from tests.helpers import build_code_dex, build_dex, build_macho, temp_apk, temp_ipa


def clean_dex():
    return build_code_dex(
        [("Lcom/Synthetic;", "run", "Ljavax/crypto/Cipher;", "getInstance", "AES/GCM/NoPadding")]
    )


@pytest.mark.parametrize("indicator", ["ordinary synthetic string", "MD5"])
def test_actual_partial_dex_scope_cannot_claim_complete_and_keeps_positives(indicator):
    broken = bytearray(build_dex([indicator]))
    struct.pack_into("<II", broken, 0x60, 1, len(broken) - 4)
    with temp_apk(files={"classes.dex": clean_dex(), "classes2.dex": bytes(broken)}, v1=False) as path:
        report = lint.analyze(Path(path).resolve())
    scope = next(row for row in report["coverage"] if row["rule_id"] == "QG-DEX-BYTECODE-SCOPE")
    assert scope["state"] == "partial"
    assert report["metadata"]["complete"] is False
    assert "Quaygate check incomplete: QG-DEX-BYTECODE-SCOPE" in report["warnings"]
    assert report_incomplete({"inventory": {"quaygate": report["metadata"]}, "coverage": report["coverage"]})
    candidates = [row for row in report["findings"] if row["rule_id"] == "QG-DEX-WEAK-CRYPTO"]
    assert bool(candidates) == (indicator == "MD5")
    assert all(row["status"] == "candidate" for row in candidates)


def test_successful_actual_dex_has_no_partial_scope_marker():
    with temp_apk(files={"classes.dex": clean_dex()}, v1=False) as path:
        report = lint.analyze(Path(path).resolve())
    scope = next(row for row in report["coverage"] if row["rule_id"] == "QG-DEX-BYTECODE-SCOPE")
    assert scope["state"] == "not-applicable"
    assert report["metadata"]["complete"] is True
    assert "Quaygate check incomplete: QG-DEX-BYTECODE-SCOPE" not in report["warnings"]
    assert "QG-DEX-BYTECODE-SCOPE" in {row["id"] for row in lint.catalog()}


def test_optional_unavailable_check_still_abstains_without_partial_execution(tmp_path, monkeypatch):
    target = tmp_path / "synthetic.ipa"
    target.write_bytes(b"fresh synthetic adapter fixture")
    monkeypatch.setattr(
        lint, "_audit", lambda _: ({}, [Finding("bin-secrets", "Unavailable", "na", None, "no input")])
    )
    report = lint.analyze(target)
    check = next(row for row in report["coverage"] if row["rule_id"] == "QG-BIN-SECRETS")
    assert check["state"] == "not-run"
    assert report["metadata"]["complete"] is True
    assert not report_incomplete({"coverage": report["coverage"]})


def test_actual_partial_ipa_stream_is_partial_execution(monkeypatch):
    monkeypatch.setattr(ipa_module, "BINARY_SCAN_LIMIT", 32)
    monkeypatch.setattr(ipa_module, "MAX_BINARY_BYTES", 128)
    with temp_ipa(binary=build_macho() + b"\0" * 1024) as path:
        report = lint.analyze(Path(path).resolve())
    scope = next(row for row in report["coverage"] if row["rule_id"] == "QG-BIN-SCAN-SCOPE")
    assert scope["state"] == "partial"
    assert report["metadata"]["complete"] is False
    assert "Quaygate check incomplete: QG-BIN-SCAN-SCOPE" in report["warnings"]
    assert report_incomplete({"coverage": report["coverage"]})


def test_successful_actual_ipa_has_no_partial_stream_marker():
    with temp_ipa(binary=build_macho()) as path:
        report = lint.analyze(Path(path).resolve())
    scope = next(row for row in report["coverage"] if row["rule_id"] == "QG-BIN-SCAN-SCOPE")
    assert scope["state"] == "not-applicable"
    assert report["metadata"]["complete"] is True
    assert "QG-BIN-SCAN-SCOPE" in {row["id"] for row in lint.catalog()}


def test_partial_dynamic_call_retains_remediation():
    dynamic = build_code_dex(
        [("Lcom/Synthetic;", "run", "Ljava/lang/Runtime;", "exec", "synthetic command never executed")]
    )
    broken = bytearray(build_dex(["ordinary synthetic string"]))
    struct.pack_into("<II", broken, 0x60, 1, len(broken) - 4)
    with temp_apk(files={"classes.dex": dynamic, "classes2.dex": bytes(broken)}, v1=False) as path:
        report = lint.analyze(Path(path).resolve())
    finding = next(row for row in report["findings"] if row["rule_id"] == "QG-DEX-DYNAMIC-CODE")
    assert finding["status"] == "candidate"
    assert "입력 출처를 검증하세요" in finding["remediation"]
    assert report["metadata"]["complete"] is False


def test_actual_all_unreadable_native_members_have_partial_scope():
    with temp_apk(
        files={"classes.dex": clean_dex(), "lib/arm64-v8a/libsynthetic.so": b"not ELF"}, v1=False
    ) as path:
        report = lint.analyze(Path(path).resolve())
    scope = next(row for row in report["coverage"] if row["rule_id"] == "QG-NATIVE-SCAN-SCOPE")
    assert scope["state"] == "partial"
    assert report["metadata"]["complete"] is False
    assert report_incomplete({"coverage": report["coverage"]})
    assert not any(row["rule_id"] == "QG-NATIVE-SCAN-SCOPE" for row in report["findings"])
