from __future__ import annotations

import base64
import copy
import hashlib

import pytest

from mobile_audit.artifact_oracle import MAX_OUTPUT_BYTES, record_digest, validate_artifact_observation


def fresh_record():
    digest = hashlib.sha256(b"new synthetic bytes").hexdigest()
    value = {
        "schema_version": 1,
        "oracle": "codesign_integrity",
        "argv": [
            "/usr/bin/codesign",
            "--verify",
            "--deep",
            "--strict",
            "--verbose=4",
            "/private/tmp/new/App.app",
        ],
        "environment": {"PATH": "/usr/bin:/bin", "TMPDIR": "/private/tmp/new"},
        "tool_sha256": digest,
        "input_sha256": {"App.app/App": digest},
        "source_sha256": {"new.c": digest},
        "compiler_sha256": {"clang": digest},
        "returncode": 0,
        "timed_out": False,
        "output_truncated": False,
    }
    for name, raw in (("stdout", b""), ("stderr", b"synthetic tool-reported validity")):
        value[f"{name}_base64"] = base64.b64encode(raw).decode()
        value[f"{name}_sha256"] = hashlib.sha256(raw).hexdigest()
    value["record_sha256"] = record_digest(value)
    return value


def consume(value, reference=None):
    reference = reference or fresh_record()
    return validate_artifact_observation(
        value,
        expected_inputs=reference["input_sha256"],
        expected_argv=reference["argv"],
        expected_tool_sha256=reference["tool_sha256"],
        expected_environment=reference["environment"],
    )


def test_consistent_record_is_attested_and_never_install_or_trust_proof():
    summary = consume(fresh_record())
    assert summary["state"] == "reported-pass"
    assert "authenticity not cryptographically verified" in summary["provenance"]
    for key in (
        "installability_verified",
        "resource_merge_verified",
        "apple_identity_policy_verified",
        "provisioning_authorization_verified",
        "revocation_checked",
    ):
        assert summary[key] is False


@pytest.mark.parametrize("field", ["timed_out", "output_truncated"])
def test_incomplete_capture_does_not_report_pass(field):
    value = fresh_record()
    value[field] = True
    value["record_sha256"] = record_digest(value)
    assert consume(value)["state"] == "incomplete"


def test_failure_is_preserved_despite_success_text():
    value = fresh_record()
    value["returncode"] = 1
    value["record_sha256"] = record_digest(value)
    assert consume(value)["state"] == "reported-fail"


@pytest.mark.parametrize("binding", ["input_sha256", "tool_sha256", "argv"])
def test_fresh_independent_binding_rejects_recomputed_forged_record(binding):
    value = fresh_record()
    if binding == "input_sha256":
        value[binding]["App.app/App"] = "0" * 64
    elif binding == "tool_sha256":
        value[binding] = "0" * 64
    else:
        value[binding][-1] = "/private/tmp/new/Other.app"
    value["record_sha256"] = record_digest(value)
    with pytest.raises(ValueError, match="mismatch|match"):
        consume(value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("returncode", True),
        ("timed_out", 0),
        ("output_truncated", "false"),
        ("oracle", []),
        ("stderr_base64", "%%%%"),
        ("stdout_sha256", "0" * 64),
        ("source_sha256", {}),
        ("compiler_sha256", {}),
    ],
)
def test_malformed_or_tampered_record_rejected(field, value):
    record = fresh_record()
    record[field] = value
    record["record_sha256"] = record_digest(record)
    with pytest.raises(ValueError):
        consume(record)


def test_output_budget_and_checksum_are_enforced():
    record = fresh_record()
    bad = copy.deepcopy(record)
    bad["stdout_base64"] = base64.b64encode(b"x" * (MAX_OUTPUT_BYTES + 1)).decode()
    bad["record_sha256"] = record_digest(bad)
    with pytest.raises(ValueError, match="budget|binding"):
        consume(bad)
    record["returncode"] = 1
    with pytest.raises(ValueError, match="checksum"):
        consume(record)


def test_unrelated_successful_command_cannot_be_labeled_integrity_oracle():
    record = fresh_record()
    record["argv"] = ["/usr/bin/true"]
    record["record_sha256"] = record_digest(record)
    with pytest.raises(ValueError, match="command shape"):
        consume(record, record)


def test_unmeasured_bundletool_selection_schema_cannot_report_pass():
    record = fresh_record()
    record["oracle"] = "bundletool_selection"
    record["record_sha256"] = record_digest(record)
    with pytest.raises(ValueError, match="kind unsupported"):
        consume(record)


def test_independently_expected_environment_rejects_recomputed_transcript():
    record = fresh_record()
    record["environment"]["JAVA_HOME"] = "/private/tmp/new/unexpected-runtime"
    record["record_sha256"] = record_digest(record)
    with pytest.raises(ValueError, match="environment binding"):
        consume(record)
