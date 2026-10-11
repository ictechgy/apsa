"""Bounded, snapshot-bound external artifact observations.

Hashes establish consistency, not the authenticity of a submitted tool transcript.
Callers must retain how a transcript was captured. This module never infers device
installability, resource-merge behavior, provisioning authorization or Apple trust.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

MAX_RECORD_BYTES = 512 * 1024
MAX_OUTPUT_BYTES = 128 * 1024
MAX_INPUTS = 256
MAX_ARGV = 128
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ORACLES = {"codesign_integrity", "apksigner_signature"}
_FIELDS = {
    "schema_version",
    "oracle",
    "argv",
    "environment",
    "tool_sha256",
    "input_sha256",
    "source_sha256",
    "compiler_sha256",
    "returncode",
    "timed_out",
    "output_truncated",
    "stdout_base64",
    "stderr_base64",
    "stdout_sha256",
    "stderr_sha256",
    "record_sha256",
}


def _hashes(value: object, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or not 1 <= len(value) <= MAX_INPUTS:
        raise ValueError(f"Oracle {label} requires a bounded nonempty digest map")
    result = {}
    for name, digest in value.items():
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 1024
            or "\x00" in name
            or not isinstance(digest, str)
            or not _DIGEST.fullmatch(digest)
        ):
            raise ValueError(f"Oracle {label} name/digest invalid")
        result[name] = digest
    return result


def record_digest(value: Mapping[str, Any]) -> str:
    """Canonical consistency checksum; it is not a digital signature."""
    payload = {key: item for key, item in value.items() if key != "record_sha256"}
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_artifact_observation(
    value: object,
    *,
    expected_inputs: Mapping[str, str],
    expected_argv: Sequence[str],
    expected_tool_sha256: str,
    expected_environment: Mapping[str, str],
) -> dict[str, Any]:
    """Check a record against independently supplied current input/tool identities.

    Even a matching record remains a caller-attested observation. JSON with a
    self-consistent checksum cannot prove that an official tool actually ran.
    """
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError("Oracle record fields unsupported")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("Oracle schema unsupported")
    if not isinstance(value["oracle"], str) or value["oracle"] not in _ORACLES:
        raise ValueError("Oracle kind unsupported")
    argv = value["argv"]
    if (
        not isinstance(argv, list)
        or not 1 <= len(argv) <= MAX_ARGV
        or any(not isinstance(arg, str) or not 1 <= len(arg) <= 4096 or "\x00" in arg for arg in argv)
        or argv != list(expected_argv)
    ):
        raise ValueError("Oracle argv does not match independently expected command")
    environment = value["environment"]
    if (
        not isinstance(environment, dict)
        or not {"PATH", "TMPDIR"} <= set(environment)
        or set(environment) - {"PATH", "TMPDIR", "JAVA_HOME"}
        or any(
            not isinstance(item, str) or not 1 <= len(item) <= 4096 or "\x00" in item
            for item in environment.values()
        )
        or environment != dict(expected_environment)
    ):
        raise ValueError("Oracle environment binding mismatch")
    if value["oracle"] == "codesign_integrity":
        valid_command = (
            len(argv) == 6
            and argv[0].endswith("/codesign")
            and argv[1:5] == ["--verify", "--deep", "--strict", "--verbose=4"]
            and argv[5].startswith("/")
            and argv[5].endswith(".app")
        )
    else:
        valid_command = (
            len(argv) == 5
            and argv[0].endswith("/apksigner")
            and argv[1:4] == ["verify", "--verbose", "--print-certs"]
            and argv[4].startswith("/")
            and argv[4].endswith(".apk")
        )
    if not valid_command:
        raise ValueError("Oracle command shape unsupported")
    if (
        not isinstance(expected_tool_sha256, str)
        or not _DIGEST.fullmatch(expected_tool_sha256)
        or value["tool_sha256"] != expected_tool_sha256
    ):
        raise ValueError("Oracle tool identity mismatch")
    inputs = _hashes(value["input_sha256"], "inputs")
    if inputs != _hashes(dict(expected_inputs), "expected inputs"):
        raise ValueError("Oracle current input binding mismatch")
    sources = _hashes(value["source_sha256"], "sources")
    compilers = _hashes(value["compiler_sha256"], "compilers")
    if type(value["returncode"]) is not int or not -128 <= value["returncode"] <= 255:
        raise ValueError("Oracle exit status invalid")
    if type(value["timed_out"]) is not bool or type(value["output_truncated"]) is not bool:
        raise ValueError("Oracle capture completion flags invalid")
    for stream in ("stdout", "stderr"):
        encoded = value[f"{stream}_base64"]
        if not isinstance(encoded, str) or len(encoded) > (MAX_OUTPUT_BYTES + 2) // 3 * 4:
            raise ValueError("Oracle output byte budget exceeded")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError:
            raise ValueError("Oracle output encoding invalid") from None
        if (
            len(raw) > MAX_OUTPUT_BYTES
            or base64.b64encode(raw).decode() != encoded
            or hashlib.sha256(raw).hexdigest() != value[f"{stream}_sha256"]
        ):
            raise ValueError("Oracle output digest/encoding binding mismatch")
    if not isinstance(value["record_sha256"], str) or not _DIGEST.fullmatch(value["record_sha256"]):
        raise ValueError("Oracle record consistency checksum invalid")
    # All containers/scalars have been bounded before allocating serialization.
    serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(serialized.encode()) > MAX_RECORD_BYTES:
        raise ValueError("Oracle record byte budget exceeded")
    if value["record_sha256"] != record_digest(value):
        raise ValueError("Oracle record consistency checksum mismatch")
    complete = not value["timed_out"] and not value["output_truncated"]
    state = "reported-pass" if complete and value["returncode"] == 0 else "reported-fail"
    if not complete:
        state = "incomplete"
    return {
        "state": state,
        "oracle": value["oracle"],
        "record_sha256": value["record_sha256"],
        "input_sha256": inputs,
        "tool_sha256": expected_tool_sha256,
        "source_sha256": sources,
        "compiler_sha256": compilers,
        "provenance": "caller-attested; transcript authenticity not cryptographically verified",
        "installability_verified": False,
        "resource_merge_verified": False,
        "apple_identity_policy_verified": False,
        "provisioning_authorization_verified": False,
        "revocation_checked": False,
    }
