"""Explicit public anchors for chain-only evidence, never Apple identity policy."""

from __future__ import annotations

import base64
import hashlib
import json

MAX_TRUST_POLICY_BYTES = 65_536
MAX_ANCHOR_BYTES = 8192
MAX_ANCHORS = 4
APPLE_ROOT_PIN_SOURCE = "https://support.apple.com/en-us/126047"
# Official Apple OS26 trust-store SHA-256 fingerprint table, checked 2026-10-11.
# These are public root identities only, not developer certificate/signer policy.
APPLE_ROOT_SHA256 = frozenset(
    {
        "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",  # Apple Root CA
        "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",  # Apple Root CA G2
        "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",  # Apple Root CA G3
    }
)


def validate_trust_policy(value: object) -> dict:
    if (
        not isinstance(value, dict)
        or set(value) - {"schema_version", "anchors", "verification_time", "policy_sha256"}
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("IPA trust policy schema is unsupported")
    try:
        serialized = json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        raise ValueError("IPA trust policy must contain JSON values") from None
    if len(serialized.encode()) > MAX_TRUST_POLICY_BYTES:
        raise ValueError("IPA trust policy byte budget exceeded")
    anchors = value.get("anchors")
    if not isinstance(anchors, list) or not 1 <= len(anchors) <= MAX_ANCHORS:
        raise ValueError("IPA trust policy requires one to four explicit anchors")
    normalized = {"schema_version": 1, "anchors": []}
    seen = set()
    for anchor in anchors:
        if (
            not isinstance(anchor, dict)
            or set(anchor) != {"der_base64", "sha256"}
            or not isinstance(anchor["der_base64"], str)
            or not isinstance(anchor["sha256"], str)
        ):
            raise ValueError("IPA trust anchor fields are invalid")
        try:
            der = base64.b64decode(anchor["der_base64"], validate=True)
        except ValueError:
            raise ValueError("IPA trust anchor is not canonical base64 DER") from None
        digest = hashlib.sha256(der).hexdigest()
        if (
            not 1 <= len(der) <= MAX_ANCHOR_BYTES
            or der[0] != 0x30
            or base64.b64encode(der).decode() != anchor["der_base64"]
            or digest != anchor["sha256"]
            or digest in seen
        ):
            raise ValueError("IPA trust anchor digest/DER binding or budget invalid")
        seen.add(digest)
        normalized["anchors"].append({"der_base64": anchor["der_base64"], "sha256": digest})
    normalized["anchors"].sort(key=lambda item: item["sha256"])
    if "verification_time" in value:
        when = value["verification_time"]
        if type(when) is not int or not 0 <= when <= 253402300799:
            raise ValueError("IPA verification time must be a bounded epoch integer")
        normalized["verification_time"] = when
    digest = hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if "policy_sha256" in value and value["policy_sha256"] != digest:
        raise ValueError("IPA trust policy digest mismatch")
    normalized["policy_sha256"] = digest
    return normalized


def trust_policy_summary(policy: dict) -> dict:
    return {
        "policy_sha256": policy["policy_sha256"],
        "anchor_sha256": [anchor["sha256"] for anchor in policy["anchors"]],
        "verification_time": policy.get("verification_time", "current-time"),
        "purpose": "cryptographic-chain-only",
        "revocation": "not-checked",
        "apple_identity_policy": "unsupported",
    }


def pinned_apple_anchors(policy: dict) -> list[dict]:
    return [anchor for anchor in policy["anchors"] if anchor["sha256"] in APPLE_ROOT_SHA256]
