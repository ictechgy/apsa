"""Bounded detached CMS and explicit-anchor chain checks; Apple signer policy is separate."""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

from .apple_trust import (
    APPLE_ROOT_PIN_SOURCE,
    pinned_apple_anchors,
    trust_policy_summary,
    validate_trust_policy,
)
from .processes import command

MAX_CMS_BYTES = 4 * 1024 * 1024
MAX_DER_NODES = 20_000
MAX_DER_DEPTH = 32
SIGNED_DATA_OID = bytes.fromhex("2a864886f70d010702")
DATA_OID = bytes.fromhex("2a864886f70d010701")


@dataclass(frozen=True)
class _CMSNode:
    tag: int
    body: memoryview
    children: tuple[_CMSNode, ...] = ()


def _cms_nodes(raw: bytes) -> tuple[_CMSNode, ...]:
    """Parse once under shared budgets; retain original signed bytes without conversion.

    Native Apple signatures use BER constructed indefinite lengths. Only those
    lengths are accepted: primitive indefinite values and misplaced EOCs fail
    closed, and definite lengths retain the existing canonical-length checks.
    Views avoid copying a large body once per nested constructed value.
    """
    if len(raw) > MAX_CMS_BYTES:
        raise ValueError("CMS byte budget exceeded")
    view = memoryview(raw)
    remaining = MAX_DER_NODES

    def parse(start: int, end: int, depth: int, indefinite: bool = False):
        nonlocal remaining
        if depth > MAX_DER_DEPTH:
            raise ValueError("CMS depth budget exceeded")
        nodes = []
        cursor = start
        while cursor < end:
            if cursor + 2 > end:
                raise ValueError("Truncated CMS header")
            tag, size = view[cursor], view[cursor + 1]
            if tag == 0:
                if size == 0 and indefinite:
                    return tuple(nodes), cursor + 2
                raise ValueError("Unexpected or malformed CMS end-of-contents")
            remaining -= 1
            if remaining < 0:
                raise ValueError("CMS node budget exceeded")
            if tag & 31 == 31:
                raise ValueError("Unsupported CMS tag")
            cursor += 2
            if size == 0x80:
                if not tag & 32:
                    raise ValueError("Primitive indefinite CMS length")
                body_start = cursor
                children, cursor = parse(cursor, end, depth + 1, True)
                nodes.append(_CMSNode(tag, view[body_start : cursor - 2], children))
                continue
            if size & 128:
                width = size & 127
                if not 1 <= width <= 4 or cursor + width > end or view[cursor] == 0:
                    raise ValueError("Invalid CMS definite length")
                size = int.from_bytes(view[cursor : cursor + width], "big")
                cursor += width
                if size < 128:
                    raise ValueError("Noncanonical CMS definite length")
            value_end = cursor + size
            if value_end > end:
                raise ValueError("Truncated CMS value")
            children = ()
            if tag & 32:
                children, _ = parse(cursor, value_end, depth + 1)
            nodes.append(_CMSNode(tag, view[cursor:value_end], children))
            cursor = value_end
        if indefinite:
            raise ValueError("Missing CMS end-of-contents")
        return tuple(nodes), cursor

    return parse(0, len(raw), 0)[0]


def _detached_signed_data(raw: bytes) -> None:
    outer = _cms_nodes(raw)
    if len(outer) != 1 or outer[0].tag != 0x30:
        raise ValueError("CMS ContentInfo must be one sequence")
    info = outer[0].children
    if len(info) != 2 or info[0].tag != 6 or info[0].body != SIGNED_DATA_OID or info[1].tag != 0xA0:
        raise ValueError("CMS content is not SignedData")
    wrapped = info[1].children
    if len(wrapped) != 1 or wrapped[0].tag != 0x30:
        raise ValueError("Invalid CMS SignedData wrapper")
    signed = wrapped[0].children
    if len(signed) < 4 or signed[0].tag != 2 or signed[1].tag != 0x31 or signed[2].tag != 0x30:
        raise ValueError("Invalid CMS SignedData fields")
    content = signed[2].children
    if len(content) != 1 or content[0].tag != 6 or content[0].body != DATA_OID:
        raise ValueError("Only detached CMS data content is supported")
    if signed[-1].tag != 0x31 or not signed[-1].body:
        raise ValueError("CMS contains no signer")
    if any(node.tag not in {0xA0, 0xA1} for node in signed[3:-1]):
        raise ValueError("Unsupported CMS SignedData fields")


def verify_cms_code_directory(
    cms_der: bytes, primary_directory: bytes, trust_policy: dict | None = None
) -> dict:
    result = {
        "state": "not-run",
        "cryptographic_signature_verified": False,
        "chain_trust": "unverified",
        "certificate_chain_verified": False,
        "explicit_anchor_chain_verified": False,
        "certificate_chain_verified_alias": "explicit_anchor_chain_verified",
        "chain_scope": "explicit-anchor-cryptographic-chain-only",
        "chain_anchor_origin": "none",
        "verification_time_basis": "not-run",
        "apple_critical_extensions_verified": False,
        "signer_purpose_policy_verified": False,
        "revocation_checked": False,
        "apple_signer_trust": "unverified",
        "apple_root_anchor_trust": "unverified",
        "apple_root_anchor_chain_verified": False,
        "app_authenticity_verified": False,
        "method": "detached-cms-exact-primary-codedirectory",
    }
    policy = None
    if trust_policy is not None:
        try:
            policy = validate_trust_policy(trust_policy)
            result["trust_policy"] = trust_policy_summary(policy)
            result["chain_anchor_origin"] = "explicit-policy-anchors"
            result["verification_time_basis"] = result["trust_policy"]["verification_time_basis"]
            result["verification_time"] = result["trust_policy"]["verification_time"]
        except ValueError:
            result["chain_trust"] = "unsupported-policy"
            result["chain_anchor_origin"] = "unsupported-policy"
    if not cms_der or not primary_directory:
        return {**result, "reason": "CMS signature or primary CodeDirectory absent"}
    if len(cms_der) > MAX_CMS_BYTES or len(primary_directory) > MAX_CMS_BYTES:
        return {**result, "state": "unsupported", "reason": "CMS/CodeDirectory byte budget exceeded"}
    if len(primary_directory) < 44 or struct.unpack_from(">II", primary_directory) != (
        0xFADE0C02,
        len(primary_directory),
    ):
        return {**result, "state": "unsupported", "reason": "Malformed primary CodeDirectory"}
    try:
        _detached_signed_data(cms_der)
    except ValueError:
        return {
            **result,
            "state": "unsupported",
            "reason": "Malformed, unsigned or unsupported detached CMS structure",
        }
    result["signed_content_sha256"] = hashlib.sha256(primary_directory).hexdigest()
    try:
        with TemporaryDirectory(prefix="apsa-cms-") as temporary:
            scratch = Path(temporary)
            signature = scratch / "signature.der"
            directory = scratch / "directory.bin"
            signature.write_bytes(cms_der)
            directory.write_bytes(primary_directory)
            verifier_env = {"PATH": "/usr/bin:/bin", "OPENSSL_CONF": "/dev/null", "TMPDIR": str(scratch)}
            try:
                command(
                    [
                        "/usr/bin/openssl",
                        "cms",
                        "-cmsout",
                        "-inform",
                        "DER",
                        "-in",
                        str(signature),
                        "-outform",
                        "DER",
                    ],
                    timeout=5,
                    max_bytes=MAX_CMS_BYTES,
                    cwd=scratch,
                    env=verifier_env,
                )
            except (OSError, ValueError):
                return {
                    **result,
                    "state": "not-run",
                    "reason": "CMS verifier unavailable, denied or structure unsupported by host tool",
                }
            output = command(
                [
                    "/usr/bin/openssl",
                    "cms",
                    "-verify",
                    "-binary",
                    "-inform",
                    "DER",
                    "-in",
                    str(signature),
                    "-content",
                    str(directory),
                    "-noverify",
                ],
                timeout=10,
                max_bytes=MAX_CMS_BYTES,
                cwd=scratch,
                env=verifier_env,
            )
            if output != primary_directory:
                return {
                    **result,
                    "state": "invalid",
                    "reason": "Verified CMS content differs from primary CodeDirectory",
                }
            if policy is not None:
                result.update(
                    _verify_chain(policy, signature, directory, primary_directory, scratch, verifier_env)
                )
                result["explicit_anchor_chain_verified"] = result["certificate_chain_verified"]
                apple_anchors = pinned_apple_anchors(policy)
                if apple_anchors:
                    apple_chain = _verify_chain(
                        {**policy, "anchors": apple_anchors},
                        signature,
                        directory,
                        primary_directory,
                        scratch,
                        verifier_env,
                    )
                    verified = apple_chain["certificate_chain_verified"]
                    result["apple_root_anchor_chain_verified"] = verified
                    result["apple_root_anchor_trust"] = (
                        "verified-pinned-root-chain-only" if verified else apple_chain["chain_trust"]
                    )
                    result["apple_root_pin_source"] = APPLE_ROOT_PIN_SOURCE
    except (OSError, ValueError) as error:
        # Neither stderr nor content/identity from attacker-controlled CMS is logged.
        missing = not os.path.isfile("/usr/bin/openssl")
        failed = isinstance(error, ValueError) and str(error).startswith("Command failed")
        return {
            **result,
            "state": "invalid" if failed and not missing else "not-run",
            "reason": "CMS content/signature verification failed"
            if failed and not missing
            else "CMS verifier unavailable, denied or over budget",
        }
    return {
        **result,
        "state": "verified",
        "cryptographic_signature_verified": True,
        "reason": "Detached CMS verifies exact primary CodeDirectory; explicit-anchor chain is separately reported. "
        "Apple identity, signer-purpose policy, revocation and app authenticity remain unverified",
    }


def _verify_chain(
    policy: dict, signature: Path, directory: Path, content: bytes, scratch: Path, env: dict[str, str]
) -> dict:
    """Explicit CAfile/empty CApath replace host stores; no AIA/network lookup."""
    try:
        empty = scratch / "empty-ca"
        empty.mkdir(exist_ok=True)
        ca = scratch / "anchors.pem"
        certificates = []
        for index, anchor in enumerate(policy["anchors"]):
            der = base64.b64decode(anchor["der_base64"], validate=True)
            source = scratch / f"anchor-{index}.der"
            source.write_bytes(der)
            # Require exact canonical X.509, rejecting concatenation/trailing data.
            canonical = command(
                ["/usr/bin/openssl", "x509", "-inform", "DER", "-in", str(source), "-outform", "DER"],
                timeout=5,
                max_bytes=8192,
                cwd=scratch,
                env=env,
            )
            if canonical != der:
                return {"chain_trust": "unsupported-anchor", "certificate_chain_verified": False}
            encoded = base64.b64encode(der).decode()
            certificates.append(
                "-----BEGIN CERTIFICATE-----\n"
                + "\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))
                + "\n-----END CERTIFICATE-----\n"
            )
        ca.write_text("".join(certificates), encoding="ascii")
        chain_env = {**env, "SSL_CERT_FILE": str(ca), "SSL_CERT_DIR": str(empty)}
        argv = [
            "/usr/bin/openssl",
            "cms",
            "-verify",
            "-binary",
            "-inform",
            "DER",
            "-in",
            str(signature),
            "-content",
            str(directory),
            "-CAfile",
            str(ca),
            "-CApath",
            str(empty),
            "-purpose",
            "any",
            "-verify_depth",
            "8",
        ]
        if "verification_time" in policy:
            argv.extend(["-attime", str(policy["verification_time"])])
        output = command(argv, timeout=10, max_bytes=MAX_CMS_BYTES, cwd=scratch, env=chain_env)
        return {
            "chain_trust": "verified-explicit-anchor" if output == content else "invalid",
            "certificate_chain_verified": output == content,
        }
    except (OSError, ValueError) as error:
        failed = isinstance(error, ValueError) and str(error).startswith("Command failed")
        return {
            "chain_trust": "invalid-or-unsupported" if failed else "not-run",
            "certificate_chain_verified": False,
        }
