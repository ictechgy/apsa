"""Portable, explicitly approved baseline artifacts with externally pinned integrity."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .core import MAX_FILE, canonical_json, digest, now, read_bounded, report_incomplete
from .output import assistant_finding


def baseline_artifact(report: dict, approved_by: str, approval_reference: str) -> dict:
    if not approved_by.strip() or not approval_reference.strip():
        raise ValueError("Baseline export requires an explicit approver and approval reference")
    if len(approved_by) > 256 or len(approval_reference) > 2048:
        raise ValueError("Baseline approval metadata is too long")
    if report_incomplete(report) or not report["inventory"].get("fingerprint_complete", False):
        raise ValueError("An incomplete audit cannot be exported as an approved baseline")
    identities = {
        (a["platform"], a["package"]) for a in report["inventory"].get("apps", []) if a.get("package")
    }
    if len(identities) != 1:
        raise ValueError(
            "Baseline export requires one explicit app identity; select a source configuration or supply a build"
        )
    body = {k: report[k] for k in ("schema_version", "id", "target", "created", "coverage")}
    body["inventory"] = {
        k: report["inventory"][k]
        for k in ("apps", "platforms", "package", "fingerprint", "fingerprint_complete", "source_selection")
        if k in report["inventory"]
    }
    body["findings"] = [assistant_finding(f) for f in report["findings"]]
    artifact = {
        "schema_version": 1,
        "kind": "apsa-baseline",
        "report": body,
        "report_sha256": digest(canonical_json(body).encode()),
        "approval": {"approved_by": approved_by, "reference": approval_reference, "recorded_at": now()},
    }
    if len((json.dumps(artifact, ensure_ascii=False, indent=2) + "\n").encode()) > MAX_FILE:
        raise ValueError("Portable baseline exceeds the file size limit")
    return artifact


def load_baseline(path: Path, expected_sha256: str, *, authorized=False) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256 or ""):
        raise ValueError("Baseline files require an externally approved --baseline-sha256")
    raw = read_bounded(path if authorized else path.expanduser().resolve())
    if digest(raw) != expected_sha256:
        raise ValueError("Baseline artifact does not match the approved SHA-256")
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != 1
        or value.get("kind") != "apsa-baseline"
    ):
        raise ValueError("Unsupported baseline artifact schema")
    body, approval = value.get("report"), value.get("approval")
    if not isinstance(body, dict) or value.get("report_sha256") != digest(canonical_json(body).encode()):
        raise ValueError("Baseline report integrity check failed")
    if not isinstance(approval, dict) or not all(
        isinstance(approval.get(k), str) and approval[k].strip()
        for k in ("approved_by", "reference", "recorded_at")
    ):
        raise ValueError("Baseline approval provenance is missing")
    if (
        body.get("schema_version") != 2
        or not isinstance(body.get("inventory"), dict)
        or body["inventory"].get("fingerprint_complete") is not True
        or not isinstance(body.get("findings"), list)
        or not all(isinstance(item, dict) for item in body["findings"])
        or not isinstance(body.get("coverage"), list)
        or not all(isinstance(item, dict) for item in body["coverage"])
        or not isinstance(body.get("id"), str)
        or not isinstance(body.get("target"), str)
    ):
        raise ValueError("Baseline report is unsupported or incomplete")
    identities = {
        (app.get("platform"), app.get("package"))
        for app in body["inventory"].get("apps", [])
        if isinstance(app, dict) and isinstance(app.get("package"), str) and app["package"]
    }
    if len(identities) != 1 or report_incomplete(body):
        raise ValueError("Baseline requires one complete app identity")
    body["baseline_provenance"] = {"artifact_sha256": expected_sha256, "approval": approval}
    return body
