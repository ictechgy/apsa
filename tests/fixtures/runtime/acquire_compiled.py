"""Acquire fresh compiled fixtures; persist only recorder observation digests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mobile_audit.runtime_acquisition import AcquisitionRecorder, evaluate_backend_invalidation
from mobile_audit.runtime_compiled import CompiledSyntheticAdapter, FreshIosSimulatorAdapter
from mobile_audit.runtime_evidence import build_binding, evaluate_workflow
from tests.test_runtime_evidence import scenario


def execute(root: Path, platform: str, kind: str, simulator: bool) -> dict:
    value = scenario(platform, kind)
    for account in value["workflow"]["accounts"].values():
        account.update(canary_surface="storage", login_surface="storage")
    value["workflow"]["transitions"][0]["surface"] = "storage"
    adapter_type = FreshIosSimulatorAdapter if simulator else CompiledSyntheticAdapter
    adapter = adapter_type(value, root)
    try:
        binding = build_binding(platform, value["package"], adapter.environment()["app"])
        start_session = adapter.start_session

        def checked_session(binding, nonce):
            try:
                return start_session(binding, nonce)
            except ValueError as error:
                # All adapter errors are bounded source-defined messages, never response bodies.
                (root / "session-error.json").write_text(json.dumps({"error": str(error)}) + "\n")
                raise

        adapter.start_session = checked_session
        recorder = AcquisitionRecorder(adapter, binding, value["markers"])
        binding = recorder.binding
        if recorder.session is None:
            raise ValueError("Fresh fixture recorder session did not bind")
        transition = value["workflow"]["transitions"][0]
        account = transition["from_account"]
        before = recorder.capture(
            "before", {"account": account, "state": "authenticated" if account else "logged_out"}, None
        )
        adapter.open_url("synthetic://transition")
        account = transition["to_account"]
        after = recorder.capture(
            "after", {"account": account, "state": "authenticated" if account else "logged_out"}, kind
        )
        binding = recorder.binding
        snapshots = {"before": before, "after": after}
        result = {
            "platform": platform,
            "kind": kind,
            "binding": binding,
            "manifest": adapter.manifest,
            "snapshots": snapshots,
            "workflow": evaluate_workflow(value, snapshots, binding),
            "backend_invalidation": evaluate_backend_invalidation(value, snapshots),
            "external_proof": {"physical_device": "unmeasured", "backend_HTTP": "unmeasured"},
        }
        (root / "recorder-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
        return {
            "platform": platform,
            "kind": kind,
            "workflow": result["workflow"][0]["state"],
            "mode": recorder.metadata()["mode"],
            "path": str(root / "recorder-evidence.json"),
        }
    finally:
        cleanup = adapter.close()
        (root / "cleanup.json").write_text(json.dumps(cleanup, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--simulator", action="store_true")
    arguments = parser.parse_args()
    arguments.out.mkdir(parents=True, exist_ok=False)
    platforms = ("ios",) if arguments.simulator else ("android", "ios")
    summary = []
    for platform in platforms:
        for kind in ("login", "account_switch", "logout"):
            outcome = execute(arguments.out / (platform + "-" + kind), platform, kind, arguments.simulator)
            summary.append(outcome)
            print(json.dumps(outcome), flush=True)
    (arguments.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
