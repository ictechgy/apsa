"""Bounded authenticated workflow and operator observation contracts.

Operator observations contain labels and digests only. They are untrusted manual
corroboration, never acquisition proof or backend session-invalidation evidence.
"""

from __future__ import annotations

import copy
import re

from .core import canonical_json, digest

LABEL = re.compile(r"[A-Za-z0-9_-]{1,60}")
HASH = re.compile(r"[a-f0-9]{64}")
BUILD_FIELDS = {
    "version",
    "version_code",
    "apk_sha256",
    "executable_sha256",
    "info_plist_sha256",
    "runtime_model_sha256",
}
HASH_FIELDS = {"apk_sha256", "executable_sha256", "info_plist_sha256", "runtime_model_sha256"}
SURFACES = {"storage", "ui", "logs", "network", "artifact"}


def _named(value, names) -> bool:
    return isinstance(value, str) and value in names


def _exact(value: dict, required: set[str], optional: set[str] | None = None) -> None:
    if (
        not isinstance(value, dict)
        or not required <= value.keys()
        or value.keys() - required - (optional or set())
    ):
        raise ValueError("Evidence object has missing or unsupported fields")


def validate_build(build: dict) -> dict:
    if (
        not isinstance(build, dict)
        or build.keys() - BUILD_FIELDS
        or any(
            not isinstance(v, str) or not 1 <= len(v) <= 200 or (k in HASH_FIELDS and not HASH.fullmatch(v))
            for k, v in build.items()
        )
    ):
        raise ValueError("Build binding needs allowlisted string versions or SHA-256 digests")
    return build


def build_binding(platform: str, package: str, app: dict, *, allow_synthetic_model: bool = False) -> dict:
    build = {k: str(v) for k, v in app.items() if k in BUILD_FIELDS and v}
    validate_build(build)
    strong = bool(build.get("apk_sha256") if platform == "android" else build.get("executable_sha256"))
    # Only a validated constructor-injected synthetic session opts in. Normal
    # runtime metadata and operator declarations never promote a model hash.
    strong = strong or (allow_synthetic_model is True and bool(build.get("runtime_model_sha256")))
    bound = {"platform": platform, "package": package, "build": build}
    return {
        **bound,
        "identity": digest(canonical_json(bound).encode()),
        "state": "bound" if strong else "unavailable",
    }


def validate_workflow(scenario: dict, labels: dict[str, int]) -> None:
    workflow = scenario.get("workflow")
    if workflow is None:
        if "workflow" in scenario or scenario.get("schema_version", 1) == 2:
            raise ValueError("Version 2 scenarios require an authenticated workflow")
        return
    _exact(workflow, {"accounts", "transitions"})
    accounts = workflow["accounts"]
    markers = scenario["markers"]
    if not isinstance(accounts, dict) or not 1 <= len(accounts) <= 10:
        raise ValueError("Workflow needs 1–10 synthetic account labels")
    used = []
    for label, account in accounts.items():
        if not isinstance(label, str) or not LABEL.fullmatch(label):
            raise ValueError("Workflow account labels must be simple identifiers")
        _exact(account, {"canary", "login_marker"}, {"canary_surface", "login_surface"})
        if any(not _named(account[k], markers) for k in ("canary", "login_marker")):
            raise ValueError("Account canary and login marker must name declared markers")
        if any(
            not _named(account.get(k, default), SURFACES)
            for k, default in (("canary_surface", "storage"), ("login_surface", "ui"))
        ):
            raise ValueError("Account marker surface is unsupported")
        used.extend([account["canary"], account["login_marker"]])
    if len(set(used)) != len(used):
        raise ValueError("Each account must have distinct canary and login markers")
    transitions = workflow["transitions"]
    if not isinstance(transitions, list) or not 1 <= len(transitions) <= 30:
        raise ValueError("Workflow needs 1–30 authenticated transitions")
    states = {}
    for transition in transitions:
        _exact(
            transition,
            {"kind", "baseline", "snapshot", "from_account", "to_account", "state_marker", "delivery_marker"},
            {"surface", "baseline_marker"},
        )
        kind, before, after = transition["kind"], transition["from_account"], transition["to_account"]
        if not _named(kind, {"login", "account_switch", "logout"}) or any(
            a is not None and not _named(a, accounts) for a in (before, after)
        ):
            raise ValueError("Unsupported transition kind or account")
        if not (
            (kind == "login" and before is None and after is not None)
            or (kind == "logout" and before is not None and after is None)
            or (kind == "account_switch" and before is not None and after is not None and before != after)
        ):
            raise ValueError("Transition account states do not match its kind")
        if (
            not _named(transition["baseline"], labels)
            or not _named(transition["snapshot"], labels)
            or labels[transition["baseline"]] >= labels[transition["snapshot"]]
        ):
            raise ValueError("Workflow baseline must precede its after snapshot")
        required = ["state_marker", "delivery_marker"] + (["baseline_marker"] if before is None else [])
        if "baseline_marker" in transition and not _named(transition["baseline_marker"], markers):
            raise ValueError("Baseline state marker must name a declared marker")
        if (
            any(not _named(transition.get(k), markers) for k in required)
            or transition["state_marker"] == transition["delivery_marker"]
        ):
            raise ValueError(
                "Transitions need distinct state/delivery markers and a logged-out baseline marker for login"
            )
        if any(transition[k] in used for k in ("state_marker", "delivery_marker")):
            raise ValueError("Transition state and delivery markers must differ from account markers")
        if not _named(transition.get("surface", "ui"), SURFACES):
            raise ValueError("Transition marker surface is unsupported")
        for snapshot, account in ((transition["baseline"], before), (transition["snapshot"], after)):
            state = {"account": account, "state": "authenticated" if account else "logged_out"}
            if snapshot in states and states[snapshot] != state:
                raise ValueError("Shared workflow snapshots must retain identical account states")
            states[snapshot] = state


def workflow_states(scenario: dict) -> dict:
    states = {}
    for t in scenario.get("workflow", {}).get("transitions", []):
        for label, account in ((t["baseline"], t["from_account"]), (t["snapshot"], t["to_account"])):
            states[label] = {"account": account, "state": "authenticated" if account else "logged_out"}
    return states


def validate_operator_captures(scenario: dict, labels: dict[str, int]) -> None:
    captures = scenario.get("operator_captures", [])
    if not isinstance(captures, list) or len(captures) > 50:
        raise ValueError("Operator captures must be a list of at most 50 digest-only observations")
    states = workflow_states(scenario)
    seen = set()
    total = 0
    count = 0
    for capture in captures:
        _exact(
            capture,
            {
                "schema_version",
                "snapshot",
                "platform",
                "package",
                "build",
                "account",
                "state",
                "surface",
                "observations",
            },
        )
        if type(capture["schema_version"]) is not int or capture["schema_version"] != 1:
            raise ValueError("Unsupported operator capture schema version")
        if (
            not _named(capture["snapshot"], labels)
            or capture["platform"] != scenario["platform"]
            or capture["package"] != scenario["package"]
        ):
            raise ValueError("Operator capture app/snapshot binding differs from scenario")
        if not _named(capture["surface"], {"network", "artifact"}):
            raise ValueError("Operator capture surface must be network or artifact")
        state = {"account": capture["account"], "state": capture["state"]}
        if states.get(capture["snapshot"]) != state:
            raise ValueError("Operator capture must exactly bind to a workflow account/state")
        validate_build(capture["build"])
        identity = (capture["snapshot"], capture["surface"])
        if identity in seen:
            raise ValueError("Duplicate operator capture snapshot/surface")
        seen.add(identity)
        entries = capture["observations"]
        if not isinstance(entries, list) or len(entries) > 4000:
            raise ValueError("Operator observations exceed the entry limit")
        count += len(entries)
        if count > 4000:
            raise ValueError("Operator observations exceed the total entry limit")
        for entry in entries:
            _exact(entry, {"label", "sha256", "bytes", "marker_labels"})
            if (
                not isinstance(entry["label"], str)
                or not LABEL.fullmatch(entry["label"])
                or not isinstance(entry["sha256"], str)
                or not HASH.fullmatch(entry["sha256"])
            ):
                raise ValueError("Operator observations need simple labels and SHA-256 digests")
            if type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= 64 * 1024 * 1024:
                raise ValueError("Operator observation byte count exceeds limits")
            markers = entry["marker_labels"]
            if (
                not isinstance(markers, list)
                or len(markers) > 30
                or any(not isinstance(m, str) or m not in scenario["markers"] for m in markers)
                or len(set(markers)) != len(markers)
            ):
                raise ValueError("Operator observations must name unique declared marker labels")
            total += entry["bytes"]
        if total > 64 * 1024 * 1024:
            raise ValueError("Operator observations exceed total byte limit")


def attach_operator_captures(scenario: dict, snapshots: dict, binding: dict) -> None:
    for capture in scenario.get("operator_captures", []):
        snap = snapshots.get(capture["snapshot"])
        if snap is None:
            continue
        surface = capture["surface"]
        if snap.get("surfaces", {}).get(surface, {}).get("acquisition") == "adapter-acquired":
            # Manual observations cannot overwrite recorder-produced provenance.
            continue
        if binding["state"] != "bound" or capture["build"] != binding["build"]:
            snap["surfaces"][surface] = {
                "state": "inconclusive",
                "reason": "Operator build binding does not exactly match the observed installed build",
            }
            continue
        snap["surfaces"][surface] = {
            "state": "operator-supplied",
            "files": len(capture["observations"]),
            "acquisition": "unverified",
        }
        for entry in capture["observations"]:
            snap["files"].append(
                {
                    "surface": surface,
                    "path": entry["label"],
                    "sha256": entry["sha256"],
                    "bytes": entry["bytes"],
                    "origin": "operator-supplied",
                }
            )
            snap["matches"].extend(
                {
                    "surface": surface,
                    "path": entry["label"],
                    "marker_label": label,
                    "origin": "operator-supplied",
                }
                for label in entry["marker_labels"]
            )


def _present(snapshot: dict, marker: str, surface: str) -> bool:
    return snapshot.get("surfaces", {}).get(surface, {}).get("state") == "captured" and any(
        m.get("marker_label") == marker
        and m.get("surface") == surface
        and m.get("origin") != "operator-supplied"
        for m in snapshot.get("matches", [])
    )


def evaluate_workflow(scenario: dict, snapshots: dict, binding: dict) -> list[dict]:
    results = []
    accounts = scenario.get("workflow", {}).get("accounts", {})
    for t in scenario.get("workflow", {}).get("transitions", []):
        before, after = snapshots.get(t["baseline"], {}), snapshots.get(t["snapshot"], {})
        missing = []
        if "acquisition" in before or "acquisition" in after:
            before_acq, after_acq = before.get("acquisition", {}), after.get("acquisition", {})
            if (
                before_acq.get("state") != "bound"
                or after_acq.get("state") != "bound"
                or before_acq.get("session_sha256") != after_acq.get("session_sha256")
                or not before_acq.get("capture_sha256")
                or not after_acq.get("capture_sha256")
                or before_acq.get("capture_sha256") == after_acq.get("capture_sha256")
                or after_acq.get("delivery") != "target-observed"
            ):
                missing.append("trusted-session-state-delivery-binding")
        if binding["state"] != "bound" or any(
            s.get("binding", {}).get("identity") != binding["identity"] for s in (before, after)
        ):
            missing.append("app-build-binding")
        for label, snap, account in (
            ("baseline", before, t["from_account"]),
            ("after", after, t["to_account"]),
        ):
            if account is not None:
                a = accounts[account]
                for field, default in (("canary", "storage"), ("login_marker", "ui")):
                    surface = a.get("canary_surface" if field == "canary" else "login_surface", default)
                    if not _present(snap, a[field], surface):
                        missing.append(f"{label}-{field}")
            elif label == "baseline" and not _present(snap, t["baseline_marker"], t.get("surface", "ui")):
                missing.append("baseline-logged-out-marker")
            for other_label, other in accounts.items():
                if other_label == account:
                    continue
                surface = other.get("login_surface", "ui")
                if snap.get("surfaces", {}).get(surface, {}).get("state") != "captured" or _present(
                    snap, other["login_marker"], surface
                ):
                    missing.append(f"{label}-ambiguous-account-state")
        for field in ("state_marker", "delivery_marker"):
            if not _present(after, t[field], t.get("surface", "ui")) or _present(
                before, t[field], t.get("surface", "ui")
            ):
                missing.append(field)
        results.append(
            {
                "transition": copy.deepcopy(t),
                "state": "inconclusive" if missing else "passed",
                "missing_evidence": missing,
                "note": "Observed test markers only; backend session invalidation is not tested.",
            }
        )
    return results


def static_runtime_links(report: dict) -> list[dict]:
    """Trace labels are source evidence, not a claim that runtime confirms that rule."""
    result = []
    for item in report.get("findings", []):
        if item.get("status") == "runtime-confirmed":
            continue
        traces = []
        for evidence in item.get("evidence", []):
            trace = {
                k: copy.deepcopy(evidence[k])
                for k in ("path", "line", "source", "sink", "sink_api", "trace", "source_trace")
                if k in evidence
            }
            if trace:
                traces.append(trace)
        result.append(
            {
                "finding_id": item["id"],
                "rule_id": item["rule_id"],
                "source_traces": traces,
                "runtime_state": "not-observed",
                "note": "Plan linkage only; rule-specific acquisition evidence is required for corroboration.",
            }
        )
    return result
