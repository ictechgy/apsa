from __future__ import annotations

import json
import os
import signal
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .input_snapshot import identity, stage_input
from .processes import CommandFailure, command

PARSER_TIMEOUT = 90
MAX_RESULT = 32 * 1024 * 1024
PARSER_COVERAGE_STATES = frozenset({"checked", "partial", "not-run", "not-applicable"})


def _string_list(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _dependency(value: object) -> bool:
    if not isinstance(value, dict) or any(
        not isinstance(value.get(key), str) for key in ("ecosystem", "name", "version")
    ):
        return False
    if any(key in value and not isinstance(value[key], str) for key in ("path", "confidence")):
        return False
    for key in ("resolution", "osv_query"):
        metadata = value.get(key)
        if metadata is not None and (
            not isinstance(metadata, dict)
            or ("state" in metadata and not isinstance(metadata["state"], str))
            or ("checked" in metadata and not isinstance(metadata["checked"], bool))
        ):
            return False
    return True


def _worker_schema(result: dict) -> bool:
    """Required worker fields used by scan, refresh and report exports.

    Findings and extra metadata remain extensible. Coverage states must match
    the producers and completeness consumers, which cannot assess other states.
    """
    inventory, findings, coverage = (result.get(key) for key in ("inventory", "findings", "coverage"))
    if (
        not isinstance(inventory, dict)
        or not _string_list(inventory.get("warnings"))
        or not _string_list(inventory.get("platforms"))
        or not isinstance(inventory.get("fingerprint"), str)
        or not isinstance(inventory.get("partial"), bool)
        or not isinstance(inventory.get("fingerprint_complete"), bool)
        or not isinstance(inventory.get("dependencies"), list)
        or any(not _dependency(dep) for dep in inventory["dependencies"])
        or not isinstance(findings, list)
        or not isinstance(coverage, list)
    ):
        return False
    for item in findings:
        if (
            not isinstance(item, dict)
            or any(
                not isinstance(item.get(key), str)
                for key in ("id", "rule_id", "title", "severity", "status", "masvs", "remediation")
            )
            or not _string_list(item.get("references"))
            or not isinstance(item.get("evidence"), list)
            or any(not isinstance(entry, dict) for entry in item["evidence"])
            or ("maswe" in item and not _string_list(item["maswe"]))
        ):
            return False
    for check in coverage:
        if (
            not isinstance(check, dict)
            or any(not isinstance(check.get(key), str) for key in ("rule_id", "state"))
            or check["state"] not in PARSER_COVERAGE_STATES
            or (check.get("dependency") is not None and not _dependency(check["dependency"]))
        ):
            return False
    return True


@contextmanager
def parser_lease(directory: Path | None = None):
    if os.name != "posix":
        raise ValueError("Bounded parser execution currently supports macOS and Linux hosts")
    import fcntl

    directory = directory or (
        Path(os.environ["APSA_PARSER_LOCK_DIR"])
        if os.environ.get("APSA_PARSER_LOCK_DIR")
        else Path.home() / ".cache/mobile-audit/parser-locks"
    )
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = None
    for index in range(2):
        candidate = os.open(directory / f"{index}.lock", os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(candidate, fcntl.LOCK_EX | fcntl.LOCK_NB)
            descriptor = candidate
            break
        except BlockingIOError:
            os.close(candidate)
        except BaseException:
            os.close(candidate)
            raise
    if descriptor is None:
        raise ValueError("Two parsers are already active; wait for another audit to finish")
    try:
        yield
    finally:
        os.close(descriptor)


def analyze_target(
    target: Path,
    sbom: Path | None = None,
    expected_target: Path | None = None,
    configuration: str | None = None,
    *,
    report_home: Path | None = None,
    specs: dict | None = None,
    dependency_selection: dict | None = None,
    apk_set_device: dict | None = None,
    ipa_trust_policy: dict | None = None,
) -> dict:
    caller_bound = expected_target is not None
    resolved = target.expanduser().resolve()
    expected_target = expected_target or resolved
    if resolved != expected_target:
        raise ValueError("Authorized input moved or became a symlink; audit refused")
    if not resolved.exists():
        raise ValueError(f"Input not found: {resolved}")
    from .run_options import artifact_options

    apk_set_device, ipa_trust_policy = artifact_options(resolved, apk_set_device, ipa_trust_policy)
    sbom = (sbom if caller_bound else sbom.expanduser().resolve()) if sbom else None
    with parser_lease(), tempfile.TemporaryDirectory(prefix="mobile-audit-work-") as directory:
        root = Path(directory).resolve()
        scratch = root / "work"
        scratch.mkdir()
        staged = root / "input" / resolved.name
        hidden = (Path.home() / ".local/share/mobile-audit",) + (
            (report_home.resolve(),) if report_home else ()
        )
        snapshot = stage_input(resolved, staged, hidden=hidden)
        staged_sbom = root / "sbom" / "sbom.json" if sbom else None
        if sbom and staged_sbom:
            stage_input(sbom, staged_sbom, source=False)
        from .hybrid_observations import PROTOCOL
        from .hybrid_observations import write as write_hybrid_observations

        write_hybrid_observations(scratch, snapshot)
        args = [
            sys.executable,
            "-I",
            "-B",
            "-m",
            "mobile_audit._parser_worker",
            str(staged),
            str(staged_sbom) if staged_sbom else "",
            str(staged),
            str(scratch),
            configuration or "",
            # Notes are for people; the parser needs only names, kinds and the file hash.
            json.dumps(
                {
                    **specs,
                    "source": [{k: v for k, v in e.items() if k != "note"} for e in specs["source"]],
                    "sink": [{k: v for k, v in e.items() if k != "note"} for e in specs["sink"]],
                },
                sort_keys=True,
            )
            if specs
            else "",
            json.dumps(dependency_selection, sort_keys=True) if dependency_selection else "",
            json.dumps(apk_set_device, sort_keys=True) if apk_set_device is not None else "",
            json.dumps(ipa_trust_policy, sort_keys=True) if ipa_trust_policy is not None else "",
            PROTOCOL,
        ]
        from .parser_sandbox import activate, sandbox_command

        wrapped, isolation = sandbox_command(args, staged, staged_sbom, scratch, report_home=report_home)
        wrapped, isolation = activate(wrapped, args, isolation, scratch)
        try:
            raw = command(
                wrapped,
                timeout=PARSER_TIMEOUT,
                max_bytes=MAX_RESULT,
                max_rss=1024 * 1024 * 1024,
                cwd=scratch,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(scratch)},
            )
        except ValueError as error:
            if (
                isinstance(error, CommandFailure)
                and hasattr(signal, "SIGXCPU")
                and error.returncode == -signal.SIGXCPU
            ):
                raise ValueError(
                    "Parser exceeded CPU time limit (SIGXCPU); audit incomplete. The audit was not retried."
                ) from None
            if isolation["state"] == "enforced" and str(error).startswith("Command failed"):
                raise ValueError(
                    f"Sandboxed parser failed under {isolation['backend']}; the audit was not retried "
                    f"without OS isolation. {error} If the backend is incompatible with this host, "
                    "APSA_PARSER_SANDBOX=off runs with resource limits only."
                ) from None
            raise
        if resolved.resolve() != expected_target or identity(resolved) != snapshot["identity"]:
            raise ValueError("Authorized input moved or became a symlink; audit refused")
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise ValueError("Parser worker returned invalid output; audit incomplete") from None
    if not isinstance(result, dict):
        raise ValueError("Parser worker returned an invalid schema; audit incomplete")
    if "error" in result:
        if not isinstance(result["error"], str) or not result["error"]:
            raise ValueError("Parser worker returned an invalid schema; audit incomplete")
        raise ValueError(result["error"])
    if not _worker_schema(result):
        raise ValueError("Parser worker returned an invalid schema; audit incomplete")
    result["inventory"]["parser_isolation"] = isolation
    if isolation.get("activation_probe") == "failed":
        result["inventory"]["warnings"].append(
            f"Parser OS isolation unavailable; parsed with resource limits only: {isolation['unavailable_reason']}"
        )
    result["inventory"]["target"] = str(resolved)
    result["inventory"]["input_snapshot"] = {
        "kind": "parent-staged-descriptor-safe",
        "files": snapshot["files"],
        "bytes": snapshot["bytes"],
        "partial": bool(snapshot["warnings"]),
        # Files left out when the tree exceeded the staging budgets, by kind (staged in that order).
        "omitted": snapshot.get("omitted", {}),
        "omitted_by_module": snapshot.get("omitted_by_module", {}),
        "omitted_module_groups": snapshot.get("omitted_module_groups", 0),
        "omitted_by_module_truncated": snapshot.get("omitted_by_module_truncated", False),
        "omitted_other_modules": snapshot.get("omitted_other_modules", {}),
        "app_scope_complete": snapshot.get("app_scope_complete", True),
        "hybrid_input_inventory_complete": snapshot.get("hybrid_input_inventory_complete", True),
        "hybrid_inputs_truncated": snapshot.get("hybrid_inputs_truncated", False),
    }
    if snapshot["warnings"]:
        result["inventory"]["warnings"].extend(snapshot["warnings"])
        result["inventory"]["partial"] = True
        result["inventory"]["fingerprint_complete"] = False
        credential_metadata = result["inventory"].get("credential_text")
        if isinstance(credential_metadata, dict):
            # The worker's observed counts cannot enumerate unstaged members.
            credential_metadata["partial"] = True
            credential_metadata["staging_incomplete"] = True
        # The worker saw only staged files. A skipped ancestor or import can
        # invalidate interpolation even when its remaining literal looks exact.
        # Withdraw that derived provenance before the caller correlates versions;
        # directly observed literals and lockfile coordinates remain evidence.
        for dependency in result["inventory"]["dependencies"]:
            expression = dependency.get("version_expression")
            if (
                dependency.get("version_interpolation")
                and isinstance(expression, str)
                and expression
                and isinstance(dependency.get("version_source"), dict)
            ):
                dependency["version"] = expression
                dependency["confidence"] = "unknown"
                dependency.pop("version_source", None)
                dependency.pop("resolution", None)
        # Without all app code and configuration, a rule may only look not-applicable
        # (for example, the platform's sources were left out).
        downgraded = {"checked"} | (set() if snapshot.get("app_scope_complete", True) else {"not-applicable"})
        for check in result.get("coverage", []):
            if check["state"] in downgraded:
                check["state"] = "partial"
    return result
