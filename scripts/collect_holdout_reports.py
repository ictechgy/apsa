"""Retain only truth-derived CI reports; incomplete evaluation is always a failure.

fpfn_eval stores archive hashes in results.json and reports at
work/<truth pair ID>/<side>/scan/report.json. Legacy v3 caught pair errors drop side
metadata; v4 preserves independent side outcomes. Both known paths are checked for partial evidence.
No source archives or other work-directory files are inspected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from pathlib import Path

from mobile_audit.maswe import rule_state
from mobile_audit.rules import rules as rule_catalog
from mobile_audit.verify import COVERAGE_ALIASES

SIDES = ("vulnerable", "fixed")
MAX_PAIRS = 256
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_REPORT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_REPORT_BYTES = 512 * 1024 * 1024
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


@contextmanager
def directory_at(parent: int, parts: tuple[str, ...], *, create: bool = False):
    """Keep each directory open, refusing symlinks even during path replacement."""
    handle = os.dup(parent)
    try:
        for part in parts:
            if create:
                try:
                    os.mkdir(part, dir_fd=handle)
                except FileExistsError:
                    pass
            next_handle = os.open(part, DIRECTORY_FLAGS, dir_fd=handle)
            os.close(handle)
            handle = next_handle
        yield handle
    finally:
        os.close(handle)


@contextmanager
def directory(path: Path, *, create: bool = False, exclusive: bool = False):
    absolute = path.absolute()
    if ".." in absolute.parts or not absolute.name:
        raise ValueError("Directory paths must not contain traversal")
    root = os.open(absolute.anchor, DIRECTORY_FLAGS)
    try:
        with directory_at(root, absolute.parts[1:-1], create=create) as parent:
            if exclusive:
                os.mkdir(absolute.name, dir_fd=parent)
            with directory_at(parent, (absolute.name,), create=create and not exclusive) as handle:
                yield handle
    finally:
        os.close(root)


def read_file(parent: int, name: str, limit: int) -> bytes:
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    with os.fdopen(handle, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("Evidence must be a regular file with one link")
        if metadata.st_size > limit:
            raise ValueError("Evidence exceeds the byte budget")
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Evidence exceeds the byte budget")
        return data


def read_document(path: Path) -> bytes:
    with directory(path.parent) as parent:
        return read_file(parent, path.name, MAX_DOCUMENT_BYTES)


def unique_object(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON keys")
        result[key] = value
    return result


def document(data: bytes) -> dict:
    try:
        value = json.loads(data, object_pairs_hook=unique_object)
    except RecursionError as error:
        raise ValueError("JSON nesting exceeds the parser budget") from error
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def truth_pairs(truth: dict) -> dict[str, dict]:
    pairs = truth.get("pairs")
    if truth.get("schema") not in {"apsa-fpfn-pairs-v1", "apsa-fpfn-pairs-v2"}:
        raise ValueError("Unsupported truth schema")
    if not isinstance(pairs, list) or not 1 <= len(pairs) <= MAX_PAIRS:
        raise ValueError("Invalid truth pair count")
    expected = {}
    for pair in pairs:
        pair_id = pair.get("id") if isinstance(pair, dict) else None
        if not isinstance(pair_id, str) or not ID.fullmatch(pair_id) or pair_id in expected:
            raise ValueError("Invalid or duplicate truth pair ID")
        if not isinstance(pair.get("repository"), str) or not pair["repository"]:
            raise ValueError("Missing truth repository")
        for side in SIDES:
            commit = pair.get(f"{side}_commit")
            if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
                raise ValueError("Invalid truth commit")
        for field in ("expected_rules", "weaknesses"):
            labels = pair.get(field, [])
            if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
                raise ValueError("Invalid truth labels")
        expected[pair_id] = pair
    return expected


def totals(pairs: list[dict], *, v4: bool = False) -> dict:
    scored = [
        pair for pair in pairs if (pair.get("expected_rules") or pair.get("weaknesses")) and "outcome" in pair
    ]
    return {
        "tp": sum(pair["outcome"]["vulnerable"] == "tp" for pair in scored),
        "fn": sum(pair["outcome"]["vulnerable"] == "fn" for pair in scored),
        "fp": sum(pair["outcome"]["fixed"] == "fp" for pair in scored),
        "tn": sum(pair["outcome"]["fixed"] == "tn" for pair in scored),
        "line_level_tp": sum(pair["outcome"].get("vulnerable_line_level", False) for pair in scored),
        "discriminating_tp": sum(pair["outcome"].get("discriminating_tp", False) for pair in scored),
        "errors": sum("error" in pair for pair in pairs),
        "unscored_sides": sum(pair["outcome"][side] == "unscored" for pair in scored for side in SIDES),
        "scored_pairs": sum(
            any(pair["outcome"][side] in {"tp", "fn", "fp", "tn"} for side in SIDES) for pair in scored
        )
        if v4
        else len(scored),
    }


def validate_execution(execution: object, *, successful: bool) -> None:
    if not isinstance(execution, dict) or execution.get("schema") != "apsa-benchmark-scan-execution-v1":
        raise ValueError("Missing or invalid scan execution metadata")
    argv = execution.get("argv")
    elapsed = execution.get("elapsed_seconds")
    if (
        not isinstance(argv, list)
        or not argv
        or any(not isinstance(arg, str) for arg in argv)
        or not isinstance(execution.get("cwd"), str)
        or not isinstance(elapsed, (int, float))
        or isinstance(elapsed, bool)
        or not 0 <= elapsed <= 24 * 60 * 60
        or type(execution.get("timed_out")) is not bool
        or (execution.get("exit_code") is not None and type(execution["exit_code"]) is not int)
    ):
        raise ValueError("Invalid scan execution fields")
    if successful and (execution["timed_out"] or execution.get("exit_code") not in {0, 3, 4}):
        raise ValueError("Failed invocation cannot be a successful side")
    if execution["timed_out"] and execution.get("exit_code") is not None:
        raise ValueError("Timeout cannot claim a completed exit code")
    for stream in ("stdout", "stderr"):
        item = execution.get(stream)
        if (
            not isinstance(item, dict)
            or item.get("path") != stream + ".txt"
            or type(item.get("bytes")) is not int
            or item["bytes"] < 0
            or type(item.get("retained_bytes")) is not int
            or not 0 <= item["retained_bytes"] <= min(item["bytes"], 1024 * 1024)
            or type(item.get("truncated")) is not bool
            or item["truncated"] != (item["retained_bytes"] < item["bytes"])
            or not isinstance(item.get("sha256"), str)
            or not DIGEST.fullmatch(item["sha256"])
        ):
            raise ValueError("Invalid scan stream evidence")


def validate_archive(archive: object, truth: dict, side: str) -> None:
    url = f"https://codeload.github.com/{truth['repository']}/zip/{truth[f'{side}_commit']}"
    if not isinstance(archive, dict) or archive.get("url") != url:
        raise ValueError("Missing or mismatched archive URL")
    digest = archive.get("sha256")
    size = archive.get("bytes")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or type(size) is not int or size < 0:
        raise ValueError("Missing or invalid archive hash/size")


def relevant_rule_ids(pair: dict) -> set[str]:
    """Independently derive execution checks from frozen labels and the catalog."""
    checks = set(pair.get("expected_rules", []))
    if not checks:
        weaknesses = set(pair.get("weaknesses", []))
        checks = {
            rule["id"]
            for rule in rule_catalog()
            if rule.get("mode") in {"source", "ast", "source-pattern", "configuration"}
            and not rule["id"].startswith("QG-")
            and weaknesses & set(rule.get("maswe", []))
        }
    return {COVERAGE_ALIASES.get(check) or check for check in checks}


def checked_labeled_scope(side: dict) -> bool:
    checks = side.get("labeled_rule_states")
    return (
        not side.get("missing_labeled_paths")
        and bool(side.get("labeled_file_states"))
        and all(state == "checked" for state in side["labeled_file_states"].values())
        and isinstance(checks, dict)
        and all(state == "checked" for state in checks.values())
    )


def validate_report_rule_scope(report: dict, pair: dict, side: str) -> None:
    """A summary cannot claim checked rules that the retained report did not run."""
    coverage = report.get("coverage", [])
    if not isinstance(coverage, list) or any(
        not isinstance(row, dict) or not isinstance(row.get("state"), str) for row in coverage
    ):
        raise ValueError("Invalid retained rule coverage")
    observed = {
        rule: rule_state({row["state"] for row in coverage if row.get("rule_id") == rule})
        for rule in relevant_rule_ids(pair)
    }
    if observed != pair[side].get("labeled_rule_states"):
        raise ValueError("Retained rule coverage differs from labeled rule states")


def successful_ids(results: dict, expected: dict[str, dict], truth_sha: str) -> set[str]:
    required = {
        "schema",
        "truth",
        "truth_sha256",
        "amendments_sha256",
        "apsa_commit",
        "worktree_dirty",
        "evaluator_sha256",
        "source_catalog_sha256",
        "source_weaknesses",
        "totals",
        "in_scope_totals",
        "pairs",
    }
    if not required <= results.keys():
        raise ValueError("Missing result provenance or summary fields")
    v4 = results.get("schema") == "apsa-fpfn-results-v4"
    if (
        results.get("schema") not in {"apsa-fpfn-results-v3", "apsa-fpfn-results-v4"}
        or results.get("truth_sha256") != truth_sha
    ):
        raise ValueError("Results schema or frozen truth hash mismatch")
    if not isinstance(results["truth"], str) or not results["truth"]:
        raise ValueError("Missing result truth name")
    for field, pattern in (
        ("apsa_commit", COMMIT),
        ("evaluator_sha256", DIGEST),
        ("source_catalog_sha256", DIGEST),
    ):
        if not isinstance(results[field], str) or not pattern.fullmatch(results[field]):
            raise ValueError("Invalid result provenance hash")
    if results["worktree_dirty"] is not None and type(results["worktree_dirty"]) is not bool:
        raise ValueError("Invalid result worktree status")
    if not isinstance(results["source_weaknesses"], list) or any(
        not isinstance(weakness, str) for weakness in results["source_weaknesses"]
    ):
        raise ValueError("Invalid result source weaknesses")
    if results.get("amendments_sha256") is not None:
        raise ValueError("This collector requires unamended frozen truth")
    pairs = results.get("pairs")
    if not isinstance(pairs, list) or len(pairs) != len(expected):
        raise ValueError("Results do not contain every truth pair")
    observed = set()
    successful = set()
    for pair in pairs:
        pair_id = pair.get("id") if isinstance(pair, dict) else None
        if not isinstance(pair_id, str) or pair_id not in expected or pair_id in observed:
            raise ValueError("Unexpected or duplicate result pair ID")
        observed.add(pair_id)
        if "error" in pair and not v4:
            if set(pair) != {"id", "error"} or not isinstance(pair["error"], str) or not pair["error"]:
                raise ValueError("Malformed pair error")
            continue
        truth = expected[pair_id]
        if pair.get("repository") != truth["repository"] or not isinstance(pair.get("in_scope"), bool):
            raise ValueError("Missing or mismatched successful pair metadata")
        for field in ("expected_rules", "weaknesses"):
            if pair.get(field) != sorted(set(truth.get(field, []))):
                raise ValueError("Result labels differ from frozen truth")
        if v4:
            expected_scope = bool(pair["expected_rules"]) or bool(
                set(pair["weaknesses"]) & set(results["source_weaknesses"])
            )
            if pair["in_scope"] != expected_scope:
                raise ValueError("Incorrect pair scope")
            if "error" in pair and (not isinstance(pair["error"], str) or not pair["error"]):
                raise ValueError("Malformed pair error")
        failed_sides = []
        outcome = pair.get("outcome")
        if not isinstance(outcome, dict):
            raise ValueError("Missing successful pair outcome")
        for side, allowed in (
            ("vulnerable", {"tp", "fn", "unscored", "out-of-scope"}),
            ("fixed", {"fp", "tn", "unscored", "out-of-scope"}),
        ):
            if not isinstance(outcome.get(side), str) or outcome[side] not in allowed:
                raise ValueError("Invalid successful pair outcome")
            result_side = pair.get(side)
            if not isinstance(result_side, dict) or result_side.get("commit") != truth[f"{side}_commit"]:
                raise ValueError("Missing or mismatched successful side commit")
            if v4:
                if type(result_side.get("report_returned")) is not bool:
                    raise ValueError("Missing report-return observation")
                if "error" in result_side:
                    failed_sides.append(side)
                    if (
                        not isinstance(result_side["error"], str)
                        or not result_side["error"]
                        or result_side.get("error_phase")
                        not in {"prepare", "fetch", "extract", "scan", "score"}
                        or outcome[side] != "unscored"
                        or (
                            result_side.get("audit_incomplete") is not None
                            and type(result_side["audit_incomplete"]) is not bool
                        )
                    ):
                        raise ValueError("Malformed side failure or scored failed side")
                    if result_side["report_returned"] and "execution" not in result_side:
                        raise ValueError("Returned report lacks execution evidence")
                    if "execution" in result_side:
                        validate_execution(result_side["execution"], successful=False)
                    if "archive" in result_side:
                        validate_archive(result_side["archive"], truth, side)
                    continue
                if not result_side["report_returned"] or "error_phase" in result_side:
                    raise ValueError("Successful side has no returned report")
                validate_execution(result_side.get("execution"), successful=True)
            side_fields = {
                "commit",
                "archive",
                "scan_root",
                "audit_incomplete",
                "rule_version",
                "missing_labeled_paths",
                "labeled_file_states",
                "hits",
                "hit_rules",
                "hits_in_labeled_lines",
                "in_range_rules",
                "any_rule_findings_in_labeled_files",
            }
            if not side_fields <= result_side.keys():
                raise ValueError("Missing successful side fields")
            if (
                not isinstance(result_side["scan_root"], str)
                or type(result_side["audit_incomplete"]) is not bool
            ):
                raise ValueError("Invalid successful side scan metadata")
            if not isinstance(result_side["labeled_file_states"], dict) or any(
                not isinstance(result_side[field], list)
                for field in (
                    "missing_labeled_paths",
                    "hits",
                    "hit_rules",
                    "hits_in_labeled_lines",
                    "in_range_rules",
                    "any_rule_findings_in_labeled_files",
                )
            ):
                raise ValueError("Invalid successful side finding metadata")
            if v4:
                checks = result_side.get("labeled_rule_states")
                if (
                    not isinstance(checks, dict)
                    or set(checks) != relevant_rule_ids(truth)
                    or any(
                        not isinstance(state, str)
                        or state not in {"checked", "partial", "not-run", "not-applicable"}
                        for state in checks.values()
                    )
                ):
                    raise ValueError("Missing or invalid relevant labeled rule coverage")
            validate_archive(result_side.get("archive"), truth, side)
            if v4 and outcome[side] in {"fn", "tn"} and not checked_labeled_scope(result_side):
                raise ValueError("Scored silence requires completely checked labeled scope")
        if v4:
            if bool(failed_sides) != ("error" in pair):
                raise ValueError("Pair error does not match side errors")
            if failed_sides and outcome.get("discriminating_tp", False):
                raise ValueError("Failed sides cannot discriminate a fix")
            if "vulnerable" in failed_sides and outcome.get("vulnerable_line_level", False):
                raise ValueError("Failed vulnerable side cannot be a line-level detection")
            fixed = pair["fixed"]
            if outcome.get("discriminating_tp", False) and not checked_labeled_scope(fixed):
                raise ValueError("Fix discrimination requires checked fixed-side labeled scope")
        if pair["expected_rules"] or pair["weaknesses"]:
            if any(
                type(outcome.get(field)) is not bool
                for field in ("vulnerable_line_level", "discriminating_tp")
            ):
                raise ValueError("Missing successful pair scoring fields")
        if not failed_sides:
            successful.add(pair_id)
    for field, measured in (
        ("totals", pairs),
        ("in_scope_totals", [pair for pair in pairs if pair.get("in_scope")]),
    ):
        counts = results[field]
        if not isinstance(counts, dict) or any(
            type(value) is not int or value < 0 for value in counts.values()
        ):
            raise ValueError("Invalid result totals")
        if counts != totals(measured, v4=v4):
            raise ValueError("Results totals differ from pair outcomes")
    return successful


def write_file(parent: int, name: str, data: bytes) -> None:
    handle = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    with os.fdopen(handle, "wb") as stream:
        stream.write(data)


def collect(truth: Path, results: Path, work: Path, out: Path, evaluation_outcome: str = "success") -> dict:
    manifest = {
        "schema": "apsa-holdout-reports-v1",
        "evaluation_outcome": evaluation_outcome,
        "status": "incomplete",
        "reports": [],
        "errors": [],
    }
    errors = manifest["errors"]
    expected = {}
    summary = {}
    successful = set()
    truth_sha = ""
    if evaluation_outcome != "success":
        errors.append(f"Evaluation step outcome: {evaluation_outcome}")
    # The destination must be fresh: retained files cannot mask missing evidence.
    with directory(out, create=True, exclusive=True) as destination:
        try:
            truth_raw = read_document(truth)
            truth_sha = hashlib.sha256(truth_raw).hexdigest()
            expected = truth_pairs(document(truth_raw))
        except (OSError, ValueError) as error:
            errors.append(f"Frozen truth unavailable or invalid ({type(error).__name__})")
        if expected:
            try:
                summary = document(read_document(results))
                successful = successful_ids(summary, expected, truth_sha)
                if len(successful) != len(expected):
                    errors.append(f"Evaluation failed for {len(expected) - len(successful)} pair(s)")
            except (OSError, ValueError, TypeError) as error:
                errors.append(f"Results unavailable or invalid ({type(error).__name__})")
            retained_bytes = 0
            try:
                with directory(work) as source:
                    for pair_id in sorted(expected):
                        for side in SIDES:
                            parts = (pair_id, side, "scan")
                            relative = "/".join((*parts, "report.json"))
                            try:
                                with directory_at(source, parts) as report_directory:
                                    data = read_file(report_directory, "report.json", MAX_REPORT_BYTES)
                                if retained_bytes + len(data) > MAX_TOTAL_REPORT_BYTES:
                                    raise ValueError("Total report byte budget exceeded")
                                with directory_at(destination, parts, create=True) as target:
                                    write_file(target, "report.json", data)
                                retained_bytes += len(data)
                                manifest["reports"].append(
                                    {
                                        "path": relative,
                                        "bytes": len(data),
                                        "sha256": hashlib.sha256(data).hexdigest(),
                                    }
                                )
                                if pair_id in successful:
                                    report = document(data)
                                    report = report.get("report", report)
                                    if (
                                        not isinstance(report, dict)
                                        or not isinstance(report.get("findings"), list)
                                        or not isinstance(report.get("inventory"), dict)
                                    ):
                                        raise ValueError("Invalid successful scan report")
                                    if summary.get("schema") == "apsa-fpfn-results-v4":
                                        pair_result = next(
                                            row for row in summary["pairs"] if row["id"] == pair_id
                                        )
                                        validate_report_rule_scope(report, pair_result, side)
                            except FileNotFoundError:
                                if pair_id in successful:
                                    errors.append(f"Missing required report: {relative}")
                            except (OSError, ValueError, TypeError) as error:
                                errors.append(
                                    f"Cannot retain valid report: {relative} ({type(error).__name__})"
                                )
            except (OSError, ValueError) as error:
                errors.append(f"Work directory unavailable or unsafe ({type(error).__name__})")
        if not errors:
            manifest["status"] = "complete"
        write_file(
            destination, "collection.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("truth", "results", "work", "out"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument(
        "--evaluation-outcome", choices=("success", "failure", "cancelled", "skipped"), default="success"
    )
    args = parser.parse_args()
    try:
        manifest = collect(args.truth, args.results, args.work, args.out, args.evaluation_outcome)
    except (OSError, ValueError) as error:
        print(f"Cannot create fresh report artifact ({type(error).__name__})")
        return 1
    print(
        f"Report collection {manifest['status']}: {len(manifest['reports'])} retained, "
        f"{len(manifest['errors'])} error(s)"
    )
    return 0 if manifest["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
