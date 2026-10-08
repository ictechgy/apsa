"""Internal parser boundary. This process never accesses the report database or network."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from contextlib import contextmanager, nullcontext
from pathlib import Path


def limits() -> None:
    if sys.platform == "win32":
        return
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (45, 46))
    resource.setrlimit(resource.RLIMIT_FSIZE, (512 * 1024 * 1024, 512 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))


@contextmanager
def stable_input(target: Path, scratch: Path | None = None):
    from .core import MAX_ARCHIVE_TOTAL, open_file

    if target.is_dir():
        yield target
        return
    fd = open_file(target)
    directory_context = (
        nullcontext(str(scratch)) if scratch else tempfile.TemporaryDirectory(prefix="mobile-audit-parser-")
    )
    with os.fdopen(fd, "rb") as source, directory_context as directory:
        import stat

        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_TOTAL:
            raise ValueError("Archive is not a regular input within the size limit")
        snapshot = Path(directory) / ("input" + target.suffix)
        total = 0
        with snapshot.open("wb") as output:
            snapshot.chmod(0o600)
            while chunk := source.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_ARCHIVE_TOTAL:
                    raise ValueError("Archive grew beyond the input size limit")
                output.write(chunk)
        after = os.fstat(source.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("Archive changed during inspection; rerun with a stable build")
        yield snapshot


def analyze(target: Path, sbom: Path | None, configuration: str | None = None) -> dict:
    from .inputs import inspect_target
    from .rules import static_checks

    inventory, sources = inspect_target(target, sbom, authorized=True, configuration=configuration)
    findings, coverage = static_checks(inventory, sources)
    if inventory.get("configuration_ambiguous"):
        for item in findings:
            if item["status"] == "configuration-confirmed":
                item["status"] = "candidate"
                item["configuration_scope"] = "ambiguous source configurations"
    from .source_analysis import analyze_sources

    structural = analyze_sources(sources)
    findings.extend(structural["findings"])
    coverage.extend(structural["coverage"])
    inventory["warnings"].extend(structural["warnings"])
    if target.suffix.lower() in {".apk", ".ipa"}:
        from .binary_analysis import analyze_binary

        binary = analyze_binary(target, inventory)
        findings.extend(binary["findings"])
        coverage.extend(binary["coverage"])
        inventory["warnings"].extend(binary["warnings"])
        inventory["binary"] = binary["metadata"]
        inventory["features"] = sorted(
            set(inventory["features"])
            | {feature for dex in binary["metadata"].get("dex", []) for feature in dex.get("features", [])}
        )
        from .quaygate_analysis import analyze as analyze_lint
        from .quaygate_analysis import merge

        lint = analyze_lint(target)
        findings = merge(findings, lint["findings"])
        coverage.extend(lint["coverage"])
        inventory["warnings"].extend(lint["warnings"])
        inventory["quaygate"] = lint["metadata"]
        if not lint["metadata"]["complete"]:
            inventory["partial"] = True
    inventory["engines"] = ["mobile-audit"] + (["quaygate-lint"] if "quaygate" in inventory else [])
    if not inventory["fingerprint_complete"]:
        inventory["partial"] = True
        for check in coverage:
            if check["state"] == "checked":
                check["state"] = "partial"
        inventory["warnings"].append(
            "Input coverage is incomplete; the fingerprint identifies inspected source files only."
        )
    return {"inventory": inventory, "findings": findings, "coverage": coverage}


def main() -> None:
    limits()

    try:
        target = Path(sys.argv[1])
        if not target.exists():
            raise ValueError(f"Input not found: {target}")
        if not target.is_dir() and target.suffix.lower() not in {".apk", ".ipa", ".zip", ".aab"}:
            raise ValueError("Use a source folder, APK, IPA, simulator .app folder, or supported app ZIP")
        expected = Path(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else target
        if target.resolve() != expected:
            raise ValueError("Authorized input moved or became a symlink; audit refused")
        scratch = Path(sys.argv[4]) if len(sys.argv) > 4 else None
        with stable_input(target, scratch) as snapshot:
            result = analyze(
                snapshot,
                Path(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2] else None,
                sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None,
            )
            result["inventory"]["target"] = str(target)
    except (ValueError, OSError, TypeError, KeyError) as error:
        result = {"error": f"Input analysis failed ({type(error).__name__}): {error}"}
    sys.stdout.write(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
