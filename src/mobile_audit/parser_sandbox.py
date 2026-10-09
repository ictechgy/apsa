"""Optional OS isolation for the parser, with no unsandboxed retry after a launch failure."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path


def backend(platform: str | None = None) -> str | None:
    platform = platform or sys.platform
    candidate = (
        "/usr/bin/sandbox-exec"
        if platform == "darwin"
        else "/usr/bin/bwrap"
        if platform.startswith("linux")
        else None
    )
    if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
        return candidate
    return None


def _runtime_roots() -> list[Path]:
    import mobile_audit
    import quaygate

    roots = {
        Path(sys.prefix).resolve(),
        Path(sys.base_prefix).resolve(),
        Path(mobile_audit.__file__).resolve().parent,
        Path(quaygate.__file__).resolve().parent,
    }
    # Editable installs resolve the package under src; allow only that package tree.
    return sorted(roots)


def sandbox_command(
    args: list[str],
    target: Path,
    sbom: Path | None,
    scratch: Path,
    *,
    mode: str | None = None,
    report_home: Path | None = None,
) -> tuple[list[str], dict]:
    mode = mode or os.environ.get("APSA_PARSER_SANDBOX", "auto")
    if mode not in {"auto", "required", "off"}:
        raise ValueError("APSA_PARSER_SANDBOX must be auto, required or off")
    executable = backend() if mode != "off" else None
    if not executable:
        if mode == "required":
            raise ValueError("Required parser OS sandbox is unavailable; audit refused")
        return args, {
            "mode": mode,
            "backend": "resource-limits-only",
            "state": "disabled" if mode == "off" else "unavailable",
            "network_denied_by_os": False,
            "filesystem_restricted_by_os": False,
        }
    target, scratch = target.resolve(), scratch.resolve()
    reads = sorted(set(_runtime_roots() + [target] + ([sbom.resolve()] if sbom else [])))
    hidden = {Path.home() / ".local/share/mobile-audit"}
    if report_home:
        hidden.add(report_home.resolve())
    protected = sorted(
        path.resolve() for path in hidden if any(path.resolve().is_relative_to(root) for root in reads)
    )
    if sys.platform == "darwin":
        # JSON quoted path strings have the escaping needed by SBPL string literals.
        def quoted(path):
            return json.dumps(str(path), ensure_ascii=True)

        paths = [Path("/System"), Path("/usr/lib"), Path("/usr/share"), *reads]
        executable_maps = [Path("/System"), Path("/usr/lib"), *_runtime_roots()]
        rules = [
            "(version 1)",
            "(deny default)",
            "(allow process-fork)",
            "(allow sysctl-read)",
            "(allow process-exec (literal " + quoted(Path(sys.executable).resolve()) + "))",
            '(allow process-exec (literal "/usr/bin/openssl"))',
            "(allow file-read-metadata)",
            "(allow file-read* file-test-existence "
            + " ".join("(subpath " + quoted(path) + ")" for path in paths)
            + ' (literal "/"))',
            "(allow file-map-executable "
            + " ".join("(subpath " + quoted(path) + ")" for path in executable_maps)
            + ' (literal "/usr/bin/openssl"))',
            '(allow file-read* (literal "/dev/null") (literal "/dev/urandom") (literal "/dev/random"))',
            '(allow file-read-data file-write-data file-test-existence (subpath "/dev/fd"))',
            "(allow file-write* (subpath " + quoted(scratch) + ') (literal "/dev/null"))',
        ]
        rules += [
            "(deny file-read* file-write* file-map-executable (subpath " + quoted(path) + "))"
            for path in protected
        ]
        profile = "\n".join(rules) + "\n"
        path = scratch / "parser.sb"
        path.write_text(profile)
        path.chmod(0o600)
        command = [executable, "-f", str(path), *args]
        policy_bytes = profile.encode()
    else:
        command = [
            executable,
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--setenv",
            "LANG",
            "C.UTF-8",
            "--setenv",
            "TMPDIR",
            str(scratch),
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
        ]
        system = [Path("/usr"), Path("/bin"), Path("/lib"), Path("/lib64"), Path("/etc/ld.so.cache")]
        for path in system + reads:
            if path.exists():
                command += ["--ro-bind", str(path), str(path)]
        command += ["--bind", str(scratch), str(scratch), "--chdir", str(scratch), "--", *args]
        for path in protected:
            if path.is_dir():
                index = command.index("--")
                command[index:index] = ["--tmpfs", str(path), "--remount-ro", str(path)]
            elif path.exists():
                raise ValueError("Report store overlaps a sandbox input as a file; audit refused")
        policy_bytes = json.dumps(command[: -len(args)], ensure_ascii=True).encode()
    return command, {
        "mode": mode,
        "backend": "seatbelt" if sys.platform == "darwin" else "bubblewrap",
        "state": "enforced",
        "network_denied_by_os": True,
        "filesystem_restricted_by_os": True,
        "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "scope": "authorized input/SBOM and trusted Python runtime read-only; scratch write; no host report-store mount",
    }
