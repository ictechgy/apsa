"""Optional OS isolation for the parser, with no unsandboxed retry after a launch failure."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
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

        system_code = [
            Path("/System/Library"),
            Path("/System/Cryptexes"),
            Path("/System/Volumes/Preboot/Cryptexes"),
            Path("/usr/lib"),
        ]
        paths = [*system_code, Path("/usr/share"), scratch, *reads]
        executable_maps = [*system_code, *_runtime_roots()]
        # Python's editable-install finder lists the package parent directory.
        # Grant only the directory itself, never sibling package contents.
        read_parents = sorted(
            {root.parent for root in _runtime_roots()} | {root.parent for root in reads if root.is_file()}
        )
        rules = [
            "(version 1)",
            "(deny default)",
            "(allow process-fork)",
            "(allow sysctl-read)",
            "(allow process-exec (literal " + quoted(Path(sys.executable).resolve()) + "))",
            *(
                # Framework builds (python.org, Homebrew) re-exec this app-bundle interpreter.
                "(allow process-exec (literal " + quoted(app.resolve()) + "))"
                for app in [Path(sys.base_prefix) / "Resources/Python.app/Contents/MacOS/Python"]
                if app.is_file()
            ),
            '(allow process-exec (literal "/usr/bin/openssl"))',
            '(allow file-read* file-test-existence (literal "/usr/bin/openssl"))',
            "(allow file-read-metadata)",
            "(allow file-read* file-test-existence "
            + " ".join("(subpath " + quoted(path) + ")" for path in paths)
            + ' (literal "/"))',
            "(allow file-read* file-test-existence "
            + " ".join("(literal " + quoted(path) + ")" for path in read_parents)
            + ")",
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
        "scope": "authorized input/SBOM and trusted Python runtime read-only; runtime/file-input parent directory listing; scratch read/write; no host report-store mount",
    }


def activate(command: list[str], args: list[str], metadata: dict, scratch: Path) -> tuple[list[str], dict]:
    """Load the parser, without any input, under the exact policy before parsing.

    The probe decides availability; it never runs the parser. In auto mode a
    backend that cannot start (nested Seatbelt, blocked user namespaces) is
    recorded as unavailable. Once the parser itself launches under isolation,
    a failure aborts the audit without an unsandboxed retry.
    """
    if metadata.get("state") != "enforced":
        return command, metadata
    import importlib.util

    from ._parser_worker import PROBE_MODULES

    # Modules visible to the parent must also load inside the sandbox; a module
    # absent from the installation is reported by the parser, not the probe.
    available = [name for name in PROBE_MODULES if importlib.util.find_spec(name) is not None]
    probe = command[: len(command) - len(args)] + [
        sys.executable,
        "-I",
        "-B",
        "-m",
        "mobile_audit._parser_worker",
        "--probe",
        *available,
    ]
    try:
        result = subprocess.run(
            probe,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=30,
            cwd=scratch,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(scratch)},
        )
        returncode = result.returncode
        detail = result.stderr[:300].decode("utf-8", errors="replace").strip()
    except (OSError, subprocess.SubprocessError) as error:
        returncode, detail = None, type(error).__name__
    if returncode == 0:
        return command, {**metadata, "activation_probe": "passed"}
    reason = f"{metadata['backend']} activation probe failed (exit {returncode}): {detail or 'no diagnostic'}"
    if metadata["mode"] == "required":
        raise ValueError(
            f"Required parser OS sandbox could not start; audit refused. {reason}. "
            "APSA_PARSER_SANDBOX=auto or off runs the parser with resource limits only."
        )
    return args, {
        "mode": metadata["mode"],
        "backend": "resource-limits-only",
        "state": "unavailable",
        "attempted_backend": metadata["backend"],
        "activation_probe": "failed",
        "unavailable_reason": reason,
        "network_denied_by_os": False,
        "filesystem_restricted_by_os": False,
    }
