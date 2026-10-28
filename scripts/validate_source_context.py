"""Compile the six explicit-context regression sources on a fresh hosted runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import selectors
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REVISION = "explicit-source-context-r1"
PAIRS = {"java": "intent", "kotlin": "query", "swift": "url"}


def swift_extension_type_probes() -> dict[str, str]:
    """Fresh type assertions prove lookup, without app execution or SDK signing."""
    declaration = """struct FakeURL {
    let host: String? = "synthetic.example.test"
    init?(string: String) {}
}
"""
    result = {}
    for name, constructor, expected, member in [
        ("nested-nominal", "URL", "Handler.URL", declaration.replace("FakeURL", "URL")),
        ("nested-alias", "URL", "FakeURL", "typealias URL = FakeURL"),
        ("qualified-sdk", "Foundation.URL", "Foundation.URL", declaration.replace("FakeURL", "URL")),
    ]:
        result[name] = (
            "import Foundation\n"
            + declaration
            + "class Handler {\nfunc probe(_ incoming: Foundation.URL) {\n"
            + f"let parsed = {constructor}(string: incoming.absoluteString)!\n"
            + f"let _: {expected} = parsed\n"
            + "}\n}\nextension Handler {\n"
            + member
            + "\n}\n"
        )
    for name, protocol in [
        ("protocol-conformance", "protocol P { typealias URL = FakeURL }\n"),
        ("protocol-extension-conformance", "protocol P {}\nextension P { typealias URL = FakeURL }\n"),
    ]:
        result[name] = (
            "import Foundation\n"
            + declaration
            + protocol
            + "class Handler {\nfunc probe(_ incoming: Foundation.URL) {\n"
            + "let parsed = URL(string: incoming.absoluteString)!\n"
            + "let _: FakeURL = parsed\n"
            + "}\n}\nextension Handler: P {}\n"
        )
    for name, owner, protocol in [
        ("implicit-actor", "actor Handler", "Actor"),
        ("implicit-enum-equatable", "enum Handler", "Equatable"),
        ("implicit-enum-hashable", "enum Handler", "Hashable"),
    ]:
        result[name] = (
            "import Foundation\n"
            + declaration
            + f"extension {protocol} {{ typealias URL = FakeURL }}\n"
            + owner
            + " {\n"
            + ("case main\n" if owner.startswith("enum") else "")
            + "func probe(_ incoming: Foundation.URL) {\n"
            + "let parsed = URL(string: incoming.absoluteString)!\n"
            + "let _: FakeURL = parsed\n"
            + "}\n}\n"
        )
    return result


def inputs(root: Path, languages: list[str]) -> list[tuple[str, Path, str]]:
    """Validate committed source identities before invoking any compiler."""
    manifest = json.loads((root / "benchmarks/corpus.json").read_text())
    if manifest.get("input_revision") != REVISION:
        raise ValueError("Unexpected source-context revision")
    cases = manifest["cases"]
    result = []
    for language in languages:
        for variant in ("vulnerable", "fixed"):
            case_id = f"{language}-{PAIRS[language]}-{variant}"
            selected = [case for case in cases if case["id"] == case_id]
            if len(selected) != 1:
                raise ValueError("Missing or duplicate context case: " + case_id)
            case = selected[0]
            source = (root / "benchmarks" / case["path"]).resolve()
            if not source.is_relative_to((root / "benchmarks/cases").resolve()):
                raise ValueError("Context source must be a committed public case")
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            context = case.get("context_revision", {})
            if context.get("id") != REVISION or context.get("current_sha256") != digest:
                raise ValueError("Source-context input hash differs: " + case_id)
            result.append((case_id, source, digest))
    return result


MAX_COMPILER_OUTPUT_BYTES = 1024 * 1024


def _wait_unreaped(process: subprocess.Popen, deadline: float) -> bool:
    """Observe only this owned child's exit without releasing its PID custody."""
    while True:
        waitid = getattr(os, "waitid", None)
        if waitid is not None:
            event = waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            exited = event is not None
        else:
            # Darwin has no os.waitid; status() does not reap the owned child.
            import psutil

            try:
                exited = psutil.Process(process.pid).status() == psutil.STATUS_ZOMBIE
            except psutil.NoSuchProcess:
                raise ChildProcessError("Owned child custody unavailable") from None
        if exited:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def run(argv: list[str]) -> dict:
    """Preserve bounded compiler evidence even on timeout or invalid UTF-8."""
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = truncated = custody_lost = False
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        return {
            "argv": argv,
            "exit_code": None,
            "timed_out": False,
            "output_truncated": False,
            "output_decode_error": False,
            "spawn_error_type": type(error).__name__,
            "stdout": "",
            "stderr": "",
        }
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + 180
    exited_observed = False
    group_cleanup = "unconfirmed"
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                timed_out = True
                break
            for key, _ in selector.select(0.05):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                remaining = MAX_COMPILER_OUTPUT_BYTES - len(streams[key.data])
                streams[key.data].extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
            if truncated:
                break
        if not timed_out and not truncated:
            exited_observed = _wait_unreaped(process, deadline)
            timed_out = not exited_observed
    except ChildProcessError:
        custody_lost = True
    finally:
        if not custody_lost:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                group_cleanup = "signal-sent"
            except ProcessLookupError:
                group_cleanup = "absent"
            except PermissionError:
                # Observed exit is distinct from confirmed group cleanup.
                # Never tolerate a denied signal to a live or hung child.
                if not exited_observed:
                    raise
        process.wait()
        selector.close()
        process.stdout.close()
        process.stderr.close()
    decode_error = False
    decoded = {}
    for name, raw in streams.items():
        try:
            decoded[name] = raw.decode("utf-8")
        except UnicodeError:
            decode_error = True
            decoded[name] = raw.decode("utf-8", errors="replace")
    return {
        "argv": argv,
        "exit_code": None if timed_out or custody_lost else process.returncode,
        "timed_out": timed_out,
        "output_truncated": truncated,
        "output_decode_error": decode_error,
        "child_custody_lost": custody_lost,
        "process_group_cleanup": group_cleanup,
        **decoded,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--language", choices=("android", "swift"), required=True)
    parser.add_argument("--sdk", type=Path, required=True)
    parser.add_argument("--kotlinc", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or not args.out.resolve().is_relative_to(
        Path(os.environ["RUNNER_TEMP"]).resolve()
    ):
        raise ValueError("Compiler validation requires a fresh hosted runner temporary directory")
    if args.out.resolve().is_relative_to(ROOT):
        raise ValueError("Compiler evidence must be outside the checkout")
    languages = ["java", "kotlin"] if args.language == "android" else ["swift"]
    sources = inputs(ROOT, languages)
    if args.language == "android" and args.kotlinc is None:
        raise ValueError("Android context validation requires the pinned Kotlin compiler")
    args.out.mkdir(parents=True, exist_ok=False)
    if args.language == "android":
        tools = {"java": run(["javac", "-version"]), "kotlin": run([str(args.kotlinc), "-version"])}
    else:
        tools = {"swift": run(["xcrun", "swiftc", "--version"])}
    results = []
    for case_id, source, digest in sources:
        destination = args.out / case_id
        destination.mkdir()
        if case_id.startswith("java-"):
            command = [
                "javac",
                "-classpath",
                str(args.sdk / "android.jar"),
                "-d",
                str(destination),
                str(source),
            ]
        elif case_id.startswith("kotlin-"):
            command = [
                str(args.kotlinc),
                "-classpath",
                str(args.sdk / "android.jar"),
                "-d",
                str(destination),
                str(source),
            ]
        else:
            arch = "arm64" if platform.machine() == "arm64" else "x86_64"
            command = [
                "xcrun",
                "swiftc",
                "-typecheck",
                "-swift-version",
                "6",
                "-sdk",
                str(args.sdk),
                "-target",
                arch + "-apple-ios17.0-simulator",
                str(source),
            ]
        results.append({"case_id": case_id, "source_sha256": digest, **run(command)})
    lookup_results = []
    if args.language == "swift":
        for case_id, source_text in swift_extension_type_probes().items():
            source = args.out / f"extension-lookup-{case_id}.swift"
            source.write_text(source_text)
            lookup_results.append(
                {
                    "case_id": case_id,
                    "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                    **run([*results[-1]["argv"][:-1], str(source)]),
                }
            )
    passed = all(
        row["exit_code"] == 0
        and not any(
            row.get(flag)
            for flag in ("timed_out", "output_truncated", "output_decode_error", "child_custody_lost")
        )
        for row in list(tools.values()) + results + lookup_results
    )
    report = {
        "input_revision": REVISION,
        "sdk": str(args.sdk),
        "tools": tools,
        "cases": results,
        "extension_type_lookup_cases": lookup_results,
        "passed": passed,
        "scope": "Synthetic source and extension member-type lookup typechecking only; no app execution or legacy-v1 compilation claim",
    }
    (args.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
