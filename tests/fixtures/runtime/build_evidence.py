"""Compile trusted mobile sources with explicit toolchain configuration and hashed journals."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import NamedTuple


class BuildConfig(NamedTuple):
    jdk_bin: Path
    sdk: Path
    android_platform: str
    build_tools: str
    ios_sdk: str
    ios_runtime: str
    ios_target: str
    ios_minimum: str
    xcrun: Path
    codesign: Path


def resolve_build_config(
    *,
    jdk_bin: Path | None,
    sdk: Path | None,
    android_platform: str,
    build_tools: str,
    ios_sdk: str,
    ios_runtime: str,
    ios_target: str,
    environment: dict[str, str],
) -> BuildConfig:
    """Validate explicit components before source/output access or any tool invocation."""
    if (sdk is not None and not isinstance(sdk, Path)) or (
        jdk_bin is not None and not isinstance(jdk_bin, Path)
    ):
        raise ValueError("Explicit SDK and JDK bin configuration must use paths")
    if not isinstance(android_platform, str) or not re.fullmatch(
        r"android-[1-9][0-9]{0,2}", android_platform
    ):
        raise ValueError("An explicit Android platform component is required")
    if int(android_platform.removeprefix("android-")) < 26:
        raise ValueError("The Android platform must support the fixture minimum API 26")
    if not isinstance(build_tools, str) or not re.fullmatch(
        r"[1-9][0-9]{0,2}\.[0-9]{1,2}\.[0-9]{1,2}", build_tools
    ):
        raise ValueError("An explicit Android build-tools version component is required")
    if not isinstance(ios_sdk, str) or not re.fullmatch(
        r"iphonesimulator(?:[1-9][0-9]?(?:\.[0-9]{1,2}){1,2})?", ios_sdk
    ):
        raise ValueError("An explicit iOS simulator SDK selector is required")
    runtime = (
        re.fullmatch(
            r"com\.apple\.CoreSimulator\.SimRuntime\.iOS-([1-9][0-9]?)-([0-9]{1,2})(?:-([0-9]{1,2}))?",
            ios_runtime,
        )
        if isinstance(ios_runtime, str)
        else None
    )
    target = (
        re.fullmatch(
            r"(?:arm64|x86_64)-apple-ios([1-9][0-9]?)\.([0-9]{1,2})(?:\.([0-9]{1,2}))?-simulator", ios_target
        )
        if isinstance(ios_target, str)
        else None
    )
    if runtime is None or target is None:
        raise ValueError("Explicit simulator runtime and compilation target components are required")
    if tuple(int(item or 0) for item in target.groups()) > tuple(int(item or 0) for item in runtime.groups()):
        raise ValueError("The iOS deployment target exceeds the explicitly planned simulator runtime")
    sdk_version = ios_sdk.removeprefix("iphonesimulator")
    if sdk_version:
        sdk_parts = [int(item) for item in sdk_version.split(".")]
        sdk_parts += [0] * (3 - len(sdk_parts))
        if tuple(int(item or 0) for item in target.groups()) > tuple(sdk_parts):
            raise ValueError("The iOS deployment target exceeds the explicitly selected SDK version")
    minimum = ".".join(item for item in target.groups() if item is not None)
    if sdk is None:
        configured = (
            environment.get("APSA_TEST_ANDROID_SDK_ROOT")
            or environment.get("ANDROID_SDK_ROOT")
            or environment.get("ANDROID_HOME")
        )
        if not configured:
            raise ValueError("An explicit Android SDK or configured SDK environment variable is required")
        sdk = Path(configured)
    if jdk_bin is None:
        home = environment.get("APSA_TEST_JAVA_HOME") or environment.get("JAVA_HOME")
        javac = shutil.which("javac", path=environment.get("PATH", "")) if not home else None
        if home:
            jdk_bin = Path(home) / "bin"
        elif javac:
            jdk_bin = Path(javac).parent
        else:
            raise ValueError("An explicit JDK bin directory, configured JDK, or javac on PATH is required")
    if not isinstance(sdk, Path) or not isinstance(jdk_bin, Path):
        raise ValueError("Explicit SDK and JDK bin configuration must use paths")
    sdk, jdk_bin = sdk.expanduser().absolute(), jdk_bin.expanduser().absolute()
    xcrun = shutil.which("xcrun", path=environment.get("PATH", ""))
    codesign = shutil.which("codesign", path=environment.get("PATH", ""))
    if not xcrun or not codesign:
        raise ValueError("The configured PATH must provide xcrun and codesign")
    tools = [jdk_bin / name for name in ("java", "javac", "keytool")]
    tools += [sdk / "build-tools" / build_tools / name for name in ("aapt2", "d8", "zipalign", "apksigner")]
    tools += [Path(xcrun), Path(codesign)]
    if not all(path.is_file() and os.access(path, os.X_OK) for path in tools):
        raise ValueError("Configured build tool executables are unavailable")
    if not (sdk / "platforms" / android_platform / "android.jar").is_file():
        raise ValueError("Configured Android platform is unavailable")
    return BuildConfig(
        jdk_bin,
        sdk,
        android_platform,
        build_tools,
        ios_sdk,
        ios_runtime,
        ios_target,
        minimum,
        Path(xcrun),
        Path(codesign),
    )


def command_evidence(argv: list[str], result: subprocess.CompletedProcess) -> dict:
    return {
        "argv_sha256": hashlib.sha256(json.dumps(argv, separators=(",", ":")).encode()).hexdigest(),
        "status": result.returncode,
        "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
        "stdout_bytes": len(result.stdout),
        "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
        "stderr_bytes": len(result.stderr),
    }


def build_new(
    output: Path,
    *,
    jdk_bin: Path | None = None,
    sdk: Path | None = None,
    android_platform: str,
    build_tools: str,
    ios_sdk: str,
    ios_runtime: str,
    ios_target: str,
    environment: dict[str, str] | None = None,
) -> dict:
    if not isinstance(output, Path):
        raise ValueError("New fixture output must be a path")
    if environment is not None and (
        not isinstance(environment, dict)
        or any(not isinstance(key, str) or not isinstance(value, str) for key, value in environment.items())
    ):
        raise ValueError("Build environment must contain only string names and values")
    env = dict(os.environ if environment is None else environment)
    config = resolve_build_config(
        jdk_bin=jdk_bin,
        sdk=sdk,
        android_platform=android_platform,
        build_tools=build_tools,
        ios_sdk=ios_sdk,
        ios_runtime=ios_runtime,
        ios_target=ios_target,
        environment=env,
    )
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    original = Path(__file__).parent
    fixture_source = output / "source"
    fixture_source.mkdir()
    for name in ("build.py", "ios/Main.swift", "android/MainActivity.java", "android/AndroidManifest.xml"):
        destination = fixture_source / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original / name, destination)
    spec = importlib.util.spec_from_file_location("owned_fixture_builder", fixture_source / "build.py")
    if spec is None or spec.loader is None:
        raise ValueError("Trusted fixture builder unavailable")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    env["JAVA_HOME"] = str(config.jdk_bin.parent)
    env["PATH"] = str(config.jdk_bin) + os.pathsep + env.get("PATH", "")

    def write_journal() -> None:
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")

    def run(argv):
        argv = [str(value) for value in argv]
        if Path(argv[0]).name in {"javac", "java", "keytool"}:
            argv[0] = str(config.jdk_bin / Path(argv[0]).name)
        # Adapt the trusted legacy builder's fixed components without evaluating
        # replacement source or consulting any default SDK/device installation.
        for index, value in enumerate(argv):
            if value == str(config.sdk / "platforms/android-36/android.jar"):
                argv[index] = str(config.sdk / "platforms" / config.android_platform / "android.jar")
            elif value.startswith(str(config.sdk / "build-tools/36.0.0") + os.sep):
                argv[index] = str(config.sdk / "build-tools" / config.build_tools / Path(value).name)
            elif value == "xcrun":
                argv[index] = str(config.xcrun)
            elif value == "codesign":
                argv[index] = str(config.codesign)
        if "--sdk" in argv:
            argv[argv.index("--sdk") + 1] = config.ios_sdk
        if "swiftc" in argv:
            argv += ["-module-cache-path", str(output / "swift-module-cache")]
            if "-target" in argv:
                argv[argv.index("-target") + 1] = config.ios_target
        if Path(argv[0]).name == "codesign":
            info_path = Path(argv[-1]) / "Info.plist"
            info = plistlib.loads(info_path.read_bytes())
            info["MinimumOSVersion"] = config.ios_minimum
            info_path.write_bytes(plistlib.dumps(info))
        try:
            result = subprocess.run(argv, env=env, capture_output=True, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            stdout = (
                error.stdout
                if isinstance(error, subprocess.TimeoutExpired) and isinstance(error.stdout, bytes)
                else b""
            )
            stderr = (
                error.stderr
                if isinstance(error, subprocess.TimeoutExpired) and isinstance(error.stderr, bytes)
                else b""
            )
            evidence = command_evidence(argv, subprocess.CompletedProcess(argv, -1, stdout, stderr))
            evidence["status"] = "timeout" if isinstance(error, subprocess.TimeoutExpired) else "unavailable"
            commands.append(evidence)
            write_journal()
            raise ValueError(
                "Fresh mobile fixture tool operation failed; see hashed command evidence"
            ) from None
        commands.append(command_evidence(argv, result))
        write_journal()
        if result.returncode:
            raise ValueError("Fresh mobile fixture compilation failed; see hashed command evidence")
        try:
            return result.stdout.decode("utf-8", errors="strict")
        except UnicodeError:
            raise ValueError("Fresh mobile fixture tool output is not valid UTF-8") from None

    builder.__dict__["run"] = run
    builder.__dict__["shutil"] = SimpleNamespace(which=lambda name: shutil.which(name, path=env["PATH"]))
    for argv in (
        [str(config.jdk_bin / "javac"), "-version"],
        [str(config.jdk_bin / "java"), "-version"],
        [str(config.xcrun), "swiftc", "--version"],
        [str(config.xcrun), "--sdk", config.ios_sdk, "--show-sdk-version"],
        [str(config.sdk / "build-tools" / config.build_tools / "aapt2"), "version"],
    ):
        run(argv)
    android = output / "android"
    ios = output / "ios"
    android.mkdir()
    ios.mkdir()
    apk = builder.android(config.sdk, android)
    app = builder.ios(ios, False, False)
    files = [
        fixture_source / name
        for name in (
            "build.py",
            "ios/Main.swift",
            "android/MainActivity.java",
            "android/AndroidManifest.xml",
        )
    ]
    manifest = {
        "compiled": True,
        "installed": False,
        "android_target": config.android_platform + "/min-api-26",
        "android_build_tools": config.build_tools,
        "ios_target": config.ios_target,
        "ios_sdk_selector": config.ios_sdk,
        "planned_ios_runtime": config.ios_runtime,
        "ios_runtime_verified": False,
        "commands": commands,
        "sources": [
            {
                "name": str(path.relative_to(fixture_source)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in files
        ],
        "apk": str(apk),
        "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "app": str(app),
        "executable_sha256": hashlib.sha256((app / "AuditFixture").read_bytes()).hexdigest(),
        "info_plist_sha256": hashlib.sha256((app / "Info.plist").read_bytes()).hexdigest(),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def parser() -> argparse.ArgumentParser:
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--out", type=Path, required=True)
    arguments.add_argument("--jdk-bin", type=Path)
    arguments.add_argument("--sdk", type=Path)
    arguments.add_argument("--android-platform", required=True)
    arguments.add_argument("--build-tools", required=True)
    arguments.add_argument("--ios-sdk", required=True)
    arguments.add_argument("--ios-runtime", required=True)
    arguments.add_argument("--ios-target", required=True)
    return arguments


def main() -> None:
    args = parser().parse_args()
    result = build_new(
        args.out,
        jdk_bin=args.jdk_bin,
        sdk=args.sdk,
        android_platform=args.android_platform,
        build_tools=args.build_tools,
        ios_sdk=args.ios_sdk,
        ios_runtime=args.ios_runtime,
        ios_target=args.ios_target,
    )
    print(json.dumps({key: result[key] for key in ("apk", "app", "apk_sha256", "executable_sha256")}))


if __name__ == "__main__":
    main()
