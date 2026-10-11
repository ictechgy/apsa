"""Compile trusted mobile sources into a new directory and record build evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

JDK = Path("/Users/coden/.local/jdks/jdk-17.0.20+8/Contents/Home")
SDK = Path("/Users/coden/Library/Android/sdk")


def build_new(output: Path) -> dict:
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
    env = dict(os.environ)
    env["JAVA_HOME"] = str(JDK)
    env["PATH"] = str(JDK / "bin") + os.pathsep + env.get("PATH", "")

    def run(argv):
        argv = [str(value) for value in argv]
        if argv[0].endswith("javac"):
            argv[0] = str(JDK / "bin/javac")
        if argv[0] == "keytool":
            argv[0] = str(JDK / "bin/keytool")
        if "swiftc" in argv:
            argv += ["-module-cache-path", str(output / "swift-module-cache")]
        result = subprocess.run(argv, env=env, capture_output=True, timeout=120, check=False)
        commands.append(
            {
                "argv": argv,
                "status": result.returncode,
                "stdout": result.stdout.decode(errors="replace"),
                "stderr": result.stderr.decode(errors="replace"),
            }
        )
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise ValueError("Fresh mobile fixture compilation failed; see generated command evidence")
        return result.stdout.decode()

    builder.__dict__["run"] = run
    for argv in (
        [str(JDK / "bin/javac"), "-version"],
        [str(JDK / "bin/java"), "-version"],
        ["/usr/bin/xcrun", "swiftc", "--version"],
        ["/usr/bin/xcrun", "--sdk", "iphonesimulator", "--show-sdk-version"],
        [str(SDK / "build-tools/36.0.0/aapt2"), "version"],
    ):
        run(argv)
    android = output / "android"
    ios = output / "ios"
    android.mkdir()
    ios.mkdir()
    apk = builder.android(SDK, android)
    app = builder.ios(ios, False, False)
    files = [
        fixture_source / "build.py",
        fixture_source / "ios/Main.swift",
        fixture_source / "android/MainActivity.java",
        fixture_source / "android/AndroidManifest.xml",
    ]
    manifest = {
        "compiled": True,
        "installed": False,
        "android_target": "android-36/min-api-26",
        "ios_target": "arm64-apple-ios18.0-simulator/SDK-27.0",
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    result = build_new(parser.parse_args().out)
    print(json.dumps({key: result[key] for key in ("apk", "app", "apk_sha256", "executable_sha256")}))
