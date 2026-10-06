"""Build owned platform fixtures locally, without downloading dependencies."""

from __future__ import annotations

import argparse
import os
import plistlib
import shutil
import subprocess
import zipfile
from pathlib import Path


def run(args: list[str]) -> str:
    return subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=90).decode()


def android(sdk: Path, output: Path) -> Path:
    tools = sdk / "build-tools/36.0.0"
    platform = sdk / "platforms/android-36/android.jar"
    source = Path(__file__).parent / "android"
    classes, dex = output / "classes", output / "dex"
    classes.mkdir(parents=True, exist_ok=True)
    dex.mkdir(parents=True, exist_ok=True)
    javac = shutil.which("javac")
    if not javac:
        raise SystemExit("Install a JDK 17+ and put javac on PATH")
    run(
        [
            javac,
            "--release",
            "8",
            "-classpath",
            str(platform),
            "-d",
            str(classes),
            str(source / "MainActivity.java"),
        ]
    )
    run(
        [
            str(tools / "d8"),
            "--lib",
            str(platform),
            "--min-api",
            "26",
            "--output",
            str(dex),
            str(classes / "audit/fixture/runtime/MainActivity.class"),
        ]
    )
    unsigned = output / "unsigned.apk"
    run(
        [
            str(tools / "aapt2"),
            "link",
            "-I",
            str(platform),
            "--manifest",
            str(source / "AndroidManifest.xml"),
            "-o",
            str(unsigned),
        ]
    )
    with zipfile.ZipFile(unsigned, "a") as archive:
        archive.write(dex / "classes.dex", "classes.dex")
    aligned = output / "aligned.apk"
    run([str(tools / "zipalign"), "-f", "4", str(unsigned), str(aligned)])
    key = output / "fixture.keystore"
    if not key.exists():
        run(
            [
                "keytool",
                "-genkeypair",
                "-keystore",
                str(key),
                "-storepass",
                "fixture-password",
                "-keypass",
                "fixture-password",
                "-alias",
                "fixture",
                "-dname",
                "CN=Owned Mobile Audit Test Fixture",
                "-keyalg",
                "RSA",
                "-validity",
                "3650",
            ]
        )
        key.chmod(0o600)
    apk = output / "fixture.apk"
    run(
        [
            str(tools / "apksigner"),
            "sign",
            "--ks",
            str(key),
            "--ks-pass",
            "pass:fixture-password",
            "--out",
            str(apk),
            str(aligned),
        ]
    )
    return apk


def ios(output: Path, retained: bool, switching: bool) -> Path:
    app = output / "Payload/AuditFixture.app"
    app.mkdir(parents=True, exist_ok=True)
    sdk = run(["xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"]).strip()
    run(
        [
            "xcrun",
            "swiftc",
            "-sdk",
            sdk,
            "-target",
            "arm64-apple-ios18.0-simulator",
            "-parse-as-library",
            "-module-name",
            "AuditFixture",
            str(Path(__file__).parent / "ios/Main.swift"),
            "-o",
            str(app / "AuditFixture"),
        ]
    )
    info = {
        "CFBundleExecutable": "AuditFixture",
        "CFBundleIdentifier": "audit.fixture.runtime.ios",
        "CFBundleName": "AuditFixture",
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "1",
        "MinimumOSVersion": "18.0",
        "LSRequiresIPhoneOS": True,
        "UIDeviceFamily": [1, 2],
        "UILaunchScreen": {},
        "AuditFixtureRetainCanary": retained,
        "AuditFixtureSwitchAccount": switching,
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["mobileauditfixture"]}],
        "UIApplicationSceneManifest": {
            "UIApplicationSupportsMultipleScenes": False,
            "UISceneConfigurations": {
                "UIWindowSceneSessionRoleApplication": [
                    {
                        "UISceneConfigurationName": "Default",
                        "UISceneDelegateClassName": "AuditFixture.SceneDelegate",
                    }
                ]
            },
        },
    }
    (app / "Info.plist").write_bytes(plistlib.dumps(info))
    run(["codesign", "--force", "--sign", "-", str(app)])
    ipa = output / "fixture-simulator.ipa"
    with zipfile.ZipFile(ipa, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(app.rglob("*")):
            if path.is_file():
                archive.write(path, str(path.relative_to(output)))
    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sdk", type=Path, default=Path(os.environ.get("ANDROID_HOME", Path.home() / "Library/Android/sdk"))
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--platform", choices=["android", "ios"], default="android")
    parser.add_argument("--retained", action="store_true")
    parser.add_argument("--switch-account", action="store_true")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    print(
        android(args.sdk, args.out)
        if args.platform == "android"
        else ios(args.out, args.retained, args.switch_account)
    )


if __name__ == "__main__":
    main()
