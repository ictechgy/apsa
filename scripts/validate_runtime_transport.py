#!/usr/bin/env python3
"""Compile NEW apps, install only on NEW CI devices and retain digest-only evidence.

Networking and device operations are exclusive to a disposable GitHub runner.
Never select booted/default devices or enumerate apps, accounts, logs or state.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import plistlib
import re
import shlex
import shutil
import subprocess
import time
import uuid
import zipfile
from pathlib import Path
from urllib.request import ProxyHandler, Request, build_opener

from mobile_audit.core import digest
from mobile_audit.runtime_acquisition import AcquisitionRecorder, evaluate_backend_invalidation
from mobile_audit.runtime_evidence import build_binding, evaluate_workflow
from mobile_audit.runtime_transport import AuthorityServer, InstalledTransportAdapter, OwnedAuthority

SOURCES = Path(__file__).resolve().parents[1] / "tests/fixtures/runtime/transport"
MAX_OUTPUT = 64 * 1024 * 1024


class OwnedResources:
    """Crash-surviving journal for this NEW runner directory, never device discovery."""

    def __init__(self, root: Path, *, load: bool = False):
        self.root, self.path = root, root / "owned-resources.json"
        identity = {
            "root": str(root),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "commit": os.environ.get("GITHUB_SHA"),
        }
        if load:
            self.value = json.loads(self.path.read_text())
            if any(self.value.get(key) != value for key, value in identity.items()):
                raise ValueError("Owned resource journal identity differs")
        else:
            self.value = {**identity, "android": None, "ios": {}}
            self.save()

    def save(self):
        temporary = self.path.with_suffix(".new")
        temporary.write_text(json.dumps(self.value, sort_keys=True) + "\n")
        temporary.replace(self.path)

    def android(self, **changes):
        self.value["android"] = {**(self.value["android"] or {}), **changes}
        self.save()

    def ios(self, device: str, *, deleted: bool = False):
        device = str(uuid.UUID(device)).upper()
        self.value["ios"][device] = {"deleted": deleted}
        self.save()


def cleanup_owned(root: Path, commands: "Commands", resources: OwnedResources) -> dict:
    """Idempotent fallback, only explicitly journaled new resources and paths."""
    results = []
    android = resources.value["android"]
    if android:
        if not re.fullmatch(r"apsa-new-[a-f0-9]{32}", android.get("avd", "")):
            raise ValueError("Owned resource journal Android name differs")
        sdk = Path(android["sdk"])
        commands.env.update(
            ANDROID_AVD_HOME=str(root / "avd"),
            ANDROID_USER_HOME=str(root / "android-user"),
            ANDROID_EMULATOR_HOME=str(root / "emulator-home"),
            ANDROID_ADB_SERVER_PORT="5049",
            ADB_SERVER_SOCKET="tcp:127.0.0.1:5049",
        )
        if android.get("emulator") and not android.get("emulator_closed"):
            commands.run(
                [str(sdk / "platform-tools/adb"), "-P", "5049", "-s", "emulator-5580", "emu", "kill"],
                optional=True,
            )
            results.append(
                {
                    "scope": "owned emulator serial on isolated adb port",
                    "state": "confirmed" if commands.last_status == 0 else "unconfirmed",
                }
            )
            if commands.last_status == 0:
                resources.android(emulator_closed=True)
        if android.get("adb") and not android.get("adb_closed"):
            commands.run([str(sdk / "platform-tools/adb"), "-P", "5049", "kill-server"], optional=True)
            results.append(
                {
                    "scope": "isolated adb port 5049",
                    "state": "confirmed" if commands.last_status == 0 else "unconfirmed",
                }
            )
            if commands.last_status == 0:
                resources.android(adb_closed=True)
    for device, record in resources.value["ios"].items():
        if str(uuid.UUID(device)).upper() != device:
            raise ValueError("Owned resource journal simulator UUID differs")
        if record["deleted"]:
            continue
        # The simulator belongs to this fresh device set, including after driver death.
        prefix = ["/usr/bin/xcrun", "simctl", "--set", str(root / "simulator-set")]
        commands.run(prefix + ["shutdown", device], optional=True)
        commands.run(prefix + ["delete", device], optional=True)
        confirmed = commands.last_status == 0 or not (root / "simulator-set" / device).exists()
        results.append(
            {
                "scope": "owned new simulator UUID",
                "uuid": device,
                "state": "confirmed" if confirmed else "unconfirmed",
            }
        )
        if confirmed:
            resources.ios(device, deleted=True)
    state = "confirmed" if all(item["state"] == "confirmed" for item in results) else "unconfirmed"
    if state == "confirmed":
        # Exact owned names only; preserve evidence, command digests and ownership journal.
        for name in (
            "avd",
            "android-user",
            "emulator-home",
            "simulator-set",
            "case-0",
            "case-1",
            "case-2",
            "case-3",
        ):
            path = root / name
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)
    return {"scope": "only journaled NEW resources", "state": state, "results": results}


FAILURE_REASONS = {
    "NEW emulator exited before boot": "android-emulator-exited-before-boot",
    "NEW emulator boot timed out": "android-boot-deadline",
    "NEW installed Android APK differs": "android-installed-apk-hash-mismatch",
    "NEW installed Android package path differs": "android-installed-package-path-shape",
    "NEW Android OS URL routing failed": "android-os-url-resolution",
    "NEW Android fixture rejected binding or transport": "android-fixture-binding-or-http",
    "NEW Android response challenge timed out": "android-app-response-deadline",
    "NEW installed iOS executable differs": "ios-installed-executable-hash-mismatch",
    "NEW simulator container UUID differs": "ios-container-uuid-mismatch",
    "NEW iOS fixture rejected binding or transport": "ios-fixture-binding-or-http",
    "NEW iOS OS URL response challenge timed out": "ios-app-response-deadline",
    "NEW iOS fixture launch timed out": "ios-fixture-launch-deadline",
    "Installed fixture transition unsupported": "installed-session-or-transition-unavailable",
    "Installed fixture target/build/transport response differs": "installed-target-build-transport-mismatch",
    "Installed fixture HTTP/session initialization differs": "installed-session-or-http-initialization",
    "Installed fixture logout delivery/HTTP authority differs": "installed-logout-or-http-binding",
    "Installed fixture capture challenge/state differs": "installed-capture-challenge-or-state",
    "Owned authority replay challenge/status differs": "http-replay-challenge-or-status",
    "Installed fixture session acquisition inconclusive": "installed-session-acquisition-inconclusive",
    "Installed fixture baseline acquisition inconclusive": "installed-baseline-acquisition-inconclusive",
    "Installed fixture after acquisition inconclusive": "installed-after-acquisition-inconclusive",
}


def command_kind(argv: list[str]) -> str:
    """Fixed operation labels only; arbitrary command data never enters logs."""
    tool = Path(argv[0]).name
    if tool == "avdmanager":
        return "android-avd-create" if "create" in argv else "android-avd-delete"
    if tool == "emulator":
        return "android-emulator-launch"
    if tool == "adb":
        if "install" in argv:
            return "android-app-install"
        if "run-as" in argv:
            return "android-app-response-read"
        if "cat" in argv:
            return "android-installed-apk-read"
        if "shell" in argv:
            tail = argv[argv.index("shell") + 1 :]
            if tail and tail[0].startswith("am start "):
                return "android-os-url-delivery"
            if "getprop" in tail:
                return "android-boot-status"
            if "pm" in tail:
                return "android-installed-package-path"
        return "android-adb-control"
    if tool == "xcrun" and "simctl" in argv:
        operations = {
            "create",
            "boot",
            "bootstatus",
            "install",
            "get_app_container",
            "openurl",
            "launch",
            "shutdown",
            "delete",
        }
        return "ios-simctl-" + next((part for part in argv if part in operations), "unsupported")
    if tool in {"javac", "d8", "aapt2", "keytool", "zipalign", "apksigner", "codesign"}:
        return "build-" + tool
    if tool == "xcrun" and "swiftc" in argv:
        return "build-swiftc"
    return "public-tool-command"


class CommandFailure(ValueError):
    def __init__(self, reason: str, observation: dict):
        self.reason, self.observation = reason, observation
        super().__init__(reason)


class FixtureFailure(ValueError):
    def __init__(self, reason: str, observation: dict):
        self.observation = observation
        super().__init__(reason)


def safe_command_observation(record: dict) -> dict:
    allowed = {
        "operation",
        "status",
        "timed_out",
        "elapsed_seconds",
        "stdout_sha256",
        "stdout_bytes",
        "stderr_sha256",
        "stderr_bytes",
        "argv_sha256",
        "errno",
        "process_status",
        "output",
    }
    return {key: value for key, value in record.items() if key in allowed}


def failure_observation(error: Exception, stage: str, records: list[dict]) -> dict:
    command_reasons = {
        "command-spawn-os-error",
        "command-timeout",
        "command-output-bound",
        "command-nonzero-status",
    }
    reason = (
        error.reason
        if isinstance(error, CommandFailure) and error.reason in command_reasons
        else FAILURE_REASONS.get(str(error), "fixture-validation-unclassified")
    )
    error_type = type(error).__name__
    if error_type not in {
        "CommandFailure",
        "FixtureFailure",
        "ValueError",
        "FileNotFoundError",
        "PermissionError",
        "OSError",
        "TimeoutExpired",
        "HTTPError",
        "URLError",
    }:
        error_type = "other-validation-error"
    observation = {
        "exception_type": error_type,
        "reason": reason,
        "stage": stage,
        "errno": error.errno if isinstance(error, OSError) else None,
        "recent_commands": [safe_command_observation(record) for record in records[-16:]],
        "owned_processes": [
            safe_command_observation(record)
            for record in records
            if record.get("operation") == "android-emulator-launch"
        ],
    }
    if isinstance(error, FixtureFailure):
        observation["fixture"] = error.observation
    return observation


class Commands:
    def __init__(self, root: Path, env: dict | None = None, *, output_name: str = "commands.json"):
        self.root, self.env = root, os.environ.copy() if env is None else env
        self.output_name = output_name
        self.records: list[dict] = []
        self.last_status: int | None = None
        self.pre_cleanup_failure: dict | None = None
        self.resources: OwnedResources | None = None

    def run(
        self, argv: list[str], *, input: bytes | None = None, timeout: int = 120, optional: bool = False
    ) -> bytes:
        started = time.monotonic()
        timed_out = False
        try:
            result = subprocess.run(
                argv, input=input, capture_output=True, timeout=timeout, env=self.env, cwd=self.root
            )
            status, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            timed_out = True
            status = None
            stdout = error.stdout if isinstance(error.stdout, bytes) else b""
            stderr = error.stderr if isinstance(error.stderr, bytes) else b""
        except OSError as error:
            record = {
                "operation": command_kind(argv),
                "argv_sha256": digest(json.dumps(argv).encode()),
                "status": None,
                "errno": error.errno,
                "timed_out": False,
            }
            self.records.append(record)
            (self.root / self.output_name).write_text(json.dumps(self.records, indent=2) + "\n")
            raise CommandFailure("command-spawn-os-error", safe_command_observation(record)) from None
        self.last_status = status
        self.records.append(
            {
                "argv_sha256": digest(json.dumps(argv).encode()),
                "operation": command_kind(argv),
                "status": status,
                "timed_out": timed_out,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "stdout_sha256": digest(stdout),
                "stdout_bytes": len(stdout),
                "stderr_sha256": digest(stderr),
                "stderr_bytes": len(stderr),
            }
        )
        (self.root / self.output_name).write_text(json.dumps(self.records, indent=2) + "\n")
        if timed_out or len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT or (status and not optional):
            reason = (
                "command-timeout"
                if timed_out
                else "command-output-bound"
                if len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT
                else "command-nonzero-status"
            )
            observation = safe_command_observation(self.records[-1])
            print(json.dumps({"runtime_command_failure": {"reason": reason, **observation}}), flush=True)
            raise CommandFailure(reason, observation)
        return stdout


def build_android(
    root: Path,
    package: str,
    sdk: Path,
    jdk: Path,
    commands: Commands,
    api: int = 35,
    build_tools: str = "35.0.0",
) -> Path:
    root.mkdir()
    source = root / "TransportActivity.java"
    source.write_bytes((SOURCES / source.name).read_bytes())
    android = sdk / f"platforms/android-{api}/android.jar"
    tools = sdk / "build-tools" / build_tools
    manifest = root / "AndroidManifest.xml"
    manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}" android:versionCode="1" android:versionName="1.0">
      <uses-sdk android:minSdkVersion="28" android:targetSdkVersion="35"/><uses-permission android:name="android.permission.INTERNET"/>
      <application android:debuggable="true" android:usesCleartextTraffic="true" android:label="APSA NEW fixture">
        <activity android:name="apsa.fixture.transport.TransportActivity" android:exported="true" android:launchMode="singleTask">
          <intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/>
            <category android:name="android.intent.category.BROWSABLE"/><data android:scheme="apsatransport" android:host="fixture"/></intent-filter>
        </activity></application></manifest>''')
    classes, dex = root / "classes", root / "dex"
    classes.mkdir()
    dex.mkdir()
    commands.run(
        [
            str(jdk / "bin/javac"),
            "-source",
            "17",
            "-target",
            "17",
            "-classpath",
            str(android),
            "-d",
            str(classes),
            str(source),
        ]
    )
    commands.run(
        [
            str(tools / "d8"),
            "--lib",
            str(android),
            "--min-api",
            "28",
            "--output",
            str(dex),
            str(classes / "apsa/fixture/transport/TransportActivity.class"),
        ]
    )
    unsigned = root / "unsigned.apk"
    commands.run(
        [str(tools / "aapt2"), "link", "-o", str(unsigned), "--manifest", str(manifest), "-I", str(android)]
    )
    with zipfile.ZipFile(unsigned, "a") as archive:
        archive.write(dex / "classes.dex", "classes.dex")
    key = root / "new-synthetic-key.p12"
    commands.run(
        [
            str(jdk / "bin/keytool"),
            "-genkeypair",
            "-keystore",
            str(key),
            "-storepass",
            "synthetic-only",
            "-keypass",
            "synthetic-only",
            "-alias",
            "new-fixture",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "2",
            "-dname",
            "CN=NEW APSA synthetic fixture",
            "-noprompt",
        ]
    )
    aligned, apk = root / "aligned.apk", root / "fixture.apk"
    commands.run([str(tools / "zipalign"), "-p", "4", str(unsigned), str(aligned)])
    commands.run(
        [
            str(tools / "apksigner"),
            "sign",
            "--ks",
            str(key),
            "--ks-pass",
            "pass:synthetic-only",
            "--out",
            str(apk),
            str(aligned),
        ]
    )
    commands.run([str(tools / "apksigner"), "verify", "--verbose", str(apk)])
    return apk


class NewAndroidDevice:
    def __init__(self, root: Path, sdk: Path, commands: Commands):
        self.root, self.sdk, self.commands = root, sdk, commands
        self.serial = "emulator-5580"
        self.process: subprocess.Popen | None = None
        self.avd_created = False
        self.adb_started = False
        self.adb_prefix = [str(sdk / "platform-tools/adb"), "-P", "5049", "-s", self.serial]
        self.name = "apsa-new-" + uuid.uuid4().hex
        self.env = commands.env
        self.env.update(
            ANDROID_AVD_HOME=str(root / "avd"),
            ANDROID_USER_HOME=str(root / "android-user"),
            ANDROID_EMULATOR_HOME=str(root / "emulator-home"),
            ANDROID_ADB_SERVER_PORT="5049",
            ADB_SERVER_SOCKET="tcp:127.0.0.1:5049",
        )
        for name in ("avd", "android-user", "emulator-home"):
            (root / name).mkdir()
        if commands.resources:
            commands.resources.android(avd=self.name, sdk=str(sdk))

    def start(self):
        sdk = self.sdk
        self.commands.run(
            [
                str(sdk / "cmdline-tools/latest/bin/avdmanager"),
                "create",
                "avd",
                "--name",
                self.name,
                "--package",
                "system-images;android-35;google_apis;x86_64",
                "--device",
                "pixel",
            ],
            input=b"no\n",
        )
        self.avd_created = True
        if self.commands.resources:
            self.commands.resources.android(adb=True)
        self.commands.run([str(sdk / "platform-tools/adb"), "-P", "5049", "start-server"])
        self.adb_started = True
        argv = [
            str(sdk / "emulator/emulator"),
            "-avd",
            self.name,
            "-port",
            "5580",
            "-no-window",
            "-no-audio",
            "-no-snapshot",
            "-wipe-data",
            "-gpu",
            "software",
            "-no-boot-anim",
        ]
        self.commands.records.append(
            {
                "argv_sha256": digest(json.dumps(argv).encode()),
                "operation": "android-emulator-launch",
                "scope": "new-owned-avd",
                "output": "discarded-no-raw-logs",
            }
        )
        process_record = self.commands.records[-1]
        if self.commands.resources:
            self.commands.resources.android(emulator=True)
        self.process = subprocess.Popen(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=self.env
        )
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                process_record["process_status"] = self.process.returncode
                raise ValueError("NEW emulator exited before boot")
            result = self.commands.run(
                self.adb_prefix + ["shell", "getprop", "sys.boot_completed"], optional=True, timeout=10
            )
            if result.strip() == b"1":
                return
            time.sleep(2)
        raise ValueError("NEW emulator boot timed out")

    def close(self):
        if self.process is not None:
            try:
                # Ask only our serial on our port to stop its emulator children cleanly.
                self.commands.run(self.adb_prefix + ["emu", "kill"], timeout=15, optional=True)
                self.process.wait(timeout=15)
            except (CommandFailure, subprocess.TimeoutExpired):
                self.process.terminate()
                try:
                    self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=15)
            self.process = None
            if self.commands.resources:
                self.commands.resources.android(emulator_closed=True)
        statuses = []
        if self.adb_started:
            self.commands.run(
                [str(self.sdk / "platform-tools/adb"), "-P", "5049", "kill-server"], optional=True
            )
            statuses.append(self.commands.last_status)
            if self.commands.last_status == 0 and self.commands.resources:
                self.commands.resources.android(adb_closed=True)
        # All AVD state lives within the NEW driver root; delete this name only.
        if self.avd_created:
            self.commands.run(
                [str(self.sdk / "cmdline-tools/latest/bin/avdmanager"), "delete", "avd", "--name", self.name],
                optional=True,
            )
            statuses.append(self.commands.last_status)
        return {
            "scope": "only NEW AVD and isolated adb server",
            "avd": self.name,
            "state": "confirmed" if all(status == 0 for status in statuses) else "unconfirmed",
        }


class AndroidTarget:
    platform = "android"

    def __init__(self, package: str, apk: Path, device: NewAndroidDevice):
        self.package, self.device = package, device
        self.build = {"apk_sha256": digest(apk.read_bytes())}
        self.commands = device.commands
        self.commands.run(device.adb_prefix + ["install", "--no-streaming", str(apk)])
        if self.installed_build() != self.build:
            raise ValueError("NEW installed Android APK differs")

    def installed_build(self):
        raw = (
            self.commands.run(self.device.adb_prefix + ["shell", "pm", "path", self.package]).decode().strip()
        )
        if not re.fullmatch(r"package:/data/app/[^\r\n]+/base\.apk", raw):
            raise ValueError("NEW installed Android package path differs")
        payload = self.commands.run(
            self.device.adb_prefix + ["exec-out", "cat", raw.removeprefix("package:")]
        )
        return {"apk_sha256": digest(payload)}

    def deliver(self, url: str, expected: dict) -> dict:
        # Package filter still asks the OS intent resolver to route the registered URL.
        shell = shlex.join(
            [
                "am",
                "start",
                "-W",
                "-a",
                "android.intent.action.VIEW",
                "-c",
                "android.intent.category.BROWSABLE",
                "-d",
                url,
                "-p",
                self.package,
            ]
        )
        output = self.commands.run(self.device.adb_prefix + ["shell", shell])
        if b"Error:" in output or b"unable to resolve" in output:
            raise ValueError("NEW Android OS URL routing failed")
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            raw = self.commands.run(
                self.device.adb_prefix + ["exec-out", "run-as", self.package, "cat", "files/response.json"],
                optional=True,
            )
            if raw and len(raw) <= 1024 * 1024:
                try:
                    response = json.loads(raw)
                    if response.get("action") == "fixture-error":
                        raise ValueError("NEW Android fixture rejected binding or transport")
                    if all(
                        response.get(k) == v for k, v in expected.items() if k not in {"backend", "retain"}
                    ):
                        return response
                except json.JSONDecodeError:
                    pass
            time.sleep(0.1)
        raise ValueError("NEW Android response challenge timed out")

    def close(self):
        self.commands.run(self.device.adb_prefix + ["uninstall", self.package], optional=True)
        return {
            "scope": "only NEW app",
            "package": self.package,
            "state": "confirmed" if self.commands.last_status == 0 else "unconfirmed",
        }


class IosTarget:
    platform = "ios"

    def __init__(self, root: Path, package: str, commands: Commands, runtime: str, device_type: str):
        self.package, self.commands, self.device = package, commands, None
        device_set = commands.root / "simulator-set"
        device_set.mkdir(exist_ok=True)
        self.simctl = ["/usr/bin/xcrun", "simctl", "--set", str(device_set)]
        root.mkdir()
        source = root / "Transport.swift"
        source.write_bytes((SOURCES / source.name).read_bytes())
        self.app = root / "TransportFixture.app"
        self.app.mkdir()
        sdk = commands.run(["/usr/bin/xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"]).decode().strip()
        arch = "arm64" if platform.machine() == "arm64" else "x86_64"
        commands.run(
            [
                "/usr/bin/xcrun",
                "swiftc",
                "-swift-version",
                "5",
                "-sdk",
                sdk,
                "-target",
                arch + "-apple-ios18.0-simulator",
                "-parse-as-library",
                "-module-name",
                "TransportFixture",
                str(source),
                "-o",
                str(self.app / "TransportFixture"),
                "-module-cache-path",
                str(root / "module-cache"),
            ]
        )
        (self.app / "Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "CFBundleExecutable": "TransportFixture",
                    "CFBundleIdentifier": package,
                    "CFBundleName": "TransportFixture",
                    "CFBundlePackageType": "APPL",
                    "CFBundleVersion": "1",
                    "CFBundleShortVersionString": "1.0",
                    "MinimumOSVersion": "18.0",
                    "LSRequiresIPhoneOS": True,
                    "UIDeviceFamily": [1, 2],
                    "UILaunchScreen": {},
                    "CFBundleURLTypes": [{"CFBundleURLSchemes": ["apsatransport"]}],
                    "NSAppTransportSecurity": {
                        "NSAllowsLocalNetworking": True,
                        "NSAllowsArbitraryLoads": True,
                    },
                    "UIApplicationSceneManifest": {
                        "UIApplicationSupportsMultipleScenes": False,
                        "UISceneConfigurations": {
                            "UIWindowSceneSessionRoleApplication": [
                                {
                                    "UISceneConfigurationName": "Default",
                                    "UISceneDelegateClassName": "TransportFixture.SceneDelegate",
                                }
                            ]
                        },
                    },
                }
            )
        )
        commands.run(["/usr/bin/codesign", "--force", "--sign", "-", str(self.app)])
        commands.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(self.app)])
        self.build = {
            "executable_sha256": digest((self.app / "TransportFixture").read_bytes()),
            "info_plist_sha256": digest((self.app / "Info.plist").read_bytes()),
        }
        created = (
            commands.run(self.simctl + ["create", "APSA-NEW-" + uuid.uuid4().hex, device_type, runtime])
            .decode()
            .strip()
        )
        self.device = str(uuid.UUID(created)).upper()
        if commands.resources:
            commands.resources.ios(self.device)
        try:
            commands.run(self.simctl + ["boot", self.device])
            commands.run(self.simctl + ["bootstatus", self.device, "-b"], timeout=180)
            commands.run(self.simctl + ["install", self.device, str(self.app)])
            self.installed = self.container("app")
            self.response = self.container("data") / "Documents/response.json"
            self.stage_path = self.response.with_name("stage.txt")
            if self.installed_build() != self.build:
                raise ValueError("NEW installed iOS executable differs")
            # Establish a ready NEW scene before delivering the session URL through the OS.
            commands.run(self.simctl + ["launch", self.device, self.package])
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if self.stage_path.is_file() and self.stage_path.read_bytes() == b"startup-scene":
                    break
                time.sleep(0.1)
            else:
                raise FixtureFailure("NEW iOS fixture launch timed out", self.lifecycle_observation())
        except Exception as error:
            commands.pre_cleanup_failure = failure_observation(
                error, "ios-target-create-boot-install", commands.records
            )
            try:
                self.close()
            except (ValueError, OSError, subprocess.SubprocessError):
                commands.pre_cleanup_failure["constructor_cleanup"] = "unconfirmed"
            raise

    def container(self, kind: str) -> Path:
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        path = Path(
            self.commands.run(self.simctl + ["get_app_container", self.device, self.package, kind])
            .decode()
            .strip()
        )
        if not path.is_absolute() or self.device not in path.parts:
            raise ValueError("NEW simulator container UUID differs")
        return path

    def installed_build(self):
        return {
            "executable_sha256": digest((self.installed / "TransportFixture").read_bytes()),
            "info_plist_sha256": digest((self.installed / "Info.plist").read_bytes()),
        }

    def lifecycle_observation(self):
        raw = (
            self.stage_path.read_bytes()
            if self.stage_path.is_file() and self.stage_path.stat().st_size <= 4096
            else b""
        )
        allowed = {
            "startup-app",
            "startup-scene",
            "url-received",
            "http-issue",
            "http-logout",
            "response-written",
            "binding-or-transport-failure",
        }
        stage = raw.decode("ascii", errors="replace")
        return {
            "response_file_present": self.response.is_file(),
            "lifecycle_stage": stage if stage in allowed else "not-observed",
            "stage_sha256": digest(raw),
            "stage_bytes": len(raw),
        }

    def deliver(self, url: str, expected: dict) -> dict:
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        self.commands.run(self.simctl + ["openurl", self.device, url])
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if self.response.is_file() and self.response.stat().st_size <= 1024 * 1024:
                try:
                    response = json.loads(self.response.read_bytes())
                    if response.get("action") == "fixture-error":
                        raise FixtureFailure(
                            "NEW iOS fixture rejected binding or transport", self.lifecycle_observation()
                        )
                    if all(
                        response.get(k) == v for k, v in expected.items() if k not in {"backend", "retain"}
                    ):
                        return response
                except json.JSONDecodeError:
                    pass
            time.sleep(0.1)
        raise FixtureFailure("NEW iOS OS URL response challenge timed out", self.lifecycle_observation())

    def close(self):
        if self.device:
            device, self.device = self.device, None
            self.commands.run(self.simctl + ["shutdown", device], optional=True)
            self.commands.run(self.simctl + ["delete", device], optional=True)
            if self.commands.last_status == 0 and self.commands.resources:
                self.commands.resources.ios(device, deleted=True)
            return {
                "scope": "only NEW simulator UUID",
                "uuid": device,
                "state": "confirmed" if self.commands.last_status == 0 else "unconfirmed",
            }
        return {"scope": "no remaining owned UUID", "state": "confirmed"}


def scenario(platform_name: str, package: str) -> dict:
    return {
        "schema_version": 2,
        "platform": platform_name,
        "package": package,
        "markers": {key: "synthetic-unique-" + key for key in ("a", "login_a", "state", "delivery")},
        "workflow": {
            "accounts": {
                "a": {
                    "canary": "a",
                    "login_marker": "login_a",
                    "canary_surface": "storage",
                    "login_surface": "storage",
                }
            },
            "transitions": [
                {
                    "kind": "logout",
                    "from_account": "a",
                    "to_account": None,
                    "baseline": "before",
                    "snapshot": "after",
                    "state_marker": "state",
                    "delivery_marker": "delivery",
                    "surface": "storage",
                }
            ],
        },
    }


def execute_case(target, *, invalidate: bool, retain: bool) -> dict:
    value = scenario(target.platform, target.package)
    key = "apk_sha256" if target.platform == "android" else "executable_sha256"
    authority = OwnedAuthority(target.package, target.build[key], invalidate=invalidate)
    server = AuthorityServer(authority)
    try:
        adapter = InstalledTransportAdapter(target, server, retain=retain)
        binding = build_binding(target.platform, target.package, target.build)
        recorder = AcquisitionRecorder(adapter, binding, value["markers"])
        if recorder.session is None:
            raise adapter.acquisition_error or ValueError(
                "Installed fixture session acquisition inconclusive"
            )
        before = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
        if before.get("acquisition", {}).get("capture_errors"):
            raise adapter.acquisition_error or ValueError(
                "Installed fixture baseline acquisition inconclusive"
            )
        adapter.open_url("synthetic://transition")
        after = recorder.capture("after", {"account": None, "state": "logged_out"}, "logout")
        if after.get("acquisition", {}).get("capture_errors"):
            raise adapter.acquisition_error or ValueError("Installed fixture after acquisition inconclusive")
        snapshots = {"before": before, "after": after}
        backend = evaluate_backend_invalidation(value, snapshots)
        workflow = evaluate_workflow(value, snapshots, recorder.binding)
        local_complete = all(
            s.get("surfaces", {}).get("storage", {}).get("state") == "captured" for s in (before, after)
        )
        residual = any(
            m["marker_label"] == "a" and m["surface"] == "storage" for m in after.get("matches", [])
        )
        storage = [
            {
                "state": ("failed" if residual else "passed")
                if local_complete and workflow[0]["state"] == "passed"
                else "inconclusive",
                "scope": "old account canary in NEW fixture state.dat only",
            }
        ]
        expected_backend, expected_storage = (
            ("passed" if invalidate else "failed"),
            ("failed" if retain else "passed"),
        )
        verified = (
            backend[0]["state"] == expected_backend
            and storage[0]["state"] == expected_storage
            and workflow[0]["state"] == "passed"
        )
        return {
            "state": "passed" if verified else "inconclusive",
            "fixture_policy": {"invalidate": invalidate, "retain": retain},
            "platform": target.platform,
            "package": target.package,
            "installed_build": target.build,
            "installed": True,
            "physical_device_verified": False,
            "delivery_transport": adapter.delivery_transport,
            "storage_scope": "only NEW fixture state.dat",
            "network_scope": "only owned synthetic HTTP protected endpoint; replay sent separately by driver",
            "ui": "unsupported",
            "logs": "unsupported",
            "backend": backend,
            "storage": storage,
            "workflow": workflow,
            "snapshots": snapshots,
            "authority_events": authority.events,
        }
    finally:
        server.close()


def execute_backend_cases() -> list[dict]:
    """Real HTTP fallback proof, explicitly without installed-app or OS delivery claims."""
    results = []
    for invalidate in (True, False):
        authority = OwnedAuthority(
            "apsa.fixture.backend", digest(b"NEW synthetic HTTP-only client"), invalidate=invalidate
        )
        authority.bind(uuid.uuid4().hex + uuid.uuid4().hex)
        server = AuthorityServer(authority)
        try:
            body = json.dumps(
                {"session": authority.session, "package": authority.package, "build": authority.build}
            ).encode()
            opener = build_opener(ProxyHandler({}))
            request = Request(
                server.endpoint + "/issue",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with opener.open(request, timeout=10) as response:
                issued = json.loads(response.read(4097))
                if response.status != 200 or issued.get("credential") != authority.credential:
                    raise ValueError("HTTP-only client credential issuance differs")
            before = server.replay(uuid.uuid4().hex + uuid.uuid4().hex)
            request = Request(
                server.endpoint + "/logout",
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + authority.credential,
                },
                method="POST",
            )
            with opener.open(request, timeout=10) as response:
                if (
                    response.status != 200
                    or json.loads(response.read(4097)).get("outcome") != "logout-observed"
                ):
                    raise ValueError("HTTP-only client logout differs")
            after = server.replay(uuid.uuid4().hex + uuid.uuid4().hex)

            def record(probe):
                return {
                    "authority_sha256": probe.authority_sha256,
                    "credential_sha256": probe.credential_sha256,
                    "outcome": probe.outcome,
                    "request_sha256": digest(probe.request),
                    "response_sha256": digest(probe.response),
                    "request_bytes": len(probe.request),
                    "response_bytes": len(probe.response),
                }

            verified = (
                before.outcome == "accepted"
                and after.outcome == ("rejected" if invalidate else "accepted")
                and before.credential_sha256 == after.credential_sha256
                and before.authority_sha256 == after.authority_sha256
            )
            results.append(
                {
                    "state": "passed" if verified else "inconclusive",
                    "invalidate": invalidate,
                    "scope": "owned synthetic authority; actual separate HTTP issue/logout/replay requests only",
                    "installed_app": "unsupported",
                    "os_delivery": "unsupported",
                    "probes": [record(before), record(after)],
                    "authority_events": authority.events,
                }
            )
        finally:
            server.close()
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("android", "ios", "backend"), required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--jdk", type=Path)
    parser.add_argument("--ios-runtime", default="com.apple.CoreSimulator.SimRuntime.iOS-18-5")
    parser.add_argument("--ios-device-type", default="com.apple.CoreSimulator.SimDeviceType.iPhone-16")
    args = parser.parse_args()
    # Never offer a flag that lets local workspace execution bypass this boundary.
    if (
        os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("CI") != "true"
        or not os.environ.get("RUNNER_TEMP")
    ):
        parser.error("Device/HTTP execution requires a disposable GitHub Actions runner")
    root = args.work.resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    if root == runner_temp or not root.is_relative_to(runner_temp):
        parser.error("NEW work directory must lie within RUNNER_TEMP")
    if args.cleanup_only:
        if not root.exists():
            print(json.dumps({"cleanup": "confirmed", "scope": "no NEW work directory"}))
            return
        commands = Commands(root, output_name="cleanup-commands.json")
        result: dict = {"state": "unconfirmed", "scope": "only journaled NEW resources"}
        try:
            resources = OwnedResources(root, load=True)
            result = cleanup_owned(root, commands, resources)
        except Exception as error:
            result["failure_observation"] = failure_observation(
                error, "workflow-owned-cleanup", commands.records
            )
        finally:
            # Also produce terminal evidence if the driver was killed before its finally block.
            evidence_path = root / "evidence.json"
            try:
                evidence = json.loads(evidence_path.read_text()) if evidence_path.is_file() else {}
                if not isinstance(evidence, dict):
                    evidence = {}
            except (OSError, ValueError):
                evidence = {}
            if evidence.get("terminal") is not True:
                evidence["state"] = "inconclusive"
                evidence["failure_observation"] = {"reason": "driver-terminal-evidence-unavailable"}
            evidence.update(
                terminal=True, commit=os.environ.get("GITHUB_SHA"), run_id=os.environ.get("GITHUB_RUN_ID")
            )
            evidence["workflow_cleanup"] = result
            if result["state"] != "confirmed":
                evidence["state"] = "inconclusive"
            evidence_path.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
            (root / "cleanup.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
        print(json.dumps({"workflow_cleanup": result}), flush=True)
        if result["state"] != "confirmed":
            raise SystemExit(1)
        return
    root.mkdir(exist_ok=False)
    commands = Commands(root)
    commands.resources = OwnedResources(root)
    evidence = {
        "schema_version": 1,
        "state": "inconclusive",
        "terminal": False,
        "platform": args.platform,
        "commit": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "source_sha256": {
            path.name: digest(path.read_bytes())
            for path in (
                SOURCES / "Transport.swift",
                SOURCES / "TransportActivity.java",
                Path(__file__).resolve(),
                Path(__file__).parents[1] / "src/mobile_audit/runtime_transport.py",
            )
        },
        "scope": "NEW synthetic apps/devices only; no physical device or real backend claim",
        "cases": [],
        "cleanup": "not-run",
        "cleanup_results": [],
    }
    device = None
    stage = "initialization"
    (root / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    try:
        if args.platform == "backend":
            stage = "backend-http-controls"
            evidence["cases"] = execute_backend_cases()
            evidence["state"] = (
                "passed" if all(case["state"] == "passed" for case in evidence["cases"]) else "inconclusive"
            )
            print(json.dumps({"state": evidence["state"], "cases": len(evidence["cases"])}))
            raise SystemExit(0 if evidence["state"] == "passed" else 1)
        if args.platform == "android":
            if not args.sdk or not args.jdk:
                parser.error("Android requires explicit SDK and JDK source tool paths")
            commands.env["JAVA_HOME"] = str(args.jdk.resolve())
            device = NewAndroidDevice(root, args.sdk.resolve(), commands)
            stage = "android-avd-create-and-boot"
            device.start()
            evidence["new_device"] = {"avd": device.name, "serial": device.serial, "adb_server_port": 5049}
        for index, (invalidate, retain) in enumerate(
            ((True, False), (True, True), (False, False), (False, True))
        ):
            package = "apsa.fixture.c" + uuid.uuid4().hex + ".case" + str(index)
            target = None
            try:
                case_root = root / ("case-" + str(index))
                if device:
                    stage = "android-case-" + str(index) + "-compile"
                    apk = build_android(case_root, package, args.sdk.resolve(), args.jdk.resolve(), commands)
                    stage = "android-case-" + str(index) + "-install"
                    target = AndroidTarget(package, apk, device)
                else:
                    stage = "ios-case-" + str(index) + "-compile-create-install"
                    target = IosTarget(case_root, package, commands, args.ios_runtime, args.ios_device_type)
                stage = args.platform + "-case-" + str(index) + "-session-delivery-capture-http"
                result = execute_case(target, invalidate=invalidate, retain=retain)
                if args.platform == "ios":
                    result["new_simulator_uuid"] = target.device
                evidence["cases"].append(result)
            except Exception as error:
                if commands.pre_cleanup_failure is None:
                    commands.pre_cleanup_failure = failure_observation(error, stage, commands.records)
                raise
            finally:
                if target:
                    try:
                        evidence["cleanup_results"].append(target.close())
                    except Exception as error:
                        evidence["cleanup_results"].append({"scope": "NEW target", "state": "unconfirmed"})
                        if commands.pre_cleanup_failure is None:
                            commands.pre_cleanup_failure = failure_observation(error, stage, commands.records)
                (root / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
        evidence["state"] = (
            "passed"
            if len(evidence["cases"]) == 4 and all(case["state"] == "passed" for case in evidence["cases"])
            else "inconclusive"
        )
    except Exception as error:
        evidence["error"] = {
            "type": failure_observation(error, stage, commands.records)["exception_type"],
            "detail": "NEW fixture build/install/transport/capture failed; inspect digest-only command status",
        }
        evidence["failure_observation"] = commands.pre_cleanup_failure or failure_observation(
            error, stage, commands.records
        )
        print(json.dumps({"runtime_failure_observation": evidence["failure_observation"]}), flush=True)
    finally:
        if device:
            try:
                evidence["cleanup_results"].append(device.close())
            except Exception:
                evidence["cleanup_results"].append({"scope": "NEW AVD", "state": "unconfirmed"})
        evidence["cleanup"] = {
            "scope": "only NEW resources",
            "state": "confirmed"
            if all(result["state"] == "confirmed" for result in evidence["cleanup_results"])
            else "unconfirmed",
        }
        if evidence["cleanup"]["state"] != "confirmed":
            evidence["state"] = "inconclusive"
        evidence["commands_sha256"] = digest(json.dumps(commands.records, sort_keys=True).encode())
        evidence["terminal"] = True
        (root / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"state": evidence["state"], "cases": len(evidence["cases"])}))
    if evidence["state"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
