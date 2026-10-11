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


class Commands:
    def __init__(self, root: Path, env: dict | None = None):
        self.root, self.env = root, os.environ.copy() if env is None else env
        self.records: list[dict] = []
        self.last_status: int | None = None

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
        self.last_status = status
        # URL arguments contain fresh nonce/session material. Preserve their digest only.
        redacted = [
            "fresh-url-argument-sha256:" + digest(arg.encode()) if "apsatransport://" in arg else arg
            for arg in argv
        ]
        self.records.append(
            {
                "argv": redacted,
                "status": status,
                "timed_out": timed_out,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "stdout_sha256": digest(stdout),
                "stdout_bytes": len(stdout),
                "stderr_sha256": digest(stderr),
                "stderr_bytes": len(stderr),
            }
        )
        (self.root / "commands.json").write_text(json.dumps(self.records, indent=2) + "\n")
        if timed_out or len(stdout) > MAX_OUTPUT or len(stderr) > MAX_OUTPUT or (status and not optional):
            raise ValueError("Synthetic command failed or exceeded output bound; digest evidence retained")
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
            "swiftshader_indirect",
            "-no-boot-anim",
        ]
        self.commands.records.append(
            {"argv": argv, "scope": "new-owned-avd", "output": "discarded-no-raw-logs"}
        )
        self.process = subprocess.Popen(
            argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=self.env
        )
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
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
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)
            self.process = None
        statuses = []
        if self.adb_started:
            self.commands.run(
                [str(self.sdk / "platform-tools/adb"), "-P", "5049", "kill-server"], optional=True
            )
            statuses.append(self.commands.last_status)
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
            commands.run(
                ["/usr/bin/xcrun", "simctl", "create", "APSA-NEW-" + uuid.uuid4().hex, device_type, runtime]
            )
            .decode()
            .strip()
        )
        self.device = str(uuid.UUID(created)).upper()
        try:
            commands.run(["/usr/bin/xcrun", "simctl", "boot", self.device])
            commands.run(["/usr/bin/xcrun", "simctl", "bootstatus", self.device, "-b"], timeout=180)
            commands.run(["/usr/bin/xcrun", "simctl", "install", self.device, str(self.app)])
            self.installed = self.container("app")
            self.response = self.container("data") / "Documents/response.json"
            if self.installed_build() != self.build:
                raise ValueError("NEW installed iOS executable differs")
        except Exception:
            self.close()
            raise

    def container(self, kind: str) -> Path:
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        path = Path(
            self.commands.run(
                ["/usr/bin/xcrun", "simctl", "get_app_container", self.device, self.package, kind]
            )
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

    def deliver(self, url: str, expected: dict) -> dict:
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        self.commands.run(["/usr/bin/xcrun", "simctl", "openurl", self.device, url])
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            if self.response.is_file() and self.response.stat().st_size <= 1024 * 1024:
                try:
                    response = json.loads(self.response.read_bytes())
                    if response.get("action") == "fixture-error":
                        raise ValueError("NEW iOS fixture rejected binding or transport")
                    if all(
                        response.get(k) == v for k, v in expected.items() if k not in {"backend", "retain"}
                    ):
                        return response
                except json.JSONDecodeError:
                    pass
            time.sleep(0.1)
        raise ValueError("NEW iOS OS URL response challenge timed out")

    def close(self):
        if self.device:
            device, self.device = self.device, None
            self.commands.run(["/usr/bin/xcrun", "simctl", "shutdown", device], optional=True)
            self.commands.run(["/usr/bin/xcrun", "simctl", "delete", device], optional=True)
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
        before = recorder.capture("before", {"account": "a", "state": "authenticated"}, None)
        adapter.open_url("synthetic://transition")
        after = recorder.capture("after", {"account": None, "state": "logged_out"}, "logout")
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
    if not root.is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve()):
        parser.error("NEW work directory must lie within RUNNER_TEMP")
    root.mkdir(exist_ok=False)
    commands = Commands(root)
    evidence = {
        "schema_version": 1,
        "state": "inconclusive",
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
    try:
        if args.platform == "backend":
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
                    apk = build_android(case_root, package, args.sdk.resolve(), args.jdk.resolve(), commands)
                    target = AndroidTarget(package, apk, device)
                else:
                    target = IosTarget(case_root, package, commands, args.ios_runtime, args.ios_device_type)
                result = execute_case(target, invalidate=invalidate, retain=retain)
                if args.platform == "ios":
                    result["new_simulator_uuid"] = target.device
                evidence["cases"].append(result)
            finally:
                if target:
                    evidence["cleanup_results"].append(target.close())
        evidence["state"] = (
            "passed"
            if len(evidence["cases"]) == 4 and all(case["state"] == "passed" for case in evidence["cases"])
            else "inconclusive"
        )
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        evidence["error"] = {
            "type": type(error).__name__,
            "detail": "NEW fixture build/install/transport/capture failed; inspect digest-only command status",
        }
    finally:
        if device:
            try:
                evidence["cleanup_results"].append(device.close())
            except (OSError, ValueError, subprocess.SubprocessError):
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
        (root / "evidence.json").write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"state": evidence["state"], "cases": len(evidence["cases"])}))
    if evidence["state"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
