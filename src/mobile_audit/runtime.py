from __future__ import annotations

import copy
import io
import json
import os
import plistlib
import re
import shlex
import stat
import tarfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import NoReturn

from defusedxml import ElementTree as ET

from .audit import correlate, summarize
from .core import (
    MAX_FILE,
    canonical_json,
    digest,
    file_digest,
    finding,
    now,
    read_bounded,
    read_json,
    read_under,
    redact,
    severity_rank,
    uid,
)
from .intel import source_health
from .processes import command
from .store import Store
from .tools import resolve_tool

MAX_CAPTURE = 64 * 1024 * 1024
MAX_SNAPSHOT_FILES = 4000
PACKAGE = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+")


def devices() -> dict:
    result = {"android": [], "ios_simulators": [], "errors": []}
    if adb := resolve_tool("adb"):
        try:
            for line in command([adb, "devices"]).decode().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 2:
                    result["android"].append({"id": parts[0], "state": parts[1]})
        except ValueError as error:
            result["errors"].append(str(error))
    if xcrun := resolve_tool("xcrun"):
        try:
            value = json.loads(command([xcrun, "simctl", "list", "devices", "available", "--json"]))
            for runtime, items in value.get("devices", {}).items():
                result["ios_simulators"].extend(
                    {"id": d["udid"], "name": d["name"], "state": d["state"], "runtime": runtime}
                    for d in items
                )
        except (ValueError, json.JSONDecodeError) as error:
            result["errors"].append(str(error))
    return result


class Android:
    def __init__(self, package: str, device: str | None):
        self.package = package
        if not device:
            available = [d["id"] for d in devices()["android"] if d["state"] == "device"]
            if len(available) != 1:
                raise ValueError(
                    "Specify device serial; exactly one authorized Android device is required otherwise."
                )
            device = available[0]
        self.prefix = [resolve_tool("adb") or "adb", "-s", device]

    def shell(self, args: list[str], **kwargs) -> bytes:
        return command(self.prefix + ["shell", shlex.join(args)], **kwargs)

    def environment(self) -> dict:
        installed = self.shell(["dumpsys", "package", self.package]).decode(errors="replace")
        if not re.search(r"Package \[" + re.escape(self.package) + r"\]", installed):
            raise ValueError("Audited Android package is not installed")
        paths = self.shell(["pm", "path", self.package]).decode().splitlines()
        base = next((p.removeprefix("package:") for p in paths if p.endswith("/base.apk")), "")
        app = {"package": self.package}
        for key, pattern in [("version_code", r"versionCode=(\d+)"), ("version", r"versionName=([^\s]+)")]:
            match = re.search(pattern, installed)
            app[key] = match[1] if match else ""
        if base and base.startswith("/data/app/"):
            try:
                hash_output = self.shell(["sha256sum", base]).decode().split()
                if hash_output and re.fullmatch(r"[a-f0-9]{64}", hash_output[0]):
                    app["apk_sha256"] = hash_output[0]
            except ValueError:
                pass
        return {
            "platform": "android",
            "version": self.shell(["getprop", "ro.build.version.release"]).decode().strip(),
            "security_patch": self.shell(["getprop", "ro.build.version.security_patch"]).decode().strip(),
            "model": self.shell(["getprop", "ro.product.model"]).decode().strip(),
            "observed_at": now(),
            "app": app,
            "device_id": self.prefix[-1],
        }

    def launch(self):
        self.shell(["monkey", "-p", self.package, "-c", "android.intent.category.LAUNCHER", "1"])

    def open_url(self, url: str):
        response = self.shell(
            ["am", "start", "-W", "-a", "android.intent.action.VIEW", "-d", url, "-p", self.package]
        )
        if b"Error:" in response or b"unable to resolve" in response:
            raise ValueError("The audited package cannot resolve this deep link")
        activity = re.search(rb"Activity:\s+([^\s]+)", response)
        component = activity[1].decode() if activity else ""
        return {
            "delivery": "target-activity-reported"
            if component.split("/")[0] == self.package
            else "requested-not-confirmed",
            "component": component,
        }

    def require_foreground(self):
        state = self.shell(["dumpsys", "activity", "activities"]).decode(errors="replace")
        resumed = re.findall(
            r"(?:mResumedActivity|topResumedActivity).*?\s([A-Za-z0-9_.]+)/(?:[^\s}]+)", state
        )
        if self.package not in resumed:
            raise ValueError("Audited app is not foreground; tap/input would target another app")

    def tap(self, x: int, y: int):
        self.require_foreground()
        self.shell(["input", "tap", str(x), str(y)])

    def input_text(self, text: str):
        self.require_foreground()
        self.shell(["input", "text", text.replace(" ", "%s")])

    def screenshot(self, path: Path):
        data = command(self.prefix + ["exec-out", "screencap", "-p"], max_bytes=MAX_FILE)
        if not data.startswith(b"\x89PNG"):
            raise ValueError("Screenshot was not a PNG")
        path.write_bytes(data)

    def storage(self) -> list[tuple[str, bytes]]:
        raw = command(
            self.prefix + ["exec-out", shlex.join(["run-as", self.package, "tar", "-cf", "-", "."])]
        )
        output = []
        total = 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for index, item in enumerate(archive):
                if index >= MAX_SNAPSHOT_FILES:
                    raise ValueError("Storage file count exceeds limit; snapshot incomplete")
                if item.isfile():
                    total += item.size
                    if total > MAX_CAPTURE:
                        raise ValueError("Storage total byte limit exceeded; snapshot incomplete")
                    if item.size > MAX_FILE:
                        raise ValueError("Storage file exceeds limit; snapshot incomplete")
                    stream = archive.extractfile(item)
                    if stream:
                        output.append((item.name, stream.read(MAX_FILE + 1)))
        return output

    def ui(self) -> bytes:
        # A per-run app-specific remote filename avoids races with other auditors.
        remote = f"/sdcard/{uid('mobile_audit_ui')}.xml"
        try:
            self.shell(["uiautomator", "dump", remote])
            return scoped_android_ui(self.shell(["cat", remote], max_bytes=MAX_FILE), self.package)
        finally:
            try:
                self.shell(["rm", "-f", remote])
            except ValueError:
                pass

    def logs(self) -> bytes:
        pid = self.shell(["pidof", "-s", self.package]).decode().strip()
        if not pid.isdigit():
            raise ValueError("App is not running; cannot scope logs to its process")
        return self.shell(["logcat", "-d", "--pid", pid, "-t", "3000"], max_bytes=MAX_FILE)


class IOS:
    def __init__(self, package: str, device: str | None):
        self.package = package
        if not device:
            booted = [d["id"] for d in devices()["ios_simulators"] if d["state"] == "Booted"]
            if len(booted) != 1:
                raise ValueError("Specify simulator UDID, or boot exactly one iOS simulator.")
            device = booted[0]
        self.device = str(device)

    def simctl(self, args: list[str]) -> bytes:
        return command([resolve_tool("xcrun") or "xcrun", "simctl"] + args)

    def environment(self) -> dict:
        available = devices()["ios_simulators"]
        info = next((d for d in available if d["id"] == self.device), {})
        version = info.get("runtime", "").split("iOS-")[-1].replace("-", ".")
        root = Path(self.simctl(["get_app_container", self.device, self.package, "app"]).decode().strip())
        info_raw = read_bounded(root / "Info.plist")
        info_plist = plistlib.loads(info_raw)
        if info_plist.get("CFBundleIdentifier") != self.package:
            raise ValueError("Simulator installed app identity differs from audited bundle")
        app = {
            "package": self.package,
            "version": info_plist.get("CFBundleShortVersionString", ""),
            "version_code": info_plist.get("CFBundleVersion", ""),
            "info_plist_sha256": digest(info_raw),
        }
        executable = info_plist.get("CFBundleExecutable", "")
        if executable and Path(executable).name == executable:
            app["executable_sha256"] = file_digest(root / executable)
        return {
            "platform": "ios",
            "version": version,
            "simulator": True,
            "observed_at": now(),
            "app": app,
            "device_id": self.device,
        }

    def launch(self):
        self.simctl(["launch", self.device, self.package])

    def open_url(self, url: str) -> dict:
        # simctl openurl routes via the OS. Confirm app identity manually in the captured evidence.
        self.simctl(["openurl", self.device, url])
        return {
            "delivery": "requested-not-confirmed",
            "note": "The OS may require manual Open confirmation or route to another app. Verify the transition in the test app.",
        }

    def tap(self, x: int, y: int):
        raise ValueError("tap is unavailable in the iOS simctl adapter")

    def input_text(self, text: str):
        raise ValueError("input_text is unavailable in the iOS simctl adapter")

    def screenshot(self, path: Path):
        self.simctl(["io", self.device, "screenshot", str(path)])

    def storage(self) -> list[tuple[str, bytes]]:
        root = Path(
            self.simctl(["get_app_container", self.device, self.package, "data"]).decode().strip()
        ).resolve()
        if not root.is_dir():
            raise ValueError("Simulator app data container not found")
        return local_storage(root)

    def ui(self) -> bytes:
        raise ValueError("simctl does not provide UI text capture; storage and screenshots are available")

    def logs(self) -> bytes:
        raise ValueError(
            "iOS process-scoped logs require a separate logging capture; this surface was not checked"
        )


def scoped_android_ui(raw: bytes, package: str) -> bytes:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        raise ValueError("Android UI capture is invalid XML") from None
    nodes = [
        {
            k: v
            for k, v in node.attrib.items()
            if k in {"text", "content-desc", "resource-id", "class", "package"}
        }
        for node in root.iter("node")
        if node.get("package") == package
    ]
    if not nodes:
        raise ValueError("Audited app has no visible UI nodes; surface not captured")
    return canonical_json(nodes).encode()


def local_storage(root: Path) -> list[tuple[str, bytes]]:
    def capture_error(error: OSError) -> NoReturn:
        try:
            location = str(Path(error.filename).relative_to(root)) if error.filename else "."
        except (TypeError, ValueError):
            location = "."
        raise ValueError(
            f"Storage capture failed: {location} ({type(error).__name__}); coverage incomplete"
        ) from None

    result = []
    total = 0
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=capture_error):
        dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
        for name in sorted(names):
            path = Path(directory) / name
            try:
                metadata = path.lstat()
            except OSError as error:
                capture_error(error)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                continue
            if len(result) >= MAX_SNAPSHOT_FILES or metadata.st_size > MAX_FILE:
                raise ValueError("Storage snapshot exceeds limits; coverage incomplete")
            try:
                raw = read_under(root, path.relative_to(root))
            except OSError as error:
                capture_error(error)
            total += len(raw)
            if total > MAX_CAPTURE:
                raise ValueError("Storage snapshot exceeds total byte limit; coverage incomplete")
            result.append((str(path.relative_to(root)), raw))
    return result


def replace_markers(text: str, markers: dict[str, str]) -> str:
    for label, marker in markers.items():
        text = text.replace(marker, f"[CANARY:{label}]")
    return text


def snapshot(adapter, markers: dict[str, str]) -> dict:
    result = {"created": now(), "surfaces": {}, "matches": [], "files": []}
    for surface, capture in [("storage", adapter.storage), ("ui", adapter.ui), ("logs", adapter.logs)]:
        try:
            value = capture()
            entries = value if isinstance(value, list) else [(surface, value)]
            for path, raw in entries:
                path = redact(replace_markers(path, markers))
                result["files"].append(
                    {"surface": surface, "path": path, "sha256": digest(raw), "bytes": len(raw)}
                )
                for label, marker in markers.items():
                    if any(
                        marker.encode(encoding) in raw for encoding in ("utf-8", "utf-16-le", "utf-16-be")
                    ):
                        result["matches"].append(
                            {
                                "surface": surface,
                                "path": path,
                                "marker_label": label,
                                "marker_sha256": digest(marker.encode()),
                            }
                        )
            result["surfaces"][surface] = {"state": "captured", "files": len(entries)}
        except (ValueError, OSError, tarfile.TarError) as error:
            result["surfaces"][surface] = {
                "state": "not-run",
                "reason": redact(replace_markers(str(error), markers)),
            }
    result["surfaces"]["clipboard"] = {
        "state": "not-run",
        "reason": "Clipboard is not captured by these device adapters.",
    }
    return result


def validate_scenario(value: dict) -> dict:
    if not isinstance(value, dict) or value.get("platform") not in {"android", "ios"}:
        raise ValueError("Scenario platform must be android or ios")
    package = value.get("package")
    if not isinstance(package, str) or not PACKAGE.fullmatch(package):
        raise ValueError("Scenario needs a valid app package/bundle identifier")
    precondition = value.get("precondition")
    if not isinstance(precondition, str) or not 1 <= len(precondition) <= 2000:
        raise ValueError("Document the prepared app/login state in scenario.precondition (1–2000 characters)")
    markers = value.get("markers")
    if not isinstance(markers, dict) or not 1 <= len(markers) <= 30:
        raise ValueError("Provide 1–30 unique test canaries, each 8–200 characters")
    if any(
        not isinstance(k, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", k)
        or not isinstance(v, str)
        or not 8 <= len(v) <= 200
        for k, v in markers.items()
    ) or len(set(markers.values())) != len(markers):
        raise ValueError("Provide 1–30 unique test canaries with simple labels, each 8–200 characters")
    steps = value.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 100:
        raise ValueError("Scenario must contain 1–100 steps")
    labels = {}
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValueError("Each scenario step must be an object")
        action = step.get("action")
        if action not in {"launch", "open_url", "tap", "input_text", "wait", "snapshot"}:
            raise ValueError(f"Unsupported scenario action: {action}")
        if action == "open_url":
            url = step.get("url")
            if not isinstance(url, str) or len(url) > 4096 or not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", url):
                raise ValueError("open_url needs an absolute URL with a scheme (at most 4096 characters)")
        if action == "snapshot":
            label = step.get("label")
            if (
                not isinstance(label, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,60}", label)
                or label in labels
            ):
                raise ValueError("Snapshot labels must be unique simple identifiers")
            labels[label] = index
        if action == "wait":
            seconds = step.get("seconds", 0)
            if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 <= seconds <= 10:
                raise ValueError("Wait steps are limited to 10 seconds")
        if action in {"tap", "input_text"} and value["platform"] != "android":
            raise ValueError("tap/input_text are Android actions; use app-specific test URLs on iOS")
        if action == "tap" and any(
            type(step.get(k)) is not int or not 0 <= step[k] <= 20000 for k in ("x", "y")
        ):
            raise ValueError("tap needs nonnegative integer coordinates")
        if action == "input_text" and (not isinstance(step.get("text"), str) or len(step["text"]) > 2000):
            raise ValueError("input_text needs text of at most 2000 characters")
    assertions = value.get("assertions", [])
    if not isinstance(assertions, list) or len(assertions) > 100:
        raise ValueError("Assertions must be a list of at most 100 objects")
    for assertion in assertions:
        if not isinstance(assertion, dict):
            raise ValueError("Each assertion must be an object")
        if (
            assertion.get("snapshot") not in labels
            or assertion.get("baseline") not in labels
            or assertion.get("marker") not in markers
        ):
            raise ValueError("Assertions need an existing snapshot, baseline and marker")
        if labels[assertion["baseline"]] >= labels[assertion["snapshot"]]:
            raise ValueError("Assertion baseline must precede a distinct after snapshot")
        if assertion.get("surface", "storage") not in {"storage", "ui", "logs"}:
            raise ValueError("Assertion surface must be storage, ui or logs")
        if assertion.get("expect", "absent") not in {"absent", "present"}:
            raise ValueError("Assertion expect must be absent or present")
        if assertion.get("purpose", "residual") not in {
            "residual",
            "transition",
            "delivery",
            "authentication",
        }:
            raise ValueError("Assertion purpose must be residual, transition, delivery or authentication")
    return value


def plan(report: dict, platform: str | None = None, package: str | None = None) -> dict:
    platforms = report["inventory"]["platforms"]
    platform = platform or (platforms[0] if platforms else "android")
    if platform not in {"android", "ios"} or (platforms and platform not in platforms):
        raise ValueError("Requested runtime platform is not in this inventory")
    apps = [a["package"] for a in report["inventory"].get("apps", []) if a.get("platform") == platform]
    if not package and len(set(apps)) > 1:
        raise ValueError("Multiple app identifiers; select --package explicitly")
    package = package or (apps[0] if apps else report["inventory"]["package"]) or "com.example.app"
    if not PACKAGE.fullmatch(package) or (apps and package not in apps):
        raise ValueError("Requested runtime package is not a valid inventoried app identifier")
    links = []
    for link in report["inventory"]["deep_links"]:
        if link.get("bundle_role") == "embedded":
            continue
        if link.get("platform") and link["platform"] != platform:
            continue
        scheme = link["scheme"]
        if (
            scheme
            and "*" not in link.get("host", "")
            and link.get("path_kind", "") in {"", "path", "pathPrefix"}
        ):
            port = ":" + link["port"] if link.get("port") else ""
            links.append(f"{scheme}://{link.get('host') or 'test'}{port}{link.get('path') or '/'}")
    steps = [{"action": "snapshot", "label": "before_logout"}]
    if links:
        steps.append({"action": "open_url", "url": links[0]})
    steps += [{"action": "wait", "seconds": 1}, {"action": "snapshot", "label": "after_logout"}]
    return {
        "platform": platform,
        "package": package,
        "device": None,
        "precondition": "EDIT: Prepare account A with the unique canary. Add your app's logout/account-switch actions between snapshots; generated links are discovery candidates.",
        "markers": {"account_a": "mobile-audit-UNIQUE-CANARY"},
        "steps": steps,
        "assertions": [
            {
                "snapshot": "after_logout",
                "baseline": "before_logout",
                "marker": "account_a",
                "surface": "storage",
                "policy": "This canary must be removed from private storage after logout",
            }
        ],
        "notes": {
            "available_platforms": platforms,
            "available_packages": apps,
            "deep_link_candidates": links,
            "runtime_scope": "Own authorized test app. Android storage requires debuggable run-as; iOS requires an installed simulator build. This template does not automatically log out.",
        },
    }


def evaluate_assertions(scenario: dict, snapshots: dict) -> list[dict]:
    results = []
    for assertion in scenario.get("assertions", []):
        surface = assertion.get("surface", "storage")
        baseline = snapshots.get(assertion["baseline"], {})
        after = snapshots.get(assertion["snapshot"], {})

        def hits(snap, assertion=assertion, surface=surface):
            return [
                m
                for m in snap.get("matches", [])
                if m["marker_label"] == assertion["marker"] and m["surface"] == surface
            ]

        if any(s.get("surfaces", {}).get(surface, {}).get("state") != "captured" for s in [baseline, after]):
            state = "not-run"
        elif assertion.get("expect", "absent") == "present":
            state = "inconclusive" if hits(baseline) else ("passed" if hits(after) else "failed")
        elif not hits(baseline):
            state = "inconclusive"
        elif hits(after):
            state = "failed"
        else:
            state = "passed"
        results.append(
            {
                "assertion": assertion,
                "state": state,
                "matches": hits(after),
                "note": "Pass is limited to the captured surface and canary; it does not establish complete data deletion.",
            }
        )
    return results


@contextmanager
def device_lease(platform: str, device: str, directory: Path | None = None):
    if os.name != "posix":
        raise ValueError("Runtime device leases currently require a macOS or Linux host")
    import fcntl

    directory = directory or Path.home() / ".cache/mobile-audit/device-locks"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / f"{digest((platform + ':' + device).encode())}.lock"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Device is already used by another APSA scenario") from None
        yield
    finally:
        os.close(fd)


def run(
    store: Store, scenario_path: Path, report_id="latest", screenshots=False, adapter=None, *, scenario=None
) -> dict:
    scenario = validate_scenario(scenario if scenario is not None else read_json(scenario_path))
    if scenario["precondition"].startswith("EDIT:"):
        raise ValueError(
            "Customize the scenario template and confirm the prepared precondition before execution."
        )
    resolved = adapter or (Android if scenario["platform"] == "android" else IOS)(
        scenario["package"], scenario.get("device")
    )
    prefix = getattr(resolved, "prefix", [])
    serial = getattr(resolved, "device", None) or (prefix[-1] if prefix else f"test-adapter-{id(resolved)}")
    with device_lease(scenario["platform"], serial):
        return _run(store, scenario_path, report_id, screenshots, adapter=resolved, scenario=scenario)


def assertion_identity(assertion: dict) -> dict:
    """Executable assertion semantics; preparation/policy prose is not identity."""
    return {
        key: assertion.get(key, default)
        for key, default in (
            ("baseline", ""),
            ("snapshot", ""),
            ("marker", ""),
            ("surface", "storage"),
            ("expect", "absent"),
            ("purpose", "residual"),
        )
    }


def _run(
    store: Store,
    scenario_path: Path,
    report_id="latest",
    screenshots=False,
    adapter=None,
    scenario: dict | None = None,
) -> dict:
    scenario = scenario or validate_scenario(read_json(scenario_path))
    if scenario["precondition"].startswith("EDIT:"):
        raise ValueError(
            "Customize the scenario template and confirm the prepared precondition before execution."
        )
    previous = store.report(report_id)
    known_apps = [
        a["package"]
        for a in previous["inventory"].get("apps", [])
        if a.get("platform") == scenario["platform"]
    ]
    legacy_package = previous["inventory"]["package"]
    if not known_apps and (previous["inventory"].get("apps") or not legacy_package):
        raise ValueError(
            "No audited app identifier for this platform; provide a manifest, Info.plist or build"
        )
    if (known_apps and scenario["package"] not in known_apps) or (
        not previous["inventory"].get("apps") and legacy_package and scenario["package"] != legacy_package
    ):
        raise ValueError("Scenario package differs from the audited app")
    if scenario["platform"] not in previous["inventory"]["platforms"]:
        raise ValueError("Scenario platform differs from the audited app")
    adapter = adapter or (Android if scenario["platform"] == "android" else IOS)(
        scenario["package"], scenario.get("device")
    )
    report = copy.deepcopy(previous)
    report["id"] = uid("audit")
    report["parent_report"] = previous["id"]
    report["created"] = now()
    run_id = uid("runtime")
    directory = store.home / "artifacts" / run_id
    directory.mkdir(parents=True, mode=0o700)
    snapshots = {}
    transcript = []
    environment = adapter.environment()
    observed_app = environment.get("app", {})
    if observed_app.get("package") and observed_app["package"] != scenario["package"]:
        raise ValueError("Installed app identity differs from the scenario package")
    expected_build = scenario.get("build", {})
    if not isinstance(expected_build, dict):
        raise ValueError("Scenario build must be an object")
    for key, expected in expected_build.items():
        if key not in {
            "version",
            "version_code",
            "apk_sha256",
            "executable_sha256",
            "info_plist_sha256",
        } or not isinstance(expected, str):
            raise ValueError("Build expectations must be string version or hash fields")
        if observed_app.get(key) != expected:
            raise ValueError(f"Installed app does not match scenario build expectation: {key}")
    build_verification = "observed-installed-build"
    if previous["inventory"]["input_kind"] == "apk":
        if observed_app.get("apk_sha256"):
            if observed_app["apk_sha256"] != previous["inventory"]["fingerprint"]:
                raise ValueError("Installed APK differs from the audited APK; scan the installed build first")
            build_verification = "audited-apk-match"
        else:
            build_verification = "audited-apk-match-unavailable"
    elif previous["inventory"]["input_kind"] == "ipa":
        expected_apps = previous["inventory"].get("binary", {}).get("apps", [])
        hashes = {a.get("executable_sha256") for a in expected_apps if a.get("executable_sha256")}
        actual_hash = observed_app.get("executable_sha256")
        if hashes and actual_hash:
            if actual_hash not in hashes:
                raise ValueError("Installed iOS executable differs from the audited IPA")
            build_verification = "audited-ipa-executable-match"
            matching = [a for a in expected_apps if a.get("executable_sha256") == actual_hash]
            info_hashes = {a["info_plist_sha256"] for a in matching if a.get("info_plist_sha256")}
            if info_hashes and observed_app.get("info_plist_sha256"):
                if observed_app["info_plist_sha256"] not in info_hashes:
                    raise ValueError("Installed iOS Info.plist differs from the audited IPA")
                build_verification = "audited-ipa-executable-and-config-match"
        else:
            build_verification = "audited-ipa-match-unavailable"
    for index, step in enumerate(scenario["steps"]):
        action = step["action"]
        details = {}
        try:
            if action == "snapshot":
                snapshots[step["label"]] = snapshot(adapter, scenario["markers"])
                if screenshots:
                    path = directory / f"{step['label']}.png"
                    adapter.screenshot(path)
                    snapshots[step["label"]]["screenshot"] = str(path)
            elif action == "launch":
                adapter.launch()
            elif action == "open_url":
                outcome = adapter.open_url(step["url"])
                if isinstance(outcome, dict):
                    details = outcome
            elif action == "tap":
                adapter.tap(int(step["x"]), int(step["y"]))
            elif action == "input_text":
                adapter.input_text(str(step["text"]))
            elif action == "wait":
                time.sleep(float(step.get("seconds", 0)))
            transcript.append({"step": index, "action": action, "state": "completed", **details})
        except (ValueError, OSError, KeyError) as error:
            transcript.append({"step": index, "action": action, "state": "error", "error": str(error)})
            break
    results = evaluate_assertions(scenario, snapshots)
    scenario_hash = digest(canonical_json(scenario).encode())
    identity_data = {key: scenario[key] for key in ("platform", "package", "steps", "assertions")}
    legacy_identity = digest(replace_markers(canonical_json(identity_data), scenario["markers"]).encode())
    identity_data["assertions"] = [assertion_identity(a) for a in scenario["assertions"]]
    scenario_identity = digest(replace_markers(canonical_json(identity_data), scenario["markers"]).encode())
    scope_data = {key: scenario[key] for key in ("platform", "package", "steps")}
    scenario_scope = digest(replace_markers(canonical_json(scope_data), scenario["markers"]).encode())
    legacy_scopes = {}
    for prior_run in report.get("runtime", []):
        prior_assertions = [r["assertion"] for r in prior_run.get("assertions", [])]
        candidate = {**scope_data, "assertions": prior_assertions}
        legacy_scopes[prior_run["id"]] = digest(
            replace_markers(canonical_json(candidate), scenario["markers"]).encode()
        )
    if (
        results
        and all(
            r["state"] == "passed"
            for r in results
            if r["assertion"].get("purpose") in {"transition", "delivery"}
        )
        and not any(s["state"] == "error" for s in transcript)
    ):
        report["findings"] = [
            f
            for f in report["findings"]
            if not (
                f["status"] == "runtime-confirmed"
                and any(
                    (
                        f.get("scenario_hash") == scenario_hash
                        or e.get("scenario_scope") == scenario_scope
                        or (
                            e.get("scenario_identity") is not None
                            and e["scenario_identity"]
                            in {scenario_identity, legacy_identity, legacy_scopes.get(e.get("runtime_id"))}
                        )
                    )
                    and any(
                        r["state"] in {"passed", "failed"}
                        and assertion_identity(r["assertion"]) == assertion_identity(e.get("assertion", {}))
                        for r in results
                    )
                    for e in f["evidence"]
                )
            )
        ]
    for result in results:
        if result["state"] == "failed" and result["assertion"].get("expect", "absent") == "absent":
            surface = result["assertion"].get("surface", "storage")
            report["findings"].append(
                finding(
                    "RUNTIME-AUTH-EXPOSURE"
                    if result["assertion"].get("purpose") == "authentication"
                    else ("RUNTIME-RESIDUAL" if surface != "ui" else "RUNTIME-UI-EXPOSURE"),
                    "Test canary remains observable at the after-transition snapshot",
                    "high" if surface in {"ui", "logs"} else "medium",
                    "runtime-confirmed",
                    [
                        {
                            "runtime_id": run_id,
                            "scenario_identity": scenario_identity,
                            "scenario_scope": scenario_scope,
                            "assertion": result["assertion"],
                            "matches": result["matches"],
                        }
                    ],
                    "Review the logout/account-switch transition, storage deletion policy and token invalidation. Rerun this scenario after fixing it.",
                    "MASVS-AUTH"
                    if result["assertion"].get("purpose") == "authentication"
                    else ("MASVS-PLATFORM" if surface == "ui" else "MASVS-STORAGE"),
                    scenario_hash=scenario_hash,
                )
            )
    # Retain inconclusive historical evidence, but replace repeat observations
    # of the same finding instead of publishing duplicate stable IDs.
    report["findings"] = list({f["id"]: f for f in report["findings"]}.values())
    record = {
        "id": run_id,
        "scenario_hash": scenario_hash,
        "precondition": redact(replace_markers(scenario["precondition"], scenario["markers"])),
        "build_verification": build_verification,
        "delivery_verification": "marker-observed"
        if any(r["state"] == "passed" and r["assertion"].get("purpose") == "delivery" for r in results)
        else "requested-not-confirmed",
        "environment": environment,
        "snapshots": snapshots,
        "steps": transcript,
        "assertions": results,
        "transition_verification": "marker-observed"
        if any(r["state"] == "passed" and r["assertion"].get("purpose") == "transition" for r in results)
        else "scenario-declared",
        "partial": any(s["state"] == "error" for s in transcript)
        or not results
        or any(
            r["state"] in {"not-run", "inconclusive"}
            or (r["state"] == "failed" and r["assertion"].get("expect", "absent") == "present")
            for r in results
        ),
    }
    report["runtime"].append(record)
    report["environment"] = environment
    intel_findings, report["environment_advisories"] = correlate(
        report["inventory"], store.intelligence(limit=100000), environment
    )
    report["findings"] = [f for f in report["findings"] if f.get("origin") != "intelligence"] + intel_findings
    report["findings"].sort(key=lambda f: -severity_rank(f["severity"]))
    report["intel_snapshot"] = source_health(store)
    residual_results = [r for r in results if r["assertion"].get("purpose", "residual") == "residual"]
    for entry in report["coverage"]:
        if entry["rule_id"] == "RUNTIME-RESIDUAL":
            entry["state"] = "checked" if residual_results and not record["partial"] else "not-run"
            entry["note"] = (
                "Residual-purpose canary assertions only; delivery, transition and authentication assertions do not establish residual coverage. See per-surface capture states."
            )
        if entry["rule_id"] == "RUNTIME-DEEPLINK" and any(
            s["action"] == "open_url" and s["state"] == "completed" for s in transcript
        ):
            entry["state"] = "observed"
            entry["note"] = (
                "URL dispatch requested. Confirm OS prompts and target-app delivery; authentication/origin behavior requires explicit UI assertions or manual review."
            )
            if record["delivery_verification"] == "marker-observed":
                entry["state"] = "checked"
                entry["note"] = (
                    "Target-app marker changed after dispatch. Review separate authentication assertions; delivery alone is not authentication proof."
                )
    report["summary"] = summarize(report)
    return store.save_report(report)
