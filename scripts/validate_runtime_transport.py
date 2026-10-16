#!/usr/bin/env python3
"""Compile NEW apps, install only on NEW CI devices and retain digest-only evidence.

Networking and device operations are exclusive to a disposable GitHub runner.
Never select booted/default devices or enumerate apps, accounts, logs or state.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import plistlib
import re
import shlex
import shutil
import stat
import subprocess
import time
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urlencode, urlsplit, urlunsplit
from urllib.request import ProxyHandler, Request, build_opener
from xml.parsers.expat import ExpatError

from mobile_audit.core import digest
from mobile_audit.runtime_acquisition import AcquisitionRecorder, evaluate_backend_invalidation
from mobile_audit.runtime_evidence import build_binding, evaluate_workflow
from tests.support.runtime_transport import AuthorityServer, InstalledTransportAdapter, OwnedAuthority

SOURCES = Path(__file__).resolve().parents[1] / "tests/fixtures/runtime/transport"
MAX_OUTPUT = 64 * 1024 * 1024
IOS_EVENT_BYTES = 64 * 1024
IOS_EVENT_LIMIT = 128
IOS_ENTRY_BYTES = 4096
IOS_CONTRACT_BYTES = 64 * 1024
IOS_PINNED_RUNTIME = "com.apple.CoreSimulator.SimRuntime.iOS-18-5"
IOS_PINNED_DEVICE_TYPE = "com.apple.CoreSimulator.SimDeviceType.iPhone-16"
RUNTIME_CONTROL_SOURCE_VERSION = 2
ANDROID_ERROR_BYTES = 4096
ANDROID_ERROR_PHASES = {
    "binding",
    "http-issue",
    "http-logout",
    "http-switch",
    "http-protected",
    "state-write",
    "state-read",
    "response-write",
}
ANDROID_ERROR_CATEGORIES = {
    "argument",
    "http-status",
    "socket-timeout",
    "connect",
    "host",
    "io",
    "json",
    "security",
    "other",
}
IOS_PHASES = {
    "startup-app",
    "startup-scene",
    "scene-active",
    "os-app-url-received",
    "os-url-context-received",
    "os-cold-url-context-received",
    "url-received",
    "url-processing",
    "http-issue",
    "http-logout",
    "http-switch",
    "http-protected",
    "response-written",
    "binding-or-transport-failure",
    "failure-url-shape",
    "failure-session-fields",
    "failure-session-policy",
    "failure-session-binding",
    "failure-http-issue",
    "failure-http-logout",
    "failure-http-switch",
    "failure-http-protected",
    "failure-store-write",
    "failure-transition-fields",
    "failure-capture-fields",
    "failure-store-read-or-response",
    "will-launch-url-present",
    "will-launch-url-absent",
    "launch-options-url-present",
    "launch-options-url-absent",
    "configuration-url-present",
    "configuration-url-absent",
    "scene-connect-url-present",
    "scene-connect-url-absent",
    "scene-non-window",
    "warm-context-url-present",
    "warm-context-url-absent",
    "os-dispatch",
}


def safe_android_error(raw: bytes) -> dict:
    """Bounded fixture-error diagnostics never establish delivery/acquisition."""
    result = {"state": "unmeasured", "sha256": digest(raw), "bytes": len(raw)}
    if not raw or len(raw) > ANDROID_ERROR_BYTES:
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique_journal_keys)
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "action",
                "code",
                "diagnostic",
                "package",
                "apk_sha256",
                "session",
                "account",
                "state",
                "delivery",
                "delivery_transport",
            }
            or value["action"] != "fixture-error"
            or value["code"] != "binding-or-transport"
        ):
            return result
        diagnostic = value["diagnostic"]
        if (
            not isinstance(diagnostic, dict)
            or set(diagnostic) != {"schema_version", "phase", "category"}
            or type(diagnostic["schema_version"]) is not int
            or diagnostic["schema_version"] != 1
            or diagnostic["phase"] not in ANDROID_ERROR_PHASES
            or diagnostic["category"] not in ANDROID_ERROR_CATEGORIES
        ):
            return result
        return {**result, "state": "diagnostic-only", **diagnostic}
    except (ValueError, TypeError, KeyError):
        return result


def safe_ios_events(raw: bytes, expected: dict | None = None, readiness_epoch: str | None = None) -> dict:
    """Allowlisted diagnostics only, separate from trusted acquisition verdicts."""
    result: dict = {"state": "unavailable", "sha256": digest(raw), "bytes": len(raw)}
    if not raw:
        return result
    result["state"] = "malformed-or-over-bound"
    if len(raw) > IOS_EVENT_BYTES:
        return result

    def hash_value(value):
        return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None

    try:
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema_version", "complete", "events", "launch_epoch_sha256"}
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or type(value["complete"]) is not bool
            or not hash_value(value["launch_epoch_sha256"])
            or not isinstance(value["events"], list)
            or len(value["events"]) > IOS_EVENT_LIMIT
        ):
            return result
        counters, receipts = {}, []
        for sequence, entry in enumerate(value["events"], 1):
            base = {"sequence", "phase", "main_thread"}
            if (
                not isinstance(entry, dict)
                or type(entry.get("sequence")) is not int
                or entry["sequence"] != sequence
                or entry.get("phase") not in IOS_PHASES
                or type(entry.get("main_thread")) is not bool
            ):
                return result
            phase = entry["phase"]
            counters[phase] = counters.get(phase, 0) + 1
            if phase != "os-dispatch":
                if set(entry) != base:
                    return result
                continue
            if (
                set(entry) != base | {"lifecycle", "action", "uri_sha256", "session_sha256", "nonce_sha256"}
                or entry["lifecycle"]
                not in {
                    "cold-url-context",
                    "warm-url-context",
                    "application-url-callback",
                    "launch-options-url",
                }
                or entry["action"] not in {"session", "capture", "transition", "unsupported"}
                or not hash_value(entry["uri_sha256"])
                or any(
                    entry[key] is not None and not hash_value(entry[key])
                    for key in ("session_sha256", "nonce_sha256")
                )
            ):
                return result
            receipt = entry.copy()
            receipt["matches_expected_dispatch"] = expected is not None and all(
                entry[key] == expected[key]
                for key in ("lifecycle", "action", "uri_sha256", "session_sha256", "nonce_sha256")
            )
            receipts.append(receipt)
    except (ValueError, TypeError, KeyError):
        return result
    return {
        **result,
        "state": "complete" if value["complete"] else "capped",
        "launch_epoch_sha256": value["launch_epoch_sha256"],
        "process_epoch_relation": "unknown"
        if readiness_epoch is None
        else "same-as-readiness"
        if value["launch_epoch_sha256"] == readiness_epoch
        else "new-since-readiness",
        "counters": counters,
        "receipts": receipts,
    }


def safe_ios_entry(
    raw: bytes,
    *,
    expected_paths: dict | None = None,
    process: dict | None = None,
    readiness_epoch: str | None = None,
    callback_epoch: str | None = None,
) -> dict:
    """Digest-only process entry is diagnostic; never URL delivery/acquisition."""
    result = {
        "state": "unmeasured" if raw else "absent",
        "sha256": digest(raw),
        "bytes": len(raw),
        "write_status": "unknown",
        "acquisition": "unsupported",
    }
    if not raw or len(raw) > IOS_ENTRY_BYTES:
        return result
    keys = {
        "schema_version",
        "phase",
        "process_epoch_sha256",
        "pid_sha256",
        "home_path_sha256",
        "documents_path_sha256",
        "entry_path_sha256",
        "write_status",
    }
    try:
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value) != keys
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["phase"] != "before-uiapplication-main"
            or value["write_status"] not in {"attempted", "confirmed"}
            or any(
                not isinstance(value[key], str) or re.fullmatch(r"[a-f0-9]{64}", value[key]) is None
                for key in keys
                if key.endswith("_sha256")
            )
        ):
            return result
    except (ValueError, TypeError, KeyError):
        return result
    relation = "unmeasured"
    if process and isinstance(process.get("pid_sha256"), str):
        if value["pid_sha256"] != process["pid_sha256"]:
            relation = "differs-known-owner"
        elif process.get("state") == "live-verified":
            relation = "matches-live-verified"
        elif process.get("state") == "exited":
            relation = "matches-exited-owner"
    paths_match = (
        None
        if expected_paths is None
        else all(
            value[key] == expected_paths[key]
            for key in ("home_path_sha256", "documents_path_sha256", "entry_path_sha256")
        )
    )
    if paths_match is False:
        return {**result, "expected_paths_match": False, "reason": "entry-path-digests-differ"}
    return {
        **result,
        **value,
        "state": "diagnostic-only",
        "expected_paths_match": paths_match,
        "pid_identity_relation": relation,
        "process_epoch_relation": "unknown"
        if readiness_epoch is None
        else "same-as-readiness"
        if value["process_epoch_sha256"] == readiness_epoch
        else "new-since-readiness",
        "callback_epoch_relation": "unknown"
        if callback_epoch is None
        else "same-as-callback"
        if value["process_epoch_sha256"] == callback_epoch
        else "differs-callback",
    }


def ios_launch_pid(raw: bytes, package: str) -> int | None:
    if len(raw) > 4096:
        return None
    match = re.fullmatch(re.escape(package).encode() + rb": ([1-9][0-9]{0,9})\s*", raw)
    return int(match[1]) if match and int(match[1]) <= 2147483647 else None


def ios_process_identity(pid: int | None, executable: Path) -> dict:
    """CI only: inspect one PID returned for the exact NEW launched package."""
    if (
        type(pid) is not int
        or not 0 < pid <= 2147483647
        or platform.system() != "Darwin"
        or os.environ.get("GITHUB_ACTIONS") != "true"
        or os.environ.get("CI") != "true"
    ):
        return {"state": "unmeasured"}
    result = {"pid_sha256": digest(str(pid).encode())}
    # Only ESRCH from signal zero establishes exit; an unsupported libproc cannot.
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return {**result, "state": "exited"}
    except OSError:
        return {**result, "state": "unmeasured"}
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        library.proc_pidpath.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(4096)
        if library.proc_pidpath(pid, buffer, len(buffer)) <= 0:
            return {**result, "state": "unmeasured"}
        observed = buffer.value.decode("utf-8", errors="strict")
        # Compare strings without following a possibly reused PID's path.
        matches = os.path.normpath(observed) == str(executable.resolve())
        return {
            **result,
            "state": "live-verified" if matches else "identity-mismatch",
            "executable_path_sha256": digest(observed.encode()),
        }
    except (OSError, UnicodeError, AttributeError):
        return {**result, "state": "unmeasured"}


class UniquePlistKeys(dict):
    """Reject duplicate XML/binary plist keys instead of silently taking the last."""

    def __setitem__(self, key, value):
        if key in self:
            raise ValueError("duplicate plist key")
        super().__setitem__(key, value)


def same_typed_shape(value, expected) -> bool:
    if isinstance(expected, dict):
        return (
            isinstance(value, dict)
            and set(value) == set(expected)
            and all(same_typed_shape(value[key], item) for key, item in expected.items())
        )
    if isinstance(expected, list):
        return (
            isinstance(value, list)
            and len(value) == len(expected)
            and all(same_typed_shape(item, wanted) for item, wanted in zip(value, expected, strict=True))
        )
    return type(value) is type(expected) and value == expected


def safe_ios_installed_contract(raw: bytes, package: str, scheme: str, *, helper=False) -> dict:
    """Only digest/boolean projections of the exact NEW installed Info.plist."""
    result = {"state": "malformed-or-over-bound", "sha256": digest(raw)}
    if not raw or len(raw) > IOS_CONTRACT_BYTES:
        return result
    try:
        value = plistlib.loads(raw, dict_type=UniquePlistKeys)
    except (ValueError, TypeError, OverflowError, RecursionError, ExpatError, plistlib.InvalidFileException):
        return result
    if not isinstance(value, dict):
        return result
    module, delegate = (
        ("UrlDispatcherFixture", "DispatcherScene") if helper else ("TransportFixture", "SceneDelegate")
    )
    expected_scene = {
        "UIApplicationSupportsMultipleScenes": False,
        "UISceneConfigurations": {
            "UIWindowSceneSessionRoleApplication": [
                {
                    "UISceneConfigurationName": "Default",
                    "UISceneDelegateClassName": module + "." + delegate,
                }
            ]
        },
    }
    url_types = [
        {
            "CFBundleTypeRole": "Editor",
            "CFBundleURLName": package + ".transport",
            "CFBundleURLSchemes": [scheme],
        }
    ]
    checks = {
        "package_matches": type(value.get("CFBundleIdentifier")) is str
        and value["CFBundleIdentifier"] == package,
        "scheme_matches": re.fullmatch(r"a[a-f0-9]{32}", scheme) is not None
        and type(value.get("APSAFixtureScheme")) is str
        and value["APSAFixtureScheme"] == scheme,
        "url_types_match": "CFBundleURLTypes" not in value
        if helper
        else same_typed_shape(value.get("CFBundleURLTypes"), url_types),
        "query_schemes_match": same_typed_shape(value.get("LSApplicationQueriesSchemes"), [scheme])
        if helper
        else "LSApplicationQueriesSchemes" not in value,
        "scene_matches": same_typed_shape(value.get("UIApplicationSceneManifest"), expected_scene),
        "executable_matches": type(value.get("CFBundleExecutable")) is str
        and value["CFBundleExecutable"] == ("UrlDispatcher" if helper else "TransportFixture"),
    }
    return {**result, **checks, "state": "verified" if all(checks.values()) else "mismatch"}


def safe_ios_appinfo(raw: bytes, package: str, scheme: str = "apsatransport") -> dict:
    """Project only matching identity and URL-type booleans from NEW app metadata."""
    result = {"state": "unmeasured", "sha256": digest(raw), "bytes": len(raw)}
    if not raw or len(raw) > IOS_EVENT_BYTES:
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique_journal_keys)
    except (ValueError, UnicodeError):
        try:
            value = plistlib.loads(raw, dict_type=UniquePlistKeys)
        except (
            ValueError,
            TypeError,
            OverflowError,
            RecursionError,
            ExpatError,
            plistlib.InvalidFileException,
        ):
            return result
    if not isinstance(value, dict):
        return result
    identifier = value.get("CFBundleIdentifier")
    types = value.get("CFBundleURLTypes")
    return {
        **result,
        "state": "measured" if isinstance(identifier, str) else "unmeasured",
        "package_matches": identifier == package if isinstance(identifier, str) else None,
        "url_types_state": "unreported" if "CFBundleURLTypes" not in value else "reported",
        "url_types_present": isinstance(types, list) if "CFBundleURLTypes" in value else None,
        "url_types_match": types
        == [
            {
                "CFBundleTypeRole": "Editor",
                "CFBundleURLName": package + ".transport",
                "CFBundleURLSchemes": [scheme],
            }
        ]
        if isinstance(types, list)
        else None,
    }


def safe_ios_dispatcher(raw: bytes, expected_uri: str | None) -> dict:
    result = {"state": "unmeasured", "sha256": digest(raw), "bytes": len(raw)}
    if not raw or len(raw) > 4096:
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique_journal_keys)
        phase = value["phase"]
        if phase not in {
            "rejected-owned-uri",
            "validated-owned-uri",
            "os-open-requested",
            "os-open-completed",
        }:
            return result
        keys = {"phase"} if phase == "rejected-owned-uri" else {"phase", "uri_sha256"}
        if phase in {"os-open-requested", "os-open-completed"} and "can_open_url" in value:
            keys.add("can_open_url")
            if type(value.get("can_open_url")) is not bool:
                return result
        if phase == "os-open-completed":
            keys.add("open_completion")
            if type(value.get("open_completion")) is not bool:
                return result
        if set(value) != keys or (
            phase != "rejected-owned-uri" and re.fullmatch(r"[a-f0-9]{64}", value["uri_sha256"]) is None
        ):
            return result
        return {
            **result,
            "state": "diagnostic-only",
            **value,
            "uri_matches": expected_uri is not None and value.get("uri_sha256") == expected_uri,
        }
    except (ValueError, TypeError, KeyError):
        return result


def owned_ios_url(url: str, scheme: str) -> str:
    parts = urlsplit(url)
    if (
        len(url.encode()) > 4096
        or re.fullmatch(r"a[a-f0-9]{32}", scheme) is None
        or parts.scheme != "apsatransport"
        or parts.netloc != "fixture"
        or parts.path
        or parts.fragment
    ):
        raise ValueError("NEW iOS URL origin differs")
    return urlunsplit((scheme, "fixture", "", parts.query, ""))


def ios_default_set(env: dict) -> Path:
    """Operational CI-only guard, never an acquisition/host attestation."""
    if (
        platform.system() != "Darwin"
        or any(
            env.get(key) != value
            for key, value in {
                "GITHUB_ACTIONS": "true",
                "CI": "true",
                "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "macOS",
                "HOME": "/Users/runner",
                "DEVELOPER_DIR": "/Applications/Xcode_16.4.app/Contents/Developer",
            }.items()
        )
        or any(
            key in env
            for key in {
                "SIMULATOR_DEVICE_SET_PATH",
                "SIMCTL_DEVICE_SET_PATH",
                "CORE_SIMULATOR_DEVICE_SET_PATH",
                "CFFIXED_USER_HOME",
                "SIMULATOR_ROOT",
                "SIMULATOR_HOME",
                "SIMULATOR_UDID",
            }
        )
        or any(key.startswith("SIMCTL_CHILD_") for key in env)
    ):
        raise ValueError("NEW default-set control requires pinned hosted macOS namespace")
    # Literal from the disposable runner home. No parent discovery/listing/stat.
    return Path("/Users/runner/Library/Developer/CoreSimulator/Devices")


def ios_selector(root: Path, selector: str, env: dict) -> tuple[list[str], Path]:
    if selector == "default":
        return ["/usr/bin/xcrun", "simctl"], ios_default_set(env)
    if selector == "custom":
        device_set = (root / "simulator-set").resolve()
        return ["/usr/bin/xcrun", "simctl", "--set", str(device_set)], device_set
    raise ValueError("Owned resource journal simulator selector differs")


def unique_journal_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Owned resource journal duplicate key")
        result[key] = value
    return result


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
            if self.path.is_symlink() or self.path.stat().st_size > IOS_EVENT_BYTES:
                raise ValueError("Owned resource journal shape differs")
            self.value = json.loads(self.path.read_text(), object_pairs_hook=unique_journal_keys)
            if not isinstance(self.value, dict) or set(self.value) != set(identity) | {"android", "ios"}:
                raise ValueError("Owned resource journal shape differs")
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

    def ios(self, device: str, *, deleted: bool = False, selector: str | None = None):
        device = str(uuid.UUID(device)).upper()
        previous = self.value["ios"].get(device, {})
        selector = selector if selector is not None else previous.get("selector", "custom")
        if selector not in {"custom", "default"}:
            raise ValueError("Owned resource journal simulator selector differs")
        self.value["ios"][device] = {"deleted": deleted, "selector": selector}
        self.save()


def cleanup_owned(root: Path, commands: "Commands", resources: OwnedResources) -> dict:
    """Idempotent fallback, only explicitly journaled new resources and paths."""
    results = []
    # Validate the entire iOS journal and all guards before ANY SDK operation.
    if (
        not isinstance(resources.value, dict)
        or set(resources.value) != {"root", "run_id", "commit", "android", "ios"}
        or resources.value["root"] != str(root)
        or not isinstance(resources.value["ios"], dict)
    ):
        raise ValueError("Owned resource journal simulator shape differs")
    android = resources.value["android"]
    if android is not None and (
        not isinstance(android, dict)
        or not {"avd", "sdk"}.issubset(android)
        or not set(android).issubset({"avd", "sdk", "emulator", "adb", "emulator_closed", "adb_closed"})
        or not isinstance(android["avd"], str)
        or not isinstance(android["sdk"], str)
        or any(type(android[key]) is not bool for key in set(android) - {"avd", "sdk"})
    ):
        raise ValueError("Owned resource journal Android shape differs")
    selectors = {}
    for device, record in resources.value["ios"].items():
        if (
            str(uuid.UUID(device)).upper() != device
            or not isinstance(record, dict)
            or set(record) != {"deleted", "selector"}
            or type(record["deleted"]) is not bool
        ):
            raise ValueError("Owned resource journal simulator shape differs")
        selectors[device] = ios_selector(root, record["selector"], commands.env)
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
        # Selector persists across driver death; only the CREATE-returned UUID is targeted.
        prefix, device_set = selectors[device]
        commands.run(prefix + ["shutdown", device], optional=True)
        commands.run(prefix + ["delete", device], optional=True)
        confirmed = commands.last_status == 0 or (
            record["selector"] == "custom" and not (device_set / device).exists()
        )
        results.append(
            {
                "scope": "owned new simulator UUID",
                "uuid": device,
                "selector": record["selector"],
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
            "case-4",
            "case-5",
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
    "NEW iOS URL lifecycle differs": "ios-os-url-lifecycle-mismatch",
    "NEW iOS owned PID identity differs": "ios-owned-pid-identity-mismatch",
    "NEW iOS registered package differs": "ios-registered-package-mismatch",
    "NEW iOS installed URL contract differs": "ios-installed-url-contract-mismatch",
    "NEW iOS callback receipt differs": "ios-callback-receipt-mismatch",
    "NEW iOS cold process epoch differs": "ios-cold-process-epoch-mismatch",
    "NEW iOS target termination unverified": "ios-target-termination-unverified",
    "NEW iOS diagnostic control readiness differs": "ios-control-readiness-unverified",
    "NEW iOS diagnostic URL control timed out": "ios-control-response-deadline",
    "NEW XCTest dispatch ownership differs": "ios-xctest-owned-target-mismatch",
    "NEW XCTest dispatch manifest differs": "ios-xctest-manifest-shape",
    "NEW XCTest dispatch environment differs": "ios-xctest-environment-shape",
    "NEW XCTest dispatch URI differs": "ios-xctest-uri-shape",
    "NEW XCTest dispatch limit exceeded": "ios-xctest-dispatch-bound",
    "NEW XCTest build completion unverified": "ios-xctest-build-status-unverified",
    "NEW XCTest dispatch completion unverified": "ios-xctest-dispatch-status-unverified",
    "Installed fixture transition unsupported": "installed-session-or-transition-unavailable",
    "Installed fixture target/build/transport response differs": "installed-target-build-transport-mismatch",
    "Installed fixture HTTP/session initialization differs": "installed-session-or-http-initialization",
    "Installed fixture logout delivery/HTTP authority differs": "installed-logout-or-http-binding",
    "Installed fixture switch delivery/HTTP authority differs": "installed-switch-or-http-binding",
    "Installed fixture account B authentication differs": "installed-switch-account-b-authentication",
    "Installed fixture capture transition kind differs": "installed-capture-transition-kind",
    "Installed fixture capture nonce differs": "installed-capture-nonce-binding",
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
        if "help" in argv:
            return "ios-simctl-help"
        operations = {
            "create",
            "boot",
            "bootstatus",
            "install",
            "get_app_container",
            "appinfo",
            "openurl",
            "launch",
            "terminate",
            "shutdown",
            "delete",
        }
        return "ios-simctl-" + next((part for part in argv if part in operations), "unsupported")
    if tool in {"javac", "d8", "aapt2", "keytool", "zipalign", "apksigner", "codesign"}:
        return "build-" + tool
    if tool == "xcrun" and "swiftc" in argv:
        return "build-swiftc"
    if tool == "xcodebuild":
        return (
            "ios-xctest-build"
            if "build-for-testing" in argv
            else "ios-xctest-dispatch"
            if "test-without-building" in argv
            else "ios-xctest-unsupported"
        )
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
                        raise FixtureFailure(
                            "NEW Android fixture rejected binding or transport", safe_android_error(raw)
                        )
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

    def __init__(
        self,
        root: Path,
        package: str,
        commands: Commands,
        runtime: str | None,
        device_type: str,
        *,
        url_driver: str = "simctl",
        device_set_mode: str = "custom",
        readiness_only: bool = False,
    ):
        if url_driver not in {"simctl", "companion", "xctest"}:
            raise ValueError("NEW iOS URL driver unsupported")
        if url_driver == "xctest" and device_set_mode != "default":
            raise ValueError("NEW XCTest dispatch requires owned default-set target")
        self.package, self.commands, self.device = package, commands, None
        self.url_driver, self.device_set_mode = url_driver, device_set_mode
        self.readiness_only = readiness_only
        self.scheme = "a" + uuid.uuid4().hex
        self.delivery_observations: list[dict] = []
        self.simctl, self.device_set = ios_selector(commands.root, device_set_mode, commands.env)
        if device_set_mode == "default":
            if (
                runtime != IOS_PINNED_RUNTIME
                or device_type != IOS_PINNED_DEVICE_TYPE
                or commands.resources is None
            ):
                raise ValueError(
                    "NEW default-set control requires explicit pinned inputs and ownership journal"
                )
        else:
            runtime = runtime or IOS_PINNED_RUNTIME
            self.device_set.mkdir(exist_ok=True)
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
                "-strict-concurrency=complete",
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
                    "APSAFixtureScheme": self.scheme,
                    "CFBundleURLTypes": [
                        {
                            "CFBundleTypeRole": "Editor",
                            "CFBundleURLName": package + ".transport",
                            "CFBundleURLSchemes": [self.scheme],
                        }
                    ],
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
        journaled = False
        try:
            if commands.resources:
                commands.resources.ios(self.device, selector=device_set_mode)
                journaled = True
            commands.run(self.simctl + ["boot", self.device])
            commands.run(self.simctl + ["bootstatus", self.device, "-b"], timeout=180)
            commands.run(self.simctl + ["install", self.device, str(self.app)])
            self.installed = self.container("app")
            self.response = self.container("data") / "Documents/response.json"
            self.stage_path = self.response.with_name("stage.txt")
            self.events_path = self.response.with_name("events.json")
            self.require_installed_contract()
            if self.installed_build() != self.build:
                raise ValueError("NEW installed iOS executable differs")
            self.tool_help = self.tool_help_observations()
            self.registration = self.appinfo()
            if self.registration.get("package_matches") is False:
                raise FixtureFailure("NEW iOS registered package differs", self.registration)
            if self.url_driver == "companion":
                self.install_dispatcher(root, sdk, arch)
            elif self.url_driver == "xctest":
                from scripts.ios_xctest_dispatch import IosXCTestDispatcher

                self.xctest_dispatcher = IosXCTestDispatcher(
                    root / "xctest-dispatch", commands, self.device, self.package, self.scheme
                )
            # Establish a ready NEW scene before delivering the session URL through the OS.
            self.require_installed_contract()
            raw = commands.run(self.simctl + ["launch", self.device, self.package])
            self.owned_pid = ios_launch_pid(raw, self.package)
            initial = ios_process_identity(self.owned_pid, self.installed / "TransportFixture")
            self.process_observations = {"initial": initial}
            if initial["state"] == "identity-mismatch":
                raise FixtureFailure("NEW iOS owned PID identity differs", initial)
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if self.stage_path.is_file() and self.stage_path.read_bytes() == b"scene-active":
                    break
                time.sleep(0.1)
            else:
                raise FixtureFailure("NEW iOS fixture launch timed out", self.lifecycle_observation())
            self.readiness_epoch = self.events_observation().get("launch_epoch_sha256")
            self.readiness_entry = self.entry_observation(process=initial)
            self.readiness_entry_epoch = self.readiness_entry.get("process_epoch_sha256")
            # No URL, credentials or baseline exist yet. Force the first session URL
            # through genuine cold OS scene connection; later captures/logout are warm.
            if readiness_only:
                return
            commands.run(self.simctl + ["terminate", self.device, self.package])
            terminated = {"state": "unmeasured"}
            if initial["state"] == "live-verified":
                deadline = time.monotonic() + 5
                while True:
                    terminated = ios_process_identity(self.owned_pid, self.installed / "TransportFixture")
                    if terminated["state"] != "live-verified" or time.monotonic() >= deadline:
                        break
                    time.sleep(0.1)
            self.process_observations["after_terminate"] = terminated
            if terminated["state"] == "identity-mismatch":
                raise FixtureFailure("NEW iOS owned PID identity differs", terminated)
        except Exception as error:
            commands.pre_cleanup_failure = failure_observation(
                error, "ios-target-create-boot-install", commands.records
            )
            commands.pre_cleanup_failure["process_entry"] = self.entry_observation()
            commands.pre_cleanup_failure["installed_url_contract"] = getattr(
                self, "installed_url_contract", {"state": "unavailable"}
            )
            try:
                cleanup = self.close(timeout=120 if journaled else 15, update_journal=journaled)
                commands.pre_cleanup_failure["constructor_cleanup"] = {
                    **{key: value for key, value in cleanup.items() if key != "uuid"},
                    "uuid_sha256": digest(cleanup["uuid"].encode()) if "uuid" in cleanup else None,
                }
            except (ValueError, OSError, subprocess.SubprocessError, CommandFailure):
                commands.pre_cleanup_failure["constructor_cleanup"] = "unconfirmed"
            raise

    def container(self, kind: str, *, package: str | None = None) -> Path:
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        path = Path(
            self.commands.run(self.simctl + ["get_app_container", self.device, package or self.package, kind])
            .decode()
            .strip()
        )
        owned = self.device_set / self.device
        if not path.is_absolute() or not path.is_relative_to(owned):
            raise ValueError("NEW simulator container UUID differs")
        resolved = path.resolve()
        if not resolved.is_relative_to(owned):
            raise ValueError("NEW simulator container UUID differs")
        return resolved

    def install_dispatcher(self, root: Path, sdk: str, arch: str):
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        self.helper_package = self.package + ".dispatcher"
        source = root / "UrlDispatcher.swift"
        source.write_bytes((SOURCES / source.name).read_bytes())
        app = root / "UrlDispatcher.app"
        app.mkdir()
        self.commands.run(
            [
                "/usr/bin/xcrun",
                "swiftc",
                "-swift-version",
                "5",
                "-strict-concurrency=complete",
                "-sdk",
                sdk,
                "-target",
                arch + "-apple-ios18.0-simulator",
                "-parse-as-library",
                "-module-name",
                "UrlDispatcherFixture",
                str(source),
                "-o",
                str(app / "UrlDispatcher"),
                "-module-cache-path",
                str(root / "dispatcher-module-cache"),
            ]
        )
        info = {
            "CFBundleExecutable": "UrlDispatcher",
            "CFBundleIdentifier": self.helper_package,
            "CFBundleName": "UrlDispatcher",
            "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1",
            "CFBundleShortVersionString": "1.0",
            "MinimumOSVersion": "18.0",
            "LSRequiresIPhoneOS": True,
            "UIDeviceFamily": [1, 2],
            "UILaunchScreen": {},
            "APSAFixtureScheme": self.scheme,
            "LSApplicationQueriesSchemes": [self.scheme],
            "UIApplicationSceneManifest": {
                "UIApplicationSupportsMultipleScenes": False,
                "UISceneConfigurations": {
                    "UIWindowSceneSessionRoleApplication": [
                        {
                            "UISceneConfigurationName": "Default",
                            "UISceneDelegateClassName": "UrlDispatcherFixture.DispatcherScene",
                        }
                    ]
                },
            },
        }
        (app / "Info.plist").write_bytes(plistlib.dumps(info))
        self.commands.run(["/usr/bin/codesign", "--force", "--sign", "-", str(app)])
        self.commands.run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(app)])
        self.commands.run(self.simctl + ["install", self.device, str(app)])
        self.helper_installed = self.container("app", package=self.helper_package)
        self.helper_receipt = self.container("data", package=self.helper_package) / "Documents/dispatch.json"
        self.helper_build = {
            name: digest((app / name).read_bytes()) for name in ("UrlDispatcher", "Info.plist")
        }
        self.require_installed_contract(helper=True)
        if self.helper_installed_build() != self.helper_build:
            raise ValueError("NEW installed iOS dispatcher differs")

    def helper_installed_build(self):
        return {
            name: digest((self.helper_installed / name).read_bytes())
            for name in ("UrlDispatcher", "Info.plist")
        }

    def dispatch(self, url: str):
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        self.require_installed_contract()
        if self.url_driver == "simctl":
            self.commands.run(self.simctl + ["openurl", self.device, url])
            return
        if self.url_driver == "xctest":
            if self.installed_build() != self.build:
                raise ValueError("NEW installed iOS executable differs")
            self.xctest_dispatcher.dispatch(url)
            # Runner completion establishes no callback, session, HTTP or state
            # verdict. deliver() still requires the authoritative target proof.
            return
        if self.helper_installed_build() != self.helper_build:
            raise ValueError("NEW installed iOS dispatcher differs")
        self.require_installed_contract(helper=True)
        # deliver() already rewrote the URI to this NEW target's registered scheme.
        # Bind only helper diagnostics; target callback/session proof remains separate.
        self.helper_uri_sha256 = digest(url.encode())
        self.commands.run(
            self.simctl + ["terminate", self.device, self.helper_package], optional=True, timeout=15
        )
        if hasattr(self, "helper_pid"):
            deadline = time.monotonic() + 5
            while True:
                previous = ios_process_identity(self.helper_pid, self.helper_installed / "UrlDispatcher")
                if previous["state"] != "live-verified" or time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            if previous["state"] != "exited":
                raise FixtureFailure("NEW iOS target termination unverified", previous)
        raw = self.commands.run(self.simctl + ["launch", self.device, self.helper_package, url], timeout=30)
        self.helper_pid = ios_launch_pid(raw, self.helper_package)
        process = ios_process_identity(self.helper_pid, self.helper_installed / "UrlDispatcher")
        if process["state"] != "live-verified":
            raise FixtureFailure("NEW iOS owned PID identity differs", process)
        self.helper_process = process

    def diagnostic_command(self, argv: list[str], *, timeout: int, input: bytes | None = None):
        """Only noncritical public help/NEW app metadata can be unmeasured."""
        help_commands = [
            self.simctl + ["help", operation]
            for operation in ("launch", "terminate", "openurl", "appinfo", "get_app_container")
        ]
        metadata = self.simctl + ["appinfo", self.device, self.package]
        conversion = ["/usr/bin/plutil", "-convert", "json", "-o", "-", "--", "-"]
        if argv not in help_commands and argv != metadata and argv != conversion:
            raise ValueError("NEW iOS diagnostic command scope differs")
        if input is not None and (argv != conversion or len(input) > IOS_EVENT_BYTES):
            raise ValueError("NEW iOS diagnostic input differs")
        try:
            raw = self.commands.run(argv, timeout=timeout, input=input, optional=True)
        except CommandFailure as error:
            # Commands already retained timed_out/status/hash evidence. Never retry.
            reason = (
                error.reason
                if error.reason
                in {
                    "command-spawn-os-error",
                    "command-timeout",
                    "command-output-bound",
                    "command-nonzero-status",
                }
                else "diagnostic-command-failure"
            )
            fields = {
                key: value
                for key, value in safe_command_observation(error.observation).items()
                if key not in {"output", "process_status"}
            }
            return None, {"state": "unmeasured", "reason": reason, **fields}
        return raw, {
            "state": "measured" if self.commands.last_status == 0 else "unmeasured",
            "status": self.commands.last_status,
            "sha256": digest(raw),
            "bytes": len(raw),
        }

    def tool_help_observations(self):
        observations = {}
        operations = ("launch", "terminate", "openurl", "appinfo", "get_app_container")
        for index, operation in enumerate(operations):
            _, result = self.diagnostic_command(self.simctl + ["help", operation], timeout=10)
            observations[operation] = result
            if result["state"] == "unmeasured":
                for remaining in operations[index + 1 :]:
                    observations[remaining] = {
                        "state": "unmeasured",
                        "reason": "not-attempted-after-diagnostic-failure",
                    }
                break
        return observations

    def appinfo(self):
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        raw, command = self.diagnostic_command(
            self.simctl + ["appinfo", self.device, self.package], timeout=30
        )
        if raw is None or command["state"] == "unmeasured" or len(raw) > IOS_EVENT_BYTES:
            return command if command["state"] == "unmeasured" else {**command, "state": "unmeasured"}
        result = {**safe_ios_appinfo(raw, self.package, self.scheme), "command": command}
        if result["state"] == "unmeasured" and raw:
            converted, conversion = self.diagnostic_command(
                ["/usr/bin/plutil", "-convert", "json", "-o", "-", "--", "-"], input=raw, timeout=10
            )
            result["conversion"] = conversion
            if converted is not None and conversion["state"] == "measured":
                result = {
                    **safe_ios_appinfo(converted, self.package, self.scheme),
                    "command": command,
                    "conversion": conversion,
                }
        return result

    def installed_build(self):
        return {
            "executable_sha256": digest((self.installed / "TransportFixture").read_bytes()),
            "info_plist_sha256": digest((self.installed / "Info.plist").read_bytes()),
        }

    def installed_contract_observation(self, *, helper=False):
        app = getattr(self, "helper_installed" if helper else "installed", None)
        if not isinstance(app, Path) or self.device is None or not hasattr(self, "device_set"):
            return {"state": "unavailable"}
        path = app / "Info.plist"
        try:
            owned = (self.device_set / self.device).resolve()
            if (
                not app.is_relative_to(owned)
                or app.is_symlink()
                or app.resolve() != app
                or path.is_symlink()
                or path.resolve() != app / "Info.plist"
            ):
                return {"state": "owned-path-mismatch"}
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > IOS_CONTRACT_BYTES:
                return {"state": "malformed-or-over-bound"}
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
                metadata = os.fstat(handle.fileno())
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > IOS_CONTRACT_BYTES:
                    return {"state": "malformed-or-over-bound"}
                raw = handle.read(IOS_CONTRACT_BYTES + 1)
        except (OSError, RuntimeError, ValueError):
            return {"state": "unavailable"}
        return safe_ios_installed_contract(
            raw, self.helper_package if helper else self.package, self.scheme, helper=helper
        )

    def require_installed_contract(self, *, helper=False):
        observation = self.installed_contract_observation(helper=helper)
        if helper:
            self.helper_url_contract = observation
        else:
            self.installed_url_contract = observation
        if observation["state"] != "verified":
            raise FixtureFailure(
                "NEW iOS installed URL contract differs",
                {"helper_url_contract" if helper else "installed_url_contract": observation},
            )

    def url_contract_diagnostics(self):
        try:
            dispatcher = self.dispatcher_observation()
        except (OSError, ValueError, RuntimeError):
            dispatcher = {"state": "unmeasured"}
        return {
            "installed_url_contract": getattr(self, "installed_url_contract", {"state": "unavailable"}),
            "helper_url_contract": getattr(self, "helper_url_contract", {"state": "unavailable"}),
            "dispatcher": dispatcher,
            "registration": getattr(self, "registration", {"state": "unmeasured"}),
        }

    def lifecycle_observation(self):
        raw = (
            self.stage_path.read_bytes()
            if self.stage_path.is_file() and self.stage_path.stat().st_size <= 4096
            else b""
        )
        stage = raw.decode("ascii", errors="replace")
        return {
            "response_file_present": self.response.is_file(),
            "lifecycle_stage": stage if stage in IOS_PHASES else "not-observed",
            "stage_sha256": digest(raw),
            "stage_bytes": len(raw),
            "callback_events": self.events_observation(),
            "dispatcher": self.dispatcher_observation(),
            "installed_url_contract": getattr(self, "installed_url_contract", {"state": "unavailable"}),
            "helper_url_contract": getattr(self, "helper_url_contract", {"state": "unavailable"}),
            "process_entry": self.entry_observation(),
            "process_entry_readiness": getattr(self, "readiness_entry", {"state": "unmeasured"}),
            "device_set_selector": getattr(self, "device_set_mode", "custom"),
        }

    def entry_observation(self, *, process: dict | None = None):
        if not hasattr(self, "response") or not hasattr(self, "device_set") or self.device is None:
            return {"state": "unmeasured", "write_status": "unknown", "acquisition": "unsupported"}
        data = self.response.parent.parent
        documents, path = data / "Documents", data / "Documents/process-entry.json"
        try:
            owned = (self.device_set / self.device).resolve()
            # Recheck the exact NEW path before stat/read; never follow an entry symlink.
            if (
                not data.resolve().is_relative_to(owned)
                or not documents.resolve().is_relative_to(data.resolve())
                or path.is_symlink()
                or path.resolve() != documents.resolve() / "process-entry.json"
            ):
                return {
                    "state": "unmeasured",
                    "reason": "owned-entry-path-differs",
                    "write_status": "unknown",
                    "acquisition": "unsupported",
                }
            if path.is_file() and path.stat().st_size > IOS_ENTRY_BYTES:
                return {
                    "state": "unmeasured",
                    "reason": "entry-over-bound",
                    "bytes": path.stat().st_size,
                    "write_status": "unknown",
                    "acquisition": "unsupported",
                }
            raw = b""
            if path.is_file():
                with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as entry:
                    raw = entry.read(IOS_ENTRY_BYTES + 1)
            expected_paths = {
                "home_path_sha256": digest(str(data.resolve()).encode()),
                "documents_path_sha256": digest(str(documents.resolve()).encode()),
                "entry_path_sha256": digest(str(path.resolve()).encode()),
            }
        except (OSError, RuntimeError, ValueError):
            return {
                "state": "unmeasured",
                "reason": "entry-read-unavailable",
                "write_status": "unknown",
                "acquisition": "unsupported",
            }
        if process is None:
            process = getattr(self, "process_observations", {}).get("after_terminate")
        try:
            callback_epoch = self.events_observation().get("launch_epoch_sha256")
        except (OSError, RuntimeError, ValueError):
            callback_epoch = None
        return safe_ios_entry(
            raw,
            expected_paths=expected_paths,
            process=process,
            readiness_epoch=getattr(self, "readiness_entry_epoch", None),
            callback_epoch=callback_epoch,
        )

    def dispatcher_observation(self):
        xctest = getattr(self, "xctest_dispatcher", None)
        if xctest is not None:
            return xctest.latest.copy()
        path = getattr(self, "helper_receipt", None)
        if path is None:
            return {"state": "not-selected"}
        raw = path.read_bytes() if path.is_file() and path.stat().st_size <= 4096 else b""
        return safe_ios_dispatcher(raw, getattr(self, "helper_uri_sha256", None))

    def events_observation(self):
        path = getattr(self, "events_path", self.response.with_name("events.json"))
        if path.is_file() and path.stat().st_size > IOS_EVENT_BYTES:
            return {"state": "over-bound", "bytes": path.stat().st_size}
        raw = path.read_bytes() if path.is_file() else b""
        return safe_ios_events(
            raw, getattr(self, "dispatch_expectation", None), getattr(self, "readiness_epoch", None)
        )

    def deliver(self, url: str, expected: dict) -> dict:
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        if hasattr(self, "scheme"):
            url = owned_ios_url(url, self.scheme)
        self.dispatch_expectation = {
            "action": expected["action"],
            "lifecycle": "cold-url-context" if expected["action"] == "session" else "warm-url-context",
            "uri_sha256": digest(url.encode()),
            "session_sha256": digest(expected["session"].encode()),
            "nonce_sha256": digest(expected["nonce"].encode()) if "nonce" in expected else None,
        }
        self.dispatch(url)
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
                        self.record_delivery(response, expected, raw=self.response.read_bytes())
                        return response
                except json.JSONDecodeError:
                    pass
            time.sleep(0.1)
        primary = self.lifecycle_observation()
        primary["owned_process"] = getattr(self, "process_observations", {"state": "unmeasured"})
        primary["registration"] = getattr(self, "registration", {"state": "unmeasured"})
        primary["tool_help"] = getattr(self, "tool_help", {})
        # Save the original cold challenge evidence before any tail command can change files.
        if expected["action"] == "session":
            self.cold_diagnostic_progress = {
                "process_epoch_observed": None,
                "scene_active_observed": None,
                "warm_probe_attempted": False,
            }
            try:
                tail = self.cold_timeout_diagnostic()
                primary["diagnostic_tail"] = {**self.cold_diagnostic_progress, **tail}
            except (ValueError, OSError, subprocess.SubprocessError):
                primary["diagnostic_tail"] = {
                    **self.cold_diagnostic_progress,
                    "state": "unmeasured",
                    "reason": "diagnostic-command-failure",
                }
        raise FixtureFailure("NEW iOS OS URL response challenge timed out", primary)

    def cold_timeout_diagnostic(self):
        """One separated probe; never call acquisition, HTTP, or primary deliver again."""
        progress = self.cold_diagnostic_progress = {
            "process_epoch_observed": None,
            "scene_active_observed": None,
            "warm_probe_attempted": False,
        }
        if self.device is None:
            raise ValueError("NEW simulator has no owned UUID")
        self.require_installed_contract()
        old = self.events_observation().get("launch_epoch_sha256")
        readiness = getattr(self, "readiness_epoch", old)
        app, data = self.container("app"), self.container("data")
        observed_build = {
            "executable_sha256": digest((app / "TransportFixture").read_bytes()),
            "info_plist_sha256": digest((app / "Info.plist").read_bytes()),
        }
        result = {
            **progress,
            "state": "diagnostic-only",
            "url_driver": "simctl",
            "acquisition": "unsupported",
            "app_container_matches": app == self.installed,
            "data_container_matches": data == self.response.parent.parent,
            "app_container_sha256": digest(str(app).encode()),
            "data_container_sha256": digest(str(data).encode()),
            "installed_build_matches": observed_build == self.build,
            "registration": self.appinfo(),
            "process_entry_before_launch": self.entry_observation(),
        }
        if observed_build != self.build or result["registration"].get("package_matches") is False:
            return {**result, "state": "identity-mismatch"}
        raw = self.commands.run(self.simctl + ["launch", self.device, self.package], timeout=30)
        process = ios_process_identity(ios_launch_pid(raw, self.package), app / "TransportFixture")
        result["direct_launch_process"] = process
        if process["state"] == "identity-mismatch":
            return {
                **result,
                "state": "identity-mismatch",
                "process_entry_after_launch": self.entry_observation(process=process),
            }
        events_path = data / "Documents/events.json"
        events = safe_ios_events(b"", readiness_epoch=readiness)

        def observe_events():
            # Independent facts from the currently observed owned event receipt.
            # A new epoch without scene activation never makes readiness pass.
            relation = events.get("process_epoch_relation")
            progress["process_epoch_observed"] = (
                relation == "new-since-readiness"
                if relation in {"same-as-readiness", "new-since-readiness"}
                else None
            )
            progress["scene_active_observed"] = (
                events.get("counters", {}).get("scene-active", 0) >= 1
                if events.get("state") == "complete"
                else None
            )
            result.update(progress)

        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            raw = (
                events_path.read_bytes()
                if events_path.is_file() and events_path.stat().st_size <= IOS_EVENT_BYTES
                else b""
            )
            events = safe_ios_events(raw, readiness_epoch=readiness)
            observe_events()
            if (
                events.get("process_epoch_relation") == "new-since-readiness"
                and events.get("counters", {}).get("scene-active", 0) >= 1
            ):
                break
            time.sleep(0.1)
        else:
            return {
                **result,
                "fresh_epoch": False,
                "warm_receipt_bound": False,
                "diagnostic_launch_created_fresh_epoch": None
                if old is None or events.get("launch_epoch_sha256") is None
                else events["launch_epoch_sha256"] != old,
                "callback_events": events,
                "process_entry_after_launch": self.entry_observation(process=process),
            }
        result["fresh_epoch"] = True
        result["diagnostic_launch_created_fresh_epoch"] = (
            None if old is None else events["launch_epoch_sha256"] != old
        )
        result["process_entry_after_launch"] = self.entry_observation(process=process)
        fields = {
            "action": "capture",
            "session": uuid.uuid4().hex + uuid.uuid4().hex,
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
        }
        url = self.scheme + "://fixture?" + urlencode(fields)
        expected = {
            "action": "capture",
            "lifecycle": "warm-url-context",
            "uri_sha256": digest(url.encode()),
            "session_sha256": digest(fields["session"].encode()),
            "nonce_sha256": digest(fields["nonce"].encode()),
        }
        # A different synthetic session cannot initialize credentials or satisfy primary acquisition.
        deadline = time.monotonic() + 15
        progress["warm_probe_attempted"] = True
        result.update(progress)
        self.commands.run(self.simctl + ["openurl", self.device, url], timeout=15)
        while True:
            raw = (
                events_path.read_bytes()
                if events_path.is_file() and events_path.stat().st_size <= IOS_EVENT_BYTES
                else b""
            )
            events = safe_ios_events(raw, expected, readiness)
            observe_events()
            bound = events.get("state") == "complete" and any(
                r["matches_expected_dispatch"] for r in events.get("receipts", [])
            )
            if bound or time.monotonic() >= deadline:
                return {**result, "warm_receipt_bound": bound, "callback_events": events}
            time.sleep(0.1)

    def url_control(self) -> dict:
        """Separate NEW noncredential warm/cold probe; never acquisition or HTTP proof."""
        if not getattr(self, "readiness_only", False) or self.device is None:
            raise ValueError("NEW iOS diagnostic control requires readiness-only target")
        events = self.events_observation()
        process = ios_process_identity(self.owned_pid, self.installed / "TransportFixture")
        if (
            process["state"] != "live-verified"
            or self.installed_build() != self.build
            or events.get("state") != "complete"
            or events.get("launch_epoch_sha256") != self.readiness_epoch
            or events.get("counters", {}).get("scene-active", 0) < 1
            or events.get("receipts")
        ):
            raise FixtureFailure("NEW iOS diagnostic control readiness differs", self.lifecycle_observation())
        self.control_observations = []
        self.control_observations.append(self.url_control_probe("warm-url-context"))
        self.commands.run(self.simctl + ["terminate", self.device, self.package])
        deadline = time.monotonic() + 5
        while True:
            terminated = ios_process_identity(self.owned_pid, self.installed / "TransportFixture")
            if terminated["state"] != "live-verified" or time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        self.process_observations["after_terminate"] = terminated
        if terminated["state"] != "exited":
            raise FixtureFailure(
                "NEW iOS target termination unverified",
                {
                    "owned_process": terminated,
                    "control_observations": self.control_observations,
                },
            )
        self.control_observations.append(self.url_control_probe("cold-url-context"))
        return {
            "state": "passed",
            "scope": "NEW noncredential warm/cold OS callback diagnostic only",
            "platform": "ios",
            "installed_build": self.build,
            "acquisition": "unsupported",
            "backend": "unsupported",
            "storage": "unsupported",
            "url_driver": self.url_driver,
            "device_set_selector": self.device_set_mode,
            "readiness_events": events,
            "process_entry_readiness": getattr(self, "readiness_entry", {"state": "unmeasured"}),
            "owned_process": self.process_observations,
            "control_observations": self.control_observations,
        }

    def url_control_probe(self, lifecycle: str) -> dict:
        if lifecycle not in {"warm-url-context", "cold-url-context"}:
            raise ValueError("NEW iOS diagnostic control lifecycle differs")
        fields = {
            "action": "capture",
            "session": uuid.uuid4().hex + uuid.uuid4().hex,
            "nonce": uuid.uuid4().hex + uuid.uuid4().hex,
            "snapshot": "before",
            "account": "",
            "state": "logged_out",
            "transition": "",
        }
        # Companion accepts this full capture shape, but no session was initialized.
        # Target must receipt the OS callback, then reject binding before HTTP/storage.
        url = self.scheme + "://fixture?" + urlencode(fields)
        self.dispatch_expectation = {
            "action": "capture",
            "lifecycle": lifecycle,
            "uri_sha256": digest(url.encode()),
            "session_sha256": digest(fields["session"].encode()),
            "nonce_sha256": digest(fields["nonce"].encode()),
        }
        self.dispatch(url)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            events = self.events_observation()
            counters = events.get("counters", {})
            epoch_matches = events.get("process_epoch_relation") == (
                "same-as-readiness" if lifecycle == "warm-url-context" else "new-since-readiness"
            )
            raw = (
                self.response.read_bytes()
                if self.response.is_file() and self.response.stat().st_size <= 1024 * 1024
                else b""
            )
            try:
                response = json.loads(raw)
            except (ValueError, UnicodeError):
                response = None
            rejected = isinstance(response, dict) and all(
                response.get(key) == value
                for key, value in {
                    "action": "fixture-error",
                    "code": "failure-session-binding",
                    "package": self.package,
                    **self.build,
                    "session": "",
                    "account": "",
                    "state": "logged_out",
                    "delivery": "baseline",
                    "delivery_transport": "ios-os-url-context",
                    "delivery_lifecycle": lifecycle,
                }.items()
            )
            if (
                events.get("state") == "complete"
                and epoch_matches
                and any(receipt["matches_expected_dispatch"] for receipt in events.get("receipts", []))
                and rejected
                and counters.get("failure-session-binding", 0) >= 1
                and counters.get("http-issue", 0) == 0
                and counters.get("http-logout", 0) == 0
                and counters.get("http-switch", 0) == 0
                and counters.get("http-protected", 0) == 0
            ):
                return {
                    "lifecycle": lifecycle,
                    "state": "passed",
                    "session_rejection_observed": True,
                    "http_events_absent": True,
                    "response_sha256": digest(raw),
                    "response_bytes": len(raw),
                    "callback_events": events,
                    "dispatcher": self.dispatcher_observation(),
                    "process_entry": self.entry_observation(),
                }
            time.sleep(0.1)
        raise FixtureFailure(
            "NEW iOS diagnostic URL control timed out",
            {
                **self.lifecycle_observation(),
                "expected_lifecycle": lifecycle,
                "control_observations": getattr(self, "control_observations", []),
            },
        )

    def record_delivery(self, response: dict, expected: dict, *, raw: bytes):
        lifecycle = "cold-url-context" if expected["action"] == "session" else "warm-url-context"
        if response.get("delivery_lifecycle") != lifecycle:
            raise FixtureFailure("NEW iOS URL lifecycle differs", self.lifecycle_observation())
        events = self.events_observation()
        if events.get("state") != "complete" or not any(
            r["matches_expected_dispatch"] for r in events.get("receipts", [])
        ):
            raise FixtureFailure("NEW iOS callback receipt differs", self.lifecycle_observation())
        if expected["action"] == "session":
            if events.get("process_epoch_relation") != "new-since-readiness":
                raise FixtureFailure("NEW iOS cold process epoch differs", self.lifecycle_observation())
            if self.process_observations.get("after_terminate", {}).get("state") != "exited":
                raise FixtureFailure("NEW iOS target termination unverified", self.lifecycle_observation())
        self.delivery_observations.append(
            {
                "action": expected["action"],
                "lifecycle": lifecycle,
                "session_sha256": digest(expected["session"].encode()),
                "capture_nonce_sha256": digest(expected["nonce"].encode()) if "nonce" in expected else None,
                "response_sha256": digest(raw),
                "response_bytes": len(raw),
                "callback_events": events,
                "url_driver": getattr(self, "url_driver", "simctl"),
                "device_set_selector": getattr(self, "device_set_mode", "custom"),
                "helper_installed_build": getattr(self, "helper_build", None),
                "helper_process": getattr(self, "helper_process", None),
                "dispatcher": self.dispatcher_observation(),
                "process_entry": self.entry_observation(),
                "process_entry_readiness": getattr(self, "readiness_entry", {"state": "unmeasured"}),
            }
        )

    def close(self, *, timeout: int = 120, update_journal: bool = True):
        if self.device:
            device, self.device = self.device, None
            try:
                self.commands.run(self.simctl + ["shutdown", device], optional=True, timeout=timeout)
            except CommandFailure:
                # If journaling failed, still attempt deletion of only CREATE's UUID.
                if update_journal:
                    raise
            self.commands.run(self.simctl + ["delete", device], optional=True, timeout=timeout)
            if self.commands.last_status == 0 and self.commands.resources and update_journal:
                self.commands.resources.ios(device, deleted=True)
            return {
                "scope": "only NEW simulator UUID",
                "uuid": device,
                "selector": getattr(self, "device_set_mode", "custom"),
                "state": "confirmed" if self.commands.last_status == 0 else "unconfirmed",
            }
        return {"scope": "no remaining owned UUID", "state": "confirmed"}


def scenario(platform_name: str, package: str, transition_kind: str = "logout") -> dict:
    if transition_kind not in {"logout", "account_switch"}:
        raise ValueError("Installed fixture transition kind unsupported")
    value = {
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
                    "kind": transition_kind,
                    "from_account": "a",
                    "to_account": "b" if transition_kind == "account_switch" else None,
                    "baseline": "before",
                    "snapshot": "after",
                    "state_marker": "state",
                    "delivery_marker": "delivery",
                    "surface": "storage",
                }
            ],
        },
    }
    if transition_kind == "account_switch":
        value["markers"].update({key: "synthetic-unique-" + key for key in ("b", "login_b")})
        value["workflow"]["accounts"]["b"] = {
            "canary": "b",
            "login_marker": "login_b",
            "canary_surface": "storage",
            "login_surface": "storage",
        }
    return value


def old_account_switch_replay(before: dict, after: dict) -> list[dict]:
    """Separate old-A replay control; B authentication is verified independently."""
    captures = [before.get("acquisition", {}), after.get("acquisition", {})]
    probes = [before.get("backend_probe", {}), after.get("backend_probe", {})]
    valid = (
        all(capture.get("state") == "bound" for capture in captures)
        and bool(captures[0].get("session_sha256"))
        and captures[0].get("session_sha256") == captures[1].get("session_sha256")
        and all(capture.get("capture_sha256") for capture in captures)
        and captures[0]["capture_sha256"] != captures[1]["capture_sha256"]
        and captures[1].get("account") == "b"
        and captures[1].get("observed_state") == "authenticated"
        and captures[1].get("delivery") == "target-observed"
        and all(probe.get("provenance", {}).get("state") == "bound" for probe in probes)
        and all(
            all(
                probe.get("provenance", {}).get(key) == capture.get(key)
                for key in (
                    "session_sha256",
                    "capture_sha256",
                    "binding_identity",
                    "snapshot",
                    "account",
                    "observed_state",
                )
            )
            for probe, capture in zip(probes, captures, strict=True)
        )
        and bool(captures[0].get("binding_identity"))
        and captures[0]["binding_identity"] == captures[1].get("binding_identity")
        and all(
            probes[0].get(key) and probes[0].get(key) == probes[1].get(key)
            for key in ("authority_sha256", "credential_sha256")
        )
        and all(
            isinstance(probe.get(key), str) and re.fullmatch(r"[a-f0-9]{64}", probe[key])
            for probe in probes
            for key in ("request_sha256", "response_sha256")
        )
        and probes[0]["request_sha256"] != probes[1]["request_sha256"]
        and probes[0].get("outcome") == "accepted"
        and all(
            snapshot.get("surfaces", {}).get("network", {}).get("state") == "captured"
            and snapshot.get("surfaces", {}).get("network", {}).get("acquisition") == "adapter-acquired"
            for snapshot in (before, after)
        )
    )
    return [
        {
            "transition_kind": "account_switch",
            "state": ("passed" if probes[1].get("outcome") == "rejected" else "failed")
            if valid and probes[1].get("outcome") in {"accepted", "rejected"}
            else "inconclusive",
            "scope": "independent before/after replay of old A credential at the same owned authority",
        }
    ]


def ios_delivery_complete(observations: list[dict], before: dict, after: dict) -> bool:
    """Bind cold/warm callback proof to the exact acquired session and captures."""
    session = before.get("acquisition", {}).get("session_sha256")
    if not isinstance(session, str) or not re.fullmatch(r"[a-f0-9]{64}", session):
        return False
    if after.get("acquisition", {}).get("session_sha256") != session:
        return False
    expected = [
        ("session", "cold-url-context", None),
        ("capture", "warm-url-context", before.get("acquisition", {}).get("capture_sha256")),
        ("transition", "warm-url-context", None),
        ("capture", "warm-url-context", after.get("acquisition", {}).get("capture_sha256")),
    ]
    if len(observations) != len(expected) or any(
        not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{64}", nonce)
        for action, _, nonce in expected
        if action == "capture"
    ):
        return False
    return all(
        observation.get("action") == action
        and observation.get("lifecycle") == lifecycle
        and observation.get("session_sha256") == session
        and observation.get("capture_nonce_sha256") == nonce
        and isinstance(observation.get("response_sha256"), str)
        and re.fullmatch(r"[a-f0-9]{64}", observation["response_sha256"]) is not None
        and type(observation.get("response_bytes")) is int
        and 0 < observation["response_bytes"] <= 1024 * 1024
        for observation, (action, lifecycle, nonce) in zip(observations, expected, strict=True)
    )


def execute_case(
    target,
    *,
    invalidate: bool,
    retain: bool,
    evidence: dict | None = None,
    transition_kind: str = "logout",
) -> dict:
    value = scenario(target.platform, target.package, transition_kind)
    key = "apk_sha256" if target.platform == "android" else "executable_sha256"
    authority = OwnedAuthority(target.package, target.build[key], invalidate=invalidate)
    server = AuthorityServer(authority)
    evidence = {} if evidence is None else evidence
    evidence.update(
        state="inconclusive",
        source_version=RUNTIME_CONTROL_SOURCE_VERSION,
        transition_kind=transition_kind,
        platform=target.platform,
        installed_build=target.build,
        fixture_policy={"invalidate": invalidate, "retain": retain},
        authority_health=[],
        verified_fields={},
    )
    primary_failed = False
    try:
        health = server.health()
        evidence["authority_health"].append({"phase": "before-session", **health})
        if health["state"] != "verified":
            raise ValueError("Owned authority readiness/identity unconfirmed")
        adapter = InstalledTransportAdapter(target, server, retain=retain, transition_kind=transition_kind)
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
        after = recorder.capture(
            "after",
            {"account": "b", "state": "authenticated"}
            if transition_kind == "account_switch"
            else {"account": None, "state": "logged_out"},
            transition_kind,
        )
        if after.get("acquisition", {}).get("capture_errors"):
            raise adapter.acquisition_error or ValueError("Installed fixture after acquisition inconclusive")
        snapshots = {"before": before, "after": after}
        backend = (
            old_account_switch_replay(before, after)
            if transition_kind == "account_switch"
            else evaluate_backend_invalidation(value, snapshots)
        )
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
            ("passed" if transition_kind == "account_switch" or invalidate else "failed"),
            ("failed" if retain else "passed"),
        )
        evidence["verified_fields"] = {
            "backend_policy": backend[0]["state"] == expected_backend,
            "storage_policy": storage[0]["state"] == expected_storage,
            "workflow": workflow[0]["state"] == "passed",
            "bound_os_delivery": (
                target.platform != "ios" or ios_delivery_complete(target.delivery_observations, before, after)
            ),
        }
        if transition_kind == "account_switch":
            evidence["verified_fields"]["account_b_authentication"] = (
                adapter.account_b_authentication is not None
                and bool(authority.b_credential)
                and authority.b_active
                and authority.switched
                and not authority.active
                and not authority.logged_out
            )
            evidence["account_b_authentication"] = adapter.account_b_authentication
        evidence.update(
            {
                "state": "passed" if all(evidence["verified_fields"].values()) else "inconclusive",
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
                "os_delivery_observations": target.delivery_observations if target.platform == "ios" else [],
            }
        )
        return evidence
    except Exception:
        primary_failed = True
        # Diagnostics run only after the original acquisition deadline has failed.
        # They cannot replace its exception or turn missing delivery into success.
        try:
            health = server.health()
        except Exception:
            health = {"state": "unconfirmed"}
        evidence["authority_health"].append({"phase": "after-failure", **health})
        raise
    finally:
        evidence["authority_event_counts"] = server.event_counts()
        with authority.lock:
            evidence["authority_issue_diagnostic"] = authority_issue_projection(authority.events)
        try:
            server.close()
            evidence["authority_cleanup"] = "confirmed"
        except Exception:
            evidence["authority_cleanup"] = "unconfirmed"
            evidence["state"] = "inconclusive"
            if not primary_failed:
                raise


def execute_backend_cases(results: list[dict] | None = None) -> list[dict]:
    """Real HTTP fallback proof, explicitly without installed-app or OS delivery claims."""
    results = [] if results is None else results
    for invalidate in (True, False):
        authority = OwnedAuthority(
            "apsa.fixture.backend", digest(b"NEW synthetic HTTP-only client"), invalidate=invalidate
        )
        authority.bind(uuid.uuid4().hex + uuid.uuid4().hex)
        server = AuthorityServer(authority)
        result = {"state": "inconclusive", "invalidate": invalidate, "authority_health": []}
        results.append(result)
        primary_failed = False
        try:
            health = server.health()
            result["authority_health"].append({"phase": "before-session", **health})
            if health["state"] != "verified":
                raise ValueError("Owned authority readiness/identity unconfirmed")
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
            result.update(
                {
                    "state": "passed" if verified else "inconclusive",
                    "invalidate": invalidate,
                    "scope": "owned synthetic authority; actual separate HTTP issue/logout/replay requests only",
                    "installed_app": "unsupported",
                    "os_delivery": "unsupported",
                    "probes": [record(before), record(after)],
                    "authority_events": authority.events,
                    "verified_fields": {"backend_policy": verified},
                }
            )
        except Exception:
            primary_failed = True
            try:
                health = server.health()
            except Exception:
                health = {"state": "unconfirmed"}
            result["authority_health"].append({"phase": "after-failure", **health})
            raise
        finally:
            result["authority_event_counts"] = server.event_counts()
            try:
                server.close()
                result["authority_cleanup"] = "confirmed"
            except Exception:
                result["authority_cleanup"] = "unconfirmed"
                result["state"] = "inconclusive"
                if not primary_failed:
                    raise
    return results


def ios_url_diagnostic_projection(observation: dict) -> dict:
    """Retain only fixed enums, booleans and digests; never interpret as delivery."""
    result = {}
    contract_states = {
        "verified",
        "mismatch",
        "malformed-or-over-bound",
        "unavailable",
        "owned-path-mismatch",
    }
    for name in ("installed_url_contract", "helper_url_contract"):
        value = observation.get(name)
        if not isinstance(value, dict):
            continue
        result[name] = {
            "state": value.get("state")
            if isinstance(value.get("state"), str) and value.get("state") in contract_states
            else "unavailable",
            **{
                key: item
                for key, item in value.items()
                if key
                in {
                    "package_matches",
                    "scheme_matches",
                    "url_types_match",
                    "query_schemes_match",
                    "scene_matches",
                    "executable_matches",
                }
                and type(item) is bool
            },
        }
        if isinstance(value.get("sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", value["sha256"]):
            result[name]["sha256"] = value["sha256"]
    value = observation.get("dispatcher")
    if isinstance(value, dict):
        result["dispatcher"] = {
            "state": "diagnostic-only" if value.get("state") == "diagnostic-only" else "unmeasured",
            **{
                key: item
                for key, item in value.items()
                if key in {"can_open_url", "open_completion", "uri_matches", "xctest_exit_success"}
                and type(item) is bool
            },
        }
        for key in ("uri_sha256", "manifest_sha256", "device_sha256", "target_package_sha256"):
            if isinstance(value.get(key), str) and re.fullmatch(r"[a-f0-9]{64}", value[key]):
                result["dispatcher"][key] = value[key]
        if type(value.get("invocation")) is int and 1 <= value["invocation"] <= 8:
            result["dispatcher"]["invocation"] = value["invocation"]
        if isinstance(value.get("phase"), str) and value.get("phase") in {
            "rejected-owned-uri",
            "validated-owned-uri",
            "os-open-requested",
            "os-open-completed",
        }:
            result["dispatcher"]["phase"] = value["phase"]
    value = observation.get("registration")
    if isinstance(value, dict):
        result["registration"] = {
            "url_types_state": value.get("url_types_state")
            if isinstance(value.get("url_types_state"), str)
            and value.get("url_types_state") in {"reported", "unreported"}
            else "unmeasured"
        }
    return result


def authority_issue_projection(events) -> dict:
    """Bounded issuance diagnostics; never a retry or an acceptance condition."""
    counts = {"requests", "accepted", "rejected", "bound", "unbound", "distinct_request_digests"}
    if isinstance(events, dict):
        if (
            set(events) == counts | {"state", "truncated"}
            and events.get("state") == "diagnostic-only"
            and type(events.get("truncated")) is bool
            and all(type(events[key]) is int and 0 <= events[key] <= 1024 for key in counts)
        ):
            return events.copy()
        return {"state": "unmeasured"}
    if not isinstance(events, list):
        return {"state": "unmeasured"}
    issues = [event for event in events[:1024] if isinstance(event, dict) and event.get("route") == "/issue"]
    request_digests = {
        event["request_sha256"]
        for event in issues
        if isinstance(event.get("request_sha256"), str)
        and re.fullmatch(r"[a-f0-9]{64}", event["request_sha256"])
    }
    return {
        "state": "diagnostic-only",
        "requests": len(issues),
        "accepted": sum(type(event.get("status")) is int and event["status"] == 200 for event in issues),
        "rejected": sum(type(event.get("status")) is int and event["status"] == 403 for event in issues),
        "bound": sum(event.get("bound") is True for event in issues),
        "unbound": sum(event.get("bound") is False for event in issues),
        "distinct_request_digests": len(request_digests),
        "truncated": len(events) > 1024,
    }


def runtime_projection(evidence: dict) -> dict:
    """Small, typed public-CI proof; arbitrary error text/URLs/bodies stay out."""

    def hash_value(value):
        return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None

    def state(value, allowed):
        return value if isinstance(value, str) and value in allowed else "unmeasured"

    cases = []
    for case in evidence.get("cases", [])[:6]:
        health = []
        for probe in case.get("authority_health", [])[:2]:
            health.append(
                {
                    "phase": state(probe.get("phase"), {"before-session", "after-failure"}),
                    "state": state(probe.get("state"), {"verified", "unconfirmed"}),
                    **{
                        key: probe[key]
                        for key in ("nonce_sha256", "pid_sha256", "instance_sha256", "response_sha256")
                        if hash_value(probe.get(key))
                    },
                }
            )
        cases.append(
            {
                "state": state(case.get("state"), {"passed", "inconclusive"}),
                "source_version": case.get("source_version")
                if type(case.get("source_version")) is int
                else None,
                "transition_kind": state(case.get("transition_kind"), {"logout", "account_switch"}),
                "fixture_policy": {
                    key: value
                    for key, value in case.get(
                        "fixture_policy", {"invalidate": case.get("invalidate")}
                    ).items()
                    if key in {"invalidate", "retain"} and type(value) is bool
                },
                "installed_build": {
                    key: value
                    for key, value in case.get("installed_build", {}).items()
                    if key in {"apk_sha256", "executable_sha256", "info_plist_sha256"} and hash_value(value)
                },
                "authority_health": health,
                "authority_event_counts": {
                    key: value
                    for key, value in case.get("authority_event_counts", {}).items()
                    if key in {"/issue", "/logout", "/switch", "/protected", "unsupported"}
                    and type(value) is int
                    and 0 <= value <= 1024
                },
                "authority_issue_diagnostic": authority_issue_projection(
                    case.get("authority_issue_diagnostic", case.get("authority_events"))
                ),
                "authority_cleanup": state(case.get("authority_cleanup"), {"confirmed", "unconfirmed"}),
                "verified_fields": {
                    key: value
                    for key, value in case.get("verified_fields", {}).items()
                    if key
                    in {
                        "backend_policy",
                        "storage_policy",
                        "workflow",
                        "bound_os_delivery",
                        "account_b_authentication",
                    }
                    and type(value) is bool
                },
            }
        )
    result = {
        "schema_version": 1,
        "source_version": evidence.get("source_version")
        if type(evidence.get("source_version")) is int
        else None,
        "state": state(evidence.get("state"), {"passed", "inconclusive"}),
        "terminal": evidence.get("terminal") is True,
        "platform": state(evidence.get("platform"), {"android", "ios", "backend"}),
        "measurement": state(
            evidence.get("measurement"),
            {"installed-acquisition", "backend-http-controls", "os-url-diagnostic-control"},
        ),
        "commit": evidence.get("commit")
        if isinstance(evidence.get("commit"), str) and re.fullmatch(r"[a-f0-9]{40}", evidence["commit"])
        else None,
        "source_sha256": {
            key: value
            for key, value in evidence.get("source_sha256", {}).items()
            if key
            in {
                "Transport.swift",
                "UrlDispatcher.swift",
                "TransportActivity.java",
                "validate_runtime_transport.py",
                "runtime_transport.py",
                "runtime_acquisition.py",
                "runtime_evidence.py",
                "ios_xctest_dispatch.py",
                "validate_runtime_xctest_control.py",
            }
            and hash_value(value)
        },
        "case_count": len(evidence.get("cases", [])),
        "cases": cases,
        "ios_url_diagnostics": ios_url_diagnostic_projection(
            {**evidence.get("ios_url_diagnostics", {}), **evidence.get("failure_observation", {})}
        ),
        "cleanup": state(
            evidence.get("cleanup", {}).get("state") if isinstance(evidence.get("cleanup"), dict) else None,
            {"confirmed", "unconfirmed"},
        ),
        "workflow_cleanup": state(
            evidence.get("workflow_cleanup", {}).get("state"), {"confirmed", "unconfirmed"}
        ),
        "physical_device_verified": False,
    }
    encoded = json.dumps(result, sort_keys=True).encode()
    if len(encoded) > 16 * 1024:
        return {
            "state": "unmeasured",
            "reason": "projection-over-bound",
            "sha256": digest(encoded),
            "bytes": len(encoded),
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("android", "ios", "backend"), required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--jdk", type=Path)
    parser.add_argument("--ios-url-driver", choices=["simctl", "companion", "xctest"], default="simctl")
    parser.add_argument("--ios-device-set", choices=["custom", "default"], default="custom")
    parser.add_argument("--ios-runtime")
    parser.add_argument("--ios-device-type", default=IOS_PINNED_DEVICE_TYPE)
    parser.add_argument(
        "--ios-os-url-control",
        action="store_true",
        help="NEW noncredential warm/cold callback diagnostic; no acquisition/HTTP claim",
    )
    args = parser.parse_args()
    if args.ios_device_set == "default" and args.platform != "ios":
        parser.error("NEW default-set control requires iOS")
    if args.ios_os_url_control and args.platform != "ios":
        parser.error("NEW OS URL diagnostic control requires iOS")
    if args.ios_url_driver == "xctest" and (args.platform != "ios" or args.ios_device_set != "default"):
        parser.error("NEW XCTest dispatch requires iOS and an owned default-set target")
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
        print(json.dumps({"runtime_validation": runtime_projection(evidence)}, sort_keys=True), flush=True)
        if result["state"] != "confirmed":
            raise SystemExit(1)
        return
    root.mkdir(exist_ok=False)
    commands = Commands(root)
    commands.resources = OwnedResources(root)
    evidence = {
        "schema_version": 1,
        "source_version": RUNTIME_CONTROL_SOURCE_VERSION,
        "state": "inconclusive",
        "terminal": False,
        "platform": args.platform,
        "ios_device_set": args.ios_device_set if args.platform == "ios" else None,
        "ios_url_driver": args.ios_url_driver if args.platform == "ios" else None,
        "measurement": "os-url-diagnostic-control"
        if args.ios_os_url_control
        else "backend-http-controls"
        if args.platform == "backend"
        else "installed-acquisition",
        "commit": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "source_sha256": {
            path.name: digest(path.read_bytes())
            for path in (
                SOURCES / "Transport.swift",
                SOURCES / "UrlDispatcher.swift",
                SOURCES / "TransportActivity.java",
                Path(__file__).resolve(),
                Path(__file__).parents[1] / "tests/support/runtime_transport.py",
                Path(__file__).parents[1] / "src/mobile_audit/runtime_acquisition.py",
                Path(__file__).parents[1] / "src/mobile_audit/runtime_evidence.py",
                *(
                    (
                        Path(__file__).with_name("ios_xctest_dispatch.py"),
                        Path(__file__).with_name("validate_runtime_xctest_control.py"),
                    )
                    if args.platform == "ios" and args.ios_url_driver == "xctest"
                    else ()
                ),
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
            execute_backend_cases(evidence["cases"])
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
        policies = (
            (("logout", True, False),)
            if args.ios_os_url_control
            else (
                ("logout", True, False),
                ("logout", True, True),
                ("logout", False, False),
                ("logout", False, True),
                ("account_switch", True, False),
                ("account_switch", True, True),
            )
        )
        for index, (transition_kind, invalidate, retain) in enumerate(policies):
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
                    target = IosTarget(
                        case_root,
                        package,
                        commands,
                        args.ios_runtime
                        if args.ios_device_set == "default"
                        else args.ios_runtime or IOS_PINNED_RUNTIME,
                        args.ios_device_type,
                        url_driver=args.ios_url_driver,
                        device_set_mode=args.ios_device_set,
                        readiness_only=args.ios_os_url_control,
                    )
                stage = (
                    args.platform
                    + "-case-"
                    + str(index)
                    + (
                        "-os-url-diagnostic-control"
                        if args.ios_os_url_control
                        else "-session-delivery-capture-http"
                    )
                )
                if args.ios_os_url_control:
                    if not isinstance(target, IosTarget):
                        raise ValueError("NEW OS URL diagnostic control requires iOS target")
                    result = target.url_control()
                else:
                    result = {
                        "transition_kind": transition_kind,
                        "source_version": RUNTIME_CONTROL_SOURCE_VERSION,
                    }
                    # Persist the failed case too, before cleanup and without raw responses.
                    evidence["cases"].append(result)
                    execute_case(
                        target,
                        invalidate=invalidate,
                        retain=retain,
                        evidence=result,
                        transition_kind=transition_kind,
                    )
                if isinstance(target, IosTarget):
                    result["new_simulator_uuid"] = target.device
                    evidence["ios_url_diagnostics"] = target.url_contract_diagnostics()
                if args.ios_os_url_control:
                    evidence["cases"].append(result)
            except Exception as error:
                if isinstance(target, IosTarget):
                    try:
                        evidence["ios_url_diagnostics"] = target.url_contract_diagnostics()
                    except Exception:
                        # Diagnostics cannot replace the original acquisition/OS failure.
                        evidence["ios_url_diagnostics"] = {}
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
            if len(evidence["cases"]) == len(policies)
            and all(case["state"] == "passed" for case in evidence["cases"])
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
        print(json.dumps({"runtime_validation": runtime_projection(evidence)}, sort_keys=True), flush=True)
        if args.ios_os_url_control:
            # Only the bounded diagnostic structures produced above; never raw files/URLs.
            projection = {
                key: evidence.get(key)
                for key in ("measurement", "state", "terminal", "cases", "failure_observation", "cleanup")
            }
            serialized = json.dumps(projection, sort_keys=True).encode()
            if len(serialized) > 8 * IOS_EVENT_BYTES:
                projection = {
                    "measurement": "os-url-diagnostic-control",
                    "state": "unmeasured",
                    "reason": "control-evidence-over-bound",
                    "sha256": digest(serialized),
                    "bytes": len(serialized),
                }
            print(json.dumps({"runtime_url_control_diagnostic": projection}, sort_keys=True), flush=True)
    print(json.dumps({"state": evidence["state"], "cases": len(evidence["cases"])}))
    if evidence["state"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
