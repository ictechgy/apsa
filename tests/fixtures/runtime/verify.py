"""Reproduce eight owned Android/iOS fixture modes on explicitly selected devices."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import sys
from pathlib import Path

from mobile_audit.audit import scan
from mobile_audit.core import file_digest, now, write_json
from mobile_audit.processes import command
from mobile_audit.runtime import devices, run
from mobile_audit.store import Store
from mobile_audit.tools import resolve_tool

ANDROID_PACKAGE = "audit.fixture.runtime"
IOS_PACKAGE = "audit.fixture.runtime.ios"
ACCOUNT_A = "mobile-audit-account-A-2026-canary"
FIXTURES = Path(__file__).resolve().parent


def invoke(args: list[str], timeout=90) -> str:
    return command(args, timeout=timeout, max_bytes=2 * 1024 * 1024).decode().strip()


def private_tree(root: Path) -> None:
    for directory, _, filenames in os.walk(root):
        Path(directory).chmod(0o700)
        for filename in filenames:
            path = Path(directory) / filename
            if path.is_file() and not path.is_symlink():
                path.chmod(0o700 if path.stat().st_mode & 0o111 else 0o600)


def build(platform: str, output: Path, sdk: Path, retained=False, switching=False) -> Path:
    args = [
        sys.executable,
        str(FIXTURES / "build.py"),
        "--platform",
        platform,
        "--sdk",
        str(sdk),
        "--out",
        str(output),
    ]
    if retained:
        args.append("--retained")
    if switching:
        args.append("--switch-account")
    path = Path(invoke(args).splitlines()[-1])
    private_tree(output)
    return path


def assertion(
    identifier: str, marker: str, *, surface="storage", purpose="residual", expect="absent"
) -> dict:
    return {
        "id": identifier,
        "baseline": "before",
        "snapshot": "after",
        "marker": marker,
        "surface": surface,
        "purpose": purpose,
        "expect": expect,
        "policy": f"Owned fixture assertion: {identifier}",
    }


def android_scenario(device: str, retained: bool, switching: bool, apk: Path) -> dict:
    transition = "switch" if switching else "logout"
    state = "Account B active" if switching else "Signed out state"
    screen = "Protected screen:" if retained and not switching else "Access denied"
    return {
        "platform": "android",
        "package": ANDROID_PACKAGE,
        "device": device,
        "build": {"apk_sha256": file_digest(apk)},
        "precondition": "Fresh owned fixture installation; account A is seeded through the explicit prepare URL. No production accounts or backend are used.",
        "markers": {"account_a": ACCOUNT_A, "transition": state, "target_screen": screen},
        "steps": [
            {
                "action": "open_url",
                "url": f"mobileaudit://test/prepare?mode={'retained' if retained else 'fixed'}",
            },
            {"action": "wait", "seconds": 1},
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": f"mobileaudit://test/{transition}"},
            {"action": "open_url", "url": "mobileaudit://test/protected"},
            {"action": "wait", "seconds": 1},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            assertion("residual_storage", "account_a"),
            assertion("transition_storage", "transition", purpose="transition", expect="present"),
            assertion(
                "target_delivery_ui", "target_screen", surface="ui", purpose="delivery", expect="present"
            ),
            assertion("authentication_ui", "account_a", surface="ui", purpose="authentication"),
        ],
    }


def ios_scenario(device: str, switching: bool, app: Path) -> dict:
    state = "Account B active" if switching else "Signed out state"
    return {
        "platform": "ios",
        "package": IOS_PACKAGE,
        "device": device,
        "build": {
            "executable_sha256": file_digest(app / "AuditFixture"),
            "info_plist_sha256": file_digest(app / "Info.plist"),
        },
        "precondition": "Fresh owned simulator fixture seeds account A on launch and performs its configured logout/account switch automatically four seconds after launch. No production account or backend is used.",
        "markers": {"account_a": ACCOUNT_A, "transition": state},
        "steps": [
            {"action": "launch"},
            {"action": "wait", "seconds": 1},
            {"action": "snapshot", "label": "before"},
            {"action": "wait", "seconds": 6},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            assertion("residual_storage", "account_a"),
            assertion("transition_storage", "transition", purpose="transition", expect="present"),
        ],
    }


def case_summary(report: dict, name: str, retained: bool, switching: bool) -> dict:
    observed = report["runtime"][-1]
    actual = {item["assertion"]["id"]: item["state"] for item in observed["assertions"]}
    expected = {"residual_storage": "failed" if retained else "passed", "transition_storage": "passed"}
    if observed["environment"]["platform"] == "android":
        expected.update(
            {
                "target_delivery_ui": "passed",
                "authentication_ui": "failed" if retained and not switching else "passed",
            }
        )
    surfaces = {
        label: {surface: detail["state"] for surface, detail in snapshot["surfaces"].items()}
        for label, snapshot in observed["snapshots"].items()
    }
    build_match = observed["build_verification"] in {
        "audited-apk-match",
        "audited-ipa-executable-and-config-match",
    }
    return {
        "case": name,
        "report_id": report["id"],
        "runtime_id": observed["id"],
        "state": "passed" if actual == expected and not observed["partial"] and build_match else "failed",
        "expected_assertions": expected,
        "actual_assertions": actual,
        "partial": observed["partial"],
        "build_verification": observed["build_verification"],
        "transition_verification": observed["transition_verification"],
        "delivery_verification": observed["delivery_verification"]
        if observed["environment"]["platform"] == "android"
        else "not-tested-in-storage-case",
        "target_activities": sorted(
            {step.get("component", "") for step in observed["steps"] if step.get("component")}
        ),
        "surfaces": surfaces,
        "runtime_findings": [
            finding["rule_id"] for finding in report["findings"] if finding["status"] == "runtime-confirmed"
        ],
        "installed_app": observed["environment"]["app"],
        "scope": "Owned fixture and captured canaries only; backend token invalidation and complete authentication security were not tested.",
    }


def verify_android(args, store: Store, apk: Path) -> list[dict]:
    adb = resolve_tool("adb")
    if not adb:
        raise ValueError("Android SDK adb is required")
    prefix = [adb, "-s", args.android_device]
    installed = invoke(prefix + ["shell", "pm", "list", "packages", ANDROID_PACKAGE]).splitlines()
    if f"package:{ANDROID_PACKAGE}" in installed:
        invoke(prefix + ["uninstall", ANDROID_PACKAGE])
    invoke(prefix + ["install", "-r", str(apk)])
    results = []
    for switching in (False, True):
        for retained in (True, False):
            name = f"android-{'switch' if switching else 'logout'}-{'retained' if retained else 'fixed'}"
            print(json.dumps({"event": "case-start", "case": name}), flush=True)
            try:
                if "Success" not in invoke(prefix + ["shell", "pm", "clear", ANDROID_PACKAGE]):
                    raise ValueError("Owned Android fixture data reset did not succeed")
                scenario = android_scenario(args.android_device, retained, switching, apk)
                scenario_path = args.out / name / "scenario.json"
                write_json(scenario_path, scenario)
                audited = scan(store, apk)
                report = run(store, scenario_path, audited["id"], screenshots=True)
                summary = case_summary(report, name, retained, switching)
                summary["audited_build_sha256"] = file_digest(apk)
                write_json(args.out / name / "report.json", report)
            except (ValueError, OSError) as error:
                summary = {"case": name, "state": "failed", "error": str(error)}
            write_json(args.out / name / "result.json", summary)
            results.append(summary)
            print(json.dumps({"event": "case-result", **summary}), flush=True)
    return results


def reset_ios(device: str) -> None:
    xcrun = resolve_tool("xcrun") or "xcrun"
    try:
        invoke([xcrun, "simctl", "uninstall", device, IOS_PACKAGE])
    except ValueError:
        # An absent owned fixture is already reset. Any remaining installation
        # after an unsuccessful uninstall is an error, rather than a reused state.
        try:
            invoke([xcrun, "simctl", "get_app_container", device, IOS_PACKAGE, "app"])
        except ValueError:
            return
        raise ValueError("Could not reset the owned iOS fixture") from None


def verify_ios(args, store: Store) -> list[dict]:
    results = []
    xcrun = resolve_tool("xcrun") or "xcrun"
    for switching in (False, True):
        for retained in (True, False):
            name = f"ios-{'switch' if switching else 'logout'}-{'retained' if retained else 'fixed'}"
            print(json.dumps({"event": "case-start", "case": name}), flush=True)
            try:
                case = args.out / name
                app = build("ios", case / "build", args.sdk, retained, switching)
                reset_ios(args.ios_device)
                invoke([xcrun, "simctl", "install", args.ios_device, str(app)])
                scenario = ios_scenario(args.ios_device, switching, app)
                scenario_path = case / "scenario.json"
                write_json(scenario_path, scenario)
                audited = scan(store, case / "build/fixture-simulator.ipa")
                report = run(store, scenario_path, audited["id"], screenshots=True)
                summary = case_summary(report, name, retained, switching)
                installed = Path(
                    invoke([xcrun, "simctl", "get_app_container", args.ios_device, IOS_PACKAGE, "app"])
                )
                source_info = plistlib.loads((app / "Info.plist").read_bytes())
                installed_info = plistlib.loads((installed / "Info.plist").read_bytes())
                summary["fixture_mode_metadata_matches"] = all(
                    source_info.get(key) == installed_info.get(key)
                    for key in ("AuditFixtureRetainCanary", "AuditFixtureSwitchAccount")
                )
                summary["info_plist_sha256"] = {
                    "built": file_digest(app / "Info.plist"),
                    "installed": file_digest(installed / "Info.plist"),
                }
                if not summary["fixture_mode_metadata_matches"]:
                    summary["state"] = "failed"
                write_json(case / "report.json", report)
            except (ValueError, OSError) as error:
                summary = {"case": name, "state": "failed", "error": str(error)}
            write_json(args.out / name / "result.json", summary)
            results.append(summary)
            print(json.dumps({"event": "case-result", **summary}), flush=True)
    return results


def ios_delivery_probe(args, store: Store) -> dict:
    name = "ios-deep-link-delivery-probe"
    case = args.out / "ios-switch-fixed"
    audited = scan(store, case / "build/fixture-simulator.ipa")
    scenario = {
        "platform": "ios",
        "package": IOS_PACKAGE,
        "device": args.ios_device,
        "precondition": "Owned fixed simulator fixture is installed after the eight-mode verification; URL-delivery canary has not been written.",
        "markers": {"target_delivery": "Target received deep link"},
        "steps": [
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": "mobileauditfixture://transition"},
            {"action": "wait", "seconds": 2},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [assertion("target_delivery", "target_delivery", purpose="delivery", expect="present")],
    }
    path = args.out / name / "scenario.json"
    write_json(path, scenario)
    report = run(store, path, audited["id"], screenshots=True)
    record = report["runtime"][-1]
    result = {
        "state": "confirmed" if record["delivery_verification"] == "marker-observed" else "unconfirmed",
        "report_id": report["id"],
        "runtime_id": record["id"],
        "assertions": record["assertions"],
        "manual_os_confirmation": False,
        "scope": "Delivery marker in the owned app only; no iOS UI or authentication assertion.",
    }
    write_json(args.out / name / "report.json", report)
    write_json(args.out / name / "result.json", result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--android-device", required=True)
    parser.add_argument("--ios-device", required=True)
    parser.add_argument("--sdk", type=Path, default=Path.home() / "Library/Android/sdk")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--ios-url-probe", action="store_true")
    args = parser.parse_args()
    args.out = args.out.expanduser().resolve()
    args.out.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.out.chmod(0o700)
    available = devices()
    if not any(
        device["id"] == args.android_device and device["state"] == "device" for device in available["android"]
    ):
        raise ValueError("Explicit Android device is unavailable")
    if not any(
        device["id"] == args.ios_device and device["state"] == "Booted"
        for device in available["ios_simulators"]
    ):
        raise ValueError("Explicit owned iOS simulator must already be booted")
    store = Store(args.out / "state")
    try:
        apk = build("android", args.out / "android-build", args.sdk)
        cases = verify_android(args, store, apk) + verify_ios(args, store)
        result = {
            "created": now(),
            "state": "passed"
            if len(cases) == 8 and all(case["state"] == "passed" for case in cases)
            else "failed",
            "cases": cases,
            "devices": {"android": args.android_device, "ios": args.ios_device},
            "scope": {
                "applications": [ANDROID_PACKAGE, IOS_PACKAGE],
                "ios_ui": "not-run",
                "ios_logs": "not-run",
                "clipboard": "not-run",
                "server_token_invalidation": "not-run",
                "physical_ios": "not-run",
                "intelligence": "offline cache only",
            },
        }
        if args.ios_url_probe and all(
            case["state"] == "passed" for case in cases if case["case"].startswith("ios-")
        ):
            result["ios_delivery_probe"] = ios_delivery_probe(args, store)
        write_json(args.out / "summary.json", result)
        private_tree(args.out)
        print(
            json.dumps(
                {
                    "event": "summary",
                    "state": result["state"],
                    "cases": len(cases),
                    "expected_vulnerable_modes": 4,
                    "delivery_probe": result.get("ios_delivery_probe", {}).get("state", "not-run"),
                    "evidence": str(args.out / "summary.json"),
                }
            ),
            flush=True,
        )
        return 0 if result["state"] == "passed" else 1
    finally:
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
