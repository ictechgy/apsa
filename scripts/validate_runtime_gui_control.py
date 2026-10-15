#!/usr/bin/env python3
"""Hosted-only Simulator GUI setup differential around the unchanged driver.

No UI inspection, booted/default device selectors, discovery or raw Simulator logs.
The Simulator arguments have upstream usage, not a supported Apple contract:
https://github.com/plu/simctl/blob/master/lib/simctl/command/launch.rb
Process liveness does not attest GUI binding, foreground state or URL delivery.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from mobile_audit.core import digest
from scripts import validate_runtime_transport as transport

PINNED_DEVELOPER_DIR = "/Applications/Xcode_16.4.app/Contents/Developer"
MODERN_DEVELOPER_DIR = "/Applications/Xcode_26.3.app/Contents/Developer"
GUI_SETTLE_SECONDS = 5
GUI_WAIT_SECONDS = 10
GUI_BOOTSTATUS_SECONDS = 600


@dataclass(frozen=True)
class GuiToolchain:
    key: str
    developer_dir: str
    runtime: str
    device_type: str

    def evidence(self) -> dict:
        values = {
            "toolchain": self.key,
            "developer_dir": self.developer_dir,
            "ios_runtime": self.runtime,
            "ios_device_type": self.device_type,
        }
        return {**values, **{f"{key}_sha256": digest(value.encode()) for key, value in values.items()}}


GUI_TOOLCHAINS: Mapping[str, GuiToolchain] = MappingProxyType(
    {
        "legacy": GuiToolchain(
            "legacy", PINNED_DEVELOPER_DIR, transport.IOS_PINNED_RUNTIME, transport.IOS_PINNED_DEVICE_TYPE
        ),
        "modern": GuiToolchain(
            "modern",
            MODERN_DEVELOPER_DIR,
            "com.apple.CoreSimulator.SimRuntime.iOS-26-2",
            "com.apple.CoreSimulator.SimDeviceType.iPhone-16",
        ),
    }
)


def selected_toolchain(key: str) -> GuiToolchain:
    try:
        return GUI_TOOLCHAINS[key]
    except (KeyError, TypeError):
        raise ValueError("GUI setup control toolchain must be legacy or modern") from None


def validate_selector(selector: str, config: GuiToolchain):
    if selector not in {"custom", "default"}:
        raise ValueError("GUI setup control device-set selector differs")
    if config.key == "modern" and selector != "custom":
        raise ValueError("GUI setup control modern toolchain requires custom device set")


def validate_setup_mode(setup_mode: str, config: GuiToolchain, selector: str):
    if setup_mode not in {"gui", "headless"}:
        raise ValueError("Simulator setup mode must be gui or headless")
    if setup_mode == "headless" and (config.key != "modern" or selector != "custom"):
        raise ValueError("Headless setup control requires modern custom device set")


def hosted_gui_guard(root: Path, env: Mapping[str, str], toolchain: str = "legacy") -> Path:
    """Operational containment only; no host/device/UI attestation."""
    config = selected_toolchain(toolchain)
    required = {
        "GITHUB_ACTIONS": "true",
        "CI": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "macOS",
        "HOME": "/Users/runner",
        "DEVELOPER_DIR": config.developer_dir,
    }
    forbidden = {
        "SIMULATOR_DEVICE_SET_PATH",
        "SIMCTL_DEVICE_SET_PATH",
        "CORE_SIMULATOR_DEVICE_SET_PATH",
        "CFFIXED_USER_HOME",
        "SIMULATOR_ROOT",
        "SIMULATOR_HOME",
        "SIMULATOR_UDID",
    }
    if (
        platform.system() != "Darwin"
        or platform.machine() != "arm64"
        or any(env.get(key) != value for key, value in required.items())
        or forbidden.intersection(env)
        or any(key.startswith("SIMCTL_CHILD_") for key in env)
        or not env.get("RUNNER_TEMP")
    ):
        raise ValueError("GUI setup control requires pinned disposable hosted ARM macOS")
    runner_temp = Path(env["RUNNER_TEMP"]).resolve()
    if root != root.resolve() or root == runner_temp or not root.is_relative_to(runner_temp):
        raise ValueError("GUI setup control work must be contained in RUNNER_TEMP")
    # Exact pinned source, without xcode-select, preferences or tool discovery.
    return Path(config.developer_dir) / "Applications/Simulator.app/Contents/MacOS/Simulator"


class GuiCommands(transport.Commands):
    """Observe fresh CREATE/boot custody and retain only spawned GUI children."""

    def __init__(
        self,
        root: Path,
        env: Mapping[str, str] | None = None,
        *,
        output_name: str = "commands.json",
        selector: str = "custom",
        toolchain: str = "legacy",
        setup_mode: str = "gui",
    ):
        self.config = selected_toolchain(toolchain)
        validate_selector(selector, self.config)
        validate_setup_mode(setup_mode, self.config, selector)
        self.setup_mode = setup_mode
        super().__init__(root, env=dict(env) if env is not None else None, output_name=output_name)
        hosted_gui_guard(root, self.env, self.config.key)
        self.selector = selector
        # Default is the literal disposable hosted home factory, never caller input.
        self._selected()
        self.created: set[str] = set()
        self.booted: set[str] = set()
        self.gui: dict[str, subprocess.Popen[bytes]] = {}
        self.gui_records: list[dict] = []
        self.gui_cleanup: dict[str, dict] = {}
        self.setup_records: list[dict] = []
        self.gui_update: Callable[[], None] | None = None

    def _selected(self) -> tuple[list[str], Path]:
        prefix, device_set = transport.ios_selector(self.root, self.selector, self.env)
        if self.selector == "custom":
            literal = self.root / "simulator-set"
            if literal.is_symlink() or device_set != literal or literal.resolve() != literal:
                raise ValueError("GUI setup control custom device-set ownership differs")
        return prefix, device_set

    def _record(self, operation: str, **fields):
        record = {"operation": operation, **fields}
        self.records.append(record)
        (self.root / self.output_name).write_text(json.dumps(self.records, indent=2) + "\n")
        if self.gui_update is not None:
            self.gui_update()

    def _owned(self, device: str):
        hosted_gui_guard(self.root, self.env, self.config.key)
        if (
            str(uuid.UUID(device)).upper() != device
            or device not in self.created
            or self.resources is None
            or self.resources.root != self.root
            or self.resources.value.get("root") != str(self.root)
            or self.resources.value.get("ios", {}).get(device)
            != {"deleted": False, "selector": self.selector}
        ):
            raise ValueError("GUI setup control requires a fresh journaled UUID with matching selector")
        _, device_set = self._selected()
        return device_set

    def _start_gui(self, device: str):
        if self.setup_mode != "gui":
            raise ValueError("Headless setup control cannot start Simulator GUI")
        device_set = self._owned(device)
        if device not in self.booted or device in self.gui:
            raise ValueError("GUI setup control boot custody differs")
        argv = [
            str(hosted_gui_guard(self.root, self.env, self.config.key)),
            "-CurrentDeviceUDID",
            device,
            "-DeviceSetPath",
            str(device_set),
        ]
        record = {
            **self.config.evidence(),
            "uuid_sha256": digest(device.encode()),
            "argv_sha256": digest(json.dumps(argv).encode()),
            "selector": self.selector,
            "bootstatus_timeout_seconds": GUI_BOOTSTATUS_SECONDS,
            "state": "spawn-unconfirmed",
            "binding": "unverified-undocumented-arguments",
            "foreground": "unmeasured",
            "delivery": "unsupported",
        }
        self.gui_records.append(record)
        # Persist unknown custody before spawning. An interrupted driver cannot
        # use an old PID to recover ownership or later claim confirmed UI cleanup.
        self._record("ios-simulator-gui-start-pending", **record)
        try:
            # The direct executable provides lifetime custody; `open` would not.
            process = subprocess.Popen(
                argv,
                cwd=self.root,
                env=self.env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.gui[device] = process
            record["state"] = "spawned"
            time.sleep(GUI_SETTLE_SECONDS)
            record["process_status"] = process.poll()
            record["state"] = "live-after-settle" if record["process_status"] is None else "exited"
        except OSError as error:
            record["errno"] = error.errno
            self._record("ios-simulator-gui-start", **record)
            raise transport.CommandFailure("command-spawn-os-error", record) from None
        self._record("ios-simulator-gui-start", **record)
        if record["state"] != "live-after-settle":
            raise ValueError("GUI setup control Simulator child exited during setup")

    def close_gui(self, device: str) -> dict:
        """Signal/reap only the exact Popen child, never a saved PID or global app."""
        process = self.gui[device]
        result = {
            "uuid_sha256": digest(device.encode()),
            "selector": self.selector,
            "state": "unconfirmed",
            "reaped": False,
        }
        try:
            if process.poll() is None:
                process.terminate()
            result["process_status"] = process.wait(timeout=GUI_WAIT_SECONDS)
            result.update(state="confirmed", reaped=True)
        except (OSError, subprocess.SubprocessError) as error:
            result["reason"] = "owned-gui-reap-unconfirmed"
            if isinstance(error, OSError):
                result["errno"] = error.errno
        self.gui_cleanup[device] = result
        try:
            self._record("ios-simulator-gui-cleanup", **result)
        except OSError:
            result["command_journal"] = "unconfirmed"
        return result

    def close_all_gui(self) -> dict:
        for device in self.gui:
            if self.gui_cleanup.get(device, {}).get("state") != "confirmed":
                self.close_gui(device)
        results = list(self.gui_cleanup.values())
        return {
            "scope": "only directly spawned Simulator children",
            "state": "confirmed" if all(item["state"] == "confirmed" for item in results) else "unconfirmed",
            "results": results,
        }

    def run(self, argv: list[str], **kwargs) -> bytes:
        hosted_gui_guard(self.root, self.env, self.config.key)
        prefix, _ = self._selected()
        tail = argv[len(prefix) :] if argv[: len(prefix)] == prefix else []
        if "simctl" in argv and not tail:
            raise ValueError("GUI setup control requires its exact device-set selector")
        if tail and tail[0] == "create":
            if (
                len(tail) != 4
                or tail[2:] != [self.config.device_type, self.config.runtime]
                or not tail[1].startswith("APSA-NEW-")
            ):
                raise ValueError("GUI setup control fresh CREATE inputs differ")
        elif tail and tail[0] != "help":
            if (
                tail[0]
                not in {
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
                or len(tail) < 2
            ):
                raise ValueError("GUI setup control device operation differs")
            self._owned(tail[1])
        if tail and tail[0] in {"boot", "bootstatus"}:
            expected_length = 3 if tail[0] == "bootstatus" else 2
            if len(tail) != expected_length or (tail[0] == "bootstatus" and tail[2] != "-b"):
                raise ValueError("GUI setup control boot selector differs")
            self._owned(tail[1])
            if tail[0] == "bootstatus" and tail[1] not in self.booted:
                raise ValueError("GUI setup control requires successful owned boot")
            if tail[0] == "bootstatus":
                # This setup differential alone has a longer fresh-boot budget.
                # CommandFailure still propagates once; no retry or fallback.
                kwargs["timeout"] = GUI_BOOTSTATUS_SECONDS
        if tail and tail[0] in {"shutdown", "delete"} and len(tail) == 2 and tail[1] in self.gui:
            if self.gui_cleanup.get(tail[1], {}).get("state") != "confirmed":
                self.close_gui(tail[1])
        raw = super().run(argv, **kwargs)
        if tail and tail[0] == "create":
            if (
                len(tail) != 4
                or tail[2:] != [self.config.device_type, self.config.runtime]
                or not tail[1].startswith("APSA-NEW-")
                or self.last_status != 0
            ):
                raise ValueError("GUI setup control fresh CREATE inputs differ")
            device = str(uuid.UUID(raw.decode().strip())).upper()
            if (
                device in self.created
                or self.resources is None
                or device in self.resources.value.get("ios", {})
            ):
                raise ValueError("GUI setup control CREATE UUID is not fresh")
            self.created.add(device)
        elif tail and tail[0] == "boot" and self.last_status == 0:
            self.booted.add(tail[1])
        elif tail and tail[0] == "bootstatus" and self.last_status == 0:
            if self.setup_mode == "gui":
                self._start_gui(tail[1])
            else:
                record = {
                    **self.config.evidence(),
                    "uuid_sha256": digest(tail[1].encode()),
                    "selector": self.selector,
                    "state": "owned-bootstatus-complete",
                    "setup_mode": "headless",
                    "gui_spawned": False,
                    "bootstatus_timeout_seconds": GUI_BOOTSTATUS_SECONDS,
                    "delivery": "unsupported",
                }
                self.setup_records.append(record)
                self._record("ios-headless-setup-ready", **record)
        return raw


def run_control(
    root: Path, driver: str, selector: str = "custom", toolchain: str = "legacy", setup_mode: str = "gui"
):
    """Keep driver verdict/exit intact, attach a separate setup-specific result."""
    config = selected_toolchain(toolchain)
    validate_selector(selector, config)
    validate_setup_mode(setup_mode, config, selector)
    hosted_gui_guard(root, dict(os.environ), config.key)
    if root.exists() or root.is_symlink():
        raise ValueError("GUI setup control requires a NEW work directory")
    if driver not in {"simctl", "companion"}:
        raise ValueError("GUI setup control URL driver differs")
    transport.ios_selector(root, selector, dict(os.environ))
    instances: list[GuiCommands] = []
    original_commands, original_argv = transport.Commands, sys.argv
    evidence_name = "headless-control.json" if setup_mode == "headless" else "gui-control.json"

    class CapturedGuiCommands(GuiCommands):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, selector=selector, toolchain=config.key, setup_mode=setup_mode, **kwargs)
            instances.append(self)
            self.gui_update = checkpoint
            checkpoint()

    result = {
        "schema_version": 1,
        "source_version": 2,
        **config.evidence(),
        "measurement": f"hosted-simulator-{setup_mode}-setup-control",
        "setup_mode": setup_mode,
        "scope": "Only CREATE-returned journaled NEW UUIDs; setup-specific result independent of primary gate",
        "hypothesis": "Pinned toolchain/runtime, device-set selection, fresh boot allowance and Simulator GUI startup may affect OS URL delivery",
        "state": "inconclusive",
        "terminal": False,
        "driver": driver,
        "ios_device_set": selector,
        "bootstatus_timeout_seconds": GUI_BOOTSTATUS_SECONDS,
        "primary_bootstatus_timeout_seconds": 180,
        "commit": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "source_sha256": digest(Path(__file__).read_bytes()),
        "ui_inspection": "none",
        "gui_binding": "not-started" if setup_mode == "headless" else "unverified-undocumented-arguments",
        "gui_foreground": "not-started" if setup_mode == "headless" else "unmeasured",
        "driver_exit_status": None,
        "gui": [],
        "setup": [],
    }

    def checkpoint():
        result["gui"] = [item for commands in instances for item in commands.gui_records]
        result["setup"] = [item for commands in instances for item in commands.setup_records]
        result["gui_cleanup"] = {
            "scope": "only directly spawned Simulator children",
            "state": "unconfirmed",
            "reason": "driver-active-or-interrupted-no-terminal-reap-proof",
            "results": [item for commands in instances for item in commands.gui_cleanup.values()],
        }
        if setup_mode == "headless":
            result["gui_cleanup"] = {"scope": "no GUI child requested", "state": "not-started", "results": []}
        (root / evidence_name).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")

    failed = True
    try:
        transport.Commands = CapturedGuiCommands
        sys.argv = [
            str(Path(transport.__file__)),
            "--platform",
            "ios",
            "--ios-device-set",
            selector,
            "--ios-runtime",
            config.runtime,
            "--ios-device-type",
            config.device_type,
            "--ios-url-driver",
            driver,
            "--work",
            str(root),
        ]
        try:
            transport.main()
        except SystemExit as error:
            result["driver_exit_status"] = (
                error.code if type(error.code) is int else 0 if error.code is None else 1
            )
            failed = result["driver_exit_status"] != 0
            if failed:
                raise
        else:
            result["driver_exit_status"] = 0
            failed = False
    finally:
        transport.Commands, sys.argv = original_commands, original_argv
        cleanups = []
        for commands in instances if setup_mode == "gui" else []:
            try:
                cleanups.append(commands.close_all_gui())
            except Exception:
                # Cleanup diagnostics cannot suppress the original driver failure.
                cleanups.append({"state": "unconfirmed", "reason": "owned-gui-cleanup-unconfirmed"})
        result["gui"] = [item for commands in instances for item in commands.gui_records]
        result["setup"] = [item for commands in instances for item in commands.setup_records]
        result["gui_cleanup"] = {
            "scope": "only directly spawned Simulator children",
            "state": "confirmed" if all(item["state"] == "confirmed" for item in cleanups) else "unconfirmed",
            "results": cleanups,
        }
        setup_passed = (
            bool(result["gui"])
            and all(item["state"] == "live-after-settle" for item in result["gui"])
            and result["gui_cleanup"]["state"] == "confirmed"
            and all(
                item.get("command_journal") != "unconfirmed"
                for commands in instances
                for item in commands.gui_cleanup.values()
            )
        )
        if setup_mode == "headless":
            result["gui_cleanup"] = {"scope": "no GUI child requested", "state": "not-started", "results": []}
            setup_passed = (
                bool(result["setup"])
                and not result["gui"]
                and all(not commands.gui for commands in instances)
                and all(item["state"] == "owned-bootstatus-complete" for item in result["setup"])
            )
        result["state"] = "passed-setup-specific" if not failed and setup_passed else "inconclusive"
        result["terminal"] = True
        if root.is_dir():
            try:
                (root / evidence_name).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
            except OSError:
                result["state"] = "inconclusive"
                result["evidence_write"] = "unconfirmed"
        key = "runtime_headless_control" if setup_mode == "headless" else "runtime_gui_control"
        print(json.dumps({key: result}, sort_keys=True), flush=True)
    if result["state"] != "passed-setup-specific":
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--ios-url-driver", choices=("simctl", "companion"), default="simctl")
    parser.add_argument("--ios-device-set", choices=("custom", "default"), default="custom")
    parser.add_argument("--ios-toolchain", choices=tuple(GUI_TOOLCHAINS), default="legacy")
    parser.add_argument("--setup-mode", choices=("gui", "headless"), default="gui")
    args = parser.parse_args()
    if args.setup_mode == "gui":
        run_control(args.work.resolve(), args.ios_url_driver, args.ios_device_set, args.ios_toolchain)
    else:
        run_control(
            args.work.resolve(), args.ios_url_driver, args.ios_device_set, args.ios_toolchain, args.setup_mode
        )


if __name__ == "__main__":
    main()
