"""Hosted-only public OS URL dispatch to a journaled NEW transport fixture.

Builds one independent UI-test helper per case and reuses its generated
xctestrun for each URI. XCTest completion is diagnostic only: the transport
fixture's existing receipt, HTTP, storage and lifecycle checks decide delivery.

Apple contracts:
https://developer.apple.com/documentation/xcuiautomation/xcuisystem/open(_:)
https://developer.apple.com/library/archive/technotes/tn2339/_index.html
"""

from __future__ import annotations

import copy
import json
import plistlib
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mobile_audit.core import digest
from scripts import validate_runtime_xctest_control as control

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_URI_BYTES = 32 * 1024
MAX_DISPATCHES = 8
ENV_KEYS = {"APSA_DISPATCH_URI", "APSA_DISPATCH_URI_SHA256", "APSA_DISPATCH_SCHEME"}

TEST_SOURCE = r"""import XCTest
import CryptoKit

final class CallbackTests: XCTestCase {
    func testDispatchOwnedURL() throws {
        continueAfterFailure = false
        let env = ProcessInfo.processInfo.environment
        guard let raw = env["APSA_DISPATCH_URI"], raw.utf8.count <= 32768,
              let expected = env["APSA_DISPATCH_URI_SHA256"],
              let scheme = env["APSA_DISPATCH_SCHEME"],
              let url = URL(string: raw), url.scheme == scheme,
              url.host == "fixture", url.fragment == nil,
              SHA256.hash(data: Data(raw.utf8)).map({ String(format: "%02x", $0) }).joined() == expected
        else { XCTFail("NEW dispatch environment differs"); return }
        // Only the OS URL API delivers the challenge. Never launch/terminate the
        // independent transport app or manufacture its callback/HTTP response.
        XCUIDevice.shared.system.open(url)
    }
}
"""


def checked_uri(url: str, scheme: str) -> str:
    if (
        not isinstance(url, str)
        or re.fullmatch(r"a[a-f0-9]{32}", scheme) is None
        or not url.isascii()
        or len(url.encode()) > MAX_URI_BYTES
        or any(ord(char) < 33 or ord(char) == 127 for char in url)
    ):
        raise ValueError("NEW XCTest dispatch URI differs")
    parsed = urlsplit(url)
    if (
        parsed.scheme != scheme
        or parsed.netloc != "fixture"
        or parsed.path
        or not parsed.query
        or parsed.fragment
    ):
        raise ValueError("NEW XCTest dispatch URI differs")
    return url


def dispatch_manifest(raw: bytes, url: str, scheme: str) -> bytes:
    """Change only the known test host's environment; preserve Xcode paths."""
    checked_uri(url, scheme)
    if not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("NEW XCTest dispatch manifest differs")
    value = plistlib.loads(raw)
    if (
        not isinstance(value, dict)
        or set(value) - {"CallbackTests", "__xctestrun_metadata__"}
        or not isinstance(value.get("CallbackTests"), dict)
        or not isinstance(value.get("__xctestrun_metadata__", {}), dict)
        or value.get("__xctestrun_metadata__", {}).get("FormatVersion", 1) != 1
    ):
        raise ValueError("NEW XCTest dispatch manifest differs")
    target = value["CallbackTests"]
    environment = target.get("EnvironmentVariables", {})
    if (
        not isinstance(environment, dict)
        or any(not isinstance(k, str) or not isinstance(v, str) for k, v in environment.items())
        or ENV_KEYS.intersection(environment)
        or not isinstance(target.get("TestBundlePath"), str)
        or not isinstance(target.get("TestHostPath"), str)
    ):
        raise ValueError("NEW XCTest dispatch environment differs")
    result = copy.deepcopy(value)
    result["CallbackTests"]["EnvironmentVariables"] = {
        **environment,
        "APSA_DISPATCH_URI": url,
        "APSA_DISPATCH_URI_SHA256": digest(url.encode()),
        "APSA_DISPATCH_SCHEME": scheme,
    }
    return plistlib.dumps(result)


def write_project(root: Path, helper_package: str, helper_scheme: str) -> dict:
    """Generate only NEW helper sources; the helper is not the transport app."""
    control.write_project(
        root,
        helper_package,
        helper_scheme,
        ("0" * 64, "1" * 64),
        "fresh-install",
        "system-open",
    )
    (root / "CallbackTests.swift").write_text(TEST_SOURCE)
    return {
        str(path.relative_to(root)): digest(path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class IosXCTestDispatcher:
    """Run only on the exact CREATE-returned and journaled simulator UUID."""

    def __init__(self, root: Path, commands: Any, device: str, package: str, scheme: str):
        # ios_default_set checks the pinned disposable hosted namespace without
        # enumerating any device, account, app or user directory.
        control.transport.ios_default_set(commands.env)
        if (
            str(uuid.UUID(device)).upper() != device
            or re.fullmatch(r"apsa\.fixture\.c[a-f0-9]{32}\.case[0-5]", package) is None
            or re.fullmatch(r"a[a-f0-9]{32}", scheme) is None
            or commands.resources is None
            or commands.resources.value["ios"].get(device) != {"deleted": False, "selector": "default"}
            or root.is_symlink()
            or not root.resolve().is_relative_to(commands.root.resolve())
        ):
            raise ValueError("NEW XCTest dispatch ownership differs")
        self.root, self.commands, self.device = root, commands, device
        self.package, self.scheme = package, scheme
        self.observations: list[dict] = []
        self.latest: dict = {"state": "not-dispatched", "acquisition": "unsupported"}
        self.helper_package = "org.apsa.synthetic.p" + uuid.uuid4().hex
        self.generated = write_project(root, self.helper_package, "a" + uuid.uuid4().hex)
        self.derived = root / "derived"
        self.base = [
            "/usr/bin/xcodebuild",
            "-destination",
            "platform=iOS Simulator,id=" + device,
            "-parallel-testing-enabled",
            "NO",
            "-maximum-concurrent-test-simulator-destinations",
            "1",
            "-disableAutomaticPackageResolution",
            "-skipPackageUpdates",
        ]
        commands.run(
            self.base
            + [
                "-project",
                str(root / "Callback.xcodeproj"),
                "-scheme",
                "Callback",
                "-configuration",
                "Debug",
                "-sdk",
                "iphonesimulator",
                "-derivedDataPath",
                str(self.derived),
                "build-for-testing",
            ],
            timeout=600,
        )
        if commands.last_status != 0:
            raise ValueError("NEW XCTest build completion unverified")
        # This is only the newly generated products directory, never SDK/user
        # discovery. Keep copies beside the original to preserve __TESTROOT__.
        products = self.derived / "Build/Products"
        manifests = sorted(products.glob("*.xctestrun"))
        if len(manifests) != 1 or manifests[0].is_symlink():
            raise ValueError("NEW XCTest dispatch manifest differs")
        self.manifest = manifests[0]
        if self.manifest.stat().st_size > MAX_MANIFEST_BYTES:
            raise ValueError("NEW XCTest dispatch manifest differs")
        self.raw_manifest = self.manifest.read_bytes()
        self.build_observation = {
            "state": "built",
            "manifest_sha256": digest(self.raw_manifest),
            "generated_source_sha256": self.generated,
            "helper_package_sha256": digest(self.helper_package.encode()),
            "device_sha256": digest(device.encode()),
            "acquisition": "unsupported",
        }

    def dispatch(self, url: str) -> dict:
        checked_uri(url, self.scheme)
        if len(self.observations) >= MAX_DISPATCHES:
            raise ValueError("NEW XCTest dispatch limit exceeded")
        # Recheck the live ownership journal before every XCTest startup.
        if self.commands.resources.value["ios"].get(self.device) != {
            "deleted": False,
            "selector": "default",
        }:
            raise ValueError("NEW XCTest dispatch ownership differs")
        number = len(self.observations) + 1
        invocation = self.manifest.with_name(f"apsa-dispatch-{number}.xctestrun")
        encoded = dispatch_manifest(self.raw_manifest, url, self.scheme)
        with invocation.open("xb") as handle:
            handle.write(encoded)
        self.latest = {
            "state": "diagnostic-only",
            "phase": "os-open-requested",
            "uri_sha256": digest(url.encode()),
            "manifest_sha256": digest(encoded),
            "device_sha256": digest(self.device.encode()),
            "target_package_sha256": digest(self.package.encode()),
            "invocation": number,
            "xctest_exit_success": False,
            "acquisition": "unsupported",
        }
        self.observations.append(self.latest)
        self.commands.run(
            self.base
            + [
                "test-without-building",
                "-xctestrun",
                str(invocation),
                "-only-testing:CallbackTests/CallbackTests/testDispatchOwnedURL",
                "-resultBundlePath",
                str(self.root / f"dispatch-{number}.xcresult"),
            ],
            timeout=300,
        )
        if self.commands.last_status != 0:
            raise ValueError("NEW XCTest dispatch completion unverified")
        self.latest.update({"phase": "os-open-completed", "xctest_exit_success": True})
        (self.root / "dispatch-diagnostics.json").write_text(
            json.dumps({"build": self.build_observation, "dispatches": self.observations}, indent=2) + "\n"
        )
        return self.latest.copy()
