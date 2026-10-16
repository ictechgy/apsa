#!/usr/bin/env python3
"""A NEW hosted Xcode/XCUITest callback differential; never R02 acceptance.

Builds one synthetic scene app and one UI test, targeting only a CREATE-returned
UUID. No discovery, existing app data, screenshots, or raw service logs are read.
Apple API contract: https://developer.apple.com/documentation/xcuiautomation/xcuiapplication/open(_:)
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import uuid
from pathlib import Path
from xml.sax.saxutils import escape

from mobile_audit.core import digest
from scripts import validate_runtime_transport as transport

APP_SOURCE = r"""import UIKit
import CryptoKit

func sha(_ value: Data) -> String { SHA256.hash(data: value).map { String(format: "%02x", $0) }.joined() }

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    let epoch = UUID().uuidString
    var receipts: [[String: String]] = []
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]?) -> Bool { true }
    func application(_ application: UIApplication, configurationForConnecting session: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let config = UISceneConfiguration(name: "Default", sessionRole: session.role)
        config.delegateClass = SceneDelegate.self
        return config
    }
    func receive(_ url: URL, lifecycle: String, label: UILabel) {
        guard url.scheme == Bundle.main.object(forInfoDictionaryKey: "ProbeScheme") as? String,
              url.host == "callback", let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems,
              items.count == 1, items[0].name == "nonce", let nonce = items[0].value,
              nonce.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil,
              receipts.count < 2 else { return }
        do {
            let executable = Bundle.main.executableURL!
            let info = Bundle.main.bundleURL.appendingPathComponent("Info.plist")
            receipts.append(["uri_sha256": sha(Data(url.absoluteString.utf8)), "nonce_sha256": sha(Data(nonce.utf8)), "lifecycle": lifecycle])
            let value: [String: Any] = ["schema_version": 1, "package": Bundle.main.bundleIdentifier!,
                "epoch_sha256": sha(Data(epoch.utf8)), "executable_sha256": sha(try Data(contentsOf: executable)),
                "info_plist_sha256": sha(try Data(contentsOf: info)), "receipts": receipts]
            let bytes = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
            guard bytes.count <= 8192 else { return }
            let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            try FileManager.default.createDirectory(at: documents, withIntermediateDirectories: true)
            try bytes.write(to: documents.appendingPathComponent("callback.json"), options: [.atomic])
            label.text = lifecycle + ":" + nonce
        } catch { label.text = "receipt-unavailable" }
    }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    let label = UILabel()
    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { return }
        let controller = UIViewController()
        controller.view.backgroundColor = .white
        label.accessibilityIdentifier = "owned-callback"
        label.text = "ready"
        label.frame = CGRect(x: 10, y: 100, width: 360, height: 100)
        controller.view.addSubview(label)
        let window = UIWindow(windowScene: scene)
        window.rootViewController = controller
        self.window = window
        window.makeKeyAndVisible()
        for context in options.urlContexts { receive(context.url, lifecycle: "cold-url-context") }
    }
    func receive(_ url: URL, lifecycle: String) { (UIApplication.shared.delegate as? AppDelegate)?.receive(url, lifecycle: lifecycle, label: label) }
    func scene(_ scene: UIScene, openURLContexts contexts: Set<UIOpenURLContext>) {
        for context in contexts { receive(context.url, lifecycle: "warm-url-context") }
    }
}
"""

TEST_SOURCE = """import XCTest

final class CallbackTests: XCTestCase {
    @MainActor
    func testOwnedColdAndWarmCallbacks() {
        continueAfterFailure = false
        let app = XCUIApplication(bundleIdentifier: __PACKAGE__)
        if __PRELAUNCH__ {
            app.launch()
            XCTAssertTrue(app.wait(for: .runningForeground, timeout: 30))
            app.terminate()
        }
        XCTAssertTrue(app.wait(for: .notRunning, timeout: 15))
        app.open(URL(string: __COLD_URL__)!)
        let label = app.staticTexts["owned-callback"]
        let cold = NSPredicate(format: "label == %@", __COLD_LABEL__)
        expectation(for: cold, evaluatedWith: label)
        waitForExpectations(timeout: 30)
        app.open(URL(string: __WARM_URL__)!)
        let warm = NSPredicate(format: "label == %@", __WARM_LABEL__)
        expectation(for: warm, evaluatedWith: label)
        waitForExpectations(timeout: 30)
        app.terminate()
    }
}
"""


def checked_inputs(package: str, scheme: str, nonces: tuple[str, str]):
    if (
        re.fullmatch(r"org\.apsa\.synthetic\.p[a-f0-9]{32}", package) is None
        or re.fullmatch(r"a[a-f0-9]{32}", scheme) is None
        or len(nonces) != 2
        or any(re.fullmatch(r"[a-f0-9]{64}", nonce) is None for nonce in nonces)
        or len(set(nonces)) != 2
    ):
        raise ValueError("NEW callback input identity differs")


def ascii_plist(value) -> str:
    if isinstance(value, dict):
        return (
            "{\n" + "\n".join(json.dumps(k) + " = " + ascii_plist(v) + ";" for k, v in value.items()) + "\n}"
        )
    if isinstance(value, list):
        return "(" + ",".join(ascii_plist(v) for v in value) + ")"
    return json.dumps(str(value))


def write_project(
    root: Path,
    package: str,
    scheme: str,
    nonces: tuple[str, str],
    initial_state: str = "prelaunched",
    url_driver: str = "app-open",
) -> dict:
    """Pure source generation; does not look up or run any host tool."""
    checked_inputs(package, scheme, nonces)
    if initial_state not in {"prelaunched", "fresh-install"}:
        raise ValueError("NEW callback initial state differs")
    if url_driver not in {"app-open", "system-open"}:
        raise ValueError("NEW callback URL driver differs")
    root.mkdir(exist_ok=False)
    urls = tuple(f"{scheme}://callback?nonce={nonce}" for nonce in nonces)
    test = TEST_SOURCE.replace("__PRELAUNCH__", "true" if initial_state == "prelaunched" else "false")
    if url_driver == "system-open":
        # Public OS-default routing to this newly registered random scheme only.
        # https://developer.apple.com/documentation/xcuiautomation/xcuisystem
        test = test.replace("app.open(URL(string:", "XCUIDevice.shared.system.open(URL(string:")
    values = {
        "PACKAGE": package,
        "COLD_URL": urls[0],
        "WARM_URL": urls[1],
        "COLD_LABEL": "cold-url-context:" + nonces[0],
        "WARM_LABEL": "warm-url-context:" + nonces[1],
    }
    for key, value in values.items():
        test = test.replace("__" + key + "__", json.dumps(value))
    (root / "Callback.swift").write_text(APP_SOURCE)
    (root / "CallbackTests.swift").write_text(test)
    info = {
        "CFBundleExecutable": "Callback",
        "CFBundleIdentifier": package,
        "CFBundleName": "Callback",
        "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1",
        "CFBundleShortVersionString": "1.0",
        "MinimumOSVersion": "18.0",
        "LSRequiresIPhoneOS": True,
        "UIDeviceFamily": [1],
        "UILaunchScreen": {},
        "ProbeScheme": scheme,
        "CFBundleURLTypes": [{"CFBundleTypeRole": "Editor", "CFBundleURLSchemes": [scheme]}],
        "UIApplicationSceneManifest": {
            "UIApplicationSupportsMultipleScenes": False,
            "UISceneConfigurations": {
                "UIWindowSceneSessionRoleApplication": [
                    {
                        "UISceneConfigurationName": "Default",
                        "UISceneDelegateClassName": "Callback.SceneDelegate",
                    }
                ]
            },
        },
    }
    (root / "Info.plist").write_bytes(plistlib.dumps(info))
    objects: dict[str, dict] = {}

    def add(key: str, isa: str, **fields):
        objects[key] = {"isa": isa, **fields}
        return key

    ids = {
        name: f"{n:024X}"
        for n, name in enumerate(
            (
                "project",
                "group",
                "products",
                "app",
                "tests",
                "appfile",
                "testfile",
                "appsrc",
                "testsrc",
                "appbuild",
                "testbuild",
                "appref",
                "testref",
                "projectcfg",
                "appcfg",
                "testcfg",
                "projectlist",
                "applist",
                "testlist",
                "proxy",
                "dependency",
            ),
            1,
        )
    }
    add(
        ids["appfile"],
        "PBXFileReference",
        lastKnownFileType="sourcecode.swift",
        path="Callback.swift",
        sourceTree="<group>",
    )
    add(
        ids["testfile"],
        "PBXFileReference",
        lastKnownFileType="sourcecode.swift",
        path="CallbackTests.swift",
        sourceTree="<group>",
    )
    add(
        ids["appref"],
        "PBXFileReference",
        explicitFileType="wrapper.application",
        path="Callback.app",
        sourceTree="BUILT_PRODUCTS_DIR",
    )
    add(
        ids["testref"],
        "PBXFileReference",
        explicitFileType="wrapper.cfbundle",
        path="CallbackTests.xctest",
        sourceTree="BUILT_PRODUCTS_DIR",
    )
    for kind in ("app", "test"):
        add(ids[kind + "build"], "PBXBuildFile", fileRef=ids[kind + "file"])
        add(
            ids[kind + "src"],
            "PBXSourcesBuildPhase",
            buildActionMask=2147483647,
            files=[ids[kind + "build"]],
            runOnlyForDeploymentPostprocessing=0,
        )
    add(
        ids["products"],
        "PBXGroup",
        children=[ids["appref"], ids["testref"]],
        name="Products",
        sourceTree="<group>",
    )
    add(
        ids["group"],
        "PBXGroup",
        children=[ids["appfile"], ids["testfile"], ids["products"]],
        sourceTree="<group>",
    )
    common = {
        "SDKROOT": "iphonesimulator",
        "SUPPORTED_PLATFORMS": "iphonesimulator",
        "IPHONEOS_DEPLOYMENT_TARGET": "18.0",
        "SWIFT_VERSION": "5.0",
        "CLANG_ENABLE_MODULES": "YES",
        "CODE_SIGN_IDENTITY": "-",
        "CODE_SIGNING_ALLOWED": "YES",
        "SWIFT_OPTIMIZATION_LEVEL": "-Onone",
        "ENABLE_TESTABILITY": "YES",
        "TARGETED_DEVICE_FAMILY": "1",
    }
    add(ids["projectcfg"], "XCBuildConfiguration", name="Debug", buildSettings=common)
    add(
        ids["appcfg"],
        "XCBuildConfiguration",
        name="Debug",
        buildSettings={
            "PRODUCT_NAME": "Callback",
            "PRODUCT_BUNDLE_IDENTIFIER": package,
            "INFOPLIST_FILE": "Info.plist",
            "GENERATE_INFOPLIST_FILE": "NO",
        },
    )
    add(
        ids["testcfg"],
        "XCBuildConfiguration",
        name="Debug",
        buildSettings={
            "PRODUCT_NAME": "CallbackTests",
            "PRODUCT_BUNDLE_IDENTIFIER": package + ".uitests",
            "GENERATE_INFOPLIST_FILE": "YES",
            "TEST_TARGET_NAME": "Callback",
            "LD_RUNPATH_SEARCH_PATHS": [
                "$(inherited)",
                "@executable_path/Frameworks",
                "@loader_path/Frameworks",
            ],
        },
    )
    for kind in ("project", "app", "test"):
        add(
            ids[kind + "list"],
            "XCConfigurationList",
            buildConfigurations=[ids[kind + "cfg"]],
            defaultConfigurationIsVisible=0,
            defaultConfigurationName="Debug",
        )
    add(
        ids["proxy"],
        "PBXContainerItemProxy",
        containerPortal=ids["project"],
        proxyType=1,
        remoteGlobalIDString=ids["app"],
        remoteInfo="Callback",
    )
    add(ids["dependency"], "PBXTargetDependency", target=ids["app"], targetProxy=ids["proxy"])
    add(
        ids["app"],
        "PBXNativeTarget",
        name="Callback",
        productName="Callback",
        productType="com.apple.product-type.application",
        productReference=ids["appref"],
        buildConfigurationList=ids["applist"],
        buildPhases=[ids["appsrc"]],
        buildRules=[],
        dependencies=[],
    )
    add(
        ids["tests"],
        "PBXNativeTarget",
        name="CallbackTests",
        productName="CallbackTests",
        productType="com.apple.product-type.bundle.ui-testing",
        productReference=ids["testref"],
        buildConfigurationList=ids["testlist"],
        buildPhases=[ids["testsrc"]],
        buildRules=[],
        dependencies=[ids["dependency"]],
    )
    add(
        ids["project"],
        "PBXProject",
        attributes={
            "LastUpgradeCheck": "1640",
            "TargetAttributes": {ids["tests"]: {"TestTargetID": ids["app"]}},
        },
        buildConfigurationList=ids["projectlist"],
        compatibilityVersion="Xcode 14.0",
        developmentRegion="en",
        knownRegions=["en"],
        mainGroup=ids["group"],
        productRefGroup=ids["products"],
        projectDirPath="",
        projectRoot="",
        targets=[ids["app"], ids["tests"]],
    )
    project = root / "Callback.xcodeproj"
    schemes = project / "xcshareddata/xcschemes"
    schemes.mkdir(parents=True)
    (project / "project.pbxproj").write_text(
        "// !$*UTF8*$!\n"
        + ascii_plist(
            {
                "archiveVersion": 1,
                "classes": {},
                "objectVersion": 56,
                "objects": objects,
                "rootObject": ids["project"],
            }
        )
        + "\n"
    )

    def reference(key: str, name: str, product: str):
        return f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{ids[key]}" BuildableName="{escape(product)}" BlueprintName="{escape(name)}" ReferencedContainer="container:Callback.xcodeproj"/>'

    appref = reference("app", "Callback", "Callback.app")
    testref = reference("tests", "CallbackTests", "CallbackTests.xctest")
    (schemes / "Callback.xcscheme").write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="1640" version="1.3"><BuildAction parallelizeBuildables="NO" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="NO" buildForArchiving="NO" buildForAnalyzing="YES">{appref}</BuildActionEntry><BuildActionEntry buildForTesting="YES" buildForRunning="NO" buildForProfiling="NO" buildForArchiving="NO" buildForAnalyzing="YES">{testref}</BuildActionEntry></BuildActionEntries></BuildAction><TestAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" shouldUseLaunchSchemeArgsEnv="YES"><Testables><TestableReference skipped="NO" parallelizable="NO">{testref}</TestableReference></Testables></TestAction><LaunchAction buildConfiguration="Debug"><BuildableProductRunnable runnableDebuggingMode="0">{appref}</BuildableProductRunnable></LaunchAction></Scheme>
""")
    return {
        "urls": urls,
        "generated_source_sha256": {
            str(p.relative_to(root)): digest(p.read_bytes()) for p in sorted(root.rglob("*")) if p.is_file()
        },
    }


def verify_receipt(
    raw: bytes, package: str, urls: tuple[str, str], nonces: tuple[str, str], build: dict
) -> dict:
    if len(raw) > 8192:
        raise ValueError("NEW callback receipt over bound")
    value = json.loads(raw, object_pairs_hook=transport.unique_journal_keys)
    expected = [
        {"uri_sha256": digest(url.encode()), "nonce_sha256": digest(nonce.encode()), "lifecycle": lifecycle}
        for url, nonce, lifecycle in zip(urls, nonces, ("cold-url-context", "warm-url-context"), strict=True)
    ]
    if (
        not isinstance(value, dict)
        or set(value)
        != {"schema_version", "package", "epoch_sha256", "executable_sha256", "info_plist_sha256", "receipts"}
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["package"] != package
        or re.fullmatch(r"[a-f0-9]{64}", value.get("epoch_sha256", "")) is None
        or value["receipts"] != expected
        or any(value.get(k) != v for k, v in build.items())
    ):
        raise ValueError("NEW callback receipt binding differs")
    return {
        "state": "verified",
        "receipt_sha256": digest(raw),
        "epoch_sha256": value["epoch_sha256"],
        "receipts": expected,
        "build": build,
    }


def xcode_diagnostic(raw: bytes, action: str, status: int | None) -> dict:
    """Only fixed labels and own test line numbers leave NEW Xcode output."""
    if action not in {"build-for-testing", "test-without-building"}:
        raise ValueError("NEW Xcode action differs")
    text = raw[: transport.MAX_OUTPUT].decode(errors="replace")
    test_lines = TEST_SOURCE.splitlines()
    waits = [i for i, line in enumerate(test_lines, 1) if "waitForExpectations(" in line]
    issues = []
    for line in text.splitlines():
        match = re.search(r"CallbackTests\.swift:(\d+)(?::\d+)?:\s+error:", line)
        if match is None:
            continue
        number = int(match[1])
        if not 1 <= number <= len(test_lines):
            continue
        category = (
            "expectation-timeout"
            if "Asynchronous wait failed" in line or "unfulfilled expectations" in line
            else "assertion-failed"
            if "XCTAssert" in line
            else "own-test-error"
        )
        issues.append(
            {
                "source_line": number,
                "category": category,
                "probe": "cold" if number == waits[0] else "warm" if number == waits[1] else "setup-or-other",
            }
        )
        if len(issues) == 16:
            break
    phrases = {
        "runner-never-started": "never began executing tests",
        "early-runner-exit": "Early unexpected exit",
        "app-launch-failed": "Failed to launch",
        "destination-unavailable": "Unable to find a destination",
        "test-failed": "** TEST EXECUTE FAILED **",
    }
    return {
        "state": "diagnostic-only",
        "action": action,
        "exit_status": status,
        "stdout_sha256": digest(raw),
        "stdout_bytes": len(raw),
        "own_test_issues": issues,
        "categories": [key for key, phrase in phrases.items() if phrase in text],
    }


def callback_diagnostic(
    raw: bytes, package: str, urls: tuple[str, str], nonces: tuple[str, str], build: dict
) -> dict:
    """Partial receipts identify observed facts only; never satisfy the test gate."""
    result = {"state": "diagnostic-only", "receipt_sha256": digest(raw), "receipt_bytes": len(raw)}
    if not raw or len(raw) > 8192:
        return {**result, "receipt_state": "absent-or-over-bound"}
    try:
        value = json.loads(raw, object_pairs_hook=transport.unique_journal_keys)
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version",
                "package",
                "epoch_sha256",
                "executable_sha256",
                "info_plist_sha256",
                "receipts",
            }
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or not isinstance(value["receipts"], list)
            or len(value["receipts"]) > 2
        ):
            raise ValueError("receipt shape")
        receipts = []
        for receipt in value["receipts"]:
            if (
                not isinstance(receipt, dict)
                or set(receipt) != {"lifecycle", "uri_sha256", "nonce_sha256"}
                or receipt["lifecycle"] not in {"cold-url-context", "warm-url-context"}
                or any(
                    not isinstance(receipt[key], str) or re.fullmatch(r"[a-f0-9]{64}", receipt[key]) is None
                    for key in ["uri_sha256", "nonce_sha256"]
                )
            ):
                raise ValueError("receipt shape")
            matches = [
                name
                for name, url, nonce in zip(("cold", "warm"), urls, nonces, strict=True)
                if receipt["uri_sha256"] == digest(url.encode())
                and receipt["nonce_sha256"] == digest(nonce.encode())
            ]
            receipts.append(
                {
                    "lifecycle": receipt["lifecycle"],
                    "expected_probe": matches[0] if len(matches) == 1 else "unbound",
                }
            )
        return {
            **result,
            "receipt_state": "parsed",
            "package_matches": value["package"] == package,
            "build_matches": all(value.get(key) == expected for key, expected in build.items()),
            "receipts": receipts,
        }
    except (ValueError, TypeError):
        return {**result, "receipt_state": "malformed"}


def observe_owned_callback(
    commands, device: str, package: str, urls: tuple[str, str], nonces: tuple[str, str], build: dict
) -> dict:
    """Read one known NEW target file; no discovery or other app access."""
    raw = commands.run(["/usr/bin/xcrun", "simctl", "get_app_container", device, package, "data"], timeout=30)
    container = Path(raw.decode().strip()).resolve()
    if not container.is_relative_to(transport.ios_default_set(commands.env) / device):
        raise ValueError("NEW callback diagnostic container differs")
    path = container / "Documents/callback.json"
    if (
        path.is_symlink()
        or path.resolve().parent != (container / "Documents").resolve()
        or not path.resolve().is_relative_to(container)
    ):
        raise ValueError("NEW callback diagnostic path differs")
    if path.is_file() and path.stat().st_size <= 8192:
        return callback_diagnostic(path.read_bytes(), package, urls, nonces, build)
    return callback_diagnostic(b"", package, urls, nonces, build)


def installed_owned_build(commands, device: str, package: str, expected: dict) -> dict:
    """Bind the NEW installed target before either public URL driver runs."""
    if re.fullmatch(r"org\.apsa\.synthetic\.p[a-f0-9]{32}", package) is None:
        raise ValueError("NEW installed callback package differs")
    raw = commands.run(["/usr/bin/xcrun", "simctl", "get_app_container", device, package, "app"])
    container = Path(raw.decode().strip()).resolve()
    if not container.is_relative_to(transport.ios_default_set(commands.env) / device):
        raise ValueError("NEW installed callback container differs")
    actual = {
        "executable_sha256": digest((container / "Callback").read_bytes()),
        "info_plist_sha256": digest((container / "Info.plist").read_bytes()),
    }
    if actual != expected:
        raise ValueError("NEW installed callback build differs")
    return {"state": "verified", "build": actual}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--initial-state", choices=("prelaunched", "fresh-install"), default="prelaunched")
    parser.add_argument("--url-driver", choices=("app-open", "system-open"), default="app-open")
    args = parser.parse_args()
    root = args.work.resolve()
    env = dict(os.environ)
    transport.ios_default_set(env)  # Pinned disposable hosted macOS only; no SDK lookup locally.
    temporary = Path(env["RUNNER_TEMP"]).resolve()
    if root == temporary or not root.is_relative_to(temporary) or args.work.is_symlink():
        raise ValueError("NEW callback work root differs")
    root.mkdir(exist_ok=False)
    commands = transport.Commands(root, env=env)
    resources = transport.OwnedResources(root)
    commands.resources = resources
    evidence: dict = {
        "schema_version": 1,
        "measurement": "xcode-xctest-callback-differential",
        "acquisition": "unsupported",
        "r02_acceptance": False,
        "initial_state": args.initial_state,
        "url_driver": args.url_driver,
        "state": "inconclusive",
        "terminal": False,
        "commit": env.get("GITHUB_SHA"),
        "source_sha256": digest(Path(__file__).read_bytes()),
    }
    device = package = None
    generated = build = None
    nonces: tuple[str, str] | None = None
    try:
        package = "org.apsa.synthetic.p" + uuid.uuid4().hex
        scheme = "a" + uuid.uuid4().hex
        nonces = (uuid.uuid4().hex + uuid.uuid4().hex, uuid.uuid4().hex + uuid.uuid4().hex)
        project_root = root / "generated"
        generated = write_project(project_root, package, scheme, nonces, args.initial_state, args.url_driver)
        evidence["generated_source_sha256"] = generated["generated_source_sha256"]
        simctl = ["/usr/bin/xcrun", "simctl"]
        device = str(
            uuid.UUID(
                commands.run(
                    simctl
                    + [
                        "create",
                        "APSA-NEW-XCTEST-" + uuid.uuid4().hex,
                        transport.IOS_PINNED_DEVICE_TYPE,
                        transport.IOS_PINNED_RUNTIME,
                    ]
                )
                .decode()
                .strip()
            )
        ).upper()
        resources.ios(device, selector="default")
        evidence["device_sha256"] = digest(device.encode())
        commands.run(simctl + ["boot", device])
        commands.run(simctl + ["bootstatus", device, "-b"], timeout=600)
        derived = root / "derived"
        xcode = [
            "/usr/bin/xcodebuild",
            "-project",
            str(project_root / "Callback.xcodeproj"),
            "-scheme",
            "Callback",
            "-configuration",
            "Debug",
            "-sdk",
            "iphonesimulator",
            "-destination",
            "platform=iOS Simulator,id=" + device,
            "-derivedDataPath",
            str(derived),
            "-parallel-testing-enabled",
            "NO",
            "-maximum-concurrent-test-simulator-destinations",
            "1",
            "-disableAutomaticPackageResolution",
            "-skipPackageUpdates",
        ]
        output = commands.run(xcode + ["build-for-testing"], timeout=600, optional=True)
        evidence["xcode_build"] = xcode_diagnostic(output, "build-for-testing", commands.last_status)
        if commands.last_status != 0:
            raise ValueError("NEW Xcode build failed")
        built = derived / "Build/Products/Debug-iphonesimulator/Callback.app"
        build = {
            "executable_sha256": digest((built / "Callback").read_bytes()),
            "info_plist_sha256": digest((built / "Info.plist").read_bytes()),
        }
        commands.run(simctl + ["install", device, str(built)])
        evidence["installed_before_test"] = installed_owned_build(commands, device, package, build)
        output = commands.run(
            xcode
            + [
                "test-without-building",
                "-only-testing:CallbackTests/CallbackTests/testOwnedColdAndWarmCallbacks",
                "-resultBundlePath",
                str(root / "test-result.xcresult"),
            ],
            timeout=600,
            optional=True,
        )
        evidence["xcode_test"] = xcode_diagnostic(output, "test-without-building", commands.last_status)
        if commands.last_status != 0:
            raise ValueError("NEW Xcode callback test failed")
        evidence["xctest_exit_success"] = True
        default_set = transport.ios_default_set(env)
        containers = {}
        for kind in ("app", "data"):
            container = Path(
                commands.run(simctl + ["get_app_container", device, package, kind]).decode().strip()
            ).resolve()
            if not container.is_relative_to(default_set / device):
                raise ValueError("NEW callback container identity differs")
            containers[kind] = container
        installed = {
            "executable_sha256": digest((containers["app"] / "Callback").read_bytes()),
            "info_plist_sha256": digest((containers["app"] / "Info.plist").read_bytes()),
        }
        if installed != build:
            raise ValueError("NEW callback installed build differs")
        receipt = containers["data"] / "Documents/callback.json"
        if receipt.is_symlink() or receipt.stat().st_size > 8192:
            raise ValueError("NEW callback receipt shape differs")
        evidence["callback"] = verify_receipt(receipt.read_bytes(), package, generated["urls"], nonces, build)
        evidence["state"] = "verified-callback-control"
    except Exception as error:
        # New fixture command output is retained only as bounded digest metadata.
        evidence["failure"] = {
            "exception_type": type(error).__name__,
            "stage": "new-xctest-callback-control",
            "recent_commands": commands.records[-4:],
        }
    finally:
        if (
            device is not None
            and package is not None
            and generated is not None
            and nonces is not None
            and build is not None
        ):
            try:
                evidence["callback_diagnostic"] = observe_owned_callback(
                    commands, device, package, generated["urls"], nonces, build
                )
            except Exception as error:
                evidence["callback_diagnostic"] = {
                    "state": "unmeasured",
                    "exception_type": type(error).__name__,
                }
        try:
            evidence["cleanup"] = transport.cleanup_owned(root, commands, resources)
        except Exception as error:
            evidence["cleanup"] = {"state": "unconfirmed", "exception_type": type(error).__name__}
        evidence["terminal"] = True
        if evidence["cleanup"].get("state") != "confirmed":
            evidence["state"] = "inconclusive"
        (root / "xctest-control.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        print("APSA_XCTEST_CONTROL=" + json.dumps(evidence, sort_keys=True), flush=True)
    if evidence["state"] != "verified-callback-control":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
