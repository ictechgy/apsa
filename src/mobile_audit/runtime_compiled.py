"""Fresh compiled fixture acquisition over bounded IPC, never device discovery.

The host JVM is an executable synthetic app model. Mobile build artifacts can be
compiled alongside it, but this adapter never claims installation or HTTP proof.
Only the recorder persists observation digests; protocol bodies stay in memory.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import plistlib
import select
import subprocess
import time
import uuid
import zipfile
from pathlib import Path
from urllib.parse import urlencode

from .core import digest
from .runtime_acquisition import (
    AcquiredCapture,
    AcquisitionSession,
    BackendProbe,
    CaptureRequest,
    RawObservation,
    SurfaceCapture,
)

JDK = Path("/Users/coden/.local/jdks/jdk-17.0.20+8/Contents/Home/bin")
MAX_LINE = 1024 * 1024

# No marker, credential or operator-selected path is embedded in this source.
SOURCE = r"""import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
public final class CompiledAuthFixture {
  static String enc(String s) { return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8)); }
  static String dec(String s) { return new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8); }
  static String hash(byte[] s) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(s)); }
  static String[] fields(String line) { return Arrays.stream(line.split("\t", -1)).map(CompiledAuthFixture::dec).toArray(String[]::new); }
  static void emit(String... fields) { System.out.println(String.join("\t", Arrays.stream(fields).map(CompiledAuthFixture::enc).toArray(String[]::new))); }
  static final class Authority {
    final Map<String,String> tokens = new HashMap<>();
    String issue(String account) { String token = UUID.randomUUID().toString(); tokens.put(token, account); return token; }
    void revoke(String token, boolean invalidate) { if (invalidate) tokens.remove(token); }
    String replay(String token) { return tokens.containsKey(token) ? "accepted" : "rejected"; }
  }
  public static void main(String[] args) throws Exception {
    Path root = Path.of(args[0]);
    Files.createDirectory(root);
    Path storage = root.resolve("state.dat");
    String build = hash(Files.readAllBytes(Path.of(args[1])));
    String model = hash(Files.readAllBytes(Path.of(args[2])));
    BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    String[] init = fields(input.readLine());
    if (!init[0].equals("init") || init.length != 13) throw new IllegalArgumentException("init shape");
    String platform = init[1], packageName = init[2], kind = init[3], account = init[4], target = init[5];
    String baseline = init[6], after = init[7], canary = init[8], original = account;
    boolean invalidate = init[9].equals("true"), retain = init[10].equals("true");
    Authority authority = new Authority();
    String credential = account.isEmpty() ? "" : authority.issue(account);
    String authorityId = UUID.randomUUID().toString(), session = "";
    boolean transitioned = false;
    Files.writeString(storage, baseline);
    emit("ready", platform, packageName, build, model, "fresh-store");
    for (String line; (line = input.readLine()) != null;) {
      String[] f = fields(line);
      if (f[0].equals("session")) {
        if (f.length != 5 || !f[2].equals(platform) || !f[3].equals(packageName) || !f[4].equals(build) || !session.isEmpty()) throw new IllegalArgumentException("session binding");
        session = f[1]; emit("session", session, platform, packageName, build, model);
      } else if (f[0].equals("transition")) {
        if (f.length != 4 || !f[1].equals(session) || !f[2].equals(kind) || !f[3].equals("synthetic://transition") || transitioned) throw new IllegalArgumentException("delivery binding");
        authority.revoke(credential, invalidate); account = target; transitioned = true;
        if (!account.isEmpty()) authority.issue(account);
        Files.writeString(storage, after + (retain ? " " + canary : ""));
        emit("delivered", session, kind, account, "target-observed");
      } else if (f[0].equals("capture")) {
        if (f.length != 8 || !f[1].equals(session) || !f[4].equals(account) || !f[5].equals(account.isEmpty() ? "logged_out" : "authenticated") || !f[6].equals(transitioned ? kind : "")) throw new IllegalArgumentException("capture binding");
        String replay = credential.isEmpty() ? "not_checked" : authority.replay(credential);
        emit("capture", session, f[2], f[3], account, f[5], f[6], build, model,
          transitioned ? "target-observed" : "baseline", Files.readString(storage),
          transitioned ? after : baseline, authorityId, credential, replay,
          "IPC replay credential=" + credential, "IPC outcome=" + replay + (replay.equals("accepted") ? " " + canary : ""), original);
      } else if (f[0].equals("close")) { emit("closed"); return; }
      else throw new IllegalArgumentException("unsupported command");
    }
  }
}
"""


def compile_model(root: Path, *, jdk: Path = JDK) -> dict:
    """Create a new owned directory, compile generic source and record commands."""
    root.mkdir(parents=True, exist_ok=False)
    source = root / "CompiledAuthFixture.java"
    source.write_text(SOURCE)
    commands = []
    for argv in (
        [str(jdk / "javac"), "-version"],
        [str(jdk / "java"), "-version"],
        [str(jdk / "javac"), "-d", str(root), str(source)],
    ):
        result = subprocess.run(argv, capture_output=True, timeout=90, check=False)
        commands.append(
            {
                "argv": argv,
                "status": result.returncode,
                "stdout": result.stdout.decode(errors="replace"),
                "stderr": result.stderr.decode(errors="replace"),
            }
        )
        (root / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if result.returncode:
            raise ValueError("Fresh compiled fixture build failed")
    binary = root / "compiled-fixture.jar"
    classes = ("CompiledAuthFixture.class", "CompiledAuthFixture$Authority.class")
    with zipfile.ZipFile(binary, "w") as archive:
        for name in classes:
            archive.writestr(zipfile.ZipInfo(name), (root / name).read_bytes())
    return {
        "mode": "synthetic",
        "compile_target": "JVM-17-host-process",
        "compiled": True,
        "installed": False,
        "source_sha256": digest(source.read_bytes()),
        "model_sha256": digest(binary.read_bytes()),
        "classes": [{"name": name, "sha256": digest((root / name).read_bytes())} for name in classes],
        "commands": commands,
    }


class CompiledSyntheticAdapter:
    """Constructor-only compiled process adapter; JSON cannot select commands."""

    def __init__(
        self,
        scenario: dict,
        root: Path,
        *,
        jdk: Path = JDK,
        invalidate_backend: bool = True,
        local_residual: bool = False,
    ):
        self.scenario = copy.deepcopy(scenario)
        transitions = self.scenario["workflow"]["transitions"]
        if len(transitions) != 1:
            raise ValueError("Compiled fixture requires one transition per fresh store")
        self.transition = transitions[0]
        self.root = root
        self.manifest = compile_model(root, jdk=jdk)
        self.build_hash = self.manifest["model_sha256"]
        self.build_key = "runtime_model_sha256"
        # Contract build identity is the compiled host model. Explicit metadata
        # distinguishes this from an APK, installed app or simulator executable.
        self.manifest["binding_scope"] = "compiled-host-model-sha256"
        self.manifest["network_scope"] = "IPC-authority-model; HTTP-unmeasured"
        self.manifest["fixture_policy"] = {
            "invalidate_backend": invalidate_backend,
            "local_residual": local_residual,
        }
        self.session: AcquisitionSession | None = None
        self.after = False
        self.argv = [
            str(jdk / "java"),
            "-cp",
            str(root / "compiled-fixture.jar"),
            "CompiledAuthFixture",
            str(root / "store"),
            str(root / "compiled-fixture.jar"),
            str(root / "compiled-fixture.jar"),
        ]
        self.process = subprocess.Popen(
            self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.stdout_hash = hashlib.sha256()
        self.stdout_bytes = 0
        self.stdin_hash = hashlib.sha256()
        self.stdin_bytes = 0
        t = self.transition
        labels_before = self._labels(t["from_account"], False)
        labels_after = self._labels(t["to_account"], True)
        canary = ""
        if t["from_account"]:
            canary = self.scenario["markers"][
                self.scenario["workflow"]["accounts"][t["from_account"]]["canary"]
            ]
        try:
            ready = self._exchange(
                [
                    "init",
                    scenario["platform"],
                    scenario["package"],
                    t["kind"],
                    t["from_account"] or "",
                    t["to_account"] or "",
                    labels_before,
                    labels_after,
                    canary,
                    str(invalidate_backend).lower(),
                    str(local_residual).lower(),
                    "fresh",
                    "bounded",
                ]
            )
        except (ValueError, OSError):
            self.close()
            raise
        if ready != [
            "ready",
            scenario["platform"],
            scenario["package"],
            self.build_hash,
            self.build_hash,
            "fresh-store",
        ]:
            self.close()
            raise ValueError("Compiled fixture startup identity differs")

    def _labels(self, account: str | None, after: bool) -> str:
        t, markers = self.transition, self.scenario["markers"]
        labels = []
        if account:
            a = self.scenario["workflow"]["accounts"][account]
            labels += [a["canary"], a["login_marker"]]
        elif not after:
            labels.append(t["baseline_marker"])
        if after:
            labels += [t["state_marker"], t["delivery_marker"]]
        return " ".join(markers[label] for label in labels)

    def _exchange(self, fields: list[str]) -> list[str]:
        if self.process.stdin is None or self.process.stdout is None:
            raise ValueError("Compiled fixture transport unavailable")
        line = b"\t".join(base64.b64encode(field.encode()) for field in fields) + b"\n"
        if len(line) > MAX_LINE:
            raise ValueError("Compiled fixture IPC request exceeds bound")
        self.process.stdin.write(line)
        self.process.stdin.flush()
        self.stdin_hash.update(line)
        self.stdin_bytes += len(line)
        if not select.select([self.process.stdout], [], [], 10)[0]:
            raise ValueError("Compiled fixture IPC timed out")
        raw = self.process.stdout.readline(MAX_LINE + 1)
        self.stdout_hash.update(raw)
        self.stdout_bytes += len(raw)
        if not raw.endswith(b"\n") or len(raw) > MAX_LINE:
            raise ValueError("Compiled fixture IPC response exceeds bound")
        try:
            return [
                base64.b64decode(value, validate=True).decode() for value in raw.rstrip(b"\n").split(b"\t")
            ]
        except (ValueError, UnicodeError) as error:
            raise ValueError("Compiled fixture IPC response invalid") from error

    def environment(self) -> dict:
        actual = digest((self.root / "compiled-fixture.jar").read_bytes())
        return {
            "platform": self.scenario["platform"],
            "synthetic": True,
            "app": {"package": self.scenario["package"], self.build_key: actual},
        }

    def start_session(self, binding: dict, nonce: str) -> AcquisitionSession:
        expected = {self.build_key: self.build_hash}
        if (
            binding["platform"] != self.scenario["platform"]
            or binding["package"] != self.scenario["package"]
            or binding["build"] != expected
        ):
            raise ValueError("Compiled fixture session build differs")
        observed = self._exchange(
            ["session", nonce, binding["platform"], binding["package"], self.build_hash]
        )
        if observed != [
            "session",
            nonce,
            binding["platform"],
            binding["package"],
            self.build_hash,
            self.build_hash,
        ]:
            raise ValueError("Compiled fixture session response differs")
        self.session = AcquisitionSession(
            "compiled-jvm-fixture", "synthetic", nonce, binding["platform"], binding["package"], expected
        )
        return self.session

    def open_url(self, url: str) -> dict:
        if not self.session or url != "synthetic://transition" or self.after:
            raise ValueError("Compiled fixture transition unsupported")
        t = self.transition
        observed = self._exchange(["transition", self.session.nonce, t["kind"], url])
        if observed != ["delivered", self.session.nonce, t["kind"], t["to_account"] or "", "target-observed"]:
            raise ValueError("Compiled fixture target delivery differs")
        self.after = True
        return {"delivery": "target-activity-reported"}

    def capture(self, request: CaptureRequest) -> AcquiredCapture:
        if request.session != self.session:
            raise ValueError("Compiled fixture capture session differs")
        response = self._exchange(
            [
                "capture",
                request.session.nonce,
                request.nonce,
                request.snapshot,
                request.account or "",
                request.state,
                request.transition or "",
                "bounded",
            ]
        )
        expected = [
            "capture",
            request.session.nonce,
            request.nonce,
            request.snapshot,
            request.account or "",
            request.state,
            request.transition or "",
            self.build_hash,
            self.build_hash,
        ]
        if (
            len(response) != 18
            or response[:9] != expected
            or response[9] not in {"baseline", "target-observed"}
        ):
            raise ValueError("Compiled fixture capture challenge differs")
        probe = None
        if response[13]:
            outcome = {"accepted": "accepted", "rejected": "rejected", "not_checked": "not_checked"}.get(
                response[14]
            )
            if outcome is None:
                raise ValueError("Compiled fixture replay outcome invalid")
            probe = BackendProbe(
                digest(response[12].encode()),
                digest(response[13].encode()),
                "accepted"
                if outcome == "accepted"
                else "rejected"
                if outcome == "rejected"
                else "not_checked",
                response[15].encode(),
                response[16].encode(),
            )
        return AcquiredCapture(
            request,
            response[4] or None,
            response[5],
            "target-observed" if response[9] == "target-observed" else "baseline",
            (
                SurfaceCapture(
                    "storage", "complete", (RawObservation("fresh-store", response[10].encode()),)
                ),
                SurfaceCapture("ui", "unsupported", ()),
                SurfaceCapture("logs", "unsupported", ()),
                SurfaceCapture(
                    "network", "partial", (RawObservation("ipc-authority-response", response[16].encode()),)
                ),
            ),
            probe,
        )

    def close(self) -> dict:
        """Reap this owned process and expose only hashed IPC diagnostics."""
        if self.process.poll() is None:
            try:
                self._exchange(["close"])
                self.process.wait(timeout=5)
            except (ValueError, OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=5)
        stderr = self.process.stderr.read(MAX_LINE) if self.process.stderr else b""
        return {
            "argv": self.argv,
            "status": self.process.returncode,
            "stdout": "IPC observations withheld; recorder stores digests only",
            "stdout_sha256": self.stdout_hash.hexdigest(),
            "stdout_bytes": self.stdout_bytes,
            "stdin_sha256": self.stdin_hash.hexdigest(),
            "stdin_bytes": self.stdin_bytes,
            "stderr_sha256": digest(stderr),
            "stderr_bytes": len(stderr),
        }

    def write_manifest(self, destination: Path) -> None:
        destination.write_text(json.dumps(self.manifest, indent=2) + "\n")


class FreshIosSimulatorAdapter:
    """Compile and install an owned fixture on a newly created explicit simulator.

    This measures only simulator fixture storage and URL delivery, never physical
    devices, UI, logs or HTTP. Construction creates a dedicated simulator; it
    never enumerates or selects a booted/default/user device.
    """

    def __init__(self, scenario: dict, root: Path, *, local_residual: bool = False):
        if (
            scenario["platform"] != "ios"
            or scenario["package"] != "com.synthetic.app"
            or len(scenario["workflow"]["transitions"]) != 1
        ):
            raise ValueError("Fresh iOS fixture needs one iOS transition")
        self.scenario = copy.deepcopy(scenario)
        self.transition = self.scenario["workflow"]["transitions"][0]
        if scenario["markers"] != {
            label: "synthetic-unique-" + label
            for label in ("a", "b", "login_a", "login_b", "state", "delivery", "baseline")
        }:
            raise ValueError("Fresh simulator accepts only owned fixture markers")
        root.mkdir(parents=True, exist_ok=False)
        self.root = root
        self.commands: list[dict] = []
        self.device: str | None = None
        self.package = scenario["package"]
        self.local_residual = local_residual
        self.session: AcquisitionSession | None = None
        self.after = False
        source = Path(__file__).parents[2] / "tests/fixtures/runtime/ios/Instrumented.swift"
        copied = root / "Instrumented.swift"
        copied.write_bytes(source.read_bytes())
        app = root / "InstrumentedFixture.app"
        app.mkdir()
        sdk = self._command(["/usr/bin/xcrun", "--sdk", "iphonesimulator", "--show-sdk-path"]).strip()
        self._command(["/usr/bin/xcrun", "swiftc", "--version"])
        self._command(
            [
                "/usr/bin/xcrun",
                "swiftc",
                "-sdk",
                sdk,
                "-target",
                "arm64-apple-ios18.0-simulator",
                "-parse-as-library",
                "-module-name",
                "InstrumentedFixture",
                str(copied),
                "-o",
                str(app / "InstrumentedFixture"),
                "-module-cache-path",
                str(root / "module-cache"),
            ]
        )
        (app / "Info.plist").write_bytes(
            plistlib.dumps(
                {
                    "CFBundleExecutable": "InstrumentedFixture",
                    "CFBundleIdentifier": self.package,
                    "CFBundleName": "InstrumentedFixture",
                    "CFBundlePackageType": "APPL",
                    "CFBundleVersion": "1",
                    "CFBundleShortVersionString": "1.0",
                    "MinimumOSVersion": "18.0",
                    "LSRequiresIPhoneOS": True,
                    "UIDeviceFamily": [1, 2],
                    "UILaunchScreen": {},
                    "CFBundleURLTypes": [{"CFBundleURLSchemes": ["apsacompiled"]}],
                    "UIApplicationSceneManifest": {
                        "UIApplicationSupportsMultipleScenes": False,
                        "UISceneConfigurations": {
                            "UIWindowSceneSessionRoleApplication": [
                                {
                                    "UISceneConfigurationName": "Default",
                                    "UISceneDelegateClassName": "InstrumentedFixture.SceneDelegate",
                                }
                            ]
                        },
                    },
                }
            )
        )
        self._command(["/usr/bin/codesign", "--force", "--sign", "-", str(app)])
        self.build = {
            "executable_sha256": digest((app / "InstrumentedFixture").read_bytes()),
            "info_plist_sha256": digest((app / "Info.plist").read_bytes()),
        }
        self.manifest = {
            "mode": "instrumented",
            "target": "dedicated-iOS-27.0-simulator",
            "compiled": True,
            "installed": False,
            "capture_state": "not-measured",
            "physical_device_verified": False,
            "source_sha256": digest(copied.read_bytes()),
            "build": self.build,
            "app": str(app),
            "commands": self.commands,
            "network_scope": "unsupported; HTTP-unmeasured",
            "storage_scope": "only fresh fixture session state.dat",
        }
        (root / "manifest.json").write_text(json.dumps(self.manifest, indent=2) + "\n")
        created = self._command(
            [
                "/usr/bin/xcrun",
                "simctl",
                "create",
                "APSA-Fresh-" + uuid.uuid4().hex,
                "com.apple.CoreSimulator.SimDeviceType.iPhone-17",
                "com.apple.CoreSimulator.SimRuntime.iOS-27-0",
            ]
        ).strip()
        self.device = str(uuid.UUID(created)).upper()
        try:
            self._command(["/usr/bin/xcrun", "simctl", "boot", self.device])
            self._command(["/usr/bin/xcrun", "simctl", "bootstatus", self.device, "-b"], timeout=120)
            self._command(["/usr/bin/xcrun", "simctl", "install", self.device, str(app)])
            installed = Path(
                self._command(
                    ["/usr/bin/xcrun", "simctl", "get_app_container", self.device, self.package, "app"]
                ).strip()
            )
            data = Path(
                self._command(
                    ["/usr/bin/xcrun", "simctl", "get_app_container", self.device, self.package, "data"]
                ).strip()
            )
            # Both paths are returned for exactly this new device and own package.
            if self.device not in str(installed) or self.device not in str(data):
                raise ValueError("Fresh simulator container identity differs")
            self.installed = installed
            self.response_path = data / "Documents/response.json"
            if self.environment()["app"] != {"package": self.package, **self.build}:
                raise ValueError("Fresh simulator installed executable differs")
            self.manifest.update(installed=True, device=self.device)
            self._command(["/usr/bin/xcrun", "simctl", "launch", self.device, self.package])
            ready = self._response({"action": "ready"})
            if ready.get("package") != self.package or any(ready.get(k) != v for k, v in self.build.items()):
                raise ValueError("Fresh simulator launched build differs")
            self.manifest = {
                "mode": "instrumented",
                "target": "dedicated-iOS-27.0-simulator",
                "compiled": True,
                "installed": True,
                "physical_device_verified": False,
                "source_sha256": digest(copied.read_bytes()),
                "build": self.build,
                "app": str(app),
                "device": self.device,
                "commands": self.commands,
                "network_scope": "unsupported; HTTP-unmeasured",
                "storage_scope": "only fresh fixture session state.dat",
                "capture_state": "ready",
                "delivery_scope": "target-app-argv-handler; OS-deep-link-routing-unmeasured",
                "fixture_policy": {"local_residual": local_residual},
            }
            (root / "manifest.json").write_text(json.dumps(self.manifest, indent=2) + "\n")
        except (ValueError, OSError, subprocess.SubprocessError):
            self.manifest["capture_state"] = "inconclusive"
            (root / "manifest.json").write_text(json.dumps(self.manifest, indent=2) + "\n")
            self.close()
            raise

    def _command(self, argv: list[str], timeout: int = 90) -> str:
        result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
        self.commands.append(
            {
                "argv": argv,
                "status": result.returncode,
                "stdout": result.stdout.decode(errors="replace"),
                "stderr": result.stderr.decode(errors="replace"),
            }
        )
        (self.root / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n")
        if result.returncode:
            raise ValueError("Fresh simulator command failed; generated bounded command evidence retained")
        return result.stdout.decode()

    def _response(self, expected: dict) -> dict:
        deadline = time.monotonic() + 15
        last_action = "missing"
        while time.monotonic() < deadline:
            try:
                if self.response_path.stat().st_size > MAX_LINE:
                    raise ValueError("Fresh simulator response exceeds bound")
                response = json.loads(self.response_path.read_bytes())
                if isinstance(response, dict) and response.get("action") in {
                    "ready",
                    "url-received",
                    "session",
                    "transition",
                    "capture",
                    "fixture-error",
                }:
                    last_action = response["action"]
                if isinstance(response, dict) and response.get("action") == "fixture-error":
                    code = response.get("code")
                    if code in {"url-shape", "field-shape", "challenge", "session-state", "account", "store"}:
                        raise ValueError("Fresh simulator fixed fixture error: " + code)
                    raise ValueError("Fresh simulator fixture error")
                if isinstance(response, dict) and all(response.get(k) == v for k, v in expected.items()):
                    return response
            except (FileNotFoundError, json.JSONDecodeError):
                pass
            time.sleep(0.05)
        raise ValueError("Fresh simulator response challenge timed out; fixed stage=" + last_action)

    def _url(self, fields: dict[str, str]) -> dict:
        self._command(
            [
                "/usr/bin/xcrun",
                "simctl",
                "launch",
                "--terminate-running-process",
                self.device or "",
                self.package,
                "apsacompiled://fixture?" + urlencode(fields),
            ]
        )
        return self._response(fields)

    def environment(self) -> dict:
        return {
            "platform": "ios",
            "simulator": True,
            "app": {
                "package": self.package,
                "executable_sha256": digest((self.installed / "InstrumentedFixture").read_bytes()),
                "info_plist_sha256": digest((self.installed / "Info.plist").read_bytes()),
            },
        }

    def start_session(self, binding: dict, nonce: str) -> AcquisitionSession:
        if (
            binding["platform"] != "ios"
            or binding["package"] != self.package
            or binding["build"] != self.build
        ):
            raise ValueError("Fresh simulator binding differs")
        fields = {
            "action": "session",
            "session": nonce,
            "kind": self.transition["kind"],
            "account": self.transition["from_account"] or "",
            "retain": str(self.local_residual).lower(),
        }
        self._command(
            [
                "/usr/bin/xcrun",
                "simctl",
                "launch",
                "--terminate-running-process",
                self.device or "",
                self.package,
                "apsacompiled://fixture?" + urlencode(fields),
            ]
        )
        response = self._response({"action": "session", "session": nonce})
        if (
            response.get("fresh_store") is not True
            or response.get("package") != self.package
            or any(response.get(k) != v for k, v in self.build.items())
        ):
            raise ValueError("Fresh simulator session build differs")
        self.session = AcquisitionSession(
            "fresh-ios-simulator", "instrumented", nonce, "ios", self.package, copy.deepcopy(self.build)
        )
        return self.session

    def open_url(self, url: str) -> dict:
        if url != "synthetic://transition" or self.after or not self.session:
            raise ValueError("Fresh simulator transition unsupported")
        response = self._url(
            {"action": "transition", "session": self.session.nonce, "kind": self.transition["kind"]}
        )
        if (
            response.get("account") != (self.transition["to_account"] or "")
            or response.get("delivery") != "target-observed"
            or response.get("executable_sha256") != self.build["executable_sha256"]
        ):
            raise ValueError("Fresh simulator delivery differs")
        self.after = True
        return {"delivery": "target-activity-reported"}

    def capture(self, request: CaptureRequest) -> AcquiredCapture:
        if request.session != self.session:
            raise ValueError("Fresh simulator capture session differs")
        response = self._url(
            {
                "action": "capture",
                "session": request.session.nonce,
                "nonce": request.nonce,
                "snapshot": request.snapshot,
                "account": request.account or "",
                "state": request.state,
                "transition": request.transition or "",
            }
        )
        if (
            any(response.get(k) != v for k, v in self.build.items())
            or response.get("completeness") != "complete"
            or not isinstance(response.get("storage"), str)
        ):
            raise ValueError("Fresh simulator capture build or completeness differs")
        expected_delivery = "target-observed" if self.after else "baseline"
        if response.get("delivery") != expected_delivery:
            raise ValueError("Fresh simulator delivery differs")
        return AcquiredCapture(
            request,
            response["account"] or None,
            response["state"],
            expected_delivery,
            (
                SurfaceCapture(
                    "storage",
                    "complete",
                    (RawObservation("fresh-fixture-state", response["storage"].encode()),),
                ),
                SurfaceCapture("ui", "unsupported", ()),
                SurfaceCapture("logs", "unsupported", ()),
                SurfaceCapture("network", "unsupported", ()),
            ),
        )

    def close(self) -> dict:
        if self.device:
            device, self.device = self.device, None
            self._command(["/usr/bin/xcrun", "simctl", "shutdown", device])
            self._command(["/usr/bin/xcrun", "simctl", "delete", device])
        return {"commands": self.commands, "scope": "fresh-owned-simulator-only"}
