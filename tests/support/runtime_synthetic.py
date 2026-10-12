"""Executable, in-memory test app and transport; never contacts a device or URL."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from mobile_audit.core import digest
from mobile_audit.runtime_acquisition import (
    AcquiredCapture,
    AcquisitionSession,
    BackendProbe,
    CaptureRequest,
    RawObservation,
    SurfaceCapture,
)


class MockBackendTransport:
    """A replayable backend model, independent of the app's local state."""

    def __init__(self, markers: dict, invalidate: bool):
        self.markers = markers
        self.invalidate = invalidate
        self.credentials: dict[bytes, str] = {}
        self.events: list[RawObservation] = []
        self.counter = 0

    def issue(self, account: str) -> bytes:
        self.counter += 1
        credential = f"new-synthetic-credential-{account}-{self.counter}".encode()
        self.credentials[credential] = account
        return credential

    def revoke(self, credential: bytes | None) -> None:
        if self.invalidate and credential:
            self.credentials.pop(credential, None)

    def probe(self, credential: bytes, canary_label: str) -> BackendProbe:
        account = self.credentials.get(credential)
        raw = json.dumps(
            {"status": 200 if account else 401, "canary": self.markers[canary_label] if account else ""}
        ).encode()
        request = b"credential=" + credential
        self.events.append(RawObservation("replay-request", request))
        self.events.append(RawObservation("replay-response", raw))
        return BackendProbe(
            digest(b"in-memory-synthetic-backend"),
            digest(credential),
            "accepted" if account else "rejected",
            request,
            raw,
        )


class SyntheticTestAppAdapter:
    """Owned newly generated app model, not Android/iOS instrumentation proof.

    This object implements both runtime actions and the typed acquisition protocol.
    Its backend lifetime and local residual policy are independently configurable.
    """

    def __init__(self, scenario: dict, *, invalidate_backend: bool = True, local_residual: bool = False):
        self.scenario = copy.deepcopy(scenario)
        if len(self.scenario["workflow"]["transitions"]) != 1:
            raise ValueError("Synthetic adapter supports exactly one transition per fresh app model")
        self.transition = self.scenario["workflow"]["transitions"][0]
        self.account = self.transition["from_account"]
        self.backend = MockBackendTransport(self.scenario["markers"], invalidate_backend)
        self.credential = self.backend.issue(self.account) if self.account else None
        self.replay_credential = self.credential
        self.replay_account = self.account
        self.after = False
        self.local_residual = local_residual
        self.session: AcquisitionSession | None = None

    def environment(self) -> dict:
        key = "apk_sha256" if self.scenario["platform"] == "android" else "executable_sha256"
        return {
            "platform": self.scenario["platform"],
            "synthetic": True,
            "app": {"package": self.scenario["package"], key: digest(b"new-synthetic-test-app-build")},
        }

    def start_session(self, binding: dict, nonce: str) -> AcquisitionSession:
        environment = self.environment()
        observed_build = {k: v for k, v in environment["app"].items() if k != "package"}
        if (
            binding["platform"] != environment["platform"]
            or binding["package"] != environment["app"]["package"]
            or binding["build"] != observed_build
        ):
            raise ValueError("Synthetic app build does not match acquisition request")
        self.session = AcquisitionSession(
            "synthetic-test-app",
            "synthetic",
            nonce,
            binding["platform"],
            binding["package"],
            copy.deepcopy(binding["build"]),
        )
        return self.session

    def open_url(self, url: str) -> dict:
        if url != "synthetic://transition" or self.after:
            raise ValueError("Only one modeled synthetic transition is supported")
        self.backend.revoke(self.credential)
        self.account = self.transition["to_account"]
        self.credential = self.backend.issue(self.account) if self.account else None
        self.after = True
        return {"delivery": "target-activity-reported"}

    def capture(self, request: CaptureRequest) -> AcquiredCapture:
        if self.session is None or request.session != self.session:
            raise ValueError("Synthetic acquisition session challenge differs")
        markers = self.scenario["markers"]
        labels = []
        if self.account:
            account = self.scenario["workflow"]["accounts"][self.account]
            labels.extend([account["canary"], account["login_marker"]])
        elif not self.after:
            labels.append(self.transition["baseline_marker"])
        if self.after:
            labels.extend([self.transition["state_marker"], self.transition["delivery_marker"]])
        payload = " ".join(markers[label] for label in labels).encode()
        self.backend.events = [RawObservation("app-state-response", payload)]
        probe = None
        if self.replay_credential and self.replay_account:
            canary = self.scenario["workflow"]["accounts"][self.replay_account]["canary"]
            probe = self.backend.probe(self.replay_credential, canary)
        storage = payload
        if self.after and self.local_residual and self.replay_account:
            canary = self.scenario["workflow"]["accounts"][self.replay_account]["canary"]
            storage += b" " + markers[canary].encode()
        return AcquiredCapture(
            request,
            self.account,
            "authenticated" if self.account else "logged_out",
            "target-observed" if self.after else "baseline",
            (
                SurfaceCapture("network", "complete", tuple(self.backend.events)),
                SurfaceCapture("storage", "complete", (RawObservation("app-storage", storage),)),
                SurfaceCapture("ui", "complete", (RawObservation("app-ui", payload),)),
                SurfaceCapture("logs", "unsupported", ()),
            ),
            probe,
        )


def generate_synthetic_sources(root: Path) -> dict:
    """Write new source-only models for review, without building or installing."""
    root.mkdir(parents=True, exist_ok=False)
    sources = {
        "SyntheticAuth.kt": """// Source model only; no device build or installation claim.
package com.synthetic.app
class SyntheticAuth {
    var account: String? = null
    var credential: String? = null
    fun login(name: String) { account = name; credential = \"synthetic-\" + name }
    fun switchAccount(name: String) { logout(); login(name) }
    fun logout() { account = null; credential = null }
}
""",
        "SyntheticAuth.swift": """// Source model only; no device build or installation claim.
final class SyntheticAuth {
    var account: String? = nil
    var credential: String? = nil
    func login(_ name: String) { account = name; credential = \"synthetic-\" + name }
    func switchAccount(_ name: String) { logout(); login(name) }
    func logout() { account = nil; credential = nil }
}
""",
    }
    evidence = []
    for name, source in sources.items():
        raw = source.encode()
        (root / name).write_bytes(raw)
        evidence.append({"label": name, "sha256": digest(raw), "bytes": len(raw)})
    return {"mode": "source-only-synthetic", "compiled": False, "installed": False, "sources": evidence}
