"""Constructor-injected acquisition boundary; JSON never grants acquisition trust.

Adapters are trusted application code, not untrusted plugins. The recorder binds
their observations to fresh challenges and computes evidence without persisting
payloads. No physical-device/proxy adapter is shipped by this contract.
"""

from __future__ import annotations

import copy
import re
import secrets
from dataclasses import dataclass
from typing import Literal, Protocol

from .core import canonical_json, digest, now
from .runtime_evidence import HASH, LABEL, SURFACES, build_binding, validate_build

MAX_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 4000


@dataclass(frozen=True)
class AcquisitionSession:
    adapter_id: str
    mode: Literal["synthetic", "instrumented"]
    nonce: str
    platform: str
    package: str
    build: dict[str, str]


@dataclass(frozen=True)
class CaptureRequest:
    session: AcquisitionSession
    nonce: str
    snapshot: str
    account: str | None
    state: Literal["authenticated", "logged_out"]
    transition: str | None


@dataclass(frozen=True)
class RawObservation:
    label: str
    data: bytes


@dataclass(frozen=True)
class SurfaceCapture:
    surface: str
    completeness: Literal["complete", "partial", "unsupported"]
    observations: tuple[RawObservation, ...]


@dataclass(frozen=True)
class BackendProbe:
    """Probe of a previously issued credential, scoped to one backend authority.

    The credential and authority themselves stay in memory. An adapter must issue a
    fresh request with that credential; local deletion is never this probe.
    """

    authority_sha256: str
    credential_sha256: str
    outcome: Literal["accepted", "rejected", "not_checked"]
    request: bytes
    response: bytes


@dataclass(frozen=True)
class AcquiredCapture:
    request: CaptureRequest
    observed_account: str | None
    observed_state: str
    delivery: Literal["baseline", "target-observed", "unconfirmed"]
    surfaces: tuple[SurfaceCapture, ...]
    backend_probe: BackendProbe | None = None


class AcquisitionAdapter(Protocol):
    def start_session(self, binding: dict, nonce: str) -> AcquisitionSession: ...

    def capture(self, request: CaptureRequest) -> AcquiredCapture: ...


def acquisition_plan(platform: str, package: str) -> dict:
    """Public read-only plan; deliberately does not enumerate targets or devices."""
    if platform not in {"android", "ios"}:
        raise ValueError("Acquisition platform must be android or ios")
    if not isinstance(package, str) or not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", package):
        raise ValueError("Acquisition package must be an app identifier")
    return {
        "schema_version": 1,
        "platform": platform,
        "package": package,
        "live_acquisition": "unsupported",
        "injection": "constructor-only",
        "synthetic_adapter": "mobile_audit.runtime_synthetic.SyntheticTestAppAdapter",
        "required_binding": [
            "platform",
            "package",
            "build",
            "session-nonce",
            "capture-nonce",
            "account",
            "state",
            "delivery",
        ],
        "persisted_evidence": "labels, byte counts, SHA-256 digests and bounded states only",
        "backend_invalidation": "Separate baseline accepted and after rejected probes of the same credential and authority",
        "pending": [
            "explicit authorized target and dedicated test accounts",
            "platform-specific instrumented app or authenticated proxy adapter",
            "installed-build identity, delivery and capture-completeness measurement",
            "authorized backend credential replay probe",
        ],
    }


class AcquisitionRecorder:
    def __init__(self, adapter: AcquisitionAdapter, binding: dict, markers: dict[str, str]):
        self.adapter = adapter
        self.binding = copy.deepcopy(binding)
        self.markers = copy.deepcopy(markers)
        self.session_nonce = secrets.token_hex(32)
        self.session: AcquisitionSession | None = None
        self.error = False
        self.total_bytes = 0
        self.total_entries = 0
        self.used_nonces: set[str] = set()
        try:
            acquisition_plan(binding["platform"], binding["package"])
            reconstructed = build_binding(binding["platform"], binding["package"], binding["build"])
            self.binding = reconstructed
            if reconstructed != binding:
                raise ValueError("Invalid acquisition app binding")
            candidate = adapter.start_session(copy.deepcopy(binding), self.session_nonce)
            if type(candidate) is not AcquisitionSession:
                raise ValueError("Untyped acquisition session")
            validate_build(candidate.build)
            if (
                not isinstance(candidate.adapter_id, str)
                or not LABEL.fullmatch(candidate.adapter_id)
                or candidate.mode not in {"synthetic", "instrumented"}
                or ("runtime_model_sha256" in candidate.build and candidate.mode != "synthetic")
                or candidate.nonce != self.session_nonce
                or candidate.platform != binding["platform"]
                or candidate.package != binding["package"]
                or candidate.build != binding["build"]
            ):
                raise ValueError("Unbound acquisition session")
            promoted = build_binding(
                binding["platform"],
                binding["package"],
                binding["build"],
                allow_synthetic_model=candidate.mode == "synthetic",
            )
            if promoted["state"] != "bound":
                raise ValueError("Acquisition session lacks a strong build binding")
            self.binding = promoted
            self.session = copy.deepcopy(candidate)
        except (ValueError, TypeError, AttributeError, KeyError, OSError):
            self.error = True
            self._revoke_model_binding()

    def _revoke_model_binding(self) -> None:
        build = self.binding.get("build", {})
        platform_key = "apk_sha256" if self.binding.get("platform") == "android" else "executable_sha256"
        if isinstance(build, dict) and build.get("runtime_model_sha256") and not build.get(platform_key):
            self.binding["state"] = "unavailable"

    def metadata(self) -> dict:
        return {
            "state": "bound" if self.session and self.binding.get("state") == "bound" else "inconclusive",
            "mode": self.session.mode if self.session else "unavailable",
            "adapter_id": self.session.adapter_id if self.session else "unavailable",
            "session_sha256": digest(self.session_nonce.encode()),
            "live_device_verified": False,
            "capture_errors": self.error,
            "note": "Injected adapter evidence; synthetic mode proves only the executable fixture contract. Physical-device acquisition requires separate evidence.",
        }

    def _unavailable(self, state: dict | None) -> dict:
        self._revoke_model_binding()
        return {
            "created": now(),
            "binding": self.binding,
            "declared_state": state,
            "surfaces": {
                s: {
                    "state": "inconclusive",
                    "acquisition": "unverified",
                    "reason": "Acquisition binding or bounded capture validation failed",
                }
                for s in SURFACES
            },
            "files": [],
            "matches": [],
            "acquisition": self.metadata(),
        }

    def capture(self, label: str, state: dict | None, transition: str | None) -> dict:
        if (
            self.session is None
            or self.binding.get("state") != "bound"
            or state is None
            or not isinstance(label, str)
            or not LABEL.fullmatch(label)
            or state.get("state") not in {"authenticated", "logged_out"}
            or (
                state.get("account") is not None
                and (not isinstance(state["account"], str) or not LABEL.fullmatch(state["account"]))
            )
            or (state.get("state") == "authenticated") != (state.get("account") is not None)
            or transition not in {None, "login", "account_switch", "logout"}
        ):
            return self._unavailable(state)
        nonce = secrets.token_hex(32)
        request = CaptureRequest(
            copy.deepcopy(self.session), nonce, label, state["account"], state["state"], transition
        )
        try:
            capture = self.adapter.capture(copy.deepcopy(request))
            return self._record(request, capture)
        except (ValueError, TypeError, AttributeError, KeyError, OSError):
            self.error = True
            return self._unavailable(state)

    def _record(self, request: CaptureRequest, capture: AcquiredCapture) -> dict:
        if (
            type(capture) is not AcquiredCapture
            or type(capture.request) is not CaptureRequest
            or capture.request != request
            or request.nonce in self.used_nonces
            or capture.observed_account != request.account
            or capture.observed_state != request.state
            or capture.delivery not in {"baseline", "target-observed", "unconfirmed"}
            or not isinstance(capture.surfaces, tuple)
            or len(capture.surfaces) > len(SURFACES)
        ):
            raise ValueError("Unbound acquisition capture")
        self.used_nonces.add(request.nonce)
        provenance = {
            **self.metadata(),
            "capture_sha256": digest(request.nonce.encode()),
            "snapshot": request.snapshot,
            "account": request.account,
            "observed_state": request.state,
            "delivery": capture.delivery,
            "binding_identity": self.binding["identity"],
        }
        result = {
            "created": now(),
            "binding": self.binding,
            "declared_state": {"account": request.account, "state": request.state},
            "surfaces": {s: {"state": "not-run", "acquisition": "unsupported"} for s in SURFACES},
            "files": [],
            "matches": [],
            "acquisition": provenance,
        }
        seen = set()
        entries = 0
        byte_count = 0
        for surface in capture.surfaces:
            if (
                type(surface) is not SurfaceCapture
                or not isinstance(surface.surface, str)
                or surface.surface not in SURFACES
                or surface.surface in seen
                or surface.completeness not in {"complete", "partial", "unsupported"}
                or not isinstance(surface.observations, tuple)
                or len(surface.observations) > MAX_ENTRIES
                or (surface.completeness == "unsupported" and surface.observations)
            ):
                raise ValueError("Unsupported or duplicate capture surface")
            seen.add(surface.surface)
            labels = set()
            for observation in surface.observations:
                if (
                    type(observation) is not RawObservation
                    or not isinstance(observation.label, str)
                    or not LABEL.fullmatch(observation.label)
                    or observation.label in labels
                    or type(observation.data) is not bytes
                    or len(observation.data) > MAX_BYTES
                ):
                    raise ValueError("Invalid bounded raw observation")
                labels.add(observation.label)
                entries += 1
                byte_count += len(observation.data)
                if self.total_entries + entries > MAX_ENTRIES or self.total_bytes + byte_count > MAX_BYTES:
                    raise ValueError("Acquisition total budget exceeded")
                result["files"].append(
                    {
                        "surface": surface.surface,
                        "path": observation.label,
                        "sha256": digest(observation.data),
                        "bytes": len(observation.data),
                        "origin": "adapter-acquired",
                    }
                )
                for marker, value in self.markers.items():
                    if any(
                        value.encode(enc) in observation.data for enc in ("utf-8", "utf-16-le", "utf-16-be")
                    ):
                        result["matches"].append(
                            {
                                "surface": surface.surface,
                                "path": observation.label,
                                "marker_label": marker,
                                "marker_sha256": digest(value.encode()),
                                "origin": "adapter-acquired",
                            }
                        )
            result["surfaces"][surface.surface] = {
                "state": "captured" if surface.completeness == "complete" else "inconclusive",
                "files": len(surface.observations),
                "completeness": surface.completeness,
                "acquisition": "adapter-acquired",
                "provenance": provenance,
            }
        if capture.backend_probe is not None:
            probe = capture.backend_probe
            if (
                type(probe) is not BackendProbe
                or any(
                    not isinstance(v, str) or not HASH.fullmatch(v)
                    for v in (probe.authority_sha256, probe.credential_sha256)
                )
                or probe.outcome not in {"accepted", "rejected", "not_checked"}
                or type(probe.request) is not bytes
                or type(probe.response) is not bytes
                or len(probe.request) > MAX_BYTES
                or len(probe.response) > MAX_BYTES
                or not probe.request
                or not probe.response
                or self.total_bytes + byte_count + len(probe.request) + len(probe.response) > MAX_BYTES
            ):
                raise ValueError("Invalid backend replay probe")
            byte_count += len(probe.request) + len(probe.response)
            result["backend_probe"] = {
                "authority_sha256": probe.authority_sha256,
                "credential_sha256": probe.credential_sha256,
                "outcome": probe.outcome,
                "request_sha256": digest(probe.request),
                "request_bytes": len(probe.request),
                "response_sha256": digest(probe.response),
                "bytes": len(probe.response),
                "provenance": provenance,
            }
        self.total_entries += entries
        self.total_bytes += byte_count
        result["evidence_sha256"] = digest(
            canonical_json(
                {k: result[k] for k in ("files", "matches", "surfaces", "backend_probe") if k in result}
            ).encode()
        )
        return result


def evaluate_backend_invalidation(scenario: dict, snapshots: dict) -> list[dict]:
    """Never infer backend behavior from UI, local residuals or manual captures."""
    results = []
    for transition in scenario.get("workflow", {}).get("transitions", []):
        if transition["kind"] != "logout":
            continue
        before = snapshots.get(transition["baseline"], {})
        after = snapshots.get(transition["snapshot"], {})
        probes = [before.get("backend_probe", {}), after.get("backend_probe", {})]
        valid = all(p.get("provenance", {}).get("state") == "bound" for p in probes)
        valid = valid and before.get("acquisition", {}).get("session_sha256") == after.get(
            "acquisition", {}
        ).get("session_sha256")
        valid = valid and all(
            probes[0].get(k) and probes[0].get(k) == probes[1].get(k)
            for k in ("authority_sha256", "credential_sha256")
        )
        valid = (
            valid
            and probes[0].get("outcome") == "accepted"
            and after.get("acquisition", {}).get("delivery") == "target-observed"
        )
        state = "inconclusive"
        valid = valid and all(
            snapshot.get("surfaces", {}).get("network", {}).get("state") == "captured"
            and snapshot.get("surfaces", {}).get("network", {}).get("acquisition") == "adapter-acquired"
            for snapshot in (before, after)
        )
        if valid and probes[1].get("outcome") in {"accepted", "rejected"}:
            state = "passed" if probes[1]["outcome"] == "rejected" else "failed"
        results.append(
            {
                "baseline": transition["baseline"],
                "snapshot": transition["snapshot"],
                "state": state,
                "mode": after.get("acquisition", {}).get("mode", "unavailable"),
                "note": "Credential replay at the same backend authority only; local deletion and whole-system invalidation are separate.",
            }
        )
    return results
