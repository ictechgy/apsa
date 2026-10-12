"""Validate per-run source resolution and remote transmission options."""

from dataclasses import asdict
from pathlib import Path

from .dependency_evidence import ResolvedBuildSelection
from .dependency_policy import DependencyTransmissionPolicy


def artifact_options(
    target: Path, apk_set_device: dict | None = None, ipa_trust_policy: dict | None = None
) -> tuple[dict | None, dict | None]:
    """Normalize explicit artifact options before process or job serialization."""
    if target.suffix.lower() == ".apks":
        from .apks_selection import DeviceSpec

        if apk_set_device is None:
            raise ValueError("An .apks audit requires an explicit APK-set device specification")
        # Keep validated supplementary metadata across job/process boundaries so
        # final selection can report its field-name-only normalization provenance.
        apk_set_device = DeviceSpec.from_dict(apk_set_device).as_input_dict()
    elif apk_set_device is not None:
        raise ValueError("APK-set device selection requires an .apks archive")
    if ipa_trust_policy is not None:
        if target.suffix.lower() != ".ipa":
            raise ValueError("IPA trust policy requires an .ipa archive")
        from .apple_trust import validate_trust_policy

        ipa_trust_policy = validate_trust_policy(ipa_trust_policy)
    return apk_set_device, ipa_trust_policy


def build_selection(
    module: str | None, configuration: str | None, evidence_paths: list[str] | None = None
) -> dict | None:
    if not module and not configuration and not evidence_paths:
        return None
    if not module or not configuration:
        raise ValueError("Dependency selection requires both application module and runtime configuration")
    return asdict(ResolvedBuildSelection(module, configuration, tuple(evidence_paths or [])))


def transmission_policy(
    ecosystems: list[str] | None = None, names: list[str] | None = None, coordinates: list[str] | None = None
) -> dict:
    return asdict(
        DependencyTransmissionPolicy(tuple(ecosystems or []), tuple(names or []), tuple(coordinates or []))
    )
