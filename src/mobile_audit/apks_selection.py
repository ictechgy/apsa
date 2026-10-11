"""Bounded APK-set selection for an explicit, synthetic or user-supplied device spec.

This is a conservative subset of bundletool, not an installability verifier.
Unsupported metadata anywhere in the TOC prevents selection. In particular,
overlapping variants are rejected instead of relying on variant-number priority.
The caller must independently bound ZIP sizes, compression, encryption and reads.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any, Generic, Literal, NoReturn, TypeVar, overload

MAX_TOC_BYTES = 2 * 1024 * 1024
MAX_FIELDS = 60_000
MAX_MEMBERS = 20_000
MAX_VARIANTS = 128
MAX_APKS = 2_048
MAX_MODULES = 256
MAX_TARGET_VALUES = 128
REFERENCE_URLS = (
    "https://developer.android.com/tools/bundletool",
    "https://github.com/google/bundletool/blob/master/src/main/proto/commands.proto",
    "https://github.com/google/bundletool/blob/master/src/main/proto/targeting.proto",
    "https://github.com/google/bundletool/blob/master/src/main/proto/devices.proto",
    "https://github.com/google/bundletool/blob/master/src/main/java/com/android/tools/build/bundletool/device/AbiMatcher.java",
    "https://github.com/google/bundletool/blob/master/src/main/java/com/android/tools/build/bundletool/device/SdkVersionMatcher.java",
    "https://github.com/google/bundletool/blob/master/src/main/java/com/android/tools/build/bundletool/device/LanguageMatcher.java",
    "https://github.com/google/bundletool/blob/master/src/main/java/com/android/tools/build/bundletool/model/targeting/ScreenDensitySelector.java",
    "https://github.com/google/bundletool/blob/1.18.3/src/main/java/com/android/tools/build/bundletool/splitters/ModuleSplitter.java",
)
ABI_NAMES = {
    1: "armeabi",
    2: "armeabi-v7a",
    3: "arm64-v8a",
    4: "x86",
    5: "x86_64",
    6: "mips",
    7: "mips64",
    8: "riscv64",
}
DENSITIES = {2: 120, 3: 160, 4: 213, 5: 240, 6: 320, 7: 480, 8: 640}
_LOCALE = re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z]{4})?(?:-(?:[A-Za-z]{2}|[0-9]{3}))?\Z")
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")


class ApkSetSelectionError(ValueError):
    """A non-selecting result; callers must not fall back to scanning arbitrary APKs."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _fail(code: str, message: str) -> NoReturn:
    raise ApkSetSelectionError(code, message)


@dataclass(frozen=True)
class DeviceSpec:
    sdk_version: int
    supported_abis: tuple[str, ...]
    screen_density: int
    supported_locales: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.sdk_version) is not int or not 1 <= self.sdk_version < 10_000:
            _fail("invalid_device_spec", "Device SDK must be an explicit released positive SDK below 10000")
        if type(self.screen_density) is not int or not 1 <= self.screen_density <= 10_000:
            _fail("invalid_device_spec", "Device screen density must be an explicit positive dpi")
        for values, limit, label in (
            (self.supported_abis, 8, "ABIs"),
            (self.supported_locales, 128, "locales"),
        ):
            if not isinstance(values, tuple) or not 1 <= len(values) <= limit:
                _fail("invalid_device_spec", f"Device {label} must be a nonempty bounded tuple")
            if any(not isinstance(value, str) for value in values) or len(set(values)) != len(values):
                _fail("invalid_device_spec", f"Device {label} contain invalid or duplicate values")
        if any(value not in ABI_NAMES.values() for value in self.supported_abis):
            _fail("invalid_device_spec", "Device contains an unknown ABI")
        if any(not _LOCALE.fullmatch(value) for value in self.supported_locales):
            _fail("invalid_device_spec", "Device locale is outside the supported language/script/region form")
        if len({value.lower() for value in self.supported_locales}) != len(self.supported_locales):
            _fail("invalid_device_spec", "Device locales are duplicated after case normalization")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> DeviceSpec:
        expected = {"sdkVersion", "supportedAbis", "screenDensity", "supportedLocales"}
        if not isinstance(value, Mapping) or set(value) != expected:
            _fail(
                "invalid_device_spec",
                "Device spec requires exactly sdkVersion/supportedAbis/screenDensity/supportedLocales",
            )
        if not isinstance(value["supportedAbis"], (list, tuple)) or not isinstance(
            value["supportedLocales"], (list, tuple)
        ):
            _fail("invalid_device_spec", "Device ABI and locale values must be arrays")
        return cls(
            value["sdkVersion"],
            tuple(value["supportedAbis"]),
            value["screenDensity"],
            tuple(value["supportedLocales"]),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "sdkVersion": self.sdk_version,
            "supportedAbis": list(self.supported_abis),
            "screenDensity": self.screen_density,
            "supportedLocales": list(self.supported_locales),
        }

    @property
    def languages(self) -> frozenset[str]:
        # bundletool's ResourcesUtils preserves pre-JDK25 Android language names.
        legacy = {"he": "iw", "id": "in", "yi": "ji"}
        return frozenset(
            legacy.get(value.split("-")[0].lower(), value.split("-")[0].lower())
            for value in self.supported_locales
        )


TargetValue = TypeVar("TargetValue", bound=str | int, covariant=True)


@dataclass(frozen=True)
class Dimension(Generic[TargetValue]):
    values: tuple[TargetValue, ...] = ()
    alternatives: tuple[TargetValue, ...] = ()

    def as_dict(self) -> dict[str, list[str | int]]:
        values: list[str | int] = [*self.values]
        alternatives: list[str | int] = [*self.alternatives]
        return {"values": values, "alternatives": alternatives}


@dataclass(frozen=True)
class Targeting:
    sdk: Dimension[int] = Dimension()
    abi: Dimension[str] = Dimension()
    density: Dimension[int] = Dimension()
    language: Dimension[str] = Dimension()

    def as_dict(self) -> dict[str, dict[str, list[str | int]]]:
        return {name: dimension.as_dict() for name, dimension in self.dimensions()}

    def dimensions(self) -> tuple[tuple[str, Dimension[str | int]], ...]:
        return (("sdk", self.sdk), ("abi", self.abi), ("density", self.density), ("language", self.language))


@dataclass(frozen=True)
class SelectedApk:
    path: str
    module_name: str
    kind: str
    is_master_split: bool
    split_id: str
    fused_modules: tuple[str, ...]
    dependencies: tuple[str, ...]
    targeting: Targeting

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "module_name": self.module_name,
            "kind": self.kind,
            "is_master_split": self.is_master_split,
            "split_id": self.split_id,
            "fused_modules": list(self.fused_modules),
            "dependencies": list(self.dependencies),
            "delivery_type": "install-time",
            "targeting": self.targeting.as_dict(),
        }


@dataclass(frozen=True)
class ApkSetSelection:
    selected_apks: tuple[SelectedApk, ...]
    variant_number: int
    variant_targeting: Targeting
    device_spec: DeviceSpec
    package_name: str
    bundletool_version: str
    total_apks: int
    toc_sha256: str
    warnings: tuple[str, ...] = ()
    state: str = "selected"

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "selected_apks": [apk.as_dict() for apk in self.selected_apks],
            "variant_number": self.variant_number,
            "variant_targeting": self.variant_targeting.as_dict(),
            "device_spec": self.device_spec.as_dict(),
            "package_name": self.package_name,
            "bundletool_version": self.bundletool_version,
            "total_apks": self.total_apks,
            "toc_sha256": self.toc_sha256,
            "warnings": list(self.warnings),
            "reference_urls": list(REFERENCE_URLS),
            "installability_verified": False,
        }


class _Decoder:
    def __init__(self) -> None:
        self.remaining = MAX_FIELDS

    @staticmethod
    def varint(raw: bytes, cursor: int) -> tuple[int, int]:
        value = 0
        for index in range(10):
            if cursor >= len(raw):
                _fail("malformed_toc", "Truncated TOC protobuf integer")
            byte = raw[cursor]
            cursor += 1
            if index == 9 and byte > 1:
                _fail("malformed_toc", "TOC protobuf integer exceeds 64 bits")
            value |= (byte & 127) << (index * 7)
            if byte < 128:
                if index and byte == 0:
                    _fail("malformed_toc", "Noncanonical TOC protobuf integer")
                return value, cursor
        _fail("malformed_toc", "Invalid TOC protobuf integer")

    def fields(self, raw: bytes, allowed: set[int], label: str) -> dict[int, list[tuple[int, Any]]]:
        result: dict[int, list[tuple[int, Any]]] = {}
        cursor = 0
        while cursor < len(raw):
            self.remaining -= 1
            if self.remaining < 0:
                _fail("budget_exceeded", "TOC protobuf field budget exceeded")
            tag, cursor = self.varint(raw, cursor)
            number, wire = tag >> 3, tag & 7
            if not 1 <= number < (1 << 29):
                _fail("malformed_toc", "Invalid TOC protobuf field number")
            if number not in allowed:
                _fail("unsupported_toc", f"Unsupported {label} field {number}")
            if wire == 0:
                value, cursor = self.varint(raw, cursor)
            elif wire == 2:
                length, cursor = self.varint(raw, cursor)
                if cursor + length > len(raw):
                    _fail("malformed_toc", "Truncated TOC protobuf message")
                value = raw[cursor : cursor + length]
                cursor += length
            else:
                _fail("malformed_toc", "Unsupported TOC protobuf wire type")
            result.setdefault(number, []).append((wire, value))
        return result


def _one(fields: dict, number: int, *, wire: int = 2, default: Any = None) -> Any:
    values = fields.get(number, [])
    if len(values) > 1 or (values and values[0][0] != wire):
        _fail("malformed_toc", "Duplicate or mistyped singular TOC field")
    return values[0][1] if values else default


def _many(fields: dict, number: int) -> list[bytes]:
    values = fields.get(number, [])
    if any(wire != 2 for wire, _ in values):
        _fail("malformed_toc", "Mistyped repeated TOC field")
    return [raw for _, raw in values]


def _text(raw: bytes, *, limit: int = 1024) -> str:
    if not isinstance(raw, bytes) or len(raw) > limit:
        _fail("malformed_toc", "TOC string absent or exceeds budget")
    try:
        result = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        _fail("malformed_toc", "Invalid TOC UTF-8 string")
    if any(ord(char) < 32 or ord(char) == 127 for char in result):
        _fail("malformed_toc", "TOC string contains control characters")
    return result


def _boolean(fields: dict, number: int) -> bool:
    value = _one(fields, number, wire=0, default=0)
    if value not in (0, 1):
        _fail("malformed_toc", "Noncanonical TOC boolean")
    return bool(value)


def _names(raws: list[bytes]) -> tuple[str, ...]:
    names = tuple(_text(raw, limit=128) for raw in raws)
    if (
        len(names) > MAX_MODULES
        or len(set(names)) != len(names)
        or any(not _NAME.fullmatch(n) for n in names)
    ):
        _fail("malformed_toc", "Invalid or duplicate module names")
    return names


def _safe_name(name: str) -> bool:
    if not isinstance(name, str) or not name:
        return False
    try:
        if len(name.encode("utf-8")) > 1024:
            return False
    except UnicodeError:
        return False
    parts = name.rstrip("/").split("/")
    return (
        not name.startswith("/")
        and not any(p in {"", ".", ".."} for p in parts)
        and not any(ord(c) < 32 or ord(c) == 127 for c in name)
        and "\\" not in name
        and ":" not in name
        and unicodedata.normalize("NFC", name) == name
    )


@overload
def _dimension(dec: _Decoder, raw: bytes, kind: Literal["sdk", "density"]) -> Dimension[int]: ...


@overload
def _dimension(dec: _Decoder, raw: bytes, kind: Literal["abi", "language"]) -> Dimension[str]: ...


def _dimension(dec: _Decoder, raw: bytes, kind: str) -> Dimension[str | int]:
    fields = dec.fields(raw, {1, 2}, f"{kind} targeting")

    def atom(item: bytes) -> str | int:
        if kind == "language":
            value = _text(item, limit=3)
            if not re.fullmatch(r"[a-z]{2,3}", value):
                _fail("unsupported_toc", "Unsupported TOC language code")
            return value
        fields = dec.fields(item, {1, 2} if kind == "density" else {1}, kind)
        if kind == "sdk":
            minimum = _one(fields, 1)
            if minimum is None:
                return 0
            wrapper = dec.fields(minimum, {1}, "SDK minimum")
            value = _one(wrapper, 1, wire=0, default=0)
            if not 0 <= value < 10_000:
                _fail("unsupported_toc", "Unsupported prerelease or negative SDK targeting")
            return value
        if kind == "abi":
            value = _one(fields, 1, wire=0, default=0)
            if value not in ABI_NAMES:
                _fail("unsupported_toc", "Unknown TOC ABI alias")
            return ABI_NAMES[value]
        if len(fields) != 1:
            _fail("malformed_toc", "Missing or conflicting density oneof")
        if 1 in fields:
            alias = _one(fields, 1, wire=0)
            if alias not in DENSITIES:
                _fail("unsupported_toc", "Unsupported default/nodpi/unknown density alias")
            return DENSITIES[alias]
        value = _one(fields, 2, wire=0)
        if not 1 <= value <= 10_000:
            _fail("unsupported_toc", "Unsupported density dpi")
        return value

    values = tuple(atom(item) for item in _many(fields, 1))
    alternatives = tuple(atom(item) for item in _many(fields, 2))
    if len(values) + len(alternatives) > MAX_TARGET_VALUES:
        _fail("budget_exceeded", "Targeting value budget exceeded")
    if len(set(values + alternatives)) != len(values + alternatives):
        _fail("malformed_toc", "Duplicate or overlapping targeting values and alternatives")
    if kind == "sdk" and len(values) > 1:
        _fail("malformed_toc", "Multiple SDK minimum values")
    return Dimension(values, alternatives)


def _targeting(dec: _Decoder, raw: bytes, *, variant: bool = False) -> Targeting:
    fields = dec.fields(
        raw, {1, 2, 3} if variant else {1, 3, 4, 5}, "variant targeting" if variant else "APK targeting"
    )
    sdk_field, abi_field, density_field = (1, 2, 3) if variant else (5, 1, 4)
    return Targeting(
        sdk=_dimension(dec, _one(fields, sdk_field, default=b""), "sdk"),
        abi=_dimension(dec, _one(fields, abi_field, default=b""), "abi"),
        density=_dimension(dec, _one(fields, density_field, default=b""), "density"),
        language=Dimension() if variant else _dimension(dec, _one(fields, 3, default=b""), "language"),
    )


def _matches(target: Targeting, spec: DeviceSpec) -> bool:
    sdk = target.sdk
    minimum = sdk.values[0] if sdk.values else 0
    if spec.sdk_version < minimum or any(minimum < alt <= spec.sdk_version for alt in sdk.alternatives):
        return False
    abi = target.abi
    if abi.values or abi.alternatives:
        best = next((name for name in spec.supported_abis if name in abi.values + abi.alternatives), None)
        if best not in abi.values and (best is not None or abi.values):
            return False
    density = target.density
    if density.values or density.alternatives:

        def compare(a: int, b: int) -> int:
            if a == b:
                return 0
            if a > b:
                return -compare(b, a)
            desired = spec.screen_density
            if desired >= b:
                return -1
            if desired <= a:
                return 1
            return 1 if (2 * a - desired) * b > desired * desired else -1

        best = max(density.values + density.alternatives, key=cmp_to_key(compare))
        if best not in density.values:
            return False
    language = target.language
    if language.values:
        return bool(spec.languages.intersection(language.values))
    if language.alternatives:
        return not spec.languages.issubset(language.alternatives)
    return True


def _config_dimension(target: Targeting) -> str:
    active = [name for name, atom in target.dimensions() if atom.values or atom.alternatives]
    if len(active) == 1:
        return active[0]
    # ModuleSplitter.addDefaultSdkApkTargeting puts the common module SDK
    # minimum on every config split. It is an AND guard, not a second selector.
    if (
        len(active) == 2
        and "sdk" in active
        and len(target.sdk.values) == 1
        and target.sdk.values[0] >= 21
        and not target.sdk.alternatives
    ):
        return next(name for name in active if name != "sdk")
    _fail("unsupported_toc", "Config splits must have one selector, optionally with a shared SDK minimum")


def _validate_config_sdk_guards(apks: tuple[SelectedApk, ...]) -> None:
    for apk in apks:
        if apk.kind != "split" or apk.is_master_split or _config_dimension(apk.targeting) == "sdk":
            continue
        sdk = apk.targeting.sdk
        if not sdk.values and not sdk.alternatives:
            continue
        masters = [item for item in apks if item.module_name == apk.module_name and item.is_master_split]
        if not masters or any(item.targeting.sdk != sdk for item in masters):
            _fail("unsupported_toc", "Config SDK minimum must match every master split of its module")


def _validate_siblings(apks: tuple[SelectedApk, ...]) -> None:
    # Dimensions outside the contested one identify independent targeting groups.
    for dimension in ("sdk", "abi", "density", "language"):
        groups: dict[tuple, list[Dimension[str | int]]] = {}
        for apk in apks:
            atom = getattr(apk.targeting, dimension)
            if not atom.values and not atom.alternatives:
                continue
            key = (
                apk.module_name,
                apk.kind,
                apk.is_master_split,
                tuple((name, value) for name, value in apk.targeting.dimensions() if name != dimension),
            )
            groups.setdefault(key, []).append(atom)
        for atoms in groups.values():
            universe = set().union(*(set(atom.values + atom.alternatives) for atom in atoms))
            observed: set[str | int] = set()
            fallback = False
            for atom in atoms:
                if set(atom.values + atom.alternatives) != universe:
                    _fail("malformed_toc", "Inconsistent sibling targeting alternatives")
                if observed.intersection(atom.values) or (not atom.values and fallback):
                    _fail("ambiguous_selection", "Overlapping sibling targeting selectors")
                observed.update(atom.values)
                fallback |= not atom.values
            if universe - observed and not fallback:
                _fail("malformed_toc", "Targeting alternatives have no corresponding sibling APK")


def _validate_dependencies(modules: dict[str, tuple[str, ...]]) -> None:
    if "base" not in modules or modules["base"]:
        _fail("malformed_toc", "Variant requires an independent base module")
    for name, deps in modules.items():
        if name in deps or set(deps) - set(modules):
            _fail("malformed_toc", "Missing or self-dependent module")
    visited: set[str] = set()

    def visit(name: str, ancestors: frozenset[str]) -> None:
        if name in ancestors:
            _fail("malformed_toc", "Cyclic module dependencies")
        if name in visited:
            return
        for dep in modules[name]:
            visit(dep, ancestors | {name})
        visited.add(name)

    for name in modules:
        visit(name, frozenset())


def select_apks(
    raw_toc: bytes, device_spec: DeviceSpec | Mapping[str, Any], member_names: Iterable[str]
) -> ApkSetSelection:
    """Return authoritative paths only after fully validating the bounded TOC.

    Requires install-time feature modules, split or fused standalone APKs and the
    four modeled targeting dimensions. No current device/app data is acquired.
    """
    import hashlib

    spec = device_spec if isinstance(device_spec, DeviceSpec) else DeviceSpec.from_dict(device_spec)
    if not isinstance(raw_toc, bytes) or not raw_toc or len(raw_toc) > MAX_TOC_BYTES:
        _fail("budget_exceeded", "TOC is empty or exceeds byte budget")
    members: set[str] = set()
    normalized: set[str] = set()
    for name in member_names:
        if len(members) >= MAX_MEMBERS:
            _fail("budget_exceeded", "APK-set archive member budget exceeded")
        if not _safe_name(name):
            _fail("unsafe_member", "Unsafe APK-set archive member path")
        key = name.rstrip("/").casefold()
        if name in members or key in normalized:
            _fail("unsafe_member", "Duplicate or normalization-colliding APK-set members")
        members.add(name)
        normalized.add(key)
    if "toc.pb" not in members:
        _fail("missing_member", "APK set lacks toc.pb")
    files = {name.casefold() for name in members if not name.endswith("/")}
    for name in members:
        components = name.rstrip("/").casefold().split("/")
        if any("/".join(components[:end]) in files for end in range(1, len(components))):
            _fail("unsafe_member", "Archive member has a file as a parent directory")
    dec = _Decoder()
    top = dec.fields(raw_toc, {1, 2, 4, 5}, "BuildApksResult")
    if 5 in top:
        # bundletool 1.18.3 always serializes this message, including when
        # local testing is disabled. Disabled metadata has no delivery effect.
        local = dec.fields(_one(top, 5), {1, 2}, "local testing metadata")
        enabled = _boolean(local, 1)
        local_path = _text(_one(local, 2, default=b""))
        if enabled or local_path:
            _fail("unsupported_toc", "Enabled local testing or a local testing path is unsupported")
    package = _text(_one(top, 4, default=b""), limit=255)
    if package and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package):
        _fail("malformed_toc", "Invalid TOC package name")
    version = ""
    if 2 in top:
        version = _text(_one(dec.fields(_one(top, 2), {2}, "bundletool metadata"), 2, default=b""), limit=128)
    variants = _many(top, 1)
    if not variants or len(variants) > MAX_VARIANTS:
        _fail("budget_exceeded", "TOC variants absent or exceed count budget")
    all_paths: set[str] = set()
    numbers: set[int] = set()
    parsed: list[tuple[int, Targeting, tuple[SelectedApk, ...]]] = []
    for raw_variant in variants:
        variant = dec.fields(raw_variant, {1, 2, 3, 4}, "variant")
        number = _one(variant, 3, wire=0, default=0)
        if number > 0xFFFFFFFF or number in numbers:
            _fail("ambiguous_selection", "Duplicate or invalid TOC variant number")
        numbers.add(number)
        target = _targeting(dec, _one(variant, 1, default=b""), variant=True)
        if 4 in variant:
            props = dec.fields(_one(variant, 4), {1, 2, 3}, "variant properties")
            for field in props:
                _boolean(props, field)
        sets = _many(variant, 2)
        if not sets or len(sets) > MAX_MODULES:
            _fail("budget_exceeded", "Variant modules absent or exceed count budget")
        apks: list[SelectedApk] = []
        modules: dict[str, tuple[str, ...]] = {}
        for raw_set in sets:
            apk_set = dec.fields(raw_set, {1, 2}, "APK set")
            module = dec.fields(_one(apk_set, 1, default=b""), {1, 2, 3, 4, 5, 6, 7}, "module metadata")
            name = _text(_one(module, 1, default=b""), limit=128)
            if not _NAME.fullmatch(name) or name in modules:
                _fail("malformed_toc", "Missing, invalid or duplicate module name")
            dependencies = _names(_many(module, 4))
            if 5 in module:
                # BundleModule.getModuleMetadata always sets ModuleTargeting.
                # Only the empty, unconditional message is supported; every
                # populated condition (including unknown future fields) fails.
                dec.fields(_one(module, 5), set(), "conditional module targeting")
            if _boolean(module, 2) or _boolean(module, 3):
                _fail("unsupported_toc", "On-demand, instant or conditional module delivery is unsupported")
            if _one(module, 6, wire=0, default=0) != 1 or _one(module, 7, wire=0, default=1) != 1:
                _fail("unsupported_toc", "Only explicit install-time feature modules are supported")
            modules[name] = dependencies
            descriptions = _many(apk_set, 2)
            if not descriptions:
                _fail("malformed_toc", "Module has no APK descriptions")
            split_ids: set[str] = set()
            for raw_apk in descriptions:
                if len(all_paths) >= MAX_APKS:
                    _fail("budget_exceeded", "TOC APK count budget exceeded")
                apk = dec.fields(raw_apk, {1, 2, 3, 4, 10}, "APK description")
                path = _text(_one(apk, 2, default=b""))
                if not _safe_name(path) or not path.endswith(".apk"):
                    _fail("unsafe_member", "Unsafe or non-APK TOC path")
                if path in all_paths:
                    _fail("malformed_toc", "Duplicate APK path in TOC")
                all_paths.add(path)
                if path not in members:
                    _fail("missing_member", "A TOC APK path is absent from the archive")
                targeting = _targeting(dec, _one(apk, 1, default=b""))
                if (3 in apk) == (4 in apk):
                    _fail("malformed_toc", "APK must have exactly one split or standalone metadata value")
                if 10 in apk:
                    signing = dec.fields(_one(apk, 10), {1}, "signing description")
                    _boolean(signing, 1)
                fused: tuple[str, ...] = ()
                split_id = ""
                if 3 in apk:
                    metadata = dec.fields(_one(apk, 3), {1, 2}, "split metadata")
                    split_id = _text(_one(metadata, 1, default=b""), limit=128)
                    master = _boolean(metadata, 2)
                    if (not split_id and not master) or (split_id and not _NAME.fullmatch(split_id)):
                        _fail("malformed_toc", "Invalid or absent split ID")
                    if split_id in split_ids:
                        _fail("malformed_toc", "Duplicate module split ID")
                    split_ids.add(split_id)
                    kind = "split"
                    if not master:
                        _config_dimension(targeting)
                else:
                    metadata = dec.fields(_one(apk, 4), {1, 3}, "standalone metadata")
                    fused = _names(_many(metadata, 1))
                    if "base" not in fused or _one(metadata, 3, default=b""):
                        _fail("unsupported_toc", "Only standalone APKs fused with base are supported")
                    master = False
                    kind = "standalone"
                apks.append(SelectedApk(path, name, kind, master, split_id, fused, dependencies, targeting))
        _validate_dependencies(modules)
        kinds = {apk.kind for apk in apks}
        if len(kinds) != 1 or ("standalone" in kinds and set(modules) != {"base"}):
            _fail(
                "unsupported_toc",
                "Mixed split/standalone or separate standalone feature modules are unsupported",
            )
        _validate_config_sdk_guards(tuple(apks))
        _validate_siblings(tuple(apks))
        parsed.append((number, target, tuple(apks)))
    if {name for name in members if name.lower().endswith(".apk")} - all_paths:
        _fail("malformed_toc", "Archive contains APKs absent from authoritative TOC")
    matching = [item for item in parsed if _matches(item[1], spec)]
    if not matching:
        _fail("no_matching_variant", "No TOC variant matches the explicit device specification")
    if len(matching) != 1:
        _fail(
            "ambiguous_selection",
            "Multiple TOC variants match; overlapping priority selection is unsupported",
        )
    number, target, matching_apks = matching[0]
    selected = tuple(apk for apk in matching_apks if _matches(apk.targeting, spec))
    if not selected:
        _fail("no_matching_apks", "Matching variant has no matching APKs")
    if selected[0].kind == "standalone":
        if len(selected) != 1:
            _fail("ambiguous_selection", "Multiple standalone APKs match")
    else:
        for module in {apk.module_name for apk in matching_apks}:
            chosen = [apk for apk in selected if apk.module_name == module]
            if len([apk for apk in chosen if apk.is_master_split]) != 1:
                _fail(
                    "ambiguous_selection",
                    "Each install-time module requires exactly one matching master split",
                )
            for dimension in ("sdk", "abi", "density"):
                offered = [
                    apk
                    for apk in matching_apks
                    if apk.module_name == module
                    and not apk.is_master_split
                    and _config_dimension(apk.targeting) == dimension
                    and (
                        getattr(apk.targeting, dimension).values
                        or getattr(apk.targeting, dimension).alternatives
                    )
                ]
                if offered and len([apk for apk in chosen if apk in offered]) != 1:
                    _fail("no_matching_apks", "Missing or ambiguous required configuration split")
    return ApkSetSelection(
        selected,
        number,
        target,
        spec,
        package,
        version,
        len(all_paths),
        hashlib.sha256(raw_toc).hexdigest(),
        ("Selection models targeting only; APK identity/signatures and installability are not verified.",),
    )
