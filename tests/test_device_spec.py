"""Pinned device-spec interoperability using only newly generated synthetic inputs."""

from __future__ import annotations

import copy
import json
from dataclasses import replace

import pytest

from mobile_audit import apks_selection as selection
from mobile_audit.apks_selection import (
    ApkSetSelectionError,
    DeviceSpec,
    parse_device_spec_json,
    read_device_spec,
    select_apks,
)
from tests.apks_fixture import DEFAULT_DEVICE, description, field, module, split_toc, toc, variant

SUPPLEMENTARY = {
    "deviceFeatures": [
        "android.hardware.camera",
        "android.software.verified_boot",
        "android.hardware.vulkan.level=1",
        "reqGlEsVersion=0x30002",
    ],
    "glExtensions": ["GL_KHR_texture_compression_astc_ldr", "GL_EXT_texture_format_BGRA8888"],
    "codename": "REL",
    "deviceTier": 0,
    "deviceGroups": ["synthetic_group"],
    "sdkRuntime": {"supported": True},
    "countrySet": "synthetic_country_set",
    "ramBytes": "8589934592",
    "buildBrand": "synthetic brand",
    "buildDevice": "synthetic_product",
    "socManufacturer": "synthetic manufacturer",
    "socModel": "synthetic model",
}


def rich_device(**changes):
    return copy.deepcopy({**DEFAULT_DEVICE, **SUPPLEMENTARY, **changes})


def test_official_richer_shape_preserves_four_dimension_selection_and_explains_normalization():
    raw, paths = split_toc()
    minimal = select_apks(raw, DEFAULT_DEVICE, ("toc.pb", *paths))
    richer = select_apks(raw, rich_device(), ("toc.pb", *paths))
    assert richer.selected_apks == minimal.selected_apks
    assert richer.device_spec.as_dict() == minimal.device_spec.as_dict() == DEFAULT_DEVICE
    provenance = richer.as_dict()["device_spec_normalization"]
    assert provenance == {
        "schema": "bundletool-1.18.3",
        "selection_dimensions": list(selection.DEVICE_SPEC_DIMENSIONS),
        "validated_supplementary_fields_not_used_for_selection": sorted(SUPPLEMENTARY),
        "unsupported_toc_targeting": "rejected",
    }
    report = json.dumps(richer.as_dict())
    assert all(
        value not in report
        for value in (
            "synthetic brand",
            "synthetic_product",
            "synthetic manufacturer",
            "synthetic model",
            "android.hardware.camera",
            "GL_KHR_texture_compression_astc_ldr",
            "synthetic_group",
        )
    )
    assert "synthetic_product" not in repr(richer.device_spec)


def test_metadata_is_canonical_immutable_and_not_silently_discarded_in_memory():
    original = rich_device()
    expected = DeviceSpec.from_dict(original)
    reordered = dict(reversed(list(original.items())))
    reordered["deviceFeatures"] = list(reversed(original["deviceFeatures"]))
    reordered["ramBytes"] = 8589934592
    assert DeviceSpec.from_dict(reordered) == expected
    original["deviceFeatures"].append("android.hardware.synthetic_new")
    original["sdkRuntime"]["supported"] = False
    assert DeviceSpec.from_dict(original) != expected
    assert expected.as_dict() == DEFAULT_DEVICE
    assert (
        DeviceSpec.from_dict(DEFAULT_DEVICE).normalization_provenance()[
            "validated_supplementary_fields_not_used_for_selection"
        ]
        == []
    )


def test_normalization_preserves_supplementary_provenance_across_serialized_options(tmp_path):
    from mobile_audit.run_options import artifact_options

    raw, paths = split_toc()
    original = rich_device(ramBytes=8589934592)
    normalized, policy = artifact_options(tmp_path / "new-synthetic.apks", original)
    assert policy is None
    assert normalized is not None
    assert normalized["ramBytes"] == "8589934592"
    assert normalized["deviceFeatures"] == sorted(original["deviceFeatures"])
    submitted = json.loads(json.dumps(normalized))
    repeated, _ = artifact_options(tmp_path / "new-synthetic.apks", submitted)
    assert repeated is not None
    assert repeated == normalized
    result = select_apks(raw, repeated, ("toc.pb", *paths))
    assert result.as_dict()["device_spec"] == DEFAULT_DEVICE
    assert result.as_dict()["device_spec_normalization"][
        "validated_supplementary_fields_not_used_for_selection"
    ] == sorted(SUPPLEMENTARY)
    assert "synthetic_product" not in json.dumps(result.as_dict())


@pytest.mark.parametrize(
    "supplement",
    [
        {"deviceFeatures": []},
        {"glExtensions": []},
        {"deviceGroups": []},
        {"codename": ""},
        {"codename": "REL"},
        {"sdkRuntime": {}},
        {"sdkRuntime": {"supported": False}},
        {"deviceTier": (1 << 31) - 1},
        {"ramBytes": 0},
        {"ramBytes": "0"},
        {"ramBytes": str((1 << 63) - 1)},
        {"countrySet": ""},
        {"buildBrand": ""},
        {"socModel": "synthetic model"},
        {"buildDevice": "x" * 256},
    ],
)
def test_supported_supplementary_defaults_and_numeric_bounds(supplement):
    assert DeviceSpec.from_dict({**DEFAULT_DEVICE, **supplement}).as_dict() == DEFAULT_DEVICE


@pytest.mark.parametrize(
    "name,limit", [("deviceFeatures", 1024), ("glExtensions", 1024), ("deviceGroups", 128)]
)
def test_supplementary_array_cardinality_bounds_are_inclusive(name, limit):
    spec = DeviceSpec.from_dict({**DEFAULT_DEVICE, name: [f"synthetic_{i}" for i in range(limit)]})
    assert len(spec.as_input_dict()[name]) == limit


@pytest.mark.parametrize(
    "change",
    [
        {"deviceId": "synthetic_serial"},
        {"densityAlias": "XXHDPI"},
        {"futureField": []},
        {"codename": "Preview"},
        {"codename": None},
        {"codename": 34},
        {"deviceFeatures": "android.hardware.camera"},
        {"deviceFeatures": [1]},
        {"deviceFeatures": ["android.hardware.camera"] * 2},
        {"deviceFeatures": ["bad token"]},
        {"deviceFeatures": ["x" * 257]},
        {"deviceFeatures": [f"feature_{i}" for i in range(1025)]},
        {"glExtensions": [None]},
        {"glExtensions": ["GL_EXT_x", "GL_EXT_x"]},
        {"glExtensions": [f"GL_EXT_{i}" for i in range(1025)]},
        {"deviceGroups": ["group", "group"]},
        {"deviceGroups": [f"group_{i}" for i in range(129)]},
        {"deviceTier": True},
        {"deviceTier": -1},
        {"deviceTier": 1 << 31},
        {"deviceTier": "0"},
        {"sdkRuntime": None},
        {"sdkRuntime": []},
        {"sdkRuntime": {"supported": 1}},
        {"sdkRuntime": {"supported": "true"}},
        {"sdkRuntime": {"supported": True, "future": False}},
        {"countrySet": {"value": "synthetic"}},
        {"countrySet": None},
        {"ramBytes": True},
        {"ramBytes": -1},
        {"ramBytes": 1 << 63},
        {"ramBytes": 1.0},
        {"ramBytes": "-1"},
        {"ramBytes": "+1"},
        {"ramBytes": "01"},
        {"ramBytes": "1e6"},
        {"ramBytes": str(1 << 63)},
        {"ramBytes": "9" * 10000},
        {"buildBrand": "x" * 257},
        {"buildDevice": "bad\nvalue"},
        {"socModel": "bad\u202evalue"},
        {"socManufacturer": 5},
        {"supportedAbis": ["x86", "x86"]},
        {"supportedLocales": ["en-US", "EN-us"]},
    ],
)
def test_invalid_and_unknown_supplementary_fields_fail_closed(change):
    with pytest.raises(ApkSetSelectionError) as error:
        DeviceSpec.from_dict({**DEFAULT_DEVICE, **change})
    assert error.value.code == "invalid_device_spec"


@pytest.mark.parametrize("target_field", [6, 7, 8, 9, 10, 11])
def test_richer_capabilities_do_not_enable_unsupported_apk_targeting(target_field):
    raw = toc([variant([module([description("base.apk", field(target_field, b""), master=True)])])])
    with pytest.raises(ApkSetSelectionError) as error:
        select_apks(raw, rich_device(), ("toc.pb", "base.apk"))
    assert error.value.code == "unsupported_toc"


def test_richer_capabilities_do_not_enable_module_or_device_group_targeting():
    for raw in (
        toc(
            [
                variant(
                    [module([description("base.apk", master=True)], metadata_extra=field(5, field(1, b"")))]
                )
            ]
        ),
        toc([variant([module([description("base.apk", master=True)])])], extra=field(9, b"")),
    ):
        with pytest.raises(ApkSetSelectionError) as error:
            select_apks(raw, rich_device(), ("toc.pb", "base.apk"))
        assert error.value.code == "unsupported_toc"


def test_typed_device_spec_supplementary_validation_cannot_be_bypassed():
    spec = DeviceSpec.from_dict(DEFAULT_DEVICE)
    for supplementary in (
        [("codename", "REL")],
        (("future", "value"),),
        (("codename", "Preview"),),
        (("codename", "REL"), ("codename", "REL")),
        (("deviceFeatures", ["android.hardware.camera"]),),
        (("deviceFeatures", ("z", "a")),),
        (("sdkRuntime", 1),),
    ):
        with pytest.raises(ApkSetSelectionError):
            replace(spec, _supplementary=supplementary)


def test_strict_reader_roundtrips_new_synthetic_bundletool_json(tmp_path):
    value = rich_device()
    raw = json.dumps(value).encode()
    assert parse_device_spec_json(raw) == value
    path = tmp_path / "new-device-spec.json"
    path.write_bytes(raw)
    assert read_device_spec(path) == value


@pytest.mark.parametrize(
    "extra",
    [
        '"sdkVersion":34',
        '"deviceFeatures":[],"deviceFeatures":[]',
        '"ramBytes":"0","ramBytes":"1"',
        '"sdkRuntime":{"supported":false,"supported":true}',
        '"sdk\\u0056ersion":34',
    ],
)
def test_raw_duplicate_json_keys_are_rejected_at_all_levels(extra):
    raw = json.dumps(DEFAULT_DEVICE)[:-1] + "," + extra + "}"
    with pytest.raises(ApkSetSelectionError) as error:
        parse_device_spec_json(raw.encode())
    assert error.value.code == "invalid_device_spec"


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b"null",
        b"{}",
        b"true",
        b"\xff",
        b"{",
        b"{} {}",
        b"\xef\xbb\xbf{}",
        b'{"sdkVersion":NaN}',
        b'{"sdkVersion":Infinity}',
        b'{"sdkVersion":-Infinity}',
        b"[" * 2000 + b"]" * 2000,
    ],
)
def test_malformed_raw_device_json_fails_closed(raw):
    with pytest.raises(ApkSetSelectionError) as error:
        parse_device_spec_json(raw)
    assert error.value.code == "invalid_device_spec"


def test_reader_byte_budget_and_regular_file_checks(tmp_path, monkeypatch):
    monkeypatch.setattr(selection, "MAX_DEVICE_SPEC_BYTES", 128)
    path = tmp_path / "new-oversized-spec.json"
    path.write_bytes(b" " * 129)
    for operation in (
        lambda: parse_device_spec_json(path.read_bytes()),
        lambda: read_device_spec(path),
        lambda: read_device_spec(tmp_path),
    ):
        with pytest.raises(ApkSetSelectionError) as error:
            operation()
        assert error.value.code == "invalid_device_spec"


def test_reader_refuses_new_synthetic_symlink_and_missing_file(tmp_path):
    path = tmp_path / "new-spec.json"
    path.write_text(json.dumps(DEFAULT_DEVICE))
    link = tmp_path / "new-spec-link.json"
    link.symlink_to(path)
    for candidate in (link, tmp_path / "new-missing.json"):
        with pytest.raises(ApkSetSelectionError) as error:
            read_device_spec(candidate)
        assert error.value.code == "invalid_device_spec"


@pytest.mark.parametrize("background", [False, True])
def test_cli_strict_reader_rejects_duplicate_before_scanning_or_starting_job(
    tmp_path, monkeypatch, background, store
):
    from mobile_audit import cli

    path = tmp_path / "new-duplicate-spec.json"
    path.write_text(json.dumps(DEFAULT_DEVICE)[:-1] + ',"sdkVersion":34}')
    calls = []
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: calls.append("scan"))
    monkeypatch.setattr(cli.jobs, "start", lambda *args, **kwargs: calls.append("start"))
    args = ["scan", str(tmp_path / "new-synthetic.apks"), "--apk-set-device", str(path)]
    if background:
        args.append("--background")
    with pytest.raises(ApkSetSelectionError):
        cli.dispatch(cli.parser().parse_args(args), store)
    assert calls == []
