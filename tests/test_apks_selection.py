from __future__ import annotations

import io
import random
import zipfile
from dataclasses import replace
from xml.etree import ElementTree

import pytest

from mobile_audit import apks_selection as selection
from mobile_audit.apks_selection import ApkSetSelectionError, DeviceSpec, select_apks
from tests.apks_fixture import (
    DEFAULT_DEVICE,
    DEFAULT_PATHS,
    description,
    dimension,
    field,
    module,
    split_toc,
    targeting,
    toc,
    variant,
    write_split_apks,
)


def select(raw, paths, device=None):
    return select_apks(raw, DEFAULT_DEVICE if device is None else device, ("toc.pb", *paths))


def single(*, target=b"", master=True, **kwargs):
    return toc([variant([module([description("splits/base.apk", target, master=master, **kwargs)])])])


def test_selection_explicit_metadata_and_vulnerable_split(tmp_path):
    path = tmp_path / "new-synthetic.apks"
    raw, paths = write_split_apks(path)
    result = select(raw, paths)
    assert [apk.path for apk in result.selected_apks] == [DEFAULT_PATHS[i] for i in (0, 1, 4, 5)]
    assert result.selected_apks[1].module_name == "base"
    assert result.selected_apks[1].targeting.abi.values == ("arm64-v8a",)
    assert result.selected_apks[0].split_id == ""
    assert result.as_dict()["device_spec"] == DEFAULT_DEVICE
    assert result.as_dict()["installability_verified"] is False
    assert result.as_dict()["toc_sha256"] and result.warnings
    with zipfile.ZipFile(path) as archive:

        def selected_text(device):
            values = []
            for apk in select(raw, paths, device).selected_apks:
                with zipfile.ZipFile(io.BytesIO(archive.read(apk.path))) as inner:
                    manifest = ElementTree.fromstring(inner.read("AndroidManifest.xml"))
                    assert manifest.attrib["package"] == "org.synthetic.apks"
                    assert manifest.attrib["{http://schemas.android.com/apk/res/android}versionCode"] == "1"
                    assert manifest.get("split", "") == apk.split_id
                    if not apk.is_master_split:
                        assert manifest.find("application") is None
                    values.append(inner.read("assets/synthetic.txt"))
            return b" ".join(values)

        assert b"http://synthetic.invalid" in selected_text(DEFAULT_DEVICE)
        neutral = {
            **DEFAULT_DEVICE,
            "supportedAbis": ["x86"],
            "screenDensity": 240,
            "supportedLocales": ["ko-KR"],
        }
        assert b"http://synthetic.invalid" not in selected_text(neutral)


def test_ordered_abi_preference():
    raw, paths = split_toc()
    result = select(raw, paths, {**DEFAULT_DEVICE, "supportedAbis": ["x86", "arm64-v8a"]})
    assert DEFAULT_PATHS[2] in [apk.path for apk in result.selected_apks]
    assert DEFAULT_PATHS[1] not in [apk.path for apk in result.selected_apks]


@pytest.mark.parametrize("dpi, expected", [(240, 240), (300, 480), (480, 480), (200, 240), (600, 480)])
def test_density_uses_android_scaling_preference(dpi, expected):
    raw, paths = split_toc()
    result = select(raw, paths, {**DEFAULT_DEVICE, "screenDensity": dpi})
    offered = [
        apk.targeting.density.values[0] for apk in result.selected_apks if apk.targeting.density.values
    ]
    assert offered == [expected]


def test_density_alias_matches_explicit_dpi():
    raw = single(target=field(4, field(1, field(1, 7))))
    assert select(raw, ["splits/base.apk"]).selected_apks


def test_multiple_languages_and_fallback():
    raw, paths = split_toc()
    fallback = "splits/base-fallback.apk"
    # Generate an independent language group with complete alternatives.
    apks = [
        description("splits/base.apk", master=True),
        description("splits/en.apk", targeting(language=(("en",), ("ko",)))),
        description("splits/ko.apk", targeting(language=(("ko",), ("en",)))),
        description(fallback, targeting(language=((), ("en", "ko")))),
    ]
    raw = toc([variant([module(apks)])])
    paths = ["splits/base.apk", "splits/en.apk", "splits/ko.apk", fallback]
    result = select(raw, paths, {**DEFAULT_DEVICE, "supportedLocales": ["en-US", "ko-KR"]})
    assert {apk.path for apk in result.selected_apks} == set(paths) - {fallback}
    result = select(raw, paths, {**DEFAULT_DEVICE, "supportedLocales": ["en-US", "fr-FR"]})
    assert {apk.path for apk in result.selected_apks} == {paths[0], paths[1], fallback}


@pytest.mark.parametrize("modern,legacy", [("he-IL", "iw"), ("id-ID", "in"), ("yi", "ji")])
def test_android_legacy_language_names(modern, legacy):
    raw = single(target=targeting(language=((legacy,), ())))
    assert select(raw, ["splits/base.apk"], {**DEFAULT_DEVICE, "supportedLocales": [modern]}).selected_apks


def test_sdk_alternatives_choose_variant_without_merging():
    low = description("standalones/low.apk", standalone=True)
    high = description("splits/high.apk", master=True)
    raw = toc(
        [
            variant([module([low])], targeting(variant=True, sdk=((1,), (21,))), number=0),
            variant([module([high])], targeting(variant=True, sdk=((21,), (1,))), number=1),
        ]
    )
    paths = ["standalones/low.apk", "splits/high.apk"]
    assert select(raw, paths).selected_apks[0].path == paths[1]
    result = select(raw, paths, {**DEFAULT_DEVICE, "sdkVersion": 19})
    assert result.selected_apks[0].path == paths[0]
    assert result.selected_apks[0].fused_modules == ("base",)


def test_sdk_alternatives_choose_master():
    apks = [
        description("splits/low.apk", targeting(sdk=((21,), (30,))), master=True),
        description("splits/high.apk", targeting(sdk=((30,), (21,))), master=True),
    ]
    raw = toc([variant([module(apks)])])
    assert select(raw, ["splits/low.apk", "splits/high.apk"]).selected_apks[0].path == "splits/high.apk"


def test_install_time_feature_dependencies_preserved():
    raw = toc(
        [
            variant(
                [
                    module([description("base.apk", master=True)]),
                    module([description("feature.apk", master=True)], "feature", ("base",)),
                ]
            )
        ]
    )
    result = select(raw, ["base.apk", "feature.apk"])
    assert result.selected_apks[1].dependencies == ("base",)


@pytest.mark.parametrize(
    "change",
    [
        {"sdkVersion": 0},
        {"sdkVersion": True},
        {"sdkVersion": 10000},
        {"screenDensity": 0},
        {"supportedAbis": []},
        {"supportedAbis": ["future"]},
        {"supportedAbis": ["x86", "x86"]},
        {"supportedLocales": []},
        {"supportedLocales": ["en_US"]},
        {"supportedLocales": ["en-US", "EN-us"]},
        {"supportedLocales": "en-US"},
        {"codename": "Preview"},
        {"sdkVersion": "34"},
    ],
)
def test_invalid_device_specs_fail_closed(change):
    with pytest.raises(ApkSetSelectionError) as error:
        select(single(), ["splits/base.apk"], {**DEFAULT_DEVICE, **change})
    assert error.value.code == "invalid_device_spec"


def test_missing_explicit_device_dimension_and_typed_validation():
    with pytest.raises(ApkSetSelectionError):
        DeviceSpec.from_dict({"sdkVersion": 34})
    with pytest.raises(ApkSetSelectionError):
        DeviceSpec(34, ("x86",), 320, ())
    spec = DeviceSpec.from_dict(DEFAULT_DEVICE)
    assert select(single(), ["splits/base.apk"], spec).device_spec == spec
    with pytest.raises(ApkSetSelectionError):
        replace(spec, sdk_version=-1)


@pytest.mark.parametrize(
    "raw",
    [
        b"\x80",
        b"\x0a\x02\x01",
        b"\x00",
        b"\x0b",
        b"\x8a\x00\x00",
        field(1, b"") + field(4, "org.x") + field(4, "org.y"),
    ],
)
def test_malformed_protobuf_fails_closed(raw):
    with pytest.raises(ApkSetSelectionError):
        select(raw, ["splits/base.apk"])


@pytest.mark.parametrize(
    "target",
    [
        field(6, b""),
        field(7, b""),
        field(8, b""),
        field(11, b""),
        field(1, dimension("abi", (99,), ())),
        field(4, field(1, field(1, 1))),
        field(4, field(1, field(1, 0))),
        targeting(sdk=((10000,), ())),
    ],
)
def test_unknown_or_unsupported_targeting_fails_closed(target):
    with pytest.raises(ApkSetSelectionError) as error:
        select(single(target=target), ["splits/base.apk"])
    assert error.value.code == "unsupported_toc"


@pytest.mark.parametrize("extra", [field(3, b""), field(6, b""), field(7, b""), field(9, b"")])
def test_asset_default_localtesting_device_group_top_metadata_rejected(extra):
    with pytest.raises(ApkSetSelectionError) as error:
        select(single() + extra, ["splits/base.apk"])
    assert error.value.code == "unsupported_toc"


@pytest.mark.parametrize("local", [b"", field(1, 0), field(2, ""), field(1, 0) + field(2, "")])
def test_disabled_local_testing_and_empty_module_targeting_have_no_selection_effect(local):
    # Synthetic encoding of the empty messages unconditionally emitted by the
    # official 1.18.3 serializer. Remote real build/extract remains the oracle.
    raw = toc(
        [variant([module([description("base.apk", master=True)], metadata_extra=field(5, b""))])],
        extra=field(5, local),
    )
    result = select(raw, ["base.apk"])
    assert [apk.path for apk in result.selected_apks] == ["base.apk"]


@pytest.mark.parametrize("local", [field(1, 1), field(2, "new-local-test"), field(3, b"")])
def test_active_path_or_unknown_local_testing_metadata_stays_unsupported(local):
    with pytest.raises(ApkSetSelectionError) as error:
        select(single() + field(5, local), ["splits/base.apk"])
    assert error.value.code == "unsupported_toc"


@pytest.mark.parametrize("local", [field(1, 2), field(1, b""), field(1, 0) * 2, field(2, 0)])
def test_malformed_disabled_local_testing_metadata_fails_closed(local):
    with pytest.raises(ApkSetSelectionError) as error:
        select(single() + field(5, local), ["splits/base.apk"])
    assert error.value.code == "malformed_toc"


@pytest.mark.parametrize(
    "condition", [field(1, b""), field(2, b""), field(3, b""), field(5, b""), field(99, b"")]
)
def test_populated_module_targeting_is_unsupported_even_if_condition_is_empty(condition):
    raw = toc([variant([module([description("base.apk", master=True)], metadata_extra=field(5, condition))])])
    with pytest.raises(ApkSetSelectionError) as error:
        select(raw, ["base.apk"])
    assert error.value.code == "unsupported_toc"


@pytest.mark.parametrize("extra", [field(5, b"") * 2, field(5, 0)])
def test_duplicate_or_mistyped_empty_module_targeting_fails_closed(extra):
    raw = toc([variant([module([description("base.apk", master=True)], metadata_extra=extra)])])
    with pytest.raises(ApkSetSelectionError) as error:
        select(raw, ["base.apk"])
    assert error.value.code == "malformed_toc"


@pytest.mark.parametrize(
    "extra", [field(2, 1), field(3, 1), field(5, field(1, b"")), field(8, b""), field(9, b"")]
)
def test_unsupported_module_delivery_rejected(extra):
    raw = toc([variant([module([description("base.apk", master=True)], metadata_extra=extra)])])
    with pytest.raises(ApkSetSelectionError) as error:
        select(raw, ["base.apk"])
    assert error.value.code == "unsupported_toc"


@pytest.mark.parametrize("delivery", [0, 2, 3, 99])
def test_unknown_on_demand_fast_follow_delivery_rejected(delivery):
    raw = toc([variant([module([description("base.apk", master=True)], delivery=delivery)])])
    with pytest.raises(ApkSetSelectionError):
        select(raw, ["base.apk"])


@pytest.mark.parametrize("extra", [field(5, b""), field(6, b""), field(7, b""), field(8, b""), field(9, b"")])
def test_instant_system_asset_apex_archived_apks_rejected(extra):
    with pytest.raises(ApkSetSelectionError):
        select(single(description_extra=extra), ["splits/base.apk"])


def test_multiple_matching_variants_and_duplicate_variant_numbers_rejected():
    one = variant([module([description("one.apk", master=True)])])
    two = variant([module([description("two.apk", master=True)])], number=1)
    with pytest.raises(ApkSetSelectionError, match="Multiple TOC variants"):
        select(toc([one, two]), ["one.apk", "two.apk"])
    with pytest.raises(ApkSetSelectionError, match="variant number"):
        select(toc([one, one]), ["one.apk"])


def test_no_matching_variant_and_required_abi_config():
    raw = toc(
        [variant([module([description("base.apk", master=True)])], targeting(variant=True, sdk=((35,), ())))]
    )
    with pytest.raises(ApkSetSelectionError) as error:
        select(raw, ["base.apk"])
    assert error.value.code == "no_matching_variant"
    raw, paths = split_toc()
    with pytest.raises(ApkSetSelectionError) as error:
        select(raw, paths, {**DEFAULT_DEVICE, "supportedAbis": ["riscv64"]})
    assert error.value.code == "no_matching_apks"


def test_unsupported_unselected_variant_is_not_silently_ignored():
    supported = variant([module([description("base.apk", master=True)])])
    unsupported = variant(
        [module([description("future.apk", field(11, b""), master=True)])],
        targeting(variant=True, sdk=((99,), ())),
        number=1,
    )
    with pytest.raises(ApkSetSelectionError) as error:
        select(toc([supported, unsupported]), ["base.apk", "future.apk"])
    assert error.value.code == "unsupported_toc"


def test_default_abi_fallback_selects_when_no_alternatives_match():
    apks = [
        description("base.apk", master=True),
        description("arm.apk", targeting(abi=((3,), ()))),
        description("fallback.apk", targeting(abi=((), (3,)))),
    ]
    raw = toc([variant([module(apks)])])
    result = select(
        raw, ["base.apk", "arm.apk", "fallback.apk"], {**DEFAULT_DEVICE, "supportedAbis": ["x86"]}
    )
    assert [apk.path for apk in result.selected_apks] == ["base.apk", "fallback.apk"]


@pytest.mark.parametrize(
    "target",
    [
        targeting(abi=((3,), (3,))),
        targeting(abi=((3, 3), ())),
        targeting(sdk=((21, 30), ())),
        field(4, field(1, field(1, 7) + field(2, 480))),
    ],
)
def test_malformed_targeting_rejected(target):
    with pytest.raises(ApkSetSelectionError) as error:
        select(single(target=target), ["splits/base.apk"])
    assert error.value.code == "malformed_toc"


def test_missing_ambiguous_inconsistent_selector_groups_fail():
    for paths, apks, message in (
        (
            ["base.apk", "other.apk"],
            [description("base.apk", master=True), description("other.apk", master=True)],
            "master split",
        ),
        (
            ["base.apk", "arm.apk"],
            [description("base.apk", master=True), description("arm.apk", targeting(abi=((3,), (4,))))],
            "no corresponding",
        ),
        (
            ["base.apk", "arm.apk", "x86.apk"],
            [
                description("base.apk", master=True),
                description("arm.apk", targeting(abi=((3,), (4,)))),
                description("x86.apk", targeting(abi=((4,), (5,)))),
            ],
            "Inconsistent",
        ),
        (
            ["base.apk", "arm.apk", "arm2.apk"],
            [
                description("base.apk", master=True),
                description("arm.apk", targeting(abi=((3,), ()))),
                description("arm2.apk", targeting(abi=((3,), ()))),
            ],
            "Overlapping",
        ),
    ):
        raw = toc([variant([module(apks)])])
        with pytest.raises(ApkSetSelectionError, match=message):
            select(raw, paths)


def test_config_split_requires_modeled_single_dimension():
    for target in (b"", targeting(abi=((3,), ()), density=((480,), ()))):
        with pytest.raises(ApkSetSelectionError, match="must have one selector"):
            select(single(target=target, master=False), ["splits/base.apk"])


def test_shared_sdk_guard_is_an_and_constraint_not_a_required_sdk_config():
    sdk = ((21,), ())
    paths = ["base.apk", "hdpi.apk", "xhdpi.apk", "fr.apk"]
    apks = [
        description(paths[0], targeting(sdk=sdk), master=True),
        description(paths[1], targeting(sdk=sdk, density=((240,), (320,)))),
        description(paths[2], targeting(sdk=sdk, density=((320,), (240,)))),
        description(paths[3], targeting(sdk=sdk, language=(("fr",), ()))),
    ]
    raw = toc([variant([module(apks)])])
    cases = [(240, ["en-US"], [0, 1]), (320, ["fr-FR"], [0, 2, 3]), (213, ["en-US", "fr-FR"], [0, 1, 3])]
    for density, locales, selected_indices in cases:
        result = select(raw, paths, {**DEFAULT_DEVICE, "screenDensity": density, "supportedLocales": locales})
        assert [apk.path for apk in result.selected_apks] == [paths[i] for i in selected_indices]
        assert all(apk.targeting.sdk.values == (21,) for apk in result.selected_apks)
    with pytest.raises(ApkSetSelectionError) as error:
        select(raw, paths, {**DEFAULT_DEVICE, "sdkVersion": 19})
    assert error.value.code == "no_matching_apks"


@pytest.mark.parametrize("sdk", [((20,), ()), ((), (21,)), ((21,), (30,))])
def test_compound_config_sdk_guard_requires_single_released_split_minimum(sdk):
    target = targeting(sdk=sdk, density=((240,), ()))
    with pytest.raises(ApkSetSelectionError) as error:
        select(single(target=target, master=False), ["splits/base.apk"])
    assert error.value.code == "unsupported_toc"


@pytest.mark.parametrize("master_sdk", [None, ((30,), ()), ((21,), (30,))])
def test_config_sdk_guard_must_equal_its_module_master_sdk(master_sdk):
    master_target = b"" if master_sdk is None else targeting(sdk=master_sdk)
    apks = [
        description("base.apk", master_target, master=True),
        description("hdpi.apk", targeting(sdk=((21,), ()), density=((240,), ()))),
    ]
    with pytest.raises(ApkSetSelectionError, match="must match every master"):
        select(toc([variant([module(apks)])]), ["base.apk", "hdpi.apk"])


def test_shared_sdk_guard_does_not_allow_compound_config_selectors_or_unknown_targeting():
    for target in (
        targeting(sdk=((21,), ()), abi=((3,), ()), density=((240,), ())),
        targeting(sdk=((21,), ()), language=(("fr",), ())) + field(11, b""),
    ):
        with pytest.raises(ApkSetSelectionError) as error:
            select(single(target=target, master=False), ["splits/base.apk"])
        assert error.value.code == "unsupported_toc"


def test_shared_sdk_guards_preserve_density_sibling_completeness():
    sdk = ((21,), ())
    apks = [
        description("base.apk", targeting(sdk=sdk), master=True),
        description("hdpi.apk", targeting(sdk=sdk, density=((240,), (320,)))),
    ]
    with pytest.raises(ApkSetSelectionError, match="no corresponding sibling"):
        select(toc([variant([module(apks)])]), ["base.apk", "hdpi.apk"])


def test_standalone_requires_unique_match_and_fused_base():
    apks = [description("one.apk", standalone=True), description("two.apk", standalone=True)]
    with pytest.raises(ApkSetSelectionError, match="Multiple standalone"):
        select(toc([variant([module(apks)])]), ["one.apk", "two.apk"])
    raw = toc([variant([module([field(2, "one.apk") + field(4, field(1, "feature"))])])])
    with pytest.raises(ApkSetSelectionError, match="fused with base"):
        select(raw, ["one.apk"])


@pytest.mark.parametrize(
    "name",
    [
        "../evil.apk",
        "/evil.apk",
        "splits/../evil.apk",
        "splits//base.apk",
        "splits\\base.apk",
        "C:evil.apk",
        "splits/./base.apk",
        "evil\x00.apk",
        "e\u0301.apk",
        "evil\n.apk",
    ],
)
def test_unsafe_zip_and_toc_paths_rejected(name):
    with pytest.raises(ApkSetSelectionError):
        select(single(), ["splits/base.apk", name])
    raw = toc([variant([module([description(name, master=True)])])])
    with pytest.raises(ApkSetSelectionError):
        select(raw, ["splits/base.apk"])


def test_duplicate_collision_missing_unlisted_members_rejected():
    for names in (
        ["splits/base.apk", "splits/base.apk"],
        ["splits/base.apk", "SPLITS/BASE.apk"],
        ["splits/base.apk", "unlisted.apk"],
        [],
    ):
        with pytest.raises(ApkSetSelectionError):
            select(single(), names)
    with pytest.raises(ApkSetSelectionError, match="lacks toc.pb"):
        select_apks(single(), DEFAULT_DEVICE, ["splits/base.apk"])
    with pytest.raises(ApkSetSelectionError, match="parent directory"):
        select(single(), ["splits/base.apk", "splits"])
    with pytest.raises(ApkSetSelectionError):
        select(single(), ["splits/base.apk", "bad\udfff"])


def test_duplicate_singular_fields_and_oneofs_rejected():
    for raw in (
        single(description_extra=field(2, "duplicate.apk")),
        single(description_extra=field(4, field(1, "base"))),
        single(metadata_extra=field(2, 1)),
        single(metadata_extra=field(2, 2)),
    ):
        with pytest.raises(ApkSetSelectionError):
            select(raw, ["splits/base.apk", "duplicate.apk"])


def test_missing_cycle_self_module_dependencies_rejected():
    for dependencies in (("missing",), ("feature",)):
        raw = toc(
            [
                variant(
                    [
                        module([description("base.apk", master=True)]),
                        module([description("feature.apk", master=True)], "feature", dependencies),
                    ]
                )
            ]
        )
        with pytest.raises(ApkSetSelectionError):
            select(raw, ["base.apk", "feature.apk"])
    raw = toc(
        [
            variant(
                [
                    module([description("base.apk", master=True)]),
                    module([description("a.apk", master=True)], "a", ("b",)),
                    module([description("b.apk", master=True)], "b", ("a",)),
                ]
            )
        ]
    )
    with pytest.raises(ApkSetSelectionError, match="Cyclic"):
        select(raw, ["base.apk", "a.apk", "b.apk"])


@pytest.mark.parametrize(
    "constant,value",
    [
        ("MAX_TOC_BYTES", 2),
        ("MAX_FIELDS", 2),
        ("MAX_MEMBERS", 1),
        ("MAX_APKS", 1),
        ("MAX_VARIANTS", 0),
        ("MAX_MODULES", 0),
        ("MAX_TARGET_VALUES", 1),
    ],
)
def test_budgets_fail_closed(monkeypatch, constant, value):
    monkeypatch.setattr(selection, constant, value)
    raw, paths = split_toc()
    with pytest.raises(ApkSetSelectionError) as error:
        select(raw, paths)
    assert error.value.code == "budget_exceeded"


def test_empty_toc_and_bounded_lazy_member_iterable():
    with pytest.raises(ApkSetSelectionError):
        select(b"", [])
    with pytest.raises(ApkSetSelectionError) as error:
        select_apks(single(), DEFAULT_DEVICE, (f"safe-{i}" for i in range(selection.MAX_MEMBERS + 1)))
    assert error.value.code == "budget_exceeded"


def test_bounded_random_malformed_inputs_have_typed_nonselecting_results():
    generator = random.Random(112358)
    for size in range(1, 512):
        raw = generator.randbytes(size)
        with pytest.raises(ApkSetSelectionError):
            select(raw, ["splits/base.apk"])
