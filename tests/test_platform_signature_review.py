"""Fresh synthetic regressions for platform-configuration and resource-seal review defects."""

from __future__ import annotations

import hashlib
import io
import plistlib
import random
import re
import struct
import time
import zipfile
from pathlib import Path

import pytest

from mobile_audit import quaygate_analysis
from mobile_audit.audit import scan
from mobile_audit.binary_analysis import analyze_binary
from mobile_audit.ipa_resource_seal import verify_resource_seal
from mobile_audit.platform_checks import _masked_code, _sub_tokens, exposed_providers, platform_checks
from quaygate.apk import Apk
from quaygate.appchecks import audit_apk
from quaygate.axml import parse_axml
from quaygate.checks import INFO, LOW, MEDIUM
from quaygate.ipa import Ipa, audit_ipa
from quaygate.network_security import analyze
from tests.helpers import build_ipa, build_macho, make_plist, temp_apk, temp_ipa
from tests.test_ipa_trust import chain_fixture as synthetic_chain_fixture
from tests.test_ipa_trust import directory_fixture

chain_fixture = synthetic_chain_fixture


def by_rule(report: dict, rule: str) -> list[dict]:
    return [item for item in report["findings"] if item["rule_id"] == rule]


def coverage(report: dict, rule: str) -> dict:
    return next(item for item in report["coverage"] if item["rule_id"] == rule)


def checks(findings, check_id: str) -> list[tuple[str, str | None]]:
    return [(item.status, item.severity) for item in findings if item.check_id == check_id]


# --- Info.plist must be sealed before signed resources are verified ---------------------------

INFO_PLIST = plistlib.dumps({"CFBundleIdentifier": "synthetic.test", "CFBundleExecutable": "App"})
TAMPERED_INFO = plistlib.dumps(
    {
        "CFBundleIdentifier": "synthetic.test",
        "CFBundleExecutable": "App",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
    }
)


def signed_app(chain, tmp_path, *, slots=(1, 3), on_disk=INFO_PLIST, envelope_seals_info=False) -> dict:
    _, _, policy, scratch, run = chain
    files = {"asset": {"hash2": hashlib.sha256(b"asset").digest()}}
    if envelope_seals_info:
        files["Info.plist"] = {"hash2": hashlib.sha256(INFO_PLIST).digest()}
    envelope = plistlib.dumps({"files2": files, "rules2": {"^.*": True}})
    unsigned = bytearray(4096)
    struct.pack_into("<IiiIIIII", unsigned, 0, 0xFEEDFACF, 0x100000C, 0, 2, 1, 16, 0x200000, 0)
    struct.pack_into("<IIII", unsigned, 32, 0x1D, 16, 4096, 16384)
    blobs = {1: INFO_PLIST, 3: envelope}
    directory = directory_fixture(bytes(unsigned), (0,), special={slot: blobs[slot] for slot in slots})
    content, cms = tmp_path / "directory.bin", tmp_path / "signature.der"
    content.write_bytes(directory)
    run(
        [
            "cms",
            "-sign",
            "-binary",
            "-in",
            str(content),
            "-signer",
            str(scratch / "leaf.pem"),
            "-inkey",
            str(scratch / "leaf.key"),
            "-certfile",
            str(scratch / "intermediate.pem"),
            "-outform",
            "DER",
            "-out",
            str(cms),
            "-md",
            "sha256",
        ]
    )
    wrapper = struct.pack(">II", 0xFADE0B01, len(cms.read_bytes()) + 8) + cms.read_bytes()
    length = 28 + len(directory) + len(wrapper)
    signature = (
        struct.pack(">IIIIIII", 0xFADE0CC0, length, 2, 0, 28, 0x10000, 28 + len(directory))
        + directory
        + wrapper
    )
    target = tmp_path / "synthetic.ipa"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", on_disk)
        archive.writestr("Payload/App.app/App", bytes(unsigned) + signature + bytes(16384 - len(signature)))
        archive.writestr("Payload/App.app/asset", b"asset")
        archive.writestr("Payload/App.app/_CodeSignature/CodeResources", envelope)
    result = analyze_binary(target, {"package": "synthetic.test", "ipa_trust_policy": policy})
    return result["metadata"]["apps"][0]


def test_unbound_modified_info_plist_never_verifies_signed_resources(chain_fixture, tmp_path):
    app = signed_app(chain_fixture, tmp_path, slots=(3,), on_disk=TAMPERED_INFO)
    signature = app["slices"][0]["code_signature"]
    assert signature["cryptographic_signature_verified"]
    assert signature["code_directories"][0]["info_plist_state"] == "not-sealed"
    seal = app["resource_seal"]
    assert seal["code_directory_bound"] is True
    assert seal["info_plist_seal"] == "unsealed" and seal["unsealed_files"] == 1
    assert seal["state"] == "modified"
    assert seal["signed_resources_verified"] is False


def test_bound_but_modified_info_plist_never_verifies_signed_resources(chain_fixture, tmp_path):
    app = signed_app(chain_fixture, tmp_path, on_disk=TAMPERED_INFO)
    assert app["slices"][0]["code_signature"]["code_directories"][0]["info_plist_state"] == "modified"
    seal = app["resource_seal"]
    assert seal["info_plist_seal"] == "unsealed" and seal["state"] == "modified"
    assert seal["signed_resources_verified"] is False


@pytest.mark.parametrize(
    "slots,envelope_seals_info,sealed_by",
    [((1, 3), False, "code-directory"), ((3,), True, "resource-envelope")],
)
def test_info_plist_sealed_by_directory_or_envelope_stays_verified(
    chain_fixture, tmp_path, slots, envelope_seals_info, sealed_by
):
    app = signed_app(chain_fixture, tmp_path, slots=slots, envelope_seals_info=envelope_seals_info)
    seal = app["resource_seal"]
    assert seal["info_plist_seal"] == sealed_by and seal["state"] == "consistent"
    assert seal["signed_resources_verified"] is True
    assert app["app_authenticity_verified"] is False


def test_envelope_sealed_info_plist_detects_modification_without_slot_one(chain_fixture, tmp_path):
    app = signed_app(chain_fixture, tmp_path, slots=(3,), on_disk=TAMPERED_INFO, envelope_seals_info=True)
    seal = app["resource_seal"]
    assert seal["modified_files"] == 1 and seal["state"] == "modified"
    assert seal["signed_resources_verified"] is False


def test_resource_seal_excludes_info_plist_only_when_bound():
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        archive.writestr("Payload/App.app/Info.plist", INFO_PLIST)
        archive.writestr("Payload/App.app/asset", b"asset")
    envelope = plistlib.dumps(
        {"files2": {"asset": {"hash2": hashlib.sha256(b"asset").digest()}}, "rules2": {"^.*": True}}
    )
    raw.seek(0)
    with zipfile.ZipFile(raw) as archive:
        unknown = verify_resource_seal(archive, "Payload/App.app", "App", envelope)
        bound = verify_resource_seal(archive, "Payload/App.app", "App", envelope, True)
    assert (unknown["state"], unknown["unsealed_files"], unknown["info_plist_seal"]) == (
        "modified",
        1,
        "unsealed",
    )
    assert (bound["state"], bound["unsealed_files"], bound["info_plist_seal"]) == (
        "consistent",
        0,
        "code-directory",
    )


# --- IPA ATS exception domains agree with a source Info.plist ---------------------------------

WEAK_ATS = {
    "NSExceptionDomains": {
        "legacy.example": {
            "NSIncludesSubdomains": True,
            "NSThirdPartyExceptionAllowsInsecureHTTPLoads": True,
        },
        "old-tls.example": {
            "NSExceptionMinimumTLSVersion": "TLSv1.0",
            "NSExceptionRequiresForwardSecrecy": False,
        },
        "modern.example": {"NSIncludesSubdomains": True, "NSExceptionMinimumTLSVersion": "TLSv1.2"},
    }
}
SAFE_ATS = {"NSExceptionDomains": {"modern.example": {"NSExceptionMinimumTLSVersion": "TLSv1.3"}}}


def test_quaygate_reports_every_weakening_exception_domain():
    with temp_ipa({"NSAppTransportSecurity": WEAK_ATS}) as path, Ipa(path) as archive:
        findings = audit_ipa(archive)[1]
    [domains] = [f for f in findings if f.check_id == "ipa-ats-domains"]
    assert (domains.status, domains.severity) == ("warn", LOW)
    assert "평문 허용 예외 도메인 1개: legacy.example" in domains.detail
    assert (
        "old-tls.example NSExceptionMinimumTLSVersion=TLSv1.0, NSExceptionRequiresForwardSecrecy=false"
        in (domains.detail)
    )
    assert "modern.example" not in domains.detail
    media = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoadsForMedia": True}}
    with temp_ipa(media) as path, Ipa(path) as archive:
        assert checks(audit_ipa(archive)[1], "ipa-ats-domains") == [("warn", LOW)]


@pytest.mark.parametrize(
    "ats",
    [
        SAFE_ATS,
        {"NSExceptionDomains": {"x.example": {"NSExceptionMinimumTLSVersion": ["TLSv1.0"]}}},
        {"NSExceptionDomains": {"x.example": {"NSExceptionRequiresForwardSecrecy": True}}},
    ],
)
def test_strict_or_unrecognized_exception_values_pass_in_both_engines(ats):
    with temp_ipa({"NSAppTransportSecurity": ats}) as path, Ipa(path) as archive:
        assert checks(audit_ipa(archive)[1], "ipa-ats-domains") == [("pass", None)]
    inventory = {"platforms": ["ios"], "ios_config": [{"path": "Info.plist", "ats": ats}], "warnings": []}
    findings, states = platform_checks(inventory, [])
    assert not [f for f in findings if f["rule_id"] == "IOS-ATS-EXCEPTION"]
    assert {c["rule_id"]: c["state"] for c in states}["IOS-ATS-EXCEPTION"] == "checked"


def test_packaged_ats_exception_domains_match_the_source_tree(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    ipa = tmp_path / "weak.ipa"
    build_ipa(str(ipa), make_plist({"NSAppTransportSecurity": WEAK_ATS}), build_macho())
    packaged = scan(store, ipa)
    source = tmp_path / "source"
    source.mkdir()
    (source / "Info.plist").write_bytes(plistlib.dumps(make_plist({"NSAppTransportSecurity": WEAK_ATS})))
    (source / "App.swift").write_text("import UIKit\n")
    [exception] = by_rule(scan(store, source), "IOS-ATS-EXCEPTION")
    flagged = {entry["domain"]: entry["reasons"] for entry in exception["evidence"]}
    assert flagged == {
        "legacy.example": ["NSThirdPartyExceptionAllowsInsecureHTTPLoads permits HTTP"],
        "old-tls.example": [
            "NSExceptionMinimumTLSVersion TLSv1.0",
            "NSExceptionRequiresForwardSecrecy disabled",
        ],
    }
    [lint] = by_rule(packaged, "QG-IPA-ATS-DOMAINS")
    details = " ".join(lint["evidence"][0]["details"])
    assert all(domain in details for domain in flagged) and "modern.example" not in details
    assert coverage(packaged, "QG-IPA-ATS-DOMAINS")["state"] == "checked"


# --- Providers without android:exported are exported by default up to targetSdk 16 -------------


def provider_inventory(target: str | None, exported: str = "unspecified", **extra) -> dict:
    inventory = {
        "input_kind": "source",
        "platforms": ["android"],
        "components": [
            {
                "name": "com.example.NotesProvider",
                "type": "provider",
                "exported": exported,
                "permission": "",
                "read_permission": "",
                "write_permission": "",
                "intent_filters": 0,
                "launcher": False,
                "path": "app/src/main/AndroidManifest.xml",
                **extra,
            }
        ],
        "android_config": [
            {
                "path": "app/src/main/AndroidManifest.xml",
                "debuggable": "false",
                "cleartext": "unspecified",
                "network_security_config": "",
                "allow_backup": "false",
            }
        ],
        "ios_config": [],
        "warnings": [],
    }
    if target is not None:
        inventory["android_sdk"] = {"min": "14", "target": target, "path": "app/src/main/AndroidManifest.xml"}
    return inventory


def exported_components(inventory: dict, sources=()) -> list[dict]:
    findings = platform_checks(inventory, list(sources))[0]
    return [f["evidence"][0] for f in findings if f["rule_id"] == "ANDROID-EXPORTED-COMPONENT"]


def test_source_provider_default_export_follows_target_sdk():
    [evidence] = exported_components(provider_inventory("16"))
    assert evidence["component"] == "com.example.NotesProvider" and evidence["implicit_export"] is True
    assert exposed_providers(provider_inventory("16")) == {"NotesProvider"}
    # Unknown targetSdk is treated as the platform default (exported).
    assert exposed_providers(provider_inventory(None)) == {"NotesProvider"}
    assert exported_components(provider_inventory(None))


def test_source_provider_private_by_default_from_target_17_or_protection():
    gradle = [("app/build.gradle", "android { defaultConfig { targetSdkVersion 30 } }\n")]
    assert not exported_components(provider_inventory("17"))
    assert exposed_providers(provider_inventory("17")) == set()
    assert exposed_providers(provider_inventory(None), gradle) == set()
    assert not exported_components(provider_inventory(None), gradle)
    assert not exported_components(provider_inventory("16", exported="false"))
    assert not exported_components(provider_inventory("16", permission="com.example.SIGNATURE"))


PROVIDER = [("provider", {"name": "com.example.P", "authorities": "com.example.p"}, [])]


def test_quaygate_provider_default_export_is_medium_below_target_17():
    with temp_apk(components=PROVIDER, sdk_over={"minSdkVersion": "14", "targetSdkVersion": "16"}) as path:
        findings = audit_apk(Apk(path))[1]
    [exported] = [f for f in findings if f.check_id == "app-exported"]
    assert (exported.status, exported.severity) == ("warn", MEDIUM) and "com.example.P" in exported.detail
    # targetSdkVersion absent: the platform uses minSdkVersion.
    with temp_apk(components=PROVIDER, sdk_over={"minSdkVersion": "14", "targetSdkVersion": None}) as path:
        assert checks(audit_apk(Apk(path))[1], "app-exported") == [("warn", MEDIUM)]
    granting = [
        ("provider", {"name": "com.example.P", "authorities": "x", "grantUriPermissions": "true"}, [])
    ]
    with temp_apk(components=granting, sdk_over={"minSdkVersion": "14", "targetSdkVersion": "16"}) as path:
        assert checks(audit_apk(Apk(path))[1], "app-provider-grant") == [("warn", MEDIUM)]


@pytest.mark.parametrize(
    "sdk,attrs",
    [
        ({"minSdkVersion": "14", "targetSdkVersion": "17"}, {}),
        ({"minSdkVersion": "14", "targetSdkVersion": "16"}, {"exported": "false"}),
        ({"minSdkVersion": "14", "targetSdkVersion": "16"}, {"permission": "com.example.SIGNATURE"}),
    ],
)
def test_quaygate_private_or_protected_provider_passes(sdk, attrs):
    components = [("provider", {"name": "com.example.P", "authorities": "com.example.p", **attrs}, [])]
    with temp_apk(components=components, sdk_over=sdk) as path:
        findings = audit_apk(Apk(path))[1]
    assert checks(findings, "app-exported") == [("pass", None)]
    assert checks(findings, "app-provider-grant") == [("pass", None)]


# --- Implicit intent-filter exports use the explicit-export severity and protection ------------


def service(**attrs):
    return [
        (
            "service",
            {"name": "com.example.S", **attrs},
            [("intent-filter", {}, [("action", {"name": "com.example.DO"}, [])])],
        )
    ]


def test_quaygate_implicit_export_below_target_31_is_medium():
    with temp_apk(components=service(), sdk_over={"targetSdkVersion": "30"}) as path:
        [exported] = [f for f in audit_apk(Apk(path))[1] if f.check_id == "app-exported"]
    assert (exported.status, exported.severity) == ("warn", MEDIUM) and "com.example.S" in exported.detail


def test_quaygate_permission_protected_implicit_export_passes():
    with temp_apk(
        components=service(permission="com.example.SIG"), sdk_over={"targetSdkVersion": "30"}
    ) as path:
        assert checks(audit_apk(Apk(path))[1], "app-exported") == [("pass", None)]
    # targetSdk 31+ rejects the manifest; an unprotected filter stays an informational note.
    with temp_apk(components=service(), sdk_over={"targetSdkVersion": "34"}) as path:
        assert checks(audit_apk(Apk(path))[1], "app-exported") == [("info", INFO)]
    with temp_apk(
        components=service(permission="com.example.SIG"), sdk_over={"targetSdkVersion": "34"}
    ) as path:
        assert checks(audit_apk(Apk(path))[1], "app-exported") == [("pass", None)]


# --- minSdk below 24 keeps the manifest cleartext setting for older devices --------------------

NSC_BLOCKING = [
    ("network-security-config", {}, [("base-config", {"cleartextTrafficPermitted": "false"}, [])])
]
NSC_REF = {"networkSecurityConfig": "@xml/network_security_config"}


def test_quaygate_manifest_cleartext_applies_below_min_sdk_24(tmp_path):
    app = {**NSC_REF, "usesCleartextTraffic": "true"}
    with temp_apk(app_over=app, sdk_over={"minSdkVersion": "21"}, nsc=NSC_BLOCKING) as path:
        assert ("warn", MEDIUM) in checks(audit_apk(Apk(path))[1], "app-cleartext")
        report = quaygate_analysis.analyze(Path(path).resolve())
    assert [f["severity"] for f in report["findings"] if f["rule_id"] == "QG-APP-CLEARTEXT"] == ["medium"]
    with temp_apk(app_over=app, sdk_over={"minSdkVersion": "24"}, nsc=NSC_BLOCKING) as path:
        assert checks(audit_apk(Apk(path))[1], "app-cleartext") == [("pass", None)]


def test_quaygate_blocked_manifest_and_config_below_min_sdk_24_pass():
    # minSdk 23: API 21-22 devices, which ignore usesCleartextTraffic, cannot install it.
    app = {**NSC_REF, "usesCleartextTraffic": "false"}
    with temp_apk(app_over=app, sdk_over={"minSdkVersion": "23"}, nsc=NSC_BLOCKING) as path:
        assert checks(audit_apk(Apk(path))[1], "app-cleartext") == [("pass", None)]


def test_quaygate_unresolved_manifest_cleartext_below_min_sdk_24_is_partial():
    # minSdk 23 isolates the unresolved value; below 23 the API 21-22 warning is added.
    app = {**NSC_REF, "usesCleartextTraffic": "@2130837504"}
    with temp_apk(app_over=app, sdk_over={"minSdkVersion": "23"}, nsc=NSC_BLOCKING) as path:
        assert checks(audit_apk(Apk(path))[1], "app-cleartext") == [("pass", None), ("na", None)]
        report = quaygate_analysis.analyze(Path(path).resolve())
    assert coverage(report, "QG-APP-CLEARTEXT")["state"] == "partial"


# --- targetSdk 23 and lower trust user-installed CAs by default ---------------------------------


def android_tree(root: Path, target: int, config: str | None = None) -> Path:
    reference = ' android:networkSecurityConfig="@xml/network_security_config"' if config else ""
    (root / "res/xml").mkdir(parents=True)
    (root / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.ca">'
        f'<uses-sdk android:minSdkVersion="21" android:targetSdkVersion="{target}" />'
        f'<application android:usesCleartextTraffic="false"{reference} /></manifest>'
    )
    if config:
        (root / "res/xml/network_security_config.xml").write_text(config)
    return root


def default_user_ca(report: dict) -> list[dict]:
    return [
        f["evidence"][0]
        for f in by_rule(report, "ANDROID-NSC-USER-CA")
        if f["evidence"][0]["scope"] == "platform-default"
    ]


def test_target_23_without_base_trust_anchors_trusts_user_cas(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    [evidence] = default_user_ca(scan(store, android_tree(tmp_path / "none", 23)))
    assert (evidence["path"], evidence["target_sdk"]) == ("AndroidManifest.xml", 23)
    domain_only = (
        '<network-security-config><domain-config cleartextTrafficPermitted="true">'
        "<domain>legacy.example</domain></domain-config></network-security-config>\n"
    )
    report = scan(store, android_tree(tmp_path / "domain", 23, domain_only))
    [evidence] = default_user_ca(report)
    assert evidence["path"] == "res/xml/network_security_config.xml"
    assert next(f for f in by_rule(report, "ANDROID-NSC-USER-CA"))["status"] == "candidate"


def test_system_only_anchors_or_target_24_do_not_trust_user_cas(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    system_only = (
        "<network-security-config><base-config><trust-anchors>"
        '<certificates src="system" /></trust-anchors></base-config></network-security-config>\n'
    )
    for name, target, config in (("system", 23, system_only), ("modern", 24, None)):
        report = scan(store, android_tree(tmp_path / name, target, config))
        assert not by_rule(report, "ANDROID-NSC-USER-CA")
        assert coverage(report, "ANDROID-NSC-USER-CA")["state"] == "checked"


# --- Nested domain-config inherits its parent's cleartext permission -----------------------------

NESTED = """<network-security-config>
  <base-config cleartextTrafficPermitted="false" />
  <domain-config cleartextTrafficPermitted="true">
    <domain>a.example</domain>
    <domain-config>
      <domain>b.example</domain>
    </domain-config>
    <domain-config cleartextTrafficPermitted="false">
      <domain>c.example</domain>
    </domain-config>
  </domain-config>
  <domain-config>
    <domain>d.example</domain>
    <domain-config><domain>e.example</domain></domain-config>
  </domain-config>
</network-security-config>
"""


def test_quaygate_nested_domain_config_inherits_cleartext():
    result = analyze(parse_axml(NESTED.encode()))
    assert sorted(result["cleartext_domains"]) == ["a.example", "b.example"]
    assert not result["domain_unknown"]


def test_source_nested_domain_config_inherits_cleartext(store, tmp_path, monkeypatch):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    report = scan(store, android_tree(tmp_path / "nested", 34, NESTED))
    domains = sorted(
        domain
        for f in by_rule(report, "ANDROID-CLEARTEXT")
        if f["evidence"][0]["path"].endswith(".xml")
        for domain in f["evidence"][0]["domains"]
    )
    assert domains == ["a.example", "b.example"]


# --- Privacy manifest categories need a non-empty reasons list ----------------------------------

USER_DEFAULTS_SWIFT = (
    'import UIKit\nfinal class S { func save() { UserDefaults.standard.set(1, forKey: "k") } }\n'
)


def privacy(reasons: str | None) -> str:
    entry = "<key>NSPrivacyAccessedAPIType</key><string>NSPrivacyAccessedAPICategoryUserDefaults</string>"
    if reasons is not None:
        entry += f"<key>NSPrivacyAccessedAPITypeReasons</key>{reasons}"
    return (
        '<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>'
        f"<key>NSPrivacyAccessedAPITypes</key><array><dict>{entry}</dict></array></dict></plist>"
    )


@pytest.mark.parametrize(
    "reasons,reported",
    [
        (None, True),
        ("<array/>", True),
        ("<array><string></string></array>", True),
        ("<array><integer>1</integer></array>", True),
        ("<string>CA92.1</string>", True),
        ("<array><string>CA92.1</string></array>", False),
    ],
)
def test_privacy_category_needs_reason_codes(store, tmp_path, monkeypatch, reasons, reported):
    monkeypatch.setenv("APSA_PARSER_SANDBOX", "off")
    root = tmp_path / "ios"
    root.mkdir()
    (root / "S.swift").write_text(USER_DEFAULTS_SWIFT)
    (root / "PrivacyInfo.xcprivacy").write_text(privacy(reasons))
    report = scan(store, root)
    found = [
        f["evidence"][0]
        for f in by_rule(report, "IOS-PRIVACY-MANIFEST")
        if f["evidence"][0]["category"] == "NSPrivacyAccessedAPICategoryUserDefaults"
    ]
    assert bool(found) is reported
    if reported:
        assert found[0]["declaration"] == "missing-reasons" and found[0]["line"] == 2


# --- Comment/string masking is linear and keeps the previous token boundaries -------------------

PRIVACY_TOKENS = re.compile(r"//[^\r\n]*|/\*[\s\S]*?\*/")
CODE_TOKENS = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\\n])*"')


def previous_masks(text: str) -> tuple[str, str]:
    privacy_mask = PRIVACY_TOKENS.sub(lambda m: re.sub(r"[^\r\n]", " ", m[0]), text)
    code_mask = CODE_TOKENS.sub(
        lambda m: re.sub(r"[^\n]", " ", m[0]) if m[0].startswith("/") else '"' + " " * (len(m[0]) - 2) + '"',
        text,
    )
    return privacy_mask, code_mask


def test_token_masking_matches_previous_regex_boundaries():
    samples = [
        'let a = "/*" + b // c\n/* d */ e',
        '"abc // def\nx /* y',
        '"\\"\\"" /* "*/ "q" /*/ z',
        "a /* b */ c /* unterminated\n// e\r\nf",
        'x = "\\\n" /* */',
    ]
    alphabet = ["/", "*", '"', "\\", "\n", "\r", "a", " ", "//", "/*", "*/", '\\"']
    rng = random.Random(20261101)
    samples += ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 24))) for _ in range(5000)]
    for text in samples:
        privacy_mask, code_mask = previous_masks(text)
        assert _sub_tokens(text, lambda t: re.sub(r"[^\r\n]", " ", t), breaks="\r\n") == privacy_mask
        assert _masked_code(text) == code_mask


def test_many_unterminated_block_comments_are_linear(monkeypatch):
    text = "import UIKit\nlet x = UserDefaults.standard\n" + "/* a\n" * 60_000
    quotes = 'let s = "' + '\\"' * 150_000 + "\n"
    started = time.monotonic()
    findings, states = platform_checks(
        {"input_kind": "source", "platforms": ["ios"], "ios_config": [], "warnings": []},
        [("App/Notes.swift", text), ("App/Quotes.swift", quotes)],
    )
    _masked_code(text)
    _masked_code(quotes)
    assert time.monotonic() - started < 5
    privacy_lines = [f["evidence"][0]["line"] for f in findings if f["rule_id"] == "IOS-PRIVACY-MANIFEST"]
    assert privacy_lines == [2]
    assert {c["rule_id"]: c["state"] for c in states}["IOS-PRIVACY-MANIFEST"] == "checked"
