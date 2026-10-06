"""Regressions for independent product reviews of the unified 1.0.1 release."""

import copy
import json
import plistlib
import struct
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from mobile_audit.audit import compare, correlate, refresh_report, scan
from mobile_audit.cli import integration_config, main
from mobile_audit.core import canonical_json, digest, read_json, report_incomplete, uid
from mobile_audit.inputs import inspect_target
from mobile_audit.intel import _normalize_osv, query_dependencies, source_health, sync
from mobile_audit.mcp_server import create_server
from mobile_audit.output import assistant_context
from mobile_audit.policy import evaluate, load_policy
from mobile_audit.runtime import plan, replace_markers, run
from mobile_audit.skills import install_skill, skill_status
from mobile_audit.watch import reassess_targets
from quaygate.appchecks import build_manifest
from quaygate.arsc import parse_resource_names
from quaygate.cert import _parse_not_after, analyze_v1_certificate
from quaygate.elf import PT_GNU_STACK, parse
from quaygate.ipa import Ipa, audit_ipa, macho_hardening
from tests.helpers import build_arsc, build_elf64
from tests.test_binary_analysis import _fat, _ipa, _macho
from tests.test_cert import make_runner
from tests.test_runtime import Device


@pytest.mark.parametrize(
    "extra",
    [
        {"coverage": [{"rule_id": "DEX", "state": "partial"}]},
        {"online_query": {"requested": True, "errors": ["OSV unavailable"]}},
    ],
)
def test_foreground_scan_cannot_exit_zero_for_explicit_partial_work(store, capsys, monkeypatch, extra):
    report = {"inventory": {"partial": False}, "findings": [], "coverage": [], **extra}
    monkeypatch.setattr("mobile_audit.cli.scan", lambda *args: report)
    assert main(["--home", str(store.home), "--json", "scan", "unused.apk", "--fail-on", "high"]) == 3
    assert json.loads(capsys.readouterr().out)["exit_code"] == 3
    assert evaluate(report, {"schema_version": 1})["state"] == "incomplete"
    assert not report_incomplete({"coverage": [{"rule_id": "RUNTIME", "state": "not-run"}]})


def test_ipa_embedded_plists_cannot_replace_main_app_or_runtime_identity(store, tmp_path):
    path = _ipa(tmp_path, _macho(entitlements={"get-task-allow": True}))
    with zipfile.ZipFile(path, "a") as archive:
        for location, package in [
            ("PlugIns/Widget.appex", "audit.fixture.widget"),
            ("Frameworks/Kit.framework", "audit.kit"),
        ]:
            archive.writestr(
                f"Payload/App.app/{location}/Info.plist", plistlib.dumps({"CFBundleIdentifier": package})
            )
    report = scan(store, path)
    assert report["inventory"]["package"] == "audit.fixture"
    assert [a["package"] for a in report["inventory"]["apps"]] == ["audit.fixture"]
    assert len(report["inventory"]["embedded_bundles"]) == 2
    assert next(c for c in report["coverage"] if c["rule_id"] == "BINARY-IOS-MACHO")["state"] == "checked"
    assert report["inventory"]["binary"]["apps"][0]["executable_sha256"]
    assert plan(report)["package"] == "audit.fixture"
    with pytest.raises(ValueError, match="package"):
        plan(report, package="audit.fixture.widget")


def test_simulator_app_directory_embedded_plists_cannot_become_runtime_targets(store, tmp_path):
    app = tmp_path / "Owned.app"
    for location, package in [
        ("", "owned.app"),
        ("Frameworks/Kit.framework", "other.framework"),
        ("PlugIns/Widget.appex", "owned.widget"),
    ]:
        folder = app / location
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": package}))
    report = scan(store, app)
    assert report["inventory"]["package"] == "owned.app"
    assert [a["package"] for a in report["inventory"]["apps"]] == ["owned.app"]
    assert len(report["inventory"]["embedded_bundles"]) == 2
    assert plan(report)["package"] == "owned.app"
    with pytest.raises(ValueError, match="package"):
        plan(report, package="other.framework")


@pytest.mark.parametrize("name", ["quaygate", "mobile-audit"])
@pytest.mark.parametrize("version", ["1.0.1", "1.0.2"])
def test_known_old_skill_upgrades_without_force_but_user_edits_remain(name, version, tmp_path):
    destination = tmp_path / name
    destination.mkdir()
    old = (Path(__file__).parent / "fixtures/skills" / f"{name}-{version}.md").read_bytes()
    (destination / "SKILL.md").write_bytes(old)
    assert skill_status(name, destination) == "outdated"
    assert install_skill(name, destination)["status"] == "installed"
    assert skill_status(name, destination) == "current"
    (destination / "SKILL.md").write_bytes(old + b"\nUser customization\n")
    assert skill_status(name, destination) == "modified"
    with pytest.raises(FileExistsError):
        install_skill(name, destination)


@pytest.mark.parametrize("profile", ["absent", "broken", "false"])
def test_unverified_provisioning_never_becomes_legacy_pass(store, tmp_path, profile):
    path = _ipa(
        tmp_path,
        _macho(),
        profile={"Entitlements": {"get-task-allow": False}} if profile == "false" else None,
    )
    if profile == "broken":
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("Payload/App.app/embedded.mobileprovision", b"invalid profile")
    with Ipa(str(path)) as ipa:
        _, findings = audit_ipa(ipa)
        assert next(f for f in findings if f.check_id == "ipa-get-task-allow").status == "na"
    report = scan(store, path)
    assert (
        next(c for c in report["coverage"] if c["rule_id"] == "QG-IPA-GET-TASK-ALLOW")["state"] == "not-run"
    )


def test_missing_gnu_stack_is_unknown_and_mixed_fat_pie_cannot_pass():
    raw = bytearray(build_elf64())
    stack = raw.find(struct.pack("<I", PT_GNU_STACK))
    assert stack >= 64
    struct.pack_into("<I", raw, stack, 0)
    parsed = parse(bytes(raw))
    assert parsed is not None and parsed["nx"] is None
    assert macho_hardening(_fat(_macho(pie=True), _macho(pie=False, cpu=12)))["pie"] is False
    assert macho_hardening(_fat(_macho(pie=True), _macho(pie=True, cpu=12)))["pie"] is True


def test_offset16_missing_entry_does_not_read_plausible_data_262140_bytes_later():
    raw = bytearray(build_arsc([("bool", ["debuggable"])], bool_true_refs=("debuggable",)))
    assert parse_resource_names(bytes(raw))
    chunk = raw.index(b"\x01\x02\x1c\x00")
    package = raw.index(b"\x00\x02\x20\x01")
    entry = chunk + struct.unpack_from("<I", raw, chunk + 16)[0]
    raw[chunk + 9] = 2
    struct.pack_into("<H", raw, chunk + 28, 0xFFFF)
    phantom = entry + 0xFFFF * 4
    raw.extend(bytes(phantom + 16 - len(raw)))
    struct.pack_into("<HHIHBBI", raw, phantom, 8, 0, 0, 8, 0, 0x12, 1)
    for start in (0, package, chunk):
        struct.pack_into("<I", raw, start + 4, len(raw) - start)
    assert parse_resource_names(bytes(raw)) == {}


def test_openssl_english_months_do_not_use_locale_and_unknown_expiry_cannot_pass(monkeypatch):
    import quaygate.cert as cert

    class NoLocaleParser:
        def __new__(cls, *args):
            return datetime(*args)

        @staticmethod
        def strptime(*args):
            raise AssertionError("English month parsing must not depend on LC_TIME")

    monkeypatch.setattr(cert, "datetime", NoLocaleParser)
    date = _parse_not_after("notAfter=Oct 10 12:00:00 2020 GMT")
    assert date is not None and date.isoformat() == "2020-10-10"
    monkeypatch.setattr(cert, "datetime", datetime)
    info = analyze_v1_certificate(b"x", make_runner(x509_out="subject=CN=Release\nnotAfter=invalid\n"))
    assert info["expired"] is None and info["error"]


@pytest.mark.parametrize(
    "severity",
    [
        {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]},
        {
            "severity": [
                {
                    "type": "CVSS_V4",
                    "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N",
                }
            ]
        },
        {"database_specific": {"severity": "CRITICAL"}},
    ],
)
def test_critical_osv_dependency_blocks_default_policy(store, severity):
    dep = {"ecosystem": "Maven", "name": "a:b", "version": "1.0", "confidence": "exact", "path": "lock"}
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"vulns": [{"id": "OSV-test", **severity}]})
        )
    )
    records, failures = query_dependencies(store, [dep], client)
    assert failures == []
    findings, _ = correlate({"dependencies": [dep], "platforms": []}, records)
    assert findings[0]["severity"] == "critical" and findings[0]["severity_basis"] != "unknown"
    assert evaluate({"findings": findings, "coverage": []}, {"schema_version": 1})["exit_code"] == 4
    assert _normalize_osv({"id": "OSV-unknown"}, dep)["severity_basis"] == "unknown"
    client.close()


def test_cve_fetch_freshness_and_pending_policy_are_separate(store):
    stamp = datetime.now(timezone.utc).isoformat()
    identifiers = [f"CVE-2026-{90000 + i}" for i in range(100)]

    def response(request):
        if request.url.path.endswith("deltaLog.json"):
            return httpx.Response(
                200,
                json=[{"fetchTime": stamp, "new": [{"cveId": i, "dateUpdated": stamp} for i in identifiers]}],
            )
        identifier = (
            request.url.path.name
            if hasattr(request.url.path, "name")
            else request.url.path.rsplit("/", 1)[-1].removesuffix(".json")
        )
        return httpx.Response(
            200,
            json={"cveMetadata": {"cveId": identifier}, "containers": {"cna": {"title": "Android issue"}}},
        )

    client = httpx.Client(transport=httpx.MockTransport(response))
    sync(store, ["cve"], limit=3, client=client)
    health = next(f for f in source_health(store) if f["source"] == "cve")
    assert health["fetched_ok"] and not health["stale"] and health["pending"] == 70
    report = {"findings": [], "coverage": [], "intel_snapshot": [health]}
    policy = {"schema_version": 1, "require_fresh_intel": True, "required_feeds": ["cve"]}
    assert evaluate(report, policy)["exit_code"] == 3
    assert evaluate(report, {**policy, "intel_max_pending": 70})["exit_code"] == 0
    assert (
        evaluate(
            {**report, "intel_snapshot": [{**health, "retrying": 1}]}, {**policy, "intel_max_pending": 70}
        )["exit_code"]
        == 3
    )
    client.close()


def test_watch_is_offline_by_default_deduplicates_and_isolates_bad_reports(store, demo, monkeypatch):
    original = scan(store, demo)
    monkeypatch.setattr(
        "mobile_audit.watch.query_dependencies", lambda *a: pytest.fail("No implicit OSV upload")
    )
    reassess_targets(store)
    count = len(store.reports())
    assert reassess_targets(store)["reaudited_reports"] == []
    assert len(store.reports()) == count
    store.db.execute("UPDATE reports SET body_hash='tampered' WHERE id=?", (original["id"],))
    store.db.commit()
    # Make the corrupted snapshot the latest for its target.
    store.db.execute("DELETE FROM reports WHERE id!=?", (original["id"],))
    store.db.commit()
    assert reassess_targets(store)["reaudit_errors"]


def test_mcp_roots_are_explicit_and_packaged_skill_is_installable(store, tmp_path):
    config = integration_config(store.home, [tmp_path])
    args = config["mcpServers"]["apsa"]["args"]
    assert args[-2:] == ["--root", str(tmp_path.resolve())]
    with pytest.raises(ValueError, match="requires --root"):
        create_server(store.home)
    assert create_server(store.home, allow_any_root=True)
    for name in ("apsa", "quaygate", "mobile-audit"):
        directory = tmp_path / "skills" / name
        assert install_skill(name, directory)["status"] == "installed"
        assert (directory / "SKILL.md").read_bytes() == (
            Path(__file__).parents[1] / ".agents/skills" / name / "SKILL.md"
        ).read_bytes()
        (directory / "SKILL.md").write_text("user customization")
        with pytest.raises(FileExistsError):
            install_skill(name, directory)


def test_mcp_configuration_uses_canonical_module_without_console_script(store, tmp_path, monkeypatch):
    monkeypatch.setattr("mobile_audit.cli.shutil.which", lambda command: None)
    server = integration_config(store.home, [tmp_path])["mcpServers"]["apsa"]
    assert server["command"] == sys.executable
    assert server["args"][:2] == ["-m", "apsa"]
    assert server["args"][-2:] == ["--root", str(tmp_path.resolve())]


def test_other_platform_intel_cannot_satisfy_os_rule_and_compare_severity_changes(store, demo):
    store.upsert_intel([{"id": "CVE-2026-12345", "source": "apple", "platform": "ios", "title": "iOS issue"}])
    report = scan(store, demo, environment={"platform": "android", "security_patch": "2026-09-05"})
    assert next(c for c in report["coverage"] if c["rule_id"] == "OS-CVE")["state"] == "not-run"
    assert (
        evaluate(
            report,
            {"schema_version": 1, "required_rules": ["OS-CVE"], "thresholds": {"high": -1, "critical": -1}},
        )["exit_code"]
        == 3
    )
    after = copy.deepcopy(report)
    after["id"] = "audit_changed"
    after["findings"][0]["severity"] = "critical"
    store.save_report(after)
    assert compare(store, report["id"], after["id"])["changed"]
    assert (
        next(c for c in refresh_report(store, report["id"])["coverage"] if c["rule_id"] == "OS-CVE")["state"]
        == "not-run"
    )


def test_runtime_unknown_identity_is_refused_before_device_use(store, tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "App.kt").write_text("class App {}")
    report = scan(store, source)
    scenario = plan(report)
    scenario["package"] = "com.other.app"
    scenario["precondition"] = "Owned fixture prepared"
    with pytest.raises(ValueError, match="No audited app identifier"):
        run(store, tmp_path / "unused", report["id"], scenario=scenario, adapter=Device())


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("different_steps", [False, True])
def test_runtime_passing_rerun_uses_check_semantics_not_prose(store, demo, tmp_path, legacy, different_steps):
    report = scan(store, demo)
    scenario = {
        "platform": "android",
        "package": "com.example.mobileauditdemo",
        "precondition": "Owned fixture prepared",
        "markers": {"account_a": "unique-test-account-A"},
        "steps": [
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": "auditdemo://app/logout"},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            {"snapshot": "after", "baseline": "before", "marker": "account_a", "policy": "old wording"}
        ],
    }
    failed = run(store, tmp_path / "unused", report["id"], scenario=scenario, adapter=Device(True))
    assert any(f["status"] == "runtime-confirmed" for f in failed["findings"])
    if legacy:
        old_identity = digest(
            replace_markers(
                canonical_json(
                    {key: scenario[key] for key in ("platform", "package", "steps", "assertions")}
                ),
                scenario["markers"],
            ).encode()
        )
        for f in failed["findings"]:
            if f["status"] == "runtime-confirmed":
                for evidence in f["evidence"]:
                    evidence.pop("scenario_scope")
                    evidence["scenario_identity"] = old_identity
        failed["id"] = uid("audit")
        store.save_report(failed)
    scenario["precondition"] = "Updated preparation notes, same tested transition"
    scenario["assertions"][0]["policy"] = "new wording"
    if different_steps:
        scenario["steps"].insert(1, {"action": "wait", "seconds": 0})
    passed = run(store, tmp_path / "unused", failed["id"], scenario=scenario, adapter=Device(False))
    assert any(f["status"] == "runtime-confirmed" for f in passed["findings"]) is different_steps


def test_app_zip_preserves_embedded_security_config_without_selecting_embedded_links(store, tmp_path):
    path = tmp_path / "simulator.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Owned.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "owned.app"}))
        archive.writestr(
            "Owned.app/PlugIns/Widget.appex/Info.plist",
            plistlib.dumps(
                {
                    "CFBundleIdentifier": "owned.widget",
                    "MinimumOSVersion": "10.0",
                    "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
                    "CFBundleURLTypes": [{"CFBundleURLSchemes": ["widget"]}],
                }
            ),
        )
    report = scan(store, path)
    assert report["inventory"]["package"] == "owned.app"
    embedded = next(c for c in report["inventory"]["ios_config"] if c["bundle_role"] == "embedded")
    assert embedded["minimum_os"] == "10.0" and embedded["ats"]["NSAllowsArbitraryLoads"]
    assert any(f["rule_id"] == "IOS-ATS" for f in report["findings"])
    assert report["inventory"]["deep_links"][0]["bundle_role"] == "embedded"
    assert not plan(report)["notes"]["deep_link_candidates"]


@pytest.mark.parametrize("kind", [".app", ".zip", ".ipa"])
@pytest.mark.parametrize("malformed_main", [False, True])
def test_embedded_config_alone_never_substitutes_for_main_app(store, tmp_path, kind, malformed_main):
    target = tmp_path / ("Owned" + kind)
    embedded = plistlib.dumps(
        {"CFBundleIdentifier": "owned.framework", "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    )
    if kind == ".app":
        (target / "Frameworks/Kit.framework").mkdir(parents=True)
        (target / "Frameworks/Kit.framework/Info.plist").write_bytes(embedded)
        if malformed_main:
            (target / "Info.plist").write_bytes(b"unreadable")
    else:
        prefix = "Payload/" if kind == ".ipa" else ""
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr(prefix + "Owned.app/Frameworks/Kit.framework/Info.plist", embedded)
            if malformed_main:
                archive.writestr(prefix + "Owned.app/Info.plist", b"unreadable")
    with pytest.raises(ValueError, match="main.*Info.plist|main iOS Info.plist"):
        scan(store, target)


def test_large_fat_slice_bounds_do_not_falsely_report_missing_pie():
    data = bytearray(_fat(_macho(pie=True), _macho(pie=True, cpu=12)))
    struct.pack_into(">I", data, 8 + 12, len(data) * 10)
    assert macho_hardening(bytes(data), truncated=True)["pie"] is True
    assert macho_hardening(bytes(data))["pie"] is None
    struct.pack_into(">I", data, 8 + 20 + 8, len(data) * 20)
    assert macho_hardening(bytes(data), truncated=True)["pie"] is None


def test_debug_certificate_keeps_unknown_expiry_and_known_debug_fact():
    info = analyze_v1_certificate(b"x", make_runner(x509_out="subject=CN=Android Debug\nnotAfter=invalid\n"))
    assert info["debug"] is True and info["expired"] is None and info["error"]


def test_osv_moderate_database_rating_has_known_medium_severity():
    value = _normalize_osv(
        {"id": "OSV-moderate", "database_specific": {"severity": "MODERATE"}},
        {"ecosystem": "Maven", "name": "a:b", "version": "1"},
    )
    assert value["severity"] == "medium" and value["severity_basis"] == "database_specific.severity"


def test_archive_byte_budget_stops_once_with_accurate_partial_reason(tmp_path, monkeypatch):
    manifest = b'<manifest package="owned.app"><application/></manifest>'
    monkeypatch.setattr("mobile_audit.inputs.MAX_SOURCE_TOTAL", len(manifest) + 2)
    path = tmp_path / "app.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        for name in ("First.kt", "Second.kt", "Third.kt"):
            archive.writestr(name, "class Example")
    inventory, _ = inspect_target(path)
    assert inventory["partial"] and not inventory["fingerprint_complete"]
    assert inventory["warnings"] == ["Source/configuration total byte limit reached; coverage incomplete"]


def test_multiple_source_plists_in_zip_remain_scannable_without_main_app_claim(store, tmp_path):
    path = tmp_path / "source.zip"
    with zipfile.ZipFile(path, "w") as archive:
        for name, package in [
            ("ios/Runner/Info.plist", "owned.runner"),
            ("ios/RunnerTests/Info.plist", "owned.tests"),
        ]:
            archive.writestr(name, plistlib.dumps({"CFBundleIdentifier": package}))
        archive.writestr(
            "AndroidManifest.xml", b'<manifest package="owned.android"><application/></manifest>'
        )
    report = scan(store, path)
    assert report["inventory"]["platforms"] == ["android", "ios"]
    assert next(c for c in report["coverage"] if c["rule_id"] == "IOS-CONFIG")["state"] == "not-run"
    assert not any(a["platform"] == "ios" for a in report["inventory"]["apps"])


def test_mixed_android_and_broken_app_zip_cannot_hide_missing_main_ios_identity(store, tmp_path):
    path = tmp_path / "mixed.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Owned.app/Info.plist", b"unreadable")
        archive.writestr(
            "AndroidManifest.xml", b'<manifest package="owned.android"><application/></manifest>'
        )
    with pytest.raises(ValueError, match="main.*Info.plist"):
        scan(store, path)


@pytest.mark.parametrize("prefix", ["", "Build/", "Products/"])
def test_nested_watch_app_cannot_substitute_for_absent_root_app_in_zip(store, tmp_path, prefix):
    path = tmp_path / "watch.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            prefix + "Owned.app/Watch/W.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "owned.watch"})
        )
    with pytest.raises(ValueError, match="main.*Info.plist"):
        scan(store, path)


def test_wrapped_app_zip_selects_outer_app_and_preserves_watch_metadata(store, tmp_path):
    path = tmp_path / "wrapped.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Build/Owned.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "owned.main"}))
        archive.writestr("Other/Info.plist", plistlib.dumps({"CFBundleIdentifier": "foreign.other"}))
        archive.writestr(
            "Build/Owned.app/Watch/W.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "owned.watch"})
        )
    report = scan(store, path)
    assert [a["package"] for a in report["inventory"]["apps"]] == ["owned.main"]
    assert [a["package"] for a in report["inventory"]["embedded_bundles"]] == ["owned.watch"]
    assert plan(report)["package"] == "owned.main"
    assert assistant_context(report)["input"]["archive_role"] == "ios-app-build"


def test_framework_contained_app_is_embedded_source_evidence_not_main_build(store, tmp_path):
    path = tmp_path / "source.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Info.plist", plistlib.dumps({"CFBundleIdentifier": "owned.source"}))
        archive.writestr(
            "Kit.framework/Fake.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "foreign.fixture"})
        )
    report = scan(store, path)
    assert report["inventory"]["archive_role"] == "source-zip"
    assert assistant_context(report)["input"]["archive_role"] == "source-zip"
    assert [a["package"] for a in report["inventory"]["apps"]] == ["owned.source"]


@pytest.mark.parametrize("limited", [False, True])
def test_apk_asset_manifest_cannot_replace_root_identity_or_budget_priority(tmp_path, monkeypatch, limited):
    root = b'<manifest package="owned.android"><application/></manifest>'
    path = tmp_path / "assets.apk"
    if limited:
        monkeypatch.setattr("mobile_audit.inputs.MAX_SOURCE_TOTAL", len(root) + 2)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "assets/AndroidManifest.xml", b'<manifest package="foreign.android"><application/></manifest>'
        )
        archive.writestr("AndroidManifest.xml", root)
    inventory, _ = inspect_target(path)
    assert inventory["package"] == "owned.android"
    assert [a["package"] for a in inventory["apps"]] == ["owned.android"]
    assert inventory["partial"] is limited


def test_app_directory_reads_main_before_foreign_resources_exhaust_budget(tmp_path, monkeypatch):
    app = tmp_path / "Owned.app"
    app.mkdir()
    main = plistlib.dumps({"CFBundleIdentifier": "owned.ios"})
    (app / "Info.plist").write_bytes(main)
    (app / "AndroidManifest.xml").write_bytes(
        b'<manifest package="foreign.android"><application/></manifest>'
    )
    monkeypatch.setattr("mobile_audit.inputs.MAX_SOURCE_TOTAL", len(main) + 2)
    inventory, _ = inspect_target(app)
    assert inventory["package"] == "owned.ios" and inventory["platforms"] == ["ios"]
    assert inventory["partial"] and not inventory["fingerprint_complete"]


def test_finder_appledouble_metadata_does_not_create_false_plist_partial(store, tmp_path):
    path = tmp_path / "finder.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Owned.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "owned.main"}))
        archive.writestr("__MACOSX/Owned.app/._Info.plist", b"AppleDouble metadata")
    report = scan(store, path)
    assert report["inventory"]["package"] == "owned.main"
    assert not report["inventory"]["partial"]
    assert not any("._Info.plist" in warning for warning in report["inventory"]["warnings"])


@pytest.mark.parametrize("limited", [False, True])
def test_apk_foreign_ios_resources_cannot_change_app_identity_or_platform(tmp_path, monkeypatch, limited):
    path = tmp_path / "foreign.apk"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml", b'<manifest package="owned.android"><application/></manifest>'
        )
        archive.writestr("X.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "foreign.ios"}))
        archive.writestr("Y.app/Info.plist", plistlib.dumps({"CFBundleIdentifier": "foreign.other"}))
        archive.writestr("assets/Example.swift", "class Example {}")
    if limited:
        with zipfile.ZipFile(path) as archive:
            monkeypatch.setattr(
                "mobile_audit.inputs.MAX_SOURCE_TOTAL", len(archive.read("AndroidManifest.xml")) + 2
            )
    inventory, _ = inspect_target(path)
    assert inventory["package"] == "owned.android" and inventory["platforms"] == ["android"]
    assert not inventory["ios_config"]
    assert all(a["platform"] == "android" for a in inventory["apps"])
    assert inventory["partial"] is limited


@pytest.mark.parametrize("kind", [".ipa", ".zip", ".app"])
def test_ios_build_foreign_android_resources_cannot_change_app_identity_or_platform(store, tmp_path, kind):
    path = _ipa(tmp_path, _macho())
    with zipfile.ZipFile(path, "a") as archive:
        archive.writestr(
            "Payload/App.app/AndroidManifest.xml",
            b'<manifest package="foreign.android"><application/></manifest>',
        )
        archive.writestr("Payload/App.app/build.gradle", 'applicationId "foreign.gradle"')
        archive.writestr("Payload/App.app/Example.kt", "class Example {}")
    if kind == ".zip":
        path = path.rename(tmp_path / "Owned.zip")
    elif kind == ".app":
        app = tmp_path / "Owned.app"
        app.mkdir()
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if name.startswith("Payload/App.app/"):
                    (app / name.removeprefix("Payload/App.app/")).write_bytes(archive.read(name))
        path = app
    report = scan(store, path)
    assert report["inventory"]["package"] == "audit.fixture"
    assert report["inventory"]["platforms"] == ["ios"] and not report["inventory"]["android_config"]
    assert all(a["platform"] == "ios" for a in report["inventory"]["apps"])


@pytest.mark.parametrize("kind", [".ipa", ".zip"])
def test_ios_main_plist_precedes_foreign_android_manifest_at_byte_limit(tmp_path, monkeypatch, kind):
    path = tmp_path / ("Owned" + kind)
    main = plistlib.dumps({"CFBundleIdentifier": "owned.ios"})
    monkeypatch.setattr("mobile_audit.inputs.MAX_SOURCE_TOTAL", len(main) + 2)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml", b'<manifest package="foreign.android"><application/></manifest>'
        )
        archive.writestr(("Payload/" if kind == ".ipa" else "") + "Owned.app/Info.plist", main)
    inventory, _ = inspect_target(path)
    assert inventory["package"] == "owned.ios" and inventory["platforms"] == ["ios"]
    assert inventory["partial"] and not inventory["fingerprint_complete"]


@pytest.mark.parametrize("kind", [".ipa", ".zip", ".apk"])
def test_archive_main_identity_precedes_optional_resource_budget(tmp_path, monkeypatch, kind):
    path = tmp_path / ("Owned" + kind)
    name = (
        "AndroidManifest.xml"
        if kind == ".apk"
        else ("Payload/" if kind == ".ipa" else "") + "Owned.app/Info.plist"
    )
    main = (
        b'<manifest package="owned.android"><application/></manifest>'
        if kind == ".apk"
        else plistlib.dumps({"CFBundleIdentifier": "owned.ios"})
    )
    monkeypatch.setattr("mobile_audit.inputs.MAX_SOURCE_TOTAL", len(main) + 2)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("large.json", b"0123456789")
        archive.writestr(name, main)
    inventory, _ = inspect_target(path)
    assert inventory["package"] == ("owned.android" if kind == ".apk" else "owned.ios")
    assert inventory["partial"] and not inventory["fingerprint_complete"]
    assert inventory["warnings"][0] == "Source/configuration total byte limit reached; coverage incomplete"


def test_runtime_partial_assertions_preserve_unknown_evidence_and_never_duplicate_ids(store, demo, tmp_path):
    report = scan(store, demo)
    scenario = {
        "platform": "android",
        "package": "com.example.mobileauditdemo",
        "precondition": "Owned fixture",
        "markers": {"account_a": "unique-test-account-A", "account_b": "unique-test-account-B"},
        "steps": [
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": "auditdemo://app/logout"},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            {"snapshot": "after", "baseline": "before", "marker": marker}
            for marker in ("account_a", "account_b")
        ],
    }

    class Multiple(Device):
        def __init__(self, both, remains=True):
            super().__init__(remains)
            self.both = both

        def storage(self):
            return super().storage() + ([("b", b"unique-test-account-B")] if self.both else [])

    first = run(store, tmp_path / "unused", report["id"], scenario=scenario, adapter=Multiple(True))
    assert len([f for f in first["findings"] if f["status"] == "runtime-confirmed"]) == 2
    passed_a = run(store, tmp_path / "unused", first["id"], scenario=scenario, adapter=Multiple(False, False))
    remaining = [f for f in passed_a["findings"] if f["status"] == "runtime-confirmed"]
    assert len(remaining) == 1 and remaining[0]["evidence"][0]["assertion"]["marker"] == "account_b"
    repeat = run(store, tmp_path / "unused", first["id"], scenario=scenario, adapter=Multiple(False))
    assert len({f["id"] for f in repeat["findings"]}) == len(repeat["findings"])
    assert not any(
        reason["code"] == "duplicate-finding-id"
        for reason in evaluate(repeat, {"schema_version": 1})["reasons"]
    )


def test_watch_does_not_save_identical_intelligence_findings_due_to_sort_order(store, demo):
    dep = {"ecosystem": "Maven", "name": "a:b", "version": "1.0", "path": "lock", "confidence": "exact"}
    store.upsert_intel(
        [
            {
                "id": "OSV-test",
                "source": "osv:Maven:a:b:1.0",
                "query_match": dep,
                "title": "critical",
                "severity": "critical",
            }
        ]
    )
    before = scan(store, demo)
    before["id"] = "audit_watch_order"
    before["inventory"]["dependencies"] = [dep]
    before["findings"] += correlate(before["inventory"], store.intelligence())[0]
    before["findings"].sort(
        key=lambda f: -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[f["severity"]]
    )
    store.save_report(before)
    assert reassess_targets(store)["reaudited_reports"] == []


def test_duplicate_application_scope_ends_at_its_close():
    events = [
        ("start", "manifest", {"package": "owned.app"}),
        ("start", "application", {}),
        ("end", "application", {}),
        ("start", "application", {"debuggable": "true"}),
        ("end", "application", {}),
        ("start", "uses-sdk", {"targetSdkVersion": "35"}),
        ("end", "uses-sdk", {}),
        ("end", "manifest", {}),
    ]
    manifest = build_manifest(events)
    assert manifest.app == {} and manifest.anomalies
    assert manifest.sdk["targetSdkVersion"] == "35"


def test_sidecar_parent_symlink_is_canonicalized_but_leaf_symlink_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    (real / "config.json").write_text('{"schema_version":1}')
    assert read_json(alias / "config.json")["schema_version"] == 1
    assert load_policy(alias / "config.json")["schema_version"] == 1
    (real / "leaf.json").symlink_to(real / "config.json")
    with pytest.raises(OSError):
        read_json(alias / "leaf.json")


def test_corrupt_auxiliary_archive_member_preserves_partial_report_inventory(tmp_path):
    path = tmp_path / "corrupt.apk"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", '<manifest package="owned.app"><application/></manifest>')
        archive.writestr("res/broken.xml", "UNIQUE-CONFIG-TEXT")
    raw = path.read_bytes().replace(b"UNIQUE-CONFIG-TEXT", b"BROKEN-CONFIG-TXT!")
    path.write_bytes(raw)
    inventory, _ = inspect_target(path)
    assert inventory["partial"] and not inventory["fingerprint_complete"]
    assert any("BadZipFile" in warning for warning in inventory["warnings"])
