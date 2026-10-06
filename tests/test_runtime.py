import json

import pytest

from mobile_audit.audit import scan
from mobile_audit.runtime import (
    IOS,
    Android,
    device_lease,
    evaluate_assertions,
    plan,
    run,
    scoped_android_ui,
    snapshot,
    validate_scenario,
)


def test_device_scenarios_cannot_overlap(tmp_path):
    with device_lease("android", "one", tmp_path):
        with pytest.raises(ValueError, match="already used"):
            with device_lease("android", "one", tmp_path):
                pass
        with device_lease("android", "two", tmp_path):
            pass


def test_ui_capture_excludes_other_apps():
    raw = b'<hierarchy><node package="com.example.app" text="Our screen"/><node package="other.app" text="PRIVATE CANARY"/></hierarchy>'
    captured = scoped_android_ui(raw, "com.example.app")
    assert b"Our screen" in captured and b"PRIVATE" not in captured
    with pytest.raises(ValueError, match="no visible UI"):
        scoped_android_ui(raw, "missing.app")


def test_utf16_canary_is_observed_without_persisting_value():
    class Encoded(Device):
        def storage(self):
            return [("binary", "unique-test-account-A".encode("utf-16-le"))]

    result = snapshot(Encoded(), {"account_a": "unique-test-account-A"})
    assert any(m["surface"] == "storage" for m in result["matches"])
    assert "unique-test-account-A" not in json.dumps(result)


def test_transition_requires_a_changed_marker_state():
    scenario = {
        "assertions": [
            {
                "snapshot": "after",
                "baseline": "before",
                "marker": "logged_out",
                "expect": "present",
                "purpose": "transition",
            }
        ]
    }
    before = {"surfaces": {"storage": {"state": "captured"}}, "matches": []}
    after = dict(before, matches=[{"surface": "storage", "marker_label": "logged_out"}])
    assert evaluate_assertions(scenario, {"before": before, "after": after})[0]["state"] == "passed"
    assert evaluate_assertions(scenario, {"before": after, "after": after})[0]["state"] == "inconclusive"
    assert evaluate_assertions(scenario, {"before": before, "after": before})[0]["state"] == "failed"


def test_missing_baseline_cannot_pass():
    scenario = {"assertions": [{"snapshot": "after", "baseline": "before", "marker": "a"}]}
    snap = {"surfaces": {"storage": {"state": "captured"}}, "matches": []}
    assert evaluate_assertions(scenario, {"before": snap, "after": snap})[0]["state"] == "inconclusive"
    snap["surfaces"]["storage"]["state"] = "not-run"
    assert evaluate_assertions(scenario, {"before": snap, "after": snap})[0]["state"] == "not-run"


def test_mixed_source_plan_selects_platform_and_package(store, demo):
    report = scan(store, demo)
    apps = report["inventory"]["apps"]
    ios = next(app for app in apps if app["platform"] == "ios")
    selected = plan(report, "ios", ios["package"])
    assert selected["platform"] == "ios" and selected["package"] == ios["package"]
    with pytest.raises(ValueError, match="package"):
        plan(report, "android", "unrelated.app")


def test_wrong_installed_apk_is_refused_before_capture(store, apk, tmp_path):
    report = scan(store, apk)
    scenario = plan(report)
    scenario["precondition"] = "Prepared owned test app with a synthetic canary."
    scenario["markers"] = {"account_a": "unique-test-account-A"}
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario))

    class WrongBuild(Device):
        def environment(self):
            return {"platform": "android", "app": {"apk_sha256": "0" * 64}}

        def storage(self):
            raise AssertionError("Mismatched builds must not capture app data")

    with pytest.raises(ValueError, match="APK"):
        run(store, path, report["id"], adapter=WrongBuild())


def test_runtime_uses_frozen_scenario_and_distinguishes_transitions(store, demo, tmp_path):
    report = scan(store, demo)
    scenario = {
        "platform": "android",
        "package": "com.example.mobileauditdemo",
        "precondition": "Account A is ready with the declared canary",
        "markers": {"account_a": "unique-test-account-A"},
        "steps": [
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": "auditdemo://app/logout"},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            {"snapshot": "after", "baseline": "before", "marker": "account_a", "surface": "storage"}
        ],
    }
    missing = tmp_path / "deleted-after-queue.json"
    first = run(store, missing, report["id"], adapter=Device(), scenario=scenario)
    changed = json.loads(json.dumps(scenario))
    changed["steps"][1]["url"] = "auditdemo://app/switch-account"

    class Switch(Device):
        def open_url(self, url):
            assert url == "auditdemo://app/switch-account"
            self.logged_out = True

    after = run(store, missing, first["id"], adapter=Switch(), scenario=changed)
    observed = [finding for finding in after["findings"] if finding["status"] == "runtime-confirmed"]
    assert len(observed) == 2 and len({finding["id"] for finding in observed}) == 2


class Device:
    def __init__(self, remains=True):
        self.logged_out = False
        self.remains = remains

    def environment(self):
        return {"platform": "android", "version": "16", "security_patch": "2026-09-05"}

    def storage(self):
        return [
            (
                "shared_prefs/account.xml",
                b"unique-test-account-A" if not self.logged_out or self.remains else b"empty",
            )
        ]

    def ui(self) -> bytes:
        return b"Login screen"

    def logs(self):
        return b"No sensitive logs"

    def open_url(self, url):
        assert url == "auditdemo://app/logout"
        self.logged_out = True


@pytest.mark.parametrize("remains", [True, False])
def test_runtime_transition_produces_evidence_or_scoped_pass(store, demo, tmp_path, remains):
    report = scan(store, demo)
    scenario = {
        "platform": "android",
        "package": "com.example.mobileauditdemo",
        "precondition": "Account A logged in with canary",
        "markers": {"account_a": "unique-test-account-A"},
        "steps": [
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": "auditdemo://app/logout"},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            {
                "snapshot": "after",
                "baseline": "before",
                "marker": "account_a",
                "policy": "delete after logout",
            }
        ],
    }
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario))
    result = run(store, path, report["id"], adapter=Device(remains))
    assertions = result["runtime"][-1]["assertions"]
    assert assertions[0]["state"] == ("failed" if remains else "passed")
    from mobile_audit.policy import evaluate

    assert next(c for c in result["coverage"] if c["rule_id"] == "RUNTIME-RESIDUAL")["state"] == "checked"
    gate = evaluate(
        result,
        {
            "schema_version": 1,
            "allowed_statuses": ["runtime-confirmed"],
            "thresholds": {"medium": 0},
            "required_rules": ["RUNTIME-RESIDUAL"],
        },
    )
    assert gate["exit_code"] == (4 if remains else 0)
    assert any(f["status"] == "runtime-confirmed" for f in result["findings"]) is remains
    assert "unique-test-account-A" not in json.dumps(result)
    assert store.report(report["id"])["runtime"] == []
    if remains:
        fixed = run(store, path, result["id"], adapter=Device(False))
        assert fixed["runtime"][-1]["assertions"][0]["state"] == "passed"
        assert not any(f["status"] == "runtime-confirmed" for f in fixed["findings"])
        assert len(fixed["runtime"]) == 2
        assert store.report(result["id"])["runtime"][-1]["assertions"][0]["state"] == "failed"


def test_generated_scenario_is_preview_only_until_customized(store, demo, tmp_path):
    report = scan(store, demo)
    scenario = plan(report)
    validate_scenario(scenario)
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(scenario))
    with pytest.raises(ValueError, match="Customize"):
        run(store, path, report["id"])


def test_adb_url_is_quoted_as_remote_shell_data(monkeypatch):
    recorded = []
    monkeypatch.setattr(
        "mobile_audit.runtime.command", lambda args, **kwargs: recorded.append(args) or b"Status: ok"
    )
    device = Android("com.example.app", "serial")
    url = "example://test?value=$(touch /tmp/bad);echo hacked"
    device.open_url(url)
    assert recorded[0][-1].endswith("'example://test?value=$(touch /tmp/bad);echo hacked' -p com.example.app")


def test_ios_url_dispatch_does_not_claim_target_delivery(monkeypatch):
    monkeypatch.setattr("mobile_audit.runtime.command", lambda args, **kwargs: b"")
    result = IOS("com.example.app", "test-udid").open_url("example://logout")
    assert result["delivery"] == "requested-not-confirmed"
    assert "manual Open confirmation" in result["note"]


@pytest.mark.parametrize("delivery_confirmed", [False, True])
def test_ci_required_deeplink_requires_delivery_evidence(store, demo, tmp_path, delivery_confirmed):
    from mobile_audit.policy import evaluate

    report = scan(store, demo)
    scenario = {
        "platform": "android",
        "package": "com.example.mobileauditdemo",
        "precondition": "Owned account A contains its declared canary",
        "markers": {"account_a": "unique-test-account-A", "delivered": "unique-target-delivery"},
        "steps": [
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": "auditdemo://app/logout"},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            {"snapshot": "after", "baseline": "before", "marker": "account_a", "surface": "storage"}
        ],
    }
    if delivery_confirmed:
        scenario["assertions"].append(
            {
                "snapshot": "after",
                "baseline": "before",
                "marker": "delivered",
                "surface": "ui",
                "expect": "present",
                "purpose": "delivery",
            }
        )

    class Target(Device):
        def ui(self) -> bytes:
            return b"unique-target-delivery" if self.logged_out and delivery_confirmed else b"Login screen"

    current = run(store, tmp_path / "frozen.json", report["id"], adapter=Target(False), scenario=scenario)
    record = current["runtime"][-1]
    assert record["partial"] is False
    assert record["delivery_verification"] == (
        "marker-observed" if delivery_confirmed else "requested-not-confirmed"
    )
    gate = evaluate(
        current,
        {
            "schema_version": 1,
            "thresholds": {"critical": -1, "high": -1},
            "required_rules": ["RUNTIME-DEEPLINK"],
            "fail_on_partial": False,
        },
    )
    assert gate["exit_code"] == (0 if delivery_confirmed else 3)
    if not delivery_confirmed:
        assert any(reason["code"] == "required-rule-incomplete" for reason in gate["reasons"])


@pytest.mark.parametrize("purpose", ["delivery", "transition", "authentication"])
def test_ci_residual_coverage_excludes_other_assertion_purposes(store, demo, tmp_path, purpose):
    from mobile_audit.policy import evaluate

    report = scan(store, demo)
    scenario = {
        "platform": "android",
        "package": "com.example.mobileauditdemo",
        "precondition": "Owned test app changes its target UI marker after dispatch",
        "markers": {"delivered": "unique-target-delivery"},
        "steps": [
            {"action": "snapshot", "label": "before"},
            {"action": "open_url", "url": "auditdemo://app/logout"},
            {"action": "snapshot", "label": "after"},
        ],
        "assertions": [
            {
                "snapshot": "after",
                "baseline": "before",
                "marker": "delivered",
                "surface": "ui",
                "expect": "present",
                "purpose": purpose,
            }
        ],
    }

    class Target(Device):
        def ui(self) -> bytes:
            return b"unique-target-delivery" if self.logged_out else b"Login screen"

    current = run(store, tmp_path / "frozen.json", report["id"], adapter=Target(False), scenario=scenario)
    assert current["runtime"][-1]["assertions"][0]["state"] == "passed"
    assert current["runtime"][-1]["partial"] is False
    coverage = next(c for c in current["coverage"] if c["rule_id"] == "RUNTIME-RESIDUAL")
    assert coverage["state"] == "not-run"
    gate = evaluate(
        current,
        {
            "schema_version": 1,
            "thresholds": {"critical": -1, "high": -1},
            "required_rules": ["RUNTIME-RESIDUAL"],
            "fail_on_partial": False,
        },
    )
    assert gate["exit_code"] == 3
    assert any(reason["code"] == "required-rule-incomplete" for reason in gate["reasons"])


@pytest.mark.parametrize("expected", ["not-run", "inconclusive"])
def test_ci_residual_requires_captured_baseline_evidence(store, demo, tmp_path, expected):
    from mobile_audit.policy import evaluate

    report = scan(store, demo)
    scenario = {
        "platform": "android",
        "package": "com.example.mobileauditdemo",
        "precondition": "Owned test canary; unavailable captures cannot prove removal",
        "markers": {"account_a": "unique-test-account-A"},
        "steps": [{"action": "snapshot", "label": "before"}, {"action": "snapshot", "label": "after"}],
        "assertions": [
            {"snapshot": "after", "baseline": "before", "marker": "account_a", "purpose": "residual"}
        ],
    }

    class Missing(Device):
        def storage(self):
            if expected == "not-run":
                raise ValueError("Test storage capture unavailable")
            return []

    current = run(store, tmp_path / "frozen.json", report["id"], adapter=Missing(), scenario=scenario)
    assert current["runtime"][-1]["assertions"][0]["state"] == expected
    assert next(c for c in current["coverage"] if c["rule_id"] == "RUNTIME-RESIDUAL")["state"] == "not-run"
    gate = evaluate(
        current, {"schema_version": 1, "required_rules": ["RUNTIME-RESIDUAL"], "fail_on_partial": False}
    )
    assert gate["exit_code"] == 3
