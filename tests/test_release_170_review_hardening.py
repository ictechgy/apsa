"""1.7.0 release review: ZIP central-directory pre-check, legacy-device cleartext,
linear SARIF credential redaction and Markdown fences around report JSON.

Archives, APKs and SARIF text are synthetic and small (budgets are monkeypatched);
no network, device or app input.
"""

from __future__ import annotations

import io
import json
import re
import time
import zipfile
from pathlib import Path

import pytest

from mobile_audit import inputs, quaygate_analysis
from mobile_audit.apks_analysis import analyze_apks
from mobile_audit.binary_analysis import analyze_binary
from mobile_audit.ingest import CREDENTIAL, _text
from mobile_audit.output import markdown
from quaygate.apk import Apk
from quaygate.appchecks import audit_apk
from quaygate.checks import MEDIUM
from tests.apks_fixture import DEFAULT_DEVICE, split_toc, write_split_apks
from tests.helpers import temp_apk
from tests.test_input_robustness_review import _aliased_archive

# --- ZIP central-directory pre-check ------------------------------------------------------

# CPython 3.11 and early 3.12 releases look for the end record from 65,558 bytes before
# the end of the file, so an end record followed by 65,536 bytes is still read there.
WIDEST_TRAILER = (1 << 16) + 22


@pytest.fixture
def budget(monkeypatch):
    monkeypatch.setattr(inputs, "MAX_ZIP_ENTRIES", 8)


def refuse_zipfile(monkeypatch, *, allow_paths=False):
    real = zipfile.ZipFile

    def guarded(file, *args, **kwargs):
        if allow_paths and isinstance(file, (str, Path)):
            return real(file, *args, **kwargs)
        pytest.fail("ZipFile allocated entries before the directory budget was checked")

    monkeypatch.setattr(zipfile, "ZipFile", guarded)


def test_end_record_followed_by_65536_bytes_is_still_bounded(tmp_path, budget, monkeypatch):
    raw = _aliased_archive(9) + b"\0" * (1 << 16)
    assert len(raw) - raw.rfind(b"PK\x05\x06") == WIDEST_TRAILER
    target = tmp_path / "trailing.apk"
    target.write_bytes(raw)
    refuse_zipfile(monkeypatch)
    with pytest.raises(ValueError, match="safe size/file-count"):
        inputs.inspect_target(target)
    with pytest.raises(ValueError, match="safe size/file-count"):
        analyze_binary(target, {})


def test_an_archive_within_budget_and_65536_trailing_bytes_still_passes_the_pre_check(tmp_path, budget):
    target = tmp_path / "trailing.zip"
    target.write_bytes(_aliased_archive(8) + b"\0" * (1 << 16))
    inputs._zip_directory_within_budget(target)
    inputs._zip_directory_within_budget(io.BytesIO(target.read_bytes()))


@pytest.mark.parametrize(
    "raw",
    [
        b"PK\x03\x04" + b"\0" * 64,
        b"",
        # The end record lies one byte beyond every ZipFile search window.
        _aliased_archive(9) + b"\0" * ((1 << 16) + 1),
        # A truncated end record.
        _aliased_archive(9)[:-4],
    ],
    ids=["no-end-record", "empty", "beyond-window", "truncated"],
)
def test_an_archive_without_a_bounded_end_record_is_refused(tmp_path, monkeypatch, raw):
    target = tmp_path / "unbounded.apk"
    target.write_bytes(raw)
    refuse_zipfile(monkeypatch)
    with pytest.raises(ValueError, match="no bounded ZIP end record"):
        inputs.inspect_target(target)
    with pytest.raises(ValueError, match="no bounded ZIP end record"):
        analyze_binary(target, {})


def unexpected_member(*args, **kwargs):
    pytest.fail("An APK-set member was analyzed after its directory exceeded the budget")


def test_apk_set_directory_is_bounded_before_zipfile_reads_it(tmp_path, monkeypatch):
    target = tmp_path / "new.apks"
    write_split_apks(target)
    monkeypatch.setattr(inputs, "MAX_ZIP_ENTRIES", 7)  # the set has eight members
    refuse_zipfile(monkeypatch)
    with pytest.raises(ValueError, match="safe size/file-count"):
        analyze_apks(target, DEFAULT_DEVICE, unexpected_member)


def test_selected_apk_directory_is_bounded_before_zipfile_reads_it(tmp_path, budget, monkeypatch):
    raw_toc, paths = split_toc()
    target = tmp_path / "new.apks"
    with zipfile.ZipFile(target, "x", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("toc.pb", raw_toc)
        for name in paths:
            archive.writestr(name, _aliased_archive(9))
    assert len(paths) + 1 <= 8  # the outer set itself stays within the budget
    refuse_zipfile(monkeypatch, allow_paths=True)
    with pytest.raises(ValueError, match="safe size/file-count"):
        analyze_apks(target, DEFAULT_DEVICE, unexpected_member)


# --- Cleartext on devices below API 24 ----------------------------------------------------

NSC_BLOCKING = [
    ("network-security-config", {}, [("base-config", {"cleartextTrafficPermitted": "false"}, [])])
]
NSC_REF = {"networkSecurityConfig": "@xml/network_security_config"}
UNDECLARED = {**NSC_REF, "usesCleartextTraffic": None}  # None removes the fixture's default


def cleartext_checks(path: Path) -> list[tuple[str, str | None]]:
    findings = audit_apk(Apk(str(path)))[1]
    return [(item.status, item.severity) for item in findings if item.check_id == "app-cleartext"]


def legacy_warnings(path: Path) -> list:
    findings = audit_apk(Apk(str(path)))[1]
    return [item for item in findings if item.check_id == "app-cleartext" and item.status == "warn"]


def cleartext_severities(path: Path) -> list[str]:
    report = quaygate_analysis.analyze(path)
    return [item["severity"] for item in report["findings"] if item["rule_id"] == "QG-APP-CLEARTEXT"]


@pytest.mark.parametrize("min_sdk", ["21", "23"])
@pytest.mark.parametrize("target_sdk", ["28", "34"])
def test_undeclared_cleartext_is_reported_for_devices_below_api_24_whatever_the_target(min_sdk, target_sdk):
    sdk = {"minSdkVersion": min_sdk, "targetSdkVersion": target_sdk}
    with temp_apk(app_over=UNDECLARED, sdk_over=sdk, nsc=NSC_BLOCKING) as path:
        resolved = Path(path).resolve()
        # API 24+ follows the blocking configuration; API 21-23 ignore it and allow cleartext.
        assert cleartext_checks(resolved) == [("pass", None), ("warn", MEDIUM)]
        [legacy] = legacy_warnings(resolved)
        if min_sdk == "23":
            assert "API 23" in legacy.detail and f"targetSdk {target_sdk}" in legacy.detail
        else:
            assert "API 22 이하" in legacy.detail and "선언 없음" in legacy.detail
        assert cleartext_severities(resolved) == ["medium"]


def test_cleartext_below_api_24_keeps_explicit_and_modern_outcomes():
    with temp_apk(app_over=UNDECLARED, sdk_over={"minSdkVersion": "24"}, nsc=NSC_BLOCKING) as path:
        assert cleartext_checks(Path(path).resolve()) == [("pass", None)]
    # API 23 devices honor an explicit false; minSdk 23 excludes API 21-22 devices.
    blocked = {**NSC_REF, "usesCleartextTraffic": "false"}
    with temp_apk(app_over=blocked, sdk_over={"minSdkVersion": "23"}, nsc=NSC_BLOCKING) as path:
        assert cleartext_checks(Path(path).resolve()) == [("pass", None)]
    allowed = {**NSC_REF, "usesCleartextTraffic": "true"}
    for min_sdk in ("21", "23"):
        with temp_apk(app_over=allowed, sdk_over={"minSdkVersion": min_sdk}, nsc=NSC_BLOCKING) as path:
            assert cleartext_checks(Path(path).resolve()) == [("pass", None), ("warn", MEDIUM)]


# usesCleartextTraffic exists from API 23 and networkSecurityConfig from API 24, so API 21-22
# devices permit cleartext whatever either says.
BLOCKED = {**NSC_REF, "usesCleartextTraffic": "false"}


@pytest.mark.parametrize(
    "sdk",
    [
        {"minSdkVersion": "21"},
        {"minSdkVersion": "22", "targetSdkVersion": "28"},
        # Without minSdkVersion, Android's default minimum is 1.
        {"minSdkVersion": None},
    ],
    ids=["min21", "min22", "undeclared-min"],
)
def test_explicit_false_still_allows_cleartext_on_api_21_and_22_devices(sdk):
    with temp_apk(app_over=BLOCKED, sdk_over=sdk, nsc=NSC_BLOCKING) as path:
        resolved = Path(path).resolve()
        assert cleartext_checks(resolved) == [("pass", None), ("warn", MEDIUM)]
        [legacy] = legacy_warnings(resolved)
        assert "API 22 이하" in legacy.detail and "선언값(false)" in legacy.detail
        # Setting false cannot fix it: only a higher minSdk does.
        assert "minSdk를 23 이상" in legacy.recommendation and "24 이상" in legacy.recommendation
        assert cleartext_severities(resolved) == ["medium"]


def test_unresolved_cleartext_below_api_23_warns_and_keeps_the_api_23_gap():
    unresolved = {**NSC_REF, "usesCleartextTraffic": "@2130837504"}
    with temp_apk(app_over=unresolved, sdk_over={"minSdkVersion": "21"}, nsc=NSC_BLOCKING) as path:
        resolved = Path(path).resolve()
        assert cleartext_checks(resolved) == [("pass", None), ("warn", MEDIUM), ("na", None)]
        report = quaygate_analysis.analyze(resolved)
    assert [f["severity"] for f in report["findings"] if f["rule_id"] == "QG-APP-CLEARTEXT"] == ["medium"]
    [state] = [item["state"] for item in report["coverage"] if item["rule_id"] == "QG-APP-CLEARTEXT"]
    assert state == "partial"


def test_a_non_integer_min_sdk_adds_no_api_21_22_warning():
    # A compiled minSdkVersion that is not an integer is a preview codename, above API 22.
    with temp_apk(app_over=BLOCKED, sdk_over={"minSdkVersion": "S"}, nsc=NSC_BLOCKING) as path:
        assert cleartext_checks(Path(path).resolve()) == [("pass", None)]
    # The existing conservative check below API 24 still reports an undeclared value.
    with temp_apk(app_over=UNDECLARED, sdk_over={"minSdkVersion": "S"}, nsc=NSC_BLOCKING) as path:
        resolved = Path(path).resolve()
        assert cleartext_checks(resolved) == [("pass", None), ("warn", MEDIUM)]
        assert "API 22 이하" not in legacy_warnings(resolved)[0].detail


# --- SARIF credential redaction stays linear ----------------------------------------------

# The 1.7.0 release-candidate pattern, kept only as the reference for equivalence.
WORD_BOUNDARY_CREDENTIAL = re.compile(
    r"(?i)\b([\w.-]*(?:token|secret|password|passwd|pwd|api[_-]?key|auth)[\w.-]*\s*[=:]\s*)[^\s,;]+"
)
SAMPLES = [
    "token=abc",
    "my.api-key = abc123, .token=zzz; x=password=1",
    "-.-Secret:  s3cr3t",
    "x=token=abc",
    "token= ,",
    "token\n=\nvalue",
    "no.credential.here=1",
    "authorization: Bearer abc",
    "a.token.b",
    "API_KEY=1;PWD=2,passwd:3",
    "tokKen=kelvin",
    "é.token=è",
    "token token=1 token",
    "..--=token",
]


@pytest.mark.parametrize("text", SAMPLES)
def test_credential_redaction_keeps_the_earlier_matches(text):
    assert CREDENTIAL.sub(r"\1[REDACTED]", text) == WORD_BOUNDARY_CREDENTIAL.sub(r"\1[REDACTED]", text)


def test_credential_redaction_is_linear_on_long_key_runs():
    adversarial = [
        "a.token." * 300,
        "a-token-" * 300,
        "x.password." * 220,
        "a." * 1200,
        "token" * 480,
        "a.token." * 299 + "=value",
    ]
    started = time.perf_counter()
    for _ in range(20):
        for text in adversarial:
            _text(text)
    # Each call took over a second with the word-boundary pattern; now well under a millisecond.
    assert time.perf_counter() - started < 2.0
    assert CREDENTIAL.sub(r"\1[REDACTED]", "a.token." * 299 + "a=value").endswith(".a=[REDACTED]")


# --- Markdown fences around report JSON ---------------------------------------------------


def markdown_report(evidence: list[dict]) -> dict:
    return {
        "id": "audit_synthetic",
        "created": "2026-11-01T00:00:00+00:00",
        "target": "/synthetic/app",
        "rule_version": "synthetic",
        "inventory": {"platforms": [], "fingerprint": "0" * 64, "input_kind": "source"},
        "summary": {},
        "scope": "Synthetic scope.",
        "findings": [
            {
                "id": "F-1",
                "title": "Synthetic candidate",
                "severity": "high",
                "status": "candidate",
                "masvs": "MASVS-CODE",
                "remediation": "Review.",
                "evidence": evidence,
                "references": [],
            }
        ],
        "coverage": [{"rule_id": "X", "state": "checked", "note": "```\n# Coverage heading\n```"}],
        "intel_snapshot": [{"source": "osv", "title": "````"}],
        "warnings": [],
    }


EXCERPT = "x = 1\n```\n# Injected heading\n````\n<img src=x> ``` ## Separator heading"


def fenced_blocks(text: str) -> list[tuple[str, str]]:
    """(fence, body) per fenced block, splitting on every Unicode line boundary."""
    blocks, lines, index = [], text.splitlines(), 0
    while index < len(lines):
        opening = re.fullmatch(r"(`{3,})json", lines[index])
        if opening is None:
            index += 1
            continue
        fence, body = opening.group(1), []
        index += 1
        while not re.fullmatch(rf"`{{{len(fence)},}}\s*", lines[index]):
            body.append(lines[index])
            index += 1
        blocks.append((fence, "\n".join(body)))
        index += 1
    return blocks


def test_report_json_blocks_are_fenced_longer_than_any_backtick_run_inside():
    evidence = [{"path": "App.kt", "line": 3, "excerpt": EXCERPT}]
    report = markdown_report(evidence)
    text = markdown(report)
    blocks = fenced_blocks(text)
    assert len(blocks) == 4
    for fence, body in blocks:
        assert len(fence) > max(map(len, re.findall(r"`+", body)), default=0)
    # Each block is still the exact JSON, with line separators escaped rather than raw.
    assert [json.loads(body) for _, body in blocks] == [
        evidence,
        [],
        report["coverage"],
        report["intel_snapshot"],
    ]
    assert " " not in text and "\\u2028" in text
    assert [line for line in text.splitlines() if line.startswith("#")] == [
        "# APSA (앱사)",
        "## Findings",
        "### Synthetic candidate",
        "## OS/environment advisories",
        "## Coverage",
        "## OWASP MASWE coverage",
        "## Intelligence provenance",
        "## Limitations",
    ]


def test_report_json_blocks_render_as_one_code_block_each():
    markdown_it = pytest.importorskip("markdown_it")
    html = markdown_it.MarkdownIt("commonmark").render(
        markdown(markdown_report([{"path": "App.kt", "excerpt": EXCERPT}]))
    )
    assert html.count("<pre>") == 4
    assert "Injected heading</h" not in html and "Separator heading</h" not in html
    assert "Coverage heading</h" not in html and "<img" not in html
