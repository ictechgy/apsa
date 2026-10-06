"""점검 결과 리포트(텍스트/JSON)와 종료 코드."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from . import __version__
from .checks import SEVERITY_LABEL, SEVERITY_ORDER, STATUS_LABEL


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _sanitize(value) -> str:
    """APK 유래 문자열의 제어문자·개행·ANSI 시퀀스를 제거해 리포트 한 줄이 여러 줄로
    위조되지 않게 한다(CI 로그 무결성 — 가짜 '통과'/'요약' 줄 생성 방지)."""
    if not isinstance(value, str):
        return value
    cleaned = _CONTROL_RE.sub("", _ANSI_RE.sub("", value))  # ANSI 시퀀스 먼저(ESC 제거 전)
    return cleaned.replace("\r", " ").replace("\n", " ")


def _sort_key(finding):
    status_bucket = {"fail": 0, "error": 0, "warn": 0, "info": 1, "na": 2, "pass": 3}.get(finding.status, 2)
    return (status_bucket, SEVERITY_ORDER.get(finding.severity, 9), finding.check_id)


def summarize(findings: list) -> dict:
    counts = {"fail": 0, "warn": 0, "info": 0, "na": 0, "error": 0, "pass": 0}
    for f in findings:
        counts[f.status] = counts.get(f.status, 0) + 1
    return counts


def exit_code(findings: list) -> int:
    return 1 if any(f.status in ("fail", "error") for f in findings) else 0


def format_finding(finding) -> str:
    status_label = STATUS_LABEL.get(finding.status, finding.status or "?")
    if finding.status in ("pass", "na", "error"):
        head = f"[{status_label}] {_sanitize(finding.title)} ({finding.check_id})"
    else:
        head = (f"[{SEVERITY_LABEL.get(finding.severity, '?')}/{status_label}] "
                f"{_sanitize(finding.title)} ({finding.check_id})")
    lines = [head]
    if finding.detail:
        lines.append(f"    {_sanitize(finding.detail)}")
    if finding.recommendation:
        lines.append(f"    권장: {_sanitize(finding.recommendation)}")
    return "\n".join(lines)


def render_text(device_desc: str, findings: list) -> str:
    counts = summarize(findings)
    out = [f"대상: {device_desc}", ""]
    for f in sorted(findings, key=_sort_key):
        out.append(format_finding(f))
        out.append("")
    out.append("요약: " + " · ".join(f"{STATUS_LABEL.get(k, k)} {v}" for k, v in counts.items() if v))
    return "\n".join(out)


def render_json(meta: dict, findings: list) -> str:
    payload = {
        "tool": "apsa",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": meta,
        "summary": summarize(findings),
        "findings": [vars(f) for f in sorted(findings, key=_sort_key)],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, default=str)


def _sarif_level_kind(status: str):
    """kind는 위반 여부(fail=규칙 위반), level은 심각도 — GitHub UI 표시는 level을 따른다.

    §3.27.10의 "kind≠fail이면 level=none" 제약과 GitHub이 level=none을 숨긴다는 사실을
    함께 고려해, 사람이 봐야 하는 warn/info는 kind=fail에 level로 심각도를 표현한다.
    """
    if status in ("fail", "error"):
        return "error", "fail"
    if status == "warn":
        return "warning", "fail"
    return "note", "fail"


def render_sarif(target_uri: str, findings: list) -> str:
    """SARIF 2.1.0 — GitHub code scanning 업로드용. pass/na는 결과에서 제외한다."""
    rules = {}
    results = []
    for f in findings:
        if f.status not in ("fail", "error", "warn", "info"):
            continue
        rules.setdefault(f.check_id, {"id": f.check_id,
                                      "shortDescription": {"text": f.title}})
        message = f.detail or f.title
        if f.recommendation:
            message += " — 권장: " + f.recommendation
        level, kind = _sarif_level_kind(f.status)
        results.append({
            "ruleId": f.check_id,
            "kind": kind,
            "level": level,
            "message": {"text": message},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": target_uri},
            }}],
            "properties": {"severity": f.severity, "status": f.status},
        })
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "apsa",
                    "version": __version__,
                    "rules": [rules[k] for k in sorted(rules)],
                },
            },
            "results": results,
        }],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
