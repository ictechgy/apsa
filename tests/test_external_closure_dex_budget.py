"""Aggregate multidex output omission cannot become checked absence."""

from pathlib import Path

import pytest

from mobile_audit import quaygate_analysis
from quaygate import dexcode
from tests.helpers import build_code_dex, temp_apk


class SyntheticApk:
    def entry_names(self):
        return ["classes.dex", "classes2.dex"]

    def read(self, name):
        return name.encode()


@pytest.mark.parametrize("category", ["weak_crypto", "webview", "dynamic"])
@pytest.mark.parametrize("mode", ["over", "exact", "duplicates"])
def test_global_category_limit_has_truthful_scope(monkeypatch, category, mode):
    monkeypatch.setattr(dexcode, "MAX_FINDINGS", 3)

    def analyze(raw, **kwargs):
        first = raw == b"classes.dex"
        values = ["a", "b"] if first or mode == "duplicates" else ["c", "d"] if mode == "over" else ["c"]
        return {
            "scanned": 1,
            "instructions": 1,
            "metadata_entries": 1,
            "complete": True,
            "reasons": [],
            **{key: values if key == category else [] for key in ("weak_crypto", "webview", "dynamic")},
        }

    monkeypatch.setattr(dexcode, "analyze_dex", analyze)
    result = dexcode.scan_apk(SyntheticApk())
    assert result["available"] is True and result["failed"] == 0
    assert result["entries"] == result["scanned"] == 2
    assert len(result[category]) == (2 if mode == "duplicates" else 3)
    assert result["complete"] is (mode != "over")
    assert result.get("reasons", []) == (["aggregate finding budget"] if mode == "over" else [])
    assert all(not result[key] for key in ("weak_crypto", "webview", "dynamic") if key != category)


@pytest.mark.parametrize("limit", [1, 2])
def test_actual_multidex_output_budget_is_partial_and_retains_positive(monkeypatch, limit):
    monkeypatch.setattr(dexcode, "MAX_FINDINGS", limit)
    first = build_code_dex(
        [("Lfixture/First;", "run", "Ljava/security/MessageDigest;", "getInstance", "MD5")]
    )
    second = build_code_dex(
        [("Lfixture/Second;", "run", "Ljava/security/MessageDigest;", "getInstance", "MD5")]
    )
    with temp_apk(files={"classes.dex": first, "classes2.dex": second}, v1=False) as path:
        result = quaygate_analysis.analyze(Path(path).resolve())
    scope = next(row for row in result["coverage"] if row["rule_id"] == "QG-DEX-BYTECODE-SCOPE")
    assert scope["state"] == ("partial" if limit == 1 else "not-applicable")
    assert result["metadata"]["complete"] is (limit == 2)
    finding = next(row for row in result["findings"] if row["rule_id"] == "QG-DEX-WEAK-CRYPTO")
    assert finding["status"] == "candidate"
    assert "MessageDigest.getInstance" in str(finding["evidence"])
    if limit == 1:
        assert "확인된 호출" in str(finding["evidence"])
        assert "Quaygate check incomplete: QG-DEX-BYTECODE-SCOPE" in result["warnings"]
