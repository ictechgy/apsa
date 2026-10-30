"""Repeated omissions stay visible without thousands of duplicate diagnostics."""

from mobile_audit import hybrid_analysis


def test_large_budget_omission_keeps_each_file_and_retained_findings(monkeypatch):
    monkeypatch.setattr(hybrid_analysis, "MAX_BYTES", 100)
    sources = [(f"large-{index:04}.js", " " * 101) for index in range(250)]
    sources.append(("app.js", "const value = route.params.url; web.loadUrl(value);"))
    result = hybrid_analysis.analyze_hybrid(sources)
    assert len(result["findings"]) == 1
    files = result["metadata"]["files"]
    skipped = [row for row in files if row["analysis_state"] == "skipped"]
    assert len(files) == 251 and len(skipped) == 250
    assert {row["reason"] for row in skipped} == {"hybrid byte budget reached"}
    warnings = [row for row in result["warnings"] if "byte budget" in row]
    assert len(warnings) == 1 and "250 files" in warnings[0]
    assert "coverage incomplete" in warnings[0]
    assert all(row["state"] == "partial" for row in result["coverage"])
    assert result["metadata"]["file_warning_counts"] == [
        {"kind": "analysis incomplete", "reason": "hybrid byte budget reached", "files": 250}
    ]
    assert result == hybrid_analysis.analyze_hybrid(list(reversed(sources)))


def test_repeated_unsupported_binary_observations_keep_exact_scope():
    observed = [
        {"path": f"assets/{index}.bundle", "reason": "compiled bytecode unsupported"} for index in range(120)
    ]
    result = hybrid_analysis.analyze_hybrid([], observed)
    assert len(result["metadata"]["files"]) == 120
    assert result["metadata"]["complete"] is False
    assert len(result["warnings"]) == 1 and "120 files" in result["warnings"][0]
    assert all(row["analysis_state"] == "skipped" for row in result["metadata"]["files"])


def test_small_diagnostic_keeps_path_and_reason():
    result = hybrid_analysis.analyze_hybrid([], [{"path": "assets/main.bundle", "reason": "binary content"}])
    assert result["warnings"] == ["Hybrid source not analyzed for assets/main.bundle: binary content"]
