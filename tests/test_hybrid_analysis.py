from mobile_audit.hybrid_analysis import analyze_hybrid


def test_hybrid_direct_sources_and_literal_controls():
    result = analyze_hybrid(
        [
            (
                "App.js",
                'const value = route.params.url; web.loadUrl(value); web.loadUrl("https://safe.example");',
            ),
            (
                "main.dart",
                'void go() { final value = Uri.base.queryParameters["next"]; controller.loadRequest(value); }',
            ),
        ]
    )
    assert [(f["rule_id"], f["evidence"][0]["path"]) for f in result["findings"]] == [
        ("HYBRID-UNTRUSTED-URL", "App.js"),
        ("HYBRID-UNTRUSTED-URL", "main.dart"),
    ]
    assert all(c["state"] == "partial" for c in result["coverage"])


def test_hybrid_cross_file_arguments_returns_and_order():
    sources = [
        (
            "helper.ts",
            "export function forward(value: string) { return value; } function execute(value: string) { eval(value); }",
        ),
        (
            "app.ts",
            'import { forward, execute } from "./helper"; const value = route.params.code; web.loadUrl(forward(value)); execute(value);',
        ),
    ]
    first, second = analyze_hybrid(sources), analyze_hybrid(list(reversed(sources)))
    assert first == second
    assert {f["rule_id"] for f in first["findings"]} == {"HYBRID-UNTRUSTED-URL", "HYBRID-JS-EVAL"}
    sink = next(f for f in first["findings"] if f["rule_id"] == "HYBRID-JS-EVAL")
    assert sink["evidence"][0]["path"] == "helper.ts"
    assert sink["evidence"][0]["source"]["path"] == "app.ts"


def test_hybrid_bridge_is_candidate_and_arguments_remain_observed():
    result = analyze_hybrid(
        [("bridge.js", "const value = window.location.hash; NativeModules.Files.open(value);")]
    )
    assert len(result["findings"]) == 1
    assert result["findings"][0]["rule_id"] == "HYBRID-NATIVE-BRIDGE"
    assert result["findings"][0]["status"] == "candidate"


def test_hybrid_malformed_and_budget_are_visible(monkeypatch):
    import mobile_audit.hybrid_analysis as module

    result = analyze_hybrid([("broken.js", "function broken( {"), ("ok.js", "const safe = 1;")])
    assert result["warnings"]
    assert result["metadata"]["files"][0]["state"] == "partial"
    monkeypatch.setattr(module, "MAX_OPERATIONS", 2)
    result = analyze_hybrid([("source.js", "const value = route.params.url; web.loadUrl(value);")])
    assert any("operation budget" in note for note in result["warnings"])


def test_hybrid_unknown_helpers_do_not_establish_sanitization():
    result = analyze_hybrid(
        [("input.js", "const value = route.params.url; web.loadUrl(unmodeledCleaner(value));")]
    )
    assert result["findings"][0]["rule_id"] == "HYBRID-UNTRUSTED-URL"
