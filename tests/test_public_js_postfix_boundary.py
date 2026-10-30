import pytest

from mobile_audit.hybrid_analysis import analyze_hybrid


@pytest.mark.parametrize("extension", ["js", "ts", "jsx", "tsx", "dart"])
@pytest.mark.parametrize("expression", ["count++", "count--", "++count", "--count"])
@pytest.mark.parametrize("terminator", ["", ";"])
def test_update_expression_at_function_body_tail_retains_observed_flow(extension, expression, terminator):
    if extension == "dart":
        signature = "void execute()"
        assignment = 'final value = Uri.base.queryParameters["url"];'
    else:
        signature = "function execute()"
        assignment = "const value = route.params.url;"
    source = f"{signature} {{ {assignment} web.loadUrl(value); {expression}{terminator} }}"

    result = analyze_hybrid([(f"App.{extension}", source)])

    assert [finding["rule_id"] for finding in result["findings"]] == ["HYBRID-UNTRUSTED-URL"]
    assert result["metadata"]["files"][0]["analysis_state"] == "analyzed"
    assert result["metadata"]["files"][0]["flow_state"] == "bounded-modeled"
    assert not result["warnings"]
    assert all(item["state"] == "partial" for item in result["coverage"])


@pytest.mark.parametrize("extension", ["js", "ts", "jsx", "tsx", "dart"])
@pytest.mark.parametrize("expression", ["clean++", "clean--", "++clean", "--clean"])
@pytest.mark.parametrize("terminator", ["", ";"])
def test_updated_callable_at_body_tail_cannot_erase_argument_taint(extension, expression, terminator):
    if extension == "dart":
        declaration = 'String clean(String value) { return "https://safe.example"; }'
        signature = "void execute()"
        assignment = 'final value = Uri.base.queryParameters["url"];'
    else:
        declaration = 'function clean(value) { return "https://safe.example"; }'
        signature = "function execute()"
        assignment = "const value = route.params.url;"
    source = (
        f"{declaration} {signature} {{ {assignment} web.loadUrl(clean(value)); {expression}{terminator} }}"
    )

    result = analyze_hybrid([(f"App.{extension}", source)])

    assert any(finding["rule_id"] == "HYBRID-UNTRUSTED-URL" for finding in result["findings"])
    assert result["metadata"]["files"][0]["analysis_state"] == "analyzed"
    assert any("callable identity unresolved or shadowed" in warning for warning in result["warnings"])
    assert not any(edge["callee"] == "clean" for edge in result["metadata"]["call_edges"])


@pytest.mark.parametrize("source", ["", "++", "--", "count++", "count--", "++count", "--count"])
def test_empty_or_incomplete_update_boundaries_do_not_escape_as_index_error(source):
    result = analyze_hybrid([("boundary.ts", source)])

    assert not result["findings"]
    assert all(item["state"] == "partial" for item in result["coverage"])
    assert not result["metadata"]["complete"]


@pytest.mark.parametrize("source", ["function execute() { count++", "function execute() { --count"])
def test_unbalanced_update_boundary_preserves_incomplete_diagnostic(source):
    result = analyze_hybrid([("boundary.ts", source)])

    assert result["metadata"]["files"][0]["analysis_state"] == "skipped"
    assert any("unbalanced hybrid source" in warning for warning in result["warnings"])
    assert not result["metadata"]["complete"]
