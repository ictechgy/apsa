"""Indexed implicit-receiver writes must reach HTML through the actual payload."""

from __future__ import annotations

import pytest

from mobile_audit.source_analysis import Analyzer, analyze_sources

URL = "AST-WEBVIEW-UNTRUSTED-URL"
INPUT = 'intent.getStringExtra("q") ?: ""'


def fixture(
    *,
    source: bool = True,
    fixed_urls: bool = False,
    target: str = "attributes",
    parameter: str = "",
    member: str = "",
    module: str = "",
    before: str = "",
    write: str = "",
) -> str:
    value = INPUT if source else '"fixed"'
    url = '"https://fixed.example/"' if fixed_urls else "null"
    assignment = write or f'{target}["data-q"] = q'
    return f"""package synthetic.html
import android.content.Intent
import android.database.sqlite.SQLiteDatabase
import android.webkit.WebView
import kotlinx.html.*
import kotlinx.html.stream.createHTML
{module}
class Screen(private val db: SQLiteDatabase, private val web: WebView{member}) {{
    fun show(intent: Intent, admin: Boolean{parameter}) {{
        val q = {value}
        val html = createHTML().div {{
            {before}
            {assignment}
            +"x"
        }}
        web.loadDataWithBaseURL({url}, html, "text/html", "utf-8", {url})
    }}
}}
"""


def scan(source: str) -> dict:
    return analyze_sources([("Html.kt", source)])


def hits(report: dict) -> list[dict]:
    return [finding for finding in report["findings"] if finding["rule_id"] == URL]


@pytest.mark.parametrize("source", [True, False], ids=["intent", "constant"])
@pytest.mark.parametrize("fixed_urls", [False, True], ids=["null-urls", "fixed-urls"])
@pytest.mark.parametrize("target", ["attributes", "this.attributes"], ids=["implicit", "explicit-this"])
def test_indexed_receiver_property_reaches_the_actual_html_argument(
    monkeypatch: pytest.MonkeyPatch,
    source: bool,
    fixed_urls: bool,
    target: str,
) -> None:
    arguments = []
    check_call = Analyzer.check_call

    def inspect(self, call, frame, guards, conditions):
        if call.name == "loadDataWithBaseURL":
            # check_call runs with reuse_visited: this reads retained argument
            # values and does not execute a second call or closure.
            arguments.append([self.value(argument, frame) for argument in call.args])
        return check_call(self, call, frame, guards, conditions)

    monkeypatch.setattr(Analyzer, "check_call", inspect)
    report = scan(fixture(source=source, fixed_urls=fixed_urls, target=target))
    assert bool(hits(report)) is source, report
    assert arguments, report
    assert all(not values[0].traces and not values[4].traces for values in arguments), report
    assert all(bool(values[1].traces) is source for values in arguments), report
    assert not report["metadata"]["native_flow"]["budget_reasons"], report
    # Unknown external DSL calls retain their established bounded-model limits.
    assert report["metadata"]["native_flow"]["precision_reasons"], report


@pytest.mark.parametrize(
    "options",
    [
        {"parameter": ", attributes: MutableMap<String, String>"},
        {"member": ", private val attributes: MutableMap<String, String>"},
        {"module": "val attributes: MutableMap<String, String> = externalMap()"},
        {"parameter": ", existing: MutableMap<String, String>", "before": "val attributes = existing"},
    ],
    ids=["parameter-map", "constructor-field-map", "module-map", "local-map"],
)
def test_bound_map_write_is_not_an_implicit_html_receiver_write(options: dict) -> None:
    report = scan(fixture(**options))
    assert not hits(report), report
    assert not report["metadata"]["native_flow"]["budget_reasons"], report


@pytest.mark.parametrize("scope", ["with", "apply"])
@pytest.mark.parametrize("target", ["this.attributes", "attributes"])
def test_rebound_scope_receiver_is_not_the_enclosing_html_receiver(scope: str, target: str) -> None:
    write = f'{target}["data-q"] = q'
    write = f"with(existing) {{ {write} }}" if scope == "with" else f"existing.apply {{ {write} }}"
    report = scan(
        fixture(
            parameter=", existing: Holder",
            module="class Holder(val attributes: MutableMap<String, String>)",
            write=write,
        )
    )
    assert not hits(report), report
    assert not report["metadata"]["native_flow"]["budget_reasons"], report


def test_imported_module_map_alias_is_not_an_implicit_receiver_property() -> None:
    report = analyze_sources(
        [
            ("Html.kt", fixture(module="import helpers.entries as attributes")),
            ("Maps.kt", "package helpers\nval entries: MutableMap<String, String> = externalMap()"),
        ]
    )
    assert not hits(report), report
    assert not report["metadata"]["native_flow"]["budget_reasons"], report


def test_explicit_external_import_is_not_assumed_to_be_a_receiver_property() -> None:
    report = scan(fixture(module="import external.attributes"))
    assert not hits(report), report
    assert not report["metadata"]["native_flow"]["budget_reasons"], report


def test_existing_unary_html_content_control_stays_supported() -> None:
    report = scan(fixture(write="+q"))
    assert hits(report), report
    assert not report["metadata"]["native_flow"]["budget_reasons"], report
