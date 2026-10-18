"""Fresh reports preserve byte budgets, exclusion provenance and exact-target reuse."""

from __future__ import annotations

import copy
import json

import pytest

from mobile_audit import audit, cli
from mobile_audit import store as store_module
from mobile_audit.core import MAX_FILE, now, read_json


def report(target, identifier="owned-report", payload=""):
    return {"id": identifier, "created": now(), "target": str(target), "payload": payload}


def test_report_larger_than_input_limit_verifies_and_saves_idempotently(store, tmp_path):
    value = report(tmp_path / "new-source", payload="x" * (MAX_FILE + 1024))
    store.save_report(value)
    exported = store.home / "reports" / f"{value['id']}.json"
    assert exported.stat().st_size > MAX_FILE
    with pytest.raises(ValueError, match="File exceeds"):
        read_json(exported)
    assert store.report(value["id"]) == value
    assert store.verify_reports() == {"checked": 1, "failures": [], "state": "passed"}
    identity = exported.stat().st_ino
    assert store.save_report(value) == value
    assert exported.stat().st_ino == identity
    assert store.verify_reports()["state"] == "passed"


def test_report_exact_utf8_export_limit_rejects_before_transaction_or_export(store, tmp_path, monkeypatch):
    value = report(tmp_path / "new-source", payload="가" * 100)
    size = len((json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode())
    monkeypatch.setattr(store_module, "MAX_REPORT_BYTES", size - 1)
    calls = []
    monkeypatch.setattr(store_module, "write_json", lambda *args: calls.append(args))
    with pytest.raises(ValueError, match="Report export exceeds"):
        store.save_report(value)
    assert not calls and not store.db.in_transaction
    assert store.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 0
    assert not (store.home / "reports" / f"{value['id']}.json").exists()


def seed_exact_and_children(store, tmp_path):
    target = (tmp_path / "new-source").resolve()
    target.mkdir()
    original = report(target, "owned-exact")
    store.save_report(original)
    for index in range(51):
        store.save_report(report(target / f"module-{index}", f"owned-child-{index}"))
    return target, original


def test_cli_verification_reuses_exact_target_beyond_child_window(store, tmp_path, monkeypatch):
    target, original = seed_exact_and_children(store, tmp_path)
    monkeypatch.setattr(cli, "scan", lambda *args, **kwargs: pytest.fail("Unexpected rescan"))
    monkeypatch.setattr("mobile_audit.verify.verify_claim", lambda value, **kwargs: {"id": value["id"]})
    result, code = cli.dispatch(
        cli.parser().parse_args(["verify", str(target), "--rule", "AST-PATH-TRAVERSAL"]), store
    )
    assert code == 0 and isinstance(result, dict)
    assert result["id"] == original["id"]
    assert store.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 52


def test_mcp_verification_reuses_exact_target_beyond_child_window(store, tmp_path, monkeypatch):
    from mobile_audit import mcp_server

    target, original = seed_exact_and_children(store, tmp_path)
    monkeypatch.setattr(mcp_server, "scan", lambda *args, **kwargs: pytest.fail("Unexpected rescan"))
    monkeypatch.setattr(mcp_server, "verify_claim", lambda value, **kwargs: {"id": value["id"]})
    server = mcp_server.create_server(store.home, roots=[tmp_path])
    tool = server._tool_manager.get_tool("verify_finding")
    assert tool is not None
    assert tool.fn(str(target), rule="AST-PATH-TRAVERSAL")["id"] == original["id"]
    assert store.db.execute("SELECT count(*) FROM reports").fetchone()[0] == 52


@pytest.mark.parametrize("mode", ["auto", "legacy", "batch"])
def test_offline_exclusion_overrides_cached_checked_without_transmission(store, tmp_path, monkeypatch, mode):
    dependencies = [
        dict(name=name, ecosystem="PyPI", version="1.0", confidence="exact", path="owned.lock")
        for name in ["private-owned", "public-owned"]
    ]
    store.upsert_intel(
        [
            {
                "id": "CVE-2099-8524",
                "source": "osv:PyPI:private-owned:1.0",
                "title": "Synthetic cached advisory",
                "severity": "critical",
                "query_match": {"name": "private-owned", "ecosystem": "PyPI", "version": "1.0"},
            }
        ]
    )
    inventory = {"target": str(tmp_path), "platforms": [], "dependencies": dependencies, "warnings": []}
    monkeypatch.setattr(
        audit,
        "analyze_target",
        lambda *args, **kwargs: {"inventory": copy.deepcopy(inventory), "findings": [], "coverage": []},
    )
    monkeypatch.setattr(
        audit, "query_dependencies", lambda *args, **kwargs: pytest.fail("Offline network path")
    )
    monkeypatch.setattr(
        audit,
        "source_health",
        lambda _: [
            dict(source=f"osv:PyPI:{dep['name']}:1.0", status="ok", stale=False) for dep in dependencies
        ],
    )
    value = audit.scan(store, tmp_path, osv_policy={"exclude_names": ["private-*"]}, osv_query_mode=mode)
    rows = {row["dependency"]["name"]: row for row in value["coverage"] if "dependency" in row}
    assert rows["private-owned"]["state"] == "not-run"
    assert rows["public-owned"]["state"] == "checked"
    query = value["inventory"]["dependency_query"]
    assert query["online"] is False and query["mode"] == mode
    assert query["transmission_exclusions"] == {"exclude_names": ["private-*"]}
    assert query["packages"] == [
        dict(
            ecosystem="PyPI",
            name="private-owned",
            version="1.0",
            state="excluded",
            checked=False,
            transmitted=False,
        )
    ]
    assert value["online_query"] == {"requested": False, "errors": []}
    assert any(
        item["rule_id"] == "CVE-2099-8524" and item["severity"] == "critical" for item in value["findings"]
    )
    assert store.report(value["id"]) == value
