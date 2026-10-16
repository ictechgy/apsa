"""Reassess cached targets without implicit dependency uploads or duplicate history."""

from __future__ import annotations

from .audit import refresh_report
from .core import redact
from .intel import query_dependencies
from .store import Store


def _meaningful(report: dict) -> dict:
    return {
        key: report.get(key)
        for key in ("findings", "coverage", "environment_advisories", "warnings", "online_query")
    } | {
        "dependency_query": report.get("inventory", {}).get("dependency_query"),
        "intel_snapshot": [
            {key: value for key, value in feed.items() if key not in {"attempted", "succeeded", "fetched_ok"}}
            for feed in report.get("intel_snapshot", [])
        ],
    }


def reassess_targets(store: Store, *, online=False) -> dict:
    latest = {}
    for report in store.reports(10000):
        latest.setdefault(report["target"], report["id"])
    saved, errors = [], []
    for identifier in latest.values():
        try:
            prior = store.report(identifier)
            failures = []
            query = None
            if online:
                states: list[dict] = []
                _, failures = query_dependencies(
                    store, prior["inventory"]["dependencies"], package_states=states
                )
                query = {"mode": "auto", "packages": states, "transmission_exclusions": {}}
            current = refresh_report(
                store,
                identifier,
                save=False,
                dependency_query=query,
                online_query={"requested": True, "errors": failures} if online else None,
            )
            if _meaningful(prior) != _meaningful(current):
                saved.append(store.save_report(current)["id"])
            errors.extend({"report_id": identifier, "error": redact(message)} for message in failures)
        except Exception as error:
            errors.append({"report_id": identifier, "error": redact(str(error))[:800]})
    return {"reaudited_reports": saved, "reaudit_errors": errors}
