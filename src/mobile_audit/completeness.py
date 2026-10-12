"""Standard-library-only audit completeness contract shared with the Action.

Optional not-run checks are visible abstentions, not incomplete execution. The
latest runtime entry is the current runtime assessment; earlier attempts remain
history. Completeness is recomputed from evidence so refreshed reports do not
retain a stale cached summary.
"""

from __future__ import annotations


def analysis_incomplete(inventory: dict) -> bool:
    """Preserve explicit source/hybrid partial or malformed analysis evidence."""
    if inventory.get("hybrid_inputs_truncated") or inventory.get("hybrid_input_inventory_complete") is False:
        return True
    for key in ("source_analysis", "hybrid_analysis"):
        analysis = inventory.get(key)
        if analysis is None:
            continue
        if not isinstance(analysis, dict):
            return True
        if analysis.get("partial") or analysis.get("state") == "partial":
            return True
        if analysis.get("input_observations_truncated"):
            return True
        files = analysis.get("files", [])
        if not isinstance(files, list) or any(
            not isinstance(item, dict) or item.get("state") == "partial" or item.get("partial")
            for item in files
        ):
            return True
    return False


def report_incomplete(report: dict) -> bool:
    """Return whether explicit evidence says the stated audit scope is partial."""
    if not isinstance(report, dict):
        return False
    runtime = report.get("runtime", [])
    online = report.get("online_query", {})
    inventory = report.get("inventory", {})
    inventory = inventory if isinstance(inventory, dict) else {}
    snapshot = inventory.get("input_snapshot")
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    coverage = report.get("coverage")
    coverage = coverage if isinstance(coverage, list) else []
    return bool(
        report.get("partial") is True
        or inventory.get("partial") is True
        or inventory.get("fingerprint_complete") is False
        or snapshot.get("partial") is True
        or snapshot.get("app_scope_complete") is False
        or analysis_incomplete(inventory)
        or any(isinstance(check, dict) and check.get("state") == "partial" for check in coverage)
        or (
            isinstance(runtime, list)
            and runtime
            and isinstance(runtime[-1], dict)
            and runtime[-1].get("partial") is True
        )
        or (isinstance(online, dict) and online.get("requested") and online.get("errors"))
    )
