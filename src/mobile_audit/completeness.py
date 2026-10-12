"""Standard-library-only audit completeness contract shared with the Action.

Optional not-run checks are visible abstentions, not incomplete execution. The
latest runtime entry is the current runtime assessment; earlier attempts remain
history. Completeness is recomputed from evidence so refreshed reports do not
retain a stale cached summary.
"""

from __future__ import annotations


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
        or any(isinstance(check, dict) and check.get("state") == "partial" for check in coverage)
        or (
            isinstance(runtime, list)
            and runtime
            and isinstance(runtime[-1], dict)
            and runtime[-1].get("partial") is True
        )
        or (isinstance(online, dict) and online.get("requested") and online.get("errors"))
    )
