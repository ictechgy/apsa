"""Standard-library-only audit completeness contract shared with the Action.

Optional not-run checks are visible abstentions, not incomplete execution. The
latest runtime entry is the current runtime assessment; earlier attempts remain
history. Completeness is recomputed from evidence so refreshed reports do not
retain a stale cached summary.

Coverage separates two kinds of shortfall. ``partial`` is an execution gap:
something in the stated scope was not examined (a budget, a parse error or
lossy adaptation, a skipped file, truncated input). ``limited`` is a precision
limit: everything in scope was examined, but the bounded static model abstained
on some paths. Only execution gaps make a report incomplete by default; strict
coverage also counts precision limits.
"""

from __future__ import annotations


def _file_state(item: object, *, strict: bool) -> bool:
    # A "skipped" file row is a recognized source dropped before analysis (a
    # budget, an unavailable grammar, a parser failure): never a benign skip.
    if not isinstance(item, dict) or item.get("state") in {"partial", "skipped"} or item.get("partial"):
        return True
    return strict and item.get("state") == "limited"


def analysis_incomplete(inventory: dict, *, strict: bool = False) -> bool:
    """Preserve explicit source/hybrid partial or malformed analysis evidence.

    With ``strict``, a ``limited`` source or hybrid file also counts.
    """
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
        if strict and analysis.get("state") == "limited":
            return True
        if analysis.get("input_observations_truncated"):
            return True
        files = analysis.get("files", [])
        if not isinstance(files, list) or any(_file_state(item, strict=strict) for item in files):
            return True
    return False


def _coverage(report: dict) -> list:
    coverage = report.get("coverage")
    return coverage if isinstance(coverage, list) else []


def report_incomplete(report: dict, *, strict: bool = False) -> bool:
    """Return whether explicit evidence says the stated audit scope is partial.

    ``limited`` coverage (a precision limit of the bounded model) is complete
    for the stated scope unless ``strict`` is set.
    """
    if not isinstance(report, dict):
        return False
    runtime = report.get("runtime", [])
    online = report.get("online_query", {})
    inventory = report.get("inventory", {})
    inventory = inventory if isinstance(inventory, dict) else {}
    snapshot = inventory.get("input_snapshot")
    snapshot = snapshot if isinstance(snapshot, dict) else {}
    states = {"partial", "limited"} if strict else {"partial"}
    return bool(
        report.get("partial") is True
        or inventory.get("partial") is True
        or inventory.get("fingerprint_complete") is False
        or snapshot.get("partial") is True
        or snapshot.get("app_scope_complete") is False
        or analysis_incomplete(inventory, strict=strict)
        or any(isinstance(check, dict) and check.get("state") in states for check in _coverage(report))
        or (
            isinstance(runtime, list)
            and runtime
            and isinstance(runtime[-1], dict)
            and runtime[-1].get("partial") is True
        )
        or (isinstance(online, dict) and online.get("requested") and online.get("errors"))
    )


def report_limited(report: dict) -> bool:
    """Whether coverage or source/hybrid files record a precision limit (``limited``)."""
    if not isinstance(report, dict):
        return False
    if any(isinstance(check, dict) and check.get("state") == "limited" for check in _coverage(report)):
        return True
    inventory = report.get("inventory", {})
    inventory = inventory if isinstance(inventory, dict) else {}
    for key in ("source_analysis", "hybrid_analysis"):
        analysis = inventory.get(key)
        if not isinstance(analysis, dict):
            continue
        if analysis.get("state") == "limited":
            return True
        files = analysis.get("files", [])
        if isinstance(files, list) and any(
            isinstance(item, dict) and item.get("state") == "limited" for item in files
        ):
            return True
    return False
