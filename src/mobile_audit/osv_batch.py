"""Bounded OSV batch queries, with failure state isolated per coordinate."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import httpx

from .core import digest
from .source_context import osv_package_name
from .store import Store

QUERY_ENDPOINT = "https://api.osv.dev/v1/querybatch"
RECORD_ENDPOINT = "https://api.osv.dev/v1/vulns/"


def validate_budgets(max_packages: int, batch_size: int, max_requests: int) -> None:
    for value, maximum in ((max_packages, 10000), (batch_size, 1000), (max_requests, 10000)):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ValueError("OSV request budgets must be positive bounded integers")


def query_batch(
    store: Store,
    dependencies: list[dict],
    client: httpx.Client | None = None,
    *,
    package_states: list[dict] | None = None,
    max_packages: int = 1000,
    batch_size: int = 100,
    max_requests: int = 2000,
) -> tuple[list[dict], list[str]]:
    from .intel import (
        MAX_OSV_PAGES,
        MAX_OSV_RECORDS,
        OSV_ECOSYSTEMS,
        Fetcher,
        _list,
        _normalize_osv,
        _object,
        _provenance,
        _text,
        _timestamp,
        source_health,
    )

    validate_budgets(max_packages, batch_size, max_requests)
    found, errors = [], []
    unique, originals = {}, {}
    rank = {"unknown": 0, "declared": 1, "exact": 2}
    state_rows = {}
    input_limited = set()

    def confidence_rank(dep: dict) -> int:
        confidence = dep.get("confidence", "unknown")
        return rank.get(confidence, 0) if isinstance(confidence, str) else 0

    def state(key, status, **extra):
        result = {
            "state": status,
            "checked": status in {"complete", "cached"},
            "transmitted": status in {"complete", "partial", "error"},
            **extra,
        }
        for dep in originals.get(key, []):
            dep["osv_query"] = dict(result)
        if package_states is not None:
            row = {"ecosystem": key[0], "name": key[1], "version": key[2], **result}
            if key in state_rows:
                package_states[state_rows[key]] = row
            else:
                state_rows[key] = len(package_states)
                package_states.append(row)

    for index, dep in enumerate(dependencies):
        if not isinstance(dep, dict) or any(
            not isinstance(dep.get(k), str) for k in ("ecosystem", "name", "version")
        ):
            errors.append("Malformed dependency requires string ecosystem, name and version")
            continue
        key = tuple(dep[k] for k in ("ecosystem", "name", "version"))
        originals.setdefault(key, []).append(dep)
        if index >= 10000:
            input_limited.add(key)
            continue
        if key not in unique or confidence_rank(dep) > confidence_rank(unique[key]):
            unique[key] = dep
    for key in sorted(input_limited):
        state(key, "not-checked", reason="input-budget")
    if len(dependencies) > 10000:
        errors.append("Dependency input limit reached; remaining packages not checked")
    health = {feed["source"]: feed for feed in source_health(store)}
    margin = datetime.now(timezone.utc) - timedelta(hours=23)
    queue = []
    direct = {
        (d["ecosystem"], d["name"])
        for d in dependencies
        if isinstance(d, dict)
        and isinstance(d.get("name"), str)
        and isinstance(d.get("ecosystem"), str)
        and not str(d.get("version_source") or "").startswith("gradle-lockfile")
    }
    for key, dep in unique.items():
        if (dep.get("resolution") or {}).get("state") == "superseded-by-resolved-build":
            state(key, "superseded")
            continue
        if dep["ecosystem"] not in OSV_ECOSYSTEMS or confidence_rank(dep) == 0 or not dep["version"]:
            state(key, "unsupported")
            if len(errors) < 100:
                errors.append("Unresolved/unsupported dependency; not checked")
            continue
        feed = health.get(f"osv:{key[0]}:{key[1]}:{key[2]}")
        try:
            fresh = bool(
                feed
                and feed["status"] == "ok"
                and not feed["stale"]
                and _timestamp(feed["succeeded"], "feed succeeded") >= margin
            )
        except (ValueError, TypeError):
            fresh = False
        if fresh:
            state(key, "cached", freshness="less-than-23-hours")
            continue
        try:
            payload = {"package": {"name": osv_package_name(dep), "ecosystem": key[0]}, "version": key[2]}
        except (ValueError, TypeError):
            state(key, "unsupported", reason="repository-identity")
            errors.append("Unsupported dependency repository identity; not checked")
            continue
        queue.append(
            {
                "key": key,
                "dep": dep,
                "payload": payload,
                "ids": {},
                "hashes": [],
                "tokens": set(),
                "pages": 0,
                "records": [],
                "complete": False,
                "error": None,
                "transmitted": False,
            }
        )
    queue.sort(
        key=lambda item: (
            (item["key"][0], item["key"][1]) not in direct,
            -confidence_rank(item["dep"]),
        )
    )
    for item in queue[max_packages:]:
        state(item["key"], "not-checked", reason="package-budget")
    if len(queue) > max_packages:
        errors.append(
            f"Dependency query limit of {max_packages} reached; {len(queue) - max_packages} remaining packages not checked"
        )
    queue = queue[:max_packages]
    fetcher = Fetcher(client)
    requests = 0
    hydrated = {}
    failures = {}

    def request(method, endpoint, payload=None):
        nonlocal requests
        if requests >= max_requests:
            raise ValueError("OSV request budget reached")
        requests += 1
        if method == "POST":
            if not isinstance(payload, dict):
                raise ValueError("OSV batch request requires an object payload")
            value = fetcher.post_json(endpoint, payload)
        else:
            value = fetcher.json(endpoint)
        return value, fetcher.hashes[-1]

    try:
        for start in range(0, len(queue), batch_size):
            active = queue[start : start + batch_size]
            while active:
                try:
                    if requests < max_requests:
                        for item in active:
                            item["transmitted"] = True
                    value, content_hash = request(
                        "POST", QUERY_ENDPOINT, {"queries": [i["payload"] for i in active]}
                    )
                    value = _object(value, "OSV batch response")
                    # Position is the sole association mechanism in this API.
                    if set(value) != {"results"}:
                        raise ValueError("Malformed OSV batch response fields")
                    results = _list(value["results"], "OSV batch results")
                    if len(results) != len(active):
                        raise ValueError("OSV batch result count does not match request order")
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                    for item in active:
                        item["error"] = type(error).__name__
                    break
                pending = []
                for item, result in zip(active, results, strict=True):
                    item["pages"] += 1
                    item["hashes"].append(content_hash)
                    try:
                        result = _object(result, "OSV batch item")
                        if set(result) - {"vulns", "next_page_token"}:
                            raise ValueError("Malformed OSV batch item fields")
                        page = _list(result.get("vulns", []), "OSV batch vulnerabilities")
                        stubs = {}
                        for stub in page:
                            stub = _object(stub, "OSV vulnerability stub")
                            identifier = _text(stub.get("id"), "OSV stub id")
                            if (
                                not identifier
                                or len(identifier) > 256
                                or any(
                                    c
                                    not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
                                    for c in identifier
                                )
                            ):
                                raise ValueError("Invalid OSV stub identifier")
                            modified = _timestamp(stub.get("modified"), "OSV stub modified")
                            if identifier in stubs and stubs[identifier] != modified:
                                raise ValueError("Conflicting OSV stub modification timestamps")
                            stubs[identifier] = modified
                        token = _text(result.get("next_page_token", ""), "OSV page token")
                        if len(token) > 8192 or token and token in item["tokens"]:
                            raise ValueError("OSV pagination did not advance")
                        if any(
                            identifier in item["ids"] and item["ids"][identifier] != modified
                            for identifier, modified in stubs.items()
                        ):
                            raise ValueError("OSV record changed during pagination")
                        remaining = MAX_OSV_RECORDS - len(item["ids"])
                        new = [
                            (identifier, modified)
                            for identifier, modified in stubs.items()
                            if identifier not in item["ids"]
                        ]
                        item["ids"].update(new[:remaining])
                        if len(new) > remaining or (
                            token and (len(item["ids"]) >= MAX_OSV_RECORDS or item["pages"] >= MAX_OSV_PAGES)
                        ):
                            item["error"] = "page/record budget reached"
                        elif token:
                            item["tokens"].add(token)
                            item["payload"]["page_token"] = token
                            pending.append(item)
                        else:
                            item["complete"] = True
                    except (ValueError, KeyError, TypeError) as error:
                        item["error"] = type(error).__name__
                active = pending
        for item in queue:
            if not item["transmitted"]:
                state(item["key"], "not-checked", reason="request-budget")
                errors.append("OSV request budget reached; package not checked")
                continue
            query_hashes = list(item["hashes"])
            for identifier, modified in item["ids"].items():
                endpoint = RECORD_ENDPOINT + quote(identifier, safe="")
                try:
                    if identifier in failures:
                        raise ValueError("OSV hydration previously failed")
                    if identifier not in hydrated:
                        value, content_hash = request("GET", endpoint)
                        value = _object(value, "OSV hydrated record")
                        if value.get("id") != identifier:
                            raise ValueError("OSV record endpoint returned a different identifier")
                        hydrated[identifier] = value, content_hash
                    value, content_hash = hydrated[identifier]
                    if _timestamp(value.get("modified"), "OSV record modified") < modified:
                        raise ValueError("OSV hydrated record is older than query stub")
                    record = _provenance(_normalize_osv(value, item["dep"]), endpoint, content_hash)
                    record["provenance"]["query_url"] = QUERY_ENDPOINT
                    record["provenance"]["query_content_hashes"] = query_hashes
                    item["records"].append(record)
                    item["hashes"].append(content_hash)
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                    failures[identifier] = type(error).__name__
                    item["error"] = f"record hydration {type(error).__name__}"
            source = f"osv:{item['key'][0]}:{item['key'][1]}:{item['key'][2]}"
            complete = item["complete"] and item["error"] is None
            status = "complete" if complete else "partial" if item["pages"] or item["records"] else "error"
            if complete:
                store.replace_source(source, item["records"])
            else:
                store.upsert_intel(item["records"])
                # Error strings intentionally omit coordinate and remote exception text.
                errors.append(
                    f"OSV query incomplete for package: {item['error'] or 'budget reached'}; cached matches retained"
                )
            found.extend(item["records"])
            store.feed(
                source,
                "ok" if complete else status,
                len(item["records"]),
                error="" if complete else errors[-1],
                content_hash=digest("".join(item["hashes"]).encode()),
            )
            state(
                item["key"],
                status,
                pages=item["pages"],
                records=len(item["records"]),
                reason=item["error"] or "",
            )
    finally:
        fetcher.close()
    return found, errors
