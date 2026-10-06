from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from cvss import CVSS2, CVSS3, CVSS4

from . import __version__
from .core import digest, now, redact
from .store import Store

SOURCES = {
    "kev": "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
    "apple": "https://support.apple.com/en-us/100100",
    "android": "https://source.android.com/docs/security/bulletin/asb-overview",
    "cve": "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json",
    "owasp": "https://mas.owasp.org/MASTG/tests/",
}
DEFAULT_SOURCES = ["kev", "apple", "android", "cve", "owasp"]
OSV_ECOSYSTEMS = {"Maven", "npm", "PyPI", "Go", "Pub", "SwiftURL"}
MAX_REMOTE_BYTES = 16 * 1024 * 1024
MAX_DELTA_BYTES = 32 * 1024 * 1024
MAX_JSON_NODES = 200_000
MAX_OSV_PAGES = 5
MAX_OSV_RECORDS = 1000


def _object(value: Any, label: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"Malformed {label}: expected an object")
    return value


def _list(value: Any, label: str) -> list:
    if not isinstance(value, list):
        raise ValueError(f"Malformed {label}: expected a list")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Malformed {label}: expected a string")
    return value


def _json_limits(value: Any) -> None:
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 30 or count > MAX_JSON_NODES:
            raise ValueError("Remote JSON nesting/item budget exceeded")
        if isinstance(item, dict):
            if count + len(pending) + len(item) > MAX_JSON_NODES:
                raise ValueError("Remote JSON nesting/item budget exceeded")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            if count + len(pending) + len(item) > MAX_JSON_NODES:
                raise ValueError("Remote JSON nesting/item budget exceeded")
            pending.extend((child, depth + 1) for child in item)


def _invalid_json_number(value: str):
    raise ValueError(f"Invalid JSON number: {value}")


def _load_json(raw: bytes) -> Any:
    try:
        value = json.loads(raw, parse_constant=_invalid_json_number)
    except RecursionError as error:
        raise ValueError("Remote JSON nesting budget exceeded") from error
    _json_limits(value)
    return value


def _timestamp(value: Any, label: str) -> datetime:
    text = _text(value, label)
    stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError(f"Malformed {label}: timestamp needs a timezone")
    return stamp.astimezone(timezone.utc)


def _provenance(record: dict, url: str, content_hash: str) -> dict:
    return {**record, "provenance": {"document_url": url, "content_hash": content_hash}}


class Fetcher:
    def __init__(self, client: httpx.Client | None = None):
        self.client = client or httpx.Client(
            timeout=25,
            follow_redirects=True,
            headers={"User-Agent": f"MobileAudit/{__version__} (+local security audit)"},
        )
        self.owned = client is None
        self.hashes: list[str] = []

    def request(
        self, method: str, url: str, max_bytes: int | None = None, payload: dict | None = None
    ) -> bytes:
        max_bytes = MAX_REMOTE_BYTES if max_bytes is None else max_bytes
        with self.client.stream(method, url, json=payload) as response:
            response.raise_for_status()
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > max_bytes:
                raise ValueError("Remote document exceeds size limit")
            body = bytearray()
            for chunk in response.iter_bytes(chunk_size=65536):
                if len(body) + len(chunk) > max_bytes:
                    raise ValueError("Remote document exceeds size limit")
                body.extend(chunk)
        result = bytes(body)
        self.hashes.append(digest(result))
        return result

    def get(self, url: str, max_bytes: int | None = None) -> bytes:
        return self.request("GET", url, max_bytes)

    def json(self, url: str) -> dict | list:
        return _load_json(self.get(url))

    def post_json(self, url: str, payload: dict) -> dict:
        return _object(_load_json(self.request("POST", url, payload=payload)), "OSV response")

    def json_object(self, url: str) -> dict:
        value = self.json(url)
        if not isinstance(value, dict):
            raise ValueError("Expected a JSON object from the official CVE endpoint")
        return value

    def close(self):
        if self.owned:
            self.client.close()


def normalize_kev(value: dict) -> list[dict]:
    value = _object(value, "KEV document")
    records = []
    for entry in _list(value.get("vulnerabilities"), "KEV vulnerabilities"):
        item = _object(entry, "KEV vulnerability")
        for field in (
            "cveID",
            "vulnerabilityName",
            "vendorProject",
            "product",
            "shortDescription",
            "dateAdded",
            "requiredAction",
        ):
            _text(item.get(field, ""), f"KEV {field}")
        for field in ("vendorProject", "product"):
            if not item.get(field, "").strip():
                raise ValueError(f"Missing or empty KEV {field}")
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", item.get("cveID", "")):
            raise ValueError("Missing or invalid KEV CVE ID")
        if not item.get("vulnerabilityName"):
            raise ValueError("Missing KEV vulnerability name")
        if not any(
            word in (item.get("vendorProject", "") + " " + item.get("product", "")).lower()
            for word in ("apple", "android", "chromium", "qualcomm", "pixel", "webkit")
        ):
            continue
        records.append(
            {
                "id": item["cveID"],
                "source": "kev",
                "title": item["vulnerabilityName"],
                "description": item.get("shortDescription", ""),
                "vendor": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "modified": item.get("dateAdded", ""),
                "known_exploited": True,
                "required_action": item.get("requiredAction", ""),
                "references": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
                "affected": [],
            }
        )
    return records


def normalize_cve(value: dict) -> dict:
    value = _object(value, "CVE document")
    _json_limits(value)
    metadata = value.get("cveMetadata", {})
    containers = value.get("containers", {})
    if not isinstance(metadata, dict) or not isinstance(containers, dict):
        raise ValueError("Malformed CVE metadata or containers")
    cna = containers.get("cna", {})
    if not isinstance(cna, dict):
        raise ValueError("Malformed CVE CNA object")
    identifier = metadata.get("cveId", "")
    if not isinstance(identifier, str) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
        raise ValueError("Missing or invalid CVE ID")
    for key in ("descriptions", "affected", "references", "metrics"):
        entries = cna.get(key, [])
        if not isinstance(entries, list) or any(not isinstance(e, dict) for e in entries):
            raise ValueError(f"Malformed CVE CNA {key} list")
    descriptions = cna.get("descriptions", [])
    for entry in descriptions:
        _text(entry.get("lang", ""), "CVE description lang")
        _text(entry.get("value", ""), "CVE description value")
    for reference in cna.get("references", []):
        _text(reference.get("url", ""), "CVE reference URL")
    for product in cna.get("affected", []):
        for field in ("vendor", "product", "defaultStatus"):
            if field in product:
                _text(product[field], f"CVE affected {field}")
        for version in _list(product.get("versions", []), "CVE affected versions"):
            version = _object(version, "CVE affected version")
            for field in ("version", "status", "versionType", "lessThan", "lessThanOrEqual"):
                if field in version:
                    _text(version[field], f"CVE version {field}")
            for change in _list(version.get("changes", []), "CVE version changes"):
                change = _object(change, "CVE version change")
                _text(change.get("at", ""), "CVE version change at")
                _text(change.get("status", ""), "CVE version change status")
    for key in ("title",):
        _text(cna.get(key, ""), f"CVE CNA {key}")
    for key in ("dateUpdated", "state"):
        _text(metadata.get(key, ""), f"CVE metadata {key}")
    description = next((d.get("value", "") for d in descriptions if d.get("lang", "").startswith("en")), "")
    return {
        "id": identifier,
        "source": "cve",
        "title": cna.get("title", identifier),
        "description": description,
        "modified": metadata.get("dateUpdated", ""),
        "state": metadata.get("state", "PUBLISHED"),
        "affected": cna.get("affected", []),
        "references": [r["url"] for r in cna.get("references", []) if "url" in r],
        "metrics": cna.get("metrics", []),
    }


def cve_url(identifier: str) -> str:
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
        raise ValueError("Expected CVE-YYYY-NNNN identifier")
    _, year, number = identifier.split("-")
    return f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{number[:-3]}xxx/{identifier}.json"


def parse_apple(html: bytes, url: str, label: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    content = soup.select_one("article") or soup
    full = content.get_text(" ", strip=True)
    released = re.search(r"Released\s+([A-Za-z]+ \d{1,2}, \d{4})", full)
    records = []
    seen = set()
    for node in content.find_all(["p", "li"]):
        text = node.get_text(" ", strip=True)
        ids = re.findall(r"CVE-\d{4}-\d{4,}", text)
        if not ids:
            continue
        heading = node.find_previous(["h2", "h3"])
        component = heading.get_text(" ", strip=True) if heading else "Unknown component"
        section = []
        for previous in node.previous_siblings:
            if getattr(previous, "name", None) in {"h2", "h3"}:
                break
            if getattr(previous, "get_text", None):
                section.insert(0, previous.get_text(" ", strip=True))
        context = " ".join(section + [text])
        for identifier in ids:
            branch = (identifier, component)
            if branch in seen:
                continue
            seen.add(branch)
            records.append(
                {
                    "id": identifier,
                    "source": "apple",
                    "title": f"{component}: {label}",
                    "description": context[:4000],
                    "component": component,
                    "platform": "ios",
                    "fixed_release": label,
                    "modified": released[1] if released else "",
                    "exploitation_reported": "may have been exploited" in context.lower()
                    or "actively exploited" in context.lower(),
                    "references": [url],
                    "affected": [],
                }
            )
    if not records and not re.search(r"no (?:published )?CVE entries", full, re.I):
        raise ValueError("Apple advisory format changed; CVEs could not be attributed to components")
    return records


def parse_android(html: bytes, url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    records = []
    seen = set()
    for row in soup.select("tr"):
        cells = row.find_all(["td", "th"])
        if not cells:
            continue
        identifiers = re.findall(r"CVE-\d{4}-\d{4,}", cells[0].get_text())
        component = row.find_previous("h3")
        patch_heading = row.find_previous("h2")
        patch = re.search(r"20\d\d-\d\d-\d\d", patch_heading.get_text()) if patch_heading else None
        heading = row.find_previous("table")
        headers = (
            [
                c.get_text(" ", strip=True).lower()
                for c in heading.select("tr:first-child th, tr:first-child td")
            ]
            if heading
            else []
        )
        mapping = dict(zip(headers, [c.get_text(" ", strip=True) for c in cells], strict=False))
        for identifier in identifiers:
            branch = (
                identifier,
                component.get_text(" ", strip=True) if component else "",
                patch[0] if patch else "",
                mapping.get("updated aosp versions", ""),
            )
            if branch in seen:
                continue
            seen.add(branch)
            records.append(
                {
                    "id": identifier,
                    "source": "android",
                    "title": f"Android {component.get_text(' ', strip=True) if component else 'component'}: {identifier}",
                    "platform": "android",
                    "component": component.get_text(" ", strip=True) if component else "",
                    "fixed_patch_level": patch[0] if patch else "",
                    "updated_aosp_versions": mapping.get("updated aosp versions", ""),
                    "severity": mapping.get("severity", "unknown").lower(),
                    "description": row.get_text(" ", strip=True),
                    "modified": patch[0] if patch else "",
                    "references": [url] + [urljoin(url, str(a["href"])) for a in row.select("a[href]")],
                    "affected": [],
                }
            )
    if not records:
        raise ValueError("No CVE rows found in Android bulletin")
    return records


def parse_owasp(html: bytes, url: str) -> list[dict]:
    soup = BeautifulSoup(html, "html.parser")
    records = []
    for row in soup.select("tr"):
        text = row.get_text(" ", strip=True)
        identifier = re.search(r"MASTG-TEST-\d{4}", text)
        if not identifier:
            continue
        link = row.select_one("a[href]")
        records.append(
            {
                "id": identifier[0],
                "source": "owasp",
                "title": link.get_text(" ", strip=True) if link else text,
                "status": "deprecated"
                if "deprecated" in text
                else "placeholder"
                if "placeholder" in text
                else "current",
                "description": text,
                "modified": "",
                "references": [urljoin(url, str(link["href"]))] if link else [url],
            }
        )
    if not records:
        raise ValueError("OWASP test catalog parsing failed")
    return records


def _skip_json_whitespace(text: str, cursor: int) -> int:
    while cursor < len(text) and text[cursor] in " \t\n\r":
        cursor += 1
    return cursor


def _delta_entries(raw: bytes) -> Iterator[Any]:
    # deltaLog currently contains thousands of independent updates (~24 MiB).
    # Decode each top-level entry independently: a catalog-wide object/node cap
    # would reject valid history, while materializing the full tree wastes memory.
    text = raw.decode("utf-8-sig")
    cursor = _skip_json_whitespace(text, 0)
    if cursor >= len(text) or text[cursor] != "[":
        yield _load_json(raw)
        return
    decoder = json.JSONDecoder(parse_constant=_invalid_json_number)
    cursor += 1
    cursor = _skip_json_whitespace(text, cursor)
    if cursor < len(text) and text[cursor] == "]":
        cursor += 1
    else:
        while True:
            try:
                entry, cursor = decoder.raw_decode(text, cursor)
            except RecursionError as error:
                raise ValueError("CVE delta entry nesting budget exceeded") from error
            _json_limits(entry)
            yield entry
            cursor = _skip_json_whitespace(text, cursor)
            if cursor >= len(text):
                raise ValueError("Truncated CVE delta array")
            if text[cursor] == "]":
                cursor += 1
                break
            if text[cursor] != ",":
                raise ValueError("Malformed CVE delta array separator")
            cursor = _skip_json_whitespace(text, cursor + 1)
    if _skip_json_whitespace(text, cursor) != len(text):
        raise ValueError("Unexpected data after CVE delta array")


def _delta_candidates(entries: Iterable[Any], cutoff: str) -> tuple[list[tuple[str, str, int]], str]:
    cutoff_time = _timestamp(cutoff, "CVE delta cursor")
    newest = cutoff_time
    candidates = []
    for entry in entries:
        entry = _object(entry, "CVE delta entry")
        fetched = _timestamp(entry.get("fetchTime", ""), "CVE delta fetchTime")
        for key in ("new", "updated"):
            for item in _list(entry.get(key, []), f"CVE delta {key}"):
                if isinstance(item, dict):
                    identifier = _text(item.get("cveId", ""), "CVE delta cveId")
                    revision = (
                        _text(item.get("dateUpdated", entry["fetchTime"]), "CVE delta dateUpdated")
                        or entry["fetchTime"]
                    )
                else:
                    identifier = _text(item, "CVE delta identifier")
                    revision = entry["fetchTime"]
                if not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier):
                    raise ValueError("Missing or invalid CVE delta identifier")
                if fetched >= cutoff_time:
                    candidates.append((identifier, revision, 1))
        newest = max(newest, fetched)
    return candidates, newest.isoformat()


def _retry_after(error: httpx.HTTPStatusError) -> int | None:
    value = error.response.headers.get("Retry-After", "")
    if value.isdigit():
        return min(86_400, int(value))
    if value:
        try:
            date = parsedate_to_datetime(value)
            return min(86_400, max(0, int((date - datetime.now(timezone.utc)).total_seconds())))
        except (ValueError, TypeError, OverflowError):
            pass
    return 300 if error.response.status_code == 404 else None


def sync(store: Store, sources: list[str] | None = None, limit=8, client: httpx.Client | None = None) -> dict:
    if not 1 <= limit <= 50:
        raise ValueError("Feed limit must be between 1 and 50")
    changed = []
    results = []
    fetcher = Fetcher(client)
    try:
        for source in sources or DEFAULT_SOURCES:
            fetcher.hashes.clear()
            try:
                completed_jobs = []
                job_errors = []
                advisory_urls = []
                if source not in SOURCES:
                    raise ValueError(f"Unknown source: {source}")
                raw = fetcher.get(
                    SOURCES[source], max_bytes=MAX_DELTA_BYTES if source == "cve" else MAX_REMOTE_BYTES
                )
                document_hash = fetcher.hashes[-1]
                records = []
                if source == "kev":
                    records = [
                        _provenance(record, SOURCES[source], document_hash)
                        for record in normalize_kev(_load_json(raw))
                    ]
                elif source == "owasp":
                    records = [
                        _provenance(record, SOURCES[source], document_hash)
                        for record in parse_owasp(raw, SOURCES[source])
                    ]
                elif source in {"apple", "android"}:
                    soup = BeautifulSoup(raw, "html.parser")
                    links = []
                    for anchor in soup.select("a[href]"):
                        label = anchor.get_text(" ", strip=True)
                        url = urljoin(SOURCES[source], str(anchor["href"]))
                        if (
                            source == "apple"
                            and label.startswith(("iOS ", "iPadOS "))
                            and re.fullmatch(r"https://support\.apple\.com/(?:[a-zA-Z-]+/)?\d+", url)
                        ):
                            links.append((url, label))
                        elif (
                            source == "android"
                            and urlparse(url).scheme == "https"
                            and urlparse(url).hostname == "source.android.com"
                            and re.search(r"/bulletin/(?:\d{4}/)?\d{4}-\d{2}-\d{2}$", url)
                        ):
                            links.append((url, label))
                    unique_links = list(dict.fromkeys(links))[:limit]
                    advisory_urls = [url for url, _ in unique_links]
                    if not unique_links:
                        raise ValueError(f"No {source} advisory links found")
                    for url, label in unique_links:
                        html = fetcher.get(url)
                        parsed = (
                            parse_apple(html, url, label) if source == "apple" else parse_android(html, url)
                        )
                        records.extend(_provenance(record, url, fetcher.hashes[-1]) for record in parsed)
                elif source == "cve":
                    cutoff = (
                        store.cursor("cve-delta")
                        or (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
                    )
                    candidates, newest = _delta_candidates(_delta_entries(raw), cutoff)
                    # Official CVE data also enriches mobile IDs already discovered in vendor/KEV feeds.
                    mobile_ids = [
                        (r["id"], r.get("modified", ""), 0)
                        for r in store.intelligence(limit=5000)
                        if r["source"] in {"apple", "android", "kev"}
                    ]
                    store.enqueue_cves(mobile_ids + candidates)
                    store.set_cursor("cve-delta", newest)
                    for job in store.pending_cves(limit * 10):
                        identifier = job["id"]
                        try:
                            url = cve_url(identifier)
                            record = normalize_cve(fetcher.json_object(url))
                            if record["id"] != identifier:
                                raise ValueError("CVE endpoint returned a different identifier")
                            record = _provenance(record, url, fetcher.hashes[-1])
                        except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                            message = redact(f"{type(error).__name__}: {error}")[:300]
                            delay = _retry_after(error) if isinstance(error, httpx.HTTPStatusError) else None
                            store.retry_cve(identifier, job["revision"], message, retry_after=delay)
                            job_errors.append({"id": identifier, "error": message})
                            continue
                        searchable = json.dumps(record).lower()
                        if record.get("state") == "REJECTED" or any(
                            word in searchable
                            for word in ("android", "apple", "ios", "webkit", "chromium", "qualcomm")
                        ):
                            records.append(record)
                        completed_jobs.append((identifier, job["revision"]))
                if source in {"kev", "owasp"}:
                    updates = store.replace_source(source, records)
                elif source in {"apple", "android"}:
                    updates = store.replace_vendor_documents(source, records, advisory_urls)
                else:
                    updates = store.upsert_intel(records)
                for identifier, revision in completed_jobs:
                    store.finish_cve(identifier, revision)
                changed.extend(updates)
                source_hash = digest("".join(fetcher.hashes).encode())
                backlog = store.pending_count() if source == "cve" else 0
                status = "partial" if job_errors or backlog else "ok"
                store.feed(
                    source,
                    status,
                    len(records),
                    error=f"{backlog} CVEs remain queued; {len(job_errors)} attempts await retry"
                    if backlog
                    else "",
                    content_hash=source_hash,
                    fetched=True,
                )
                results.append(
                    {"source": source, "status": status, "records": len(records), "changed": len(updates)}
                )
                if source == "cve":
                    results[-1]["pending"] = store.pending_count()
                    results[-1]["retried"] = len(job_errors)
                    if job_errors:
                        results[-1]["errors"] = job_errors[:20]
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                # Persist failure independently. A failed sync never clears a usable cache.
                message = redact(f"{type(error).__name__}: {error}")[:300]
                store.feed(source, "error", error=message)
                results.append({"source": source, "status": "error", "error": message})
    finally:
        fetcher.close()
    result = {
        "sources": results,
        "changed_ids": sorted(set(changed)),
        "partial": any(r["status"] != "ok" for r in results),
        "collected_at": now(),
        "scope": f"Most recent {limit} vendor advisories; first CVE sync bootstraps the last day of delta updates. Pending CVEs persist across polls; not the complete historical catalog.",
    }
    store.event("intel-sync", result)
    return result


def _osv_severity(vuln: dict) -> dict:
    ratings = []
    metrics = _list(vuln.get("severity", []), "OSV severity")
    for metric in metrics:
        metric = _object(metric, "OSV severity metric")
        type_ = _text(metric.get("type", ""), "OSV severity type")
        vector = _text(metric.get("score", ""), "OSV severity score")
        calculator = {"CVSS_V2": CVSS2, "CVSS_V3": CVSS3, "CVSS_V4": CVSS4}.get(type_)
        if calculator is None or len(vector) > 2000:
            continue
        try:
            score = calculator(vector).scores()[0]
        except Exception:
            continue  # Invalid vectors are preserved, never promoted to a known rating.
        severity = (
            "critical"
            if score >= 9
            else "high"
            if score >= 7
            else "medium"
            if score >= 4
            else "low"
            if score > 0
            else "info"
        )
        ratings.append((score, severity, type_))
    declared = _object(vuln.get("database_specific", {}), "OSV database_specific").get("severity", "")
    if isinstance(declared, str) and declared.lower() == "moderate":
        declared = "medium"
    if isinstance(declared, str) and declared.lower() in {"critical", "high", "medium", "low", "info"}:
        rank_score = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0}[declared.lower()]
        ratings.append((rank_score, declared.lower(), "database_specific.severity"))
    selected = max(ratings) if ratings else (None, None, "unknown")
    return {"severity": selected[1], "severity_basis": selected[2], "severity_metrics": metrics}


def _normalize_osv(value: Any, dep: dict) -> dict:
    vuln = _object(value, "OSV vulnerability")
    osv_id = _text(vuln.get("id", ""), "OSV id")
    if not osv_id:
        raise ValueError("Missing OSV vulnerability id")
    aliases = [_text(alias, "OSV alias") for alias in _list(vuln.get("aliases", []), "OSV aliases")]
    identifier = next((alias for alias in aliases if re.fullmatch(r"CVE-\d{4}-\d{4,}", alias)), osv_id)
    for field in ("summary", "details", "modified"):
        _text(vuln.get(field, ""), f"OSV {field}")
    if vuln.get("withdrawn") is not None:
        _text(vuln["withdrawn"], "OSV withdrawn")
    references = []
    for reference in _list(vuln.get("references", []), "OSV references"):
        references.append(_text(_object(reference, "OSV reference").get("url", ""), "OSV reference URL"))
    affected = _list(vuln.get("affected", []), "OSV affected")
    for product in affected:
        product = _object(product, "OSV affected product")
        package = _object(product.get("package", {}), "OSV affected package")
        for field in ("name", "ecosystem", "purl"):
            if field in package:
                _text(package[field], f"OSV package {field}")
        for version in _list(product.get("versions", []), "OSV affected versions"):
            _text(version, "OSV affected version")
        for range_ in _list(product.get("ranges", []), "OSV affected ranges"):
            range_ = _object(range_, "OSV affected range")
            for event in _list(range_.get("events", []), "OSV range events"):
                event = _object(event, "OSV range event")
                for value in event.values():
                    _text(value, "OSV event version")
    return {
        "id": identifier,
        "source": f"osv:{dep['ecosystem']}:{dep['name']}:{dep['version']}",
        "title": vuln.get("summary", identifier),
        "description": vuln.get("details", "")[:8000],
        "modified": vuln.get("modified", ""),
        "withdrawn": vuln.get("withdrawn"),
        "affected": affected,
        "references": references,
        "query_match": {key: dep[key] for key in ("name", "ecosystem", "version")},
        "osv_id": osv_id,
        **_osv_severity(vuln),
    }


def query_dependencies(
    store: Store, dependencies: list[dict], client: httpx.Client | None = None
) -> tuple[list[dict], list[str]]:
    fetcher = Fetcher(client)
    found = []
    errors = []
    unique = {}
    for index, dep in enumerate(dependencies):
        if index >= 10_000:
            errors.append("Dependency input limit reached; remaining packages not checked")
            break
        if not isinstance(dep, dict) or any(
            not isinstance(dep.get(key), str) for key in ("ecosystem", "name", "version")
        ):
            errors.append("Malformed dependency requires string ecosystem, name and version")
            continue
        unique[(dep["ecosystem"], dep["name"], dep["version"])] = dep
    try:
        for dep in list(unique.values())[:100]:
            if (
                dep["ecosystem"] not in OSV_ECOSYSTEMS
                or dep.get("confidence", "unknown") == "unknown"
                or not dep["version"]
            ):
                errors.append(
                    f"Unresolved/unsupported dependency: {dep['ecosystem']} {dep['name']} {dep['version']}"
                )
                continue
            try:
                fetcher.hashes.clear()
                endpoint = "https://api.osv.dev/v1/query"
                payload = {
                    "package": {"name": dep["name"], "ecosystem": dep["ecosystem"]},
                    "version": dep["version"],
                }
                package_records = []
                tokens = set()
                complete = False
                for _ in range(MAX_OSV_PAGES):
                    value = fetcher.post_json(endpoint, payload)
                    if value and not ({"vulns", "next_page_token"} & value.keys()):
                        raise ValueError("Malformed OSV response: no vulnerability or pagination fields")
                    vulns = _list(value.get("vulns", []), "OSV response vulnerabilities")
                    remaining = MAX_OSV_RECORDS - len(package_records)
                    package_records.extend(
                        _provenance(_normalize_osv(vuln, dep), endpoint, fetcher.hashes[-1])
                        for vuln in vulns[:remaining]
                    )
                    token = _text(value.get("next_page_token", ""), "OSV page token")
                    if len(vulns) <= remaining and not token:
                        complete = True
                        break
                    if len(vulns) > remaining or len(package_records) >= MAX_OSV_RECORDS:
                        break
                    if token in tokens or not token:
                        raise ValueError("OSV pagination did not advance")
                    tokens.add(token)
                    payload["page_token"] = token
                source = f"osv:{dep['ecosystem']}:{dep['name']}:{dep['version']}"
                if complete:
                    store.replace_source(source, package_records)
                else:
                    # A bounded/paginated subset cannot retire prior matches.
                    store.upsert_intel(package_records)
                    errors.append(
                        f"OSV query incomplete for {dep['name']}: page/record budget reached; cached matches retained"
                    )
                found.extend(package_records)
                store.feed(
                    source,
                    "ok" if complete else "partial",
                    len(package_records),
                    error="" if complete else errors[-1],
                    content_hash=digest("".join(fetcher.hashes).encode()),
                )
            except (httpx.HTTPError, ValueError, KeyError, TypeError) as error:
                errors.append(f"OSV query failed for {dep['name']}: {type(error).__name__}")
                store.feed(
                    f"osv:{dep['ecosystem']}:{dep['name']}:{dep['version']}", "error", error=errors[-1]
                )
        if len(unique) > 100:
            errors.append("Dependency query limit of 100 reached; remaining packages not checked")
    finally:
        fetcher.close()
    return found, errors


def fetch_record(store: Store, identifier: str, client: httpx.Client | None = None) -> list[dict]:
    fetcher = Fetcher(client)
    try:
        url = cve_url(identifier)
        record = normalize_cve(fetcher.json_object(url))
        if record["id"] != identifier:
            raise ValueError("CVE endpoint returned a different identifier")
        store.upsert_intel([_provenance(record, url, fetcher.hashes[-1])])
    finally:
        fetcher.close()
    return store.intel_by_id(identifier)


def source_health(store: Store) -> list[dict]:
    output = []
    feeds = {feed["source"]: feed for feed in store.feeds()}
    for source in sorted(set(DEFAULT_SOURCES) | set(feeds)):
        feed = dict(
            feeds.get(
                source,
                {
                    "source": source,
                    "attempted": None,
                    "succeeded": None,
                    "status": "never-synced",
                    "count": 0,
                    "error": "",
                    "content_hash": "",
                },
            )
        )
        feed["required"] = source in DEFAULT_SOURCES
        if source == "cve":
            feed["pending"] = store.pending_count()
            feed["retrying"] = store.db.execute(
                "SELECT count(*) FROM cve_queue WHERE state='pending' AND last_error!=''"
            ).fetchone()[0]
        if feed["required"]:
            feed["url"] = SOURCES[source]
        succeeded = feed.get("fetched_ok") if source == "cve" else feed["succeeded"]
        try:
            feed["stale"] = not succeeded or _timestamp(succeeded, "feed succeeded") < datetime.now(
                timezone.utc
            ) - timedelta(days=1)
        except (ValueError, TypeError):
            feed["stale"] = True
            feed["error"] = "Malformed cached feed success timestamp"
        output.append(feed)
    return output
