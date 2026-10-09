"""Evaluate fixed public source snapshots and primary-evidence CVE labels.

Networked preparation/capture runs only on the disposable read-only workflow.
No upstream application code, build script, backend, or device is executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import stat
import statistics
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import httpx

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.competitive import (
    MobSF,
    apsa_observation,
    apsa_report,
    engine_metadata,
    mobsf_observation,
    observation_signature,
)
from mobile_audit.audit import correlate
from mobile_audit.inputs import TEXT_SUFFIXES
from mobile_audit.intel import normalize_cve, parse_android, parse_apple, query_dependencies
from mobile_audit.store import Store

HERE = Path(__file__).resolve().parent
SPEC = HERE / "real_world_cases.json"
PRIMARY = HERE / "real_world_advisories.json"
SCHEMA = "apsa-real-world-result-v1"
MAX_DOWNLOAD = 256 * 1024 * 1024
MAX_DOCUMENT = 4 * 1024 * 1024
MAX_RESPONSE = 16 * 1024 * 1024
PUBLIC_HOSTS = {"codeload.github.com", "github.com", "support.apple.com", "source.android.com"}


def sha(raw: bytes | bytearray) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def load_spec() -> dict:
    spec = json.loads(SPEC.read_text())
    if spec.get("schema") != "apsa-real-world-spec-v1":
        raise ValueError("Unknown evaluation specification")
    if len(spec["apps"]) != 6 or len(spec["dependency_cases"]) != 32 or len(spec["os_cases"]) != 11:
        raise ValueError("Frozen evaluation cardinality changed")
    for group in ("apps", "dependency_cases", "os_cases"):
        identifiers = [case["id"] for case in spec[group]]
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Duplicate frozen evaluation ID")
    return spec


def download(client: httpx.Client, url: str, path: Path, limit: int) -> dict:
    original = url
    for _ in range(6):
        parsed = httpx.URL(url)
        if parsed.scheme != "https" or parsed.host not in PUBLIC_HOSTS or parsed.port not in {443, None}:
            raise ValueError("Public benchmark download origin is not allowed")
        with client.stream("GET", url, follow_redirects=False) as response:
            if response.is_redirect:
                url = str(response.url.join(response.headers["location"]))
                continue
            response.raise_for_status()
            content = bytearray()
            for chunk in response.iter_bytes(65536):
                if len(content) + len(chunk) > limit:
                    raise ValueError("Public benchmark download exceeds byte limit")
                content.extend(chunk)
        path.write_bytes(content)
        return {"url": original, "resolved_url": url, "sha256": sha(content), "bytes": len(content)}
    raise ValueError("Public benchmark redirect budget exceeded")


def source_archive(upstream: Path, output: Path, app: dict) -> dict:
    """Repack unmodified text/configuration bytes; discard media, never execute code."""
    anchors = [app["config_label"], *app["dependencies"], *app.get("extra_anchors", [])]
    expected = {anchor["path"]: anchor["git_blob"] for anchor in anchors}
    observed = {}
    selected = []
    omitted = []
    with zipfile.ZipFile(upstream) as archive:
        items = archive.infolist()
        if len(items) > 50000 or sum(item.file_size for item in items) > 1024 * 1024 * 1024:
            raise ValueError("Upstream source archive exceeds enumeration/expansion budget")
        roots = {PurePosixPath(item.filename).parts[0] for item in items if item.filename}
        if len(roots) != 1:
            raise ValueError("Upstream source archive needs one repository root")
        names = set()
        total = 0
        for item in items:
            path = PurePosixPath(item.filename)
            if path.is_absolute() or ".." in path.parts or "\\" in item.filename:
                raise ValueError("Unsafe upstream source archive path")
            if item.is_dir():
                continue
            relative = PurePosixPath(*path.parts[1:])
            if not relative.parts or str(relative) in names:
                raise ValueError("Duplicate or root-level upstream source entry")
            names.add(str(relative))
            if stat.S_ISLNK(item.external_attr >> 16):
                omitted.append({"path": str(relative), "reason": "symlink"})
                continue
            if relative.suffix not in TEXT_SUFFIXES | {
                ".pbxproj",
                ".xcconfig",
                ".md",
            } and relative.name not in {
                "Package.resolved",
                "Podfile.lock",
                "LICENSE",
                "NOTICE",
                "COPYING",
                "Podfile",
                "Cartfile",
            }:
                continue
            if item.file_size > 8 * 1024 * 1024:
                omitted.append({"path": str(relative), "reason": "oversized source"})
                continue
            total += item.file_size
            if total > 512 * 1024 * 1024:
                raise ValueError("Selected source archive exceeds byte budget")
            raw = archive.read(item)
            if str(relative) in expected:
                observed[str(relative)] = hashlib.sha1(
                    b"blob " + str(len(raw)).encode() + b"\0" + raw
                ).hexdigest()
            selected.append((str(relative), raw))
    if observed != expected:
        raise ValueError("Frozen primary source/configuration anchors do not match upstream bytes")
    with zipfile.ZipFile(output, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(selected):
            entry = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, raw)
    return {
        "input": output.name,
        "sha256": sha(output.read_bytes()),
        "source_entries": len(selected),
        "source_bytes": total,
        "verified_git_blobs": observed,
        "omitted": omitted,
    }


def prepare(root: Path) -> dict:
    spec = load_spec()
    root.mkdir(parents=True, exist_ok=False)
    (root / "inputs").mkdir()
    (root / "primary").mkdir()
    prepared = []
    with httpx.Client(timeout=90, headers={"User-Agent": "APSA-public-source-benchmark"}) as client:
        for app in spec["apps"]:
            upstream = root / f"{app['id']}-upstream.zip"
            provenance = download(
                client,
                f"https://codeload.github.com/{app['repository']}/zip/{app['commit']}",
                upstream,
                MAX_DOWNLOAD,
            )
            entry = source_archive(upstream, root / "inputs" / f"{app['id']}.zip", app)
            upstream.unlink()
            prepared.append({"id": app["id"], **entry, "upstream": provenance})
            print(
                json.dumps({"prepared_app": app["id"], "source_entries": entry["source_entries"]}), flush=True
            )
        documents = []
        for doc in spec["vendor_documents"]:
            provenance = download(client, doc["url"], root / "primary" / f"{doc['id']}.html", MAX_DOCUMENT)
            documents.append({"id": doc["id"], **provenance})
    result = {
        "schema": "apsa-real-world-input-v1",
        "spec_sha256": sha(SPEC.read_bytes()),
        "primary_json_sha256": sha(PRIMARY.read_bytes()),
        "apps": prepared,
        "documents": documents,
    }
    write_json(root / "manifest.json", result)
    return result


def read_prepared(root: Path) -> dict:
    spec = load_spec()
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("schema") != "apsa-real-world-input-v1" or manifest.get("spec_sha256") != sha(
        SPEC.read_bytes()
    ):
        raise ValueError("Prepared inputs do not match frozen specification")
    if manifest.get("primary_json_sha256") != sha(PRIMARY.read_bytes()):
        raise ValueError("Primary advisory snapshot changed")
    if [app["id"] for app in manifest["apps"]] != [app["id"] for app in spec["apps"]]:
        raise ValueError("Prepared application IDs changed")
    if [doc["id"] for doc in manifest["documents"]] != [doc["id"] for doc in spec["vendor_documents"]]:
        raise ValueError("Prepared vendor document IDs changed")
    for entry in manifest["apps"]:
        if entry["input"] != entry["id"] + ".zip":
            raise ValueError("Unexpected prepared application path")
        path = root / "inputs" / entry["input"]
        if path.is_symlink() or sha(path.read_bytes()) != entry["sha256"]:
            raise ValueError("Prepared application bytes changed")
    for entry in manifest["documents"]:
        path = root / "primary" / f"{entry['id']}.html"
        if path.is_symlink() or sha(path.read_bytes()) != entry["sha256"]:
            raise ValueError("Prepared vendor document bytes changed")
    return manifest


class OSVTransport:
    """Capture bounded public OSV responses once, then replay exact response bytes."""

    def __init__(self, root: Path, capture: bool):
        self.root = root
        self.capture = capture
        root.mkdir(parents=True, exist_ok=capture is False)
        self.records = {}
        self.network = httpx.Client(timeout=30, follow_redirects=False) if capture else None
        if capture:
            write_json(root / "manifest.json", {"schema": "apsa-osv-http-snapshot-v1", "responses": []})
        if not capture:
            data = json.loads((root / "manifest.json").read_text())
            self.records = {entry["key"]: entry for entry in data["responses"]}
        self.client = httpx.Client(transport=httpx.MockTransport(self.handle), timeout=30)

    def handle(self, request: httpx.Request) -> httpx.Response:
        if str(request.url) != "https://api.osv.dev/v1/query" or request.method != "POST":
            raise ValueError("Only the public OSV exact package/version endpoint is allowed")
        payload = json.loads(request.content)
        key = sha(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        if key not in self.records:
            if not self.capture or self.network is None:
                raise ValueError("OSV request missing from frozen capture")
            with self.network.stream("POST", str(request.url), json=payload) as response:
                body = bytearray()
                for chunk in response.iter_bytes(65536):
                    if len(body) + len(chunk) > MAX_RESPONSE:
                        raise ValueError("OSV response capture byte budget exceeded")
                    body.extend(chunk)
                record = {
                    "key": key,
                    "payload": payload,
                    "status": response.status_code,
                    "sha256": sha(body),
                    "bytes": len(body),
                    "captured_at": datetime.now(timezone.utc).isoformat(),
                }
            (self.root / f"{key}.json").write_bytes(body)
            self.records[key] = record
            write_json(
                self.root / "manifest.json",
                {
                    "schema": "apsa-osv-http-snapshot-v1",
                    "responses": sorted(self.records.values(), key=lambda r: r["key"]),
                },
            )
        record = self.records[key]
        path = self.root / f"{key}.json"
        body = path.read_bytes()
        if path.is_symlink() or sha(body) != record["sha256"] or len(body) > MAX_RESPONSE:
            raise ValueError("Frozen OSV response bytes changed")
        return httpx.Response(record["status"], content=body, headers={"Content-Type": "application/json"})

    def close(self) -> None:
        self.client.close()
        if self.network:
            self.network.close()


def dependency_result(case: dict, transport: OSVTransport, home: Path) -> dict:
    dependency = case["dependency"]
    store = Store(home)
    try:
        records, errors = query_dependencies(store, [dependency], client=transport.client)
        findings, _ = correlate({"dependencies": [dependency], "platforms": []}, records)
        health = [f for f in store.feeds() if f["source"].startswith("osv:")]
    finally:
        store.close()
    matched = any(f["rule_id"] == case["cve"] for f in findings)
    unresolved = any(error.startswith("Unresolved/unsupported dependency:") for error in errors)
    return {
        "state": "abstained" if unresolved else "failed" if errors else "completed",
        "matched": matched,
        "matched_ids": sorted({f["rule_id"] for f in findings}),
        "errors": errors,
        "feed_status": [f["status"] for f in health],
        "statuses": sorted({f["status"] for f in findings}),
        "reachability": sorted({f.get("reachability", "unknown") for f in findings}),
    }


def cve_score(records: list[dict]) -> dict:
    counts = dict(
        tp=0, fp=0, fn=0, tn=0, failed=0, failed_affected=0, unknown=0, correct_abstentions=0, unstable=0
    )
    for record in records:
        expected = record["expected"]
        result = record["result"]
        if expected == "unknown":
            counts["unknown"] += 1
            counts["correct_abstentions"] += result["state"] == "abstained" and not result["matched"]
            continue
        if result["state"] != "completed":
            counts["failed"] += 1
            counts["failed_affected"] += expected == "affected"
            counts["unstable"] += result["state"] == "unstable"
            continue
        detected = result["matched"]
        counts[
            "tp"
            if detected and expected == "affected"
            else "fp"
            if detected
            else "fn"
            if expected == "affected"
            else "tn"
        ] += 1
    return {
        **counts,
        "precision": counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else None,
        "completed_recall": counts["tp"] / (counts["tp"] + counts["fn"])
        if counts["tp"] + counts["fn"]
        else None,
        "end_to_end_recall": counts["tp"] / (counts["tp"] + counts["fn"] + counts["failed_affected"])
        if counts["tp"] + counts["fn"] + counts["failed_affected"]
        else None,
    }


def path_matches(observed: str, expected: str) -> bool:
    return observed == expected or observed.endswith("/" + expected)


def dependency_inventory_score(report: dict, labels: list[dict]) -> list[dict]:
    actual = report["inventory"]["dependencies"]
    return [
        {
            **label,
            "extracted": any(
                all(d.get(k) == label[k] for k in ("ecosystem", "name", "version"))
                and path_matches(d.get("path", ""), label["path"])
                for d in actual
            ),
        }
        for label in labels
    ]


def config_result(report: dict, label: dict) -> dict:
    configurations = report["inventory"].get("android_config", []) + report["inventory"].get("ios_config", [])
    covered = any(path_matches(c.get("path", ""), label["path"]) for c in configurations)
    matched = any(
        f["rule_id"] == label["rule"]
        and any(path_matches(e.get("path", ""), label["path"]) for e in f.get("evidence", []))
        for f in report["findings"]
    )
    return {
        "covered": covered,
        "matched": matched,
        "expected": label["expected"],
        "correct": covered and matched == label["expected"],
        "path": label["path"],
        "rule": label["rule"],
    }


def evaluate_os(root: Path) -> list[dict]:
    spec = load_spec()
    primary = json.loads(PRIMARY.read_text())
    documents = {d["id"]: d for d in spec["vendor_documents"]}
    android = parse_android((root / "primary/android.html").read_bytes(), documents["android"]["url"])
    apple = parse_apple(
        (root / "primary/apple.html").read_bytes(), documents["apple"]["url"], documents["apple"]["label"]
    )
    normalized = [normalize_cve(cna) for cna in primary["cna"].values()]
    records = android + apple + normalized
    output = []
    for case in spec["os_cases"]:
        _, advisories = correlate(
            {"dependencies": [], "platforms": [case["platform"]]}, records, case["environment"]
        )
        states = sorted({a["state"] for a in advisories if a["id"] == case["cve"]})
        output.append(
            {
                **case,
                "observed_states": states,
                "correct": bool(states) and set(states) <= set(case["expected_states"]),
            }
        )
    return output


def compact_apsa(report: dict) -> dict:
    return {
        "files_scanned": report["inventory"]["files_scanned"],
        "bytes_scanned": report["inventory"]["bytes_scanned"],
        "source_inventory_partial": report["inventory"]["partial"],
        "audit_incomplete": report["summary"]["incomplete"],
        "findings": len(report["findings"]),
        "unique_rules": len({f["rule_id"] for f in report["findings"]}),
        "dependencies": len(report["inventory"]["dependencies"]),
        "unresolved_dependencies": sum(
            d.get("confidence") == "unknown" for d in report["inventory"]["dependencies"]
        ),
        "coverage": [{"rule": c["rule_id"], "state": c["state"]} for c in report["coverage"]],
        "warnings": report["warnings"],
        "inventory_warnings": report["inventory"]["warnings"],
    }


def app_signature(observed: dict, report: dict | None = None) -> str:
    """Include every APSA input to downstream selected-fact/CVE scoring."""
    return json.dumps(
        {
            "observation": observation_signature(observed),
            "inventory": {
                key: report["inventory"].get(key, [])
                for key in ("dependencies", "android_config", "ios_config")
            }
            if report is not None
            else None,
            "evidence": [
                {"rule": finding["rule_id"], "evidence": finding.get("evidence", [])}
                for finding in report["findings"]
            ]
            if report is not None
            else None,
        },
        sort_keys=True,
    )


def run(root: Path, output: Path, python: str, repeats: int, mobsf: MobSF | None, capture_osv: bool) -> dict:
    if repeats not in range(1, 4):
        raise ValueError("Use one to three repetitions")
    spec = load_spec()
    manifest = read_prepared(root)
    output.mkdir(parents=True, exist_ok=False)
    if mobsf:
        mobsf.wait()
    app_results = []
    inventories = {}
    for app, entry in zip(spec["apps"], manifest["apps"], strict=True):
        tools = {}
        first_apsa = None
        for tool in ("apsa", "mobsf") if mobsf else ("apsa",):
            observations, summaries, elapsed, errors = [], [], [], []
            signatures = []
            for iteration in range(repeats):
                folder = output / f"{app['id']}-{tool}-{iteration}"
                try:
                    if tool == "apsa":
                        report, seconds = apsa_report(python, root / "inputs" / entry["input"], folder)
                        observed = apsa_observation(report)
                        summary = compact_apsa(report)
                        if first_apsa is None:
                            first_apsa = report
                    else:
                        assert mobsf is not None
                        folder.mkdir()
                        before = time.perf_counter()
                        report, seconds = mobsf.scan(root / "inputs" / entry["input"])
                        write_json(folder / "report.json", report)
                        native = mobsf_observation(report)
                        observed = {
                            "rules": native["rules"],
                            "coverage": [],
                            "warnings": native["warnings"],
                            "audit_incomplete": None,
                        }
                        summary = {
                            "native_code_rule_entries": len(
                                report.get("code_analysis", {}).get("findings", {})
                            ),
                            "selected_rule_ids": native["rules"],
                            "coverage": "unknown",
                            "analysis_log_events": len(report.get("logs", [])),
                            "request_wall_seconds": time.perf_counter() - before,
                        }
                    observations.append(observed)
                    signatures.append(app_signature(observed, report if tool == "apsa" else None))
                    summaries.append(summary)
                    elapsed.append(seconds)
                except (ValueError, OSError, httpx.HTTPError, subprocess.TimeoutExpired) as error:
                    errors.append(f"{type(error).__name__}: {error}"[:700])
            stable = len(set(signatures)) <= 1
            tools[tool] = {
                "state": "failed" if errors else "completed" if stable else "unstable",
                "seconds": elapsed,
                "median_seconds": statistics.median(elapsed) if elapsed else None,
                "errors": errors,
                "summary": summaries[0] if summaries else None,
            }
        apsa_state = tools["apsa"]["state"]
        usable_apsa = first_apsa if apsa_state == "completed" else None
        item = {
            "id": app["id"],
            "repository": app["repository"],
            "commit": app["commit"],
            "platform": app["platform"],
            "input_sha256": entry["sha256"],
            "source_entries": entry["source_entries"],
            "tools": tools,
            "config_label": {**config_result(usable_apsa, app["config_label"]), "state": apsa_state}
            if usable_apsa
            else {
                **app["config_label"],
                "state": apsa_state,
                "covered": False,
                "matched": False,
                "correct": False,
            },
            "dependency_labels": [
                {**label, "state": apsa_state}
                for label in dependency_inventory_score(usable_apsa, app["dependencies"])
            ]
            if usable_apsa
            else [{**label, "state": apsa_state, "extracted": False} for label in app["dependencies"]],
        }
        app_results.append(item)
        if usable_apsa:
            inventories[app["id"]] = usable_apsa["inventory"]["dependencies"]
        print(json.dumps({"app": app["id"], "tools": {k: v["state"] for k, v in tools.items()}}), flush=True)
    transport = OSVTransport(root / "osv", capture=capture_osv)
    dependency_results = []
    app_cve_results = []
    try:
        for case in spec["dependency_cases"]:
            observed = [
                dependency_result(case, transport, output / f"cve-{case['id']}-{i}") for i in range(repeats)
            ]
            result = dict(observed[0])
            if len({json.dumps(o, sort_keys=True) for o in observed}) != 1:
                result["state"] = "unstable"
            dependency_results.append({**case, "result": result})
            print(
                json.dumps({"cve_case": case["id"], "state": result["state"], "matched": result["matched"]}),
                flush=True,
            )
        for app in spec["apps"]:
            for label in app["dependencies"]:
                cve = {"org.jsoup:jsoup": "CVE-2022-36033", "com.squareup.okio:okio": "CVE-2023-3635"}.get(
                    label["name"]
                )
                if cve is None:
                    continue
                # Truth comes from frozen vendor version boundaries, not API results.
                expected = "affected" if app["id"] == "antennapod" else "unaffected"
                case = {"id": app["id"] + "-" + cve, "cve": cve, "expected": expected}
                actual = [
                    d
                    for d in inventories.get(app["id"], [])
                    if d["name"] == label["name"]
                    and d["ecosystem"] == label["ecosystem"]
                    and path_matches(d["path"], label["path"])
                ]
                app_state = next(
                    item["tools"]["apsa"]["state"] for item in app_results if item["id"] == app["id"]
                )
                if app_state != "completed":
                    observed = {
                        "state": app_state,
                        "matched": False,
                        "errors": ["Selected real-app APSA scan did not complete stably"],
                    }
                elif not actual:
                    observed = {
                        "state": "failed",
                        "matched": False,
                        "errors": ["Selected real-app dependency not extracted"],
                    }
                else:
                    case["dependency"] = actual[0]
                    observed = dependency_result(case, transport, output / f"app-cve-{case['id']}")
                app_cve_results.append({**case, "source_dependency_label": label, "result": observed})
    finally:
        transport.close()
    result = {
        "schema": SCHEMA,
        "source_revision": os.environ.get("GITHUB_SHA"),
        "apsa_engine": engine_metadata(python),
        "spec_sha256": sha(SPEC.read_bytes()),
        "input_manifest_sha256": sha((root / "manifest.json").read_bytes()),
        "osv_manifest_sha256": sha((root / "osv/manifest.json").read_bytes()),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "repetitions": repeats,
        },
        "mobsf_image_digest": os.environ.get("MOBSF_BENCHMARK_DIGEST"),
        "limits": spec["limits"],
        "apps": app_results,
        "dependency_cases": dependency_results,
        "dependency_score": cve_score(dependency_results),
        "selected_real_app_cve_cases": app_cve_results,
        "selected_real_app_cve_score": cve_score(app_cve_results),
        "os_cases": evaluate_os(root),
    }
    write_json(output / "summary.json", result)
    print("APSA_REAL_WORLD_RESULT_BEGIN", flush=True)
    print(json.dumps(result), flush=True)
    print("APSA_REAL_WORLD_RESULT_END", flush=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run"))
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--apsa-python", default=sys.executable)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--mobsf-url")
    parser.add_argument("--mobsf-docker-ip")
    parser.add_argument("--capture-public-osv", action="store_true")
    args = parser.parse_args()
    if args.action == "prepare":
        prepare(args.fixtures)
    else:
        if args.out is None:
            parser.error("--out is required")
        mobsf = (
            MobSF(args.mobsf_url, os.environ.get("MOBSF_BENCHMARK_KEY", ""), args.mobsf_docker_ip)
            if args.mobsf_url
            else None
        )
        try:
            run(args.fixtures, args.out, args.apsa_python, args.repeats, mobsf, args.capture_public_osv)
        finally:
            if mobsf:
                mobsf.client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
