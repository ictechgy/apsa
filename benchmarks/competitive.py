"""Run APSA and a fresh local MobSF service on frozen synthetic fixtures.

Use the read-only GitHub Actions workflow for networked setup. This driver never
syncs public intelligence, contacts app backends, or uploads real user apps.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import statistics
import subprocess
import sys
import time
import zipfile
from pathlib import Path

import httpx

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from benchmarks.competitive_cases import MAPPING, MOBSF_COMMIT, SCHEMA, cases, generate, project_files


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def engine_metadata(python: str) -> dict:
    script = """import hashlib, importlib.metadata, json, pathlib
import mobile_audit
from mobile_audit.core import RULE_VERSION
root = pathlib.Path(mobile_audit.__file__).parent
def version(name):
    # Older released baselines lack later parser packages; record absence, not failure.
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None
files = sorted(root.rglob('*.py')) + sorted((root / 'data').glob('*.json'))
print(json.dumps({'version': mobile_audit.__version__, 'rule_version': RULE_VERSION, 'source_sha256': {
str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files},
'dependencies': {name: version(name) for name in
('androguard', 'tree-sitter', 'tree-sitter-java', 'tree-sitter-kotlin', 'tree-sitter-swift', 'tree-sitter-objc', 'psutil')}}))
"""
    return json.loads(command([python, "-I", "-c", script]).stdout)


def command(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=300, check=True, **kwargs)


def build_apks(root: Path, sdk: Path) -> dict:
    manifest = read_manifest(root)
    tools = sdk / "build-tools/35.0.0"
    android = sdk / "platforms/android-35/android.jar"
    for path in [android, tools / "aapt2", tools / "d8", tools / "apksigner"]:
        if not path.is_file():
            raise ValueError(f"Required pinned Android build input is missing: {path}")
    key = root / "synthetic-benchmark.jks"
    command(
        [
            "keytool",
            "-genkeypair",
            "-keystore",
            str(key),
            "-storepass",
            "synthetic-only",
            "-keypass",
            "synthetic-only",
            "-alias",
            "benchmark",
            "-keyalg",
            "RSA",
            "-keysize",
            "2048",
            "-validity",
            "30",
            "-dname",
            "CN=Synthetic Benchmark",
            "-noprompt",
        ]
    )
    additions = []
    for case in list(manifest["cases"]):
        if not case["flags"].get("apk"):
            continue
        project = root / case["id"]
        work = root / (case["id"] + "-compiled")
        work.mkdir()
        classes = work / "classes"
        classes.mkdir()
        java = project / "app/src/main/java/test/synthetic/ProbeActivity.java"
        command(
            [
                "javac",
                "-source",
                "8",
                "-target",
                "8",
                "-classpath",
                str(android),
                "-d",
                str(classes),
                str(java),
            ]
        )
        jar = work / "classes.jar"
        command(["jar", "cf", str(jar), "-C", str(classes), "."])
        command(
            [str(tools / "d8"), "--lib", str(android), "--min-api", "24", "--output", str(work), str(jar)]
        )
        unsigned = work / "unsigned.apk"
        command(
            [
                str(tools / "aapt2"),
                "link",
                "-I",
                str(android),
                "--manifest",
                str(project / "app/src/main/AndroidManifest.xml"),
                "--min-sdk-version",
                "24",
                "--target-sdk-version",
                "35",
                "-o",
                str(unsigned),
            ]
        )
        with zipfile.ZipFile(unsigned, "a", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(work / "classes.dex", "classes.dex")
        apk = root / (case["id"] + ".apk")
        command(
            [
                str(tools / "apksigner"),
                "sign",
                "--ks",
                str(key),
                "--ks-key-alias",
                "benchmark",
                "--ks-pass",
                "pass:synthetic-only",
                "--key-pass",
                "pass:synthetic-only",
                "--out",
                str(apk),
                str(unsigned),
            ]
        )
        command([str(tools / "apksigner"), "verify", str(apk)])
        additions.append(
            case
            | {
                "id": case["id"] + "-apk",
                "input": apk.name,
                "input_kind": "apk",
                "source_case": case["id"],
                "sha256": sha(apk),
                "compiler": {
                    "platform": "android-35",
                    "build_tools": "35.0.0",
                    "java": command(["javac", "-version"]).stdout.strip(),
                },
            }
        )
    manifest["cases"].extend(additions)
    (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def read_manifest(root: Path) -> dict:
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest.get("schema") != SCHEMA or manifest.get("mapping") != MAPPING:
        raise ValueError("Benchmark schema or frozen mapping changed")
    truth = {c["id"]: c for c in cases()}
    apk_ids = {key + "-apk": key for key, base in truth.items() if base["flags"].get("apk")}
    seen = set()
    for case in manifest["cases"]:
        if case["id"] in seen:
            raise ValueError("Duplicate benchmark sampling unit")
        seen.add(case["id"])
        if case["id"] in truth:
            if case.get("source_case") is not None or case["input_kind"] != "source-zip":
                raise ValueError("Source sampling unit changed")
            base = truth[case["id"]]
        elif case["id"] in apk_ids:
            if case.get("source_case") != apk_ids[case["id"]] or case["input_kind"] != "apk":
                raise ValueError("APK sampling unit changed")
            base = truth[apk_ids[case["id"]]]
        else:
            raise ValueError("Unexpected benchmark sampling unit")
        if base is None or any(
            case[key] != base[key]
            for key in ("language", "category", "variant", "risky", "flags", "reason", "reference")
        ):
            raise ValueError("Frozen benchmark ground truth changed")
        if Path(case["input"]).name != case["input"] or (root / case["input"]).is_symlink():
            raise ValueError("Benchmark inputs must be regular generated files inside the fixture directory")
        if sha(root / case["input"]) != case["sha256"]:
            raise ValueError("Benchmark input changed after manifest freeze")
        if case["input_kind"] == "source-zip":
            expected = project_files(base)
            with zipfile.ZipFile(root / case["input"]) as archive:
                if sorted(archive.namelist()) != sorted(expected) or any(
                    archive.read(name) != content for name, content in expected.items()
                ):
                    raise ValueError("Source bytes disagree with frozen generated ground truth")
    if not set(truth).issubset(seen):
        raise ValueError("Frozen benchmark cases were omitted")
    if seen - set(truth) not in (set(), set(apk_ids)):
        raise ValueError("Compiled benchmark must include exactly the six selected APKs")
    return manifest


def apsa_report(python: str, target: Path, output: Path) -> tuple[dict, float]:
    output.mkdir()
    env = os.environ.copy()
    env["APSA_PARSER_LOCK_DIR"] = str(output / "parser-locks")
    env["APSA_DEVICE_LOCK_DIR"] = str(output / "device-locks")
    start = time.perf_counter()
    process = subprocess.run(
        [
            python,
            "-I",
            "-m",
            "apsa",
            "--home",
            str(output / "home"),
            "scan",
            str(target),
            "--out",
            str(output / "report.json"),
            "--json",
        ],
        capture_output=True,
        text=True,
        timeout=180,
        env=env,
    )
    elapsed = time.perf_counter() - start
    # A completed but incomplete audit remains distinguishable; it is not an error or a clean pass.
    if process.returncode not in {0, 3, 4} or not (output / "report.json").is_file():
        raise ValueError(f"APSA execution failed with code {process.returncode}: {process.stderr[-500:]}")
    return json.loads((output / "report.json").read_text()), elapsed


def apsa_observation(report: dict) -> dict:
    if not isinstance(report.get("findings"), list) or not isinstance(report.get("coverage"), list):
        raise ValueError("APSA report lacks findings/coverage")
    return {
        "rules": sorted({f["rule_id"] for f in report["findings"]}),
        "evidence": [
            {
                "rule": f["rule_id"],
                "status": f["status"],
                "locations": [
                    {k: e[k] for k in ("path", "line", "basis") if k in e} for e in f.get("evidence", [])
                ],
            }
            for f in report["findings"]
        ],
        "coverage": [{"rule": c["rule_id"], "state": c["state"]} for c in report["coverage"]],
        "warnings": report.get("inventory", {}).get("warnings", []) + report.get("warnings", []),
        "audit_incomplete": report.get("summary", {}).get("incomplete"),
    }


def mobsf_observation(report: dict, category: str | None = None) -> dict:
    # MobSF can return HTTP 200 and an empty code payload after a swallowed
    # decompiler failure. Configuration-only labels do not require code analysis.
    failures = [
        item.get("status", "")
        for item in report.get("logs", [])
        if isinstance(item, dict)
        and (
            item.get("status") in {"Failed to perform code analysis", "Some DEX files failed to decompile"}
            or (item.get("exception") and "Decompil" in item.get("status", ""))
        )
    ]
    if failures and category not in {"debug", "cleartext", "ats"}:
        raise ValueError("MobSF selected code analysis is incomplete: " + "; ".join(failures))
    code = report.get("code_analysis")
    if not isinstance(code, dict) or not report.get("file_name"):
        raise ValueError("MobSF returned no source/binary analysis report")
    code = code.get("findings", code)
    if not isinstance(code, dict):
        raise ValueError("MobSF code analysis schema is unsupported")
    rules = set(code)
    evidence = [
        {
            "rule": key,
            "locations": value.get("files", {}),
            "severity": value.get("metadata", {}).get("severity", value.get("severity")),
        }
        for key, value in code.items()
        if isinstance(value, dict)
    ]
    manifest = report.get("manifest_analysis", [])
    if isinstance(manifest, dict):
        manifest = manifest.get("manifest_findings", manifest.get("findings", []))
    for item in manifest:
        if isinstance(item, dict) and item.get("rule"):
            key = "manifest:" + item["rule"]
            rules.add(key)
            evidence.append({"rule": key, "severity": item.get("severity")})
    ats = report.get("ats_analysis", report.get("ats_findings", []))
    if isinstance(ats, dict):
        ats = ats.get("ats_findings", ats.get("findings", []))
    for item in ats:
        if isinstance(item, dict) and item.get("issue"):
            key = "ats:" + item["issue"]
            rules.add(key)
            evidence.append({"rule": key, "severity": item.get("severity")})
    return {
        "rules": sorted(rules),
        "evidence": evidence,
        "coverage": None,
        "coverage_state": "MobSF does not expose APSA's per-rule execution coverage contract",
        "source_type": report.get("bin_type", report.get("app_type")),
        "warnings": [],
        "audit_incomplete": None,
    }


class MobSF:
    def __init__(self, url: str, api_key: str, docker_ip: str | None = None):
        parsed = httpx.URL(url)
        bridge = False
        if docker_ip is not None:
            address = ipaddress.ip_address(docker_ip)
            bridge = (
                address.version == 4
                and any(
                    address in net
                    for net in map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
                )
                and parsed.host == docker_ip
                and parsed.port == 8000
            )
            if not bridge:
                raise ValueError("Expected the inspected fresh Docker container's private IPv4:8000")
        if parsed.scheme != "http" or (not bridge and parsed.host not in {"127.0.0.1", "localhost", "::1"}):
            raise ValueError("Benchmark only supports a fresh local MobSF endpoint on the runner")
        self.client = httpx.Client(
            base_url=url, headers={"X-Mobsf-Api-Key": api_key}, timeout=180, trust_env=False
        )

    def wait(self):
        last = "no response"
        for _ in range(120):
            try:
                response = self.client.get("/api/v1/scans", params={"page_size": 1, "page": 1}, timeout=3)
                if response.status_code == 200:
                    return
                last = f"HTTP {response.status_code}"
            except httpx.HTTPError as error:
                last = type(error).__name__
            time.sleep(2)
        raise ValueError(f"Fresh MobSF service did not become ready: {last}")

    def scan(self, target: Path) -> tuple[dict, float]:
        start = time.perf_counter()
        with target.open("rb") as source:
            uploaded = self.client.post(
                "/api/v1/upload", files={"file": (target.name, source, "application/octet-stream")}
            )
        uploaded.raise_for_status()
        checksum = uploaded.json().get("hash")
        if not checksum:
            raise ValueError("MobSF upload did not return an input hash")
        response = self.client.post("/api/v1/scan", data={"hash": checksum, "re_scan": "1"})
        response.raise_for_status()
        report = response.json()
        if "error" in report:
            raise ValueError("MobSF analysis returned an error")
        return report, time.perf_counter() - start


def score(records: list[dict], tool: str, kind: str | None = None) -> dict:
    counts = {
        "tp": 0,
        "fp": 0,
        "fn": 0,
        "tn": 0,
        "failed": 0,
        "failed_risky": 0,
        "unstable": 0,
        "unmapped_risky": 0,
        "cases": 0,
    }
    timings = []
    for record in records:
        if kind is not None and record["input_kind"] != kind:
            continue
        result = record["tools"].get(tool)
        if result is None:
            continue
        counts["cases"] += 1
        if result["state"] != "completed":
            counts["failed"] += 1
            counts["failed_risky"] += record["risky"]
            counts["unstable"] += result["state"] == "unstable"
            continue
        timings.extend(result["seconds"])
        detected = bool(result["matched"])
        counts["unmapped_risky"] += record["risky"] and not MAPPING[record["category"]][tool]
        counts[
            "tp" if detected and record["risky"] else "fp" if detected else "fn" if record["risky"] else "tn"
        ] += 1
    precision_denominator = counts["tp"] + counts["fp"]
    recall_denominator = counts["tp"] + counts["fn"]
    end_to_end_denominator = recall_denominator + counts["failed_risky"]
    return counts | {
        "alert_precision": counts["tp"] / precision_denominator if precision_denominator else None,
        "completed_case_recall": counts["tp"] / recall_denominator if recall_denominator else None,
        "end_to_end_recall": counts["tp"] / end_to_end_denominator if end_to_end_denominator else None,
        "median_elapsed_seconds": statistics.median(timings) if timings else None,
    }


def observation_signature(observation: dict) -> str:
    return json.dumps(
        {key: observation[key] for key in ("rules", "coverage", "warnings", "audit_incomplete")},
        sort_keys=True,
    )


def run(root: Path, output: Path, python: str, mobsf: MobSF | None, repeats: int) -> dict:
    if repeats not in range(1, 6):
        raise ValueError("Use 1..5 repetitions")
    manifest = read_manifest(root)
    output.mkdir(parents=True, exist_ok=False)
    if mobsf:
        mobsf.wait()
    records = []
    for case in manifest["cases"]:
        entry = {
            key: case[key]
            for key in ("id", "category", "variant", "risky", "language", "input_kind", "sha256")
        }
        entry["tools"] = {}
        for tool in ["apsa", "mobsf"] if mobsf else ["apsa"]:
            observations, timings, errors = [], [], []
            for iteration in range(repeats):
                location = output / f"{case['id']}-{tool}-{iteration}"
                try:
                    if tool == "apsa":
                        report, elapsed = apsa_report(python, root / case["input"], location)
                        observed = apsa_observation(report)
                    else:
                        location.mkdir()
                        assert mobsf is not None
                        report, elapsed = mobsf.scan(root / case["input"])
                        (location / "report.json").write_text(json.dumps(report) + "\n")
                        observed = mobsf_observation(report, case["category"])
                    timings.append(elapsed)
                    observations.append(observed)
                except (ValueError, OSError, subprocess.TimeoutExpired, httpx.HTTPError) as error:
                    errors.append(f"{type(error).__name__}: {error}"[:700])
            stable = len({observation_signature(o) for o in observations}) <= 1
            result = {
                "state": "failed" if errors else "completed" if stable else "unstable",
                "seconds": timings,
                "errors": errors,
                "matched": sorted(set(observations[0]["rules"]) & set(MAPPING[case["category"]][tool]))
                if observations
                else [],
                "observations": observations,
            }
            entry["tools"][tool] = result
        records.append(entry)
        print(
            json.dumps(
                {
                    "case": case["id"],
                    "tools": {
                        name: {"state": result["state"], "matched": result["matched"]}
                        for name, result in entry["tools"].items()
                    },
                }
            ),
            flush=True,
        )
    summary = {
        tool: {kind: score(records, tool, kind) for kind in ("source-zip", "apk")}
        for tool in (["apsa", "mobsf"] if mobsf else ["apsa"])
    }
    result = {
        "schema": SCHEMA,
        "manifest_sha256": sha(root / "manifest.json"),
        "mobsf_commit": MOBSF_COMMIT,
        "apsa_engine": engine_metadata(python),
        "source_revision": os.environ.get("GITHUB_SHA"),
        "mobsf_image_digest": os.environ.get("MOBSF_BENCHMARK_DIGEST"),
        "mobsf_jadx_sha256": os.environ.get("MOBSF_BENCHMARK_JADX_SHA256"),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "apsa_python": python,
            "cpu_count": os.cpu_count(),
            "repetitions": repeats,
        },
        "timing_scope": "APSA fresh CLI/store/process; MobSF warm local API upload+forced rescan. Setup/pull time excluded. Not an engine-only speed ranking.",
        "limits": manifest["limits"],
        "mapping": MAPPING,
        "summary": summary,
        "cases": records,
    }
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    concise = {
        key: result[key]
        for key in (
            "schema",
            "manifest_sha256",
            "environment",
            "timing_scope",
            "summary",
            "limits",
            "apsa_engine",
            "source_revision",
            "mobsf_image_digest",
            "mobsf_jadx_sha256",
            "mobsf_commit",
        )
    }
    concise["cases"] = [
        {key: record[key] for key in ("id", "category", "risky", "input_kind")}
        | {
            "tools": {
                name: {key: value[key] for key in ("state", "matched", "seconds", "errors")}
                for name, value in record["tools"].items()
            }
        }
        for record in records
    ]
    (output / "summary.json").write_text(json.dumps(concise, indent=2) + "\n")
    print("APSA_COMPETITIVE_RESULT_BEGIN", flush=True)
    print(json.dumps(concise), flush=True)
    print("APSA_COMPETITIVE_RESULT_END", flush=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("generate", "build-apks", "run"))
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--sdk", type=Path)
    parser.add_argument("--apsa-python", default=sys.executable)
    parser.add_argument("--mobsf-url")
    parser.add_argument(
        "--mobsf-docker-ip", help="Exact IPv4 inspected from the fresh internal Docker network"
    )
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if args.action == "generate":
        manifest = generate(args.fixtures)
        print(
            json.dumps(
                {"cases": len(manifest["cases"]), "manifest_sha256": sha(args.fixtures / "manifest.json")}
            )
        )
    elif args.action == "build-apks":
        if args.sdk is None:
            parser.error("--sdk is required")
        manifest = build_apks(args.fixtures, args.sdk)
        print(
            json.dumps(
                {"cases": len(manifest["cases"]), "manifest_sha256": sha(args.fixtures / "manifest.json")}
            )
        )
    else:
        if args.out is None:
            parser.error("--out is required")
        service = (
            MobSF(
                args.mobsf_url,
                os.environ.get("MOBSF_BENCHMARK_KEY", "synthetic-benchmark-only"),
                args.mobsf_docker_ip,
            )
            if args.mobsf_url
            else None
        )
        result = run(args.fixtures, args.out, args.apsa_python, service, args.repeats)
        return int(any(metric["failed"] for group in result["summary"].values() for metric in group.values()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
