"""Check an APSA SARIF file against GitHub code scanning upload constraints."""

from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

MAX_RESULTS = 25_000
MAX_GZIP_BYTES = 10 * 1024 * 1024


def problems(raw: bytes) -> list[str]:
    errors = []
    if len(gzip.compress(raw)) > MAX_GZIP_BYTES:
        errors.append("gzip-compressed SARIF exceeds 10 MB")
    document = json.loads(raw)
    if document.get("version") != "2.1.0":
        errors.append("SARIF version must be 2.1.0")
    for index, run in enumerate(document.get("runs", [])):
        rules = {rule["id"]: rule for rule in run["tool"]["driver"].get("rules", [])}
        results = run.get("results", [])
        if len(results) > MAX_RESULTS:
            errors.append(f"run {index}: more than {MAX_RESULTS} results")
        for number, result in enumerate(results):
            where = f"run {index} result {number}"
            if result.get("ruleId") not in rules:
                errors.append(f"{where}: ruleId has no rule descriptor")
            if not result.get("partialFingerprints", {}).get("apsaFindingIdentity/v1"):
                errors.append(f"{where}: missing stable partial fingerprint")
            locations = result.get("locations") or []
            if not locations:
                errors.append(f"{where}: no location")
            for location in locations:
                uri = location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")
                if not uri or uri.startswith("/") or "://" in uri or "\\" in uri:
                    errors.append(f"{where}: location URI must be repository-relative: {uri!r}")
        for rule in rules.values():
            severity = rule.get("properties", {}).get("security-severity")
            if severity is not None:
                try:
                    if not 0.0 <= float(severity) <= 10.0:
                        raise ValueError
                except ValueError:
                    errors.append(f"rule {rule['id']}: security-severity must be a number from 0 to 10")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        raise SystemExit("usage: check_sarif.py FILE")
    found = problems(Path(argv[0]).read_bytes())
    for problem in found:
        print(problem, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
