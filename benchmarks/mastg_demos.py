"""Score APSA on OWASP MASTG v2.0 demos that state a pass or fail outcome.

Method, fixed before the first run:

- Input: the OWASP/mastg archive at a pinned commit, verified by SHA-256. Demos
  and tests are CC BY-SA 4.0; this harness copies sample sources into a fresh
  work directory and stores only identifiers and outcomes.
- Label: a demo's ``kind: fail|pass``; otherwise an unambiguous "The test
  fails/passes" statement in its Evaluation section. Other demos are unlabeled.
- Weakness: the demo's test names a MASWE beta identifier, translated to MASWE
  v1.0 through the index's beta mapping.
- Target: the demo's original sample sources (Kotlin, Java except decompiled
  ``*_reversed`` files, Swift, XML, plists); scripts and expected outputs are
  excluded.
- Outcome: flagged when any APSA finding maps to one of the demo's v1
  weaknesses. A demo is in scope when APSA has a related check for one of them.
- Score: in-scope fail demos are TP or FN, in-scope pass demos TN or FP, others
  not-assessed; scan failures are errors, never negatives. A strict pair needs
  every fail demo of a test flagged and every pass demo clear.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path

import yaml

COMMIT = "990472dbcffe126f5556045d60270c4ffdfdde72"  # OWASP/mastg v2.0.0
ARCHIVE_SHA256 = "72052f77b2e252c0034aae5f009615c22c6b2b4ebe031490b5f33711f433149c"
ARCHIVE_URL = f"https://codeload.github.com/OWASP/mastg/tar.gz/{COMMIT}"
SAMPLE_SUFFIXES = (".kt", ".java", ".swift", ".xml", ".plist", ".xcprivacy", ".m", ".h")
FAILS = re.compile(r"\btest (?:case )?fails\b|\bfails? because\b", re.I)
PASSES = re.compile(r"\btest (?:case )?passes\b|\bpasses because\b", re.I)


def front_matter(path: Path) -> tuple[dict, str]:
    _, head, body = path.read_text(encoding="utf-8").split("---", 2)
    return yaml.safe_load(head) or {}, body


def label(meta: dict, body: str) -> str | None:
    if meta.get("kind") in {"fail", "pass"}:
        return meta["kind"]
    evaluation = body.split("## Evaluation", 1)[1] if "## Evaluation" in body else ""
    fails, passes = bool(FAILS.search(evaluation)), bool(PASSES.search(evaluation))
    return "fail" if fails and not passes else "pass" if passes and not fails else None


def fetch(archive: Path | None, work: Path) -> Path:
    if archive is None:
        archive = work / "mastg.tar.gz"
        with urllib.request.urlopen(ARCHIVE_URL, timeout=120) as response:  # noqa: S310 - pinned https URL
            archive.write_bytes(response.read())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != ARCHIVE_SHA256:
        raise SystemExit(f"MASTG archive SHA-256 {digest} does not match the pinned {ARCHIVE_SHA256}")
    root = work / "mastg"
    root.mkdir()
    with tarfile.open(archive) as bundle:
        members = [
            m for m in bundle.getmembers() if m.isfile() and ("/demos/" in m.name or "/tests" in m.name)
        ]
        bundle.extractall(root, members=members, filter="data")
    return next(root.iterdir())


def demos(source: Path) -> list[dict]:
    tests = {}
    for folder in ("tests-beta", "tests"):
        for path in sorted((source / folder).rglob("MASTG-TEST-*.md")):
            meta, _ = front_matter(path)
            tests.setdefault(meta.get("id", path.stem), meta)
    found = []
    for path in sorted((source / "demos").glob("*/*/MASTG-DEMO-*/MASTG-DEMO-*.md")):
        meta, body = front_matter(path)
        test = tests.get(meta.get("test"), {})
        found.append(
            {
                "id": meta["id"],
                "platform": meta.get("platform"),
                "test": meta.get("test"),
                "test_type": test.get("type"),
                "weakness_beta": test.get("weakness"),
                "label": label(meta, body),
                "directory": path.parent,
            }
        )
    return found


def stage(directory: Path, target: Path) -> list[str]:
    target.mkdir(parents=True)
    copied = []
    for path in sorted(directory.rglob("*")):
        if path.is_file() and path.suffix in SAMPLE_SUFFIXES and "_reversed" not in path.stem:
            destination = target / path.relative_to(directory)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            copied.append(str(path.relative_to(directory)))
    return copied


def evaluate(entries: list[dict], work: Path) -> dict:
    from mobile_audit.audit import scan
    from mobile_audit.maswe import RULE_WEAKNESSES, from_beta, weaknesses_for
    from mobile_audit.store import Store

    checked = {w for mapped in RULE_WEAKNESSES.values() for w in mapped}
    rows = []
    store = Store(work / "home")
    try:
        for entry in entries:
            weaknesses = list(from_beta(entry["weakness_beta"])) if entry["weakness_beta"] else []
            row = {k: v for k, v in entry.items() if k != "directory"}
            row["weaknesses"] = weaknesses
            row["in_scope"] = bool(set(weaknesses) & checked)
            files = stage(entry["directory"], work / "targets" / entry["id"])
            row["files"] = files
            if not files:
                row["outcome"] = "no-sample"
                rows.append(row)
                continue
            try:
                report = scan(store, work / "targets" / entry["id"])
            except (ValueError, OSError) as error:
                row["outcome"] = "error"
                row["error"] = str(error)[:300]
                rows.append(row)
                continue
            related = [
                f
                for f in report["findings"]
                if set(weaknesses) & set(f.get("maswe") or weaknesses_for(f["rule_id"]))
            ]
            row["flagged"] = bool(related)
            row["findings"] = sorted({f["rule_id"] for f in related})
            row["other_findings"] = sorted({f["rule_id"] for f in report["findings"]} - set(row["findings"]))
            if entry["label"] is None:
                row["outcome"] = "unlabeled"
            elif not row["in_scope"]:
                row["outcome"] = "not-assessed"
            elif entry["label"] == "fail":
                row["outcome"] = "tp" if related else "fn"
            else:
                row["outcome"] = "fp" if related else "tn"
            rows.append(row)
    finally:
        store.close()
    summary: dict[str, int] = {}
    for row in rows:
        summary[row["outcome"]] = summary.get(row["outcome"], 0) + 1
    pairs = {}
    for row in rows:
        if row["in_scope"] and row["outcome"] in {"tp", "fn", "tn", "fp"}:
            pairs.setdefault(row["test"], []).append(row)
    strict = {
        test: all(r["outcome"] in {"tp", "tn"} for r in group)
        for test, group in pairs.items()
        if {r["label"] for r in group} == {"fail", "pass"}
    }
    return {
        "schema": "apsa-mastg-demos-v1",
        "source": {
            "repository": "OWASP/mastg",
            "commit": COMMIT,
            "archive_sha256": ARCHIVE_SHA256,
            "license": "CC-BY-SA-4.0",
        },
        "method": __doc__,
        "summary": summary,
        "labeled": sum(row["label"] is not None for row in rows),
        "strict_pairs": {"tests": len(strict), "correct": sum(strict.values()), "by_test": strict},
        "demos": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--archive", type=Path, help="Pinned OWASP/mastg tarball; downloaded when omitted")
    parser.add_argument("--work", type=Path, help="Empty work directory")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    work = args.work or Path(tempfile.mkdtemp(prefix="apsa-mastg-"))
    work.mkdir(parents=True, exist_ok=True)
    if any(work.iterdir()):
        raise SystemExit("--work must be empty")
    source = fetch(args.archive, work)
    result = evaluate(demos(source), work)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
    print(
        json.dumps(
            {
                "summary": result["summary"],
                "labeled": result["labeled"],
                "strict_pairs": {k: v for k, v in result["strict_pairs"].items() if k != "by_test"},
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
