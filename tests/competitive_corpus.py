"""Separately frozen synthetic corpus; it does not amend historical benchmarks."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def cases(*, include_objc: bool = False) -> list[dict]:
    result = []

    def add(identifier, family, label, files, rule="AST-PATH-TRAVERSAL", rationale="", partial=False):
        result.append(
            {
                "id": identifier,
                "family": family,
                "label": label,
                "rule": rule,
                "expected_partial": partial,
                "rationale": rationale,
                "files": files,
            }
        )

    for language, suffix in (("java", "java"), ("kotlin", "kt"), ("swift", "swift")):
        for guard in ("wrong-input", "late", "branch", "correct"):
            if language == "java":
                check = {
                    "wrong-input": 'if (unrelated.contains("..")) return;',
                    "late": "",
                    "branch": 'if (flag) { if (name.contains("..")) return; }',
                    "correct": 'if (name.contains("..")) return;',
                }[guard]
                late = 'if (name.contains("..")) return;' if guard == "late" else ""
                text = f'class Entry {{ void inspect(Intent incoming, String unrelated, boolean flag) {{ String name = incoming.getStringExtra("corpus_name"); {check} new FileOutputStream("/synthetic/root/" + name); {late} }} }}'
            elif language == "kotlin":
                check = {
                    "wrong-input": 'if (unrelated.contains("..")) return',
                    "late": "",
                    "branch": 'if (flag) { if (name.contains("..")) return }',
                    "correct": 'if (name.contains("..")) return',
                }[guard]
                late = 'if (name.contains("..")) return' if guard == "late" else ""
                text = f'class Entry {{ fun inspect(incoming: Intent, unrelated: String, flag: Boolean) {{ val name = incoming.getStringExtra("corpus_name")!!\n {check}\n FileOutputStream("/synthetic/root/" + name)\n {late}\n }} }}'
            else:
                check = {
                    "wrong-input": 'if unrelated.contains("..") { return false }',
                    "late": "",
                    "branch": 'if flag { if name.contains("..") { return false } }',
                    "correct": 'if name.contains("..") { return false }',
                }[guard]
                late = 'if name.contains("..") { return false }' if guard == "late" else ""
                text = f'class Entry {{ var unrelated = "fixed"; var flag = false\n func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{ let name = incoming.query!\n {check}\n let destination = URL(fileURLWithPath: "/synthetic/root/" + name)\n {late}\n return true }} }}'
            add(
                f"{language}-guard-{guard}",
                f"native-guard-{language}",
                "safe" if guard == "correct" else "vulnerable",
                {f"Entry.{suffix}": text},
                rationale="Same-input traversal guard must precede every sink route; fixed synthetic root assumes no symlinks.",
            )

        for seam in ("parameter", "return", "field"):
            for safe in (False, True):
                if language == "java":
                    value = '"constant-owned-file"' if safe else 'incoming.getStringExtra("corpus_name")'
                    if seam == "parameter":
                        entry = (
                            f"class Entry {{ void inspect(Intent incoming) {{ Helper.write({value}); }} }}"
                        )
                        helper = "class Helper { static void write(String value) { new FileOutputStream(value); } }"
                    elif seam == "return":
                        entry = f"class Entry {{ void inspect(Intent incoming) {{ new FileOutputStream(Helper.forward({value})); }} }}"
                        helper = "class Helper { static String forward(String value) { return value; } }"
                    else:
                        entry = f"class Entry {{ void inspect(Intent incoming) {{ Helper box = new Helper(); box.save({value}); new FileOutputStream(box.read()); }} }}"
                        helper = "class Helper { String saved; void save(String value) { this.saved = value; } String read() { return this.saved; } }"
                elif language == "kotlin":
                    value = '"constant-owned-file"' if safe else 'incoming.getStringExtra("corpus_name")!!'
                    if seam == "parameter":
                        entry = (
                            f"class Entry {{ fun inspect(incoming: Intent) {{ Helper().write({value}) }} }}"
                        )
                        helper = "class Helper { fun write(value: String) { FileOutputStream(value) } }"
                    elif seam == "return":
                        entry = f"class Entry {{ fun inspect(incoming: Intent) {{ FileOutputStream(Helper().forward({value})) }} }}"
                        helper = "class Helper { fun forward(value: String): String { return value } }"
                    else:
                        entry = f"class Entry {{ fun inspect(incoming: Intent) {{ val box = Helper(); box.save({value}); FileOutputStream(box.read()) }} }}"
                        helper = 'class Helper { var saved: String = "fixed"; fun save(value: String) { this.saved = value }; fun read(): String { return this.saved } }'
                else:
                    value = '"constant-owned-file"' if safe else "incoming.absoluteString"
                    operation = (
                        f"Helper().write({value})"
                        if seam == "parameter"
                        else f"let destination = URL(fileURLWithPath: Helper().forward({value}))"
                    )
                    helper = "class Helper { func write(_ value: String) { let destination = URL(fileURLWithPath: value) }; func forward(_ value: String) -> String { return value } }"
                    if seam == "field":
                        operation = f"let box = Helper(); box.save({value}); let destination = URL(fileURLWithPath: box.read())"
                        helper = 'class Helper { var saved = "fixed"; func save(_ value: String) { self.saved = value }; func read() -> String { return self.saved } }'
                    entry = f"class Entry {{ func application(_ app: UIApplication, open incoming: URL, options: [String: Any]) -> Bool {{ {operation}; return true }} }}"
                add(
                    f"{language}-interfile-{seam}-{'safe' if safe else 'vulnerable'}",
                    f"native-interfile-{language}",
                    "safe" if safe else "vulnerable",
                    {f"entry/Entry.{suffix}": entry, f"helper/Helper.{suffix}": helper},
                    rationale="Untrusted platform input reaches a path operation across the named seam; literal control has no external input.",
                )

    add(
        "java-ambiguous",
        "native-uncertainty",
        "uncertain",
        {
            "Entry.java": 'class Entry { void inspect(Intent incoming) { write(incoming.getStringExtra("name")); } void write(String value) { if (value.contains("..")) return; new FileOutputStream(value); } void write(Object value) { new FileOutputStream(value); } }'
        },
        rationale="Overload resolution is intentionally uncertain; candidate retention is not exploit ground truth.",
        partial=True,
    )
    add(
        "java-recursive",
        "native-uncertainty",
        "uncertain",
        {
            "Entry.java": 'class Entry { void inspect(Intent incoming) { new FileOutputStream(loop(incoming.getStringExtra("name"))); } String loop(String value) { return loop(value); } }'
        },
        rationale="Recursion prevents complete route evaluation; not scored as a demonstrated exploit.",
        partial=True,
    )

    for language, suffix in (("javascript", "js"), ("typescript", "ts"), ("dart", "dart")):
        for seam, rule in (
            ("direct", "HYBRID-UNTRUSTED-URL"),
            ("helper", "HYBRID-UNTRUSTED-URL"),
            ("bridge", "HYBRID-NATIVE-BRIDGE"),
        ):
            for safe in (False, True):
                value = (
                    '"https://owned.example/help"'
                    if safe
                    else ('Uri.base.queryParameters["next"]' if suffix == "dart" else "route.params.next")
                )
                if suffix == "dart":
                    operation = (
                        "controller.loadRequest(value)"
                        if seam == "direct"
                        else ("forward(value)" if seam == "helper" else 'channel.invokeMethod("open", value)')
                    )
                    text = f"void inspect() {{ final value = {value}; {operation}; }}"
                    helper = "void forward(value) { controller.loadRequest(value); }"
                    if seam == "helper":
                        text = 'import "helper.dart"; ' + text
                else:
                    operation = (
                        "browser.loadUrl(value)"
                        if seam == "direct"
                        else ("forward(value)" if seam == "helper" else "NativeModules.Browser.open(value)")
                    )
                    text = f"const value = {value}; {operation};"
                    helper = "export function forward(value) { browser.loadUrl(value); }"
                    if seam == "helper":
                        text = 'import { forward } from "./helper"; ' + text
                files = {f"entry.{suffix}": text}
                if seam == "helper":
                    files[f"helper.{suffix}"] = helper
                add(
                    f"{language}-{seam}-{'safe' if safe else 'vulnerable'}",
                    f"hybrid-{language}",
                    "safe" if safe else "vulnerable",
                    files,
                    rule,
                    "External input reaches the specified candidate sink; literal control does not. Native bridge implementation remains unknown.",
                    partial=True,
                )
    if include_objc:
        for safe in (False, True):
            value = (
                '[NSURLRequest requestWithURL:[NSURL URLWithString:@"https://owned.example/help"]]'
                if safe
                else "navigation.request"
            )
            text = (
                "#import <WebKit/WebKit.h>\n@implementation Entry\n- (void)webView:(WKWebView *)view decidePolicyForNavigationAction:(WKNavigationAction *)navigation { NSURLRequest *prepared = "
                + value
                + "; [view loadRequest:prepared]; }\n@end"
            )
            add(
                f"objc-local-request-{'safe' if safe else 'vulnerable'}",
                "native-objc-local",
                "safe" if safe else "vulnerable",
                {"Entry.m": text},
                "OBJC-WEBVIEW-UNTRUSTED-REQUEST",
                "Navigation callback request reaches a declared WKWebView; literal owned request is a local control. ObjC dispatch remains unverified.",
                partial=True,
            )
            primitive = "CC_SHA256" if safe else "CC_MD5"
            text = (
                "#import <CommonCrypto/CommonCrypto.h>\nvoid signatureDigest(const void *payload, unsigned int length, unsigned char *digest) { "
                + primitive
                + "(payload, length, digest); }"
            )
            add(
                f"objc-security-digest-{'safe' if safe else 'vulnerable'}",
                "native-objc-digest",
                "safe" if safe else "vulnerable",
                {"Digest.m": text},
                "OBJC-CRYPTO-WEAK-HASH",
                "Declared security-signature digest uses MD5 versus SHA-256; cryptographic protocol design is outside this local primitive check.",
                partial=True,
            )
    return result


def freeze(root: Path, *, include_objc: bool = False) -> dict:
    """Exclusive creation freezes source hashes and labels before analysis imports."""
    root.mkdir(parents=True, exist_ok=False)
    corpus = cases(include_objc=include_objc)
    records = []
    for case in corpus:
        files = []
        for name, text in sorted(case["files"].items()):
            destination = root / "inputs" / case["id"] / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            raw = text.encode()
            destination.write_bytes(raw)
            files.append({"path": name, "sha256": _hash(raw), "bytes": len(raw)})
        records.append({**{k: v for k, v in case.items() if k != "files"}, "files": files})
    manifest = {"schema_version": 1, "corpus": "competitive-followup-synthetic-v1", "cases": records}
    raw = _json(manifest)
    (root / "labels.json").write_bytes(raw)
    (root / "labels.sha256").write_text(_hash(raw) + "\n")
    return manifest


def evaluate(root: Path, *, output: Path | None = None) -> dict:
    """Read only this freshly frozen corpus, then run pure source analyzers."""
    destination = output or root / "results.json"
    if destination.exists():
        raise FileExistsError("Evidence result already exists; use a new snapshot filename")
    source_root = Path(__file__).resolve().parent.parent / "src" / "mobile_audit"
    modules = (
        "source_analysis.py",
        "native_flow.py",
        "native_guards.py",
        "hybrid_analysis.py",
        "objc_analysis.py",
    )
    source_hashes = {name: _hash((source_root / name).read_bytes()) for name in modules}
    from mobile_audit.hybrid_analysis import analyze_hybrid
    from mobile_audit.source_analysis import analyze_sources

    raw = (root / "labels.json").read_bytes()
    labels_hash = _hash(raw)
    if (root / "labels.sha256").read_text().strip() != labels_hash:
        raise ValueError("Frozen label hash changed")
    manifest = json.loads(raw)
    outcomes, totals = [], {}
    started = time.perf_counter()
    for case in manifest["cases"]:
        sources = []
        for entry in case["files"]:
            raw_source = (root / "inputs" / case["id"] / entry["path"]).read_bytes()
            if _hash(raw_source) != entry["sha256"]:
                raise ValueError("Frozen source hash changed")
            sources.append((entry["path"], raw_source.decode()))
        began = time.perf_counter()
        error = None
        try:
            analyzed = (
                analyze_hybrid(sources) if case["family"].startswith("hybrid") else analyze_sources(sources)
            )
            observed = [f for f in analyzed["findings"] if f["rule_id"] == case["rule"]]
            partial = any(c["state"] == "partial" for c in analyzed["coverage"])
            warnings = analyzed["warnings"]
            flow = analyzed["metadata"].get("native_flow", {})
        except Exception as failure:
            error, observed, partial, warnings, flow = type(failure).__name__, [], True, [], {}
        label = case["label"]
        classification = (
            "unscored"
            if label == "uncertain" or (error is not None and label == "safe")
            else ("TP" if observed else "FN")
            if label == "vulnerable"
            else ("FP" if observed else "TN")
        )
        entry = {
            "case_id": case["id"],
            "family": case["family"],
            "label": label,
            "rule": case["rule"],
            "classification": classification,
            "finding_ids": [f["id"] for f in observed],
            "locations": [f["evidence"] for f in observed],
            "partial": partial,
            "expected_partial": case["expected_partial"],
            "partial_expectation_met": partial == case["expected_partial"],
            "wall_seconds": time.perf_counter() - began,
            "error": error,
            "warnings": warnings,
            "native_flow": flow,
        }
        outcomes.append(entry)
        family = totals.setdefault(
            case["family"],
            {
                "TP": 0,
                "FP": 0,
                "FN": 0,
                "TN": 0,
                "unscored": 0,
                "partial": 0,
                "failures": 0,
                "wall_seconds": 0.0,
            },
        )
        family[classification] += 1
        family["partial"] += int(partial)
        family["failures"] += int(error is not None)
        family["wall_seconds"] += entry["wall_seconds"]
    result = {
        "schema_version": 1,
        "labels_sha256": labels_hash,
        "analyzer_source_sha256": source_hashes,
        "analyzer_sources_unchanged_during_run": all(
            _hash((source_root / name).read_bytes()) == value for name, value in source_hashes.items()
        ),
        "cases": outcomes,
        "families": totals,
        "wall_seconds": time.perf_counter() - started,
        "rss": {
            "state": "unmeasured",
            "reason": "No child RSS observation was attempted under the project privacy boundary.",
        },
        "competitors": {
            "state": "unmeasured",
            "reason": "No fresh competitor execution was performed; these fixtures measure APSA only.",
        },
        "limitations": "Fixed synthetic modeled paths only; candidate presence is not exploitability, partial cases remain partial, and uncertainty cases are unscored.",
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        stream.write(_json(result))
    return result


if __name__ == "__main__":
    location = Path("/private/tmp/apsa-competitive-eltug2qc/corpus")
    freeze(location)
    measured = evaluate(location)
    print(
        json.dumps(
            {
                "labels_sha256": measured["labels_sha256"],
                "families": measured["families"],
                "wall_seconds": measured["wall_seconds"],
            },
            indent=2,
        )
    )
