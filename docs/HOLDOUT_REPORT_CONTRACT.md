# Holdout report collection contract

`blind-holdout-pairs.yml` runs from a checkout that supplies
`benchmarks/fpfn_truth_holdout2.json`. Source-only release and review stages
intentionally omit holdout truth, downloaded archives, and retained results.
Those stages can test the collector with new synthetic inputs, but cannot
reproduce the historical holdout measurement by themselves.

The public protocol in
[`BLIND_PAIRS_RESULTS.md`](../benchmarks/BLIND_PAIRS_RESULTS.md) records the
holdout truth SHA-256 as
`c42c9cd345265e8621f5f8d46dce2bc8c0b993ba05f782c97756bc8c8eaae5df`.
This is a historical hash-only reference; this change does not read or reverify
the holdout dataset. A development rerun must record its checkout SHA and the
hash of the actual supplied truth, and must not claim a new blind measurement.

The producer, `benchmarks.fpfn_eval`, emits `apsa-fpfn-results-v4`, binding
`truth_sha256` to the exact truth bytes. The collector independently validates
that binding, the exact pair IDs and commits, side archive URL/hash/size,
provenance, label fields, outcomes, and recomputed totals. This workflow accepts
unamended truth only. Producer schema changes require corresponding collector
contract and synthetic fixture updates. Historical v3 results remain readable.

V4 attempts both sides independently and preserves identity and scope on failures.
A failed side is `unscored`, never FN or TN; pair errors count in both applicable
summary tables. `scored_pairs` counts eligible pairs with at least one scored
side. A run with any failed pair saves results and exits nonzero. Returned partial
reports still contribute observational findings; `report_returned` and
`audit_incomplete` explicitly separate receiving a report from complete coverage.
Neither a TN nor a collected artifact proves that a vulnerability was repaired.

Each attempted CLI scan retains `execution.json`, `stdout.txt` and `stderr.txt`
in its `scan` directory. Execution metadata includes argv, exit status, duration,
timeout state, and each stream's full SHA-256 and byte count. Stream artifacts
retain at most 1 MiB each with explicit truncation metadata. These diagnostics
remain in the work directory; this report collector copies report JSON only.
The v4 consumer validates execution metadata and rejects scored failure states,
hidden side errors and incorrect scope/error totals.

Reports have exactly the truth-derived path
`<pair-id>/<vulnerable|fixed>/scan/report.json`. The collector never searches
the work directory. A fresh destination receives those same relative paths and
`collection.json`, containing status, evaluation outcome, report hashes, and
errors. A failed evaluation or missing/invalid evidence returns nonzero while
retaining safe partial reports. The artifact upload runs even after failure;
an uploaded artifact alone does not establish complete collection or a passing
benchmark.
