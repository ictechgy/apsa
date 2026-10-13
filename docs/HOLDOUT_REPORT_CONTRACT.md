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

The producer, `benchmarks.fpfn_eval`, emits `apsa-fpfn-results-v3`, binding
`truth_sha256` to the exact truth bytes. The collector independently validates
that binding, the exact pair IDs and commits, side archive URL/hash/size,
provenance, label fields, outcomes, and recomputed totals. This workflow accepts
unamended truth only. Producer schema changes require corresponding collector
contract and synthetic fixture updates.

Reports have exactly the truth-derived path
`<pair-id>/<vulnerable|fixed>/scan/report.json`. The collector never searches
the work directory. A fresh destination receives those same relative paths and
`collection.json`, containing status, evaluation outcome, report hashes, and
errors. A failed evaluation or missing/invalid evidence returns nonzero while
retaining safe partial reports. The artifact upload runs even after failure;
an uploaded artifact alone does not establish complete collection or a passing
benchmark.
