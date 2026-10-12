# Benchmark metric and completeness contract

`benchmarks/competitive.py` uses frozen synthetic case labels and declared rule
mappings. A report return, an alert, and verified execution coverage are distinct
observations. These fields describe this fixture suite and coverage contract;
they do not establish whole-app accuracy or a cross-tool product ranking.

## Sampling and execution states

The kind filter selects records by `input_kind`. `selected_cases` includes every
selected record; `cases` includes selected records with a result for the requested
tool. `missing_tool_cases` exposes absent tool results, which are excluded from
all rates. Cases with an explicit tool result and missing/unknown `state` count
as `failed`; missing states also increment `missing_state`.

| State | Meaning | Contributes TP/FP/FN/TN? | Eligible risky completion penalty? |
| --- | --- | --- | --- |
| completed | Explicit coverage and completeness evidence satisfies the benchmark contract | Yes | Included |
| partial | Explicit incompleteness, warning, partial check, or not-run check under the benchmark contract | No | Included |
| unmeasured | Coverage/completeness contract absent, unknown, or missing state | No | Included |
| unsupported | No declared category mapping | No | Excluded |
| failed / unstable | Execution/report failure or repeat disagreement | No | Included |

Optional not-run checks do not by themselves make a **product audit** incomplete.
The benchmark's completion contract is stricter: it rejects any not-run coverage
row for scoring, as before. Empty coverage with an explicit `audit_incomplete=false`
retains the established benchmark behavior. Invalid or missing coverage row states
cannot establish completion. Explicit partial evidence takes precedence over
other observations with unmeasured coverage.

`completed` and `scored_cases` both equal TP + FP + FN + TN. `eligible_cases` is
`cases - unsupported`. Unsupported cases remain visible in the sampling totals.
The frozen category mappings, truth labels, and TP/FN/TN eligibility are unchanged.

## Rates and denominators

All zero-denominator rates are JSON `null`, including no-eligible-case slices.
The `denominators` object records the divisor for each rate.

| Field | Numerator | Denominator |
| --- | --- | --- |
| completion_rate | completed | cases (includes unsupported results) |
| eligible_completion_rate | completed | eligible_cases |
| coverage_measurement_rate | completed + partial | eligible_cases |
| completed_alert_precision / alert_precision | TP | TP + FP |
| completed_case_recall | TP | TP + FN |
| eligible_risky_completed_detection_rate / end_to_end_recall | TP | TP + FN + failed_risky + partial_risky + unmeasured_risky |

The end-to-end denominator deliberately retains eligible risky failures and
incomplete/unmeasured work. A risky partial report with an alert still contributes
only to that denominator, never to TP. This prevents completion filtering from
inflating recall. The historical `alert_precision` and `end_to_end_recall` keys
remain backward-compatible aliases with explicit scopes; `metric_aliases` records
the aliases. `coverage_unmeasured_cases` aliases `unmeasured`.

`coverage_measured_cases` counts explicit completed/partial coverage evidence.
`coverage_measurement_rate` measures availability of this execution contract,
not category breadth, rule accuracy, or proportion of an application's code scanned.

## Partial and unmeasured observations

Each of `partial` and `unmeasured` has four separate counters:

- `*_detected_risk`: risky fixture with a matched category alert.
- `*_silent_risk`: risky fixture without a matched category alert.
- `*_safe_alert`: safe fixture with a matched category alert.
- `*_safe_silent`: safe fixture without a matched category alert.

These are observations against the frozen fixture label, not scored precision,
recall, successful execution, proof of safety, or a false-positive rate. Together
they account for every partial/unmeasured result and preserve visible alerts
without treating an incomplete silent report as a scored FN or TN.

## MobSF and measurement limits

The MobSF normalizer explicitly preserves `coverage=null` and
`audit_incomplete=null`: MobSF does not expose APSA's per-rule execution coverage
contract. A valid report in a mapped category is consequently **unmeasured**, not
an analyzer partial failure. An unsupported category remains unsupported. Actual
selected analyzer/decompiler errors still fail report validation. Normalized
alerts remain available through the unmeasured observation counters.

The retained end-to-end completion penalty can make an unmeasured-only slice
zero even when matched alerts exist. That value describes inability to establish
completed detection under this benchmark contract; it cannot justify a competitor
accuracy or failure ranking. Existing recorded benchmark heads remain historical
artifacts and are not relabeled. This change adds semantics and synthetic tests,
not new real competitor measurements.

Timing includes recorded report returns independently of coverage, including
partial/unmeasured returns. RSS remains the existing actual process-tree/service
measurement with its distinct scopes; no hidden substitute or estimated RSS is
introduced. These metrics do not change fixture generation, compiler/device
operations, process measurement, or source-only validation.

## Product and GitHub Action completeness

`src/mobile_audit/completeness.py` is the stdlib-only evidence contract. Core
re-exports `report_incomplete`; the Action loads that exact source file via
`runpy`, so standalone `python -I scripts/action_summary.py` does not import APSA
or optional package dependencies. Source-only release staging and wheels include
the module as normal package source.

The contract checks report/inventory partial flags, incomplete fingerprints,
partial input staging/app scope, explicit partial coverage, the latest partial
runtime assessment, and errors from a requested online query. The latest runtime
entry supersedes earlier runtime attempts. Core recomputes from current evidence
and ignores cached summaries so refresh can clear old incompleteness. The Action
also conservatively honors a cached incomplete summary or exit code 3, and marks
failed envelopes/non-audit exit codes as failed even if a report is attached.
It accepts full reports, direct CLI envelopes, and policy envelopes containing
`data.report`.

Policy and severity outcomes remain independent of completeness. Every gate
reason except `partial-audit` fails the threshold helper, including required
rules, baseline mismatches, expired waivers, and severity thresholds. Without a
gate, only non-candidate findings at or above the selected severity count. Exit
code 4 alone does not imply incomplete execution. Tolerating partial execution
never suppresses these policy/severity failures.
