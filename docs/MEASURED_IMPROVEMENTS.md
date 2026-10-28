# Measured improvements, 2026-10-23

This development measurement uses fresh public source archives and synthetic
source ZIPs. No upstream application or build script was executed. It is not a
new blind holdout, a production accuracy estimate, or a device security test.
The measured working tree reports version 1.6.2; source hashes identify these
unpublished changes more precisely than that version or the unchanged Git HEAD.

## What changed

Profiling real Home Assistant and Element X Android source exposed repeated
evaluation of fluent receivers and qualified members. One diagnostic observed
89,126 value evaluations across only 271 distinct nodes. Import lookup also
repeatedly scanned the same declarations.

The analyzer now passes already evaluated values through receiver identity,
storage effects, member types and assignment lookup. It indexes actual import
declarations once per analysis. It does not cache expression results across
frames, suppress findings, or increase the 45 CPU-second / 90 wall-second parser
budgets. OS isolation remains enabled.

Independent review reproduced a second path: unresolved members of a known
source type doubled root evaluations at each nesting level. The final fix makes
the reviewer's depths 4/8/12/16 evaluate the root once, with 5/9/13/17 total value
calls. Regression tests cover declared and unresolved fields, reads and writes,
Java, Kotlin and Swift, and retained conservative mutator taint.

Typed SIGXCPU exits now explain that the CPU budget was exceeded and the audit
is incomplete. They no longer suggest disabling isolation. The evaluator now
attempts both sides independently, preserves scope on errors, leaves failed
sides unscored and retains bounded stdout/stderr with execution metadata. The
v4 collector validates that contract while retaining historical v3 support;
malformed oversized duration integers cannot abort partial artifact collection.

The later Nextcloud profile found repeated lexical type lookup as another
hotspot. A bounded, artifact-only cache prototype reduced lookup work, but its
40 CPU-second diagnostic still stopped without a final report. That experiment
does not prove completion within the production budget or output parity. It was
not added to the implementation. Memory-limit failures require separate work.

## Public security-fix pairs

The same 13 frozen public pairs were measured before and after the changes on
macOS arm64 with Python 3.12.13. The old evaluator stopped a pair after its first
failure, so it attempted only 15 sides. The final evaluator attempted all 26.

| Operational measure | Before | Final |
|---|---:|---:|
| Pairs returning both reports, out of 13 | 2 | 7 |
| Reports on the same 15 previously attempted sides | 4 | 9 |
| Execution errors on those same 15 sides | 11 | 6 |
| Reports on all 26 sides | Not measured | 14 |
| Execution errors on all 26 sides | Not measured | 12 |

All 14 returned reports are explicitly **partial**; none establishes complete
coverage. The final evaluator exited 1 because six pairs still failed. Of the
12 failed sides, ten hit the CPU limit (Nextcloud, Element classic, Amaze,
FairEmail and Tasks; both sides each), and two hit the memory limit (OpenClaw
iOS). They are unscored. FairEmail and Tasks retain empty expected-rule labels
from the frozen truth, so the evaluator's in-scope `unscored_sides` count is 8;
the operational count across every pair is 12. This is not evidence that the
current product has no path-traversal rules.

Home Assistant's vulnerable version changed from a confirmed CPU-limit failure
to a report in **17.51 seconds**, and its fixed version returned in 17.29 seconds.
Element X Android changed from an execution failure to reports in **26.50 / 27.04
seconds**. The legacy Element error lacks sufficient retained evidence to assign
its exact failure cause. These are single executions with concurrent diagnostics,
not a stable timing distribution. Resource limits and OS isolation were retained.

Frozen-label observations on the seven report-returning pairs are:

| Pair | Vulnerable version | Fixed version |
|---|---|---|
| Home Assistant Android | Expected URL alert absent | Expected alert absent |
| Element X Android | Expected URL alert absent | Expected alert absent |
| Element X iOS | Expected URL alert absent | Expected alert absent |
| SMSSync | SSL bypass alert at labeled line 807 | Expected alert absent |
| OpenClaw Android | Bridge alert at labeled line 126 | Bridge alert remains at line 142 |
| Tiddloid | File-access alerts at labeled lines 318/319 | Expected alert absent |
| Wikipedia iOS | ATS alerts in five labeled plist files | Expected alert absent |

The evaluator records TP 4, FN 3, FP upper bound 1 and TN 6 for these partial
observations, with three line-level hits and two discriminating pairs (SMSSync
and Tiddloid). Wikipedia's evidence has no line location. OpenClaw's fixed
version adds an internal trust guard while keeping bridge registration; a
generic bridge-presence candidate does not by itself prove a remaining
vulnerability. The three URL misses remain unresolved. Do not compare aggregate
recall with the old run, which could score only two pairs.

The four previously returned reports retain identical complete finding objects,
including IDs, evidence and excerpts: no finding was added or removed. Truth,
amendments and all 71 tracked source/evaluator inputs remained unchanged during
the final measurement. The intermediate r1 rerun was deliberately interrupted
after review found another performance path; it is not the final benchmark.

## Controlled comparison with MobSF

The actual pinned MobSF 4.5.3 service scanned the same 40 source ZIPs as APSA.
The service ran in an owned Docker container on an internal network; a local
Docker-exec HTTP transport invoked upload and forced scan. This was the full
service, not a reimplementation of its rules. The container and network were
removed after measurement.

| Shared rule mapping, 32 cases | APSA | MobSF |
|---|---:|---:|
| Risky cases with a mapped alert, out of 14 | 14 | 12 |
| Safe controls with a mapped alert, out of 18 | 0 | 4 |

These are observations, not completed-analysis precision or recall. APSA marked
all 40 reports partial. MobSF does not expose the same coverage contract, so the
32 mapped results have unmeasured coverage. Eight URL cases have no supported
cross-tool mapping and are excluded from this shared table; this is a mapping
limitation, not proof that MobSF cannot analyze them.

Across all 40 controls APSA returned 18/18 risky alerts and 3/22 safe alerts.
The three safe alerts retain conservative external-ancestry uncertainty; neither
the inputs nor their labels were changed to improve the score. The final APSA
rerun preserves every case's state, matched rules, finding evidence and coverage
exactly. These development fixtures do not establish general superiority.

The tools have different timing scopes: APSA starts a fresh CLI and store; MobSF
uses a warm service with upload, forced scan and Docker transport. Concurrent
diagnostics also ran. Timings therefore do not support a speed ranking. Process
RSS was unmeasured on this macOS run.

## Validation and reproduction

The final code passed 5,880 tests, with 41 skipped and 6 subtests passed; Ruff,
format checks and Pyright passed. Both independent review lanes approved the
12-file implementation snapshot. An offline wheel build contains the exact
changed production modules. This measurement did not publish a registry release.

Run fresh measurements from the repository root in the installed environment:

```sh
run_root=$(mktemp -d /tmp/apsa-measurement-XXXXXX)
.venv/bin/python -m benchmarks.fpfn_eval --work "$run_root/public-work" --out "$run_root/public.json"
.venv/bin/python benchmarks/competitive.py generate --fixtures "$run_root/controls"
.venv/bin/python benchmarks/competitive.py run --fixtures "$run_root/controls" --out "$run_root/apsa" --repeats 1
```

Public archive acquisition needs network access. Use the normal parser isolation
policy; running from a nested execution sandbox may require permission to launch
the OS-isolated parser. Preserve the source, truth, archive and fixture hashes
when comparing runs. See [the evaluator contract](HOLDOUT_REPORT_CONTRACT.md) for
failure and coverage semantics.

The local evidence bundle is
`../.omx/artifacts/apsa-measured-20261023/` relative to the repository root. It
retains raw reports, replay scripts, stdout/stderr, invocations, hashes, baseline
sources and both review rounds. Large public archives and raw reports are not
included in the package.

| Provenance | SHA-256 or pin |
|---|---|
| Control manifest | `9bde6e1656f78aec1155f4cbde47487f59c1d5d28abb4e6098acb9b2c306f807` |
| Public truth | `229b9070166881b136c765eaa65893dd99b09421464c72d7337b7bce97bf535a` |
| Public truth amendments | `13fc06b21d103cfeda656ee189971cdf49c298b8a76edc353360e37c69a211df` |
| Reviewed implementation patch | `00a4d93cf68566d703b36bff9d6f5d3606c2457c2d09b8234a6e94250edd327a` |
| Final control result | `df1198d5f8bd940472cbef722531776bb0ed5276527bdb3c89ae87df07b7f4c4` |
| Final public result | `e1ba88daaefb100c19c7d01cad91a48b1b2da1be9dda7b148745ee4425d66a0b` |
| Final public source manifest | `3a5cd0685a56a27f97d869d19374d26d2335ff342519a73d9978083bbc1a5ad4` |
| MobSF source commit | `d3869adc464b89db92a6a8a9e2dc13376f4a4c25` |
| MobSF image digest | `opensecurity/mobile-security-framework-mobsf@sha256:5113fbad0727445dda01afdccafea5e107bfa8632ead8a169492f5caa8aa1b7c` |
