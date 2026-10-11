# Unreleased competitive follow-up — 2026-10-11

This working-tree change preserves the published 1.5.1 package and frozen historical
measurements. It uses rule version `2026.10.11.apsa.next`; no release, tag, publication
or approved baseline is implied. The earlier [large-input follow-up](LARGE_INPUT_FOLLOWUP.md)
remains included. The subsequent [remaining follow-up](REMAINING_FOLLOWUP.md)
extends artifact selection/integrity and runtime acquisition; earlier snapshot
measurements below retain their original meaning.

## Implemented slices

| Area | Current behavior | Limit |
| --- | --- | --- |
| Native guards | Path guards bind the same input, precede use and cover modeled branches. Wrong-input, late, incomplete guards and unknown transforms cannot suppress a finding. | Lexical/canonical checks cannot prove absence of filesystem symlinks or races. |
| Native flow | Bounded cross-file arguments, helper returns, constructor/instance field summaries and source-to-sink traces for modeled Java/Kotlin/Swift calls. | Ambiguous/dynamic dispatch, recursion/budgets, callbacks, lifecycle and incomplete primary constructors stay partial. |
| Dependencies | Literal Gradle project-directory mapping; selected app/runtime lock evidence; OSV query batching, item-specific pagination, hydration and local transmission exclusions. | Lock freshness, installed-build correspondence, SDK reachability and actual build execution remain unverified. |
| Runtime | V2 login/account-switch/logout workflows bind account canaries, transition markers and captures to platform/package/observed installed build. Missing or contradictory evidence stays inconclusive. | The subsequent typed recorder is exercised on new synthetic app models; live network acquisition and physical-device measurement remain unsupported. Manual evidence cannot alone confirm a vulnerability. |
| Hybrid | Bounded JS/TS/Dart tokens/blocks with argument/return summaries, relative named JS/TS and literal Dart imports; WebView, JS execution, SQL and native-bridge candidates. Plain text `.jsx`, `.tsx`, `.jsbundle` are staged as code. | Always partial: no full grammar, sanitization proof, callbacks, destructuring/ASI completeness or bridge implementation proof. Compiled/non-UTF8 bundles are omitted explicitly. |
| AAB/IPA | AAPT2 scalar strings/integers/booleans/files/aliases resolve only when modeled modules agree. Detached CMS verifies the exact primary CodeDirectory, separately from page/entitlement hashes. | Device qualifiers/conflicts/flags/dynamic references/cycles stay unresolved. The subsequent follow-up supports explicit `.apks` selection, sparse pages/resource seals and supplied-anchor chains. Installed split merging, Apple signer identity, app authenticity and encrypted native paths remain unverified. |
| Developer evidence | Runtime plans include static finding IDs/traces. CLI/MCP comparisons can include scope/build/assertion pairing and source traces. | Finding disappearance is `no-longer-observed`, never automatic remediation. Source fingerprints are not installed binary identity. |

## Source-build and network options

Paths below are relative to the selected scan root. These options choose recorded
evidence; they do not execute Gradle or authenticate an installed app.

```sh
apsa scan ./source --dependency-module app \
  --runtime-configuration releaseRuntimeClasspath \
  --dependency-evidence app/gradle.lockfile --json

apsa scan ./source --online --osv-query-mode batch \
  --osv-exclude-name 'com.example.private:*' \
  --osv-exclude-coordinate 'npm:@private/*' --json

apsa reports compare BEFORE_ID AFTER_ID --verification --json
```

`auto` preserves single-query behavior for up to 100 eligible unique packages and
batches larger inventories. `legacy` preserves the historical bounded path;
`batch` explicitly selects batch behavior. Batching is still bounded (default
1,000 packages, 100 queries per request, 2,000 request operations). Partial item
pages, hydration failures and budgets remain per-package partial/not-checked.
Exclusion globs are case-sensitive, per-run local policy. An excluded coordinate
is never sent, and an older cached answer cannot mark that run checked. Cached
vulnerability evidence may still be shown as historical intelligence.

MCP `audit_scan` and `audit_start` expose `dependency_module`,
`runtime_configuration` and optional `dependency_evidence`. `dependency_check`
exposes `query_mode`, `exclude_ecosystems`, `exclude_names`, and
`exclude_coordinates`. `reports_compare(verification=true)` returns additive
paired observation evidence. Foreground/background CLI scans carry the same options.
The changed source tool contract and pending served check are recorded in
[MCP_SECURITY.md](MCP_SECURITY.md).

## Runtime evidence contract

`runtime plan` now emits an editable schema-v2 scenario. `workflow.accounts`
maps account labels to canary/login marker labels; `workflow.transitions` binds
login, account switch and logout to baseline/snapshot, from/to account, delivery
and state markers, and a capture surface. Build changes cannot clear previous
evidence. `static_links` refer to exact static finding IDs and rule IDs.

`operator_captures` accepts only digest/size/marker observations with exact
platform/package/build/account/state/surface binding. It rejects arbitrary
commands, headers, bodies, URLs and unknown fields. These captures remain
operator-supplied with acquisition unverified. Installed identity observations
do not establish correspondence with audited source. This run operated no existing
app, device, history, upload, output media, UI, clipboard or service-log surface.

## Validation and external comparison

[COMPETITIVE_CORPUS.md](COMPETITIVE_CORPUS.md) records independently frozen new
synthetic labels, the initial errors, later snapshots, source hashes, timing and
remaining partial cases. A synthetic score is a regression measurement for those
cases, not a general accuracy claim. Historical blind and competitor results were
not overwritten. Current competitor executions, RSS, real-device auth/network,
Apple signer identity and installed `.apks` delivery remain unmeasured; the bounded
synthetic selection, chain and resource checks are recorded separately in the
[remaining follow-up](REMAINING_FOLLOWUP.md).

Focused unit, parser, CLI/background option and report tests use only newly
generated synthetic inputs under `/private/tmp/apsa-competitive-eltug2qc`.
The host guard blocks child RSS observation; end-to-end synthetic parser tests
use a test-only RSS adapter, preserving CPU, timeout, file/output and privacy limits.
No production resource limit or project privacy policy was weakened. MCP tests
requiring the denied SDK directory are excluded; the full suite is not claimed.

Validation before independent review: 423 focused tests passed, plus 32 adoption
tests (2 excluded), with the final 7 integration tests passing after the real
parser-staging check was added. Ruff and Python-3.12 Pyright pass. Counts overlap;
they are not summed as unique tests. The review artifact binds the final aggregate
run and verdict to its exact full working-tree snapshot.

Review-v1 found a per-callable whole-file package search and missing hybrid file
state in claim verification. Package extraction is now once per file, including
the negative case, and callable owner identities are cached. A new 32-module,
32,000-method, ~32MB no-call corpus completed direct profiling in 1.051 seconds;
a separate cold parser-worker/staging run completed in 5.333 seconds with 32 files
and 32,221,366 staged bytes. Native flow explicitly remained partial at the
4,096-callable inventory budget. The worker retained 45 CPU seconds, wall/output/file
limits and the project guard; RSS was unmeasured under the synthetic-only adapter.
The initial large direct run was interrupted after exceeding 45 wall seconds,
not counted as a completed scan. These are different workloads from historical
benchmarks, with no general speedup claim. Hybrid claim verification now preserves
partial file state and candidate paths through public API, CLI and the actual MCP
tool body; the served SDK check is still pending.

Architecture review-v1 also found that origin-wide path suppression could erase
an unchecked sibling construction. Canonical proof and provisional candidate
closure are now bound to the exact construction/caller route. Source-level lexical
checks remain limited to the same unchanged input. Safe and unsafe calls sharing
one finding ID retain separate bounded route evidence; untracked/budget routes
remain partial candidates. Java/Kotlin/Swift sibling paths, both helper call orders,
unknown transformations and evidence-budget cases are regression-tested.

The final aggregate run after review-v1 rework passed 486 tests, with two excluded
tests: the existing archive-fixture SARIF case and the served MCP SDK contract
case. It completed in 4.47 seconds with fresh synthetic inputs and the test-only
RSS adapter above. Ruff passes for changed Python files; Python-3.12 Pyright
passes across `src/mobile_audit` using the project interpreter. A broader Ruff
invocation also exposed 37 existing style errors in unchanged legacy tests;
those are outside this change. No full-suite or served MCP pass is implied.

Upstream semantics used: [Semgrep language support](https://docs.semgrep.dev/supported-languages),
[OSV batch queries](https://google.github.io/osv.dev/post-v1-querybatch/),
[AAPT2 Resources.proto](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/tools/aapt2/Resources.proto),
[OpenSSL CMS verification](https://docs.openssl.org/3.0/man1/openssl-cms/),
[Apple CodeDirectory structures](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/osfmk/kern/cs_blobs.h),
and [bundletool device selection](https://developer.android.com/tools/bundletool).
Competitor feature descriptions are upstream/vendor claims, not head-to-head measurements.
