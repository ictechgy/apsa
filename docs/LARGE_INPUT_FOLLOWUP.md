# Large-input follow-up — unreleased, 2026-10-11

This change addresses the concrete large-input follow-ups listed in the 1.5.1
handoff. It is a local working-tree change with rule version
`2026.10.11.apsa.next`, not a publication or a new approved baseline.
The published 1.5.1 records and frozen blind truth/first-run results are unchanged.

## Input selection

The existing staging kinds remain `code_and_config`, `other_text`,
`localized_values`, and `tests`. Within `code_and_config`, configuration comes
first, then app native code, JS/TS/Dart, own headers, lock inventories, and
vendored code. A large `package-lock.json` cannot consume the byte budget before
app code is considered. Native AST analysis uses the same priorities.

Within a priority, files are taken one at a time from each inferred module group in
stable path order. The grouping uses the path prefix before `src`, SwiftPM's
`Sources/<target>`/`Tests/<target>`, conventional Android/iOS/modules/packages
prefixes, or the top directory. It does not resolve a Gradle/Xcode build graph,
`projectDir`, or a module's dependencies. Separate priority groups still have
separate turns; a byte budget can leave a large file out even when its module is
next. The entry/depth limits and descriptor/identity checks remain in effect.

Only explicit test layout patterns (`src/test*`, `src/androidTest*`, `Tests`,
`UITests`, `__tests__`, integration tests and recognized JS/Dart test filenames)
are deprioritized. A custom directory ending in `Tests` is treated as potentially
shipped code. `Frameworks` alone does not establish third-party origin;
`.framework`/`.xcframework` bundles and existing vendor layouts still do.

`inventory.input_snapshot` retains `omitted` and adds:

- `omitted_by_module`: inferred module group name to existing kind/file/byte counts.
- `omitted_module_groups`: total number of groups with known omitted files.
- `omitted_by_module_truncated`: whether the 256 named-group limit was reached.
- `omitted_other_modules`: kind/file/byte totals combined beyond that limit.

These count enumerated candidate files, including read/copy/size failures.
Unreadable or unvisited directories cannot supply known file counts; their
existing warnings and incomplete app scope still apply. All omitted candidate
files remain in the kind totals even if their module names are combined.

## Reporting

`reports compare` retains the existing finding deltas and adds
`audit_incomplete_before/after` and `input_before/after` (fingerprint,
fingerprint_complete, input_snapshot). A finding disappearing from a truncated
input remains `no_longer_observed`, never proof of remediation.

The GitHub Action summary shows staged file/byte counts, app-scope status,
omissions by kind, and how many inferred module groups were affected. It does
not rely solely on a cached summary flag when input/coverage says partial.

CycloneDX retains input fingerprints as `apsa:input-fingerprint`,
`apsa:input-fingerprint-complete`, and `apsa:input-fingerprint-scope` component
properties. A partial fingerprint is not emitted as an application `hashes`
entry. Complete audited-input hashes retain their existing export behavior.

## Source processing

JS/TS source-pattern checks preserve template literals, escaped backticks,
multiline text and nested `${...}` templates while blanking expression comments.
Offsets and line numbers stay stable. Native-language comment cleaning remains
unchanged. This remains heuristic pattern analysis, not a JavaScript AST or
interprocedural engine.

AST analysis reuses the bounded node inventory and caches each class's field
declaration list. Field value/type inference still runs in each function's
context. Grammar recovery, adaptation spans, node/byte budgets and candidate
evidence states retain their existing behavior.

## Local validation

All execution inputs were newly generated synthetic fixtures in a temporary
directory outside the workspace/runtime data paths. Focused source/report tests
passed: 272 tests, with four excluded cases for existing binary fixtures, MCP
startup and RSS enforcement. Ruff lint/format, Pyright (Python 3.12), and
`git diff --check` passed. This is not a full-suite validation.

The Local Media privacy sandbox denies psutil's child-task memory inspection.
A temporary test-only adapter therefore omits the RSS observation for newly
generated `mobile-audit-work-*` parser snapshots while retaining subprocess,
CPU/file/output/time limits and the project privacy sandbox. Production code is
unchanged in this respect. These runs do not verify RSS enforcement or MCP
startup: the sandbox also denies the dependency's `prompts` module directory.
Existing APK fixtures and live service/history/files/UI surfaces were not used.

A cProfile probe used eight synthetic Java files, 8,302,400 bytes and 8,000
methods. Before the AST optimization it took 1.896 s; after, 0.401 s. The complete
result JSON had the same SHA-256 in both runs:
`252c5060ceda613d70b29cb5ac777da4593413ad91b6c3231ee2f6eceb4cfebb`.
The comparison isolates the AST optimization (both runs already use the new
scheduling). It is a single profiled synthetic shape, not the earlier real-app
corpus or evidence of the same speedup on arbitrary apps.

A second, unprofiled probe used 32 synthetic Java files, 33,209,600 bytes (below
the 33,554,432-byte AST budget), and 32,000 methods. Across three runs per
variant, median AST time fell from 6.850 s to 1.063 s (6.44x). All methods were
analyzed with no warnings and identical complete result JSON SHA-256:
`0b6cefc337999033bc2f118315e0dcf093dd3c508698f402bc4414af0d2c470b`.
It measures the same isolated optimization on a synthetic shape, not end-to-end
scan time, real-app coverage or RSS.

## Remaining analysis milestones

The inherited 1.5.0 interprocedural/guard/PendingIntent/large-branch limitations,
blind misses, new holdout curation and the later OSV/Gradle/AAB/IPA/native/device
milestones remain separate work. No new blind score, remediation claim,
publication, tag or approved baseline is established by this follow-up.

Later on the same day, the working tree added bounded native guard/cross-file flow,
OSV batching, Gradle mapping/variant selection, hybrid/runtime evidence and AAB/CMS
slices in [COMPETITIVE_FOLLOWUP.md](COMPETITIVE_FOLLOWUP.md). This later change has
its own validation/review snapshot; the measurements above retain their original
scope. Device split delivery, Apple signer trust, full language/lifecycle analysis
and historical vendor catalogs remain separate work.
