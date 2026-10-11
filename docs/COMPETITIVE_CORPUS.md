# Competitive follow-up synthetic corpus

This separate corpus evaluates the new bounded native and hybrid source paths.
It does not replace the historical benchmark or establish a competitor ranking.

The source generator and hand-assigned labels live in `tests/competitive_corpus.py`.
Labels describe the explicit route to one targeted rule: vulnerable controls pass
external input to a candidate sink; safe controls use literals or a dominating
same-input traversal check beneath a synthetic root without symlinks. Ambiguous
overload and recursive cases are labeled uncertain and excluded from TP/FP/FN/TN.
Native bridge labels describe untrusted bridge arguments, not a proved native exploit.

Before importing the analyzers, the runner exclusively creates a fresh directory,
writes each source hash and label to `labels.json`, and freezes its SHA-256 in
`labels.sha256`. It verifies those hashes before each direct analyzer call. Results
retain case IDs, finding IDs and locations, partial state, warnings, errors and wall
time, plus per-family TP/FP/FN/TN and unscored counts. Scan failures remain visible.

The designated run directory is `/private/tmp/apsa-competitive-eltug2qc/corpus`.
The runner refuses to overwrite an existing corpus or result. Historical inputs,
results, device state and private media are not used. Tests validate label and
freeze contracts; they do not assert perfect scanner scores.

JS/TS/Dart coverage is partial by design. The synthetic cases do not cover real
application lifecycle, dynamic dispatch, callbacks, symlinks, encrypted code,
native bridge implementations, authentication backends or physical devices.
RSS and fresh competitor measurements are unmeasured. Wall times are local
observations from this small corpus, not general performance guarantees.

The first 50-case run froze label hash
`1a1fcfabaa551e92880151b46384ede6f03a33afd68fb1f9c298896999559f92`.
Its unchanged inputs were rerun after the three rooted-path guard false positives
and one Dart literal-import helper omission were fixed. Labels were not changed to
improve the scores. The first result remains `corpus/results.json`; the second is
`corpus/snapshots/after-fixes.json`. The first run did not record analyzer source
hashes, so its code snapshot cannot be reconstructed from this evidence alone.
The second records selected module hashes before evaluation and verifies they
remained unchanged during that run.

| Family | First TP/FP/FN/TN | Second TP/FP/FN/TN | Partial cases |
| --- | --- | --- | --- |
| Java guards | 3/1/0/0 | 3/0/0/1 | 0 |
| Java interfile | 3/0/0/3 | 3/0/0/3 | 0 |
| Kotlin guards | 3/1/0/0 | 3/0/0/1 | 4 |
| Kotlin interfile | 3/0/0/3 | 3/0/0/3 | 6 |
| Swift guards | 3/1/0/0 | 3/0/0/1 | 0 |
| Swift interfile | 3/0/0/3 | 3/0/0/3 | 0 |
| JavaScript | 3/0/0/3 | 3/0/0/3 | 6 |
| TypeScript | 3/0/0/3 | 3/0/0/3 | 6 |
| Dart | 2/0/1/3 | 3/0/0/3 | 6 |
| Ambiguity/recursion | 2 unscored | 2 unscored | 2 |

Totals are 26 TP, 3 FP, 1 FN, 18 TN initially and 27 TP, 0 FP, 0 FN,
21 TN subsequently, with two unscored uncertain cases, 30 partial cases and zero
scan failures in both. Local direct-call wall times were 0.02344 and 0.02128
seconds; these timings exclude process/import startup and are not a speed ranking.
Kotlin adaptation contributes partial coverage even when the direct flow finishes.

Four new Objective-C local request/digest controls were frozen separately in
`corpus/objective-c-extension` with label hash
`baf4937aa7d9db2675b4685af4f5f0555addf2e4c0ffd70c713c0d60c368d568`.
The expanded 54-case run yielded 29 TP, 0 FP, 0 FN, 23 TN, two unscored and
34 partial cases, zero failures, and 0.06284 seconds. All four Objective-C cases
retain partial coverage; no full Objective-C grammar or interprocedural coverage
is claimed. Its separate result includes analyzer module hashes.

After the final native duplicate-origin uncertainty fix and hybrid changes, both
frozen corpora were evaluated again in their separate
`snapshots/final-native.json` files. Counts stayed unchanged: 27 TP/21 TN on the
original corpus and 29 TP/23 TN on the extension, zero FP/FN/failures, respectively
30/34 partial and two unscored in each. Timings were 0.02431 and 0.02031 seconds.
The second run reused already imported parsers in the same process; these timings
are not comparable cold-start measurements. Labels/source fixtures remain exactly
the original frozen hashes. The selected analyzer modules remained unchanged
during both final runs and their recorded final SHA-256 hashes are:

| Module | SHA-256 |
| --- | --- |
| source_analysis.py | `66bfad978a54db5fb91e9d95393b678c8a6f6d86207165e7ddbe47373c7f2749` |
| native_flow.py | `0517b8ae088279af6c98f840e9faa8e744e3f7819f006b7e1dd5ceb57c968b63` |
| native_guards.py | `bcbfeaa37dd5b2a0e6d76c967dd6fdebc2c498ffcc1fe479ea380fcf70c8cdbb` |
| hybrid_analysis.py | `63fcad0ecf7e91836e0e59fbf35c931c752ac79a44bb812cd59e2d13ab2fbb8c` |
| objc_analysis.py | `70693e899b19794af93142213b37edfe3c4312b2c6581e6dd6103a95fb46ec8e` |

These are selected source hashes, not a complete dependency/environment lock.
This small corpus was written for the new modeled features and is not independent
third-party validation. Its zero remaining mismatches do not establish real-world
accuracy, application safety, exhaustive language support or superiority over
other scanners. No fresh competitor run was performed.

After integration formatting, `snapshots/root-final.json` was created separately
for each frozen corpus. Counts remained 27 TP/21 TN/30 partial and
29 TP/23 TN/34 partial, with two unscored and zero FP/FN/failures in each.
Times were 0.02120 and 0.02250 seconds in separate processes, still small local
direct-analyzer observations. All recorded selected analyzer sources stayed unchanged
during each run. The hybrid source hash for this later snapshot is
`572b2f640f0f997c2c534be55b5e359e9e286fed7f1679fee59f47136fcc9ced`;
the other four hashes above are unchanged. Earlier snapshots were preserved.

After review-v1 rework, `snapshots/final-review-v2.json` was created separately
for each frozen corpus. Counts remained 27 TP/21 TN/30 partial and
29 TP/23 TN/34 partial, with two unscored and zero FP/FN/failures in each.
Times were 0.02131 and 0.01897 seconds; the extension reused imported parsers
in the same process. These remain direct-analyzer observations, excluding startup.
Labels and source fixtures retain their original frozen hashes. The selected
analyzer sources stayed unchanged during each run; their hashes for this snapshot
are:

| Module | SHA-256 |
| --- | --- |
| source_analysis.py | `85bacf7e0dd6765242381fb1769b57f08264c7719e1454ba2905f7f094475778` |
| native_flow.py | `96bce0b5b8499b0eb84e83ab7b9fed7a9b246fd5758e1fdf6ced8ff9ae46fc1d` |
| native_guards.py | `0c2e82e25d195d7081de5eda2501c155a5b60b6ed9cad3c3484059d2e74ac583` |
| hybrid_analysis.py | `572b2f640f0f997c2c534be55b5e359e9e286fed7f1679fee59f47136fcc9ced` |
| objc_analysis.py | `70693e899b19794af93142213b37edfe3c4312b2c6581e6dd6103a95fb46ec8e` |

The remaining follow-up recreated the same generator inputs beneath
`/private/tmp/apsa-remaining-j0e922qc/fixtures/corpus-original` and `corpus-objc`
before evaluation, reproducing both original label hashes. Separate
`remaining-v2-results.json` files retain 27 TP/21 TN/30 partial and
29 TP/23 TN/34 partial, two unscored and zero FP/FN/failures each. Direct-call
times were 0.02443 and 0.02088 seconds; imported parsers were reused on the second
run. `native_flow.py` is now
`c05fbf15b7d49947cc97d1cc3f78ca23f39585206a62a94a6e9cca5ebeb4c092`
following the Swift helper metadata regression fix. The four other analyzer
hashes in the preceding table are unchanged.

Ten Kotlin cases retain conservative partial coverage from syntax adaptations,
although their frozen `expected_partial` field was false. Those expectation
mismatches are retained in the raw results; labels were not edited to remove
them. All cases originally expected to be partial remain partial. The first new
validation helper incorrectly asserted that every partial expectation matched;
its failure was retained, and the corrected helper reports those mismatches
separately from scored detection errors.
