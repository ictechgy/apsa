# Analysis coverage and partial diagnostics

APSA emits source candidates from bounded analysis. A checked file or an absent
finding does not prove runtime safety, installed reachability, or exploitability.
Unknown dispatch, incomplete traces, malformed input and exhausted budgets must
remain visible as partial or unavailable coverage.

## Native source flow

Java, Kotlin and Swift use bounded direct-call and field summaries. Recursion,
unknown receiver dispatch, ambiguous overloads, unavailable return/body flow and
inventory/trace/route budgets remain unresolved. They do not supply sanitizer
proof. Existing conservative coverage is retained: any unresolved native-flow
reason keeps all native rule coverage partial. An unaffected file's empty
diagnostic list does not make its rules globally complete.

`source_analysis.native_flow.partial_details` records the reason, file, line,
column, call name where available, uncertainty category, and conservative rule
scope. Global uncertainty has an analysis scope and no invented file or call.
Records are deduplicated, sorted and limited to 256; the lexicographically first
records are retained when the limit is reached. `partial_details_truncated`
means additional diagnostic locations are unknown. It never clears the reasons
or changes partial coverage. File metrics include local/global reasons and a
diagnostic completeness flag; this is explanatory scope, not a claim that only
those files or rules can be affected.

The native call limits remain eight levels, 1,024 evaluations, 4,096 inventoried
callables and four field-summary rounds. Parser, trace, route and finding limits
apply independently. Closures, lifecycle callbacks and dynamic dispatch are not
a complete application call graph.

## Hybrid source and compiled artifacts

JS, TS and Dart use token/block flow, not full compiler semantics. Analysis covers
observed argument/return flows; it does not prove sanitizers, native bridge
implementations, callbacks, lifecycle dispatch or runtime execution.

Text `.jsbundle` files are accepted as JavaScript source. A `.bundle` file is
eligible only when it is UTF-8 text without binary control bytes and has an exact
recognized name (`index.android.bundle`, `index.ios.bundle`, `main.bundle`) or a
Metro `__d(...)`/`__r(...)` marker. Recognition is a source-input heuristic, not a
proof of a valid complete React Native bundle. Unknown `.bundle` files and
non-text input are recorded as skipped.

Hermes execution/delta header signatures identify bytecode presence only; no
instructions, version compatibility or string tables are analyzed. The signatures
come from the upstream [Hermes bytecode format](https://github.com/facebook/hermes/blob/main/include/hermes/BCGen/HBC/BytecodeFileFormat.h).
`.hbc`/`.hermes` names are bytecode candidates, not validated bytecode.
`libapp.so` and `App.framework/App` names indicate Flutter AOT candidates;
recognized Flutter snapshot names indicate compiled-content candidates. These
names do not establish artifact validity, installed reachability or even the
actual compiled format. No compiled artifact is admitted to text source flow.

`hybrid_inputs` inventory records distinguish source available from skipped
content and include representation, recognition basis and skipped reason.
`hybrid_analysis.files` adds the actual `analysis_state` (`analyzed` or `skipped`).
`analyzed` means content was admitted to bounded source flow; rule coverage stays
partial and `flow_state` records whether modeling was incomplete. Framework
summaries count observed files, analyzed text files, skipped files and observed
representations. Presence of Hermes/AOT files never counts as analyzed text.

Input observations retain at most 256 records. Truncation or incomplete source
enumeration makes additional framework presence unknown. Source staging preserves
recognized compiled names as metadata without copying or opening compiled bytes.
These observations are not part of a source-content fingerprint and must not
promote fingerprint completeness. Existing exclusions and no-symlink rules apply.

Text bundles share ordinary staging/source limits and the hybrid limits: 2 MiB
per source, 16 MiB total, 100,000 tokens per file, 2,000 functions, 300,000 flow
operations and six summary rounds. A skipped or truncated file cannot establish
absence of a candidate.

## Xcode test scheduling

Complete directory components such as `MyAppTests` or `MyAppUITests` join `Tests`
and `UITests` in the lowest staging tier. Named unit-test targets require a
multiword uppercase target prefix; explicit named `UITests` targets are accepted.
Single-word names such as `BusinessTests` and `AppTests` remain ambiguous and keep
production priority without a build graph. Matches end at the directory boundary;
names such as `MyAppTestsSupport`, `LatestResults` and lowercase `protests` also
keep production priority. This is a scheduling heuristic, not build-graph proof. It does not
delete or mutate original test inputs, and budgets determine which files can be
staged.
