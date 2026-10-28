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

## Credential text admission

Known-format credential matching has a separate bounded text channel. Source
and packaged text can be inspected without admitting credential-only
`.properties`, `.strings`, `.pem` or `.key` files to general source flow. Eligible
APK/IPA text resources, including admitted JavaScript bundles in those packages,
use `PACKAGED-CREDENTIAL-TEXT`. Credential candidates from other admitted
representations (source folders, source ZIPs, AABs and `.app` folders) use
`SOURCE-HARDCODED-SECRET`. Neither route makes compiled source rules analyzed.
Only strict UTF-8 (optional BOM) and BOM-marked UTF-16 plaintext are decoded.
Binary plists, other binary content, unsupported encodings, skipped files and
exhausted limits remain unknown or partial. A filename alone proves no content.

The channel shares existing per-file, total-size and no-symlink input limits.
Reports contain aggregate coverage metadata and masked candidates, never the
collected plaintext channel. Credential values use a fixed `[REDACTED]` marker;
no prefix, exact length or value fingerprint is emitted by this matcher. Counts describe observed worker input; parent
staging omissions set channel `partial` and `staging_incomplete` without inventing
a missing-file count. Unsupported text is summarized in one counted warning
rather than one warning per binary member. Matching recognizes existing credential formats;
it does not estimate arbitrary secret entropy or contact credential services.
Google API key candidates require restriction and usage review and do not prove
a working secret. Certificates alone are not private keys. The absence of a
candidate establishes no protection against reverse engineering or backend
authorization failures. See [AI-assisted attack defense](AI_ASSISTED_ATTACK_DEFENSE.md).

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

## Bundled legacy binary screening

The bundled Quaygate APK/IPA reader freezes at most 256 MiB of compressed input
in a private temporary file before checking the ZIP directory. Directory metadata
is limited to 8 MiB and 20,000 entries, and its physical records are counted
before `ZipFile` allocates entry objects. ZIP64, concatenated prefixes and
unsupported directory layouts are rejected. Local alignment padding and APK
signing blocks before the directory remain supported. A mutable original path
cannot replace the preflighted snapshot during ZIP parsing. This adds bounded
temporary-file I/O; an over-limit file is unsupported, not a clean result.

Bare `AES` is a default-cipher candidate only when a bounded entry-prefix proof
binds that literal to the first argument of `Cipher.getInstance`. It is not
inferred from a key label elsewhere in the method. Control-flow ambiguity and
exception handlers limit that proof. Other legacy algorithm indicators retain
their documented method/string heuristics; none proves whole-program dataflow,
reachability or a vulnerability. The unified parser's OS isolation and the direct
legacy CLI's in-process limits remain distinct as described in the threat model.
