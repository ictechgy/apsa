# Improvements measured on ordinary release APKs

This change addresses noise and coverage diagnostics found in six ordinary,
officially released Android apps. It uses the same frozen APK bytes as the
2026-10-23 public-app test. No application or upstream build script was executed.
All scans retained the normal OS parser isolation and numeric resource limits.

## Actual APK results

| App | Version | Before alerts | After alerts | Coverage state |
|---|---|---:|---:|---|
| Markor | 2.16.1 | 11 | 9 | Partial; 4 → 5 partial checks |
| Loop Habit Tracker | 2.3.2 | 5 | 5 | No partial flag in selected APK checks |
| Fossify Calculator | 1.4.0 | 5 | 5 | No partial flag in selected APK checks |
| Feeder | 2.24.0 | 13 | 13 | Partial, unchanged |
| AntennaPod | 3.12.3 | 11 | 11 | No partial flag in selected APK checks |
| Etar Calendar | 1.0.57 | 6 | 5 | Partial, unchanged |

All six scans returned reports. Raw candidate records changed from 43 to 40;
the eight configuration observations were retained. The three removed records
are Markor's KaTeX sensitive-log candidate and the namespace-only HTTP indicators
in Markor and Etar. Other HTTP indicators have fewer metadata hosts but retain
non-namespace or uncertain values. No unrelated finding object changed.

The same three apps retain partial reports. Markor now has one additional partial
sensitive-log check because `assets/asciidoc/asciidoctor.min.js` (760,293 bytes)
exceeds the new AST node limit. Its candidate recovery is conservative; the limit is retained
and full log coverage is not claimed. The KaTeX member itself is fully parsed.

Feeder's file-access and JavaScript-bridge candidates and AntennaPod's credential
preference-write candidate remain byte-identical. These are static review leads,
not demonstrated exploits. Raw alert counts include overlapping engine evidence
and do not establish a production false-positive rate or accuracy improvement.

The scans used fresh offline stores. Current CVE matching and runtime behavior
were not checked. Each report still lists 34–35 checks as not-run; an exit of 0
does not certify whole-app security. Timing was one execution per APK alongside
regression tests and does not establish a throughput improvement.

## Sensitive-log boundaries

`STORAGE-SENSITIVE-LOG` checks sensitive names inside each logging call's own
argument boundary. JavaScript and TypeScript now use Tree-sitter call and
constructor argument nodes, avoiding manual decisions about regex operands,
module/type declaration terminators, ASI and function body syntax. Calls inside
interpolation remain candidates; text resembling a call inside a literal or
regex is not a call node. Recognized comments are excluded from sensitive-name
matching. The canonical call-prefix and argument patterns still govern matching.
Static terminal methods on expression receivers, such as `factory().print(...)`,
and private static properties, such as `this.#print(...)` or
`this.#console.log(...)`, retain their argument checks. Tagged templates do not trigger argument recovery;
real calls inside their interpolations are still visited. A parser deadline
produces an explicit partial result and bounded recovery.

The new grammar dependencies are pinned to `tree-sitter-javascript==0.25.0` and
`tree-sitter-typescript==0.23.2`; the existing Tree-sitter core remains `0.25.2`.
The implementation follows the [upstream binding API](https://github.com/tree-sitter/py-tree-sitter).
The [JavaScript](https://pypi.org/project/tree-sitter-javascript/0.25.0/) and
[TypeScript](https://pypi.org/project/tree-sitter-typescript/0.23.2/) package pins
are recorded in the lock and hashed release export. Installed package metadata
supplies the new notices rows. The normal OS isolation probe loads both grammars.

This rule bounds AST input to 2 MiB per source, parsing to 250,000 microseconds,
and traversal to 200,000 nodes. This separate log-check limit was selected after
the public KaTeX asset produced 158,369 nodes; the final replay parsed it in about 25 ms (one observed run).
The existing native analysis, DEX and OS budgets are unchanged. Grammar-reported parse errors, unavailable grammars and exhausted
budgets produce partial coverage and bounded, candidate-local recovery. Some
Node-accepted syntax forms are not fully represented by the pinned grammar;
those fixtures retain candidates with partial coverage rather than declaring
the input invalid or claiming complete parsing. Recovery
does not restore the old source-wide regex or report successful full parsing.
These are limits of the log-boundary check; they do not expand the hybrid
engine's dataflow guarantees or certify logging API identity or actual leakage.

Other supported languages retain the bounded lexical argument matcher. Nested
comments follow Swift/Kotlin/Dart semantics; Kotlin triple-string quote runs
preserve later calls and their boundaries. Malformed Swift raw-regex recovery
cannot retry a full suffix search on each line or hash delimiter. After the
first failed multiline lookahead, recovery is line-bounded and partial.
Deterministic same-line, multiline and mixed-hash controls retain later logs and
bound regex lookahead to twice the input length on those adversarial families.
This is a lookahead-work invariant, not a whole-tool speed claim.

The actual Markor KaTeX member previously matched a 36,431-character span across
unrelated statements. It now produces zero candidates with no boundary
uncertainty. Appending a fresh synthetic password log to that same public member
still produces one candidate. No package-name, minification or vendor exception
is used. Existing AST redaction exclusions apply before the finding cap.

The CLI/MCP rule catalog identifies the matcher, its canonical call-prefix and
sensitive-argument patterns, and its bounded heuristic scope. The exported prefix
regex alone is not the complete rule. This remains a sensitive-name heuristic,
not a complete dataflow or leakage analysis.

Source-pattern log evidence now includes a UTF-8 byte `offset`. Distinct real
calls on the same minified line therefore have distinct finding IDs. Existing
source-pattern log IDs can migrate; compare locations and evidence when
rescanning older reports. Log evidence accounts for JavaScript CR/LF/LS/PS line
terminators; other source-pattern rules retain their evidence format.

## Namespace identifiers and HTTP indicators

The shared APK/IPA string scanner excludes exact, recognized XML namespace and
SAX/Xerces option identifiers before aggregating HTTP hosts. This is an explicit
string-indicator exclusion, not a network reachability analysis. It does not use
a domain-wide allowlist: other paths on the same host, user information, ports,
queries, lookalike suffixes and malformed strings retain their indicators.

HTTP candidate host counts in the same APK strings changed as follows:

| Markor | Loop | Calculator | Feeder | AntennaPod | Etar |
|---:|---:|---:|---:|---:|---:|
| 4 → 0 | 2 → 1 | 2 → 1 | 10 → 8 | 11 → 7 | 1 → 0 |

Some Adobe metadata strings contain a malformed decoded suffix and remain
candidates. This change does not silently trim that suffix or change the binary
string decoder. All other shared string-indicator groups were unchanged.

## Bounded DEX coverage

`inventory.binary.dex[]` adds two fields:

- `budget_reasons`: distinct reasons from `global-method-limit`,
  `global-instruction-limit`, `per-method-instruction-limit`, and `finding-limit`.
- `methods_truncated`: partially visited methods where further instructions were
  demonstrably omitted. It is not a count of every unvisited method.

A method hitting its own instruction cap no longer stops the whole DEX when
global budgets remain. Later independent methods can still be checked, while
the report remains partial. Global and finding limits still stop bounded work.
An exact final cap without evidence of additional work does not invent a partial
result.

Feeder and Etar hit the global 1,000,000-instruction limit, so their partial
coverage remains. Their previous warning conflated that cause with the per-method
limit. The changed diagnostics do not imply increased coverage on those two APKs.

## Validation and provenance

The full suite passed **6,595 tests**, with 4 skipped and 6 subtests passed.
Android SDK 36 and javac compiled new synthetic safe/unsafe APK fixtures for the
tests; those apps were never installed or run. The review-derived lexer
regressions and safe controls passed. New JavaScript control cases also passed
`node --check` without execution. Ruff, formatting and Pyright passed.
An offline wheel build contains the exact changed production modules, including
the grammar-backed call matcher. This change did not publish a registry release.

The local evidence bundle is
`../.omx/artifacts/apsa-public-improve-20261023/` relative to the repository root.
It records the immutable dirty baseline, frozen input hashes, original and new
reports, complete finding-object comparisons, explicit grammar-gap and partial
coverage evidence, positive controls, full test output,
and per-worker replay evidence. `comparison-r8.json` binds all six final before/after
results; `frozen-apps.json` binds the exact APKs. Partial status is derived from
coverage and cross-checked with the report summary, including Etar; the retained
r2 comparison has a separate erratum for its derived inventory-only flag. Source
hashes, not the retained development version string 1.6.2, identify the measured
implementation.
