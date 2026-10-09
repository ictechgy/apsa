## Summary
Architectural Status: `CLEAR` for snapshot `93bf36199a88861f2c7e01bc500888d31495b669..f5c05db5c271805c518979454bf3673c035ff439`, head tree `18bf3101701d3a894ea3506936229e82a307a663`. I found no merge-blocking architecture issue in the reviewed diff.

The patch’s main trust-boundary choices are sound: parser compatibility is narrow and remains partial, source function counts distinguish recognized vs unknown inventory, and Apple custom range matching is fenced to Apple CNA/product/bulletin evidence rather than becoming a universal fixed-label heuristic.

## Analysis
No blocker: parser compatibility does not become a silent sanitizer or source rewrite. The compatibility module says it never executes or rewrites source files, then only blanks Swift `nonisolated(unsafe)` ERROR nodes before `var|let` and only replaces Kotlin `open` tokens when they are identifiers rather than modifiers (`src/mobile_audit/parser_compat.py:1`, `src/mobile_audit/parser_compat.py:97`, `src/mobile_audit/parser_compat.py:110`). The analyzer still reads evidence from original bytes (`src/mobile_audit/source_analysis.py:154`, `src/mobile_audit/source_analysis.py:171`), adapted parses are marked partial (`src/mobile_audit/source_analysis.py:1043`, `src/mobile_audit/source_analysis.py:1057`, `src/mobile_audit/source_analysis.py:1071`), and pattern exclusions are withheld for adapted/error parses (`src/mobile_audit/source_analysis.py:1076`). Tests pin original offsets and no exclusions for Swift/Kotlin adapted files (`tests/test_coverage_extension.py:143`, `tests/test_coverage_extension.py:164`).

No blocker: function counts are presented as recognized AST inventory, not complete callable truth. Error-containing functions are skipped, bodyless functions are counted separately, and aggregate coverage exposes observed/analyzed/skipped/bodyless counts plus `function_inventory_complete` (`src/mobile_audit/source_analysis.py:877`, `src/mobile_audit/source_analysis.py:888`, `src/mobile_audit/source_analysis.py:940`, `src/mobile_audit/source_analysis.py:960`, `src/mobile_audit/source_analysis.py:1116`). Per-file metadata leaves unparsed function counts as `None`, and the note explicitly says errors, unsupported languages, budgets, closures, and initializers can hide functions (`src/mobile_audit/source_analysis.py:1004`, `src/mobile_audit/source_analysis.py:1136`). Tests cover invalid/unknown inventory behavior (`tests/test_coverage_extension.py:233`).

No blocker: Apple branch correlation is intentionally narrow. The helper requires Apple assigner and CNA org IDs plus Apple vendor (`src/mobile_audit/ios_ranges.py:8`, `src/mobile_audit/ios_ranges.py:12`), rejects ambiguous custom boundaries (`src/mobile_audit/ios_ranges.py:20`), requires exact official Apple support references (`src/mobile_audit/ios_ranges.py:46`), and accepts only one matching observed-major boundary with a matching iOS/iPadOS release label (`src/mobile_audit/ios_ranges.py:68`, `src/mobile_audit/ios_ranges.py:77`, `src/mobile_audit/ios_ranges.py:81`). Correlation defaults to iOS, preserves explicit `os_product`, abstains for other branches, and labels outside-range as branch-specific rather than proof of patching (`src/mobile_audit/audit.py:161`, `src/mobile_audit/audit.py:164`, `src/mobile_audit/audit.py:174`, `src/mobile_audit/audit.py:185`, `src/mobile_audit/audit.py:191`). Scan input validation accepts only `ios|ipados` for `os_product` (`src/mobile_audit/audit.py:301`).

Validation evidence is adequate for architecture review but not a substitute for hosted CI. The supplied local artifact records 241 focused tests passed, 14/14 iOS branch fixtures correct, Ruff passed, Pyright had 0 errors, YAML parsed, and native full suite requires hosted CI because private guard blocks process RSS probes (`/private/tmp/apsa-coverage.ueSZfP/local-validation.json:4`, `/private/tmp/apsa-coverage.ueSZfP/local-validation.json:10`, `/private/tmp/apsa-coverage.ueSZfP/local-validation.json:15`, `/private/tmp/apsa-coverage.ueSZfP/local-validation.json:16`). I did not rerun the full suite in this read-only lane.

## Root Cause
The addressed design risk was false assurance from two places: parser syntax gaps could make missing source coverage look cleaner than it was, and Apple zero-based custom CVE ranges could be either ignored or overgeneralized from fixed-release labels. The patch resolves that by keeping adapted source partial, making function inventory incompleteness explicit, and requiring Apple CNA/product/reference agreement before deriving a branch decision.

## Recommendations
1. Run hosted CI/replay before merge - low effort - high impact. The architecture is clear, but the full native suite is explicitly deferred to hosted CI by the validation artifact (`/private/tmp/apsa-coverage.ueSZfP/local-validation.json:15`), and the workflow is set up to replay frozen public evidence plus upload the coverage artifact (`.github/workflows/hardening-replay.yml:46`, `.github/workflows/hardening-replay.yml:56`).

2. Add a future context-page regression for the new coverage aggregate fields - low effort - medium impact. The fields flow through `coverage` pages because model context returns the report coverage section directly (`src/mobile_audit/model_context.py:102`, `src/mobile_audit/model_context.py:111`), but a focused assertion would pin that contract.

## Trade-offs
| Option | Pros | Cons |
|---|---|---|
| Narrow compatibility with partial marking | Recovers known Swift/Kotlin syntax gaps without pretending full parse certainty | Some valid-but-unmodeled syntax remains unknown |
| General custom range interpretation | Broader CVE matching | High false-positive/false-negative risk across vendor-specific ordering |
| Apple-only fenced custom branches | Evidence-backed branch decisions with explicit abstention | Older caches need refetch for CNA identity; non-Apple custom ranges stay unknown |

## References
- `src/mobile_audit/parser_compat.py:97` - Swift compatibility gate.
- `src/mobile_audit/parser_compat.py:110` - Kotlin `open` identifier gate.
- `src/mobile_audit/source_analysis.py:1043` - compatibility only after native parse errors.
- `src/mobile_audit/source_analysis.py:1076` - adapted/error parses cannot create pattern exclusions.
- `src/mobile_audit/source_analysis.py:1116` - aggregate function coverage fields.
- `src/mobile_audit/ios_ranges.py:59` - Apple custom branch interpreter.
- `src/mobile_audit/audit.py:161` - iOS environment correlation branch.
- `tests/test_coverage_extension.py:43` - Apple branch positive/boundary tests.
- `tests/test_coverage_extension.py:70` - Apple abstention tests.
- `/private/tmp/apsa-coverage.ueSZfP/local-validation.json:4` - local focused validation status.
