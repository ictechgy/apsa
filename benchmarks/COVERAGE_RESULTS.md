# Source coverage and Apple branch extension

English is the source of truth. [한국어](COVERAGE_RESULTS.ko.md) ·
[Previous hardening results](HARDENING_RESULTS.md) ·
[Replay JSON](results/2026-10-09-public-coverage-extension.json) ·
[Execution and review evidence](results/2026-10-09-coverage-evidence.json).

The extension recovers selected Kotlin/Swift grammar gaps, exposes recognized
function coverage, and adds narrowly supported Apple CNA branch decisions.
All six frozen public-source scans completed; all six audits remain incomplete.
This is a **development rerun after labels were seen**, not a fresh holdout,
whole-app security assessment or general accuracy estimate.

Rules are the unreleased `2026.10.09.apsa.111-dev3` candidate. Package metadata
remains `1.1.0`; these are not results for published PyPI 1.1.0. The change is
staged on `hardening/real-app-cve-v1`.

## Source measurements

The table compares the native grammar with the adapted parse **within this
replay**. The previous dev2 summary did not record function counts. Functions
mean recognized AST function nodes; closures and initializers are not counted.

| Frozen app | Native → remaining error files | Adapted files | Native → final recognized functions | Analyzed / skipped / bodyless |
| --- | ---: | ---: | ---: | ---: |
| NewPipe | 0 → 0 | 0 | 4,735 → 4,735 | 4,471 / 0 / 264 |
| AntennaPod | 0 → 0 | 0 | 4,576 → 4,576 | 4,404 / 0 / 172 |
| K-9 Mail | 6 → 2 | 4 | 11,526 → 11,625 | 10,925 / 1 / 699 |
| Nextcloud iOS | 0 → 0 | 0 | 2,369 → 2,369 | 2,369 / 0 / 0 |
| Firefox iOS | 78 → 66 | 14 | 26,885 → 26,885 | 26,844 / 41 / 0 |
| Ice Cubes | 2 → 2 | 0 | 1,037 → 1,037 | 1,035 / 2 / 0 |

K-9 gains 99 recognized functions. Four Kotlin files and 14 Swift files use
compatibility; two adapted Swift files still contain errors. Thus 16 files lose
their native syntax errors. This does not measure added true-positive security
findings or prove complete function coverage.

Kotlin compatibility changes the soft keyword `open` only when used as an
identifier in parser bytes. Swift compatibility blanks the exact unsupported
`nonisolated(unsafe)` modifier before a direct `var` or `let`. Both preserve
byte offsets and use original source for evidence. Adapted files **always remain
partial** and cannot produce legacy pattern exclusions. Concurrency semantics
are not modeled.

CLI/MCP coverage and `inventory.source_analysis` now expose observed, analyzed,
skipped and bodyless function counts, native parser failures and adaptations.
Unknown file inventories stay null. Zero counted skipped functions is not a
claim that every callable was recognized. Unsupported languages, parser errors
and budgets can hide functions; only AntennaPod's recognized function inventory
is marked complete here, while its overall audit remains incomplete.

Scans repeat three times per app, with stable scored observations and finding
evidence. There are no unparsed eligible records or remaining source records
in these summaries; unsupported-language coverage remains separate.

## Apple branch decisions

Matching now requires Apple assigner and CNA provider identities, an Apple
product, a supported iOS/iPadOS alias, a shared official Apple bulletin URL,
one zero-based custom boundary in the observed major version and an exact
matching fixed-release label. Other custom ranges remain unknown. Missing
identity in an older cache requires CVE refetch before this path can apply.

The [14 additional fixtures](ios_branch_cases.json) cover **one CVE,
CVE-2025-24201**. They use synthetic environments and vendor records with labels
checked against Apple's linked pages; they are not newly captured HTTP bytes,
live devices or 14 independent vulnerabilities.

| Expected class | Agreement |
| --- | ---: |
| Affected published branch | 4 / 4 |
| Outside the published branch's affected range | 5 / 5 |
| Unknown applicability | 4 / 4 |
| Simulator only | 1 / 1 |
| Total | 14 / 14 |

The checked boundaries are [iOS 15.8.4](https://support.apple.com/en-us/122345),
[iOS 16.7.11](https://support.apple.com/en-us/122346),
[iOS 18.3.2](https://support.apple.com/en-us/122281) and
[iPadOS 17.7.6](https://support.apple.com/en-us/122372). iPadOS-only evidence
requires explicit `os_product: "ipados"`; the default is iOS. Another major,
a beta label, a mismatching bulletin or missing product evidence abstains.
Positive findings remain candidates with unknown app reachability. Outside
the published affected range does not prove patch installation or device safety.

**The original 11 OS expected states are unchanged.** Their frozen agreement
is now **9/11**, because two formerly unknown iOS cases intentionally gain
supported decisions: iOS 18.3.1 becomes `version-affected`, and 18.3.2 becomes
`outside-published-affected-range`. The other nine states are unchanged.
The additional fixture score is separate; original labels were not rewritten
to manufacture an 11/11 result.

## Regression, replay and review

Selected configuration facts remain 6/6 and dependency declarations 10/10.
The original 32 dependency/CVE units remain 8 TP, 0 FP, 0 FN, 19 TN and five
correct abstentions. Selected actual-app paths remain 1 TP and 3 TN.
AntennaPod's jsoup finding remains declared source evidence, candidate status
and unknown reachability; it reuses the previously frozen separate-time
supplement. These selected scores do not establish general production accuracy.

[Replay 37889988853](https://github.com/ictechgy/apsa/actions/runs/37889988853)
succeeded at public commit `3da9b8a99c14b638040c4361bb567fdd34453b6c`,
equivalent to local reviewed head `f5c05db5c271805c518979454bf3673c035ff439`,
common tree `18bf3101701d3a894ea3506936229e82a307a663`.
The six input ZIPs, original truth labels, 29 original OSV responses and the
one retained jsoup supplement were reused. No new OSV capture occurred. Both
historical result files remain byte-identical; their hashes and manifest hashes
are recorded in the evidence JSON.

Artifact `11598057271`, `public-coverage-replay`, includes public inputs,
frozen responses and replay reports. Its digest is
`sha256:e96ffe7ccce1491760ff9f53b344e69b1232b8e9727e745da603a902cc78e005`;
it expires `2026-11-08T05:46:04Z`. Preserve the public input artifacts before
expiration for complete offline reconstruction. The committed result is the
exact emitted coverage JSON parsed and written in the harness's sorted/indented
format; its file SHA-256 is
`499910bb95bbb25bd596a235ec571dfe98f853906f3aa094e1e01a554880267d`,
separate from the artifact digest.

[CI 37889988833](https://github.com/ictechgy/apsa/actions/runs/37889988833)
passed all four Linux/macOS × Python 3.11/3.12 lanes: **832 tests**, Ruff,
Pyright, standalone corpus, repeated builds, attribution and clean offline
installation/CLI/MCP/packaged-skill checks.
[Code/spec/security review](reviews/2026-10-09-coverage-code.md) returned
`APPROVE`; [architecture review](reviews/2026-10-09-coverage-architecture.md)
returned `CLEAR` for the complete implementation snapshot above. These are
independent Codex lanes, not Claude, Devin or Agy invocations.

## Remaining evidence

Kotlin constructor/newline syntax and modern Swift `@Sendable`, `if await`
and other syntax gaps remain. Firefox still has the large PBX reference token
budget and unavailable/invalid Deferred plist warning. Unsupported languages,
including Objective-C, build variants, AAB/IPA embedded binaries, device tests
and OS sandbox behavior need separate evaluation. No upstream app, build
script, backend or device was executed; MobSF was not rerun.

Fresh independently labeled apps/CVE cases are still needed before broader
accuracy or competitive claims. This work does not score undisclosed zero-days,
feed completeness or whole-app exploitability, and does not merge main, create
a release or publish a registry package.
