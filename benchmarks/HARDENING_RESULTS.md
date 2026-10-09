# Public app and CVE hardening results

English is the source of truth. [한국어](HARDENING_RESULTS.ko.md) ·
[Initial results](REAL_WORLD_RESULTS.md) ·
[Rerun JSON](results/2026-10-09-public-real-world-hardened.json) ·
[Execution and review evidence](results/2026-10-09-hardening-evidence.json).

The four prioritized integration repairs passed the same frozen public-source
corpus and selected CVE checks. All six app scans completed; all six still report
incomplete audits. This is a **development rerun after the labels were seen**,
with a small, selected truth set. It does not establish general detection rates,
whole-app security, exploitability or superiority to another product.

The evaluated rule set is the unreleased `2026.10.09.apsa.111-dev2` candidate.
Package metadata remains `1.1.0`; these results do not describe published PyPI
1.1.0. This change is staged on `hardening/real-app-cve-v1`.

## Measured change

| Selected measure | Initial | Hardened rerun |
| --- | ---: | ---: |
| Completed public-source app scans | 5 / 6 | 6 / 6 |
| Correct inspected cleartext/ATS source facts | 5 / 6 | 6 / 6 |
| Extracted selected dependency declarations | 8 / 10 | 10 / 10 |
| Matched affected independent dependency/CVE units | 7 / 8 | 8 / 8 |
| Correct non-affected independent units | 19 / 19 | 19 / 19 |
| Correct unresolved independent abstentions | 5 / 5 | 5 / 5 |
| Matched affected selected actual-app CVE path | 0 / 1 | 1 / 1, using the frozen supplement below |
| Correct non-affected selected actual-app CVE paths | 3 / 3 | 3 / 3 |
| OS advisory expected-state agreement | 10 / 11 | 11 / 11 |

The 32 independent units now have 8 TP, 0 FP, 0 FN, 19 TN and five unresolved
abstentions. Precision and recall are 100% **within the 27 resolved selected
units**. The units include related versions, artifacts and URL spellings; they
are not 32 independent apps. All original OSV response bytes were reused for
these units, including the previously missed SwiftNIO HTTPS identity.

The four actual-app paths have 1 TP and 3 TN. AntennaPod's jsoup 1.15.1 now
reaches the query/correlation path through the extracted Gradle declaration.
It matches CVE-2022-36033 with `candidate` status and unknown reachability. The
source expression `$jsoupVersion` and root `build.gradle:29` provenance remain
in inventory, with `declared` confidence. This does not prove the historical
compiled app's installed version or an exploitable app defect. Other returned
CVE IDs are retained but unscored against this selected truth set.

App signatures were stable over three scans of each frozen source ZIP;
independent package/CVE cases were also repeated three times. Actual-app CVE
paths use inventory from those stable scans and a separate selected query per
path. Whole-source scans remain offline. No app code, Gradle/Xcode build script,
backend or device was executed. MobSF was not rerun, so the initial comparison
does not provide a post-repair product or timing ranking.

## Repairs and limits

1. Android security patch comparison now validates actual calendar dates on
   both device and advisory sides. Invalid dates abstain instead of implying
   patch satisfaction. The four iOS cases still correctly preserve unknown,
   device-required or simulator states; they do not test positive iOS matching.
2. Gradle literal `ext` variables can be resolved across inspected files and
   literal local imports, stopping at project settings boundaries. Conflicts,
   dynamic expressions, malformed syntax, missing inputs and exceeded budgets
   remain unknown. Gradle is never executed; this is declared source evidence,
   not build resolution. AntennaPod's jsoup and OkHttp declarations are recovered.
3. Supported Swift repository URLs are canonicalized only at the OSV request
   boundary. Inventory, query-match and cache correlation retain original
   identities. This recovers the selected SwiftNIO HTTPS CVE match.
4. Literal Xcode `INFOPLIST_FILE` references can discover named source plists,
   and a named plist can be selected explicitly for a source directory. This
   recovers Nextcloud's `Brand/iOSClient.plist` and its selected ATS declaration.
   Unsupported references and multiple source configurations remain incomplete;
   IPA/app main identity selection remains strict.

All six audits remain incomplete. In particular, Firefox's large
`Client.xcodeproj/project.pbxproj` exceeded the 200,000-token reference budget,
and a referenced Deferred plist was unavailable/invalid. These are explicit
coverage warnings. Recovering the selected existing `Client/Info.plist` fact
does not establish complete configuration coverage. Existing Swift/Kotlin
syntax-recovery gaps remain, including 78 Firefox, six K-9 and two Ice Cubes
paths. Objective-C and other unsupported languages, build-variant merging,
Apple CNA aliases/custom branches, binary/device/AAB/IPA analysis and OS sandbox
behavior remain outside this repair's demonstrated coverage.

## Frozen replay provenance

The [successful replay](https://github.com/ictechgy/apsa/actions/runs/37886018674)
ran job `113676092154` at public commit
`92cfcfddd7bd30ec20433da74baad58eb42bbb15`, equivalent to local reviewed head
`8ecc3f90dfbd5afe8e081a8707821b8c267fe4e7`, common tree
`464344032f1dc6da44242dd799a2f6cc7ee9d997`.

The original six input ZIPs, input manifest, vendor/CNA labels, initial result,
and 29 original OSV captures were preserved. Their hashes were checked before
replay. The [original result](results/2026-10-09-public-real-world-initial.json)
still has SHA-256
`a08769d89866515d3af1e772260cb944b970746f2599e77415a39c77747b2d32`.

**One separate OSV supplement** was required: Maven `org.jsoup:jsoup` 1.15.1
was never queried in the initial run because extraction abstained. Its first
public HTTP 200 response was captured at `2026-10-09T04:46:41.465519+00:00`
during [failed replay attempt 37885440079](https://github.com/ictechgy/apsa/actions/runs/37885440079).
That attempt failed before app scans/scoring because of a helper response error;
its captured supplement was retained in artifact `11596401157`. The successful
rerun imported those exact bytes, validated payload/key/status/hash/size, and
made no new OSV captures. The supplement adds to, rather than replaces, the
original 29 responses. Therefore the AntennaPod actual-app improvement has a
separate feed snapshot time; it is not an identical-feed baseline comparison.
The independent 32-unit comparison uses the original snapshots throughout.

Supplement manifest SHA-256:
`604ef9085abaca3dc460bd20bdcf3fb075b08efbd66256d86101fab6d0d3c5fe`.
The supplement body SHA, request key, original/merged manifest hashes and both
artifact digests are recorded in the execution evidence and rerun JSON.

Successful artifact `11596049073` contains the public inputs, preserved original
result/manifest, original and supplemental OSV bytes, rerun reports and summary.
Its digest is
`sha256:0589d7fb1bfc4f297389cc8b5f11c7443e557721f6e527d5e827f3aad55fe903`;
it expires `2026-11-08T04:55:46Z`. Full offline replay requires retaining both
input artifacts before expiration. Committed summaries and pinned labels remain
available afterward. The committed rerun JSON was reconstructed from the exact
emitted public job-log JSON using the harness's sorted/indented JSON format;
its file hash is recorded separately from the artifact digest.

## Validation and next evidence

[Hosted CI 37886018706](https://github.com/ictechgy/apsa/actions/runs/37886018706)
passed all four Linux/macOS × Python 3.11/3.12 lanes, including 784 tests,
formatting/types, the standalone corpus, repeated builds, attribution and clean
offline installation/CLI/MCP/packaged-skill checks. The first staged CI exposed
a packaged-skill text mismatch; the copies were synced before these passing
checks. [Code/spec review](reviews/2026-10-09-hardening-code.md) returned
`APPROVE`; [architecture review](reviews/2026-10-09-hardening-architecture.md)
returned `CLEAR`. Both reviewed the complete implementation diff at the exact
runtime head/tree above. Both are independent Codex reviewer lanes.

The next accuracy claim needs fresh, independently labeled apps and CVE cases
that were not used for these repairs. Modern Swift/Kotlin parsing, explicit
parsed/skipped function coverage, and vendor-evidenced Apple CNA branch support
remain priorities before broader binary and device evaluation. This rerun
does not score undisclosed zero-days or feed completeness.
