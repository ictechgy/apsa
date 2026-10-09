# Public app source and CVE matching results

English is the source of truth. [한국어](REAL_WORLD_RESULTS.ko.md) ·
[Protocol](REAL_WORLD.md) · [Initial machine-readable result](results/2026-10-09-public-real-world-initial.json) ·
[Input/query and diagnostic evidence](results/2026-10-09-public-evidence.json).

The initial evaluation found useful matching behavior and concrete integration
gaps. APSA completed five of six public-source scans, with incomplete audits on
all five. Selected independent CVE units produced 7 TP, 0 FP, 1 FN and 19 TN;
five unresolved inputs correctly abstained. The only known affected real-app
path abstained because a Gradle variable was not resolved. An invalid Android
patch date incorrectly produced a patch-satisfied state.

This is evidence for prioritizing repairs, not a production accuracy estimate or
a product ranking. Product code was unchanged during baseline capture. The
evaluated rule set is the unreleased benchmark candidate
`2026.10.09.apsa.111-dev`; package metadata says `1.1.0`, but these results do not
measure the published PyPI 1.1.0 implementation.

## Execution and provenance

The [initial hosted run](https://github.com/ictechgy/apsa/actions/runs/37879443007)
and job `113655489966` succeeded. Workflow success means the evaluation finished;
individual scanner failures remain in the result. The executable public commit
is `5513aa0d4466f8ce0413c4720a3f2e470e417924`, corresponding to local reviewed
head `8c5a90787bcafd9484071611ad496f0453a2ff1e` and common tree
`42c8b6c9cb3beef83f630c951ac5d5e23f285db4`.

Both tools received the same repacked source ZIP for each app, three times. The
ZIP retains unmodified text/configuration bytes; media is excluded. No upstream
app code/build script, backend or device was executed. Whole repositories include
tests, libraries and build variants; this is not a merged release-build analysis.

| App | Frozen revision | APSA state | MobSF state | APSA files | APSA findings | MobSF code rule entries | Median APSA / MobSF seconds |
| --- | --- | --- | --- | ---: | ---: | ---: | --- |
| NewPipe | v0.27.6, `c6e17218` | completed, incomplete | completed | 926 | 8 | 9 | 3.02 / 5.50 |
| AntennaPod | 3.6.0, `26175298` | completed, incomplete | completed | 1,019 | 10 | 7 | 3.17 / 3.27 |
| K-9 Mail | 6.800, `62caaba7` | completed, incomplete | failed, HTTP 500 in all three repetitions | 3,011 | 4 | unavailable | 6.73 / unavailable |
| Nextcloud iOS | 6.5.0, `d590f07c` | failed, exit 1 in all three repetitions | completed | unavailable | unavailable | 11 | unavailable / 2.96 |
| Firefox iOS | 2026-10-08 source, `afcb46af` | completed, incomplete | completed | 4,285 | 63 | 18 | 19.36 / 26.26 |
| Ice Cubes | 2026-10-08 source, `2ad6e689` | completed, incomplete | completed | 534 | 0 | 3 | 1.50 / 2.32 |

Both tools had five completed apps and one failed app. No completed app's
observed signature changed across three repetitions. Alert counts have different
units and no exhaustive vulnerability truth set: they do not establish which
tool found more real vulnerabilities. MobSF's K-9 HTTP failure is an observed
integration failure under this source packaging; its root cause is unconfirmed.
MobSF does not expose APSA's per-rule coverage contract. No MobSF CVE accuracy
score or commercial-scanner comparison is provided.

APSA explicitly reported multiple source configurations and no build-system
merge. Kotlin/Swift syntax recovery skipped affected functions, including 78
Firefox paths, six K-9 paths and two Ice Cubes paths. Other unsupported source
languages and offline intelligence also reduced coverage. Ice Cubes' zero
findings therefore does not mean a clean or secure app. Whole-source CLI scans
were offline; selected dependency/CVE integration was exercised separately with
actual public OSV queries.

The timing reflects this workflow: APSA used fresh processes, while MobSF reused
a service constrained to two CPUs and 4 GiB. Three repetitions and different
execution architectures cannot support an engine-speed ranking.

## Selected source facts

Five of six selected cleartext/ATS facts were inspected and classified correctly.
Nextcloud's selected `Brand/iOSClient.plist` was not inspected because its APSA
scan failed. The [frozen-input diagnostic](https://github.com/ictechgy/apsa/actions/runs/37880872218)
reproduced exit 1 with `Archive has no readable Android manifest or main iOS Info.plist`.
The pinned Xcode project selects `Brand/iOSClient.plist` through `INFOPLIST_FILE`;
APSA's input reader recognizes names ending in `Info.plist`, leaving this valid
named source configuration unsupported. These are explicit source declarations, not six exploitable bugs or
the transport policy of a compiled app. AntennaPod/K-9 also declare network
security configuration, so broad cleartext declarations require context.

Eight of ten selected dependency identity/version declarations were extracted
correctly. Both misses were AntennaPod's external Gradle variables: jsoup 1.15.1
and OkHttp 4.12.0. Product inventory retained `$jsoupVersion` and `$okhttpVersion`
as unresolved rather than inventing values. Nextcloud has no selected exact
dependency label; minimum Xcode package requirements are not installed versions.

## Independent dependency/CVE units

Labels were frozen from vendor/CNA evidence before execution, independently of
the OSV responses being tested. APSA's actual `query_dependencies` and `correlate`
functions ran; OSV performed package/version range lookup. First response bytes
were captured per unique request and replayed in repeated checks.
The preserved OSV manifest contains 29 unique HTTP response snapshots, all with
status 200, across isolated and selected real-app checks.

| Selected CVE | Affected matched / labeled | Non-affected correct / labeled | Unresolved correctly abstained |
| --- | ---: | ---: | ---: |
| Gson CVE-2022-25647 | 1 / 1 | 4 / 4 | 1 / 1 |
| jsoup CVE-2022-36033 | 1 / 1 | 4 / 4 | 1 / 1 |
| Okio CVE-2023-3635, two patch branches | 2 / 2 | 4 / 4 | 1 / 1 |
| Bouncy Castle CVE-2024-30171, two artifacts | 2 / 2 | 4 / 4 | 1 / 1 |
| SwiftNIO CVE-2026-28970, canonical/HTTPS identities | 1 / 2 | 3 / 3 | 1 / 1 |
| Total | 7 / 8 | 19 / 19 | 5 / 5 |

The 27 resolved units completed without feed failures or repeated-result changes:
7 TP, 0 FP, 1 FN, 19 TN. Selected-label precision was 100% and recall 87.5%.
Five unresolved cases are separate abstentions, not true negatives. This small,
selected set does not establish general precision or recall.

The missed SwiftNIO unit used `https://github.com/apple/swift-nio` at 2.99.0.
The same version under `github.com/apple/swift-nio` matched CVE-2026-28970; the
HTTPS form returned no matches. Real `Package.resolved` extraction retains HTTPS
repository URLs, making this an integration gap relevant to actual iOS inputs.
The [maintainer advisory](https://github.com/apple/swift-nio/security/advisories/GHSA-cq87-8r7h-962v)
provides the independently frozen affected/fixed boundary.

Non-affected means outside the range of the **named CVE**. Some jsoup and Bouncy
Castle controls returned other CVE IDs, retained in the JSON. Those additional
records were not independently labeled and are neither confirmed app defects nor
false positives for this selected-CVE evaluation. A dependency match leaves
reachability unknown and does not prove exploitability.

## Selected actual-app CVE paths

| Extracted app declaration | Named CVE truth | Result |
| --- | --- | --- |
| NewPipe jsoup 1.17.2 | outside CVE-2022-36033 range | completed; no named match |
| AntennaPod jsoup 1.15.1, externally defined variable | affected by CVE-2022-36033 | unresolved; query abstained |
| K-9 jsoup 1.15.4 | outside CVE-2022-36033 range | completed; no named match |
| K-9 Okio 3.7.0 | outside CVE-2023-3635 range | completed; no named match |

This is 3 TN and one affected abstention, with 0 TP. End-to-end recall is 0/1;
completed-case positive recall and precision are undefined. The known version
was never injected into product inventory to improve the score. The
[jsoup maintainer advisory](https://github.com/jhy/jsoup/security/advisories/GHSA-gp7f-rwcx-9369)
fixes the selected issue in 1.15.3. A single affected declaration cannot estimate
production recall or establish what the historical build shipped.

## OS advisory correlation

Ten of eleven expected-state cases behaved as specified. These use real public
bulletins and synthetic device facts, not actual-device tests or exploit
reproduction. Four iOS cases preserve device-required/simulator/unknown states;
they do not demonstrate positive iOS affected-version matching. Apple CNA
product naming and custom branch ranges remain coverage limitations.

Android `2024-99-99` incorrectly became `vendor-patch-level-satisfied`. The
correlator accepts the date's shape and compares strings without validating a
calendar date. It should return missing/unknown applicability. This is a false
assurance defect, even though the fixture is synthetic. The valid 2024-09-01
boundary passed against the
[September 2024 Android bulletin](https://source.android.com/docs/security/bulletin/2024-09-01).
The [Apple iOS 18.3.2 bulletin](https://support.apple.com/en-us/122281) is retained
alongside the pinned CVE-2025-24201 CNA record.

## Repair priorities

1. Validate Android calendar dates before patch-level comparison; malformed
   observations must never imply patch satisfaction.
2. Resolve supported literal Gradle variables across source files without
   executing Gradle. Preserve unresolved dynamic cases and offer resolved SBOM
   input when static extraction cannot establish a version.
3. Canonicalize supported Swift package identities at the OSV boundary while
   preserving the original repository URL as provenance.
4. Support explicitly selected Xcode `INFOPLIST_FILE` paths and named plists;
   preserve app/variant ambiguity rather than choosing a release configuration.
5. Improve modern Swift/Kotlin parsing and report parsed/skipped function
   coverage; extend supported Apple CNA aliases/branches with vendor evidence.

Repairs are not included in this initial evaluation. Reusing these now-observed
inputs after a repair is a development rerun; retain the original scores and
use a new independent holdout for broader accuracy claims. Binary/device/AAB/IPA,
Objective-C depth, sandbox behavior, feed completeness and undisclosed zero-day
detection remain unscored.

## Preserved evidence

The initial result is committed unchanged in value. Canonical JSON SHA-256:
`a08769d89866515d3af1e772260cb944b970746f2599e77415a39c77747b2d32`.
Artifact `11593238939` holds public source ZIPs, vendor HTML, OSV request/response
snapshots and raw reports; digest
`sha256:30fb74fd21788fd0d2a50ee80723d164f335121fe4d75189727ee321bc7e616e`.
Its configured retention is 30 days, expiring 2026-11-08; committed summaries and
pinned primary JSON remain available afterward. Full replay requires retaining
the artifact before expiration.

The diagnostic verified the original summary bytes, all APSA engine source
hashes, and input/OSV manifest hashes before replaying the one failed source
scan. It did not recapture OSV or replace scores. An earlier diagnostic run
`37880560673` stopped at its hash guard because JSON reserialization changed
`1.0` to `1`; the corrected workflow retained the original Python JSON bytes.
Both diagnostic states and the failure stdout are preserved in the evidence JSON.

| Item | SHA-256 |
| --- | --- |
| Frozen specification | `dee900f64f18513d283c8a3581a86152f804910a535175e4198ff208573514fc` |
| Prepared public input manifest | `190a6798ad094e3f2ff65c57e9d4cfa253db0cce28ab4d2e308d5cfb6d213e1e` |
| Captured OSV manifest | `6e6fbb050eddfdf5c30b6a424e6d325946235ff18565695d3503e81f96c5fb10` |
| MobSF image | `5113fbad0727445dda01afdccafea5e107bfa8632ead8a169492f5caa8aa1b7c` |

The [general CI run](https://github.com/ictechgy/apsa/actions/runs/37879443024)
passed Linux/macOS and Python 3.11/3.12 lanes, including 716 Linux tests, lint,
types and local release verification. The benchmark's 43 targeted tests also
passed. Native code and architecture reviews approved baseline activation after
a harness failure-propagation defect was fixed; those approvals are bound to the
executable head/tree above and do not certify whole-app security.
