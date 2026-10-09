# Additional analysis and independent holdout

English is the source of truth. [한국어](NEXT_RESULTS.ko.md) ·
[Implementation and limits](../docs/NEXT_ANALYSIS.md) ·
[First holdout JSON](results/2026-10-09-next-first-holdout.json) ·
[First development replay JSON](results/2026-10-09-next-first-replay.json) ·
[Execution and review evidence](results/2026-10-09-next-evidence.json).

These are measurements for the unreleased `2026.10.09.apsa.111-dev4`
development branch, not published PyPI APSA 1.1.0. The extension adds bounded
AAB protobuf/module analysis, embedded IPA Mach-O metadata, narrow Objective-C
candidates, descriptor-safe parser input staging and optional OS isolation.
It does not establish whole-app exploitability or general production accuracy.
APSA 1.2.0 packages this evaluated runtime with release version metadata and
1.1.0 skill-upgrade hashes; the measurements below were not rerun under the
`2026.10.09.apsa.120` rule version.

## Independently labeled first evaluation

An independent code-review lane supplied source facts and version labels before
the first APSA scan of these two pinned public repositories. The frozen
[truth file](next_truth.json) has SHA-256
`b7d297d09997343049de79b79219c86d5c366c5673b2efc90d23ab9e25896bc7`.
No upstream app, build script, backend or device was executed.

| Pinned source | Selected declaration facts | Source functions: analyzed / skipped / bodyless | Native → remaining error files |
| --- | ---: | ---: | ---: |
| Tusky `43ae0bb4556392393a3d759ce42a93f3a003e83a` | 2 / 2 catalog name/version facts | 2,456 / 0 / 297 | 1 → 0 |
| VLC iOS `2383783e8460538b79814f1131bd870fa2c0753b` | 2 / 2 Podfile.lock facts | 5,165 / 275 / 17 | 22 → 22 |

Tusky's selected `usesCleartextTraffic=false` source declaration also agrees.
Catalog facts do not prove that those dependencies are used or shipped.
Both audits remain incomplete; both recognized function inventories are partial.
Each scan repeats three times with stable scored observations and evidence.

The VLC prepass suggested no checked-in Info.plist. That search-based absence
was provisional and excluded from scoring before the first scan. The full
pinned archive contains **eight** Info.plists, including iOS/tvOS application,
test and extension plists. The absence claim was wrong and remains recorded
as `absence_label_verified: false`; labels were not rewritten to create a pass.

The separate CVE comparison uses pinned Apple CNA records for
CVE-2025-31200, CVE-2025-31201 and CVE-2025-43300, with actual captured official
Apple bulletin bytes. Eight version boundaries are evaluated for both iOS and
iPadOS: **16 / 16 selected decisions agree**. These are 16 boundary cases across
three CVEs, not 16 independent vulnerabilities or physical device tests.

| CVE | Affected-side observation | Published fixed boundary | Official bulletin |
| --- | --- | --- | --- |
| CVE-2025-31200 / CVE-2025-31201 | 18.4.0 | 18.4.1 | [Apple 122282](https://support.apple.com/en-us/122282) |
| CVE-2025-43300 | 18.6.1 | 18.6.2 | [Apple 124925](https://support.apple.com/en-us/124925) |
| CVE-2025-43300 | 16.7.11 | 16.7.12 | [Apple 125141](https://support.apple.com/en-us/125141) |

Affected-side decisions are `version-affected`; fixed-boundary decisions are
`outside-published-affected-range`. Installed patch verification and app
reachability remain unknown. This does not score undisclosed zero-days, feed
completeness, exploit reproduction or broad competitive accuracy.

[First evaluation 37896002099](https://github.com/ictechgy/apsa/actions/runs/37896002099)
ran at public commit `3fb38a32f535f46b12befdce13bf6bf76317d326`, tree
`5cbc9e2b9a1813671a271e277b76810151a8b540`. The committed first summary is
byte-identical to the harness's canonical summary, SHA-256
`516ce3955c5d5702c3619c0a0f2e657041eeee13f256eba9858f7c6888616b03`.
Its `finding_statuses` field incorrectly selected a nonexistent `cve` field;
the advisory decision score is separate and correct. A later development
rerun selects the actual `OS-<CVE>` rule ID; the first summary remains unchanged.

Artifact `11600073127`, `independent-next-holdout`, contains the captured source
ZIPs, bulletin bytes and scan reports. Digest:
`sha256:c07f1f60a8d9f29a5352b8fd0b3caff271aaa3629fd87e6272275186b54ab4f9`;
expires `2026-11-08T06:54:48Z`. Preserve these public inputs before expiration
for full offline reconstruction. The first scans explicitly reported
`resource-limits-only`, with OS isolation unavailable on their runner. Separate
required-mode OS tests cannot retroactively change those scan guarantees.

## Frozen six-app development replay

The existing six public source snapshots, expected labels and OSV responses
remain frozen. This is a development rerun after their labels were seen.
The original 32 dependency/CVE units retain **8 TP, 0 FP, 0 FN, 19 TN and
five correct abstentions**.

Selected actual-app CVE paths now show **1 TP, 1 TN and two abstentions**.
The existing scorer records the abstentions in its `failed` count. They are
K-9 catalog-only jsoup and okio declarations, whose use is unresolved; the
scanner refuses to query/correlate them as actual build dependencies. The prior
three-TN claim does not apply to this snapshot. Supply resolved build/SBOM
evidence rather than treating unused catalog entries as verified dependencies.

| Frozen source | Native → remaining error files | Adapted files | Analyzed / skipped / bodyless |
| --- | ---: | ---: | ---: |
| NewPipe | 0 → 0 | 0 | 4,471 / 0 / 264 |
| AntennaPod | 0 → 0 | 0 | 4,404 / 0 / 172 |
| K-9 Mail | 6 → 1 | 5 | 10,925 / 1 / 699 |
| Nextcloud iOS | 2 → 2 | 0 | 2,700 / 4 / 0 |
| Firefox iOS | 78 → 66 | 14 | 26,858 / 41 / 3 |
| Ice Cubes | 2 → 0 | 2 | 1,037 / 0 / 0 |

All six scans completed and all six audits remain incomplete. Objective-C
adds recognized functions in the iOS inventories; syntax adaptation retains
original source coordinates and partial coverage. The counts do not measure
security detection recall or every closure, initializer and native callable.
The unavailable Deferred plist and other unsupported syntax remain explicit.
The original OS labels still agree in 9 / 11 cases; the previously added
one-CVE branch fixtures remain separate at 14 / 14.

[Replay 37896002067](https://github.com/ictechgy/apsa/actions/runs/37896002067)
uses the same first implementation tree. Its committed canonical result hash is
`fa401df04cf3cb212ecd869719975c1d23a557637ea7e941356968fd18a9ad88`.
Artifact `11600143330`, `public-coverage-replay`, has digest
`sha256:f10966d0c0008f1398c1f96aada5a0abde4044cdbe144c2fd7ee99371206d277`
and expires `2026-11-08T06:56:50Z`. No new OSV capture or MobSF rerun occurred.

## Validation status

The final reviewed runtime is local `a74442044f960744197b1fea29d03de91cc01d60`,
public `9c2d5d5033132ee2113a2638e17d3225d2e7dbc8`, common tree
`133b48e59bbf01bb2aad8458812020eee6ae157f`.
[CI 37899396137](https://github.com/ictechgy/apsa/actions/runs/37899396137)
passed all six jobs: Linux/macOS × Python 3.11/3.12 plus required-mode Linux
and macOS OS isolation. There are **873 distinct tests**: ordinary lanes pass
870 and skip three explicit OS probes; Linux required mode passes 872 and
skips the macOS-only alias probe; macOS required mode passes all 873.

The OS probes verify sibling/report-store read denial, input write denial,
scratch writes, localhost network denial and original-input replacement
containment. The macOS synthetic Data-volume alias probe executed without a
skip and denied both sibling and report-store aliases. Startup/import and
archive descriptor requirements are granted with exact parent directory
literals; broad `/System` subtree access is removed. Parser stdin is closed.
The host-run tests do not claim that the parent CLI/MCP client is sandboxed.

All four ordinary lanes also pass Ruff, Pyright, the standalone corpus,
repeated wheel/sdist builds, attribution and clean offline installation,
CLI, MCP and packaged-skill checks. Native Objective-C grammar installation
and positive/negative fixtures run in those locked environments.

[Generated AAB 37899396256](https://github.com/ictechgy/apsa/actions/runs/37899396256)
passes with Android build tools 35.0.0 and platform 35. Five decoded fields
agree with actual compiled declarations from `aapt2 dump xmltree`: package,
debuggable, cleartext, minimum SDK and target SDK. The
[canonical result](results/2026-10-09-next-generated-aab-verified.json) has hash
`3517f530199988e1f451475cdf85fe0f1ea81deda251124d665e740ab23abfc3`.
Artifact `11601213138` expires `2026-11-08T07:30:35Z`, digest
`sha256:a8f656669fd8c34c049deb91097d06ef6dafa78065f1e08fbb942b16917d07c8`.
It is a fresh synthetic base-only bundle, not a complete installed split set.

[Holdout rerun 37899396170](https://github.com/ictechgy/apsa/actions/runs/37899396170)
and [frozen replay 37899396124](https://github.com/ictechgy/apsa/actions/runs/37899396124)
also pass at this same runtime tree. These later runs hash-verify captured
inputs and are explicitly development reruns after labels were seen. The
holdout remains 4 / 4 declaration facts and 16 / 16 selected CVE decisions;
the existing replay retains its two catalog-usage abstentions. The first blind
summary and historical results remain unchanged.

The committed [holdout rerun](results/2026-10-09-next-holdout-rerun.json) has
hash `afbea375bd2a53845d5c11e625d6a25da311d1226418543a70e6c6069449f54d`;
artifact `11601329508` expires `2026-11-08T07:30:53Z`, digest
`sha256:556d0be909ff7cf306085a66d06aa5e33fbd5a6b1906a8901b1c012dac90baf2`.
The [final frozen replay](results/2026-10-09-next-replay-rerun.json) has hash
`837acc40ad40a059e06b2c08e41b8d55057b63a04c3a46532537fbaa2225eec1`;
artifact `11602045160` expires `2026-11-08T07:32:19Z`, digest
`sha256:9b2ed910b598259de2daf1b14c2dfbb5218abeeb695fecb2f1d43944f8be9ad7`.

[Code review](reviews/2026-10-09-next-runtime-code.md) and
[architecture review](reviews/2026-10-09-next-runtime-architecture.md) independently
approved the complete implementation snapshot for hosted validation; their
reports preserve the then-pending CI conditions. They are native Codex lanes,
not Claude, Devin or Agy invocations. Documentation/evidence closure applies
separately to the later snapshot with unchanged runtime. At measurement time,
the development branch had not been merged to main, tagged or published to PyPI.

Remaining scope includes AAB resource/device split merging, native instruction
analysis, signature authentication, Objective-C preprocessing/dynamic dispatch
and `.mm`, broader independently labeled security findings and physical-device
testing. These gaps remain visible in coverage rather than being marked checked.
