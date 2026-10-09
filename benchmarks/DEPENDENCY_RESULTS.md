# Gradle dependency evidence against Gradle's own resolution

English is the source of truth. [한국어](DEPENDENCY_RESULTS.ko.md) ·
[Cases](dependency_cases.json) · [Oracle](dependency_oracle.py) ·
[Evaluation](dependency_eval.py).

This development work (unreleased; not part of APSA 1.2.0) links Gradle version
catalog aliases to the build configurations that use them and reads Gradle
lockfiles as resolved build evidence. It measures how far source declarations
alone can identify shipped libraries, and whether lockfile coordinates match
what Gradle actually resolves. It does not measure vulnerability detection.

## Method

The oracle is Gradle itself. For each pinned public app, a disposable runner
resolved the app module with every configuration locked
(`gradle <app>:dependencies --write-locks`) and recorded the lockfile. APSA was
not installed in that job. A library is **shipped** when it appears in a release
runtime classpath of the app module; benchmark and non-minified baseline-profile
variants are excluded. That definition was narrowed once, before freezing and
before any APSA scan of those sources.

Each truth file was committed before APSA scanned its sources:

| Set | Oracle run | Apps (pinned commits in `dependency_cases.json`) | Scanner fixed before inspection |
| --- | --- | --- | --- |
| holdout-1 | [37906456725](https://github.com/ictechgy/apsa/actions/runs/37906456725) | nowinandroid, mihon, Wikipedia, Fossify Calculator | first implementation |
| holdout-2 | [37907617926](https://github.com/ictechgy/apsa/actions/runs/37907617926) | Pocket Casts, Fossify Gallery, element-x | `a32ad7e` (module roles) |
| holdout-3 | [37908633586](https://github.com/ictechgy/apsa/actions/runs/37908633586) | Nextcloud, Home Assistant | `0bfa345` (explicit non-shipping consumers) |

AnkiDroid, Signal and ownCloud were excluded because their Gradle configuration
needs git metadata or fails on a source archive; Amaze needs an installed NDK.
No oracle exists for them, and they are not scored.

Scored units are versioned catalog library entries. **TP**: APSA marks the alias
as a declared candidate and Gradle ships it. **FP**: declared but not shipped by
the app module. **Abstained**: APSA keeps the entry unresolved. Version-less
(BOM-managed) entries are outside the scored universe.

## First result for each holdout

| Set | TP | FP | Abstained, shipped | Abstained, not shipped | Precision | Shipped coverage |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| holdout-1 | 198 | 22 | 11 | 55 | 90.0% | 94.7% |
| holdout-2 | 90 | 9 | 126 | 77 | 90.9% | 41.7% |
| holdout-3 | 63 | 1 | 82 | 85 | 98.4% | 43.4% |

APSA 1.2.0 abstains on every catalog-only entry by design, so its declared
coverage on the same units is zero; this baseline follows from the code and was
not re-measured. Declared catalog versions differed from Gradle's resolved
version for 15 of 198, 2 of 90 and 1 of 63 true positives. A declared candidate
can therefore name a version that does not ship; exact correlation still
requires resolved evidence.

Each first result exposed a defect, fixed afterwards and recorded in the commit
history:

- holdout-1: build tooling (`kotlin-dsl` builds), Android test modules and
  test-support modules were counted as shipped.
- holdout-2: the module-consumption rule excluded application modules that
  benchmark or coverage tooling referenced, hiding all 107 Pocket Casts
  libraries.
- holdout-3: Home Assistant commits lockfiles for every module. APSA used them,
  so its catalog entries were superseded rather than declared (the 77
  abstentions). Library-module lockfiles were then treated as exact; they now
  remain candidates once another shipped module is shown to consume that module.

## Development rerun after the truth was seen

Run [37909811466](https://github.com/ictechgy/apsa/actions/runs/37909811466) scores
the current branch on all three sets. These numbers are not blind.

| Set | TP | FP | Abstained, shipped | Precision | Shipped coverage |
| --- | ---: | ---: | ---: | ---: | ---: |
| holdout-1 | 198 | 3 | 11 | 98.5% | 94.7% |
| holdout-2 | 194 | 27 | 22 | 87.8% | 89.8% |
| holdout-3 | 63 | 1 | 82 | 98.4% | 43.4% |

Remaining false positives:

- `coreLibraryDesugaring` (one per app). Desugared library code is shipped in
  the dex but is not a runtime-classpath coordinate, so the oracle does not
  count it.
- 17 of 27 in holdout-2 come from Pocket Casts' **wear** and **tv** application
  build scripts. Those libraries ship in other APKs from the same repository;
  the oracle measures only the phone app. A source scan without module
  selection merges every application in the repository. Two more come from an
  `implementation` reference in its root build script (`leakcanary`, likely a
  debug-only setup) and from `modules/services/qr` (`zxing`).
- element-x annotation-processor and test-utility modules that are consumed
  through precompiled convention scripts, which the module graph does not read.

Abstentions are mostly BOMs, transitive libraries and Home Assistant's
superseded entries, which its committed lockfiles resolve exactly.

## Lockfile evidence

With the oracle's lockfile placed in the app module, APSA's exact coordinates
include every one of Gradle's shipped coordinates in all nine apps (256, 378,
315, 179, 402, 214, 412, 384 and 372); in eight apps there is nothing extra.
This is a parser consistency check: APSA reads the same Gradle output through a
near-identical configuration filter, so it is not independent evidence of
resolution. With Home Assistant's committed lockfiles as published, all 372 app
coordinates are exact.
APSA also reports 149 further distinct exact coordinates. They come from the wear
(59 entries) and automotive (2) application modules and from the
`testing-unit` (77) and `microwakeword` (22) modules, whose test or library role
is not recognized.

## Frozen six-app replay

Replay [37909997903](https://github.com/ictechgy/apsa/actions/runs/37909997903)
keeps the original 32 dependency/CVE units at 8 TP / 0 FP / 0 FN / 19 TN / 5
correct abstentions. The two K-9 catalog-only declarations (jsoup 1.15.4, okio
3.7.0) are now declared candidates from `app/core/build.gradle.kts`
`implementation` references. They are queried and agree with their frozen
"unaffected" labels, so the selected real-app CVE paths become 1 TP / 3 TN with
no abstention. This is a development rerun after the labels were seen; the
first summaries and historical result bytes are unchanged, and a declared
candidate still does not prove the shipped version.

## Review follow-up (development, not re-blinded)

An independent code review of this branch found that a lockfile from a module
with no recognized role could still yield `exact` coordinates (and therefore
`version-affected` findings), that superseding applied across the whole
repository by package name, and that partial inputs could become not-shipped
claims. The scanner now treats only application-module lockfiles as exact,
supersedes a declared candidate only when every declaring module is that
application or a module it consumes for shipping, requires library-plugin
evidence and a complete set of build scripts before excluding a module by
consumption, ignores `constraints` blocks and `apply false` plugin lines, and
puts exact coordinates first in the OSV query budget. The oracle workflow now
pins each archive hash before upstream build code runs. The rerun after these
changes is recorded below with its run ID.

Rerun [37913317319](https://github.com/ictechgy/apsa/actions/runs/37913317319)
(head `e1f5eee`, not blind) leaves holdout-1 and holdout-2 unchanged. In
holdout-3, Home Assistant's catalog entries declared by convention plugins are
no longer superseded wholesale: 58 TP, 2 FP and 19 shipped abstentions, so the
set reaches 121 TP, 2 FP and 24 shipped abstentions (98.4% precision, 83.4%
shipped coverage). With its committed lockfiles, its 372 app coordinates stay
exact and the only extra exact coordinates now come from the wear (59) and
automotive (2) applications. The frozen six-app replay
[37913317339](https://github.com/ictechgy/apsa/actions/runs/37913317339) is
unchanged.

A second review round found that a module shared by an app with a lockfile and
an app without one could still be superseded, and that plugin detection missed
`version "…" apply false` and matched plain plugin-id strings. A declared
candidate is now superseded only when every possible app that ships its
declaring module (recognized applications and modules no other module consumes)
resolved that package; plugin detection reads only application syntax, accepts
versioned `apply false`, and lets library-plugin evidence win.

| Result file | Producing run | Head commit |
| --- | --- | --- |
| `results/2026-10-09-dependency-first-holdout1.json` | [37907202313](https://github.com/ictechgy/apsa/actions/runs/37907202313) | `6a86b95` |
| `results/2026-10-09-dependency-first-holdout2.json` | [37908373608](https://github.com/ictechgy/apsa/actions/runs/37908373608) | `36213e0` |
| `results/2026-10-09-dependency-first-holdout3.json` | [37909298008](https://github.com/ictechgy/apsa/actions/runs/37909298008) | `c24d1c3` |
| `results/2026-10-09-dependency-development-rerun.json` | [37909811466](https://github.com/ictechgy/apsa/actions/runs/37909811466) | `8de1758` |
| `results/2026-10-09-dependency-review-rerun.json` | [37913317319](https://github.com/ictechgy/apsa/actions/runs/37913317319) | `e1f5eee` |
| `results/2026-10-09-dependency-frozen-replay.json` | [37909997903](https://github.com/ictechgy/apsa/actions/runs/37909997903) | `ed02049` (reports package version 1.2.0) |

## Limits

Declared candidates keep `candidate` status in correlation. Custom `projectDir`
remapping in settings files is not read, so lockfiles of remapped modules stay
candidates. Variant selection,
conflict resolution, substitution rules, included builds, Kotlin Multiplatform
targets and dynamic dependency notation are not evaluated. The oracle trusts the
upstream build scripts it ran. Nine apps at one commit each are a narrow sample
and do not establish general accuracy.
