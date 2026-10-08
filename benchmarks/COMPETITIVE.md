# Synthetic APSA / MobSF benchmark

English is the source for this benchmark protocol. The corpus and mappings are
frozen before results are collected in `competitive_cases.py`. It creates 40 new
Java, Kotlin, Swift and configuration source ZIPs, then compiles six selected Java
cases into APKs with Android API 35 / build-tools 35.0.0. Android and iOS source
cases are listed separately by language; source ZIPs and APKs have separate
metrics. Source and binary versions of the same fixture are correlated samples,
not independent production apps.

The comparator is the actual MobSF 4.5.3 service, not a reimplementation of its
rules or a comparison with its marketing claims. Its release source reference is
`d3869adc464b89db92a6a8a9e2dc13376f4a4c25`; the run also records the actual Docker
image digest. The benchmark sends both tools identical archive bytes and uses
APSA's actual CLI plus MobSF's upload/forced-rescan API. There are no commercial
scanner results in this benchmark.

## Ground truth and scoring

- The sampling unit is one generated case / selected risk category / input kind.
  Repeated alerts or three repetitions do not increase detection support.
- Vulnerable local patterns, their fixes, and irrelevant controls are labeled
  before scanning, with primary platform references. These are risk patterns,
  not confirmed exploitable apps. The controls are not whole-app safety claims.
- The rule mappings include known scanner IDs and explicitly reserved IDs for
  APSA's missing crypto/SQL checks. MobSF has no equivalent local untrusted-URL
  rule in the pinned source catalogs. Unmapped risky cases remain visible and
  count as misses in end-to-end detection rather than being dropped to improve a
  score. All findings outside the selected category are retained but unscored.
- Precision means **alert precision against these selected risk labels**. A
  broad review alert on a fixed control contributes to triage workload; that
  does not establish that the scanner falsely claimed a confirmed vulnerability.
- A failed or inconsistent scan is not a true negative. Completed-case recall
  is shown together with end-to-end recall, which also counts failed risky cases
  as missed. Undefined denominators produce `null`, never a perfect score.
- APSA coverage and incompleteness are retained. MobSF does not provide the same
  per-rule coverage contract; its missing coverage field remains unknown.
- Each run freezes the input SHA-256, source hashes, compiler version, mapping,
  source revision, environment, repetition count and full synthetic reports.

## Execution

Use a fresh temporary directory outside any private app/runtime data. The GitHub
workflow runs on a disposable Ubuntu host with `contents: read`, a fresh MobSF
container, an internal Docker network, a loopback-only API port, and no app data
from the user's machine. It uploads only the newly generated synthetic artifacts
and removes the service afterward. It cannot publish APSA or modify repository
contents.

```sh
uv run --locked python benchmarks/competitive.py generate --fixtures /tmp/new-competitive-fixtures
uv run --locked python benchmarks/competitive.py build-apks --fixtures /tmp/new-competitive-fixtures --sdk /path/to/android-sdk
uv run --locked python benchmarks/competitive.py run --fixtures /tmp/new-competitive-fixtures --out /tmp/new-competitive-results --mobsf-url http://127.0.0.1:8000 --repeats 3
```

The service must be a new benchmark-only instance. Do not point this driver at
an existing MobSF instance or real app inputs. Without `--mobsf-url`, only APSA
runs; that is not a completed competitor benchmark.

APSA timing covers a fresh CLI process and report store. MobSF timing covers
upload and a forced rescan against an already started local service. Setup,
package installation and image pull are excluded; these measurements do not
establish an engine-only speed ranking. Three per-case repetitions test basic
consistency, not statistical significance. CPU/RSS cost is not scored.

## Interpretation

This deliberately small, handcrafted corpus exposes useful implementation gaps
and review workload. It is not a representative mobile app sample, a production
accuracy estimate, a MASVS certification, or an overall product ranking. There
are no real devices, dynamic tests, IPA binaries, AABs, obfuscation, CVE feed
comparisons, or cross-function flows. A later independent app corpus must be
kept separate from cases used to guide fixes.

Record baseline results before changing APSA detection code. Keep the labels and
inputs fixed when rerunning after a fix, and disclose that rerun as development
corpus performance. Validate fixes additionally on cases outside this corpus.
