# APSA / MobSF synthetic comparison — 2026-10-09

English is the source of truth; [한국어](COMPETITIVE_RESULTS.ko.md) follows it.

The [completed hosted run](https://github.com/ictechgy/apsa/actions/runs/37808597054)
compared actual scanners on identical generated inputs: 40 source ZIPs and six
compiled APKs, each scanned three times. Labels and mappings were frozen before
APSA fixes. All selected units completed without detected internal analysis
failures or unstable observations in this corrected run. An earlier APK run
was excluded after a hidden decompiler failure was found; see below.

The practical outcome is a verified improvement to APSA's source checks. The
unreleased candidate closes four selected misses and four control alerts from
the released baseline. This small development corpus does not establish general
accuracy or an overall product ranking.

## Source ZIP results

There are 18 selected risky patterns and 22 fixed/irrelevant controls. Java has
23 cases, Kotlin six, and Swift 11. An alert is scored only against each case's
selected category; other findings remain in the full reports.

| Engine | Detected risks / 18 | Misses | Control alerts / 22 | Selected alert precision |
| --- | ---: | ---: | ---: | ---: |
| Released APSA 1.1.0 | 14 | 4 | 4 | 77.8% |
| APSA unreleased `111-dev` | 18 | 0 | 0 | 100% |
| MobSF 4.5.3, pinned image | 12 | 6 | 4 | 75.0% |

Four of MobSF's six misses are URL cases with no directly equivalent rule in the
pinned catalogs. A separate view using only categories mapped for both tools
contains 14 risky cases and 18 controls:

| Engine | Detected mapped risks / 14 | Control alerts / 18 |
| --- | ---: | ---: |
| Released APSA | 10 | 4 |
| APSA candidate | 14 | 0 |
| MobSF | 12 | 4 |

This subset is derived from the pre-existing mappings, without changing labels
or selecting rules from observed results. The remaining MobSF misses are the
Kotlin source SSL and logging cases. Those observations apply to this ZIP layout
and these source forms; they are not claims that MobSF cannot analyze Kotlin
apps generally. MobSF's four control alerts occur on an unrelated `proceed()`
method, Java and Swift redacted logs, and bound SQL. Broad review alerts can be
useful; here they contribute review workload against the narrower risk labels.

Two Kotlin SSL cases retain partial APSA AST coverage from syntax recovery. Their
selected findings and all coverage/warnings are preserved. Offline intelligence
and runtime checks were not measured. An empty selected-category result is not
a whole-app security verdict.

## APK results

The APK group contains three selected risky configurations/calls and three
controls, compiled from selected Java source cases. It is correlated with the
source group and must not be pooled as independent apps.

| Engine | Detected risks / 3 | Control alerts / 3 | Failed / unstable units |
| --- | ---: | ---: | ---: |
| Released APSA | 3 | 0 | 0 / 0 |
| APSA candidate | 3 | 0 | 0 / 0 |
| MobSF | 3 | 0 | 0 / 0 |

This group is a tie; it demonstrates no APSA binary-analysis advantage.
In the [initial run](https://github.com/ictechgy/apsa/actions/runs/37805967800),
MobSF returned HTTP-success reports despite a missing JADX executable. The
[frozen evidence inspection](https://github.com/ictechgy/apsa/actions/runs/37807603419)
found `Decompiling with JADX failed` / `FileNotFoundError` and empty code-analysis
findings. The initial MobSF APK 1/3 is **not a valid detector comparison**.
The corrected run provisions MobSF's expected public JADX 1.5.0 and rejects
swallowed fatal code-analysis errors for code-dependent labels. Initial summaries
are retained separately as [baseline](results/2026-10-09-initial-released-baseline.json)
and [candidate/MobSF](results/2026-10-09-initial-candidate-mobsf.json); their raw APK
counts must not be reused as detector scores.

## Changes and verification

The candidate adds framework-attributed literal AES/ECB and weak digest checks,
including CommonCrypto calls in Swift trailing closures, and local platform-input
flow to Android SQLite statement arguments. All are candidate findings with
explicit scope; a weak digest API does not establish a security-sensitive use.

AST-backed pattern exclusions remove alerts only for proven literal redacted
payloads and typed local non-SDK handler calls. Dynamic concatenation,
interpolation, extra throwable arguments, misleading redaction tags, live calls
on the same line, and syntax recovery retain the broader checks. UTF-8 byte
ranges prevent Unicode comments or greedy regex spans from hiding live evidence.

Twenty-five additional regression cases outside this corpus exercise those
boundaries. They are regression tests, not an independent blind benchmark.
The full suite passed **692 tests** at local commit
`06744c4dd0523bad87cfafba4b3738ebfb3f62b0`; modified/source lint and type checks
passed. The final executable snapshot passed 21 harness tests and independent
code/architecture review. The [general hosted CI](https://github.com/ictechgy/apsa/actions/runs/37808596752)
also passed. Review approval applies to those snapshots; it is not a release.

## Reproduction and provenance

See the [protocol](COMPETITIVE.md), [released-baseline summary](results/2026-10-09-released-baseline.json)
and [candidate/MobSF summary](results/2026-10-09-candidate-mobsf.json).

- Baseline source: `6d2216e8ade07208c0b0495507b81574dbb64c61`, installed in a
  separate locked environment; rule version `2026.10.08.apsa.110`.
- Candidate/harness source: `43cafbafae6ff74ab65e5a1382b97f193b015d52`, tree
  `b76b6ef26edee48b6144d2929b914ea401cd6316`; candidate rule version
  `2026.10.09.apsa.111-dev`.
- Both still report package version `1.1.0`. The candidate is distinguished by
  its dev rule version, commit and engine hashes; it has not been released.
- Each engine's 30 recorded source/data SHA-256 values match its frozen source
  snapshot. The summary's `source_revision` is the **harness workflow commit**,
  including in the baseline summary; baseline engine identity is the archived
  baseline commit and `apsa_engine`, not that generic revision field.
- Shared manifest SHA-256:
  `a0117b72ed166dda11f95d085806bd9cd36dbe7a94739d01a9985e55fb8b1682`.
- MobSF release source: `d3869adc464b89db92a6a8a9e2dc13376f4a4c25`; actual image:
  `opensecurity/mobile-security-framework-mobsf@sha256:5113fbad0727445dda01afdccafea5e107bfa8632ead8a169492f5caa8aa1b7c`.
- JADX 1.5.0 [upstream release](https://github.com/skylot/jadx/releases/tag/v1.5.0),
  asset `163283857`; observed ZIP SHA-256:
  `c5a713fa4800cbb9e6df85ced1bef95ba329040c95cb87d54465f108483e4ef9`.
  The upstream asset exposes no expected digest. Version and size were checked;
  this hash records the downloaded bytes and is not an upstream signature.
- [Full synthetic artifact](https://github.com/ictechgy/apsa/actions/runs/37808597054/artifacts/11564840911),
  including inputs, compiler provenance and every raw report, expires
  2026-11-07. ZIP digest:
  `sha256:0a98b1c690092d3f652adc863e086ce132c2bd4e9f180d5ae468046708565899`.
  The compact summaries are committed here for durable reference.

Per-case median elapsed time on the hosted runner was 0.226/0.224/0.998 seconds
for baseline/candidate/MobSF source scans, and 0.380/0.370/2.861 seconds for APKs.
APSA uses a fresh CLI process/store; MobSF uses a warm service with two CPUs and
4 GiB assigned. Setup and image pull are excluded. These are workflow costs,
not an engine-only speed ranking; CPU/RSS and statistical significance were not
measured.

Earlier runs `37802283185` and `37804348298` stopped at service reachability and
are not competitor results. The successful run uses the inspected IP of a fresh
internal Docker network, no published service port, and no user app inputs.

## Competitive direction and next evidence

This run supports investing in precise, inspectable local source findings and
review workflow quality. MCP access itself is not an accuracy result or evidence
of exclusivity. Broader scanner coverage, runtime capabilities, feed quality,
model integration performance, and commercial products were not compared here.

The next useful evaluation is an independently labeled set of realistic open
source apps, kept separate from development cases, with source and release-build
results, rule availability, analysis failures, alert-review time and resource
cost reported. Add iOS embedded binaries, Objective-C, AAB/obfuscation and
device-backed tests as distinct groups; test CVE/OSV correlation on a frozen
advisory snapshot with known affected/fixed versions and patch-state evidence.
