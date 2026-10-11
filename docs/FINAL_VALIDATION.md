# Actual execution of the remaining gates

2026-10-11. Validation uses public source and newly generated synthetic inputs
only. No existing user app data, media, prompts, history or raw service logs
are inputs. The user separately authorized locating their device and signing
identity; targeted device/certificate metadata stays in new local evidence.
Current evidence root:
`/private/tmp/apsa-final-validation-iddl03na`.

## Local measurements

- Package/corpus checks: 9 passed using actual fresh Java/D8/AAPT2 controls.
  The fresh corpus has 30 cases, 29 matched, 19 true positive labels, zero false
  positive or false negative labels, and one known partial source case.
  `passed` remains false; its narrowly defined regression contract passes.
  The retained upstream APK sample is omitted, rather than represented by a
  reused safe APK as an independent sample.
- Competitor execution/RSS failure handling: 34 passed. Unavailable process
  inspection never becomes a zero-memory measurement. Linux RSS samples use
  only the explicitly owned process tree; the sampled maximum is a lower bound
  on peak and may double-count shared pages.
- Runtime acquisition/transport contracts: 26 passed. New Android and iOS
  fixture executables compiled successfully; actual HTTP/OS delivery remains
  pending isolated CI.
- Bundle fixture: actual AAPT2 protobuf resources/manifest, javac and D8
  compilation succeeded. The official bundletool execution is pending remote
  CI; a compiled module alone is not selection or resource-merge evidence.
- Real local SDK import remains blocked at `mcp.server.fastmcp.prompts` by the
  host privacy guard. No relocated or substitute SDK is used.

## Isolated CI contract

The new validation branch must contain only the reviewed source-stage tree,
public source fixture builders and declared contracts. It must not inherit
retained binary fixtures, local artifacts, caches, logs, `.codex`, `.omx`,
review prompts or workspace state. Validation workflows have read-only
repository permissions and use new temporary fixtures, signing keys,
emulators, simulator UUIDs, HTTP authorities and app storage.

- `synthetic-gates.yml`: actual stdio SDK initialization and `tools/list` in
  both scopes, repeated package hashes, clean installation and newly compiled
  APK scan on Linux/macOS with Python 3.11/3.12.
- `competitive-benchmark.yml`: fixed Semgrep CE and two verified upstream rule
  blobs, fixed MobSF image/JADX, shared frozen new input hashes. Historical
  whole-tree baseline archives have been removed. APSA CLI and warm MobSF
  service timing/RSS scopes remain distinct; no speed, memory-efficiency or
  whole-product ranking follows from those samples.
  Stable process exit never promotes incomplete coverage to a scored negative.
  Partial, unsupported and unmeasured cases abstain from TP/FP/FN/TN totals.
  MobSF does not expose this per-rule coverage contract, so its raw alerts and
  time/RSS observations remain visible while its accuracy cases stay partial.
- `bundletool-validation.yml`: checksum-pinned official bundletool builds and
  extracts real APK sets. Selection hashes are compared independently, then
  a new dedicated emulator acquires the installed splits and looks up a
  French resource. Unsupported selectors remain partial.
- Runtime transport validation: new dedicated Android emulator and iOS
  simulator, actual OS deep-link delivery, installed target hashes, nonce and
  session binding, and an independently replayed credential against the owned
  HTTP authority. Local app-state evidence cannot establish backend revocation.

Workflow preparation and source approval do not establish successful CI runs.
Record exact remote head, run/job conclusions and evidence hashes before
claiming a gate passed. No publication, tag, merge or published MCP baseline
approval is part of validation. Physical-device tests and genuine Apple
identity/provisioning/revocation require a separately designated new test
environment; ad-hoc simulator signing cannot prove them.

## First isolated execution

The exact reviewed source-only tree was transferred to
`validation/apsa-final-20261011-iddl03na`, commit
`397a95eacab12ea2e9348ec67b7fec95ba6a0ffd`, tree
`04942b31d34c78f0249aa8d9bb0b36e80d12ec18`. All 343 files and blob hashes
matched the reviewed stage; no retained binaries or workspace state were
transferred. The source review patch was
`cc145773672df789596f897461cd938a8d23be4719b61b9ac91e649450135013`.

- [Competitor run](https://github.com/ictechgy/apsa/actions/runs/38135893273)
  completed successfully: 46 fresh cases, three repetitions, actual Semgrep
  and pinned MobSF. Both APSA and MobSF supplied 138 measured RSS samples.
  All APSA cases and supported MobSF cases remained partial; no accuracy
  superiority follows. The two-rule Semgrep slice scored four cases:
  two true positives, two true negatives, zero false positives/negatives;
  the other 42 cases were unsupported. These are limited synthetic controls.
- [Runtime run](https://github.com/ictechgy/apsa/actions/runs/38135893334):
  backend-only actual HTTP invalidation passed both safe/unsafe controls.
  Android and iOS ended inconclusive before completing a case. No installed
  acquisition or OS-delivery success is claimed from those jobs.
- The [main CI](https://github.com/ictechgy/apsa/actions/runs/38135893275)
  completed GitHub Action checks on both OSes and framework-Python,
  nested-Seatbelt and Linux bubblewrap compatibility checks. Full test jobs
  found 29 failures, with 1584 or more passing tests. Failures were a missing
  generated plugin alias, test consumers of excluded retained JSON inputs,
  and an outdated dependency-check mock. These are being fixed with new
  synthetic inputs; excluded historical data is not restored.
- [Package gates](https://github.com/ictechgy/apsa/actions/runs/38135893306)
  stopped at those test failures before package/served-manifest measurement.
  The initial official bundletool workflow could not start because job-level
  `env` referenced the unavailable `runner` context. Source fixes and a new
  whole-diff review precede the next execution.

Initial failures remain failures. New source-only reruns must supply terminal
evidence before these gates can be marked passed. User-designated local
device/certificate identifiers are kept only in temporary local evidence and
are excluded from source transfer and public CI.

## Second isolated execution

The exact manifest-bound diagnostic v7 tree contains 345 public source files,
no extra paths, and no local signer/device evidence. Its reviewed patch is
`a36e27a7222eb93c4fb0447039f3bc2753fa44d2800ed5dc86fe77bc16573b98`;
remote commit `5f38b258eedb0289786e0e8015d21b8a29c04f8e`, tree
`3665b4fca9d27e00a2e53663648b1985fc4b4f9d`. Source-transfer review was
code APPROVE / architect WATCH, synthesized COMMENT / transfer READY only.
Both raw terminal reports are preserved locally. Recursive directory copying
was not used; every remote blob path, hash and mode matched the stage manifest.

- [CI](https://github.com/ictechgy/apsa/actions/runs/38137569843): all 11 jobs
  succeeded. [Package gates](https://github.com/ictechgy/apsa/actions/runs/38137569857):
  all four jobs succeeded. Every full matrix run reported 1,620 passed and
  25 skipped. Host/interpreter matrix: Linux/macOS, Python 3.11/3.12.
- The real SDK stdio initialization and `tools/list` matched the pending
  contract from both checkout and clean wheel installation: default 23 tools,
  SHA256 `38ed7e154cae808281ef52cdcb5b115fee6db7b9941060d18b2aed78ad0a3dc3`;
  runtime 25 tools,
  `12ffe656469b9158d5d3154adf103c7c0ea4397375508aad3786e2703e26ad4d`.
  This is served measurement, not published baseline approval.
- Repeated wheel/sdist builds matched across all observed matrix jobs:
  wheel `05e5fec26b48203761b6e01c5262ffa02b3824eca7ffe0cfd8e2c88e02e305cb`,
  sdist `fa93d3075342688c0a44b74de65b1816888f27bfc7a665789323cf96c27fa823`.
  Full SDK response objects remain in the four new package artifacts; local
  evidence uses printed actual hashes and artifact metadata, not a claimed
  local download of those response objects.
- [Runtime](https://github.com/ictechgy/apsa/actions/runs/38137569826): backend
  HTTP controls passed (job 114464491328), and Android passed all four installed
  cases with confirmed owned-device cleanup (114464491380). iOS installed and
  opened the OS URL successfully but remained inconclusive with zero cases
  because no matching app response arrived before the deadline (114464491409).
  Script deadline/lifecycle diagnostics and workflow cleanup are being improved.
- [Official bundletool](https://github.com/ictechgy/apsa/actions/runs/38137569825)
  built and extracted the real APK sets. APSA returned partial/unsupported TOC
  for all three selectors and did not establish installed resource evidence.
  Primary upstream source shows ordinary empty LocalTestingInfo and empty
  unconditional ModuleTargeting are always serialized; the selector is being
  extended to those strictly disabled/empty forms. Conditional/unknown metadata
  must continue to abstain.
- [Competitors](https://github.com/ictechgy/apsa/actions/runs/38137569853)
  completed all 46 fresh shared cases with three repetitions. APSA and MobSF
  each supplied 138 measured process-tree RSS samples. All APSA cases remained
  partial; MobSF had 38 partial and eight unsupported cases. The current
  Semgrep two-rule slice scored two true positives and two true negatives,
  zero false positives/negatives, with 42 unsupported cases; its four command
  executions also supplied measured RSS. Timing/RSS scopes differ and no
  whole-product ranking follows. Artifact ZIP SHA256:
  `bc1190e2df94aac71a733d1368c8f9e6e230a04e6c3902ef8768740ff4742ac9`.

These outcomes are bound to v7, before the new BER/CMS and subsequent runtime,
TOC and public command-provenance changes. Current source still needs complete
independent review and another isolated execution. Main, tags, releases and
published MCP baselines have not been changed.

## New Apple development signature

The user-authorized local lookup found a physical iPhone, an enabled developer
mode and an available Apple Development identity. A newly compiled arm64 UIKit
app was signed with that identity. Native strict `codesign` verification and
independent detached OpenSSL CMS verification succeeded on the original bytes.
No existing installed app, provisioning profile, account preference or private
key export was inspected. No device installation has been attempted.

The genuine fresh CMS exposed a BER indefinite-length compatibility gap in
APSA. A bounded pure parser now accepts constructed BER while preserving the
original signed attribute/certificate bytes. It shares a 4 MiB byte limit,
20,000-node budget and depth limit of 32; malformed end markers, primitive
indefinite lengths, truncation, trailing content and attached content remain
unsupported. The same original CMS changed from unsupported to verified,
with matching CodeDirectory hashes and `cms-and-code-consistent` integrity.
Forty-two synthetic signature tests passed; one existing staged-parser test
could not run under the host's denied RSS inspection and was explicitly
deselected for that focused run. It is not counted as a pass.

Cryptographic signature integrity does not establish Apple signer policy,
provisioning, revocation status or physical-device installation. Genuine local
CMS, IPA, certificate and device identifiers remain outside source transfer
and public CI. This change postdates immutable diagnostic review v7 and needs
a fresh complete review before current-source readiness can be claimed.

An independent native Apple `security verify-cert` check succeeded under the
`codeSign` certificate-chain policy with an explicit pinned Apple Root CA and
only the fresh leaf/intermediate files. Keychain search and CA fetching were
disabled; revocation networking was disabled. The verification time was
2026-10-11 11:55:30 UTC. This certificate-chain result remains separate from
APSA/OpenSSL, which returned invalid-or-unsupported for an unhandled critical
extension. Current revocation, app identity, provisioning authorization and
physical installation remain unverified; no critical-extension bypass was used.

## Primary tooling evidence

- [Semgrep CE 1.179.0](https://github.com/semgrep/semgrep/releases/tag/v1.179.0)
- [Official bundletool commands](https://developer.android.com/tools/bundletool)
- [Bundletool 1.18.3 immutable asset checksums](https://github.com/google/bundletool/releases/expanded_assets/1.18.3)
- [GitHub source-tree API](https://docs.github.com/en/rest/git/trees#create-a-tree)
