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

## Third isolated execution

The independently reviewed v8 source-only patch
`50cecca6a918ceb15c8e125d9385610c0b5a660b561e5eb62cad7c034ef0a073`
was transferred as exactly 345 manifest-bound files. Commit
`2e7a9b756cdac8ddda88d4f02e2f3cddd8ec5a80`, tree
`5c6eeacc5d854a0ecd2535899ff4a79a8793421b`. Code review APPROVE and
architecture WATCH synthesized COMMENT / source READY. Broader legacy runtime
capabilities are outside the trusted new-fixture validation path; release and
physical-device claims remain separate.

- [CI](https://github.com/ictechgy/apsa/actions/runs/38138930340) passed all
  11 jobs; [package gates](https://github.com/ictechgy/apsa/actions/runs/38138930385)
  passed all four. All eight full matrix executions reported 1,666 passed and
  25 skipped. Ruff/formatting and Pyright passed. Actual stdio initialization
  and default 23/runtime 25 tool hashes matched from checkout and clean wheels.
- Repeated package hashes matched across those jobs: wheel
  `2d6a524fec6fba0544d021191be4a7b4659d587ba037113438764549746aebef`,
  sdist `6fedc1045c26f4b5ef6bd5efeb8a208d5a1e5914e494ca28c8d391579c68aebd`.
  Full served response objects remain in new artifacts; local observations use
  printed hashes and artifact digests. No baseline approval follows.
- [Runtime](https://github.com/ictechgy/apsa/actions/runs/38138930413): backend
  passed two HTTP controls and Android passed all four installed controls with
  confirmed script and workflow cleanup. iOS remained inconclusive with zero
  cases: the startup scene was observed but no URL-received label or matching
  response appeared. Cleanup was confirmed. Missing required CFBundleTypeRole
  is a concrete URL-registration defect; its contribution to this runtime
  failure remains an inference until a fresh rerun. Active-scene readiness and
  callback-entry diagnostics are being added without treating dispatch as proof.
- [Official bundletool](https://github.com/ictechgy/apsa/actions/runs/38138930341)
  now passes ordinary empty metadata, but all three selectors remain partial:
  real config splits carry a shared SDK minimum alongside their density/language
  selector. The reported TOC SHA is
  `68d8e61a2bdac81eacdfdb546b08ef1d695cd4aa3bea2a6c24b34743ec27a7c7`.
  New support requires one selector plus a single shared SDK minimum matching
  the module masters, and still ANDs every modeled condition. Unknown, nonshared
  or compound selector dimensions remain unsupported. This change requires a
  new complete review and actual official rerun; no selection/install/resource
  success is claimed from v8.
- [Competitors](https://github.com/ictechgy/apsa/actions/runs/38138930292)
  completed all 46 fresh cases and three repetitions. Each tool supplied 138
  measured RSS samples; coverage abstention and distinct timing/RSS scopes
  remain unchanged. Semgrep scored two true positives/two true negatives with
  zero false positives/negatives on four eligible cases and abstained on 42.
  Artifact ZIP SHA256:
  `0e93a72bae8ccdbba55ed04ecae4fc0f2cf424967983741a2f836891b777e52b`.

All v8 results remain bound to that exact head. Later SDK-selection support,
bounded bundletool console evidence and iOS delivery changes stale current-source
v8 approval. The next complete source review includes the required URL role and
name, active-scene readiness, and acquisition-bound lifecycle observations. Its
iOS driver terminates only its new target before the first session and requires
the cold scene URL context, then requires warm contexts for capture and logout.
These source checks do not establish actual OS delivery before the next CI run.

## Fourth isolated execution

The full v9 patch
`8b7abd0c82e5b878f82d7455c5f34d600ca46dc31d5d26abb59bca37c58839eb`
received independent code APPROVE and architecture CLEAR / source READY.
Exactly 345 manifest-bound source files were transferred as commit
`57a8f9b5e56eea1e68d74925dec074ed6530af36`, tree
`f3f2d1af2a958f670277c4d2ef122c822459efc4`; no extra paths or local device,
signer, private workspace or retained binary evidence were transferred.

- [CI](https://github.com/ictechgy/apsa/actions/runs/38140523955) passed all
  11 jobs; [package gates](https://github.com/ictechgy/apsa/actions/runs/38140523919)
  passed all four. All eight full matrix executions reported 1,699 passed and
  25 skipped. Actual checkout and clean-wheel SDK responses matched the pending
  23 default / 25 runtime contracts. Fresh dual-engine APK and actual MCP binary
  scans passed with matching input hashes. Repeated wheel and sdist hashes
  matched across the matrix:
  `76924137808148c40b267646b33b33e9864c5b24a8201e7074b7fb35de6af98d`
  and `74c06235895398fe69e1461c48595ad30aef551ff63e2925325c405eb1d551e2`.
- [Official bundletool](https://github.com/ictechgy/apsa/actions/runs/38140523920)
  succeeded. All three official/APSA selections matched by path and digest
  (two, three and three APKs), and the installed three-APK acquisition matched
  the official selection. Expected and observed French resource SHA256 both
  equal `b3d530f23c1513fe35edc53add3cf0f326d88a660d40c5a46a58e853098c971e`.
  Instrumentation, package uninstall and owned-emulator/binary/key cleanup
  succeeded. This proves only this new fixture's selection/install/resource
  behavior; the general static selector does not claim installation or merges.
- [Runtime](https://github.com/ictechgy/apsa/actions/runs/38140523954): backend
  passed two HTTP controls and Android passed four installed controls. iOS
  remained inconclusive with zero cases and no bound app response after launch,
  terminate and cold openurl all returned zero. Its last lifecycle label was
  `scene-active`; that overwrite-only label cannot exclude transient earlier
  callbacks. The required URL-role fix did not establish delivery and must not
  be represented as the sole runtime cause. All workflow cleanup was confirmed.
  New diagnosis will retain bounded fixed-label callback receipts and digests
  without weakening the cold/warm scene or acquisition/session/nonce contract.
- [Competitors](https://github.com/ictechgy/apsa/actions/runs/38140523921)
  completed all 46 fresh cases and three repetitions. APSA and MobSF each
  supplied 138 measured RSS samples. All APSA cases remained partial; MobSF
  had 38 partial and eight unsupported cases. Semgrep's four eligible cases
  scored two true positives and two true negatives with zero false positives
  or negatives; 42 cases were unsupported. Distinct timing/RSS scopes still
  prevent any efficiency or whole-product ranking. Artifact ZIP SHA256:
  `3c76167f1ab28458397005045a7b407f2837a1ccef0919f60fe5f7ddaf9944a8`.

These terminal results are bound to v9. Subsequent iOS diagnostic changes require
another complete independent source review before a new diagnostic transfer.
Strict Swift concurrency compilation also identified UIKit main-actor state and
methods used from a background DispatchQueue, plus unsynchronized URLSession
result captures. UI callbacks and queue-owned transport state are now separated,
with locked response snapshots and bounded cumulative callback receipts. Swift 5
and Swift 6 complete-concurrency compilation passed without actor/captured-state
diagnostics, and 73 focused runtime tests passed. These
are confirmed source defects; they do not establish a Swift 5 runtime actor trap
or the cause of v9's missing response. Actual isolated delivery remains required.

## Fifth isolated execution

The complete v10 patch
`842d1f0262e29c47bc6fc426c09128102e54200fead0cf3448191ae307d91e49`
received independent code APPROVE and architecture WATCH / source READY;
synthesis was COMMENT. Exactly 345 source-manifest files became commit
`a9f90bf55cf0fac708e0c8042084e2bdee5172e3`, tree
`43f7126ec196d2e2df7c862163aa67e69fac2e64`. No release or baseline approval
was implied.

- [CI](https://github.com/ictechgy/apsa/actions/runs/38142555972) passed all
  11 jobs; [package gates](https://github.com/ictechgy/apsa/actions/runs/38142556076)
  passed all four. All eight full matrix executions reported 1,715 passed and
  25 skipped. Checkout and clean-wheel actual SDK responses matched the pending
  23 default / 25 runtime tool contracts; fresh dual-engine APK and actual MCP
  binary input hashes matched. Repeated package hashes matched across the jobs:
  wheel `76924137808148c40b267646b33b33e9864c5b24a8201e7074b7fb35de6af98d`,
  sdist `1eee03cb66ba66931202257dba1ae32336c07c4efad26e8e5fa16b7a6d726b3b`.
- [Runtime](https://github.com/ictechgy/apsa/actions/runs/38142556108) is terminal:
  backend passed two HTTP controls, Android passed four installed controls,
  and iOS remained inconclusive with zero cases. All workflow cleanup was
  confirmed. iOS's bounded cumulative diagnostics retained the same random
  launch-epoch digest as the readiness process, with seven startup/absent-URL
  events and zero URL receipts after terminate/openurl returned zero. This
  proves only that the observed file was not updated by a new process/callback;
  it does not distinguish no relaunch from another-container writes. The actor
  correction did not establish URL delivery, and queue/HTTP failure is not
  inferred from the missing receipt. NEW-only termination, app registration,
  container identity and separately labeled warm-route probes are the next
  discriminating diagnosis. Diagnostics never promote a failed case.
- The v9-to-v10 delta is exactly four files: this document, the iOS driver,
  synthetic Swift fixture and runtime tests. The other 341 staged path/blob/mode
  entries are identical. Official bundletool and competitor behavior inputs
  are unchanged, so their successful v9 executions remain bound to v9 and are
  not relabeled as v10 executions.

Any later material diagnostic change needs both independent lanes on the full
final diff before another source-only transfer. Physical provisioning and
current Apple revocation remain separate from these isolated CI runs.

## Independent iOS app-to-app control

The next source snapshot adds an explicitly selected companion URL-driver and a
separate strict CI job. The original simctl job remains independently visible;
there is no automatic fallback or reinterpretation of its failed acquisitions.
A NEW source-compiled UIKit helper calls Apple's
[`UIApplication.open`](https://developer.apple.com/documentation/uikit/uiapplication/open(_:options:completionHandler:))
once from its active scene with empty options. Both apps are installed only in
the same owned NEW device set/UUID and their installed executable/plist hashes
are checked. A freshly generated custom scheme is registered only by the target;
the helper registers none and makes no existing-app query.

The helper's opening completion is an OS result, not authenticated target
acquisition. Cold acceptance still requires confirmed owned-target termination,
a new random target process epoch, a bound scene `willConnect` URL receipt and
the matching target/session response. Later captures and logout require warm
`openURLContexts` receipts and capture nonces. Both paths retain the independent
real-HTTP authority replay and all four invalidate/retain controls.

Known-PID identity and exit checks inspect only the positive PID returned by
launching the exact NEW package; unavailable inspection remains unmeasured.
Exact-package registration and canonical container checks stay under the NEW
owned set. A bounded diagnostic after a cold timeout may independently launch
the target and try a noncredential warm challenge. This tail preserves the
original failure before mutation, is clearly separated, and never supplies
acquisition or a passing case. No target/container/PID enumeration, raw process
arguments, UI inspection or service/network workaround is used.

The final local source checks passed 116 runtime tests, including an extracted
Swift URI-validator execution on 25 newly generated boundaries (four accepted,
21 rejected). Both target and dispatcher passed Swift 5 and Swift 6 complete
concurrency builds with zero actor/captured-state diagnostics. These four local
builds and validator checks are not OS-delivery evidence. This design is pending
complete independent source review and actual isolated execution; it does not
identify a CoreSimulator bug or establish delivery yet.

## Sixth isolated execution

The full v11 patch
`5603b431583e050c03b52a99c2a96aab26009af6ea7e59605c1a3f4d75e65b74`
received code APPROVE and architecture WATCH / source READY. Exactly 346
manifest-bound source files became commit
`12e8f29047b60bc3868021cd47c881f69198e203`, tree
`c481ebb9f1160a2bea1094faf956a45e0e42c48c`.

- [CI](https://github.com/ictechgy/apsa/actions/runs/38145755571) passed all
  11 jobs; [package gates](https://github.com/ictechgy/apsa/actions/runs/38145755633)
  passed all four. Four Ubuntu main/package executions reported 1,757 passed /
  26 skipped; four macOS executions reported 1,758 passed / 25 skipped. The
  required isolation suites reported Ubuntu 1,758/25 and macOS 1,760/23.
  Actual checkout/clean-wheel 23/25-tool SDK hashes, fresh dual-engine APK and
  actual MCP input-hash checks passed. All eight repeated package outputs
  matched wheel `76924137808148c40b267646b33b33e9864c5b24a8201e7074b7fb35de6af98d`
  and sdist `80c36bf17aea4944e24d1ce5555fead1f876ebce63f822dde2b062dacd6defef`.
- [Runtime](https://github.com/ictechgy/apsa/actions/runs/38145755701): backend
  passed two and Android passed four controls. Both iOS jobs remained
  inconclusive with zero cases, before first target launch or companion
  build/install/dispatch: an optional tool-help diagnostic timed out at its
  ten-second bound and aborted construction. This is a concrete harness
  diagnostic failure, not measured failure of either OS URL delivery mode.
  All workflow cleanup was confirmed and all eight artifacts were head-bound.
- The v10-to-v11 delta has six changed existing paths plus one new helper source;
  339 staged path/blob/mode entries are unchanged. The actual bundletool and
  competitor source inputs remain unchanged and their v9 success is not
  relabeled as v11 execution.
- Architecture retains a nonblocking AAPT2 supply-chain watch: its pinned
  Maven version is downloaded over HTTPS and hashed after download, but the
  JAR lacks a predeclared expected checksum. Bounded primary-source lookup
  could not retrieve an independently verified SHA256; source-tree blob IDs
  are not substituted for artifact hashes.

The source correction now makes only allowlisted non-authority tool-help,
appinfo and plist diagnostics explicitly unmeasured and nonfatal on command
failure or timeout. After an unmeasured help probe, remaining help probes are
skipped; no retry or deadline extension is added. Command timeout/hash records
remain intact. Mandatory install, launch, PID identity/exit, callback, build,
authenticated response and HTTP authority checks still fail closed; no primary
deadline or acquisition proof is relaxed. All 125 focused runtime tests passed,
including nine new diagnostic/primary-failure boundaries; Ruff, formatting and
Pyright passed. The target/helper Swift sources and runtime workflow are
unchanged, preserving the prior strict Swift 5/6 compile evidence. This change
needs both full independent source lanes and another actual isolated execution.

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
