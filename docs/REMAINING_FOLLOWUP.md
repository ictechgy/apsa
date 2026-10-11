# Remaining follow-up — 2026-10-11

This is an unreleased working-tree follow-up to
[COMPETITIVE_FOLLOWUP.md](COMPETITIVE_FOLLOWUP.md), with acceptance criteria in
[the remaining-work plan](../work/plans/2026-10-11-remaining-followup.md).
The prior document records its completed software snapshot and historical
measurements; its validation counts do not approve this subsequent change.
The published 1.5.1 package and historical baselines remain unchanged.
Aggregate validation is recorded below. Independent review of the complete
working-tree snapshot is recorded in [the review artifact](../work/reviews/2026-10-11-remaining/REVIEW.md).
Local checks do not establish publication readiness or a comparative ranking.

The user authorized **new synthetic apps only**. There is no authorized
physical-device or installed-app target. Work uses source and newly generated
fixtures beneath `/private/tmp/apsa-remaining-j0e922qc`; it does not inspect existing
app data, history, media, uploads, outputs, prompts, private logs, preferences,
live files/jobs APIs, UI, screenshots or clipboard. New shell calls inherit the
project guard. The session reports its native permission profile as disabled;
this document does not claim named-profile activation.

## Explicit APK-set selection

CLI `scan --apk-set-device DEVICE_SPEC.json` accepts an explicit bundletool-style
device specification for an `.apks` archive. The JSON must contain exactly
`sdkVersion`, `supportedAbis`, `screenDensity` and `supportedLocales`. ABI ordering
is significant. This is a caller-declared selection specification, not a device
observation; it does not enumerate a connected device.

For example, a newly generated fixture specification can contain:

```json
{
  "sdkVersion": 34,
  "supportedAbis": ["arm64-v8a", "armeabi-v7a"],
  "screenDensity": 420,
  "supportedLocales": ["en"]
}
```

The bounded `toc.pb` selector models released SDK levels, ordered single-ABI
targeting, positive density values/numeric aliases, language targeting and
fallbacks, install-time feature modules with dependencies, split APK sets and
one selected fused standalone APK. Selection preserves module, targeting and
archive-member provenance. Missing, malformed, ambiguous or unsupported TOC
cases fail closed instead of silently choosing a build.

Unsupported cases include overlapping variant priorities; multi-ABI, texture,
sanitizer, device-group/tier/country and SDK-runtime targeting; instant, asset,
system, APEX, archived, conditional, on-demand and fast-follow delivery; default
or nodpi density selectors; prerelease SDKs; unsupported configuration-split
targeting; unknown protobuf fields; and unlisted APK archive members. Archive
path, duplicate-member, encryption, compression, byte and file-count limits still
apply to the outer archive and selected nested APKs.

Selected APKs are inspected individually, with their selection provenance
available in the inventory/report. This does not establish the effective merged
manifest/resources, installation success, an installed split set or runtime
delivery. Those remain explicitly unverified. The selector does not invoke
bundletool or install APKs.

## Explicit IPA integrity and chain policy

CLI `scan --ipa-trust-policy TRUST_POLICY.json` accepts a policy only for an
`.ipa` archive. Its schema is:

- `schema_version`: exactly `1`.
- `anchors`: one to four objects containing exactly `der_base64` and `sha256`.
  Each anchor must use canonical bounded base64 DER, have its exact SHA-256
  digest, and be unique.
- `verification_time`: optional bounded Unix epoch integer. When omitted,
  verification uses current time, identified as such in the summary.
- `policy_sha256`: optional input checksum. The implementation normalizes and
  sorts anchors, computes the policy digest without this checksum field, rejects
  a supplied mismatch, and binds evidence to the resulting digest.

Raw DER remains verification input. Reports summarize anchor digests, policy
digest, verification time and purpose; they do not include anchor DER.

Sparse CodeDirectory page mapping and CodeResources resource-sealing evidence
are checked separately from the detached CMS signature and explicit-anchor
certificate chain. Content/hash consistency and cryptographic chain validation
remain distinct results. Modified, wrong-anchor, expired, missing, unsupported
or incomplete evidence cannot become a successful authenticity claim.

The opt-in Apple-root path isolates exact allowlisted Apple root fingerprints
from other supplied anchors. A cryptographically valid chain to such a root
still does not establish Apple developer signer identity, provisioning policy,
app authenticity, revocation status, encrypted code coverage or installation
trust. Reports retain `cryptographic-chain-only`, `revocation: not-checked` and
unsupported Apple identity-policy limits.

MCP `audit_scan` and `audit_start` accept the same `apk_set_device` and
`ipa_trust_policy` options as dictionaries. Foreground and background CLI paths
carry the corresponding options. This source-level contract is covered by
integration tests; a successful served SDK session is not claimed below.

## Trusted runtime acquisition seam

`runtime.run(..., adapter=ACTION_ADAPTER, acquisition_adapter=ACQUISITION_ADAPTER)`
accepts a constructor-injected `AcquisitionAdapter`. Both adapters must be
explicit; acquisition injection cannot trigger implicit device discovery. There
is no CLI or scenario-JSON field that turns a supplied capture into trusted
acquisition proof. Existing operator digest captures remain unverified.

The recorder creates fresh session and capture nonces, checks typed responses
against their exact request, and binds platform, package, strong build identity,
snapshot, account, state and target delivery before evaluating a transition.
Only bounded raw observations enter the recorder. It computes marker matches,
byte counts and evidence digests itself and persists labels, hashes, bounded
states and provenance. It does not persist acquisition bodies, headers, URLs,
credentials or arbitrary commands. Exceptions from the acquisition adapter use
a fixed redacted failure reason.

Each capture surface declares `complete`, `partial` or `unsupported`. Missing,
partial, contradictory, replayed or malformed evidence remains inconclusive;
an unrelated complete surface cannot establish a missing surface's absence.
Manual capture JSON cannot overwrite recorder-produced provenance. Acquisition
mode and adapter identity are part of the typed scenario scope/identity, so
synthetic and instrumented evidence are incomparable and cannot clear each
other's findings even if their build digests match.

`SyntheticTestAppAdapter` executes login, account-switch and logout models for
Android/iOS-bound scenarios through an in-memory mocked transport. It supports
one transition per fresh app model. Newly generated Kotlin/Swift sources are
reviewable source models, not compiled or installed apps. Reports record
`mode: synthetic`, `synthetic-app-model-build` and
`live_device_verified: false`; residual finding evidence preserves that mode.

Backend session invalidation is a separate result: an accepted baseline replay
and a rejected after-logout replay must use the same credential digest, backend
authority and recorder session, with bound delivery and complete network
evidence. Local canary removal cannot substitute for that probe. Synthetic
tests independently vary local residual retention and backend invalidation,
including both failure cases. They prove the fixture contract, not the behavior
of an external backend or all credentials.

The public `acquisition_plan` explicitly reports live acquisition as unsupported.
Actual acquisition still needs an authorized dedicated target and test accounts,
a platform instrumented-app or authenticated-proxy adapter, measured installed
identity/delivery/completeness, and authorized backend replay. No target is
currently authorized, and none was enumerated or operated.

## Validation evidence and limits

The following are separate scoped runs. Counts can overlap and must not be
summed into a unique-test count. The final aggregate is a separate run below.
All linked temporary artifacts were newly generated in this follow-up.

| Lane | Recorded result | Fresh evidence |
| --- | --- | --- |
| APK-set selector | 95 tests passed; scoped Ruff passed | [Selection/source contract](/private/tmp/apsa-remaining-j0e922qc/fixtures/apks/evidence/selection-contract.json), [argv/status/stdout/stderr](/private/tmp/apsa-remaining-j0e922qc/fixtures/apks/evidence/pytest-final2.json) |
| IPA trust/integrity | 78 tests passed; separate CodeDirectory page-mapping selection passed 4 tests | [Source hashes](/private/tmp/apsa-remaining-j0e922qc/fixtures/ipa-trust/evidence/source-sha256.json), [78-test invocation](/private/tmp/apsa-remaining-j0e922qc/fixtures/ipa-trust/evidence/validation-5-0.json), [stdout](/private/tmp/apsa-remaining-j0e922qc/fixtures/ipa-trust/evidence/validation-5-0.stdout), [4-test invocation](/private/tmp/apsa-remaining-j0e922qc/fixtures/ipa-trust/evidence/validation-3-1.json), [stdout](/private/tmp/apsa-remaining-j0e922qc/fixtures/ipa-trust/evidence/validation-3-1.stdout) |
| Runtime acquisition/v2 evidence | 81 tests passed; scoped Ruff and Python-3.12 Pyright passed | [Source-bound manifest](/private/tmp/apsa-remaining-j0e922qc/fixtures/runtime-acquisition/verification-manifest.json), [pytest invocation](/private/tmp/apsa-remaining-j0e922qc/fixtures/runtime-acquisition/pytest-scope-final.invocation.json), [stdout](/private/tmp/apsa-remaining-j0e922qc/fixtures/runtime-acquisition/pytest-scope-final.stdout); adjacent `.stderr` and `ruff-scope-final`/`pyright-scope-final` invocation/output files retain their raw results |
| Native Swift adaptation regression | 199 passed, 3 skipped, 4 excluded; helper metadata preserves adaptation/partial state | [Source hashes](/private/tmp/apsa-remaining-j0e922qc/fixtures/native-adaptation/evidence/source-hashes.json), [Synthetic adaptation outcomes](/private/tmp/apsa-remaining-j0e922qc/fixtures/native-adaptation/evidence/adaptation-outcomes.json) |
| CLI/MCP/job option integration | 13 tests passed; actual trusted tool bodies executed, served SDK excluded | [Invocation](/private/tmp/apsa-remaining-j0e922qc/evidence/integration-final.invocation.json), [stdout](/private/tmp/apsa-remaining-j0e922qc/evidence/integration-final.stdout.txt) |

The complete selected aggregate passed **748 tests**, with 3 skipped and 6
deselected, in 7.03 seconds. The five retained archive consumers were excluded
under the input privacy boundary; the served MCP case was excluded because of
the SDK restriction below. Its [exact argv/status](/private/tmp/apsa-remaining-j0e922qc/evidence/aggregate-v3.invocation.json)
and [stdout](/private/tmp/apsa-remaining-j0e922qc/evidence/aggregate-v3.stdout.txt)
retain the selected modules and exclusion expression. This is not the full suite.
The test-only RSS adapter is limited to newly staged parser inputs and leaves
CPU, wall time, file/output limits and the project guard in place.

Ruff check and format checks pass on all 56 changed Python files; full `src`
Python-3.12 Pyright reports zero errors, warnings and informations. The
[static invocation/output records](/private/tmp/apsa-remaining-j0e922qc/evidence/static-v3-ruff-check.invocation.json)
and [Pyright result](/private/tmp/apsa-remaining-j0e922qc/evidence/static-v2-pyright.stdout.txt)
retain those scopes. A macOS policy unit fixture was made independent of the
outer parser-mode environment by explicitly selecting `required`. Earlier
aggregate attempts failed on that fixture's inherited `off` mode and, after the
source manifest changed, its documentation hash assertion; both raw failures
are retained. The final run passes both cases.

MCP source normalization reproduces both published 1.5.1 hashes before checking
the current 23-tool default and 25-tool runtime surfaces. Current fixture and
document hashes agree; [source contract proof](/private/tmp/apsa-remaining-j0e922qc/evidence/mcp-source-contract-v2.json)
records parameter schemas, descriptions and annotations. This remains an
AST/Pydantic source check, not a successful served `tools/list` response.

The 50/54-case frozen synthetic source corpora were recreated with unchanged
label hashes and rerun on the new analyzer snapshot. Scored detection totals
remain 27 TP/21 TN and 29 TP/23 TN, zero FP/FN/failures, with 30/34 partial and
two unscored cases each. Ten Kotlin partial-state expectation mismatches remain
visible rather than editing the labels; [the corpus record](COMPETITIVE_CORPUS.md)
explains this distinction.

The new native direct-profile fixture contains 32,256,000 bytes and 32,000 methods
and completed in 1.306 seconds. Native flow remained partial at the callable
inventory budget; this is neither a full-flow pass nor a comparable speedup over
historical benchmarks. See [the raw performance record](/private/tmp/apsa-remaining-j0e922qc/fixtures/native-adaptation/evidence/performance.json).

A broader legacy runtime attempt recorded 12 failures, 86 passes and one
excluded existing archive-fixture test. The failures were guard-denied child RSS
inspection during synthetic parser subprocesses. Raw results remain in
[its invocation](/private/tmp/apsa-remaining-j0e922qc/fixtures/runtime-acquisition/pytest-final.invocation.json)
and [stdout](/private/tmp/apsa-remaining-j0e922qc/fixtures/runtime-acquisition/pytest-final.stdout).
Production resource limits were not changed. This failed attempt is not counted
as successful aggregate verification.

The actual SDK import probe exited 1 with `ModuleNotFoundError` for
`mcp.server.fastmcp.prompts` in the guarded environment; see [invocation](/private/tmp/apsa-remaining-j0e922qc/evidence/served-mcp-import.invocation.json)
and [stderr](/private/tmp/apsa-remaining-j0e922qc/evidence/served-mcp-import.stderr.txt).
The actual wheel-build probe exited 1 because the available `build` namespace
lacked `build.__main__`, and hatchling was absent; see [invocation](/private/tmp/apsa-remaining-j0e922qc/evidence/wheel-build.invocation.json)
and [stderr](/private/tmp/apsa-remaining-j0e922qc/evidence/wheel-build.stderr.txt).
Neither probe is a served-MCP, clean-build or clean-install pass. No bypass,
package installation or shell network workaround was used.

No current Semgrep, MobSF, bundletool or adb executable was available to this
run. There is no fresh competitor head-to-head result, physical-device auth or
network measurement, installed split-set measurement, Apple signer/authenticity
proof, revocation measurement or publication. Upstream evidence used by the
artifact lanes is preserved in the [APK-set contract](/private/tmp/apsa-remaining-j0e922qc/fixtures/apks/evidence/selection-contract.json)
and [IPA source record](/private/tmp/apsa-remaining-j0e922qc/fixtures/ipa-trust/evidence/upstream-sources.json).
The final aggregate and independent complete-diff code/architecture review must
bind their terminal results to the final source snapshot before readiness can
be asserted.
