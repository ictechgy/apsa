# APSA 1.6.0 release candidate

This release packages the source-stage improvements previously developed after
1.5.1: bounded native cross-file analysis, JS/TS/Dart candidates, explicit
APKS selection, signature consistency and supplied-anchor evidence, dependency
selection and OSV exclusions, runtime observation contracts, large-input
staging/reporting and the subsequent CLI/parser/job/store review fixes.
Rule version: `2026.10.15.apsa.160`.

Native call summaries now require matching package/import/file identity.
Nested nominal containers keep independent lexical ownership; unresolved
ownership preserves taint and partial coverage.
Field summaries use the same nearest nominal ownership, including enum
declaration wrappers, record components and represented constructor properties.
Explicit receiver fields remain distinct from same-named parameters and locals;
unmapped constructor state retains provenance. Shared static storage and unknown
field markers use separate internal identities. Unsupported field semantics
retain candidates and partial coverage instead of supplying a clean helper result.
An unrelated module's same-named function or constructor cannot supply a
sanitizer. Unknown or ambiguous identities preserve argument/field taint and
partial coverage. Swift cross-file summaries remain unavailable without
compiler module identity.

## Upgrade effects

- New candidate findings, partial reasons and stricter source input binding can
  change policy outcomes. Skipped symlinks and ambiguous report-store roots do
  not produce complete scans. Narrow the input or resolve ambiguity explicitly.
- MCP adds tools/schema fields. Pin consumers to the served manifest hashes in
  `tests/contracts/mcp_tool_manifest_pending.json`; the historical published
  manifest is retained and this file is not an approved policy baseline.
- Existing reports, baselines and waivers remain user-owned. No baseline or
  policy is automatically approved, relaxed or re-keyed during release.
- Persistent report exports use no-replace hard links for ownership-safe
  rollback. The store must reside on a filesystem supporting same-directory
  hard links; an unsupported filesystem fails rather than claiming a save.
  Cancellation remains cooperative when process identity cannot be inspected.
- Native helper safety requires closed dispatch. Overridable Java/Swift methods
  and open/override Kotlin calls preserve taint and partial coverage when their
  runtime target is unproven; their guards cannot establish sanitizer proof.
  Qualify genuinely direct helpers appropriately and review newly retained
  candidates; incomplete analysis can now produce CLI exit 3 for such calls.
  Callable parameters/local values and declaration blocks also
  take precedence over similarly named functions where the language requires it.
  Local/member type declarations also take precedence over package classes and
  imports. Unresolved type identity cannot borrow a same-named SDK sanitizer.
  Inherited member types and static type imports also participate in ownership;
  unavailable ownership retains taint and partial coverage before package fallback.
  Member helper calls in inherited scopes require exact argument-to-parameter
  type identity; equal argument counts alone cannot select a safe overload.

## Verification and limits

The prior exact source snapshot `50f1a0f` passed eleven supported CI jobs and
four package/MCP jobs. Those observations are historical; the 1.6 candidate
requires its own supported CI, repeated package-content checks, clean install
and two independent reviews before publication.

Synthetic benchmark execution preserves incomplete controls. An earlier
baseline reported `passed=false` while its declared regression contract passed;
this does not describe the stricter candidate's quality result. Public
CVE alias overlap cases remain unscored; the component benchmark's failure is
preserved. Comparator partial results establish no accuracy or product ranking.
The stricter inherited-type boundary's direct source-only replay also observed
three disagreements among 28 unchanged corpus labels: `java-intent-fixed`,
`kotlin-query-fixed` and `swift-url-fixed` now retain URL candidates with partial
native-flow coverage instead of an empty finding list. This is a measured
support-contract impact, not a passing accuracy result. Frozen labels and the
official hosted quality gate remain unchanged; that gate must be assessed on
the final candidate.
On `3181dfd`, the unchanged official 30-case replay matched 25 cases and measured
TP19/FP3/FN0 with five partial/disagreement cases. Its regression contract and
three existing benchmark tests failed. Those results remain release blockers
until a supported correction or an explicit requirement decision resolves them;
the final candidate still requires its own measurement.
Validation preserves independent benchmark, stdio and package measurements
after an earlier failed check; the overall job still fails, and publication
gates are unchanged.
Physical devices and genuine Apple signing identity/provisioning/revocation
remain unverified. The source driver now retains four logout controls and adds two authenticated
A-to-B account-switch controls per platform (old-A canary deleted/retained).
B authentication uses an app-issued protected request, while independent replay
keeps A's original credential. Source/mock tests do not establish live runs.
iOS OS URL delivery and live account-switch coverage remain explicit open
validation items until a new installed target supplies bound observations.
Transport dispatch, process startup and HTTP backend-only success cannot
substitute for target acquisition.

A separate hosted callback differential builds a new scene app with Xcode and
uses public `XCUIApplication.open(_:)` through an actual UI test. It requires
both cold and warm callback receipts, exact installed executable/plist identity,
distinct nonces and cleanup of its CREATE-returned simulator UUID. This control
contains no login/backend/storage scenario and never satisfies R02. Source and
mock tests alone do not establish that the hosted control has run or succeeded.
The first hosted control on `45d5f5c` built successfully, then XCTest exited 65;
its new simulator cleanup was confirmed. This is an inconclusive callback
measurement. A subsequent bounded diagnostic projects only fixed failure labels
and the generated test's line numbers, preserving the failed primary result.
The next control reached its cold-label expectation deadline. That does not
distinguish a missing callback from a callback with a different lifecycle.
Separate fresh-install/prelaunched controls therefore retain bounded partial
receipt facts without relaxing the required cold/warm lifecycle assertions.

The six Android controls passed on `588150f`, including both authenticated
account switches and terminal cleanup ([owned hosted run](https://github.com/ictechgy/apsa/actions/runs/38608689172)).
That observation is bound to its recorded driver/native fixture hashes; it
does not establish iOS or physical-device acceptance.
The later `54e319c` Android rerun failed during first-session issuance with
two `/issue` requests and a fixture HTTP-status error. The failure remains
inconclusive. Bounded issuance diagnostics now distinguish accepted/rejected,
bound/unbound and distinct request digests without retaining request bodies
or changing any acceptance condition.

The next Android run on `5813403` passed all six controls, including both account
switches, with one accepted, bound issuance per case and both cleanup stages
confirmed ([owned hosted run](https://github.com/ictechgy/apsa/actions/runs/38689208783)).
This is evidence for that execution and unchanged recorded runtime inputs;
it neither identifies the earlier issuance failure's cause nor establishes iOS
acceptance or an exact-head run for a later source-analysis change.

Publication uses the stable version/tag match, required CI, repeated verified
wheel/sdist build and Trusted Publishing. A separate post-publication workflow
checks PyPI and release digests, tag/source binding, MCP Registry metadata and
cold installation/startup using new synthetic fixtures. A published version is
reported complete only after its public artifacts and those checks succeed.

## Hosted setup differentials

The first custom-set Simulator GUI control on `9255cd6` failed for both simctl
and companion dispatch. Owned GUI children and device cleanup were confirmed;
no target URL callback was observed. GUI startup alone did not establish a fix.
The next source adds an explicit custom/default set differential and a bounded
600-second setup bootstatus budget, compared with the primary 180 seconds.
Every operation remains bound to the newly created and journaled UUID. GUI
binding/foreground are unverified; all target session/nonce/build, lifecycle,
canary, B-authentication and cleanup gates remain required. Primary failures
are retained. The differential is not a universal Simulator support claim.

The custom/default legacy GUI differential on `588150f` also failed to observe
a target callback. A separate modern custom-set control pins Xcode 26.3 and
iOS 26.2 while preserving the same six-case acceptance contract. Its source
and mocked checks do not establish delivery or a fix for the legacy failures.

The modern GUI control on `54e319c` failed earlier: installation or app-container
lookup timed out before any target launch or URL probe. Its NEW device and owned
GUI-child cleanup were confirmed; no callback conclusion follows. A separate
modern/custom headless setup differential keeps the same pinned factory,
600-second bootstatus allowance, other command deadlines and six-case driver
contract while omitting GUI spawn/reap. Its measurement and evidence file are
distinct; it cannot replace a failed primary result.

Both modern headless drivers on `5813403` completed boot, installation and
container lookup, then reached the target-response deadline with no new URL
receipt or `/issue` request ([owned hosted run](https://github.com/ictechgy/apsa/actions/runs/38689208946)).
Direct diagnostic launch created a new process epoch but did not observe an
active scene, so no warm URL probe ran. Both cleanup stages were confirmed.
This control remains inconclusive and does not satisfy live iOS acceptance.

The native role-selector review processes failed before start because their
configured model is unavailable in this account. Independent code/spec and
architecture lanes use the installed role definitions with inherited session
settings; task names are tracking labels, not native role selectors. Exact
snapshots, raw reports and the failed launch records are preserved separately.
