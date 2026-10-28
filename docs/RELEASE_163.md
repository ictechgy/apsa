# APSA 1.6.3

APSA 1.6.3 improves bounded input handling, native source-flow correctness,
credential-text inspection and evidence exports. It also adds per-finding
follow-up for comparing explicit before/after reports. These are audit-engine
and workflow changes; findings remain subject to the evidence and coverage
limits below.

Package version is `1.6.3`; rule version is `2026.10.29.apsa.163`.

## Input and analysis corrections

- Supported ZIP members that are omitted because of Unix directory metadata
  now leave explicit incomplete coverage and omission diagnostics. Skipped
  compiled members retain name-only observations; their contents are not read
  or extracted for those observations. Ordinary directory entries are not
  counted as uninspected files.
- Opaque Gradle expressions remain unresolved rather than supplying invented
  dependency usage or exact-version evidence. Directory and source-ZIP paths
  retain the same conservative boundary; ambiguous evidence cannot clear
  partial coverage or establish a resolved build.
- Kotlin receiver-scope analysis distinguishes recognized standard scope
  functions from custom, imported or shadowed callables. Nonlocal return flow
  is preserved for custom `with` calls and file/package callable variables.
  Backtick-wrapped ordinary identifiers use consistent declaration, lookup,
  import, function, variable and lambda-argument identities without rewriting
  original source locations or string contents.
- Unsupported or recovered Kotlin imports cannot establish standard-library
  scope-function identity. Their original import location receives one
  uncertainty diagnostic per file, including recovery errors following
  comments. Normal imports and following valid declarations retain their
  precision. Invalid-syntax diagnostics are not executable vulnerabilities.

Native analysis remains bounded and conservative. This does not add complete
dispatch resolution, a whole-app call graph, arbitrary escaped Kotlin names or
general class/type/package alias resolution. See
[analysis coverage and partial diagnostics](ANALYSIS_LIMITS.md).

## Credential text and model evidence

- APK/IPA admitted plaintext resources, including admitted JavaScript bundles,
  have the separate `PACKAGED-CREDENTIAL-TEXT` check. Credential candidates from
  source folders, source ZIPs, AABs and `.app` folders use
  `SOURCE-HARDCODED-SECRET`. Compiled source rules do not become analyzed merely
  because text credentials were inspected.
- Credential-only `.properties`, `.strings`, `.pem` and `.key` inputs have a
  separate channel. Already admitted `.h`, `.yaml`, `.yml`, `.toml`, `.lock`,
  `.lockfile`, `.resolved`, `.pbxproj` and `.xcprivacy` text also reaches the
  credential matcher without broadening AST admission.
- Known credential formats produce candidates with the fixed `[REDACTED]`
  marker, without a value prefix, exact length or value hash. The collected
  plaintext channel is not serialized into reports. Coverage metadata is
  aggregate; unsupported encodings/binary members and parent staging omissions
  remain visible as unknown or partial. Repeated unsupported-text warnings
  are summarized instead of emitting one per binary member.
- Detailed, exact-finding and truncated model contexts retain the fixed
  untrusted-evidence guidance and output byte limits. This is advisory context;
  it does not enforce model behavior or guarantee prompt-injection prevention.

There are no credential-service requests or live-key validation. A key-shaped
string does not establish validity, privileges or compromise. Google API-key
candidates require restrictions and usage review. Binary or encoded secrets,
arbitrary-text redaction, server authorization and token revocation need their
own verification. The [AI-assisted attack assessment](AI_ASSISTED_ATTACK_DEFENSE.md)
separates the REA/ARTEX research, engineering inference and implemented scope.
No autonomous offensive executor is included.

## Report follow-up and upgrade effects

`apsa reports followup BEFORE AFTER --finding F-ID --out followup.json` and MCP
`reports_followup` preserve report hashes, distinguish possible continuations
after line changes, and report scope or coverage gaps. A disappeared finding
does not establish remediation. See [follow-up usage](FINDING_FOLLOWUP.md).

- Explicit synthetic evidence path kinds and deterministic selection among
  multiple CVE aliases can change finding IDs for existing observations.
  Rescan with one engine version before comparing reports or approving a new
  baseline; an ID disappearing during this migration does not prove a fix.
- The rule-version change distinguishes analysis snapshots for report
  comparison, paired verification and timeline scope. Cross-version
  disappearance is not remediation; rescan both inputs with the same engine
  before drawing that conclusion. Rule version itself is not part of a finding
  ID and does not automatically invalidate a policy's `only_new` baseline.
- Candidate SARIF descriptors use a candidate suffix independently of stronger
  evidence for the same APSA rule. Collision avoidance may extend that suffix.
  Candidate-only descriptor IDs migrate; this SARIF change leaves
  `properties.apsaRuleId` and finding fingerprints unchanged. Review code-scanning
  baselines and keep the existing analysis category.
- New candidates, more precise flows and corrected partial states can affect
  required-rule policies, `only_new` baselines and waivers. Inspect the new
  reports before approving replacement baselines or exceptions; existing
  saved reports and approvals are not rewritten.
- Non-findings context pages omit the `findings` field; use `page.section` and
  `section_counts`. CLI `jobs status` returns exit 3 for cancelled audits;
  a processed `jobs cancel` request returns exit 0 without claiming completion.

## Validation and delivery scope

The final local source-review snapshot passed **8,300 tests**, with 4 skipped
and 6 subtests passed, plus seven static checks and an offline wheel
production-file parity check. Independent code and architecture review found
no blocking issues in the complete 161-file review delta. Fresh synthetic
regressions and compiler checks exercise the reported failure modes; generated
classes were not executed.

Six ordinary public FOSS APKs were scanned offline in 31.49 seconds. The reports
contained 8 configuration-confirmed observations and 42 candidates and remained
partial. Those 50 observations are not 50 proven vulnerabilities or an accuracy
benchmark. Warnings fell from 5,742 in the earlier credential-channel replay to
89 without suppressing omission or incomplete-coverage information. No app was
installed or run, no device was used, and no key validity was queried.

Local validation does not establish registry publication. The exact release
commit still requires supported hosted CI, package/clean-install gates and
tag-context publication, followed by public download and installation checks.
Current status belongs in [release readiness](../RELEASE_READINESS.md); the
[publishing workflow](PUBLISHING.md) defines those gates.

The source-only release excludes historical benchmark inputs, including
`benchmarks/dependency_cases.json`. The optional external Gradle-oracle workflow
requires a separately reviewed trusted case manifest before it can run; that
workflow is not part of package publication. Its regression tests use newly
authored synthetic inputs to verify recording boundaries. Passing those tests
does not establish a successful external Gradle build or a refreshed oracle
measurement.

The CLI and `apsa tui` remain the available interfaces. The
[desktop app roadmap](DESKTOP_APP_ROADMAP.md) describes a future local wrapper
around the same engine, with isolated sidecar, IPC, lifecycle, signing and
clean-host acceptance requirements. No GUI installer is included in 1.6.3.
