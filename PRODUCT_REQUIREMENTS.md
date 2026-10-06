# APSA (앱사) product requirements

Brand: APSA, pronounced "ap-sah"; Korean name: 앱사. CLI, package and MCP identifiers use `apsa`. Tagline: Evidence-first security audits for Android & iOS.

The release objective is the user's request: **제품으로 낼 수 있을만큼 만들어줘**.
APSA helps app developers and security teams audit their own Android and iOS apps. Source trees and APK/IPA builds are both supported. Models use the same engine through MCP or the reusable skill; model authentication stays with the client.

The distribution assumption is a local application with CLI, TUI, and CI support. The user asked whether local analysis implied a closed-source product; the answer clarified that keeping inspected apps on the host and choosing an open-source license are separate decisions. No public license or external publication has been chosen. A later distribution choice can extend the product scope; it cannot silently remove the requirements below.

## Release requirements

| ID | Required behavior | Acceptance evidence |
| --- | --- | --- |
| R01 | Inspect Java/Kotlin/Swift source structurally and inspect real APK DEX and IPA executable metadata. Deep-link, WebView, authentication, and sensitive storage checks have explicit coverage and evidence. | Vulnerable/fixed pairs and unrelated-code negatives; real APK plus executable IPA fixtures; per-rule supported-language and artifact limitations. |
| R02 | Execute authorized logout/account-switch and deep-link scenarios on Android and iOS test builds, record app identity and state assertions, and distinguish delivery, transition, capture, and canary results. | Reproducible owned fixture builds; live Android and iOS runs with retained and deleted canaries; no cross-app UI claims or missing-baseline passes. |
| R03 | Ingest official vendor advisories, public CVE records, OWASP mobile guidance, KEV, and OSV; preserve branches, revisions and provenance. Reassess unchanged app inventories after updates. | Parser fixtures, malformed/oversized feed failures, retry/backlog tests, live sync and reassessment evidence; missing or stale feeds remain visible. |
| R04 | Bound untrusted file/parser/device work, preserve immutable reports, and give findings stable identities. Failures produce actionable incomplete coverage instead of fabricated passes. | Resource limit, timeout, subprocess, report-integrity and schema migration tests. |
| R05 | Teams can configure a project policy, inspect and triage findings, compare baselines, and gate CI with explicit candidate/confirmed/version-match semantics. | End-to-end policy, waiver expiry, baseline and exit-code tests plus usable CLI/TUI flows. |
| R06 | MCP and the skill expose the same audit evidence across model clients with root restrictions, runtime opt-in, progress/cancellation for long work, and sanitized context. | Protocol tests, unauthorized-root tests, job lifecycle tests and at least one real model-client connection; official configurations for other supported clients. |
| R07 | Users can install a reproducible package, discover local SDKs, diagnose missing capabilities, and follow documented updates and operation. | Clean package install, wheel contents, launch outside the checkout, version/help/doctor, locked CI and release artifacts with dependency attribution. |
| R08 | A release has a documented threat model, supported test matrix and measured rule quality, plus independent code and architecture reviews of the final snapshot. | Accuracy benchmark, live platform evidence, post-cleanup verification and independent APPROVE/CLEAR verdicts bound to exact tree and patch. |

## Architecture invariants

1. An offline scan makes no network requests and never downloads parsers implicitly.
2. CVE version correlation is not an exploit reproduction or an app vulnerability without app applicability evidence. Unpublished zero days cannot be enumerated by public feeds.
3. Candidate, configuration-confirmed, runtime-confirmed, version-affected, inconclusive and not-run results remain distinguishable in every interface.
4. Missing, failed or partial capture cannot become a pass. Runtime findings identify the tested build and the scenario assertion.
5. Inputs remain inside declared roots; archives are never extracted into the source tree; capture and parsing have finite resource budgets.
6. Reports and their provenance are immutable. Reassessment and reruns create child reports and retain previous evidence.
7. Models obtain evidence through MCP/skill. No embedded model API credentials or provider chat layer is added.
8. Device operations are opt-in and restricted to authorized test apps. Raw storage, secrets and canary values are not returned as assistant context.

## Honest scope

Coverage is mapped to OWASP mobile controls and tests individually. This product does not claim complete MASVS certification, an absence of vulnerabilities, or universal device/OS support. These limits do not excuse missing implementation of the release requirements.
