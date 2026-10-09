# Release sequence

English is the source for this release plan.

Status on 2026-10-09: [1.0.6](https://github.com/ictechgy/apsa/releases/tag/v1.0.6) and [1.1.0](https://github.com/ictechgy/apsa/releases/tag/v1.1.0) were published in that order. [1.2.0](https://github.com/ictechgy/apsa/releases/tag/v1.2.0) was then published with bounded, partial implementations of the analysis and parser-isolation stages, confirmed by its tag-context release workflow, the PyPI release and the GitHub release downloads. [1.3.0](https://github.com/ictechgy/apsa/releases/tag/v1.3.0) was then published with bounded dependency-evidence and analysis-depth work, confirmed the same way.

1. **1.0.6 — evidence correctness.** Isolated MCP Python fallback, incomplete mixed-language AST and truncated pattern coverage, bounded OS-advisory coverage, declared dependency candidates, and unified CI example. Release only after regression tests and independent snapshot-bound review.
2. **1.1.0 — model and team workflows.** Bounded/paginated model report context, portable integrity-checked baseline artifacts, exported policy decisions, and explicit source app/module selection. Release only after contract, authorization and clean-install validation.
3. **1.2.0 — bounded analysis and parser isolation.** AAB protobuf base manifest and module DEX inventory; embedded IPA executable metadata; Objective-C `.m` local candidates; platform OS sandbox with explicit unavailable/failure behavior. Resource limits are not an OS permission sandbox. See [scope and limits](NEXT_ANALYSIS.md) and the [independent holdout](../benchmarks/NEXT_RESULTS.md).
4. **1.3.0 — dependency evidence and analysis depth.** Gradle catalog usage and application-lockfile coordinates measured against Gradle's own resolution on three frozen holdouts; independent vulnerable/fixed source pairs with truth frozen before scanning; AAB feature-module manifests; Mach-O CodeDirectory page/entitlement hashes without signature authentication; bounded Swift/Objective-C adaptations; explicit Android bulletin backfill with SoC vendor and vendor patch level. See [scope and limits](NEXT_ANALYSIS.md#apsa-130-additions), [dependency results](../benchmarks/DEPENDENCY_RESULTS.md) and [source pairs](../benchmarks/FPFN_RESULTS.md).
5. **1.4.0 — adoption and agent distribution.** GitHub Action with code-scanning SARIF (stable fingerprints, security severity, MASWE tags, coverage notifications, repository-relative locations); OWASP MASWE v1.0 coverage matrix in every report; MCP Registry metadata published by the tag workflow, a Claude Code plugin marketplace, and a documented MCP security model with a pinned tool manifest hash.
6. **Later milestones.** OSV batch querying for large lockfiles; Gradle `projectDir` remapping; AAB resource and device split merging; IPA signature authentication, CodeDirectory scatter and native flow; `NS_ASSUME_NONNULL_BEGIN`, dynamic dispatch and `.mm`; Apple and vendor bulletin history and amendments; authorized physical-device evidence.

The historical CVE catalog, representative production accuracy, full
interprocedural analysis, and physical iOS device tests remain separate work.
The current handcrafted corpus is a regression check, not a production
detection-rate claim.

## Stage gates

Publish 1.0.6 before advancing the 1.1 release branch to public main. For each release, freeze the exact source tree, pass the regression/type/format/corpus checks, obtain independent code and architecture verdicts, and verify the supported CI matrix plus repeated package builds and a clean installation. Confirm the PyPI version and immutable GitHub tag; a created tag or successful build alone is not a published package. Preserve a failed publication as an operational failure rather than substituting another version or moving its tag.

1.1 adds section pagination with explicit omissions, independently pinned portable baselines, reviewable policy decision artifacts, and source module/configuration selection. Its baseline approval metadata does not authenticate a reviewer; an externally reviewed artifact hash is required. Its source selection does not merge build variants.

After 1.1 publication, the following stages were implemented in order for 1.2.0 in bounded, partial form. [NEXT_ANALYSIS.md](NEXT_ANALYSIS.md) and [NEXT_RESULTS.md](../benchmarks/NEXT_RESULTS.md) record which gate evidence 1.2.0 meets; for example, the compiled AAB check used a fresh base-only bundle, not base/feature bundles. The table remains the gate for extending each stage:

| Stage | Deliverable | Required evidence and failure behavior |
| --- | --- | --- |
| AAB | Protobuf manifest decoding and base/feature/split inventory, with module provenance for code/configuration findings | Compile fresh synthetic base/feature bundles; compare decoded manifest fields with the build tool's output. Corrupt/missing modules, unsupported schemas, duplicate entries and budget exhaustion are explicit failures or partial coverage. A bundle analysis does not prove the exact installed split set. |
| IPA embedded binaries | Enumerate and analyze framework and extension executables separately from the main app | Synthetic signed/unsigned, thin/fat, encrypted and malformed fixtures. Preserve executable hashes and bundle roles; embedded identities cannot replace the main runtime target. Unsupported/encrypted binaries remain partial or not-run, without a hardening pass. |
| Objective-C | Function-scoped local-flow rules for selected URL/WebView/security APIs | Vulnerable, fixed and irrelevant pairs plus malformed/mixed-language fixtures. Findings remain candidates; dynamic dispatch, macros, categories and unmodeled flows keep explicit limits. No interprocedural exploitability claim. |
| OS sandbox | macOS/Linux parser permissions isolated from the caller, with narrow staged input and temporary output access | Fresh synthetic denial probes for network, unrelated file reads/writes and child processes, while required parsers/helpers still run. Record the backend and activation outcome; unavailable or failed activation cannot silently claim sandbox protection. Keep CPU/RSS/time/output limits as a separate boundary. |

Do not run tests against existing user app data. Parser isolation fixtures must use new temporary paths and must not weaken the host project's privacy guard.
