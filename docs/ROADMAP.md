# Release sequence

English is the source for this release plan.

Status on 2026-10-08: [1.0.6](https://github.com/ictechgy/apsa/releases/tag/v1.0.6) and [1.1.0](https://github.com/ictechgy/apsa/releases/tag/v1.1.0) were published in that order. The later stages below remain planned; this status does not declare AAB, embedded binary, Objective-C or OS sandbox support.

1. **1.0.6 — evidence correctness.** Isolated MCP Python fallback, incomplete mixed-language AST and truncated pattern coverage, bounded OS-advisory coverage, declared dependency candidates, and unified CI example. Release only after regression tests and independent snapshot-bound review.
2. **1.1.0 — model and team workflows.** Bounded/paginated model report context, portable integrity-checked baseline artifacts, exported policy decisions, and explicit source app/module selection. Release only after contract, authorization and clean-install validation.
3. **Later milestones — analysis and parser isolation.** AAB protobuf manifests and module/split inventory; embedded IPA executables; Objective-C local-flow analysis; platform OS sandbox with explicit unavailable/failure behavior. Resource limits are not an OS permission sandbox.

The later stages now have development implementations on `hardening/real-app-cve-v1`;
see [scope and limits](NEXT_ANALYSIS.md). They remain outside the published 1.1.0
package until snapshot reviews and hosted validation complete. The historical CVE
catalog, representative production accuracy, full interprocedural analysis, and
physical iOS device tests remain separate work. The current handcrafted corpus is
a regression check, not a production detection-rate claim.

## Stage gates

Publish 1.0.6 before advancing the 1.1 release branch to public main. For each release, freeze the exact source tree, pass the regression/type/format/corpus checks, obtain independent code and architecture verdicts, and verify the supported CI matrix plus repeated package builds and a clean installation. Confirm the PyPI version and immutable GitHub tag; a created tag or successful build alone is not a published package. Preserve a failed publication as an operational failure rather than substituting another version or moving its tag.

1.1 adds section pagination with explicit omissions, independently pinned portable baselines, reviewable policy decision artifacts, and source module/configuration selection. Its baseline approval metadata does not authenticate a reviewer; an externally reviewed artifact hash is required. Its source selection does not merge build variants.

After 1.1 publication, implement the following stages in order. Each gets separate fixtures, coverage states, documentation and independent review before declaring support:

| Stage | Deliverable | Required evidence and failure behavior |
| --- | --- | --- |
| AAB | Protobuf manifest decoding and base/feature/split inventory, with module provenance for code/configuration findings | Compile fresh synthetic base/feature bundles; compare decoded manifest fields with the build tool's output. Corrupt/missing modules, unsupported schemas, duplicate entries and budget exhaustion are explicit failures or partial coverage. A bundle analysis does not prove the exact installed split set. |
| IPA embedded binaries | Enumerate and analyze framework and extension executables separately from the main app | Synthetic signed/unsigned, thin/fat, encrypted and malformed fixtures. Preserve executable hashes and bundle roles; embedded identities cannot replace the main runtime target. Unsupported/encrypted binaries remain partial or not-run, without a hardening pass. |
| Objective-C | Function-scoped local-flow rules for selected URL/WebView/security APIs | Vulnerable, fixed and irrelevant pairs plus malformed/mixed-language fixtures. Findings remain candidates; dynamic dispatch, macros, categories and unmodeled flows keep explicit limits. No interprocedural exploitability claim. |
| OS sandbox | macOS/Linux parser permissions isolated from the caller, with narrow staged input and temporary output access | Fresh synthetic denial probes for network, unrelated file reads/writes and child processes, while required parsers/helpers still run. Record the backend and activation outcome; unavailable or failed activation cannot silently claim sandbox protection. Keep CPU/RSS/time/output limits as a separate boundary. |

Do not run tests against existing user app data. Parser isolation fixtures must use new temporary paths and must not weaken the host project's privacy guard.
