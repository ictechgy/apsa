# External review strengthening

These changes are an unreleased source candidate following the 2026-10-12
Claude and Devin reviews. Agy did not return a valid review. The reviews covered
47 selected changed files and six contracts; final source review covers the
complete working-tree patch. Source review, current-head CI, runtime acquisition,
release approval and published MCP baseline approval have separate evidence.

## Implemented contracts

- [Device specification](DEVICE_SPEC.md): bounded bundletool 1.18.3 metadata
  interoperability preserves validated input for tool execution while reports
  expose sanitized provenance. Unknown targeting fields and preview SDKs still
  fail closed.
- [Analysis limits](ANALYSIS_LIMITS.md): stable per-file/call partial reasons,
  conservative rule coverage, recognized Metro text bundles, and name/header
  evidence for unavailable Hermes or Flutter compiled analysis. Parent staging
  carries bounded name-only observations to the parser; omitted compiled
  content does not become analyzed source. Xcode test-directory scheduling is
  a conservative heuristic, not a complete target-graph interpretation.
- [Benchmark metrics](BENCHMARK_METRICS.md): measured scope, coverage states,
  completed-case and end-to-end denominators, and partial/unmeasured alert
  counters are explicit. Core reports and standalone Action summaries share
  the same completeness predicate. Historical competitor measurements are
  not rerun evidence for this candidate.
- [Signature evidence](SIGNATURE_EVIDENCE.md): explicit anchor-chain scope and
  verification-time basis accompany the legacy chain flag. Every observed
  CodeDirectory has a binding state; unbound alternates keep aggregate integrity
  partial. Apple signer identity, purpose policy and current revocation are not
  established by an offline supplied-anchor chain.
- [Package contents](PACKAGE_CONTENTS.md): newly built wheel/sdist payloads must
  match the clean source manifest and package declarations, including wheel
  RECORD membership, hashes and sizes. Synthetic acquisition adapters live in
  `tests/support`, outside installed public packages. Public Python payloads
  must not contain absolute developer-home paths.
- [Report comparison](REPORT_COMPARISON.md): strict target scope remains the
  default. Explicit portable comparison permits relocation only for identical,
  complete canonical source fingerprints and unchanged analysis scope. Runtime
  build/scenario/assertion pairing remains strict; disappearance is not proof
  of remediation.
- [Compiled fixture configuration](../tests/fixtures/runtime/COMPILED.md):
  test-only builders/acquirers take explicit tool/runtime configuration and
  retain command/output digests instead of raw process journals. Simulator
  acquisition uses only its newly created custom device set and exact UUID.

## Evidence limits

Validation uses public source and newly generated synthetic fixtures outside
the checkout. Local guarded process inspection refuses some resource-limited
parser subprocesses; those executions remain unverified locally. The guard
also denies an MCP SDK dependency directory named `prompts`. Source-derived
manifest expectations do not replace actual served SDK validation on CI.

Final complete-patch review and exact-head CI results are recorded in the
workspace strengthening report. Existing main, published 1.5.1 artifacts and
published MCP manifest hashes are not updated by this work. Genuine local
device/certificate evidence stays outside review packets and CI uploads.
