# Actual execution of the remaining gates

2026-10-11. Validation uses public source and newly generated synthetic inputs
only. No existing user app, device state, media, prompts, history or raw service
logs are inputs. Current evidence root:
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

## Primary tooling evidence

- [Semgrep CE 1.179.0](https://github.com/semgrep/semgrep/releases/tag/v1.179.0)
- [Official bundletool commands](https://developer.android.com/tools/bundletool)
- [Bundletool 1.18.3 immutable asset checksums](https://github.com/google/bundletool/releases/expanded_assets/1.18.3)
- [GitHub source-tree API](https://docs.github.com/en/rest/git/trees#create-a-tree)
