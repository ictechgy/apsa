# APSA 1.6.2

This patch fixes six correctness issues found during another review of the
analysis, verification, dependency, job and report paths.

- Objective-C local and parameter names belong to their lexical scope. An
  unrelated function no longer suppresses imported CommonCrypto or WebKit
  candidates. Actual local shadows, globals and macros remain conservative;
  syntactic identity does not establish runtime dispatch or exploitability.
- Legacy/default small-inventory OSV queries retain fully validated earlier
  pages when a later page fails. A malformed page contributes no partial prefix.
  The result remains partial and unchecked, retains prior cached matches and
  preserves the error. A later complete snapshot can replace that partial state.
- An exact APSA rule claim cannot be corroborated by a sibling rule under the
  same MASWE category. Precise CWE claims use explicit correspondences for
  [path traversal (CWE-22)](https://cwe.mitre.org/data/definitions/22.html),
  [SQL injection (CWE-89)](https://cwe.mitre.org/data/definitions/89.html),
  [certificate validation (CWE-295)](https://cwe.mitre.org/data/definitions/295.html) and
  [untrusted deserialization (CWE-502)](https://cwe.mitre.org/data/definitions/502.html).
  Other CWE claims return `not-assessed`; the broader MASWE relationship is not
  sufficient evidence. Supplying both a rule and weakness constrains both.
  This deliberately reduces unsupported corroboration from older releases.
- Verification aggregates all relevant coverage entries that are present.
  A mixture of checked and unexecuted checks is `partial`, not `not-observed`.
  Not-applicable entries remain neutral; absent optional checks are not invented.
  Exact configuration claims retain their shared configuration coverage without
  accepting a sibling rule's finding as corroboration.
- Background runtime jobs observe cooperative cancellation before subsequent
  device actions, individual capture surfaces, screenshots and report saving.
  Wait steps check at intervals of at most 100 ms. An operation already executing
  can finish before the next checkpoint; this does not promise instantaneous
  interruption or reversal of an action/report commit already in progress.
- APK-set aggregation preserves a finding's semantic `origin` while rebasing
  actual evidence, dependency and archive paths to the selected APK member.

Package and rule versions advance to `1.6.2` and `2026.10.22.apsa.162`.
No dependencies or public MCP tools are added. Existing report snapshots and
approved policy baselines are not rewritten. Source, mock HTTP, in-memory or new
temporary databases and newly generated APK sets supply regression evidence;
runtime cancellation tests use synthetic adapters rather than live devices.

The supported CI matrix, package rebuild/installation gates and public
Linux/macOS checks establish publication separately from source review.
See [PUBLISHING.md](PUBLISHING.md).
