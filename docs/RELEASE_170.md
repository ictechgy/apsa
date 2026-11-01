# APSA 1.7.0

Package version: `1.7.0`. Rule version: `2026.11.01.apsa.170`.

This release follows a review of 1.6.4. It changes CI exit-code semantics,
extends policy waivers and broadens detection. It was developed and checked
against source and fresh synthetic fixtures; no app code was executed and no
device or credential service was contacted.

## Upgrade notes (read before reusing 1.6.x CI settings)

- **Coverage state `limited` and exit codes.** `partial` now means an execution
  gap: something in the stated scope was not examined (a budget, a parse error
  or lossy adaptation, a skipped file, truncated input, online query errors,
  partial runtime evidence). It still makes the audit incomplete (exit 3).
  The new `limited` state means every input was examined but the bounded static
  model abstained on some paths: non-budget native-flow abstentions, the reduced
  Objective-C model, hybrid JS/TS/Dart flow, project-specified Swift SQL sinks
  and unresolved Kotlin imports. `limited` is reported in JSON, Markdown, SARIF,
  CycloneDX, checklists, the TUI, MCP and the Action summary, and exits 0 by
  default. Most real projects that ended with exit 3 under 1.6.x now end with
  0 or 4. `scan --strict-coverage`, `policy evaluate --strict-coverage`, policy
  `strict_coverage = true` and the Action input `strict-coverage: "true"`
  restore the previous strictness. `limited` does not establish absence:
  timeline resolution, follow-up coverage and compare change verification
  still require `checked`.
- **Exit 4 takes precedence over exit 3.** When an audit is incomplete and also
  exceeds a `--fail-on` threshold or a policy threshold, the CLI and the policy
  gate now return 4 (`failed`). The incompleteness reasons are still recorded.
  CI that relied on 3 masking a threshold failure now sees 4.
- **Policy.** New optional fields: `strict_coverage` (default `false`) and, per
  waiver, `severity` and `known_exploited`. A waiver that records `severity`
  stops suppressing its finding when the finding's severity rises above it or
  the finding becomes known exploited; the gate reports this as a
  `waiver-severity-escalated` notice. Waivers without `severity` keep working
  and add a `waiver-severity-unrecorded` notice. Notices are in the gate's new
  `notices` list and never change the gate state or exit code. APSA 1.6.x
  rejects policy files that use the new fields. The decision artifact's
  `policy_sha256` changes for unchanged policy files because the normalized
  policy now includes the `strict_coverage` default. An `only_new` baseline that
  is the evaluated report itself, or was created after it, makes the gate
  incomplete (`baseline-is-report`, `baseline-not-earlier`) instead of passing.
- **Advisory identities.** Dependency advisory findings keep their IDs and now
  list equivalent identities in `advisory_ids` (display ID, grouped OSV IDs and
  aliases, at most 32). Waivers, `only_new` baselines, `reports compare`,
  verification and follow-up match a finding whose display ID changed (for
  example a GHSA advisory that gained a CVE alias) at the same dependency
  location, including against 1.6.4 reports. An alias shared by several
  findings never matches; those findings are reopened. SARIF
  `partialFingerprints` are unchanged.
- **More findings against existing baselines.** Detection is broader (below),
  `QG-APP-EXPORTED` for implicitly exported components is now MEDIUM, library
  KEV entries can raise dependency severity, `MAL-` advisories are critical and
  more source/configuration rules exist. Rescan before approving a baseline.
- **Interfaces.** MCP `reports_compare` returns bounded model context
  (`max_bytes`, excerpts removed) and report-derived MCP responses carry
  untrusted-data instructions; the MCP tool manifest hash changed. Runtime plans
  no longer prefill `open_url` steps from app data. Real devices must be named
  in `scenario.device` (only a single attached emulator is chosen
  automatically), and manipulation steps require a debuggable app. `--out`
  infers the export format from its suffix; a contradicting `--format` exits 2.
  The Action's `fail-on-incomplete` uses the report, and it has a new
  `incomplete` output. Parser isolation warnings are always shown when
  isolation is not enforced. Installed 1.6.4 agent skills report as outdated.

## Detection and correctness

- Source flow: guards no longer leak across `else if`, `switch`/`when` and loop
  bodies; Kotlin string templates, same-class constants and `apply`/`run`/`with`
  implicit receivers are modelled; Swift `if let`/`guard let` bindings and
  bodies are analyzed; `NSUserActivity.webpageURL` and SwiftUI `.onOpenURL`
  are URL sources; archive entry names (`ZipEntry.getName()` and Kotlin
  `ZipInputStream`) are path-traversal sources; one-line Kotlin class bodies
  parse losslessly.
- Swift computed properties, `get`/`set`/`willSet`/`didSet` bodies (including
  SwiftUI `var body`) and Kotlin custom accessors are analyzed. Reads of
  computed properties elsewhere remain abstained.
- Classes extending import-resolved Android/AndroidX framework bases (`Activity`,
  `AppCompatActivity`, `Fragment`, `Service`, `WebViewClient` and others), or
  in-source bases built on them, now credit scheme/host and canonical-path
  guards. SwiftUI `View`/`App`/`Scene` conformances are credited the same way
  when the file's imports are SwiftUI and Apple modules only.
- Source rules: Timber, `Log.wtf`, more `console.*`, `debugPrint` and `os_log`
  logging; `UserDefaults.setValue`, multi-line chains and Objective-C
  `NSUserDefaults` token storage; dot-anchored host suffix checks are no longer
  reported; new `SOURCE-WORLD-ACCESSIBLE-FILE`; lambda hostname verifiers and
  `X509ExtendedTrustManager`; Kotlin `*Activity` subclasses and SQLite
  accessors; Objective-C `@import`; React Navigation route params and sqflite
  `rawDelete`/`execute`; `.xcconfig` credential screening (`.env` remains
  excluded).
- Platform: Info.plist must be sealed for `signed_resources_verified`; IPA ATS
  exception-domain weakening, default-exported providers, user-CA trust on
  targetSdk ≤ 23, cleartext with minSdk < 24, nested domain-config inheritance
  and privacy declarations without reasons are reported. Multi-domain ATS
  evidence is kept and non-string TLS versions no longer crash.
- Intelligence: rejected display aliases no longer drop OSV advisories; KEV is
  matched by alias and stored in full; VEX covers GO-/MAL-/PYSEC- origins;
  several versions at one dependency path merge into one finding's
  `dependency_matches`; Markdown output escapes report text.

## Input robustness

bzip2/LZMA ZIP members, plist shared-reference expansion, malformed manifests,
SARIF ingest regular expressions, UTF-16 DTDs in legacy XML paths and very
large ZIP central directories (up to 20,000 entries / 8 MiB, including binary
analysis) now produce bounded partial results instead of stopping the audit.
Non-ASCII paths work under macOS parser isolation.

## Remaining limits

Analysis remains bounded and partial. Swift memberwise initializers are not
modelled, so SwiftUI views that construct other source views usually report
`limited`. Android framework member-type lists come from the public SDK
surface and were not checked against `android.jar`. Hermes bytecode is not
decoded, and the hybrid engine is not a complete JavaScript/TypeScript/Dart
grammar. Static candidates do not establish runtime reachability or
exploitability. This release does not include a GUI installer.

Publication is performed by the existing immutable-tag workflow after review and
hosted checks. PyPI/MCP/GitHub publication and Linux/macOS public installation
checks are separate gates; a local build alone is not publication.
