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
  model abstained on some paths: precision native-flow reasons, the reduced
  Objective-C model (`OBJC-*` rules), hybrid JS/TS/Dart flow, project-specified
  Swift SQL sinks and unresolved Kotlin imports. `limited` is reported in JSON,
  Markdown, SARIF, CycloneDX, checklists, the TUI, MCP and the Action summary,
  and exits 0 by default. Many projects that ended with exit 3 under 1.6.x now
  end with 0 or 4; Swift apps that also contain Objective-C sources, and
  projects whose sources are partly examined by a rule (see below), stay at
  exit 3 as in 1.6.4. `scan --strict-coverage`, `policy evaluate
  --strict-coverage`, policy `strict_coverage = true` and the Action input
  `strict-coverage: "true"` restore the previous strictness. Without strict
  coverage, `limited` also satisfies policy `required_rules`. `limited` does not
  establish absence: timeline resolution, follow-up coverage and compare change
  verification still require `checked`.
- **Native-flow reason kinds.** Every native-flow reason has an explicit kind
  (`budget` or `precision`, listed in `partial_details`) instead of being
  classified by the word "budget". A value the model abstained on (for example
  `constructor field mapping unavailable`) that later reaches a call records
  `source trace abstention` and stays `limited`. Origins dropped by the trace
  cap, including at a sink, record `source trace budget` and stay `partial`;
  evidence source kinds carry `[native-flow-partial]` for a budget cut and
  `[native-flow-limited]` for an abstention. Field summaries that stop
  converging while their contents no longer change record `field summary fixed
  point unresolved` (`limited`); `field summary fixed-point budget` means the
  contents were still changing at the round cap and stays `partial`.
- **Objective-C coverage.** `AST-*` rules never examine Objective-C (`.m`) or
  Objective-C++ (`.mm`). Beside Java, Kotlin or Swift sources they are
  `partial` (exit 3), as in 1.6.4; Android-only `AST-*` rules are not affected
  by those files. For Objective-C-only sources the `AST-*` rules are `not-run`
  and the `OBJC-*` rules are `limited`. An Objective-C method inside
  `#if`/`#ifdef`/`#elif`/`#else`, any `.mm` file, or an Objective-C file dropped
  before analysis leaves the `OBJC-*` rules `partial`, so a `.mm`-only project
  now exits 3. Functions hidden by unexpanded macros remain a precision limit
  (`limited`, `function_inventory_complete: false`).
- **Kotlin or Java with Swift.** `AST-CRYPTO-ECB`, `AST-CRYPTO-WEAK-CIPHER` and
  `AST-SQL-CONCAT` have no Swift model. In projects that mix Kotlin or Java
  with Swift (Kotlin Multiplatform, or Android and iOS apps in one repository)
  they are now `limited` with a note instead of `checked`: exit 0 by default, 3
  under strict coverage. Without strict coverage, `limited` also satisfies
  policy `required_rules` for them, although the Swift sources were checked by
  these rules only for project-declared SQL sinks. In such mixed projects any
  execution gap keeps them `partial`. Swift-only projects keep `not-run`, except
  `AST-SQL-CONCAT`, which is `limited` when the project declares SQL sinks.
- **Dropped sources.** When every recognized source file is dropped before
  parsing (byte or node budget, unavailable grammar, parser failure), the
  `AST-*` rules are `partial` (exit 3) instead of `not-run`. A `skipped` source
  file row also counts as incomplete.
- **Exit 4 takes precedence over exit 3.** When an audit is incomplete and also
  exceeds a `--fail-on` threshold or a policy threshold, the CLI and the policy
  gate now return 4 (`failed`), and the JSON envelope keeps `ok: true`. The
  incompleteness is still recorded in `summary.incomplete` and the gate's
  `partial-audit` reason. CI that relied on 3 masking a threshold failure now
  sees 4.
- **Policy.** New optional fields: `strict_coverage` (default `false`) and, per
  waiver, `severity` and `known_exploited`. A waiver that records `severity`
  stops suppressing its finding when the finding's severity rises above it or
  the finding becomes known exploited; the gate reports this as a
  `waiver-severity-escalated` notice. Waivers without `severity` keep working
  and add a `waiver-severity-unrecorded` notice. When several active waivers
  match one finding, any escalated one reopens it. Notices are in the gate's
  new `notices` list and never change the gate state or exit code. APSA 1.6.x
  rejects policy files that use the new fields. The decision artifact's
  `policy_sha256` changes for unchanged policy files because the normalized
  policy now includes the `strict_coverage` default. An `only_new` baseline that
  is the evaluated report itself, or was created after it, makes the gate
  incomplete (`baseline-is-report`, `baseline-not-earlier`) instead of passing.
  Report `created` times without a UTC offset are read as UTC for this check.
- **Advisory identities.** Dependency advisory findings keep their IDs and now
  list equivalent identities in `advisory_ids` (display ID, grouped OSV IDs and
  aliases, at most 32). Waivers, `only_new` baselines, `reports compare`,
  verification and follow-up match a finding whose display ID changed (for
  example a GHSA advisory that gained a CVE alias) at the same dependency
  location, including against 1.6.4 reports. An alias matches two findings
  only through a display ID: the earlier display ID is among the later
  finding's `advisory_ids`, or the reverse. Findings that share only another
  alias (for example one PYSEC or GHSA record listing several CVEs) are
  different findings, and a 1.6.4 waiver or baseline finding matches only a
  finding that lists its display ID. The match is also one-to-one: a finding
  that matches under its own ID gains no alias match, and an alias that reaches
  several earlier findings or waivers (for example merged advisories), or an
  earlier finding or waiver that several findings reach, matches nothing. Those
  findings are reopened, no longer waived, or listed by `reports compare` as
  added and no longer observed. SARIF `partialFingerprints` are unchanged.
- **More findings against existing baselines.** Detection is broader (below),
  `QG-APP-EXPORTED` for implicitly exported components is now MEDIUM, library
  KEV entries can raise dependency severity, `MAL-` advisories are critical and
  more source/configuration rules exist. Rescan before approving a baseline.
- **Interfaces.** MCP `reports_compare` returns bounded model context
  (`max_bytes`, excerpts removed): changed coverage entries and, with
  `verification=true`, finding transitions and runtime pairs are bounded and
  counted in `coverage_counts`, `verification_counts` and `omitted`, and
  oversized metadata is reduced to identities and pairing state
  (`metadata_truncated: true`) rather than failing. Report-derived MCP responses
  carry untrusted-data instructions; the MCP tool manifest hash changed. Runtime
  plans no longer prefill `open_url` steps from app data. Real devices must be
  named in `scenario.device` (only a single attached emulator is chosen
  automatically), and manipulation steps require a debuggable app. `--out`
  infers the export format from its suffix; a contradicting `--format` exits 2,
  and `--format` without `--out` still writes nothing, now with a stderr warning.
  The Action's `fail-on-incomplete` uses the report, and it has a new
  `incomplete` output; both honor policy `strict_coverage` as well as the
  `strict-coverage` input, a `partial-audit` gate reason counts as incomplete
  even with exit 4, and an exit-3 run is summarized as incomplete rather than as
  an execution error. Parser isolation warnings are always shown when isolation
  is not enforced. Installed 1.6.4 agent skills report as outdated.

## Detection and correctness

- Source flow: guards no longer leak across `else if`, `switch`/`when` and loop
  bodies; Kotlin string templates, same-class constants and `apply`/`run`/`with`
  implicit receivers are modelled; Swift `if`/`guard` condition clauses are
  analyzed in source order, so checks after `if let`/`guard let` credit the
  bound value, chained, typed, shorthand and `case` bindings and sinks in
  `guard` else bodies are followed, a shadowing `if let` no longer credits the
  outer variable, and `AST-WEBVIEW-HOST-ALLOWLIST` reads every clause of a
  navigation-policy condition; a Swift `guard` always guards the statements
  after it (including else bodies ending in `fatalError()`,
  `preconditionFailure()`, `continue` or `break`), and field and object stores
  in a `guard` else body are kept as possible effects for other methods;
  Kotlin `init` blocks and secondary constructors and Swift `init`/`deinit`
  bodies are analyzed and counted as functions (they were skipped without a
  coverage gap), while initializers of local or anonymous classes stay part of
  their enclosing function; early exits in Java constructors guard later
  statements; a receiverless `openDatabase`/`openOrCreateDatabase` that the
  native flow's own call resolution maps to project code is always followed as
  project code, and its result is typed as the framework `SQLiteDatabase` when
  the target is an override or is declared to return `SQLiteDatabase`, or when
  it is shaped like `Context.openOrCreateDatabase(String, int, factory[,
  handler])` and an implicit receiver in scope (an enclosing class, extension or
  scope-function receiver) is a Context whose inherited member wins, or may be
  one while the project function's return type is unknown;
  `NSUserActivity.webpageURL` and SwiftUI `.onOpenURL`
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
  reported unless the suffix is a bare top-level domain, a common country
  second-level suffix (such as `.co.uk`) or a shared-hosting suffix
  (`.github.io`, `.web.app`, `.herokuapp.com`, `*.amazonaws.com`, provider
  zones such as `.a.run.app` or `.<region>.r.appspot.com`, Google Cloud and
  Firebase Storage, Azure static web and Front Door, Cloudflare R2 and
  similar), which the AST engine also no longer accepts as a host allowlist; new
  `SOURCE-WORLD-ACCESSIBLE-FILE`; lambda hostname verifiers and
  `X509ExtendedTrustManager`; Kotlin `*Activity` subclasses and SQLite
  accessors; Objective-C `@import`; React Navigation route params and sqflite
  `rawDelete`/`execute`; `.xcconfig` credential screening (`.env` remains
  excluded).
- Platform: Info.plist must be sealed for `signed_resources_verified`; IPA ATS
  exception-domain weakening, default-exported providers, user-CA trust on
  targetSdk ≤ 23, cleartext with minSdk < 24, nested domain-config inheritance
  and privacy declarations without reasons are reported. Multi-domain ATS
  evidence is kept under the 1.6.4 finding ID (one per Info.plist) and
  non-string TLS versions no longer crash. QuayGate `app-cleartext`
  (`QG-APP-CLEARTEXT`) with a network security configuration reports
  cleartext for older devices as medium whatever the targetSdk: below minSdk
  24 when `usesCleartextTraffic` is not declared (API 23 and lower ignore the
  configuration), and below minSdk 23 even when it is `false` (API 21-22
  ignore the attribute as well), with the remediation to raise minSdk to 23
  or 24.
- Intelligence: rejected display aliases no longer drop OSV advisories; KEV is
  matched by alias and stored in full; VEX covers GO-/MAL-/PYSEC- origins;
  several versions at one dependency path merge into one finding's
  `dependency_matches`; Markdown output escapes report text and fences
  evidence, coverage, environment-advisory and intelligence JSON with a
  backtick run longer than any inside it, escaping line/paragraph separators
  and C1/bidi controls in that JSON.

## Input robustness

bzip2/LZMA ZIP members, plist shared-reference expansion, malformed manifests,
SARIF ingest regular expressions, UTF-16 DTDs in legacy XML paths and very
large ZIP central directories (up to 20,000 entries / 8 MiB, including binary
analysis) now produce bounded partial results instead of stopping the audit.
Non-ASCII paths work under macOS parser isolation.

APK, AAB, IPA, ZIP and APK-set inputs, including each selected APK of an
`.apks`, are refused before ZIP entries are allocated when the central
directory exceeds the entry or byte budget, or when no end record lies within
the last 64 KiB + 22 bytes (the widest window a supported CPython searches).

SARIF ingest redacts credential-like assignments in linear time, with unchanged
output. `STORAGE-TOKEN-PREFS` scans in linear time: a `UserDefaults` chain is
followed for up to four continuation lines of up to 200 characters, and the
credential word must appear within 200 characters after the setter.

## Remaining limits

Analysis remains bounded and partial. Swift memberwise initializers are not
modelled, so SwiftUI views that construct other source views usually report
`limited`. Android framework member-type lists come from the public SDK surface
and were not checked against `android.jar`. SARIF `executionSuccessful` stays
`true` for `limited` coverage; the limitation is reported as a notification.
Some URL sources (`URLContexts.first`), Swift `&&` conditions (the comma form is
credited) and negated early-return host checks are not credited as guards, so
guarded code there can still be reported. The shared-hosting and second-level
suffix lists are curated rather than the full public suffix list. A few
owner-specific provider hostnames that look like provider zones (an App Service
name ending in `-NN`, a default Static Web Apps or legacy Elastic Beanstalk
host) are reported conservatively. Constructor calls such as `Foo(x)` do not
pass their arguments into Kotlin or Swift initializer bodies, and Kotlin
class-level property initializers are not analyzed. Native field summaries can
accumulate duplicate traces of one source with re-derived origins, so whether
non-convergence is reported as `limited` (`field summary fixed point
unresolved`) or as a `partial` budget gap can depend on the round cap. A trace
cap that is hit is always a budget gap; a round cap that is hit is a budget gap
unless the field contents stopped changing in the last round. QuayGate checks
legacy devices separately only when a network security configuration is
referenced; without one, cleartext is judged by the manifest value and the
targetSdk default, although devices below API 28 permit cleartext by default and
API 21-22 ignore an explicit `false`. Hermes bytecode is not decoded, and the
hybrid engine is not a complete JavaScript/TypeScript/Dart grammar. Static
candidates do not establish runtime reachability or exploitability. This release
does not include a GUI installer.

Publication is performed by the existing immutable-tag workflow after review and
hosted checks. PyPI/MCP/GitHub publication and Linux/macOS public installation
checks are separate gates; a local build alone is not publication.
