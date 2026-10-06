# Curated static regression benchmark

This directory contains a small, handcrafted corpus with independent labels in
`corpus.json` and reviewable source files in `cases/`. Each record names its
vulnerable, fixed, or irrelevant variant, rationale, expected rule IDs, and
expected `candidate` evidence status. The APK records reference existing real
compiled DEX fixtures and lock their SHA-256 hashes; their source and build
instructions live in `tests/fixtures/binary_analysis/`.

Run with the project's installed environment:

```sh
.venv/bin/python benchmarks/run.py --out .omx/artifacts/static-benchmark.json
.venv/bin/python benchmarks/run.py --case swift-url-fixed
```

The runner invokes the actual `analyze_sources` and `analyze_binary` engines. It
reports JSON per-rule true positives, false positives, false negatives, precision,
recall, and case disagreements. A metric is `null` with an explicit undefined
state when its denominator is zero. An unexpected rule or evidence status, a
missing rule, an analysis warning, incomplete coverage, or changed binary fixture
bytes causes a nonzero exit. Expected and observed labels are compared directly;
the runner does not infer labels from the scanner's output. Input, corpus, and
engine hashes let a release record identify the bytes actually measured.

The sampling unit is a unique **case / rule / evidence-status** label. Multiple
findings of the same rule and status in one case count once. This prevents a
fixture with repeated calls from inflating detection counts. Empty-label cases
exercise false positives. Source cases cover local aliases, exact validation,
bounded subdomain suffixes, navigation allow decisions, certificate handling,
bridge removal, mutations after validation, comments/literals, object types,
unrelated methods, and lexical shadows. Binary cases exercise actual DEX calls,
constant arguments, sensitive-key value flow, and harmless literals/branch joins.

This is a release regression check for selected static evidence patterns. The
source files are parser fixtures, not complete buildable mobile apps. A
"vulnerable" label identifies a risky local pattern for which a candidate is
expected; it does not prove external reachability or exploitation. A "fixed" or
"irrelevant" label means these selected rules should not flag the fixture; it
does not claim that the app satisfies all mobile security controls. The corpus
does not measure runtime authentication, redirects, cross-function taint,
obfuscation, OEM behavior, representative production false-positive rates, or
OWASP certification. Its precision/recall must not be advertised as production
accuracy. Small support counts are visible alongside every metric.

Rationale uses primary platform references:

- [Android unsafe URI loading](https://developer.android.com/privacy-and-security/risks/unsafe-uri-loading)
  describes parsing and checking both scheme and complete hostname, including
  the leading-dot boundary for subdomain suffixes.
- [Android native bridge risks](https://developer.android.com/privacy-and-security/risks/insecure-webview-native-bridges)
  explains why untrusted WebView content and exposed native interfaces need
  separate review, including interface removal.
- [Android SSL error callback](https://developer.android.com/reference/android/webkit/WebViewClient#onReceivedSslError(android.webkit.WebView,%20android.webkit.SslErrorHandler,%20android.net.http.SslError))
  defines certificate-error cancellation behavior.
- [Apple incoming application URL callback](https://developer.apple.com/documentation/uikit/uiapplicationdelegate/application(_:open:options:))
  and [WebKit navigation policy definitions](https://github.com/WebKit/WebKit/blob/main/Source/WebKit/UIProcess/API/Cocoa/WKNavigationDelegate.h)
  establish the modeled URL input and explicit allow/cancel boundaries.

Only the trusted committed corpus should be run directly through this driver.
Adversarial or arbitrary app inputs belong in Mobile Audit's bounded parser
worker, where native parser failures cannot terminate the main scanner.
