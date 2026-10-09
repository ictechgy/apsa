# Independent vulnerable/fixed source pairs

English is the source of truth. [한국어](FPFN_RESULTS.ko.md) ·
[Truth](fpfn_truth.json) · [Evaluation](fpfn_eval.py) ·
[First result JSON](results/2026-10-09-fpfn-first.json).

This development evaluation (unreleased; not part of APSA 1.2.0) measures source
findings on real security fixes in public Android and iOS apps. It is a narrow
sample, not a production detection rate.

## Method

An independent research agent selected 13 public fixes and labeled, for each,
the vulnerable and fixed commits, the affected file, function and line range,
and the expected APSA rule family: 11 within source rule families and 2 out of
scope. It verified every commit and the changed code through the GitHub API and
did not run or read the scanner. The truth (`fpfn_truth.json`, SHA-256
`229b9070166881b136c765eaa65893dd99b09421464c72d7337b7bce97bf535a`) was
committed in `659d948` before any APSA scan of these sources.

[Run 37911256639](https://github.com/ictechgy/apsa/actions/runs/37911256639)
downloaded each commit from GitHub, extracted it without symlinks and scanned
the labeled file's top-level directory with APSA only (head `10cc402`). A
vulnerable side is a **TP** when an expected rule reports evidence in a labeled
file and an **FN** otherwise; a fixed side is an **FP** when an expected rule
still reports there and a **TN** otherwise. Line-level agreement (within three
lines of the labeled range) is recorded separately. No upstream build, backend
or device ran.

## First result

| Pairs scored | TP | FN | FP | TN | Line-level TP |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 11 | 5 | 6 | 1 | 10 | 3 |

| Pair | Expected family | Vulnerable | Fixed |
| --- | --- | --- | --- |
| SMSSync Twitter OAuth `onReceivedSslError` | WebView SSL bypass | TP (line) | TN |
| OpenClaw Android canvas bridge (CVE-2026-35643) | JS bridge | TP (line) | FP |
| Tiddloid editor file-URL access | WebView file access | TP (line) | TN |
| Amaze File Manager `usesCleartextTraffic` | Android cleartext | TP (file) | TN |
| Wikipedia iOS `NSAllowsArbitraryLoads` | iOS ATS | TP (file) | TN |
| Home Assistant `MyActivity` WebView URL (CVE-2023-41898) | Untrusted WebView URL | FN | TN |
| Element X Android call intent URL (CVE-2025-27599) | Untrusted WebView URL | FN | TN |
| Element X iOS call deep link (CVE-2026-55644) | Untrusted WebView URL | FN | TN |
| Nextcloud Android `FileContentProvider` (CVE-2021-43863) | Raw SQL concatenation | FN | TN |
| Element Android verification event log | Sensitive log | FN | TN |
| OpenClaw iOS relay credentials in `UserDefaults` | Token in preferences | FN | TN |

Both out-of-scope pairs (FairEmail attachment path traversal, Tasks share-link
file copy) produced no findings in their labeled files.

## Why each miss happened

- **Cross-file flows.** Both Element X pairs move the deep-link URL through a
  parser and navigation layer before the WebView loads it. APSA's untrusted-URL
  rule is function-local.
- **Home Assistant.** APSA reported only a substring host check
  (`WEBVIEW-HOST-MATCH`) in the labeled file, not the untrusted load itself.
- **Sink coverage.** The Nextcloud injection reaches `SQLiteDatabase.delete` and
  `SQLiteQueryBuilder.appendWhere`; `AST-SQL-CONCAT` models `rawQuery` and
  `execSQL`.
- **Data shape.** The Element Android leak is a Kotlin template that logged a
  whole event object, and the OpenClaw iOS secret sits in an encoded settings
  struct. Neither has a token- or password-named value for the pattern rules.
- **Guard-based fix.** The OpenClaw Android fix keeps `addJavascriptInterface`
  and adds an origin check, so the bridge candidate remains at the fixed commit.
  The labeler predicted this.

## Limits

Eleven scored pairs from ten repositories cannot establish general recall or
precision. The labels come from one research agent. File-level matching can
credit a finding at another line of the same file, which is why line-level
agreement is reported separately. Rule families without a trustworthy public
fix pair (ECB mode, weak hashes, Keychain accessibility, host allowlists,
debuggable builds, Objective-C WebView flow) are not measured here. Scans ran
with the development branch, which also includes the parser adaptations and
dependency evidence described in [NEXT_ANALYSIS.md](../docs/NEXT_ANALYSIS.md)
and [DEPENDENCY_RESULTS.md](DEPENDENCY_RESULTS.md).
