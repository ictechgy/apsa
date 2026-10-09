# Independent vulnerable/fixed source pairs

English is the source of truth. [한국어](FPFN_RESULTS.ko.md) ·
[Truth](fpfn_truth.json) · [Evaluation](fpfn_eval.py) ·
[First result JSON](results/2026-10-09-fpfn-first.json).

This evaluation of the APSA 1.3.0 development work (not part of 1.2.0) measures source
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

| Pairs scored | TP | FN | FP | TN | Unscored fixed sides | Line-level TP |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 11 | 5 | 6 | 1 | 9 | 1 | 3 |

The first run reported 10 TN. Code review found that the Wikipedia fixed side
was labeled with a free-text path that no file can match, so that side was
counted as TN without being measured. The frozen truth is unchanged;
[`fpfn_truth_amendments.json`](fpfn_truth_amendments.json) restates the
labeler's own note as the five plist paths, and the harness now marks any
labeled path absent from the source as unscored.

[Run 37916922456](https://github.com/ictechgy/apsa/actions/runs/37916922456)
re-measured all pairs after the review fixes (source identical to head
`e9314bc`, exact path matching, amendment applied): **5 TP, 6 FN, 1 FP and
10 TN with no unscored side**. The Wikipedia fixed side, now measured on its
five plists, is a TN. This rerun is not blind; the first result above stays as
recorded.

| Pair | Expected family | Vulnerable | Fixed |
| --- | --- | --- | --- |
| SMSSync Twitter OAuth `onReceivedSslError` | WebView SSL bypass | TP (line) | TN |
| OpenClaw Android canvas bridge (CVE-2026-35643) | JS bridge | TP (line) | FP |
| Tiddloid editor file-URL access | WebView file access | TP (line) | TN |
| Amaze File Manager `usesCleartextTraffic` | Android cleartext | TP (file) | TN |
| Wikipedia iOS `NSAllowsArbitraryLoads` | iOS ATS | TP (file) | unscored in the first result (path label); TN in the rerun |
| Home Assistant `MyActivity` WebView URL (CVE-2023-41898) | Untrusted WebView URL | FN | TN |
| Element X Android call intent URL (CVE-2025-27599) | Untrusted WebView URL | FN | TN |
| Element X iOS call deep link (CVE-2026-55644) | Untrusted WebView URL | FN | TN |
| Nextcloud Android `FileContentProvider` (CVE-2021-43863) | Raw SQL concatenation | FN | TN |
| Element Android verification event log | Sensitive log | FN | TN |
| OpenClaw iOS relay credentials in `UserDefaults` | Token in preferences | FN | TN |

Both out-of-scope pairs (FairEmail attachment path traversal, Tasks share-link
file copy) produced no findings in their labeled files.

## 1.4 development rerun

[Run 37949344101](https://github.com/ictechgy/apsa/actions/runs/37949344101)
on the 1.4.0 runtime candidate `803220d`, with the same frozen truth and
amendment: **6 TP, 5 FN, 2 FP and 9 TN**, line-level TP 4, no errors or
unscored sides. This is a development rerun on labels already seen, not a new
measurement.

The only changed pair is Nextcloud. 1.4 adds `SQLiteDatabase.delete`,
`update`, `query` and `SQLiteQueryBuilder.appendWhere` as SQL sinks for
caller-supplied arguments of exported content providers, so the vulnerable side
becomes a line-level TP. Its fixed side becomes an FP: the fix
([GHSA-vjp2-f63v-w479](https://github.com/nextcloud/android/security/advisories/GHSA-vjp2-f63v-w479))
keeps the same calls and validates the caller's selection with an SQLite
tokenizer, which APSA does not model as a sanitizer. Like the OpenClaw bridge,
this is a guard-based fix that a call-site rule cannot see.

## Why each miss happened

- **Cross-file flows.** Both Element X pairs move the deep-link URL through a
  parser and navigation layer before the WebView loads it. APSA's untrusted-URL
  rule is function-local. The Element X iOS sink file (`CallScreen.swift`) was
  also only partially parsed, which can hide a local flow.
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

The labeler knew APSA's rule family names and descriptions but not its code or
results. The parser adaptations committed three minutes after the truth were
derived from VLC iOS, Firefox iOS, Signal-iOS and WordPress-iOS parse errors;
none of the labeled pair files was inspected for them.

Eleven scored pairs from ten repositories cannot establish general recall or
precision. The labels come from one research agent. File-level matching can
credit a finding at another line of the same file, which is why line-level
agreement is reported separately. Rule families without a trustworthy public
fix pair (ECB mode, weak hashes, Keychain accessibility, host allowlists,
debuggable builds, Objective-C WebView flow) are not measured here. Scans ran
with the development branch, which also includes the parser adaptations and
dependency evidence described in [NEXT_ANALYSIS.md](../docs/NEXT_ANALYSIS.md)
and [DEPENDENCY_RESULTS.md](DEPENDENCY_RESULTS.md).
