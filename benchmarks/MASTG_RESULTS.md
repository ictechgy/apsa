# OWASP MASTG v2.0 demo evaluation

English is the source of truth; see [MASTG_RESULTS.ko.md](MASTG_RESULTS.ko.md).

[`mastg_demos.py`](mastg_demos.py) scores APSA on the demos of the OWASP Mobile
Application Security Testing Guide v2.0.0 (commit `990472d`, archive SHA-256
pinned in the harness) that state an outcome. A demo is labeled by its
`kind: fail|pass` or, when absent, an unambiguous "The test fails/passes"
statement in its Evaluation section. Its test names a MASWE beta identifier,
translated to MASWE v1.0. APSA scans only the demo's original sample sources.
A demo counts as flagged when an APSA finding maps to one of its weaknesses; it
is in scope when APSA has any related check. The method was fixed in the
module docstring before the first run. OWASP's material is CC BY-SA 4.0; only
identifiers and outcomes are stored.

## First result

[Run 37942539599](https://github.com/ictechgy/apsa/actions/runs/37942539599)
on head `60f1fb5`, before any rule was changed for these demos
(`results/2026-10-09-mastg-demos-first.json`):

| Demos | Count |
| --- | ---: |
| Labeled (fail or pass) | 133 |
| In scope: TP / FN | 15 / 53 |
| In scope: TN / FP | 4 / 1 |
| Not assessed (no related APSA check) | 32 |
| No sample source (scripts or dynamic only) | 38 |
| Unlabeled | 14 |
| Strict pairs correct | 0 of 2 |

In-scope recall is 22% (15 of 68) and precision 94% (15 of 16). The only false
positive is a pass demo (MASTG-DEMO-0060) where `STORAGE-TOKEN-PREFS` matches a
token stored with encryption that the pattern cannot see.

## What the misses show

"In scope" only means APSA has some related check; most MASWE weaknesses cover
many modes, and APSA's checks cover few of them. 42 of the 53 misses come from
static-code tests:

| Weakness (platform) | Misses | Typical demo behavior APSA has no rule for |
| --- | ---: | --- |
| MASWE-0002 (Android) | 5 | Writing sensitive data to external or shared storage |
| MASWE-0026 (iOS) | 5 | Cleartext HTTP use and network APIs outside ATS |
| MASWE-0027 (Android 4, iOS 2) | 6 | Custom TrustManager, HostnameVerifier and URLSession trust handling |
| MASWE-0034 (iOS 4, Android 1) | 5 | WebView local file access settings |
| MASWE-0050 (Android) | 4 | Untrusted data handling beyond the modeled SQL and WebView sinks |
| MASWE-0029, 0032, 0035, 0036 | 2 each per platform | Deep links, intents, WebView loading and UI exposure modes |

The 32 not-assessed demos concern weaknesses APSA does not model statically
(key storage and generation, biometrics, resilience). The 38 demos without
sample source rely on scripts, Frida hooks or device output.

These demos are small, single-file illustrations written for the MASTG tests;
they are not production apps, and scores on them do not estimate detection
rates in real apps. Changes made after this run are development work and are
reported separately from this first result.

## Development rerun

This is not a blind result: the rules it measures were added or tuned after
the first run had shown which demos APSA missed, so these numbers describe
development progress on demos already seen. [Run 37947125317](https://github.com/ictechgy/apsa/actions/runs/37947125317)
on head `9f63f84` (`results/2026-10-09-mastg-demos-dev.json`), with the same
pinned archive and unchanged method:

| Demos | First result | Development rerun |
| --- | ---: | ---: |
| In scope: TP / FN | 15 / 53 | 26 / 42 |
| In scope: TN / FP | 4 / 1 | 4 / 1 |
| Not assessed / no sample / unlabeled | 32 / 38 / 14 | 32 / 38 / 14 |
| Strict pairs correct | 0 of 2 | 0 of 2 |

In-scope recall is 38% (26 of 68) and precision 96% (26 of 27). The eleven new
true positives come from checks added for the missed modes: external storage
writes (5 demos), trust-all TrustManager and HostnameVerifier (2), Java
deserialization (1), unevaluated iOS server trust (2) and weakened ATS exception
domains (1). No pass demo became a false positive; MASTG-DEMO-0060 remains the
only one.

One intermediate result is worth recording. MASTG-DEMO-0147 was a true positive
in the first run only because `AST-PENDINGINTENT-MUTABLE` flagged the demo's
explicit Intent with `FLAG_MUTABLE`, which is not the weakness. Once the check
followed Intent variables to where they are built
([run 37946691836](https://github.com/ictechgy/apsa/actions/runs/37946691836), head `7439ce7`),
the demo became a false negative (25 / 43). The check now also treats literal
flags without `FLAG_IMMUTABLE` as mutable, because PendingIntents are mutable by
default before Android 12; the demo's implicit Intents with flags `0` and
`FLAG_UPDATE_CURRENT` are flagged and its explicit and immutable ones are not.

The 1.4.0 runtime candidate `803220d`
([run 37949319562](https://github.com/ictechgy/apsa/actions/runs/37949319562)) produced the same counts
after the PendingIntent check moved to flag bit values.

The remaining 42 misses are mostly modes APSA still has no rule for: iOS
cleartext use outside ATS (MASWE-0026) and WebView file access (0034), untrusted
data beyond the modeled sinks (0050), and intent, deep-link, WebView-loading and
UI-exposure modes (0029, 0032, 0035, 0036).

## 1.5 development rerun

1.5 adds checks for the weaknesses behind most of the misses above. They were
written after these demos had been read, so this is a development rerun on
demos already seen; the blind measurement of 1.5 is the
[MASWE-labeled pair holdout](BLIND_PAIRS_RESULTS.md).
[Run 38028133933](https://github.com/ictechgy/apsa/actions/runs/38028133933) measured the 1.5.0 runtime
`1fac679` (through `47ce760`, `results/2026-10-10-mastg-demos-dev150.json`) with the same pinned
archive and method:

| Demos | 1.4 rerun | 1.5 rerun |
| --- | ---: | ---: |
| In scope: TP / FN | 26 / 42 | 52 / 26 |
| In scope: TN / FP | 4 / 1 | 4 / 1 |
| Not assessed / no sample / unlabeled | 32 / 38 / 14 | 22 / 38 / 14 |
| Strict pairs correct | 0 of 2 | 0 of 2 |

In-scope recall is 67% (52 of 78) and precision 98% (52 of 53). Ten demos moved
into scope because 1.5 relates a check to their weakness. The 26 new true
positives come from: biometric and local authentication (5), hard-coded key
material (3), short RSA keys (2), CommonCrypto broken ciphers and ECB (2), TLS
below 1.2 (2), iOS connections outside ATS (2), and one each for the Android
broken cipher, CryptoKit `Insecure` digests, the network security config's user
CAs, UIWebView, provider SQL through `SQLiteQueryBuilder`, an implicit internal
Intent, path traversal from a provider's display name, keyed unarchiving
without secure coding, App Links without `autoVerify` and Safe Browsing turned
off. MASTG-DEMO-0060 is still the only false positive.

Of the 26 remaining misses, five are JavaScript-bridge and DOM demos that MASTG
files under MASWE-0034 while APSA maps its bridge rules to MASWE-0033; the
others are behaviors APSA has no static rule for (deep-link handlers without
input validation, WebView navigation handlers, UI and keyboard exposure, backup
exclusion, FileProvider grants, permission and purpose strings, PII in traffic,
an `SSLSocket` without host name verification, an asymmetric key used for
several purposes, `rand` reached through `@_silgen_name`, and attacker-side demo
apps).

