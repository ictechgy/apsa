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
