# Blind MASWE-labeled vulnerable/fixed pairs (APSA 1.5.0)

English is the source of truth; see [BLIND_PAIRS_RESULTS.ko.md](BLIND_PAIRS_RESULTS.ko.md).

This is the first, blind measurement of APSA 1.5.0 on 24 public vulnerable/fixed
commit pairs from Android and iOS apps and SDKs. The pairs are labeled by
[OWASP MASWE v1.0](https://mas.owasp.org/MASWE/) weakness, not by APSA rule. The
result below is recorded as produced; any later run on this truth is a
development rerun.

## Protocol

- **Curation.** An independent agent chose and labeled the pairs from public
  advisories and security-fix commits, verified every SHA, path and line range
  through the GitHub API, and froze them in
  [`fpfn_truth_holdout2.json`](fpfn_truth_holdout2.json) (sha256
  `c42c9cd345265e8621f5f8d46dce2bc8c0b993ba05f782c97756bc8c8eaae5df`). It did
  not run APSA or read its rules. It reported back only aggregate counts and the
  file hash.
- **Blindness.** The same lead agent coordinated the curator and wrote the 1.5
  rules. It did not open the truth file, its working files or any per-pair
  detail before the first run, and the code and architecture reviewers were told
  not to either. Blindness therefore rests on that attestation, not on a
  structural separation: the truth file was in the author's checkout from its
  commit onward. Future holdouts should keep it out of the author's checkout
  and commit only its hash until the run.
- **Deviation from the published plan.** The 1.4 roadmap said the holdout would
  be frozen before any 1.5 rule was written. In practice the curator worked in
  parallel with rule development (rules `9562717` at 13:04 KST; curation finished
  13:29; truth committed in `be1911b` at 13:33). Six review-driven commits
  followed the freeze (`35d2d88` through `1fac679`); none had access to the
  truth.
- **Measured code.** The run scanned `1fac679`
  (`src` tree `268ae9699b9ac0bdf9068bc091d36f986487ae1c`, package `1.5.0`, rule
  version `2026.10.10.apsa.150` on both sides of every pair) through the commit
  that added its workflow, `47ce760`, which changes no runtime code.
  [Run 38028093532](https://github.com/ictechgy/apsa/actions/runs/38028093532)
  used a clean CI checkout (`worktree_dirty: false`), evaluator sha256
  `af908a0891ad5c283625cc578e0a45a3d6e4167d397c75aa35ef367ccd3b782b`, no
  amendments. The raw result is
  [`results/2026-10-10-blind-holdout2-first.json`](results/2026-10-10-blind-holdout2-first.json).
- **Scoring, declared before the run** (in `fpfn_eval.py`). A side is flagged
  when an APSA finding mapped to one of the pair's weaknesses has evidence in a
  labeled file. The primary recall measure is the line-level TP: a hit within the
  labeled lines (±3). Secondary: the discriminating TP, an in-range hit from a
  rule that has no hit in the fixed side's labeled files. Fixed sides have no
  line ranges, so their FP is file-level and an upper bound. A pair is in scope
  when some APSA source check relates to one of its weaknesses; that is generous
  (any MASWE-0050 pair counts), so in-scope recall is weakness-level, not
  rule-family-level.

## Results

Of 24 pairs, 23 were scored and 1 failed to scan. 21 scored pairs are in scope.
Intervals are Wilson 95%.

| Measure (in-scope pairs) | Count |
| --- | --- |
| Line-level TP (primary) | **7 of 21** (33%, 17–55%); 7 of 22 counting the failed scan as a miss |
| Discriminating TP | 5 of 21 (24%, 11–45%) |
| File-level TP / FN | 9 / 12 |
| Fixed-side FP / TN (upper bound) | 4 / 17 (FP 19%, 8–40%) |

Over all pairs (out-of-scope pairs count as FN): TP 9, FN 14, FP 4, TN 19,
line-level TP 7, discriminating TP 5, 1 error, no unscored sides.

These numbers are not comparable with the [1.3 source pairs](FPFN_RESULTS.md),
which are labeled by expected rule rather than by weakness.

Two of the seven line-level hits come from rules added in 1.5
(`SOURCE-BIOMETRIC-EVENT-BOUND` and `SOURCE-BIOMETRIC-ENROLLMENT`); the other
five come from rules that already existed in 1.4 (PendingIntent mutability,
trust-all TLS, WebView file-origin access, Java deserialization and Swift server
trust). No 1.5 rule produced a fixed-side FP.

## Pairs

| Pair | Platform | MASWE | In scope | Vulnerable | Line | Discriminating | Fixed | Vulnerable-side rules | Fixed-side rules |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [element-android-mainactivity-intent-redirection](https://github.com/element-hq/element-android/security/advisories/GHSA-j6pr-fpc8-q9vm) | android | 0032 | yes | FN | no | no | TN | – | – |
| [nextcloud-android-implicit-mutable-pendingintent](https://github.com/nextcloud/security-advisories/security/advisories/GHSA-5cj3-v98r-2wmq) | android | 0032 | yes | TP | yes | yes | TN | `AST-PENDINGINTENT-MUTABLE` | – |
| [nextcloud-talk-android-share-filename-path-traversal](https://github.com/nextcloud/security-advisories/security/advisories/GHSA-36f7-93f3-mcfj) | android | 0050 | yes | FN | no | no | TN | – | – |
| [nextcloud-talk-android-unprotected-pip-receiver](https://github.com/nextcloud/security-advisories/security/advisories/GHSA-564v-3rfc-352m) | android | 0032, 0018 | yes | TP | no | no | FP | `AST-PENDINGINTENT-MUTABLE` | `AST-PENDINGINTENT-MUTABLE` |
| [capgo-native-biometric-event-only-auth](https://github.com/advisories/GHSA-vx5f-vmr6-32wf) | android | 0020 | yes | TP | yes | yes | TN | `SOURCE-BIOMETRIC-EVENT-BOUND` | – |
| [osmand-open-gpx-deeplink-path-traversal](https://securitylab.github.com/advisories/GHSL-2026-106_OsmAnd/) | android | 0029, 0050 | yes | error | – | – | error | scan refused (input staging budget) | – |
| [mifos-mobile-trust-all-hostname-verifier](https://github.com/openMF/mifos-mobile/security/advisories/GHSA-9657-33wf-rmvx) | android | 0027 | yes | TP | yes | yes | TN | `SOURCE-HOSTNAME-VERIFIER-ALL`, `SOURCE-TRUST-ALL-CERTS` | – |
| [salesforce-android-login-webview-file-url-access](https://github.com/forcedotcom/SalesforceMobileSDK-Android/pull/2546) | android | 0034 | yes | TP | yes | yes | TN | `WEBVIEW-FILE-ACCESS` | – |
| [salesforce-android-login-passcode-no-flag-secure](https://github.com/forcedotcom/SalesforceMobileSDK-Android/pull/1100) | android | 0038 | no | FN | no | no | TN | – | – |
| [freeotp-android-scan-activity-no-flag-secure](https://github.com/freeotp/freeotp-android/pull/125) | android | 0038 | no | FN | no | no | TN | – | – |
| [newpipe-backup-import-objectinputstream](https://github.com/TeamNewPipe/NewPipe/security/advisories/GHSA-wxrm-jhpf-vp6v) | android | 0050 | yes | TP | yes | no | FP | `SOURCE-JAVA-DESERIALIZATION` | `SOURCE-JAVA-DESERIALIZATION` |
| [airmapview-webview-default-file-access](https://github.com/airbnb/AirMapView/pull/72) | android | 0034 | yes | FN | no | no | TN | – | – |
| [stytch-android-pkce-time-seeded-random](https://github.com/stytchauth/stytch-android/pull/145) | android | 0012 | yes | FN | no | no | TN | – | – |
| [keepassdroid-password-generator-java-util-random](https://github.com/bpellin/keepassdroid/pull/62) | android | 0012 | yes | FN | no | no | TN | – | – |
| [home-assistant-ios-url-actions-without-confirmation](https://github.com/home-assistant/core/security/advisories/GHSA-h2jp-7grc-9xpp) | ios | 0029 | yes | FN | no | no | TN | – | – |
| [home-assistant-ios-script-bridge-all-frames](https://github.com/home-assistant/core/security/advisories/GHSA-7jp2-p2fw-mgvf) | ios | 0033 | yes | TP | no | no | FP | `WEBVIEW-JS-BRIDGE` | `WEBVIEW-JS-BRIDGE` |
| [cryptomator-ios-keychain-biometry-any](https://github.com/cryptomator/ios/security/advisories/GHSA-fmh3-xfw7-38cj) | ios | 0022 | yes | TP | yes | yes | TN | `SOURCE-BIOMETRIC-ENROLLMENT` | – |
| [cryptomator-ios-cache-in-icloud-backup](https://github.com/cryptomator/ios/security/advisories/GHSA-385v-vfgq-jxc9) | ios | 0006 | yes | FN | no | no | TN | – | – |
| [salesforce-ios-push-secret-rsa-pkcs1-fallback](https://github.com/forcedotcom/SalesforceMobileSDK-iOS/pull/4127) | ios | 0007 | yes | FN | no | no | TN | – | – |
| [zipfoundation-uncontained-symlink-extraction](https://github.com/advisories/GHSA-c2cc-3569-6jh2) | ios | 0050 | yes | FN | no | no | TN | – | – |
| [afnetworking-default-policy-no-domain-validation](https://nvd.nist.gov/vuln/detail/CVE-2015-3996) | ios | 0027 | yes | FN | no | no | TN | – | – |
| [vlc-ios-openurl-before-passcode](https://nvd.nist.gov/vuln/detail/CVE-2018-19937) | ios | 0020 | yes | FN | no | no | TN | – | – |
| [telnyx-ios-sdk-self-signed-certs-accepted](https://github.com/team-telnyx/telnyx-webrtc-ios/pull/361) | ios | 0027 | yes | TP | yes | no | FP | `SWIFT-SERVER-TRUST-ACCEPTED` | `SWIFT-SERVER-TRUST-ACCEPTED` |
| [brave-ios-opensearch-insecure-template-urls](https://github.com/brave/brave-ios/pull/7721) | ios | 0026 | yes | FN | no | no | TN | – | – |

## Why pairs were missed

- **Flow across functions (2).** In Element Android the nested Intent is passed
  to a helper that calls `startActivity`; in Nextcloud Talk the provider's
  display name is read in one function and used as a file name in another.
  APSA's flow analysis stays within one function.
- **A control that was never added (5).** Two screens without `FLAG_SECURE`
  (MASWE-0038, which APSA does not check), a WebView left with default file and
  content access, a decrypted cache not excluded from iCloud backup, and URL
  actions without user confirmation. APSA reports settings that are present, not
  controls that are absent.
- **No rule for the API (3).** An RSA PKCS#1 v1.5 decryption fallback
  (`kSecKeyAlgorithmRSAEncryptionPKCS1`), server trust evaluated with
  `SecPolicyCreateBasicX509` (no host name), and a symlink entry extracted
  without a containment check.
- **The insecure-random heuristic (2).** `SOURCE-INSECURE-RANDOM` reports a weak
  generator only when its value is assigned to a security-named variable in one
  statement; a generator object that is created once and then used to build a
  password or a PKCE verifier is missed.
- **Order and intent (2).** URL handling before the passcode check (VLC) and
  accepting http OpenSearch templates (Brave) need behavioral reasoning.
- **Failed scan (1).** OsmAnd's app folder has 71 MB of text input, 53 MB of it
  translation XML, which exceeds the 64 MB input staging budget; APSA refuses
  such an audit instead of returning a partial one.

## Why fixed sides were flagged

All four FPs are fixes that keep the related API behind a guard APSA does not
model: a Java `ObjectInputStream` subclass with a class allowlist (NewPipe), a
`#if DEBUG` branch that still accepts self-signed certificates (Telnyx), a
script message handler that now checks the frame and origin (Home Assistant),
and a receiver now protected by a permission in a file that also builds a
mutable PendingIntent (Nextcloud Talk). The last pair's vulnerable-side "TP" is
the same unrelated PendingIntent and is not a line-level hit.

## Limits

24 pairs give wide intervals, and the in-scope definition is weakness-level.
Seven pairs label a missing control, which a pattern or local-flow analyzer
rarely sees. Nine pairs are SDK or library code. The truth was curated by a
model-based agent from public sources; labels were checked against the code at
both commits but not by a second human reviewer.
