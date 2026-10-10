# GitHub 공개 소스 — 2026-10-06

## APSA 1.5.1 large inputs — candidate, 2026-10-10

1.5.1 is a patch on 1.5.0, developed on `dev/large-input`. Upgrade effects are listed in the README ("Upgrading from 1.5.0").

- **Large source trees are audited partially, not refused.** 1.5.0 refused a tree over the 64 MiB or 12,000-file text staging budget; OsmAnd's app folder, with 71 MB of text, was the failed scan in the blind run.
  - Files are now staged by kind:
    1. app code and configuration: configuration, then native code, then JS/TS/Dart, then headers, vendored code and `assets/`;
    2. other shipped text;
    3. localized or qualified Android values;
    4. tests.
  - `inventory.input_snapshot.omitted` counts what was left out.
  - `app_scope_complete` is false when code, configuration or shipped text was left out. Not-applicable coverage then becomes partial, so required rules cannot pass.
  - The following now leave files out with one warning per cause instead of refusing:
    - the entry budget (100,000, cut by name on every filesystem) and the depth budget (64);
    - oversized and unreadable files;
    - copy errors;
    - files replaced after listing.
  - SARIF carries a staging notification and `inputSnapshot`; MCP context carries `input.input_snapshot`.
- **Translation slowdown fixed.** 1.5.0 cleaned XML with the source comment stripper, whose character-literal pattern backtracked quadratically on `strings.xml` prose with escaped apostrophes: 9 s for 172 KiB, and about 150 s for 694 KiB, past the 90 s parser timeout.
  - XML now strips only `<!-- -->`.
  - The source cleaner ends every unterminated token in linear time and keeps a stray quote or `/*` as text, as 1.5.0 did.
  - It reads `'''` and `"""` strings as literals, including Kotlin raw strings that end in quotes.
- **AST budget:** within the 32 MiB budget, tests are analyzed after shipped code.

The evaluated runtime is public `a76fd9f19b303a457474199fad9510b334174478` (`src` tree `d194441e12df9f3f8cb2d2237321eabc549d9320`, package/rule version `1.5.1` / `2026.10.10.apsa.151`). Its [CI 38048775936](https://github.com/ictechgy/apsa/actions/runs/38048775936) passed all eleven jobs on the second attempt. The first attempt failed one job (macos-15, Python 3.12): `test_parser_depth` reached the parser's 250 ms native parse deadline on the runner. The change does not touch that path, and the same test passed in the other ten jobs and on the previous commit's [CI 38048342242](https://github.com/ictechgy/apsa/actions/runs/38048342242). Later commits may change only documentation and recorded results. The tag must leave `src`, `apsa`, `quaygate`, `pyproject.toml`, `uv.lock`, `requirements-release.txt`, `action.yml`, `server.json`, `plugins` and `.claude-plugin` identical to `a76fd9f`.

Every evaluation harness was re-run on this runtime (`benchmarks/results/2026-10-10-release-151-harnesses.json`). These are development reruns on truth already seen.

| Harness | Run | Result |
| --- | --- | --- |
| Gradle oracle comparison, three holdouts | [38048775788](https://github.com/ictechgy/apsa/actions/runs/38048775788) | Identical to `dependency-final-head.json` |
| Frozen six-app replay | [38048777665](https://github.com/ictechgy/apsa/actions/runs/38048777665) | 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions; selected app CVE 1 TP / 3 TN |
| Independent vulnerable/fixed source pairs | [38048779572](https://github.com/ictechgy/apsa/actions/runs/38048779572) | TP 6 / FN 5 / FP 2 / TN 9, line-level TP 4, same as 1.5.0 |
| Next holdout replay | [38048781400](https://github.com/ictechgy/apsa/actions/runs/38048781400) | 4 / 4 declared facts, 16 / 16 Apple CVE boundary decisions, stable |
| Generated AAPT2 AAB | [38048783228](https://github.com/ictechgy/apsa/actions/runs/38048783228) | Identical to `next-generated-aab-verified.json` |
| Public real-world sources, fresh OSV capture | [38048784600](https://github.com/ictechgy/apsa/actions/runs/38048784600) | 6 / 6 scans, 6 / 6 configuration labels; 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions; selected app CVE 1 TP / 3 TN |
| Synthetic APSA/MobSF comparison | [38048786165](https://github.com/ictechgy/apsa/actions/runs/38048786165) | APSA 1.5.1 source 18 / 18 risks, 0 / 22 control alerts; APK 3 / 3, 0 / 3. MobSF 12 / 18 with 4 control alerts |
| OWASP MASTG v2.0 demos (development rerun) | [38048787820](https://github.com/ictechgy/apsa/actions/runs/38048787820) | In scope TP 52 / FN 26 / TN 4 / FP 1, every demo outcome the same as 1.5.0 |
| Blind MASWE-labeled pairs (development rerun) | [38048789526](https://github.com/ictechgy/apsa/actions/runs/38048789526) | OsmAnd now scans; 7 of 22 scored in-scope pairs at the labeled lines, fixed-side FP 4 of 22 |

**Findings compared with 1.5.0.** Reports were matched by path, and findings by rule, path, line and status, against the 1.5.0 runtime's runs:

| Harness | Reports | Findings |
| --- | --- | --- |
| Frozen replay | 18 | 594 |
| Next holdout | 6 | 87 |
| Public real-world | 18 | 594 |
| Synthetic comparison | 138 | 165 |
| Independent pairs | 26 | 1,621 |

No finding or coverage state was added or removed. On these inputs the cleaning, staging-order and AST-order changes changed no result. Cleaning OsmAnd's 2,946 code and Gradle files gives byte-identical output to 1.5.0.

**OsmAnd (development rerun on truth already seen).**
- **Local scan of the app folder at the vulnerable commit:**
  - exit 3 (partial), 21 s, 167 MB RSS;
  - 6,215 files (64 MiB) staged, and 10 localized values files (4.1 MiB) omitted;
  - `app_scope_complete` true, 50 findings.
- **Blind-holdout workflow rerun:** it scored the pair. The labeled `IntentHelper.java` was staged and analyzed with no finding on it: FN on the vulnerable side, TN on the fixed side. The deep-link name reaches the path through the app's own `getAppPath` and download helper, which `AST-PATH-TRAVERSAL` does not model as file sinks.
- **Totals:** the in-scope totals become 7 of 22 at the labeled lines and fixed-side FP 4 of 22. The other 23 pairs' hits are identical to the first run.
- **The blind result stays the first measurement** (7 of 21; [BLIND_PAIRS_RESULTS.md](benchmarks/BLIND_PAIRS_RESULTS.md)).

Reviews were Claude subagent reviews, not an external lane:

- **Code review: APPROVE on `a76fd9f`.**
  - **First round** (`be92012`), two P1s, both fixed by `d9bff91`:
    - a copy error aborted the whole audit instead of leaving that file out;
    - vendored code was staged before configuration.
  - **APPROVE** on `3508a28`.
  - **REQUEST CHANGES** on `cfa55b9`, for one regression: a Kotlin raw string ending in a quote swapped strings and code for the rest of the file. The proposed one-line fix was applied unchanged in `a76fd9f`.
  - **APPROVE** on `a76fd9f`: its repro gives the same `STORAGE-SENSITIVE-LOG` result as 1.5.0, and the staging probes are partial audits rather than refusals.
- **Architecture review: WATCH, code CLEAR on `a76fd9f`.**
  - **First round** (`be92012`), three P1s, fixed in `fe3fbe1` through `d9bff91`:
    - required rules could pass on an omitted platform when `fail_on_partial` is off;
    - shipped files were ranked with tests, under prose keys;
    - this release record was missing.
  - **Later rounds** confirmed `fe3fbe1` through `a76fd9f`. The release verdict moves from WATCH to CLEAR once this record exists.

Release steps, once approved:

1. Tag `v1.5.1` on the release commit.
2. The tag-context workflow publishes to PyPI by Trusted Publishing and to the MCP Registry by GitHub OIDC.
3. Fast-forward `main` only after PyPI serves 1.5.1.
4. Record the post-publication checks: the Action smoke test repository, a cold `uvx apsa@1.5.1` start, the marketplace plugin install and the registry listing.

Deferred non-blocking items. Each one fails closed (partial or not-applicable-to-partial):

- **Budget share:** lock files such as `package-lock.json` (up to 8 MiB each) are configuration and can use the budget before code.
- **Module order:** within a kind, files go in path order, so a large tree can lose a whole module. There is no per-module round-robin or per-module omission count.
- **AST budget order:** the AST byte budget moves only tests last; vendored code can use it before app code.
- **SBOM fingerprint:** the SBOM app hash uses the partial input fingerprint.
- **Missing incompleteness flags:** `reports compare` and the Action job summary carry no incompleteness flag. The SARIF run and the gates do.
- **Classification:**
  - production folders named like `*Tests/` are staged as tests;
  - `Frameworks/` is always treated as vendored;
  - JS template literals are not cleaned, as in 1.5.0.
- **Parser headroom:** locally, a full-budget Kotlin/Java tree takes about 37 s of the 90 s parser timeout.
- **1.5.0 items:** the other deferred items from the 1.5.0 entry below remain.

## Published 1.5.0 — 2026-10-10

[1.5.0](https://github.com/ictechgy/apsa/releases/tag/v1.5.0) is bound to source commit `4a7fdff69c1f7085a9e199175eb99113959707cf` through a lightweight tag that was not moved. These paths are identical to the evaluated runtime `1fac679`: `src`, `apsa`, `quaygate`, `pyproject.toml`, `uv.lock`, `requirements-release.txt`, `action.yml`, `server.json`, `plugins` and `.claude-plugin`. Public `main` was fast-forwarded to the same commit, and that push skipped the main-context publish path as intended ([38030417846](https://github.com/ictechgy/apsa/actions/runs/38030417846)).

The tag-context [release workflow 38030112570](https://github.com/ictechgy/apsa/actions/runs/38030112570) passed all 17 jobs:

- **CI:** the eleven CI jobs.
- **Packaging and publication:** the verified package build, PyPI Trusted Publishing, MCP Registry publication by GitHub OIDC and the GitHub release downloads.

PyPI lists `apsa-1.5.0-py3-none-any.whl` (sha256 `67a7bf26935be6178054b003fb870a8ab9689e627a44ebbc94b26b1b1170f5df`) and `apsa-1.5.0.tar.gz` (sha256 `3e0c83e8d76ccd9a946cfc2d3da46feaa99ab1aee2582deda2c568e464bdda5c`). The MCP Registry lists `io.github.ictechgy/apsa` 1.5.0 as active.

Post-publication checks ran on newly generated synthetic projects:

- **Action install path:** uv 0.12.1 installed the hash-locked `requirements-release.txt` and then `apsa==1.5.0` from PyPI. The SARIF scan exited 0 and passed `scripts/check_sarif.py` with repository-relative URIs and a MASWE summary.
  - The first attempt could not resolve `apsa==1.5.0`, because the PyPI simple index had not yet listed it; it did so seconds later.
- **Cold start:** `uvx --python 3.12 apsa@1.5.0` with an empty cache reported 1.5.0.
  - Over MCP stdio it served 23 tools, and `audit_scan` completed.
  - `tool_manifest_sha256` equalled both the hash recomputed from `tools/list` and the published default in [MCP_SECURITY.md](docs/MCP_SECURITY.md), unchanged from 1.4.0.
- **Plugin:** Claude Code 2.1.296, with an isolated configuration directory, installed plugin 1.5.0 from the marketplace.
  - The plugin's skill includes the 1.5 paragraph.
  - Its MCP server runs `uvx --python 3.12 apsa@1.5.0`.
- **GitHub-hosted Action:** [ictechgy/apsa-action-smoke](https://github.com/ictechgy/apsa-action-smoke) ran `uses: ictechgy/apsa@4a7fdff69c1f7085a9e199175eb99113959707cf` with default inputs ([run 38030510902](https://github.com/ictechgy/apsa-action-smoke/actions/runs/38030510902)).
  - It installed `apsa==1.5.0` with no version-mismatch warning, and the audit exited 0.
  - Code scanning recorded analysis 1927830806 for `APSA 1.5.0` with 7 results and no processing errors.
  - The seven alerts from the 1.4.0 analysis remained the same open alerts, so fingerprints carried over unchanged.

## APSA 1.5.0 detection breadth — candidate, 2026-10-10

1.5.0 adds source checks, developed on `dev/detection` after 1.4.0, for the OWASP MASWE weaknesses behind most OWASP MASTG demo misses:

- **Crypto:** broken ciphers and implicit ECB, constant key material and IVs, short (512–1536-bit) RSA/DSA/DH key sizes, CryptoKit `Insecure` digests.
- **Local authentication:** event-bound biometrics, device-credential fallback, keys that survive new enrollment.
- **Transport:** TLS below 1.2, iOS APIs outside ATS, user CAs and cleartext in the referenced network security configuration.
- **Platform:** unverified App Links, intent redirection, implicit internal Intents.
- **Untrusted data:** path traversal, keyed unarchiving without secure coding.
- **WebView:** Safe Browsing off, UIWebView, WKWebView file access.

The AST engine also follows Kotlin scope-function lambdas. Upgrade effects are listed in the README ("Upgrading from 1.4"); scope and limits are in [NEXT_ANALYSIS.md](docs/NEXT_ANALYSIS.md#apsa-150-additions).

The evaluated runtime is public `1fac6797df1fcccb55c415f48f2fbe47463cc6e8` (`src` tree `268ae9699b9ac0bdf9068bc091d36f986487ae1c`, package/rule version `1.5.0` / `2026.10.10.apsa.150`). Its [CI 38027951214](https://github.com/ictechgy/apsa/actions/runs/38027951214) passed all eleven jobs with 1104 distinct tests. `47ce760` adds only the blind-run workflow ([CI 38028093523](https://github.com/ictechgy/apsa/actions/runs/38028093523) passed). Later commits may change only documentation and recorded results. The tag must leave `src`, `apsa`, `quaygate`, `pyproject.toml`, `uv.lock`, `requirements-release.txt`, `action.yml`, `server.json`, `plugins` and `.claude-plugin` identical to `1fac679`.

**Blind measurement.** An independent agent labeled 24 public vulnerable/fixed pairs by MASWE weakness while the rules were written. The truth was committed in `be1911b` before its first scan; [run 38028093532](https://github.com/ictechgy/apsa/actions/runs/38028093532) is the blind result.

- **Primary result:** 7 of 21 scored in-scope pairs found at the labeled lines (Wilson 95% 17–55%). Two come from rules new in 1.5; on the labeled files, 1.4.0 finds the other five (a post-run check by the architecture reviewer).
- **Discriminating TP:** 5 of 21.
- **Fixed-side FP:** 4 of 21. This is file-level, so an upper bound.
- **Errors:** 1 scan failed (exit 1, no message in the raw result). A post-run local scan reproduced the cause: OsmAnd's 71 MB of text input exceeds the 64 MB input staging budget.

[BLIND_PAIRS_RESULTS.md](benchmarks/BLIND_PAIRS_RESULTS.md) discloses:

- the protocol, including its deviation from the 1.4 roadmap wording;
- the attestation basis: the same lead coordinated the curator and wrote the rules;
- the nine post-freeze commits `35d2d88` through `1fac679`, four of which finalized the scoring, all made without access to the truth;
- per-pair results and why pairs were missed.

Every other evaluation harness was re-run on this runtime (`benchmarks/results/2026-10-10-release-150-harnesses.json`). These are development reruns on truth already seen.

| Harness | Run | Result |
| --- | --- | --- |
| Gradle oracle comparison, three holdouts | [38028119805](https://github.com/ictechgy/apsa/actions/runs/38028119805) | Identical to `dependency-final-head.json` |
| Frozen six-app replay | [38028122415](https://github.com/ictechgy/apsa/actions/runs/38028122415) | 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions; selected app CVE 1 TP / 3 TN |
| Independent vulnerable/fixed source pairs | [38028124357](https://github.com/ictechgy/apsa/actions/runs/38028124357) | TP 6 / FN 5 / FP 2 / TN 9, line-level TP 4, same as 1.4. An intermediate development run had a third FP from the new network security configuration check on a loopback-only exception; loopback-only domain configs are now excluded |
| Next holdout replay | [38028126198](https://github.com/ictechgy/apsa/actions/runs/38028126198) | 4 / 4 declared facts, 16 / 16 Apple CVE boundary decisions, stable |
| Generated AAPT2 AAB | [38028128153](https://github.com/ictechgy/apsa/actions/runs/38028128153) | Identical to `next-generated-aab-verified.json` |
| Public real-world sources, fresh OSV capture | [38028129938](https://github.com/ictechgy/apsa/actions/runs/38028129938) | 6 / 6 scans, 6 / 6 configuration labels; 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions; selected app CVE 1 TP / 3 TN |
| Synthetic APSA/MobSF comparison | [38028131804](https://github.com/ictechgy/apsa/actions/runs/38028131804) | APSA 1.5.0 source 18 / 18 risks, 0 / 22 control alerts; APK 3 / 3, 0 / 3. MobSF 12 / 18 with 4 control alerts |
| OWASP MASTG v2.0 demos (development rerun) | [38028133933](https://github.com/ictechgy/apsa/actions/runs/38028133933) | In scope TP 52 / FN 26 / TN 4 / FP 1 (recall 67%, precision 98%); 1.4: 26 / 42 / 4 / 1 |

On the six public apps of the real-world harness, the new rules' findings were reviewed by hand. Two were false positives: an `evaluatePolicy` protocol requirement and a test mock. Both were fixed by counting only calls. The rest matched each rule's definition.

Reviews were all Claude subagent reviews, not an external lane:

- **Code review, six rounds.** It approved `1fac679`. Earlier rounds found the following, all fixed:
  - worst-case CPU paths that killed the audit;
  - false positives from runtime-filled arrays, file descriptors and non-archive `*Entry` types;
  - LocalBroadcastManager fields and third-party actions;
  - `uiWebView` matched case-insensitively;
  - debug and other-module network configurations;
  - BOM-prefixed XML;
  - scope-lambda regressions in older rules;
  - weak guards.
- **Architecture review: WATCH, then CLEAR.** It gave WATCH with three P0 items: wrong-module network configurations, `?.let` merges, and `checked` on binary XML. It moved to CLEAR on `6b823df`, `866df97`, `5ff5a6d` and `1fac679` once those items and its P1 and follow-up items were addressed. It keeps the release at WATCH for the follow-ups below.

Release steps, once approved:

1. Tag `v1.5.0` on the release commit.
2. The tag-context workflow publishes to PyPI by Trusted Publishing and to the MCP Registry by GitHub OIDC.
3. Fast-forward `main` only after PyPI serves 1.5.0.
4. Record the post-publication checks: the Action smoke test repository, a cold `uvx apsa@1.5.0` start, the marketplace plugin install and the registry listing.

Deferred non-blocking items:

- **Input budget:** inputs above the 64 MB text staging budget are refused rather than audited partially. OsmAnd's 53 MB of translation XML is an example. Staging code first and omitting the rest as partial is a 1.5.x candidate.
- **Analyzer cost:** very large functions with thousands of PendingIntent calls or `if` blocks are slow but bounded. Fixing them needs copy-on-write frames and a per-function Intent-builder table.
- **Rule metadata:** titles and remediation live in both code and catalog.
- **Guards:** path and redirection guards are textual, not tied to the tainted variable.
- **AAB:** network security configurations in AABs are not decoded.
- **Same-file assumptions:** iOS read-access resolution and constants stay within one file.
- **Missed families from the blind run:** flow across functions, missing-control weaknesses (MASWE-0038 and others), the RSA PKCS#1 v1.5 fallback, `SecPolicyCreateBasicX509`, and generator objects in the insecure-random heuristic.

## Published 1.4.0 — 2026-10-10

[1.4.0](https://github.com/ictechgy/apsa/releases/tag/v1.4.0) is bound to source commit `5bed4e5b02e4b60fd49573dbe51628c0e4d1455c` through a lightweight tag that was not moved. These paths are identical to the evaluated runtime `803220d`: `src`, `apsa`, `quaygate`, `pyproject.toml`, `uv.lock`, `requirements-release.txt`, `action.yml`, `server.json`, `plugins` and `.claude-plugin`. Public `main` was fast-forwarded to the same commit, and that push skipped the main-context publish path as intended ([37955636178](https://github.com/ictechgy/apsa/actions/runs/37955636178)).

The tag-context [release workflow 37955019531](https://github.com/ictechgy/apsa/actions/runs/37955019531) passed all 17 jobs:

- **CI:** the eleven CI jobs (Linux/macOS × Python 3.11/3.12, required-mode Linux/macOS parser isolation, Homebrew framework Python, nested Seatbelt, Ubuntu 24.04 bubblewrap, and the Linux/macOS Action self-tests).
- **Packaging and publication:** the verified package build, PyPI Trusted Publishing, MCP Registry publication by GitHub OIDC and the GitHub release downloads.

PyPI lists `apsa-1.4.0-py3-none-any.whl` (sha256 `c4ab219a18409323377dcdd0de2e2d36222354cb95207f150c59de0b325868be`) and `apsa-1.4.0.tar.gz` (sha256 `105a422d6c94c36d5c49079a4968a73ba2616b0239f8137da769f23757586cca`). The MCP Registry lists `io.github.ictechgy/apsa` 1.4.0 as active.

Post-publication checks ran on a newly generated synthetic project:

- **Action install path:** uv 0.12.1 installed the release's hash-locked `requirements-release.txt` and then `apsa==1.4.0` from PyPI, as the Action does. The SARIF scan exited 0, and the SARIF passed `scripts/check_sarif.py` with repository-relative URIs and a MASWE summary.
- **Cold start:** `uvx --python 3.12 apsa@1.4.0` with an empty cache reported 1.4.0. Over MCP stdio it served 23 tools. The `tool_manifest_sha256` from `capabilities` equalled both the hash recomputed from `tools/list` and the published default in [MCP_SECURITY.md](docs/MCP_SECURITY.md), and `audit_scan` completed.
- **Plugin:** Claude Code 2.1.295, with an isolated configuration directory, ran `claude plugin marketplace add ictechgy/apsa` and `claude plugin install apsa@apsa`. It installed plugin 1.4.0 with its skill and its MCP server, whose command is the `uvx` command above.
- **GitHub-hosted Action:** the public test repository [ictechgy/apsa-action-smoke](https://github.com/ictechgy/apsa-action-smoke) holds only a small synthetic Android project. Its workflow runs `uses: ictechgy/apsa@5bed4e5b02e4b60fd49573dbe51628c0e4d1455c` with every input at its default. [Run 38020319297](https://github.com/ictechgy/apsa-action-smoke/actions/runs/38020319297) on `ubuntu-24.04` passed:
  - uv 0.12.1 installed the hash-locked dependencies and `apsa==1.4.0` from PyPI, with no version-mismatch warning.
  - The audit exited 0 and set the `exit-code`, `report-id` and `sarif-file` outputs.
  - The pinned `upload-sarif` v4.38.2 step uploaded the SARIF, which CI does not exercise. Code scanning recorded analysis 1927474176 for tool `APSA 1.4.0` in category `apsa`, with 7 results, 7 rules and no processing errors or warnings.
  - All 7 alerts point at the repository files `app/src/main/AndroidManifest.xml` and `app/src/main/java/com/example/smoke/Main.kt`. The four candidate results carry the `candidate` tag at warning level with no security severity. The three confirmed results are rated: cleartext traffic medium, backup and `targetSdk` low.

## APSA 1.4.0 adoption, agent verification and benchmarks — candidate, 2026-10-10

1.4.0 packages the three roadmap phases developed on `dev/adoption` and `dev/phase3` after 1.3.0:

- **Distribution and integration.** A GitHub Action that uploads SARIF to code scanning, and an [OWASP MASWE v1.0](https://mas.owasp.org/MASWE/) coverage matrix in every report. The MCP server is packaged for the MCP Registry and as a Claude Code plugin, with a documented [MCP security model](docs/MCP_SECURITY.md) and a normalized tool-manifest hash.
- **Agent verification.** `verify_finding`, project taint specifications and more provider SQL sinks.
- **New source checks.** Exported components, backup, `targetSdk`, privacy manifests, ATS exceptions, hard-coded secrets, insecure randomness, trust-all TLS, external storage, Java deserialization and mutable `PendingIntent`.
- **Reports and records.** A CycloneDX 1.6 SBOM with embedded VEX, external SARIF ingestion, checklist views with finding history (with a Korean inspection guide), and a pinned OWASP MASTG v2.0 demo benchmark.

Upgrade effects are listed in the README ("Upgrading from 1.3"). Benchmark method and results are in [MASTG_RESULTS.md](benchmarks/MASTG_RESULTS.md) and [FPFN_RESULTS.md](benchmarks/FPFN_RESULTS.md).

The evaluated runtime is public `803220d743c4b5294512915d4334010208c50799` (`src` tree `7e8fc2d9697c3053063ef291268fb958f43b8d85`, package/rule version `1.4.0` / `2026.10.09.apsa.140`). Its [CI 37949319624](https://github.com/ictechgy/apsa/actions/runs/37949319624) passed all eleven jobs (the nine release jobs plus the two Action self-test jobs) with 1057 distinct tests. Later commits may change only documentation and recorded results. The tag must leave `src`, `apsa`, `quaygate`, `pyproject.toml`, `uv.lock`, `requirements-release.txt`, `action.yml`, `server.json`, `plugins` and `.claude-plugin` identical to this commit.

Every evaluation harness was re-run on this runtime (`benchmarks/results/2026-10-10-release-140-harnesses.json`). These are development reruns on truth already seen, not new blind measurements; first blind results keep their own files.

| Harness | Run | Result |
| --- | --- | --- |
| Gradle oracle comparison, three holdouts | [37949339300](https://github.com/ictechgy/apsa/actions/runs/37949339300) | Identical to `dependency-final-head.json` |
| Frozen six-app replay | [37949353951](https://github.com/ictechgy/apsa/actions/runs/37949353951) | 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions; selected app CVE 1 TP / 3 TN |
| Independent vulnerable/fixed source pairs | [37949344101](https://github.com/ictechgy/apsa/actions/runs/37949344101) | TP 6 / FN 5 / FP 2 / TN 9, line-level TP 4, no errors or unscored sides. Against 1.3.0 (5 / 6 / 1 / 10): the new provider SQL sinks catch the Nextcloud vulnerable side at line level; its fixed side, which validates the selection with an SQLite tokenizer APSA does not model, becomes an FP |
| Next holdout replay | [37949358821](https://github.com/ictechgy/apsa/actions/runs/37949358821) | 4 / 4 declared facts, 16 / 16 Apple CVE boundary decisions, stable over three repeats; Tusky unresolved dependencies 15, parse-error files 0 |
| Generated AAPT2 AAB | [37949349503](https://github.com/ictechgy/apsa/actions/runs/37949349503) | Identical to `next-generated-aab-verified.json` |
| Public real-world sources, fresh OSV capture | [37949363191](https://github.com/ictechgy/apsa/actions/runs/37949363191) | 6 / 6 APSA scans completed, 6 / 6 configuration labels; 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions; selected app CVE 1 TP / 3 TN |
| Synthetic APSA/MobSF comparison | [37949334891](https://github.com/ictechgy/apsa/actions/runs/37949334891) | APSA 1.4.0 source 18 / 18 risks, 0 / 22 control alerts; APK 3 / 3, 0 / 3. MobSF 12 / 18 with 4 control alerts. Released 1.1.0 baseline 14 / 18 with 4 |
| OWASP MASTG v2.0 demos (development rerun) | [37949319562](https://github.com/ictechgy/apsa/actions/runs/37949319562) | In scope TP 26 / FN 42 / TN 4 / FP 1 (recall 38%, precision 96%); the first blind result was 15 / 53 / 4 / 1 ([37942539599](https://github.com/ictechgy/apsa/actions/runs/37942539599)) |

The earlier candidate runtime `b5bd301` ran the same harnesses before the PendingIntent flag-value fix, and all passed. Its run IDs are listed in the summary file.

Reviews were all Claude subagent reviews, not an external lane:

- **Phase 1 code review:** requested changes on `1c46091`. Those were the action gate hidden by an incomplete audit, overstated MASWE states, SARIF locations and the MCP supply-chain claims. It approved the fixes `78e0910` through `3f56593`.
- **Architecture review:** returned BLOCK on `1c46091` for the same gate and MASWE issues. It moved to WATCH on `78e0910` (policy reasons downgraded by `fail-on-incomplete`, and candidate `security-severity` tripping default code-scanning checks), and to CLEAR on `8a21f73`.
- **Phase 2 code review:**
  - Requested changes on `1c46091`: malformed privacy manifests, Gradle `targetSdk`, finding identities and SQL sink identity.
  - Requested changes again on `7439ce7`, because further plist exception types still aborted a scan. A shared safe-plist helper now covers every plist parse.
  - Approved `21824ec`, `4464c0d`, `b5bd301` and the runtime `803220d`, after rounds on PendingIntent flag parsing and `verify_finding` path matching.

Release steps, once approved:

1. Tag `v1.4.0` on the release commit.
2. The tag-context workflow publishes to PyPI by Trusted Publishing and to the MCP Registry by GitHub OIDC.
3. Fast-forward `main` only after PyPI serves 1.4.0.

After publication, record the following checks:

- the Action from the release commit with its default version, including an upload to a test repository;
- a cold `uvx apsa@1.4.0` start and the marketplace plugin install;
- the registry listing.

Deferred non-blocking items:

- `verify_finding`: a claim on a nonexistent non-source file still reads not-observed, a reassigned Intent variable is not followed, and there is no report timestamp in its result.
- `first_observed` reads up to 1000 full reports.
- The Action hash-locks APSA's dependencies but not the APSA wheel itself, and the pinned upload-sarif step is not exercised in CI.
- `capabilities` hashes the tool surface through the SDK's private tool manager; a test pins it against the public `tools/list`.
- Candidate-quality items from the first Phase 2 review: PyPI purl normalization, `sortOrder` and `SQLiteQueryBuilder.query` sinks, a specification sink on a built-in sink, `//` inside strings and Objective-C `NSFile*` constants for required-reason APIs, and CycloneDX aggregate properties.
- The remaining MASTG modes listed in MASTG_RESULTS.md.

Publication is confirmed only by the tag-context release workflow, PyPI, the MCP Registry and the GitHub release downloads, and will be recorded once complete.

## Published 1.3.0 — 2026-10-09

[1.3.0](https://github.com/ictechgy/apsa/releases/tag/v1.3.0) is bound to source commit `30bbceabaaba25b666b53ce805648836aafe8853` through a lightweight tag that was not moved; its `src`, `pyproject.toml` and `uv.lock` are identical to the evaluated runtime `a3506ca`. Public `main` was fast-forwarded to the same commit; that push skipped the main-context publish path as intended. The tag-context [release workflow 37931663043](https://github.com/ictechgy/apsa/actions/runs/37931663043) passed all nine CI jobs (Linux/macOS × Python 3.11/3.12, required-mode Linux/macOS parser isolation, Homebrew framework Python, nested Seatbelt and Ubuntu 24.04 bubblewrap compatibility), the verified package build, PyPI Trusted Publishing and the GitHub release downloads. PyPI lists `apsa-1.3.0-py3-none-any.whl` (sha256 `796013bec8cb7f567a3dcb2b6833c4044e2ac2c9a189c93548fe81be0e673f39`) and `apsa-1.3.0.tar.gz` (sha256 `0afdd3cf267bad804b65b36b5d708cc2218bbc5423e9fa32e21265d8c7c1fc42`). A fresh `uv pip install apsa==1.3.0` reported version 1.3.0 and rule version `2026.10.09.apsa.130`, its packaged skill matched the 1.3.0 fixture, and a scan of a newly generated synthetic project found the declared cleartext setting and read the application lockfile coordinate as exact. The release commit passed CI run [37931244005](https://github.com/ictechgy/apsa/actions/runs/37931244005).

## APSA 1.3.0 dependency evidence and analysis depth — candidate, 2026-10-09

1.3.0 packages the work developed on `dev/evidence-depth` after 1.2.0: Gradle catalog usage and application-lockfile coordinates with conservative supersession, AAB feature-module manifests, Mach-O CodeDirectory page and entitlement hash recomputation without signature authentication, bounded Swift/Objective-C adaptations with uncertain Objective-C spans, and explicit Android bulletin backfill with SoC vendor and vendor patch-level context. Scope and limits are in [NEXT_ANALYSIS.md](docs/NEXT_ANALYSIS.md#apsa-130-additions); measurements are in [DEPENDENCY_RESULTS.md](benchmarks/DEPENDENCY_RESULTS.md) and [FPFN_RESULTS.md](benchmarks/FPFN_RESULTS.md).

The evaluated runtime is public `a3506ca02d305d89f8a366284ecea84fabd44b2a` (`src` tree `b720f0ec3eb1212027213f1cf36c3b1697c9d83d`, package/rule version `1.3.0` / `2026.10.09.apsa.130`). Its [CI 37930243747](https://github.com/ictechgy/apsa/actions/runs/37930243747) passed all nine jobs with 949 distinct tests. Later commits change only documentation and recorded results; the tag must leave `src`, `apsa`, `quaygate`, `pyproject.toml` and `uv.lock` identical to this commit. The release delta on top of the reviewed branch head `ed8aa81`:

- merges the 1.2.0 publication record, bumps the versions and registers the published 1.2.0 default skill hashes (also checked against the PyPI 1.2.0 wheel) so unmodified 1.2.0 skills upgrade without `--force`;
- updates the skill text: Gradle evidence, the OSV transmission scope and budget, AAB feature modules, code integrity limits, chipset patch levels and baseline re-approval;
- review fixes to the OSV budget: unresolved or unsupported entries no longer consume query slots; packages without a result from the last 23 hours go first and, among them, declared packages and non-Gradle manifests precede transitive Gradle lockfile coordinates, so a lockfile cannot crowd out declared packages and repeated runs advance through large lockfiles; the warning counts only unchecked packages;
- Android bulletin records cached by 1.2.0 derive their vendor scope from the component, and the advisory basis states when no valid vendor patch level was compared;
- records an absent parser package as null in the competitive harness's baseline metadata (`benchmarks/competitive.py`), a defect introduced during 1.2.0 development that stopped the comparison before measuring.

OSV policy for 1.3.0: the per-run budget stays at 100 package queries, as in 1.2.0. `--online` sends catalog aliases used in shipped configurations and the release-runtime lockfile coordinates of every module, including private group IDs, with no exclusion list. Application lockfiles measured 179–412 shipped coordinates, so one online run of such an app is incomplete; repeated runs within a day advance. Batch querying would change the per-package request format that the frozen OSV replay depends on and is deferred with an exclusion control.

Every evaluation harness was re-run on the final runtime (`benchmarks/results/2026-10-09-release-130-harnesses.json`). These are development reruns on truth already seen, not new blind measurements; first blind results keep their own files.

| Harness | Run | Result |
| --- | --- | --- |
| Gradle oracle comparison, three holdouts | [37930243745](https://github.com/ictechgy/apsa/actions/runs/37930243745) | Identical to `dependency-final-head.json`: 198 TP / 3 FP, 194 / 27, 121 / 2 |
| Frozen six-app replay | [37930243791](https://github.com/ictechgy/apsa/actions/runs/37930243791) | 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions; selected app CVE 1 TP / 3 TN |
| Independent vulnerable/fixed source pairs | [37930243762](https://github.com/ictechgy/apsa/actions/runs/37930243762) | TP 5 / FN 6 / FP 1 / TN 10, line-level TP 3, no errors or unscored sides |
| Next holdout replay | [37930265882](https://github.com/ictechgy/apsa/actions/runs/37930265882) | 4 / 4 declared facts, 16 / 16 Apple CVE boundary decisions, stable over three repeats; Tusky unresolved dependencies 69 → 15, VLC parse-error files 22 → 0 |
| Generated AAPT2 AAB | [37930269473](https://github.com/ictechgy/apsa/actions/runs/37930269473) | Identical to `next-generated-aab-verified.json` |
| Public real-world sources, fresh OSV capture | [37930262222](https://github.com/ictechgy/apsa/actions/runs/37930262222) | 6 / 6 APSA scans completed, 6 / 6 configuration labels; 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions; selected app CVE 1 TP / 3 TN |
| Synthetic APSA/MobSF comparison | [37930258227](https://github.com/ictechgy/apsa/actions/runs/37930258227) | APSA 1.3.0 source 18 / 18 risks, 0 / 22 control alerts; APK 3 / 3, 0 / 3. MobSF 12 / 18 with 4 control alerts. Released 1.1.0 baseline 14 / 18 with 4 |

Earlier candidate runtimes `aaac2cb` and `ee28087` ran the same harnesses before the review fixes changed the OSV query order; all passed, the `aaac2cb` results matched the table above, and their run IDs are listed in the summary file. The first competitive dispatch on `aaac2cb` ([37926967909](https://github.com/ictechgy/apsa/actions/runs/37926967909)) failed on the metadata defect above.

Independent code review (three rounds) approved `a3506ca` after its findings were fixed: unsupported entries consuming the budget, an understated transmission scope, cached chipset scope, non-advancing repeated runs, the freshness boundary and skill wording. The architecture review returned BLOCK on `aaac2cb` because an application lockfile crowded declared packages out of the OSV budget, and WATCH without blockers on `ee28087` once that was fixed and the upgrade, privacy and lockfile-trust notes were documented; the final delta only narrows the freshness window and rewords the skill. All reviews were Claude subagent reviews, not an external lane.

Deferred non-blocking items: OSV batch querying with an exclusion list and a sent count; skipping or age-ordering fresh results to reduce re-sent coordinates; the remaining freshness margin if OSV responds slowly for hours; `correlate` cost with many dependencies (about 1.7×) and `ModuleGraph` memory on adversarial graphs; Gradle `projectDir` remapping; `NS_ASSUME_NONNULL_BEGIN`; CodeDirectory scatter and `preEncryptOffset`; Apple and vendor bulletin history; the unreachable `google`/`samsung` SoC vendor entries; mirroring the 90-day oracle artifacts; physical-device evidence. Publication is confirmed only by the tag-context release workflow, PyPI and the GitHub release downloads, recorded once complete.

## Published 1.2.0 — 2026-10-09

[1.2.0](https://github.com/ictechgy/apsa/releases/tag/v1.2.0) is bound to source commit `8d915753a930279c7816f0f99e4e843505df92a6` through a lightweight tag that was not moved. Public `main` was fast-forwarded to the same commit; that push skipped the main-context publish path as intended. The tag-context [release workflow 37906807519](https://github.com/ictechgy/apsa/actions/runs/37906807519) passed all nine CI jobs (Linux/macOS × Python 3.11/3.12, required-mode Linux/macOS parser isolation, Homebrew framework Python, nested Seatbelt and Ubuntu 24.04 bubblewrap compatibility), the verified package build, PyPI Trusted Publishing and the GitHub release downloads. PyPI lists `apsa-1.2.0-py3-none-any.whl` and `apsa-1.2.0.tar.gz`; a fresh `uv pip install apsa==1.2.0` reported version 1.2.0 and rule version `2026.10.09.apsa.120` on a synthetic source scan. The release-candidate snapshot passed CI run [37906348625](https://github.com/ictechgy/apsa/actions/runs/37906348625) with 883 distinct tests. Independent code review approved the release delta `cbf3c44..8d91575`; the architecture review returned WATCH without blockers after its earlier BLOCK on sandbox activation was resolved. Deferred non-blocking items: pinning the Homebrew interpreter and wheel build backend in the compatibility job, freezing released skill fixtures by hash, and tolerating a broken optional parent package during probe module discovery.

## APSA 1.2.0 analysis extension — candidate, 2026-10-09

1.2.0 packages the bounded analysis extension developed on `hardening/real-app-cve-v1`: AAB base-manifest/module DEX analysis, embedded IPA Mach-O metadata, narrow Objective-C `.m` candidates, descriptor-safe parser input staging and macOS/Linux parser OS isolation that is on by default where an activation probe succeeds. Scope and limits are in [NEXT_ANALYSIS.md](docs/NEXT_ANALYSIS.md); measurements are in [NEXT_RESULTS.md](benchmarks/NEXT_RESULTS.md). Every AAB audit stays partial, embedded IPA metadata does not authenticate signatures, Objective-C findings remain candidates, and the parser sandbox does not isolate the parent CLI or MCP client.

The evaluated runtime is public `9c2d5d5033132ee2113a2638e17d3225d2e7dbc8` (runtime tree `133b48e59bbf01bb2aad8458812020eee6ae157f`), whose [CI 37899396137](https://github.com/ictechgy/apsa/actions/runs/37899396137) passed all six jobs with 873 distinct tests. Its code review approved and its architecture review cleared that snapshot; documentation closure followed at public `cbf3c449358f3aedaff87ce6da3a04ad0fea00f3`. The 1.2.0 release delta on top of that tree adds package/rule version metadata (`1.2.0`, `2026.10.09.apsa.120`); registration of the 1.1.0 default skill hashes so unmodified 1.1.0 skills upgrade without `--force` while user edits stay protected; an input-free parser sandbox activation probe so that `auto` records `unavailable` instead of aborting when a present backend cannot start (nested Seatbelt, blocked user namespaces), while `required` refuses with an explicit reason; the exact macOS framework-Python app-bundle interpreter in the Seatbelt exec allowance; sandbox-specific failure messages; lock-safe audit database permission repair, fixing a pre-existing race in which opening a second store in one process released the live connection's SQLite WAL-index locks and could crash it with SIGBUS when another process reinitialized the shared memory (observed once in macOS/Python 3.11 CI); a hosted isolation compatibility job (Homebrew framework Python, nested Seatbelt, Ubuntu 24.04 bubblewrap); regression tests; and release documentation. The holdout and replay measurements were not rerun after this delta. The release delta requires its own targeted review and the supported CI matrix; earlier approvals do not extend to it automatically.

Evaluation numbers keep their recorded meaning. The independent holdout agrees on 4 / 4 selected declaration facts and 16 / 16 selected Apple CVE boundary decisions, not 16 vulnerabilities or device patch verification. The frozen replay keeps 8 TP / 0 FP / 0 FN / 19 TN / 5 correct abstentions on the original dependency units and two unresolved catalog-usage abstentions on selected app paths. Publication is confirmed only by the tag-context release workflow, PyPI and the GitHub release downloads, recorded below once complete.

## Published 1.0.6 and 1.1.0 — 2026-10-08

The requested release sequence is complete through 1.1.0. [1.0.6](https://github.com/ictechgy/apsa/releases/tag/v1.0.6) is bound to source commit `2fbca30bfc03c8e5ef2b8dd0d16dd1ae720fc361`; [1.1.0](https://github.com/ictechgy/apsa/releases/tag/v1.1.0) is bound to `a2149c23288079e4e4dd57c7eda1bd822c9097d1`, whose tree exactly matches the independently reviewed local candidate. The tags were not moved. The successful tag-context workflows are [1.0.6](https://github.com/ictechgy/apsa/actions/runs/37794658338) and [1.1.0](https://github.com/ictechgy/apsa/actions/runs/37796258526). Each passed the four supported CI environments, verified package build, PyPI upload and release downloads. Local 1.1 validation also covered 648 pytest tests, Ruff/format/Pyright, corpus 31/31, repeated package hashes, clean offline installation and new-feature CLI/MCP smoke.

Main-context publish attempts failed before publisher steps after the approved tags were created; their exact cause was not confirmed. User-authorized, independently reviewed recovery workflows dispatched only the fixed version/commit pair and were removed after use. Tag creation and source upload were not treated as package publication. One separately triggered macOS/Python 3.11 CI job failed on its first execution and passed on one operational retry; the release matrix and the final recovery source CI passed all four environments. No test or coverage gate was disabled.

Code review approved the 1.1 snapshot; the architectural verdict is WATCH without source blockers. The documented tradeoffs remain numeric cursors scoped to report/section/filters, unsigned baseline approval with an externally pinned artifact hash, and declared source selection without Gradle/Xcode merging. These limits are not new analysis capabilities. AAB, IPA embedded binaries, Objective-C and parser OS sandbox remain later stages in [ROADMAP.md](docs/ROADMAP.md).

The candidate and older entries below are historical validation notes. Registry publication is established by the linked release workflow and downloads, not by a local build manifest's `published` field.

공개 저장소: [ictechgy/apsa](https://github.com/ictechgy/apsa). 영문 README가 원본이며 한국어 README를 함께 제공합니다. 현재 공개 소스의 검증은 [GitHub Actions](https://github.com/ictechgy/apsa/actions)에서 확인할 수 있습니다.

태그 배포 경로는 [PyPI](https://pypi.org/project/apsa/)와 [GitHub Releases](https://github.com/ictechgy/apsa/releases)입니다. `release.yml`은 `pypi` 환경의 Trusted Publisher를 사용하며, 태그·패키지 버전 일치, 지원 대상 CI 네 조합, 업로드할 패키지의 반복 빌드와 새 환경 설치 검증이 통과해야 업로드합니다. 다운로드와 체크섬 구성은 [배포 안내](docs/PUBLISHING.md)에 기록합니다. 이 배포 설정 변경은 새 보안 검토 승인을 의미하지 않습니다.

아래는 로컬 개발 과정의 검증 이력입니다. 원본 감사 데이터, 검토 로그, 개인 설정, 스크린샷, 로컬 가상 환경과 배포 폴더는 공개 저장소에 포함하지 않습니다. 아래의 내부 증거 경로와 과거 배포 경로는 로컬 기록을 가리키며 공개 다운로드를 뜻하지 않습니다. 과거 외부 리뷰를 현재 공개 스냅샷에 대한 새 보안 승인으로 취급하지 않습니다. 로컬 배포 파일은 `make release`로 새 출력 폴더에 생성할 수 있습니다.

---

# APSA 1.0.6 evidence correctness

Mixed unsupported source languages and per-file pattern truncation are incomplete. OS-CVE records explicitly report bounded recent-window correlation, without a historical-completeness claim. Dependency declarations produce candidates; exact inventory produces version-affected evidence. MCP fallback uses isolated Python startup. The adoption recipe uses unified scan, a reviewed project policy, current dependencies and exit codes. New regression checks use generated synthetic fixtures outside runtime data paths. Release validation and independent review are recorded for the final snapshot; older approvals do not apply.

# APSA 1.1 model and team workflows — candidate

Bounded section/evidence pages preserve response omissions separately from audit completeness. Portable baselines require explicit approval provenance and an externally pinned byte hash; source selection is part of baseline identity. Policy decision exports preserve the normalized policy, report/policy hashes, baseline provenance and waiver decisions. Explicit module/configuration selection is shared by foreground and persistent audits without build-system variant merging. Packaged skills and both READMEs describe the contract; default 1.0.6 skill upgrades preserve user customizations.

Local source validation: **648 pytest tests passed**, Ruff check/format passed, Pyright reported no errors, and the handcrafted corpus matched **31/31** cases. These are regression checks with synthetic inputs. The supported CI matrix, clean-release package checks, independent final-snapshot review and registry publication are separate gates. This entry records a candidate, not a completed publication. The requested release order remains 1.0.6, then 1.1, then the stages in [ROADMAP.md](docs/ROADMAP.md).

---

# APSA (앱사) 1.0.5 검사 누락 수정 — 2026-10-08

읽을 수 없는 소스 하위 디렉터리를 조용히 건너뛰던 열거 오류를 경고·partial·불완전한 fingerprint로 표시합니다. 열거한 파일의 상태 확인이나 읽기 실패도 같은 불완전 경로로 처리합니다. 지원하는 파일을 하나도 읽을 수 없으면 명시적인 실행 오류가 됩니다. 의도적인 제외 폴더와 심볼릭 링크 정책은 유지합니다.

iOS 로컬 저장소 캡처는 디렉터리 열거·파일 확인·읽기 실패를 `not-run`으로 남겨 canary 삭제 검사가 통과하지 않도록 합니다. 캡처 오류에 포함된 canary도 label로 가리고, 불완전한 재관찰 때문에 기존 런타임 발견 근거를 지우지 않습니다.

로컬 `make test benchmark`: **612개 pytest 통과**, Ruff check/format 통과, Pyright 오류 0건, 기존 수작업 corpus **31/31 일치**. 추가 22개 회귀 사례는 권한 거부·중첩 폴더·파일 상태 오류·CI 종료 코드·기존 런타임 근거 보존·canary 가림과 정상 삭제·의도적 제외 대조군을 검증합니다. 앞쪽 파일의 읽기 실패 이후에도 읽을 수 있는 다른 파일을 검사하며, 디렉터리에 실행 권한이 없어 자식의 상태 확인이 실패하는 경우도 검증합니다. 저장소 확인은 로컬 어댑터를 이용하며 새 시뮬레이터·실기기 실행이나 운영 앱 탐지율 측정은 포함하지 않습니다.

이 로컬 결과는 최종 스냅샷의 독립 리뷰 또는 업로드 완료를 뜻하지 않습니다. 업로드 전에 독립 리뷰, 지원 대상 CI 네 조합, 반복 wheel/sdist 빌드와 깨끗한 설치 검증을 거칩니다. 배포 완료 시 다운로드와 manifest는 [1.0.5 릴리스](https://github.com/ictechgy/apsa/releases/tag/v1.0.5)에서 확인할 수 있습니다.

---

# APSA (앱사) 1.0.4 리뷰 수정 — 2026-10-06

작업 프로세스의 Python import 경로, 승인된 MCP sidecar·정책·시나리오·소스 경로의 재해석, 소스 열거 제한의 부분 검사 표시, SQLite DB/WAL/SHM 생성 권한을 보완합니다. 잘못된 KEV routing 필드는 기존 캐시를 보존하며 오류를 표시하고, 프로젝트별 인텔 유효 시간과 CVE의 component·patch·snapshot 분기를 advisory와 version-affected 발견 근거에 모두 보존합니다. CLI의 초기 부모 심볼릭 링크 처리와 기존 명령·데이터·발견 ID는 유지합니다.

로컬 격리 사본에서 `make test benchmark`: **590개 pytest 통과**, Ruff check/format 통과, Pyright 오류 0건, 기존 수작업 corpus **31/31 일치**. 46개 회귀 사례는 두 worker의 cwd/PYTHONPATH 입력, 승인 후 경로 교체, 동결된 런타임 시나리오, 열거 제한, 공유 home의 DB 권한, malformed KEV, custom freshness, 분기 출처와 1.0.3 스킬 갱신을 검증합니다. 새 실기기 실행이나 상용 앱 탐지율 검증은 포함하지 않습니다.

이 로컬 검사 결과는 독립 리뷰 또는 배포 완료를 뜻하지 않습니다. 최종 태그 스냅샷의 리뷰 기록은 별도로 바인딩하며, 업로드 전 CI 네 환경과 반복 패키지 빌드·깨끗한 설치 검증을 거칩니다. 실제 배포 완료·다운로드와 manifest는 [1.0.4 릴리스](https://github.com/ictechgy/apsa/releases/tag/v1.0.4)에서 확인하십시오.

---

# APSA (앱사) 1.0.3 리네이밍 — 2026-10-06

제품 표기, `apsa` CLI·배포 패키지·Python 진입점·MCP URI·스킬을 새 이름으로 통일합니다. 기존 명령어·URI·환경 변수·감사 DB는 호환하며 이전 발견 ID와 lint provenance를 보존합니다. 과거 독립 보안 리뷰는 당시 스냅샷에만 적용됩니다. 현재 변경의 검증과 설치 근거는 `.omx/renames/` 아래에 별도로 기록합니다.

검증: **544개 테스트 통과**, Ruff 검사·포맷 통과, Pyright 오류 0건, 세 스킬 frontmatter 검증 통과. `apsa`와 기존 Python 진입점의 MCP stdio 왕복 및 세 URI의 동일 보고서 응답, 구버전 기본 스킬 갱신과 사용자 수정본 보존을 확인했습니다. 검사 규칙과 감사 DB schema는 변경하지 않습니다.

현재 배포 폴더는 `dist/apsa-1.0.3`입니다. 반복 빌드·새 환경의 소스/APK 검사·MCP·세 CLI 별칭/모듈/스킬 검증 근거는 이 폴더의 `release-manifest.json`과 `SHA256SUMS`로 기록합니다. 아래는 이전 이름·버전의 검증 이력입니다.

---

# Quaygate (키게이트) 1.0.2 제품 리뷰 수정 — 2026-10-06

현재 변경은 부분 검사 종료 코드, iOS 메인·내장 식별자와 ZIP 경로 구조, 메인 설정 우선 읽기와 용량 한도, 빌드별 플랫폼 식별, ARSC·Mach-O·ELF·인증서 경계, CVE 수집/처리 상태, OSV 심각도, 감시의 명시적 온라인 조회와 이력 중복 방지, MCP 기본 경로 제한, 패키지 스킬 설치, 비교·runtime·sidecar 경계를 보완합니다.

검증: 기존 478개와 새 회귀 61개를 합친 539개 테스트, Ruff 검사·포맷, Pyright 오류 0건. 새 실기기·대형 상용 앱의 탐지율 검증은 포함하지 않습니다. 원본 외부 리뷰와 수정 후 독립 리뷰는 `.omx/reviews/20261005T161101Z/`의 불변 스냅샷·패킷·실행 기록에 바인딩합니다. 검증 통과를 독립 승인으로 간주하지 않으며, 최종 판정은 별도 REVIEW 문서에 기록합니다.

반복 wheel/sdist 빌드와 새 환경 설치·소스/APK·MCP·휠 스킬 설치 결과는 `dist/quaygate-1.0.2-product-final/release-manifest.json` 및 `SHA256SUMS`로 확인합니다. 이전 배포 폴더와 검토 중 생성한 후보 산출물을 덮어쓰지 않습니다.

## 이전 버전 이력

# Quaygate (키게이트) 1.0.1 표기 정리 — 2026-10-06

사용자가 승인한 표기는 영문 **Quaygate**, 한글 **키게이트**, 발음 **key-gate**입니다. README·브랜드 규칙·제품/디자인 문서, CLI 도움말과 사람용 결과 제목, TUI 제목, Markdown 보고서, MCP 안내와 두 스킬에 반영했습니다. CLI·패키지·MCP 식별자와 감사 데이터 저장 위치는 `quaygate` 통합 제품의 기존 계약을 따릅니다.

이번 변경의 검증: **478개 테스트 통과**, Ruff 검사·포맷 통과, Pyright 오류 0건, 두 스킬의 frontmatter 검증 통과. 새 검사 규칙이나 취약점 탐지 기능은 추가하지 않았으며, 이전 보안 리뷰를 새 승인으로 표시하지 않습니다.

1.0.1 배포 입력과 새 환경 설치·오프라인 소스/APK·MCP 검증, 반복 빌드 일치 여부는 `dist/quaygate-1.0.1/release-manifest.json`과 `SHA256SUMS`에 기록합니다. 1.0.0 산출물과 아래 검증 기록은 이전 통합 버전의 이력입니다.

## Quaygate 1.0.0 통합 검증 이력

이 파일은 새 통합 제품의 검증만 기록합니다. 이전 Mobile Audit과 Quaygate의 실기기 실행·독립 리뷰 결과는 `docs/legacy/`의 이력이며, 통합 변경에 대한 새 독립 승인으로 간주하지 않습니다.

통합 패키지는 소스 분석과 취약점 대조, 두 APK/IPA 정적 엔진, TUI·CLI·MCP, 공통 이력·CI 정책·지속 작업을 포함합니다. 형제 저장소에 실행 시 의존하지 않습니다. 기존 Mobile Audit 저장소와 staged 파일은 보존합니다. 기존 데이터는 동일한 저장 위치와 schema에서 읽습니다.

검증 결과: 기존 466개와 통합 검증 12개를 합친 **478개 테스트 통과**, Ruff 검사·포맷과 Pyright 오류 0건, 기존 범위의 수작업 corpus **31/31 일치**입니다. corpus는 Quaygate의 모든 규칙이나 실제 앱 탐지율을 대표하지 않습니다. 실제 SDK 컴파일 DEX/APK fixture와 생성 Mach-O/IPA를 사용하며, MCP stdio와 persistent job을 통해 두 엔진의 근거가 같은 보고서에 저장되는지 확인합니다. 테스트는 통합된 CLI/TUI/MCP·지속 작업, 입력 경계와 정책·보고서 무결성 회귀를 검증합니다.

배포 패키지의 반복 빌드·새 환경 검사 결과와 파일 해시는 `dist/quaygate-1.0.0/release-manifest.json` 및 `SHA256SUMS`에서 확인합니다. 이 manifest가 생성되려면 두 빌드의 wheel/sdist가 일치하고, 새 환경에서 소스·두 APK 엔진·MCP stdio 검사가 통과해야 합니다.

이 통합 작업에서는 새 실기기 시나리오나 모델별 클라이언트 설정을 실행하지 않았습니다. 공개 피드의 수집·재평가 기능은 기존 엔진을 그대로 통합했고, 이번 기능 변경 검증은 캐시/fixture 기반입니다. 외부 배포·업로드는 하지 않습니다.
