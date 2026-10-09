# APSA

**Evidence-first security audits for Android and iOS.**

[English](https://github.com/ictechgy/apsa/blob/main/README.md) · [한국어](https://github.com/ictechgy/apsa/blob/main/README.ko.md)

This English README is the source of truth. The Korean README follows it.

<!-- mcp-name: io.github.ictechgy/apsa -->

APSA helps developers and security teams audit their own mobile apps. It inspects source code and APK/AAB/IPA builds, correlates public vulnerability information, and keeps evidence, coverage, and report history together. Use the CLI, terminal UI, or the same audit engine through MCP and reusable skills.

Pronounced **“ap-sah”**; Korean name **앱사**. The name connects “app + audit” with **App Security Audit**. APSA combines the earlier Quaygate lint engine and Mobile Audit workflows in one package.

APSA 1.1 adds bounded model report pages, portable approved baselines, exported policy decisions, and explicit source module/configuration selection. See [model and team workflows](docs/MODEL_WORKFLOWS.md) for the contract and [release sequence](docs/ROADMAP.md) for later analysis milestones.

Mixed unsupported source languages and truncated pattern results are incomplete. Declared Gradle versions remain candidates until resolved-build evidence is supplied. OS-CVE correlation reports a bounded recent window, so feed freshness alone cannot satisfy historical coverage.

APSA 1.2 adds AAB base-manifest/module DEX analysis, embedded IPA Mach-O
metadata, bounded Objective-C `.m` candidates and parser OS isolation that is
on by default where it can start.
Every AAB audit stays partial, and embedded IPA metadata does not authenticate
signatures. See [analysis scope and limits](https://github.com/ictechgy/apsa/blob/main/docs/NEXT_ANALYSIS.md) and the
[independent holdout](https://github.com/ictechgy/apsa/blob/main/benchmarks/NEXT_RESULTS.md).

**Upgrading from 1.1.** With the default `APSA_PARSER_SANDBOX=auto`, the parser
runs under macOS Seatbelt or Linux bubblewrap after an input-free activation
probe succeeds. Without a backend, the report records
`parser_isolation.state: unavailable` and parses with resource limits only. If
the backend is present but cannot start (for example inside another sandbox or
with blocked user namespaces), the report also records the attempted backend
and probe reason and adds an inventory warning. `required` refuses such audits; `off` skips the backend. A parser
failure after isolation has started aborts the audit without an unsandboxed
retry. Dependencies declared only in a Gradle version catalog no longer receive
CVE matches until build usage or resolved versions are supplied. New rules
(`AST-CRYPTO-ECB`, `AST-CRYPTO-WEAK-HASH`, `AST-SQL-CONCAT`,
`OBJC-CRYPTO-WEAK-HASH`, `OBJC-WEBVIEW-UNTRUSTED-REQUEST`) can add findings
relative to existing 1.1 baselines.

APSA 1.3 links Gradle version-catalog aliases to the shipped dependency
configurations that use them and reads application-module `gradle.lockfile`
coordinates as resolved versions. It also decodes AAB feature-module manifests,
recomputes Mach-O CodeDirectory page and entitlement hashes without
authenticating the signature, adapts more Swift and Objective-C syntax, and can
backfill an explicit range of Android security bulletins with SoC vendor and
vendor patch-level context. See the
[dependency evidence results](https://github.com/ictechgy/apsa/blob/main/benchmarks/DEPENDENCY_RESULTS.md),
the [independent source pairs](https://github.com/ictechgy/apsa/blob/main/benchmarks/FPFN_RESULTS.md)
and [analysis scope and limits](https://github.com/ictechgy/apsa/blob/main/docs/NEXT_ANALYSIS.md).

**Upgrading from 1.2.**

- Catalog aliases referenced from shipped configurations become `declared`
  candidates and can receive CVE matches again; unreferenced, test-only and
  build-tooling aliases stay unresolved. Application-module lockfile coordinates
  are exact, so their matches are `version-affected`, and the default policy
  fails on high and critical ones; other modules' lockfile coordinates stay
  `declared` candidates. A declared candidate that every shipping application
  resolved is superseded and leaves CVE correlation. Partial inputs keep every
  candidate, and with unparsed project references only an application's own
  declarations can be superseded.
- Lockfile assumptions: APSA does not check that dependency locking is enabled
  or that the lockfile is current, and it merges the release runtime classpaths
  of every application module (flavors and wear, TV or automotive apps).
  `--source-module` scans only that module's directory, so a root version
  catalog and library-module declarations outside it are not read.
- Baselines and waivers: a lockfile-resolved finding has a new location
  (`gradle.lockfile`) and status, so `only_new` treats it as new and waivers for
  the old finding ID no longer match. Re-approve baselines after upgrading.
- `--online` sends catalog aliases used in shipped configurations and the
  release-runtime lockfile coordinates of every module, transitive ones and
  private group IDs included, to OSV; there is no exclusion list. One run
  queries at most 100 packages: those without an OSV result from the last day
  first, and among them build-file declarations before lockfile coordinates in
  lockfile order. Measured application lockfiles hold 179–412 shipped
  coordinates, so a single run leaves the rest `not-run`: a required
  `DEPENDENCY-CVE` rule cannot pass, the online audit is incomplete and the
  default `fail_on_partial` policy exits 3. Repeated runs within a day advance
  through the remainder, and a package with an OSV result from the last day
  counts as checked. Unresolved catalog aliases and ecosystems OSV does not
  support are reported as online errors on every run, so they keep the online
  audit incomplete however many runs follow.
- IPA reports gain `BINARY-IOS-CODE-INTEGRITY`. Consistent hashes do not prove
  authenticity, because a modified binary that was re-signed is consistent. A
  mismatch adds a warning, not a finding; App Store encrypted and unsigned
  executables stay `not-run`.
- `intel sync` refreshes only the recent Android bulletin window; use
  `intel backfill` for older months. Records cached by 1.2 derive their vendor
  scope from the component name; entries outside chipset and kernel sections use
  the platform patch level only. AAB feature-module installation stays unknown.
- Adapted Swift and Objective-C files stay partial, and an Objective-C function
  overlapping a normalized preprocessor conditional is skipped as uncertain.
  Unmodified 1.2 skills upgrade with `apsa skill install`.

APSA 1.4 is easier to put in front of developers and coding agents. A GitHub
Action uploads SARIF to code scanning with stable fingerprints, security
severity, MASWE tags and evidence status; every report carries an
[OWASP MASWE v1.0](https://mas.owasp.org/MASWE/) coverage matrix that names the
weaknesses APSA did not assess; and the MCP server is packaged for the MCP
Registry and as a Claude Code plugin, with a documented
[MCP security model](https://github.com/ictechgy/apsa/blob/main/docs/MCP_SECURITY.md).

**Upgrading from 1.3.** SARIF exports now list a descriptor for every rule with
results (help, `security-severity`, precision, MASVS/MASWE tags), add
`partialFingerprints` from the finding identity, report not-run and partial
coverage as tool execution notifications, and use `--sarif-root` to make
locations repository-relative; binary findings point at the APK/AAB/IPA with the
archive member as a logical location. Code scanning may therefore show
re-keyed alerts once. Rule metadata gains MASWE v1.0 identifiers, model context
and `capabilities` gain a `maswe` section, and Markdown reports gain a MASWE
coverage table. Unmodified 1.3 skills upgrade with `apsa skill install`.

## What it checks

| Area | Available checks |
| --- | --- |
| Source code | Java/Kotlin/Swift AST analysis; bounded Objective-C `.m` candidates; WebView and deep-link patterns; Manifest, Info.plist, storage, and dependency inspection, including Gradle catalog usage and application lockfiles; exported components, backup and targetSdk; Apple required-reason APIs against privacy manifests; known credential formats (masked); weak random for security values; mutable implicit PendingIntents |
| Android builds | DEX calls and constant flow; AAB base and feature-module manifests and module DEX (always partial); resources and network configuration; exported components/providers; signing-block and v1 certificate evidence; ELF hardening |
| iOS builds | Mach-O headers, including embedded framework/extension metadata; CodeDirectory page and entitlement hash integrity (not signature authentication); limited entitlement/configuration checks (embedded XML entitlements, ATS exceptions, provisioning indicators); PIE, canary, and string evidence |
| Public intelligence | Apple/Android advisories with bounded Android bulletin backfill, CVE, CISA KEV, OWASP guidance, and OSV dependency correlation |
| Reports and CI | SQLite history, comparison and reassessment, JSON/Markdown/SARIF export, coverage requirements, and expiring waivers |
| Runtime | Prepared scenarios for owned Android test apps and iOS simulator apps; physical iOS devices are unsupported |
| Model integration | stdio MCP tools/resources and packaged skills, without a required model provider or LLM API key |

Findings distinguish `candidate`, `configuration-confirmed`, `version-affected`, and `runtime-confirmed` evidence. `coverage` and warnings show what actually ran. A signing block does not prove signature authenticity, and an affected dependency version does not prove exploitability. A scan with no findings does not establish that the whole app is secure.

OWASP mappings describe relevant checks; APSA does not certify MASVS compliance or implement every MASTG test. Public advisories cannot reveal undisclosed zero-days. App files alone cannot establish a device's OS patch state. See [OWASP coverage](https://github.com/ictechgy/apsa/blob/main/docs/OWASP_COVERAGE.md) and the [support matrix](https://github.com/ictechgy/apsa/blob/main/docs/SUPPORTED_MATRIX.md), both currently in Korean, for tested scope and limits.

## Install and run

Install **uv** on **macOS or Linux**. APSA targets **CPython 3.11 and 3.12**; not every host/Python combination has been tested (see the [support matrix](https://github.com/ictechgy/apsa/blob/main/docs/SUPPORTED_MATRIX.md)). The examples select Python 3.12, which uv can download if needed. Initial installation can use the network; scans can then use local inputs and cached intelligence.

Install the published package from [PyPI](https://pypi.org/project/apsa/):

```sh
uv tool install --python 3.12 apsa==1.4.0
apsa --version
apsa doctor --json
apsa demo --out ./apsa-demo
```

The package provides `apsa` and the compatibility aliases `quaygate` and `mobile-audit`. If the command is not found, run `uv tool update-shell` and open a new terminal. [GitHub Releases](https://github.com/ictechgy/apsa/releases) provides the wheel, source distribution, checksums, and a verified bundle with locked requirements, attribution, and the build manifest.

For development or installation with the repository's locked dependencies, use a checkout:

```sh
git clone https://github.com/ictechgy/apsa.git
cd apsa
uv sync --locked --python 3.12
uv run --locked apsa doctor --json
uv run --locked apsa demo --out ./apsa-demo
```

`doctor` checks parsers, optional device tools, and offline readiness. `demo` writes an intentionally vulnerable example and scans it; choose a new output directory.

To register the checkout's commands on your PATH:

```sh
uv tool install --editable . --force --python 3.12 --constraints requirements-release.txt
apsa --version
```

This registers `apsa` and the compatibility aliases `quaygate` and `mobile-audit`. `--force` replaces existing tools with those command names. An editable installation depends on this checkout; keep it in place. If the command is not found, run `uv tool update-shell` and open a new terminal. The examples below assume `apsa` is on PATH. Without a global installation, prefix them with `uv run --locked` from the checkout.

```sh
apsa scan /path/to/owned/mobile-project
apsa scan /path/to/owned/app.apk
apsa scan /path/to/owned/app.ipa --sbom /path/to/build.cdx.json
apsa tui
```

Use a CycloneDX JSON SBOM from the actual build to improve dependency correlation. `tui`, or `apsa` without arguments, opens the terminal interface. Run `apsa COMMAND --help` for options.

## Public intelligence and network use

A default `scan` reads local files and cached intelligence without uploading source code or builds. Public-feed collection and OSV queries use the network:

| Command | Network behavior |
| --- | --- |
| `apsa scan TARGET` | Uses local inputs and cached intelligence |
| `apsa intel sync` | Fetches public vulnerability sources |
| `apsa intel watch` | Polls public sources and reassesses saved inventories; does not reread app files or implicitly query OSV |
| `apsa intel backfill --source android --since YYYY-MM` | Fetches an explicit, bounded range of monthly Android security bulletins |
| `apsa scan TARGET --online` | Sends discovered dependency names and versions to OSV, including Gradle catalog aliases used in shipped configurations and release-runtime lockfile coordinates of every module; at most 100 packages per run, unchecked build-file declarations first |
| `apsa intel watch --online` | Also sends saved dependency names and versions to OSV, with the same budget |

```sh
apsa intel sync
apsa intel status
apsa intel watch --interval 900
apsa scan /path/to/owned/app --online
```

Watch polls every 900 seconds by default, with a 60-second minimum; it is not a push stream. It runs until interrupted unless `--cycles` sets a finite number of polls. Reassessment saves a new snapshot when findings, coverage, or intelligence state changes. Inspect feed freshness, failures, and pending CVE processing with `intel status`. Fetching a CVE document and completing its processing are separate states. The default pending-item policy allows no backlog; use `intel_max_pending` to set an explicit allowance.

```sh
apsa reports reassess latest
apsa reports compare audit_BEFORE audit_AFTER
apsa reports export latest --format sarif --out audit.sarif
apsa reports verify
```

Reassessment applies current intelligence to a saved inventory; run `scan` again for changed files or new static checks. If connected to an AI client, that client may send report metadata to its model provider. APSA's MCP context excludes source excerpts, full source files, and screenshot bytes; client-side data handling still depends on the client.

## CI and background jobs

```sh
apsa policy init --out apsa.toml
apsa scan /path/to/owned/app --policy apsa.toml --out audit.json
apsa scan /path/to/owned/app --fail-on high --include-candidates
apsa scan /path/to/owned/app --background --json
apsa jobs status JOB_ID --json
```

Severity gates exclude `candidate` findings by default. Opt in with `--include-candidates` or the policy's `allowed_statuses`. Required rules accept only `checked` or `not-applicable` coverage; partial execution and missing required checks do not pass. Waivers need a finding ID, a reason, and an expiry date. A background job being `completed` means it finished; check its `audit_incomplete` flag and report before treating the audit as complete.

Unreadable source directories and files leave warnings and incomplete coverage; a source tree with no readable supported files fails explicitly. Storage capture failures remain `not-run` and cannot establish that a canary was deleted.

| Exit code | Meaning for the unified CLI |
| --- | --- |
| `0` | Command completed or policy passed |
| `1` | Execution error |
| `2` | Invalid arguments |
| `3` | Incomplete audit or policy, failed report verification, or failed or partial intelligence synchronization |
| `4` | Findings exceeded the configured CI threshold |
| `130` | Interrupted |

`--json` emits an envelope containing `ok`, `data` or `error`, and `exit_code`; watch emits one JSON envelope per cycle (NDJSON). `ok` is `true` for codes `0` and `4`; code `4` means evaluation succeeded but the CI threshold was exceeded. CI must check `exit_code` and the policy result. Reports may still be produced for codes `3` and `4`.

### GitHub code scanning

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: ictechgy/apsa@<commit-sha> # v1.4.0; pin the full commit SHA
    with:
      path: android            # source folder, or a built APK/AAB/IPA in the workspace
      fail-on-incomplete: "true"
```

The action installs `apsa` from PyPI at the matching version, runs `scan` with
`--format sarif --sarif-root`, writes a job summary, uploads the SARIF file to
code scanning and then applies the exit code: `4` fails on a policy or
threshold, `3` fails on an incomplete audit unless `fail-on-incomplete` is
`"false"`. Use `policy` (with `baseline-file` and `baseline-sha256`) for team
gates, or `fail-on` for a severity threshold that excludes candidates.
`intel-sync` fetches public advisories first; `online` sends dependency names
and versions to OSV (see [network use](#public-intelligence-and-network-use)).
Private repositories need GitHub Code Security to upload SARIF; set
`upload-sarif: "false"` to keep only the file. Alerts uploaded to code scanning
can receive GitHub's AI fix suggestions where that feature is enabled; APSA's
evidence status stays in each alert's properties.

Without the action:

```sh
apsa scan android --format sarif --out apsa.sarif --sarif-root android
apsa reports export latest --format maswe --out maswe.json
```

See the [CI example](https://github.com/ictechgy/apsa/blob/main/docs/ci-example.yml) and [operations guide](https://github.com/ictechgy/apsa/blob/main/docs/OPERATIONS.md) (Korean) for policies, backup, limits, and troubleshooting.

## MCP and skills

```sh
apsa integrations --root /absolute/path/to/owned-apps
apsa mcp --root /absolute/path/to/owned-apps
apsa skill install
apsa context --report latest --section findings --limit 20 --json
```

Use `integrations` to generate a configuration with the installed executable path, or a `python -m apsa` fallback when no `apsa` executable is found. The shape below is illustrative; replace both absolute paths:

```json
{
  "mcpServers": {
    "apsa": {
      "command": "/absolute/path/to/apsa",
      "args": ["mcp", "--root", "/absolute/path/to/owned-apps"]
    }
  }
}
```

### Install for agents

| Client | Install |
| --- | --- |
| Claude Code | `/plugin marketplace add ictechgy/apsa`, then `/plugin install apsa@apsa`. The plugin runs `uvx --python 3.12 apsa@VERSION mcp --root <current project>` and adds the skill. |
| Any MCP client | Use the configuration from `apsa integrations`, or the MCP Registry entry `io.github.ictechgy/apsa` (PyPI package, `uvx`, required `--root`). |
| Codex and other skill runtimes | `apsa skill install`, plus the `integrations` configuration. |

Claude Code 2.1.295 and Codex CLI 0.162.0 were each verified calling
`capabilities` and `audit_scan` on a freshly generated synthetic project. Other
clients are not yet verified.

MCP uses stdio and requires an explicit `--root`; repeat it for multiple roots. `integrations` defaults to the current directory when no root is supplied. Roots restrict audited targets and access to their reports and jobs. `--allow-any-root` explicitly removes that restriction. APSA does not change model-client configuration automatically; client authentication belongs to the client.

| Purpose | MCP tools |
| --- | --- |
| Audits | `capabilities`, `audit_scan`, `audit_start`, `audit_reassess`, `verify_finding`, `specs_validate` |
| Jobs | `jobs_list`, `jobs_status`, `jobs_cancel` |
| Reports | `reports_list`, `reports_get`, `reports_compare`, `reports_export_baseline` |
| Intelligence | `intelligence_sync`, `intelligence_search`, `intelligence_get`, `dependency_check` |
| Policy | `policy_evaluate` |
| Runtime planning | `runtime_plan`, `runtime_devices` |

`verify_finding` (CLI `apsa verify`) cross-checks a finding claimed by another tool or AI reviewer against APSA's evidence and never refutes it. Project taint specifications name project-specific sources and sinks, such as a deep-link parser or an in-app browser wrapper, for APSA to follow deterministically; see [project specifications](https://github.com/ictechgy/apsa/blob/main/docs/PROJECT_SPECS.md).

`capabilities` reports `tool_manifest_sha256`, a hash of the served tool names,
descriptions, input schemas and annotations; the tool set never changes within
a process. Read-only tools are annotated read-only and idempotent, network tools
open-world. App content and advisory text are treated as untrusted data and
model context omits source excerpts; see the [MCP security model](https://github.com/ictechgy/apsa/blob/main/docs/MCP_SECURITY.md).

Resources include `apsa://rules` and `apsa://reports/{report_id}`. The previous `quaygate://` and `mobile-audit://` resource schemes remain compatible.

Report context defaults to 20 records and 64 KiB. Resolve `latest` once, then page with the returned immutable report ID and `page.next_cursor`, keeping section/filters fixed. `partial_response` describes the page; `audit_incomplete` describes execution. Oversized records are explicitly omitted and remain available in local exports. Portable baselines require explicit approval provenance and a SHA-256 pinned in reviewed CI configuration. See [workflow examples](docs/MODEL_WORKFLOWS.md).

The default server exposes runtime planning. `runtime_execute` and `runtime_start` are registered only with `--allow-runtime` at server startup. Both preview a scenario by default; `execute=true` runs it. `runtime_start` starts a cancellable background device job. Runtime tests need an authorized, prepared test app; the default audit does not boot devices or install apps. See the [operations guide](https://github.com/ictechgy/apsa/blob/main/docs/OPERATIONS.md) (Korean) before running a scenario.

`skill install` copies the packaged [APSA skill](https://github.com/ictechgy/apsa/blob/main/.agents/skills/apsa/SKILL.md) to `~/.codex/skills/apsa`. To install directly into another model runtime's skill directory:

```sh
apsa skill install --name apsa --dest /path/to/runtime/skills/apsa
```

Use `--name quaygate` or `--name mobile-audit` to update a skill installed under an older default name; custom edits are preserved unless `--force` is supplied. `integrations` reports skill status. For clients without MCP, `context` provides report context that excludes source excerpts, full source files, and screenshot bytes.

## Compatibility and stored data

`quaygate` and `mobile-audit` invoke the same unified CLI. Python entry points `python -m apsa`, `python -m quaygate`, and `python -m mobile_audit` remain available. Existing reports and `QG-*` rule IDs retain their identity.

Data is stored by default in `~/.local/share/mobile-audit`. Path precedence is `--home` → `APSA_HOME` → `QUAYGATE_HOME` → `MOBILE_AUDIT_HOME` → that default. Renaming does not copy the database or move history. Existing MCP configurations must include an authorized `--root`.

The legacy `apk`, `ipa`, and `device` subcommands retain quick lint output and exit codes `0/1/2`; they do not save unified audit history or correlate vulnerability intelligence. Use `scan` for the full workflow. Older cached OSV records without severity need a fresh `scan --online` or `intel watch --online`; reassessment alone cannot recover missing scores.

## Development, validation, and licensing

```sh
uv sync --locked --extra dev --python 3.12
make test benchmark
make export-release
make release RELEASE_OUT=dist/apsa-local-release
```

Choose a new or empty release directory. Release verification requires uv **0.12.1** and builds wheel/sdist twice, compares their hashes, and checks a clean installation outside the checkout with offline source/APK scans, MCP, and skill installation. It writes hashes, an SBOM, dependency notices, and a release manifest without publishing. Initial dependency preparation can use the network. The same-host repeat check does not claim byte-identical builds across platforms.

Tagged releases use GitHub Actions to publish the verified distributions to PyPI after the supported CI matrix passes. See [release publishing](https://github.com/ictechgy/apsa/blob/main/docs/PUBLISHING.md) for the workflow and download contents.

Recorded product validation is in [RELEASE_READINESS.md](https://github.com/ictechgy/apsa/blob/main/RELEASE_READINESS.md). The [curated benchmark](https://github.com/ictechgy/apsa/blob/main/benchmarks/README.md) is a regression corpus, not a measure of production detection rates. [Integration boundaries](https://github.com/ictechgy/apsa/blob/main/docs/INTEGRATION.md) and the [threat model](https://github.com/ictechgy/apsa/blob/main/docs/THREAT_MODEL.md) are currently in Korean. Historical reviews remain tied to their original snapshots.

A reproducible [APSA/MobSF comparison](benchmarks/COMPETITIVE.md) and its
[recorded results](benchmarks/COMPETITIVE_RESULTS.md) use freshly generated
synthetic source projects and APKs. They measure development candidates
recorded before APSA 1.2.0, not the published package; these results are not
production accuracy estimates. A rerun on the APSA 1.3.0 release runtime with
newly generated inputs reproduced the candidate figures (see
[RELEASE_READINESS.md](https://github.com/ictechgy/apsa/blob/main/RELEASE_READINESS.md)).

A separate [public-source and CVE evaluation](benchmarks/REAL_WORLD.md) records
[initial results](benchmarks/REAL_WORLD_RESULTS.md) on six pinned app source
snapshots, selected dependency/CVE units and OS advisory fixtures. It preserves
extraction gaps, scanner failures and incomplete coverage; it does not measure
whole-app security or general production accuracy.

The subsequent [hardening rerun](benchmarks/HARDENING_RESULTS.md) completes all
six source scans and closes four measured integration gaps. It reuses observed
labels and reports remaining incomplete coverage; it is a development check.

The [coverage extension](benchmarks/COVERAGE_RESULTS.md) records narrow
Swift/Kotlin compatibility, recognized function counts and Apple-evidenced
iOS/iPadOS branch decisions. Adapted source remains partial; the selected
fixtures do not establish general CVE accuracy.

The [additional analysis and independent holdout](benchmarks/NEXT_RESULTS.md)
covers AAB/IPA metadata, Objective-C, parser isolation and two independently
labeled public sources. It records selected CVE boundary agreement, unresolved
catalog usage and remaining parser gaps separately.

The [dependency evidence evaluation](benchmarks/DEPENDENCY_RESULTS.md) compares
APSA's Gradle catalog usage and lockfile coordinates with Gradle's own
resolution on three frozen holdouts of public apps, keeping first blind results
separate from reruns after the truth was seen. The
[independent source pairs](benchmarks/FPFN_RESULTS.md) score vulnerable and
fixed commits of public projects against truth frozen before scanning. Both are
narrow samples, not general accuracy estimates.

The source is publicly available on [GitHub](https://github.com/ictechgy/apsa). [LICENSE](https://github.com/ictechgy/apsa/blob/main/LICENSE) preserves the original Quaygate MIT notice. This publication does not declare an additional license for the combined product.
