# Model and team workflows

English is the source for this 1.1 contract. These features use the existing local audit engine and do not establish production detection rates.

## Bounded model context

`apsa context --report REPORT_ID --section findings --cursor 0 --limit 20 --max-bytes 65536 --json` and MCP `reports_get` return a summary and one section page. Sections are `findings`, `coverage`, `environment_advisories`, `intel_snapshot`, `runtime`, and `warnings`. Findings can be filtered by `severity` and `status`. Limits are 1–100 records and 4–256 KiB of UTF-8 JSON context; the default is 20 records and 64 KiB. CLI envelopes and MCP transport framing are additional bytes. Source excerpts are excluded recursively.

Resolve `latest` once, then use the returned `report_id` for every page. Keep the section and filters unchanged, and pass `page.next_cursor` until it is null. A numeric cursor indexes that immutable report's filtered section; changing reports or filters starts a different traversal. `section_counts` counts unfiltered records, while `page.total` counts the selected, filtered section. A finding ID selects its evidence pages; section and finding filters cannot be combined with that mode.

`partial_response` describes remaining or omitted page content. `audit_incomplete` describes audit execution independently. Always inspect coverage, including optional `not-run` checks; a complete execution is not a claim that every mobile security property was verified. When metadata is too large, `metadata_truncated` is explicit and report identity plus audit completeness remain. A record that cannot fit is omitted explicitly in `page.oversized_indices`, and the cursor advances. Retrieve it from a local JSON export. Report resources return the first bounded page; use the tool to continue.

`dependency_check` also bounds its error sample, preserving the full error count and an explicit truncation flag. Runtime execution returns a bounded runtime context; local report exports preserve all saved evidence.

## Portable approved baselines

Export a completed audit for one explicit app identity:

```sh
apsa reports export REPORT_ID --format baseline --out approved-baseline.json \
  --approved-by 'Team reviewer' --approval-reference 'review/123'
```

The artifact includes a sanitized report, report digest and approval provenance. The exporter returns the SHA-256 of the exact artifact bytes. Record that hash in independently reviewed CI configuration; it is the external trust anchor. Computing the expected hash from the downloaded baseline within the same untrusted CI step would not establish approval. Approval fields are recorded assertions, not identity authentication or a digital signature. Export rejects partial audits, incomplete fingerprints and multiple app identities. Optional checks that did not run still require separate policy requirements.

```sh
apsa scan ./owned-app --policy apsa.toml \
  --baseline-file approved-baseline.json --baseline-sha256 APPROVED_SHA256 \
  --out audit.json --json
```

The same artifact works in a fresh APSA store. Import requires a pinned byte hash, supported schema, valid internal report digest and approval provenance. Baselines from another app or source selection yield an incomplete policy decision. Stronger evidence, increased severity and new locations still reopen findings. In MCP, use `reports_export_baseline` with an existing output parent inside authorized roots. It creates a new file and refuses overwrite. `policy_evaluate` accepts the corresponding `baseline_path` and `baseline_sha256`; both inputs remain subject to root authorization.

## Exported policy decisions

`scan --policy FILE --out audit.json` writes `audit.json.decision.json` alongside the requested report format. `--decision-out PATH` selects a different decision path. `policy evaluate` can export a decision with the same option. The artifact contains the report digest, normalized policy and its digest, baseline approval/hash provenance, gate state, reasons, and active/expired waivers. Store both report and decision before interpreting exit codes: 0 passes, 3 is incomplete and 4 exceeds policy thresholds. Exports are local artifacts; no approval or signature is fabricated.

## Explicit source configuration

```sh
apsa scan ./repository --source-module app \
  --configuration src/release/AndroidManifest.xml --json
```

The module must be a normalized relative directory without traversal or symlinks. The configuration must be a readable `AndroidManifest.xml` or `.plist` file relative to that selected module. Only that file supplies app configuration/identity; source and dependency analysis still covers the selected module. The report records both module and configuration. Missing, unreadable, excluded and malformed selections fail explicitly. Foreground and persistent background audits share this contract.

Multiple configuration files or distinct declared app identities within one platform make an unselected source audit incomplete; configuration findings remain candidates. One Android and one iOS configuration can still be audited together, but portable baseline export requires selecting one app. This selection does not merge Gradle manifests, resolve build flavors, substitute Xcode variables, or prove which configuration ships. Use the final APK/IPA or resolved build evidence for that assurance. Select matching module/configuration scopes when comparing approved source baselines.

Source directories and source ZIPs also discover named plists through literal `INFOPLIST_FILE` declarations in `.xcodeproj/project.pbxproj`. Paths are relative to the project directory; only leading `$(SRCROOT)/` or `$(PROJECT_DIR)/` (and their brace forms) are recognized. References must point to already inspected, bounded files inside the input. Unsupported variables, traversal and unavailable files leave incomplete evidence. The report retains reference path/line provenance. This follows [Apple's project-relative setting](https://developer.apple.com/documentation/xcode/build-settings-reference) but does not evaluate Xcode settings or generate/merge the shipped plist. IPA and `.app` identity still require their main `Info.plist`.

Only standalone string dependency coordinates are interpreted; concatenation, casts, method calls and trailing closures remain unknown. Groovy dependency versions consisting solely of `$name` or `${name}` can use one unambiguous literal from a top-level `ext`/`project.ext` closure in an ancestor `build.gradle`, stopping at the nearest inspected `settings.gradle`/`settings.gradle.kts` project boundary. Conflicts, other code uses of the property, dynamic or conditional definitions and unavailable or unresolved imported scripts abstain. Literal relative `apply from` scripts are inspected from the same bounded source input, with cycle and file-count limits; they are never executed. Incomplete input traversal or malformed declarations leave variables unresolved. `version_expression` and `version_source` retain the declaration and definition path/line; confidence stays `declared`, never a resolved build version. Use a lockfile or SBOM for exact installed versions. Swift OSV queries use a validated scheme-free repository name while preserving the original inventory/query-match identity, consistent with the [SwiftURL ecosystem](https://ossf.github.io/osv-schema/) and [OSV's extractor guidance](https://github.com/google/osv-scalibr/issues/1966).
