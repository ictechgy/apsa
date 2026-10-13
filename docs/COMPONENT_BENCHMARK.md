# Gitleaks and OSV-Scanner component comparison

This benchmark evaluates two narrow APSA components using new synthetic inputs.
It supplements the MobSF and Semgrep experiments; it is not a whole-product
ranking, proof of credential validity, or proof that a dependency is safe.

## Frozen tools and inputs

- Gitleaks 8.30.1: official Linux x64 release archive SHA256
  `551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb`.
- OSV-Scanner 2.7.0: official Linux amd64 executable SHA256
  `160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b`.

The pins were checked against the official release APIs on 2026-10-13:
[Gitleaks](https://api.github.com/repos/gitleaks/gitleaks/releases/tags/v8.30.1)
and [OSV-Scanner](https://api.github.com/repos/google/osv-scanner/releases/tags/v2.7.0).
These release records are mutable. Acquisition requires the predeclared digest,
the published checksum manifest, the exact expected byte count, and a mutation
rejection control before extraction or execution. This verifies pinned bytes;
it does not claim independent vendor-signature verification.

The driver generates provider-shaped fake credentials and controls with an
altered, non-provider prefix, plus four CycloneDX SBOMs. The negative secret
controls do not claim identical length or entropy to the positive controls.
The driver hashes input bytes and scoped labels before the first execution.
No existing app, credential, account, repository history, or runtime data is an input.

Dependency labels concern only these advisory/version pairs:

| Package | Affected control | Unaffected control | Target advisory |
| --- | --- | --- | --- |
| Maven org.apache.logging.log4j:log4j-core | 2.14.1 | 2.17.1 | [GHSA-jfh8-c2jp-5v3q / CVE-2021-44228](https://osv.dev/vulnerability/GHSA-jfh8-c2jp-5v3q) |
| npm lodash | 4.17.20 | 4.17.21 | [GHSA-35jh-r3h4-6jhm / CVE-2021-23337](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) |

Other advisory matches are retained separately. Target identity uses the primary
OSV record ID, not a flattened union of IDs and aliases. If a different primary
record shares a target alias, an otherwise negative result is ambiguous and is
excluded from TP/FP/FN/TN. Record identities, aliases, and affected-range metadata
remain available for inspection. An unaffected control here does not assert
absence of every vulnerability. Both tools query the live public OSV service
during the same run; network and database drift remain limitations.
Only these public synthetic coordinates are sent. No private coordinates or app
source are uploaded.

## Completion and measurement contract

Gitleaks uses its shipped default rules, redacted JSON output, and finding exit
code 10 so errors cannot be mistaken for findings. Its output must identify the
expected file, line, and provider rule. APSA uses the matching source credential
component and must report checked coverage. These are format candidates, never
validated live credentials.

OSV-Scanner uses source scanning, all-packages output, explicit SBOM selection,
and disables dependency resolution and Go call analysis. A clean result must
still contain the exact expected package coordinate. APSA parses the same SBOM
and uses a new Store for every query. Each package must be completely checked;
missing output, logged errors, API failures, partial results, unsupported input,
or an unexpected cache hit do not establish a completed negative result.

Only completed, unambiguous results contribute TP/FP/FN/TN. Support scope is declared before
execution. Repetitions measure stability and retain each command's exit status
and bounded stdout/stderr separately. Subprocess latency and in-process component
latency are different scopes. Online dependency timings include OSV service
latency. Unmeasured RSS stays null; no speed or memory-efficiency ranking follows.

## Running

The dedicated component-benchmark workflow performs acquisition and execution
on a new hosted Linux runner. Locally, regression tests use only freshly generated
synthetic byte streams and mocked process/HTTP contracts; they require no download
or device access. Actual benchmark execution is a separate gate.

```sh
python -m scripts.acquire_component_tools --out "$RUNNER_TEMP/component-tools"
PYTHONPATH=.:src python benchmarks/component_compare.py \
  --tools "$RUNNER_TEMP/component-tools/manifest.json" \
  --out "$RUNNER_TEMP/component-results" --repetitions 3 --online
```

Console records bind actual executable hashes, versions, inputs, measurements,
and source revision. Uploaded artifact metadata and its digest can be correlated
with the upload output without treating an unopened ZIP as inspected evidence.
The workflow removes only its own newly generated tools and temporary state.

## Observed alias ambiguity

The first actual run on 2026-10-13 preserved an apparent false positive on lodash
4.17.21 for both tools. Inspection showed that the newer primary record
[GHSA-r5fr-rjxr-66jc](https://osv.dev/vulnerability/GHSA-r5fr-rjxr-66jc)
shares CVE-2021-23337 and the older GHSA ID as aliases, while its affected range
differs. The original flat alias scorer conflated the two records. Those v1
observations are retained as invalid scoring evidence, not a tool accuracy claim.

The original cases, versions, and expected labels remain unchanged. The revised
scorer preserves shared-alias ambiguity as inconclusive, including a nonzero
measurement gate when a case cannot be scored. It does not relabel that package
as safe, suppress its newer advisory, or claim a false positive from either tool.
