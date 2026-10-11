# Five remaining validation gates

2026-10-11. User scope: NEW synthetic apps only. Software remains 1.5.1;
rule version remains `2026.10.11.apsa.next`. No release, tag, publication or
published MCP baseline approval is implied by this work.

The continuation that executes the external gates is recorded in
[FINAL_VALIDATION.md](FINAL_VALIDATION.md). Its newly measured results are
separate from the local-only snapshot below.

## Measured results and remaining gates

| Gate | Implemented and measured | Remaining validation |
| --- | --- | --- |
| 1. Release | Source staging prunes protected directories before descent; declared public fixture sources/contracts only. New Java/D8/AAPT2 APK smoke inputs, binary-XML parser checks and provenance. Actual staged build attempts recorded. Real stdio manifest capture driver and fresh CI workflow added. | Local Hatchling/frontend unavailable; installed-wheel smoke and actual served MCP blocked. CI has not been run for this snapshot. Protected prompt paths are excluded from staging; allowed-source subset is not a complete-runtime proof. |
| 2. Competitors | Fresh 40 source controls plus 6 genuinely compiled/signed APKs with exact build evidence. Semgrep CE 1.179.0 adapter, two upstream Git-blob-pinned Java crypto rules, strict scanned-target/error checks and explicit abstention. CI retains dependency/rule/tool invocation evidence. | MobSF/Semgrep executables unavailable locally. No cross-tool accuracy, speed, or RSS ranking. Four APSA component cases remain partial: 2 alerts and 2 no-alert observations; Semgrep is unmeasured. The other 42 inputs are outside this two-rule component slice. |
| 3. APK sets | Actual AAPT2 base/French configuration split, same resource ID with different default/French values; both signatures verified by apksigner. Typed APK-set selector remains bounded and partial. | No installed bundletool JAR found at known tool locations. Bundletool selection equivalence, installed split set, and merged runtime resource lookup unmeasured. No fabricated `.apks` or `toc.pb` oracle. |
| 4. IPA | Fresh compiled iOS simulator app: codesign accepts intact and individually signed nested code; rejects plist, main executable and nested executable mutation. Bound transcript consumer validates input/tool/environment/stream consistency. APK DEX mutation is also rejected by apksigner. | Ad-hoc signing does not prove Apple signer/team, provisioning authorization, installation suitability or revocation. Submitted transcripts remain caller-attested. |
| 5. Acquisition | Compiled JAR processes: Android/iOS login, switch and logout, 6/6 synthetic workflows. New dedicated iOS simulators: 3/3 instrumented workflows with actual installed executable/Info hashes, fresh session/storage and nonce-bound app handler responses. All returned new simulator IDs removed. | iOS delivery measured through fixture argv handler; OS deep-link routing unmeasured. Android installed-device acquisition, physical devices and real HTTP backend invalidation unmeasured. IPC backend model does not prove HTTP transport. |

Authoritative fresh evidence root:
`/private/tmp/apsa-five-gates-pvymuo7d`.

- Package: `package-gate2-evidence.json`, `evidence/actual-release-offline-attempt.json`, `package-compiled-manifest-fixtures/fixture-provenance.json`.
- Competitors: `competitive-fixtures/{manifest,compiler-provenance}.json`, `semgrep-local/result.json`.
- Artifacts: `artifact-oracles-canonical`, `compiled-split-oracles`, `official-artifact-evidence.json`.
- Runtime: `gate5-jvm-binding-final/{summary,binding-hardening-summary}.json`, `gate5-simulator-argv/summary.json` and per-case recorder evidence. `gate5-acquisition-summary.json` records the previous sealed group plus unchanged simulator observations.
- Full regression/static results: `evidence`. Source review artifacts live under `work/reviews/2026-10-11-five-gates`.

## Contracts and interpretation

The proposed tool manifest lives in `tests/contracts/mcp_tool_manifest_pending.json`.
Its hashes are source AST/Pydantic expectations, not actual served SDK evidence.
`scripts/served_mcp_manifest.py` initializes the real stdio server, captures
`tools/list` for both runtime settings, and compares these proposed hashes.
The capture never approves a published baseline. The fixture records the
published HEAD hashes separately.

`artifact_oracle.validate_artifact_observation` requires independently expected
input hashes, command, environment and tool hash. Self-consistent JSON cannot
authenticate a transcript. It never promotes a pass into installation/resource
merge/Apple policy/revocation proof. Mutation observations retain raw bounded
streams and exact tool/source/compiler hashes.

Compiled host models use `runtime_model_sha256`, never `apk_sha256`.
Model-only binding is unavailable by default. Only a recorder with a validated
typed synthetic session promotes it; instrumented sessions and pre-promoted
caller input are rejected. A failed capture revokes model-only binding, and
workflow evaluation uses the recorder's final binding.
The iOS installed fixture uses actual executable and Info.plist hashes.
Network/UI/log surfaces are unsupported or partial where they were not captured;
storage success does not make backend session invalidation pass.

Native source patterns cannot claim completed coverage from APK/IPA manifest or
native-source members. Actual packaged hybrid text remains eligible. Immutable
Java field material, ZipEntry identity and same-input guards have new regression
coverage. A `../`-only guard retains a candidate because it misses bare `..`.
Undefined external receiver calls keep analysis/claim verification partial.

## Privacy and test limits

All canonical measurements use public source and newly generated inputs outside
the checkout. Existing user data/devices/apps were not enumerated. An initial
legacy full-suite benchmark read retained public test binaries; its tests were
then changed to freeze new compiled fixture bytes before measurement. The fresh
replacement of the upstream control reuses safe bytes and is explicitly not an
independent accuracy sample. Historical labels/results were not relabeled as
fresh evidence.

This host blocks child RSS inspection. Local regression uses a temporary,
test-only adapter limited to staged synthetic parser inputs and fresh job/demo
children. It does not change production process limits or the OS privacy guard.
The real RSS-enforcement test skips on `psutil.AccessDenied`; memory enforcement
and RSS measurements remain unvalidated here. SDK-dependent MCP tests are kept
separate from local non-MCP checks. No fake SDK substitutes a served check.

The new workflows are prepared validation paths with read-only repository
permissions. They are not evidence of a successful remote run. Native permission
profile activation is not claimed; no hooks/list/profile API was exposed.

The full local non-MCP regression completed with 1,568 passed, 4 skipped and
26 deselected tests. This result used newly compiled AAPT2/D8 inputs and the
temporary RSS adapter described above. It does not include a served MCP check,
clean installed package, remote CI run or a real RSS measurement.
The real `scripts/release.py --offline` invocation staged source and created a
new builder environment, then failed resolving Hatchling from an exclusively new,
empty cache. It neither consumed an existing cache nor produced a package.

## Primary references

- [Semgrep CE release 1.179.0](https://github.com/semgrep/semgrep/releases/tag/v1.179.0)
- [Semgrep CLI options](https://docs.semgrep.dev/cli-reference)
- [Semgrep local metrics policy](https://github.com/semgrep/semgrep/blob/develop/metrics.md)
- [Upstream Semgrep CE rules](https://github.com/semgrep/semgrep-rules)
- [Bundletool commands](https://developer.android.com/tools/bundletool)
- [Apple code signing certificates and policy](https://developer.apple.com/documentation/technotes/tn3161-inside-code-signing-certificates)

Exact immutable Android upstream references and facts versus inference are in
`official-artifact-evidence.json`; current observations do not establish a
competitor ranking or Apple policy verdict.
