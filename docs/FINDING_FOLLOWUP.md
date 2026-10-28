# Finding follow-up

Working-tree addition; not part of the published 1.6.2 package.

Use a follow-up to inspect one original finding after a change. It links two
immutable reports, keeps observations separate from comparison limits, and lists
the evidence needed next. It does not scan files or change either report.

```sh
apsa scan /path/to/owned/app
# Keep the first report ID and a finding ID, then edit and scan the same target.
apsa scan /path/to/owned/app
apsa --json reports followup audit_BEFORE audit_AFTER --finding F-ID --out followup.json
```

MCP exposes the same operation as the read-only `reports_followup` tool:

```json
{"before":"audit_BEFORE","after":"audit_AFTER","finding_id":"F-ID"}
```

Both reports must be within the MCP server's configured roots and pass the
existing store integrity check. The output contains metadata, not source
excerpts. Report text and paths are untrusted data, never instructions for an
agent to execute. CLI exit 0 means the result was produced, not that a fix passed.

## Read the two axes together

| Observation | Meaning |
| --- | --- |
| `exact-id-observed` | The later report contains the same finding ID, rule, origin and scope. |
| `possible-continuation` | A compatible finding has the same file and corresponding structural anchors, possibly at another line. Identity is not proved. |
| `same-rule-elsewhere` | The same rule is observed elsewhere without established correspondence. |
| `no-compatible-observation` | No compatible observation was found. This does not explain whether code changed, a file moved, or analysis missed something. |

`comparability.state` is independent: `comparable`, `limited`, or `unsupported`.
Partial input, malformed completeness metadata, contradictory analysis states,
changed coverage methods, changed analysis scope or versions, missing file
analysis and ambiguous candidates remain explicit blockers. Thus a partial scan
can still show a continuing observation without implying complete analysis.
Every blocker has a stable code and the result includes fixed next-step actions.

The first version interprets absence only for supported built-in source and
configuration evidence. Binary, runtime, intelligence and imported evidence can
show continuing observations, but their absence is not supported as a source
comparison. A static scan cannot discharge a runtime finding. No runtime
installed-build, scenario or assertion binding is weakened.

`IOS-PRIVACY-MANIFEST` and `ANDROID-NSC-USER-CA` currently lack the saved
location-level provenance needed by this operation. Their observations remain
visible, but comparison is explicitly unsupported and calls for evidence-specific
validation. Repeating a scan alone does not supply the missing adapter contract.

The result always has `remediation_proven: false`. Even comparable absence is an
observation under stated checks, not proof of safety or remediation. Findings
accepted by policy remain in the immutable reports; follow-up does not read
filtered UI rows or turn waivers into fixes.

## Identity and scope

Existing finding IDs and `reports compare` behavior are unchanged. Follow-up
uses the exact rule, origin, finding scope, file and available semantic anchors
to identify possible continuations. Line and offset changes are not sufficient
to discard a candidate. Multiple candidates stay ambiguous. A shared MASWE
category alone never establishes correspondence.

The before and after source fingerprints may differ when revisions at the same
target are compared. Both must be canonical, explicitly complete fingerprints
for a comparable result. The optional `--portable-inputs` flag (MCP
`portable_inputs=true`) retains the existing narrower rule: relocation is only
normalized for identical complete source bytes and otherwise unchanged scope.
It does not pair different revisions from different checkout paths. See
[report comparison](REPORT_COMPARISON.md).

`reports reassess` updates intelligence against saved inventory; it does not
rescan code. Follow-up reports `execution_provenance: not-established` because
the historical report format does not independently attest a fresh execution.
Run `scan` after editing code and retain both exact report IDs.

## Reproducible, bounded evidence

`before.report_sha256` and `after.report_sha256` bind the full canonical report
contents. `artifact_sha256` hashes the emitted canonical JSON body with that
field omitted. Canonical JSON uses sorted keys, no whitespace, UTF-8 and
unescaped Unicode, as in `mobile_audit.core.canonical_json`.

These hashes identify content; they are not signatures or proof that a scanner
ran correctly. Identical inputs produce an identical result. No current time,
filesystem reads, network operations or device actions enter the calculation.
The canonical output is bounded to 65,536 bytes. Truncated detail is disclosed;
all candidates are considered before display limits are applied.

Run the synthetic report-contract check with:

```sh
python -m benchmarks.followup --out /tmp/apsa-followup-contract.json
```

This corpus tests observation and comparison semantics using synthetic report
pairs. It is not a scanner accuracy benchmark, a blind holdout, or a comparison
with commercial products. Separate fresh-source integration tests exercise
scanning, a shifted SSL callback, changed code, CLI export and actual MCP stdio.
