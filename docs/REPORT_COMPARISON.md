# Report comparison and relocated source inputs

Report comparison describes observations from two immutable snapshots.
`no-longer-observed` never proves remediation, complete deletion, or backend
session invalidation. Verification adds scope, input-build, source-trace, and
runtime assertion pairing; it does not convert disappearance into a success.

## Default and opt-in use

Strict target pairing remains the default. Different target paths make the
verification scope changed and findings inconclusive, even when file bytes are
identical. Existing same-target revision comparisons retain their behavior and
continue to expose different input fingerprints as `different-builds`.

The verification API accepts a keyword-only option:

```python
compare_reports(before_report, after_report, portable_inputs=True)
```

The CLI requires both options:

```console
apsa reports compare BEFORE_ID AFTER_ID --verification --portable-inputs
```

MCP `reports_compare` accepts `verification=true, portable_inputs=true`.
`portable_inputs` defaults to false in all three interfaces. The direct API
requires an actual boolean; strings, integers, null, and collections raise
`ValueError` rather than enabling normalization by truthiness. CLI use without
`--verification` is a usage error (exit 2); MCP use without `verification=true`
raises `ValueError` before loading reports.

## Eligibility for target normalization

The option can ignore **only the absolute source target path**, and only when:

- Both inputs are source inputs with absolute targets; compiled `.app` bundles
  and binary inventory cannot use source-kind metadata to opt in.
- Both fingerprints are identical canonical SHA256 strings (64 lowercase hex
  characters), and both `fingerprint_complete` fields are exactly `true`.
- Neither report has partial source/input scope, staging/app-scope omissions,
  partial analysis coverage, or partial source/hybrid file analysis.
- Every other comparison scope field is unchanged: input kind, platforms, app
  scope, package, analysis specification, source selection, tool/rule versions,
  and the covered rule IDs. Every declared spec representation is retained;
  an effective fallback cannot hide another changed spec declaration.

Fingerprint equality is required. This option pairs relocated snapshots of the
same canonical input, not different revisions moved to different roots. Changed
fingerprints at changed paths remain inconclusive, while their distinct build
fingerprints remain visible. Invalid, legacy, absent, or incomplete fingerprints
cannot authorize normalization. Report callers must use trusted APSA snapshots;
the comparison function does not inspect filesystem paths or rehash their bytes.
CLI/MCP load immutable reports through the Store's integrity check and keep the
existing MCP root authorization.

Only an eligible target difference is normalized. Scope differences, binary
inputs, and incomplete source inputs retain their original comparison behavior.
The input dictionaries are never mutated.

## Explicit comparison evidence

The verification result adds:

- `path_pairing`: original before/after targets, whether portable pairing was
  requested/applied, an exact/changed/portable/unavailable state, and a reason.
- `normalization_basis`: `identical-complete-canonical-source-sha256` when applied,
  otherwise `none`.
- `scope_pairing.original_state`: scope state before any normalization.
- `scope_pairing.normalized_fields`: `["target"]` when applied, otherwise empty.
- `scope_pairing.comparison_before_sha256` and `comparison_after_sha256`: hashes
  used to compare effective scope after the permitted target normalization.

`scope_pairing.before` and `after`, and their existing `before_sha256` and
`after_sha256` fields, always retain original scope and original targets. Their
hashes can differ for relocated inputs while the explicitly normalized comparison
hashes agree. `build_pairing` preserves original before/after fingerprints.
No field is normalized if eligibility fails.

## Runtime and binary limits

Binary target pairing stays exact for APK/AAB/APKS/IPA and compiled app bundles.
Source portability does not establish correspondence to any installed binary.

Runtime comparisons retain **original exact target scope**, even if static
source observations are portable. They also require the same nonempty observed
installed-build identity, bound app records, identical executable scenario scope,
identical assertion identity, and complete observations on both sides. Missing
installed identities never pair merely because both are absent. Relocation,
changed/missing build identity, changed scenario/assertions, or partial runtime
observations leave runtime verification inconclusive.

A comparable observation states that the pair can be examined under the declared
scope. It is not proof that a disappeared finding was fixed or that user sessions
or server-side data were invalidated. Synthetic regression tests exercise API,
CLI, and the real MCP source handler using newly created reports and temporary
stores. Handler tests isolate that source declaration from SDK imports; actual
SDK discovery/schema checks remain part of the CI contract matrix. Fresh direct
source inspection also verifies identical relocated inputs produce equal
canonical fingerprints and changed source bytes do not. No live device,
service, historical application input, or fixture contract is changed by this
feature.
