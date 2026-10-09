## Summary

`CLEAR` for `BASE 62278bcb4ed0f4a262d1abb845258d41135b886f..HEAD 8ecc3f90dfbd5afe8e081a8707821b8c267fe4e7`, tree `464344032f1dc6da44242dd799a2f6cc7ee9d997`.

I found no remaining architectural blocker in the full 18-file diff. The hosted defects are addressed: packaged skill copies are synced with the repo skills, and the hardening replay no longer recaptures OSV or uses the broken direct `httpx.Response.raise_for_status()` path.

## Analysis

The final replay path is offline after artifact download. The workflow downloads the original public evaluation artifact, then downloads the fixed failed-attempt supplement by run/artifact ID, and passes both directories into `benchmarks.hardening_replay` without any OSV capture step in the workflow body. Evidence: `.github/workflows/hardening-replay.yml:30-52`.

The replay script freezes the original evidence before scoring. It checks the original summary SHA, input manifest SHA, OSV manifest SHA, and every original OSV response hash/byte count, then copies the original summary and OSV manifest into the work artifact. Evidence: `benchmarks/hardening_replay.py:41-60`.

The supplement is bounded to one fixed query and exact response bytes. `read_supplement` requires the expected schema, one response, exact `org.jsoup:jsoup` `1.15.1` payload, key derived from the canonical payload, non-symlink response under `MAX_RESPONSE`, status `200`, matching body SHA, and matching byte count. Evidence: `benchmarks/hardening_replay.py:19-38`. The replay then rejects collisions with original captures and runs with `capture_osv=False`, so missing or extra OSV requests fail from the frozen transport rather than recapturing. Evidence: `benchmarks/hardening_replay.py:67-73`, `benchmarks/real_world.py:244-251`.

The supplement provenance is explicit but does not turn the rerun into a new holdout measurement. The output records `development-rerun-after-labels-seen`, original run/source/hash fields, supplemental run/artifact/digest fields, and the APSA-only comparator. Evidence: `benchmarks/hardening_replay.py:74-86`.

The packaged skill-copy defect is closed. The installed package copies now carry the same source-configuration statement as the `.agents` skills: named `.plist` selection, literal `INFOPLIST_FILE` discovery, unresolved variables incomplete, multiple configs incomplete, and no Gradle/Xcode merge. Evidence: `.agents/skills/apsa/SKILL.md:40`, `src/mobile_audit/data/skills/apsa/SKILL.md:40`.

The previously reviewed runtime/harness boundaries remain intact in the full diff. Dynamic Gradle dependency expressions only set interpolation when the coordinate is standalone, and regressions cover concatenation, methods, closures, extra args, and casts remaining unknown. Evidence: `src/mobile_audit/inputs.py:82-114`, `tests/test_real_world_hardening.py:108-124`. Gradle `ext` resolution still stops at nearest inspected settings root and treats malformed/opaque source as unresolved. Evidence: `src/mobile_audit/source_context.py:31-111`, `src/mobile_audit/source_context.py:114-189`.

The final diff also keeps the documented source-evidence limits. The docs state that source config does not merge Gradle/Xcode variants, named plist discovery is literal/bounded, dependency versions are `declared` rather than build-resolved, and exact installed versions require lockfile/SBOM evidence. Evidence: `docs/MODEL_WORKFLOWS.md:45-51`.

## Root Cause

The hosted failures were integration-boundary defects, not product-engine defects: one copy of packaged skill text drifted from the `.agents` skill source, and the replay attempted a helper-level response path that was unsuitable for a frozen CI replay. The final implementation fixes this by syncing packaged skill bytes and replacing live supplement capture with validation of a previously captured public supplement artifact.

## Recommendations

1. Trigger the read-only staging branch workflow for this exact head/tree — low effort, high value.
2. Treat this `CLEAR` as a staging/replay architecture approval, not publication approval, until hosted Linux/macOS CI and frozen replay complete.
3. Preserve the replay artifact’s emitted `supplemental_osv_manifest_sha256` with the run/artifact IDs before writing final measurement claims.

## Architectural Status

`CLEAR`

## Trade-offs

| Option | Pros | Cons |
|---|---|---|
| Reuse captured supplement artifact | Offline replay, no OSV recapture, preserves failed-run evidence | Depends on fixed GitHub artifact availability and provenance retention |
| Recapture OSV in replay | Simpler code path | Reopens network variability and changes the frozen evidence boundary |
| Conservative static source parsing | Avoids false CVE certainty from partial Gradle/Xcode evidence | Misses versions that require real build resolution |

## References

- `.github/workflows/hardening-replay.yml:30-52` — downloads original and supplement artifacts, then runs replay with both paths.
- `benchmarks/hardening_replay.py:19-38` — validates supplement schema, payload, key, status, hash, size, and byte count.
- `benchmarks/hardening_replay.py:41-60` — verifies and preserves original summary/input/OSV evidence.
- `benchmarks/hardening_replay.py:67-86` — rejects supplement replacement and records replay provenance.
- `src/mobile_audit/inputs.py:82-114` — standalone Gradle dependency parsing boundary.
- `src/mobile_audit/source_context.py:114-189` — bounded Gradle resolver with settings-root stop.
- `docs/MODEL_WORKFLOWS.md:45-51` — public contract for source evidence limits.
