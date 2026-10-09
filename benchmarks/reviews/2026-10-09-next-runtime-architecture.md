## Summary

`APPROVED_FOR_HOSTED_VALIDATION` for base `f614ecc9aef5cde8f252a4b015d9bd05cfe2115f` -> head `a74442044f960744197b1fea29d03de91cc01d60`, tree `133b48e59bbf01bb2aad8458812020eee6ae157f`.

The prior `/System/Volumes/Data` concern is addressed in source: broad `/System` read/map grants are gone, replaced by narrower system runtime subpaths and an explicit disposable macOS synthetic Data-alias denial probe. Merge/publication readiness remains `BLOCKED` until the full hosted CI for this exact snapshot passes and the uncommitted docs/results drafts are committed and reviewed.

## Analysis

The macOS profile no longer grants `(subpath "/System")` or `(subpath "/System/Volumes")`. It now allows system code only under `/System/Library`, `/System/Cryptexes`, `/System/Volumes/Preboot/Cryptexes`, and `/usr/lib`, with `/usr/share`, scratch, staged reads, and runtime roots handled separately (`src/mobile_audit/parser_sandbox.py:76`, `src/mobile_audit/parser_sandbox.py:82`, `src/mobile_audit/parser_sandbox.py:83`). The unit test asserts that neither `/System` nor `/System/Volumes` appears as a subpath grant (`tests/test_next_hardening.py:464`, `tests/test_next_hardening.py:465`). This closes the specific risk that `/System/Volumes/Data/...` could expose unrelated Data-volume content through a broad `/System` grant; Apple documents user-changeable Data locations such as `/Users`, `/private`, `/var`, and `/tmp` on the Data volume, and firmlinks as traversal points from system to data volume ([Apple Platform Security](https://support.apple.com/en-ca/guide/security/seca6147599e/web), [Apple Developer WWDC19](https://developer.apple.com/videos/play/wwdc2019/710/)).

The new macOS alias probe is scoped to fresh synthetic data. It creates only `tmp_path` files, constructs exact `/System/Volumes/Data/...` spellings for those synthetic files, skips if the runner does not expose those exact aliases, and asserts the sandboxed process cannot read them (`tests/test_next_hardening.py:474`, `tests/test_next_hardening.py:486`, `tests/test_next_hardening.py:489`, `tests/test_next_hardening.py:490`, `tests/test_next_hardening.py:501`, `tests/test_next_hardening.py:509`). It does not enumerate host directories.

The literal parent read allowance is bounded. Runtime parents and staged file/SBOM parents are granted as exact literals for directory lookup, not recursive subpaths (`src/mobile_audit/parser_sandbox.py:84`, `src/mobile_audit/parser_sandbox.py:86`, `src/mobile_audit/parser_sandbox.py:101`). The test verifies the archive parent appears as a literal and not a subpath (`tests/test_next_hardening.py:466`, `tests/test_next_hardening.py:470`, `tests/test_next_hardening.py:471`). That is consistent with the stated need for parent directory opens without granting sibling contents recursively.

The staged-input containment model remains intact. The engine stages the resolved target before sandboxing (`src/mobile_audit/engine.py:66`, `src/mobile_audit/engine.py:70`, `src/mobile_audit/engine.py:88`), and the stage copy still uses stable descriptor reads, no-follow traversal, pre/post `fstat()` checks, and cumulative byte limits (`src/mobile_audit/input_snapshot.py:39`, `src/mobile_audit/input_snapshot.py:55`, `src/mobile_audit/input_snapshot.py:101`, `src/mobile_audit/input_snapshot.py:114`, `src/mobile_audit/input_snapshot.py:126`). Standard input inheritance remains closed with `DEVNULL` and `close_fds=True` (`src/mobile_audit/processes.py:28`, `src/mobile_audit/processes.py:31`).

The AAPT2 check is materially stronger. It now parses the independent `aapt2 dump xmltree` output and compares package, debuggable, cleartext, minSdkVersion, and targetSdkVersion against APSA’s decoded observation (`scripts/verify_aab.py:61`, `scripts/verify_aab.py:65`, `scripts/verify_aab.py:70`, `scripts/verify_aab.py:74`). The workflow still installs only pinned synthetic SDK inputs before running that verifier (`.github/workflows/generated-aab.yml:26`, `.github/workflows/generated-aab.yml:31`, `.github/workflows/generated-aab.yml:34`).

## Root Cause

The earlier macOS profile overfit startup needs by allowing broad `/System` subpath access. The current snapshot narrows that to expected system runtime locations and adds a synthetic Data-volume alias denial probe, preserving hosted diagnostic coverage without opening the known Data-volume alias namespace.

## Recommendations

1. Run disposable hosted validation for `a74442044f960744197b1fea29d03de91cc01d60` — low effort, high impact.
2. Keep merge/tag/PyPI blocked until full CI passes for this exact snapshot — low effort, high impact.
3. Commit and re-review the docs/results drafts before any publication claim — low effort, medium impact.

## Architectural Status

`WATCH`

No blocker for hosted validation. Merge readiness remains `BLOCKED`.

## Trade-offs

| Option | Pros | Cons |
| --- | --- | --- |
| Narrow system grants | Avoids `/System/Volumes/Data` exposure | May need another exact system path if hosted macOS exposes a new runtime dependency |
| Exact parent literals | Supports parent directory lookup for staged file/SBOM/runtime | Directory listing metadata is still exposed for those exact parents |
| Synthetic alias probe | Tests the specific Data alias risk without private data | Skips if the runner lacks that exact alias spelling |

## References

- `src/mobile_audit/parser_sandbox.py:76` — narrowed system runtime paths.
- `src/mobile_audit/parser_sandbox.py:101` — exact literal parent grants.
- `tests/test_next_hardening.py:478` — disposable macOS Data-alias denial test.
- `scripts/verify_aab.py:70` — AAPT2 dump values compared to decoded APSA observation.

Terminal verdict: `APPROVED_FOR_HOSTED_VALIDATION`
