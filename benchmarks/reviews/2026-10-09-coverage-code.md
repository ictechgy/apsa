# APSA Coverage Hardening Code/Spec/Security Review

Review lane: code/spec/security
Architecture lane: separate, not synthesized here

Reviewed snapshot:
- Base: 93bf36199a88861f2c7e01bc500888d31495b669
- Head: f5c05db5c271805c518979454bf3673c035ff439
- Head tree: 18bf3101701d3a894ea3506936229e82a307a663
- Diff scope: 20 files
- Worktree status at review: clean

Governing scope/spec:
- User-authorized hardening branch only; no main merge, release, registry publish, upstream builds, device/runtime/backend execution, or new OSV capture.
- Local Media private data boundary honored: review inspected APSA source/docs/tests/pinned public benchmark fixtures and the supplied synthetic validation artifact only. No uploads/output media/history/prompts/jobs/cache/raw service logs/preferences/UI/clipboard/live history/files APIs were inspected.
- Spec anchors: docs/MODEL_WORKFLOWS.md new "Source function coverage and Apple branch decisions" section; existing source-analysis candidate/local-flow bounds; user-provided requirements for Kotlin/Swift parser compatibility, explicit recognized/analyzed/skipped/bodyless function coverage, iOS CNA/product/branch matching, and frozen replay boundaries.

Files reviewed:
- .agents/skills/apsa/SKILL.md
- .agents/skills/mobile-audit/SKILL.md
- .agents/skills/quaygate/SKILL.md
- .github/workflows/hardening-replay.yml
- Makefile
- benchmarks/coverage_replay.py
- benchmarks/ios_branch_cases.json
- benchmarks/real_world.py
- docs/MODEL_WORKFLOWS.md
- src/mobile_audit/_parser_worker.py
- src/mobile_audit/audit.py
- src/mobile_audit/core.py
- src/mobile_audit/data/skills/apsa/SKILL.md
- src/mobile_audit/data/skills/mobile-audit/SKILL.md
- src/mobile_audit/data/skills/quaygate/SKILL.md
- src/mobile_audit/intel.py
- src/mobile_audit/ios_ranges.py
- src/mobile_audit/parser_compat.py
- src/mobile_audit/source_analysis.py
- tests/test_coverage_extension.py

Stage 1 - Spec compliance:
- PASS: parser compatibility remains narrow and partial. Kotlin `open` identifier adaptation tokenizes comments, nested block comments, strings, raw strings, backticks, and templates opaquely, fails closed on unterminated literals/comments/templates, and preserves byte length for offsets. Swift adaptation erases only `ERROR` nodes exactly matching `nonisolated(unsafe)` followed by direct `var`/`let`, with same-length spaces.
- PASS: adapted files stay partial. `source_analysis.analyze_sources` increments skipped coverage for adaptations, omits pattern exclusions for adapted files, records `normalized_files`, and reports warnings that source remains partial.
- PASS: function metrics are explicitly recognized-node metrics, not complete callable inventory. Coverage and `inventory.source_analysis` include observed/analyzed/skipped/bodyless aggregate and per-file metrics; unparsed files keep `functions: None`; notes disclose parser errors, unsupported languages, budgets, closures, and initializers.
- PASS: Apple branch matching requires Apple assigner/CNA org IDs, Apple vendor product, vendor source `apple`, shared official support.apple.com reference, custom zero-based range shape, one boundary in observed major, matching release label/product, and explicit `os_product=ipados` for iPadOS-only. Missing older-cache identity abstains.
- PASS: generic `in_cve_range` remains unchanged before Apple-specific custom fallback.
- PASS: workflow/replay boundaries preserve original frozen inputs, use the one pinned supplement, add the coverage extension, avoid new OSV capture, and document development-rerun provenance rather than claiming holdout accuracy.

Root-cause fallback/workaround guard:
- PASS: no newly introduced broad fallback masks a primary contract failure. Parser compatibility preserves failure evidence through partial/skipped states and warnings; CNA gaps abstain instead of routing to unsafe range inference; failed/ambiguous supplement and range shapes raise or return unknown.

Stage 2 - Code quality/security:
- No hardcoded secrets found in the changed implementation/workflow files.
- No broad new silent default path was found in the changed implementation. The new compatibility failure path returns no adaptation and lets the original syntax-recovery path remain partial.
- GitHub Actions changes keep third-party actions pinned by commit SHA and use read-only permissions.
- No source mutation, report database access, native app interaction, protected media/history/log inspection, or network escalation was performed during review.

Diagnostics:
- `git diff --check 93bf36199a88861f2c7e01bc500888d31495b669 f5c05db5c271805c518979454bf3673c035ff439`: passed.
- `uv run --locked --extra dev ...`: not used as validation evidence because sandbox-local uv cache setup attempted PyPI fetch for build-system requirements and native network is disabled by project policy.
- `.venv/bin/pyright --pythonpath .venv/bin/python <modified Python files>`: 0 errors, 0 warnings, 0 informations.
- `.venv/bin/python -m ruff check <modified Python files>`: all checks passed.
- `.venv/bin/python -m pytest -q tests/test_coverage_extension.py tests/test_source_analysis.py tests/test_intel.py tests/test_real_world_hardening.py`: 166 passed.
- `.venv/bin/python -c 'import yaml; yaml.safe_load(open(".github/workflows/hardening-replay.yml", encoding="utf-8")); print("workflow yaml parsed")'`: passed.
- Supplied local validation artifact `/private/tmp/apsa-coverage.ueSZfP/local-validation.json`: schema `apsa-coverage-extension-local-validation-v1`, focused_tests 241 passed, ruff passed, pyright 0 errors, workflow_yaml parsed, iOS branch fixture agreement 14/14, reviewed_head/head_tree match this review.

Issues:
- CRITICAL: 0
- HIGH: 0
- MEDIUM: 0
- LOW: 0

Recommendation: APPROVE

Notes:
- This is the code/spec/security lane only. Final merge readiness still depends on the separate architecture lane and hosted CI for the known native full-suite psutil/sysctl sandbox limitation.
- No `lsp_diagnostics` tool was exposed in this leaf lane; Pyright was run over every modified Python file as the available static diagnostics equivalent.
