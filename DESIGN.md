# Design

## Source of truth
- Status: Active
- Last refreshed: 2026-10-06
- Primary product surfaces: CLI and keyboard-first Textual TUI.
- Evidence reviewed: User requested Android/iOS source and APK/IPA audits, OWASP testing, continuously updated CVE intelligence, deep-link/WebView and post-logout data checks, and an LLM-assisted interface. Parent workspace is an unrelated trading/media collection with no mobile product. This directory is a separate project.

## Brand
- Personality: Calm, precise, practical. Product name: APSA. Korean name: 앱사.
- Pronunciation: "ap-sah". Introductory copy: "APSA, pronounced ap-sah."
- Tagline: Evidence-first security audits for Android & iOS.
- Use APSA (앱사) in Korean introductions and human-facing titles; technical identifiers stay `apsa`. Naming rules: NAMING.md.
- Trust signals: Source links, evidence strength, timestamps, input hash, explicit coverage gaps.
- Avoid: A single security score, exaggerated zero-day detection, guessed versions presented as facts.

## Product goals
- Goals: Inspect source/APK/IPA; collect official advisories; correlate verified package versions and observed device environments; run repeatable runtime scenarios; export reports; expose evidence to multiple model clients through MCP and skills.
- Non-goals: Claim exhaustive MASVS certification or discovery of undisclosed zero-days; execute downloaded exploit code; silently change audited apps.
- Success signals: Demo works without credentials; installed CLI runs from any directory; human and JSON outputs agree; failed feeds and incomplete tests remain visible.

## Personas and jobs
- Primary personas: Mobile developers and application security auditors.
- User jobs: Choose input, scan, inspect evidence, prioritize, reproduce on an owned test device, compare a fix, ask for an explanation.
- Key contexts: Local laptop, CI, offline review, terminal with no mouse.

## Information architecture
- Primary navigation: Audit / Reports / Runtime / Intelligence / Models and MCP.
- Core screens: Path entry and audit controls, findings table with details, report history, intel source health and search, model/MCP connection guide.
- Content hierarchy: Finding and status, evidence, remediation, OWASP mapping, source references, coverage limitations.

## Design principles
- Evidence precedes interpretation; static candidates are never runtime-confirmed.
- Unknown and not-run are distinct from passed.
- Both source and binary inputs use the same report model.
- Tradeoffs: Android runtime uses adb and run-as on debuggable test apps; iOS runtime uses developer-built simulator apps and simctl. Report inaccessible surfaces.

## Visual language
- Color: Dark navy surface, cyan actions, amber candidates, red confirmed high severity; status text supplements color.
- Typography: Terminal monospace; no ASCII art that obscures content.
- Spacing: Compact forms, two-pane results, spacious details.
- Shape/elevation: Simple bordered panels.
- Motion: Loading indicator only.
- Imagery: None.

## Components
- Reuse: Textual Header, Footer, Input, Button, DataTable, Markdown, TabbedContent.
- New: Audit controls, source health table, finding detail, JSON scenario editor and model connection guide.
- States: idle, working, complete, partial, offline, error.
- Ownership: tui.py; rules metadata lives in data/rules.json.

## Accessibility
- Keyboard: Tab, Enter, arrow selection; named shortcuts and visible footer.
- Readability: Always label severity and status; wrap detail text.
- Screen readers: CLI plain output alternative.
- Motion: No decorative animation.

## Responsive behavior
- Terminal target: 100x30 or larger; vertical scrolling on smaller terminals.
- CLI always usable without TUI or mouse.

## Interaction states
- Loading: Disable initiating button, show current operation; work outside UI event loop.
- Empty: Explain how to scan or run demo.
- Error: Show actionable message; preserve previous report.
- Success: Show findings and untested checks together.
- Disabled: Initiating controls during background work; runtime execution requires an available device adapter.
- Offline: Cached intelligence remains usable with source timestamps and stale state.

## Content voice
- Korean guidance in onboarding and README; technical identifiers remain English.
- Terminology: candidate, configuration-confirmed, runtime-confirmed, unknown, not-run.
- Microcopy: A failed test or feed must never look like a clean audit.

## Implementation constraints
- Python 3.11+, SQLite, Textual, httpx; archive reads bounded, no archive extraction.
- Models connect through MCP or a reusable skill. No embedded model API key is required. MCP report context omits raw source/storage/screenshot content; device execution is explicitly enabled on the server.
- Test expectations: parser/rule, feed normalization, CLI, runtime adapter, actual MCP stdio contract and TUI interaction tests.

## Open questions
- Device fleet coverage and commercial delivery format can be expanded after real app onboarding. They do not block the local CLI/TUI.
