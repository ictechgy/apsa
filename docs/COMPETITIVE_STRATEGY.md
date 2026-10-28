# Competitive direction and implementation decisions

Research date: 2026-10-23. Official product descriptions are evidence of offered
capabilities, not independent measurements of accuracy. No customer app was
uploaded and no commercial service was purchased or benchmarked for this work.

## Positioning hypothesis

APSA can compete as a local mobile audit tool whose evidence can be followed
from observation through a code change without silently turning missing results
into successful remediation. This is a testable product direction, not a claim
that competitors lack comparable tracking or that APSA has better detection.

| Market evidence | Consequence for APSA |
| --- | --- |
| [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) already offers a free local Android/iOS analysis platform. | Local execution, free availability and a CLI alone are insufficient differentiation. |
| [Ostorlab](https://ostorlab.co/product/mcp), [Oversecured](https://oversecured.com/pricing), and [NowSecure](https://github.com/nowsecure/nowsecure-mcp-server) offer MCP connections. | MCP is an integration requirement, not a unique selling point. |
| [Appknox](https://www.appknox.com/blog/appknox-mcp-find-fix-and-verify-mobile-app-vulnerabilities-without-leaving-your-ide) describes IDE triage, source fixes, uploads and rescans. | An AI fix/rescan loop needs trustworthy evidence semantics to add value. |
| [AppSweep](https://www.guardsquare.com/appsweep-mobile-application-security-testing) emphasizes taint, reachability and developer guidance; [Oversecured](https://oversecured.com/) emphasizes reproduction evidence. | Compare analysis depth and usefulness on matched inputs before making quality claims. |
| [NowSecure](https://www.nowsecure.com/solutions/by-need/mobile-app-security-testing/), [Appknox](https://www.appknox.com/faqs/features), [Quokka](https://www.quokka.io/products/q-mast) and [zScan](https://zimperium.com/maps/zscan) describe runtime/device or protection testing. | Physical iOS and authenticated runtime depth remain substantial separate investments. |

[Ostorlab's public plan](https://ostorlab.co/plans) starts at $499 per application
per month, with Android and iOS counted separately. [Oversecured](https://oversecured.com/pricing)
lists $500 per scan and $1,000 per app per month. These are dated public prices,
not equivalent scopes or total-cost comparisons. APSA can complement other
scanners through explicitly imported evidence; ingestion does not independently
corroborate the imported claim.

## Independent advisor input

Claude and Grok each received the same public-information packet and a generic
proposed design. Both returned complete substantive responses. Neither saw
APSA source in the successful consultation, ran competitors, or approved code.
Their recommendations were checked against current local implementation before
selection. The separate invocation records retain packet hashes, exact prompts,
exit status and raw stdout/stderr, including earlier operational failures.

| Advice | Disposition |
| --- | --- |
| Claude ranked a paired corpus first, then narrow per-finding follow-up; Grok recommended both as one deliverable. | Implement a per-finding operation and a predeclared synthetic report-pair contract corpus together; retain separate real scan/interface tests. |
| Both emphasized location changes, ambiguous identity, missing locus coverage, changed scope/version and external/runtime evidence boundaries. | Separate observation from comparability; expose candidates, blockers and next actions. Preserve finding IDs and existing comparison behavior. |
| Claude required a machine-readable non-claim; Grok proposed a positive `remediation_supported` path with additional proof. | Keep `remediation_proven: false`. Current snapshots do not establish the new positive proof contract. Absence, even with complete checks, is not promoted to a fix. |
| Claude proposed equality for every comparison dimension, including input identity. | Preserve different complete source fingerprints for revisions at one target. Same installed-build requirements remain specific to runtime comparisons; portable relocation remains identical-source-only. |
| Both recommended resolved dependency evidence. | APSA already has substantial lockfile/resolution evidence. Avoid duplicating it; deeper freshness and installed-build correspondence require separate validation. |
| Claude proposed exact rerun commands. | Emit fixed next-step action codes. Old report metadata cannot always reconstruct an exact historical environment, so do not invent executable commands from app-controlled text. |
| Both deferred physical iOS and broad autonomous testing. | Keep this increment local and read-only; no scanner, upload, autofix or device execution is added. |

## Selected increment

[Finding follow-up](FINDING_FOLLOWUP.md) provides API, CLI and MCP access to one
finding's before/after evidence. It retains full report hashes, input identity,
rule coverage and file-analysis evidence; distinguishes exact observations,
possible continuations and unpaired same-rule findings; and explains what
prevents comparison. Output is deterministic, bounded and contains no source
excerpts.

Acceptance requires explicit expected observation/comparability labels for
synthetic pairs, unchanged results on repeat, a valid canonical artifact hash,
and no remediation assertion. A small fresh-source integration covers actual
scans before and after line movement and a code correction. Actual stdio tests
check API/CLI/MCP parity and both report-root authorization boundaries.

This does not establish real-world detection precision, fix recall or market
superiority. The synthetic complete-report cases model a contract; they do not
claim that APSA's bounded AST engine produces complete coverage on those apps.

## Next evidence needed

1. Freeze independent vulnerable, fixed, refactored and scope-changed app pairs
   before running scanners. Include failures and unsupported cases in results.
2. Compare MobSF first, then selected commercial tools on identical inputs and
   documented configurations. Record analyst/setup time separately, and check
   terms before publishing commercial benchmark results.
3. Measure whether users and agent consumers correctly distinguish continuing
   findings, comparable absence and insufficient evidence; measure review time
   against the existing report comparison.
4. Prioritize deeper source, dependency or runtime work from measured misses.
   Physical iOS support and cross-build runtime remediation need their own
   observed-build/scenario/assertion contracts.

OWASP [MASTG](https://mas.owasp.org/MASTG/) remains a testing knowledge base, not a
certificate conferred by a subset of automated checks.
