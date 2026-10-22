# APSA 1.6.1

This patch corrects three cases where the 1.6.0 analysis could omit a finding.

- Hybrid helper summaries require callable identity. A parameter, local binding,
  nested declaration or unrelated member with the same name must not borrow a
  top-level function's clean return summary. Unresolved calls preserve tainted
  arguments and disclose uncertainty; this is not sanitizer proof.
- Rejecting the substring `..` does not establish containment of an external
  raw path: absolute paths can still reach file operations. Such paths retain
  `AST-PATH-TRAVERSAL` candidates. Canonical path checks with a trusted directory
  boundary remain supported. Existing lexical checks and fixed-root construction
  are distinguished from canonical containment.
- Dependency correlation retrieves exact cached OSV package/version results
  independently of the 100,000-record recent intelligence window. Unrelated
  newer advisories no longer hide a matching vulnerability while dependency
  coverage remains checked. Scans, report refreshes and runtime reassessments
  share the same selector, retain advisory provenance and preserve cached
  positive findings for packages excluded from new network queries.

Package and rule versions advance to `1.6.1` and `2026.10.22.apsa.161`.
The fixes can add findings on previously scanned inputs. Reassess findings and
policy baselines; the release does not approve or silently rewrite a baseline.
No new dependencies or public MCP tools are introduced. The OS advisory window
remains bounded and its existing partial-coverage semantics are unchanged.

Regressions use fresh synthetic sources and databases, including a dependency
advisory displaced by 100,000 newer unrelated records. Release publication uses
the existing supported CI, reproducible package build, clean installation and
public installation verification workflow described in [PUBLISHING.md](PUBLISHING.md).
