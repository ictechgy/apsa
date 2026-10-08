# Release sequence

English is the source for this release plan.

1. **1.0.6 — evidence correctness.** Isolated MCP Python fallback, incomplete mixed-language AST and truncated pattern coverage, bounded OS-advisory coverage, declared dependency candidates, and unified CI example. Release only after regression tests and independent snapshot-bound review.
2. **1.1.0 — model and team workflows.** Bounded/paginated model report context, portable integrity-checked baseline artifacts, exported policy decisions, and explicit source app/module selection. Release only after contract, authorization and clean-install validation.
3. **Later milestones — analysis and parser isolation.** AAB protobuf manifests and module/split inventory; embedded IPA executables; Objective-C local-flow analysis; platform OS sandbox with explicit unavailable/failure behavior. Resource limits are not an OS permission sandbox.

The historical CVE catalog, representative production accuracy, full interprocedural analysis, and physical iOS device tests remain separate work. The current handcrafted corpus is a regression check, not a production detection-rate claim.
