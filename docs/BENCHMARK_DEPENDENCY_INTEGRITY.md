# Benchmark tool integrity

The benchmark uses only newly generated synthetic sources and compiled fixtures.
APSA dependencies remain locked; MobSF is an immutable OCI reference. Semgrep and
JADX now have separate acquisition and routine execution boundaries.

The acquisition bootstrap disables the competitive execution job. An invalid
Semgrep OCI reference is rejected before pull or tool execution; an invalid JADX
SHA256 is rejected before extraction. The acquisition-only workflow fetches JADX
twice, records actual published-checksum metadata when available, and pulls and
inspects the official Semgrep `1.179.0` image without running it. Candidate hashes
never become accepted repository pins automatically.

Before enabling execution, preserve the exact acquisition head/run, byte lengths,
JADX digest and its published-versus-reviewed-acquisition basis, Semgrep OCI digest
and platform. Run a new complete independent source review. Routine execution must
use those predeclared pins; it must never derive its expected pin from that run's
download. Registry content addressing and same-origin release checksums do not
establish an independent vendor signature.

Semgrep runs through an explicitly declared immutable image and a new wrapper,
with no local executable fallback. The container receives only fresh fixture and
rule directories, read-only, with network disabled. Created container IDs are
journaled; cleanup verifies this run/head's ownership labels before removal.
The [official Semgrep Docker documentation](https://semgrep.dev/docs/update)
identifies the `semgrep/semgrep` image. Pull/inspect/run evidence belongs to CI;
the benchmark report itself records an immutable wrapper declaration, not proof
that an arbitrary caller's wrapper executed that image.

Container execution changes measurement scope. Docker-client process-tree RSS is
excluded: Semgrep target `rss` and `rss_bytes` are null with
`rss_state=unmeasured-container-boundary`. Wall time covers container start and scan
and is labeled accordingly. Finding parsing, scored denominators, unsupported
cases, and the small rule slice remain unchanged. These observations do not
support a memory or accuracy superiority claim.
