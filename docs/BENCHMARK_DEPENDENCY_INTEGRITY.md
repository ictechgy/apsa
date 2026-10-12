# Benchmark tool integrity

The benchmark uses only newly generated synthetic sources and compiled fixtures.
APSA dependencies remain locked; MobSF is an immutable OCI reference. Semgrep and
JADX now have separate acquisition and routine execution boundaries.

The acquisition bootstrap completed in [run 38248931033](https://github.com/ictechgy/apsa/actions/runs/38248931033)
at head `837324c484616323ad065fea5957ed3ea308f3ad`. The public
[pin record](benchmark-integrity.json) preserves its exact job, two acquisitions,
sidecar HTTP statuses, OCI identity, platform, and artifact digest. The candidate
pins were copied into source for a complete independent final review; the
acquisition script never accepts them automatically. Actual pinned execution
remains a separate CI result.

JADX `1.5.0` ZIP SHA-256 is
`c5a713fa4800cbb9e6df85ced1bef95ba329040c95cb87d54465f108483e4ef9`.
Both acquisitions were 104,967,983 bytes. Release metadata had no digest and the
SHA1, SHA256, and SHA512 sidecars each returned HTTP 404. This pin is reviewed
controlled HTTPS acquisition (TOFU), not a vendor-published checksum.
Semgrep `1.179.0` was acquired as
`docker.io/semgrep/semgrep@sha256:93963d9295a366f59e4850127b1550400ee7b388f04fe144e4a1f6325d96e01b`.
The execution spelling removes only `docker.io/`, preserving the same repository
and content address. The workflow accepts only those two official spellings when
matching actual RepoDigests; the record retains the original acquisition value.

Before enabling execution, preserve the exact acquisition head/run, byte lengths,
JADX digest and its published-versus-reviewed-acquisition basis, Semgrep OCI digest
and platform. Run a new complete independent source review. Routine execution must
use those predeclared pins; it must never derive its expected pin from that run's
download. Registry content addressing and same-origin release checksums do not
establish an independent vendor signature.

Semgrep runs through an explicitly declared immutable image and a new wrapper,
with no local executable fallback. The container receives only fresh fixture,
rule, and Semgrep result directories (which contain the copied synthetic Java
targets), read-only, with network disabled. Settings and cache are in the bounded
writable `/tmp` mount. Created container IDs are
journaled; cleanup verifies this run/head's ownership labels before removal.
The [official Semgrep Docker documentation](https://semgrep.dev/docs/update)
identifies the `semgrep/semgrep` image. Pull/inspect/run evidence belongs to CI;
the benchmark report itself records an immutable wrapper declaration. Independently,
the workflow verifies each journaled container's actual image ID, declared digest,
run/head labels, terminated state, and zero exit code, and preserves that evidence.
An arbitrary caller's wrapper declaration alone cannot prove execution.

Container execution changes measurement scope. Docker-client process-tree RSS is
excluded: Semgrep target `rss` and `rss_bytes` are null with
`rss_state=unmeasured-container-boundary`. Wall time covers container start and scan
and is labeled accordingly. Finding parsing, scored denominators, unsupported
cases, and the small rule slice remain unchanged. These observations do not
support a memory or accuracy superiority claim.
