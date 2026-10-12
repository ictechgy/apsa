# Release package content verification

`scripts/release.py` verifies both newly built wheel/sdist pairs before clean
installation or copying the accepted release bundle. Matching hashes from two
builds must also pass `verify_package_contents(artifact, stage, inputs)`.

Expected source membership comes from the explicit source-stage SHA-256
manifest and the staged `pyproject.toml` Hatch package/include/exclude
declarations. Verification does not query Git's tracked-file list or enumerate
the checkout to reconstruct expectations. Declared public package roots must
contain their entry modules. Explicit public resource/demo declarations must
appear in the stage manifest, so an unsupported suffix cannot silently drop
known package data.

The wheel must contain exactly those public package sources and resources,
with bytes matching the source manifest. Its generated metadata allowlist is
`METADATA`, `WHEEL`, `RECORD`, and `entry_points.txt` when console scripts are
declared, under the declared distribution/version `.dist-info` directory.
Generated license destinations are also checked against their staged source
bytes. Arbitrary metadata files and unexpected package files are rejected.
`runtime_compiled.py`, `runtime_synthetic.py`, and `runtime_transport.py` are
test acquisition helpers and cannot be authorized as public runtime modules.
Source-only test helpers under `tests/support` may appear in the sdist when
declared, and are excluded from the wheel.

Every wheel file must appear exactly once in `RECORD`. SHA-256 digests and byte
sizes must match the archive content; only `RECORD` itself has an empty digest
and size. Matching RECORD entries cannot authorize an undeclared source file
or altered module. Newly built wheel Python sources are checked for absolute
developer-home paths, including macOS, Linux, and Windows home spellings.

The sdist must contain exactly the staged sources selected by its declarations,
plus generated `PKG-INFO`, under its distribution/version prefix. Missing and
extra members, duplicate names, traversal or noncanonical paths, archive links,
encrypted ZIP entries, and expanded-byte/member budget violations are refused.
Archive verification reads bounded members in memory and does not extract
archive paths onto the filesystem.

The release manifest records the content verdict for each primary and repeated
artifact. This verifies the clean stage and archive correspondence; it does
not declare publishing approval, dependency authenticity, or cross-platform
reproducibility. Source staging continues to prune protected directories and
disallowed inputs before stat, descent, or copy. Retained uploads, fixtures,
output media, logs, histories, and caches are outside verification input scope.
