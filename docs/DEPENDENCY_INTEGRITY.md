# Dependency integrity

Verify dependency JAR bytes against a reviewed SHA256 pin declared before the
routine download. Run this check before unzipping, setting executable permissions,
checking a binary's version, or executing it:

```sh
python3 scripts/verify_dependency.py "$artifact_path" --expected-sha256 "$pinned_sha256"
```

The command exits 0 only for a matching, nonempty, stable regular file. Every
verification failure exits 1. Its single JSON line has fixed fields: `status`
(`verified` or `failed`), a fixed `reason`, observed `sha256` (or null), `filesize`
(or null), and `provenance` (`predeclared-sha256-pin` on success; `unverified` on
failure). It does not print paths, file contents, or raw OS errors. The provenance
marker describes the comparison performed; it does not authenticate the origin
of the expected value.

The reusable function is `verify(path, expected, *, max_bytes=268435456)`. Expected
digests must contain exactly 64 hexadecimal characters, with no surrounding
whitespace. File reads are streamed in 1 MiB chunks and bounded to the size limit
plus one byte, including concurrent growth. The default limit is 256 MiB and can
be reduced with `--max-bytes`. Symlinks, pipes, empty files, unreadable files, and
files changed while hashing fail closed. The helper only hashes; it never downloads,
extracts, executes, or changes a pin. Keep the artifact in a controlled temporary
directory between verification and downstream use: this separate verification
step does not prevent an outside writer from replacing it afterward.

## Acquisition evidence and routine verification

Acquisition establishes a candidate pin; routine verification compares against
that predeclared pin. Computing a SHA256 from the same routine download and using
it as the expected value is not verification.

A reviewed acquisition record should contain:

| Field | Meaning |
| --- | --- |
| `schema_version` | Provenance record format version, initially 1 |
| `coordinate` | Exact group, artifact, version, extension, and classifier |
| `artifact_url` / `final_url` | Requested official HTTPS URL and resolved URL |
| `acquired_at_utc` / `acquisition_run_url` | Timestamp and controlled CI acquisition reference |
| `http_status` / `filesize` / `observed_sha256` | Observed transport result and exact acquired bytes |
| `upstream_checksums` | For each probe: algorithm, source URL, actual HTTP status, digest if fetched, and comparison result |
| `pin_basis` | `upstream-published-sha256`, `upstream-published-sha512`, `upstream-sha1-and-reviewed-acquisition`, or `reviewed-https-acquisition` |
| `review_reference` | Reference recording review of the acquisition and resulting repository pin |

Use `upstream-published` only when an official primary source actually supplied
that exact artifact's digest. A fetched checksum must parse strictly and match
the acquired bytes. SHA1 comparison is a limited consistency check; a SHA256
computed after that comparison remains a reviewed first-acquisition (TOFU) pin,
not a Google-published SHA256. A checksum from the same origin is not independent
protection against compromise of that origin. Never update a repository pin
automatically after a mismatch.

The intended AAPT2 coordinate is
`com.android.tools.build:aapt2:jar:linux:8.10.1-12782657`, using Google's documented
[AAPT2 Maven download pattern](https://developer.android.com/tools/aapt2). No
digest was obtained during the initial hosted-web research; unavailable tool
responses did not establish HTTP status. The subsequent
[controlled acquisition](https://github.com/ictechgy/apsa/actions/runs/38241617038)
received HTTP 200 from Google's `.sha256`, `.sha512`, and `.sha1` endpoints.
Two downloads matched all three official sidecars and each contained 2,315,715 bytes.
The Google-published SHA256 now pinned in the workflow is:

```text
52f864b7fd20a9ff09fc3db96162537a63c5b38ecc1c2549db4b491c6a517ff0
```

[aapt2-integrity.json](aapt2-integrity.json) records the exact origin, sidecar
values/statuses, acquisition head/run, and pin basis. This establishes a published
checksum comparison, not an independent vendor signature. The origin and its
sidecars share a trust boundary. The routine workflow checks the predeclared hash
before unzip/chmod, rejects a mutated copy before extraction, then the driver
independently verifies the whole JAR and binds executable bytes to its unique
root `aapt2` entry before any tool command. SHA256 pin acceptance and job reenabling
receive a fresh complete review separate from the acquisition bootstrap.

Tests use synthetic ZIP-shaped dependencies and mutations, truncation, malformed
pins, oversized/growing files, changes during hashing, and unsafe file types.
Run them with `TMPDIR` and Python's cache directory set to a fresh temporary
directory outside the checkout and protected runtime paths.
