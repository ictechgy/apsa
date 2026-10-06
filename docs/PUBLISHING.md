# Publishing APSA

The PyPI project is `apsa`. Its GitHub Trusted Publisher uses these exact values:

| Setting | Value |
| --- | --- |
| Repository owner | `ictechgy` |
| Repository name | `apsa` |
| Workflow filename | `release.yml` |
| GitHub environment | `pypi` |

The workflow lives at [`.github/workflows/release.yml`](../.github/workflows/release.yml). It runs when a `v` release tag is pushed, or when a maintainer manually runs it on that tag. The tag must match the version in `pyproject.toml`; running it on a branch fails before building or publishing.

Before publishing, the workflow runs the existing macOS/Linux and Python 3.11/3.12 CI matrix. A separate Ubuntu/Python 3.12 build creates the upload artifacts and verifies repeated wheel/sdist hashes, clean wheel installation, source/APK scans, MCP stdio, and packaged skills. The publishing job waits for all checks and downloads only the two distributions from that build. It uses PyPI Trusted Publishing and attestations; no long-lived PyPI API token is required. Only the publishing job receives `id-token: write`.

After PyPI accepts the release, another job creates the GitHub release and attaches:

- The exact wheel and source distribution uploaded to PyPI.
- `SHA256SUMS` covering the standalone downloads.
- `release-manifest.json` describing the build inputs and verification.
- A verified bundle archive containing the distributions, locked runtime/build requirements, attribution, and its own complete file checksums.

The manifest's `published: false` records that the local build script itself does not publish. The workflow's publishing result and the PyPI release page record whether uploading succeeded.

For a new release, update the package version and documentation, run the checks, commit the inputs, then push the matching tag. For version 1.0.4:

```sh
git tag v1.0.4
git push origin v1.0.4
```

PyPI rejects overwriting an existing release file. If publishing fails, inspect the workflow logs and PyPI's current file list before rerunning. A failed GitHub release attachment can be retried separately from package publication. Pending publishers create the PyPI project on first use; registration alone does not reserve the name.

See [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/) and [pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).
