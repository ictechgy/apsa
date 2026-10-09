# Publishing APSA

The PyPI project is `apsa`. Its GitHub Trusted Publisher uses these exact values:

| Setting | Value |
| --- | --- |
| Repository owner | `ictechgy` |
| Repository name | `apsa` |
| Workflow filename | `release.yml` |
| GitHub environment | `pypi` |

The workflow lives at [`.github/workflows/release.yml`](../.github/workflows/release.yml). It runs when a `v` release tag is pushed, when a maintainer manually runs it on that tag, or for an explicit release commit on `main` described below. A tag invocation must match the version in `pyproject.toml`; other branches are rejected.

Before publishing, the workflow runs the existing macOS/Linux and Python 3.11/3.12 CI matrix. A separate Ubuntu/Python 3.12 build creates the upload artifacts and verifies repeated wheel/sdist hashes, clean wheel installation, source/APK scans, MCP stdio, and packaged skills. The publishing job waits for all checks and downloads only the two distributions from that build. It uses PyPI Trusted Publishing and attestations; no long-lived PyPI API token is required. Only the publishing job receives `id-token: write`.

After PyPI accepts the release, another job creates the GitHub release and attaches:

- The exact wheel and source distribution uploaded to PyPI.
- `SHA256SUMS` covering the standalone downloads.
- `release-manifest.json` describing the build inputs and verification.
- A verified bundle archive containing the distributions, locked runtime/build requirements, attribution, and its own complete file checksums.

The manifest's `published: false` records that the local build script itself does not publish. The workflow's publishing result and the PyPI release page record whether uploading succeeded.

For a new release, update the package version and documentation, run the checks, commit the reviewed inputs, then push the matching tag. Derive the tag from the committed package metadata:

```sh
APSA_RELEASE_TAG="v$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
git tag "$APSA_RELEASE_TAG"
git push origin "$APSA_RELEASE_TAG"
```

PyPI rejects overwriting an existing release file. If publishing fails, inspect the workflow logs and PyPI's current file list before rerunning. A failed GitHub release attachment can be retried separately from package publication. Pending publishers create the PyPI project on first use; registration alone does not reserve the name.

See [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/using-a-publisher/) and [pending publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/).

After PyPI accepts a release, the `mcp-registry` job publishes `server.json` to the [MCP Registry](https://registry.modelcontextprotocol.io) as `io.github.ictechgy/apsa`. It authenticates with GitHub OIDC (no stored secret), requires `server.json` and its package entry to match the released version and `README.md` to contain the `mcp-name` ownership marker, and installs a pinned `mcp-publisher` release verified by SHA-256. It runs without the `pypi` environment, so its token cannot satisfy the PyPI trusted publisher. The registry is in preview; a failed listing does not affect the PyPI release and can be retried by rerunning that job.

The Claude Code plugin in `plugins/apsa` pins `apsa@VERSION`; the marketplace serves whatever the default branch contains, so update the plugin version, `server.json` and `action.yml` together with `pyproject.toml`.

An explicit `Release APSA ...` commit on `main` that changes `pyproject.toml` also starts release verification. The workflow creates the version tag only after all checks pass and refuses a tag bound to different bytes. Its publishing job runs in the original invocation's ref context, so creating a tag does not turn a main-context invocation into a tag-context invocation. Ordinary commits do not publish packages.

If the approved tag was created but the publishing job failed before its steps, inspect job summaries and the environment/publisher configuration. The cause must be verified separately. A maintainer can start the existing workflow on that exact tag without moving it:

```sh
gh workflow run release.yml --repo ictechgy/apsa --ref "$APSA_RELEASE_TAG"
```

This reruns the CI/build gates for the tagged source. A source-only connector may not expose workflow dispatch; do not treat a successful source upload or tag creation as registry publication. Any additional dispatch automation and its permissions require their own review and authorization. Keep the [release sequence](ROADMAP.md) stage gates: confirm each published version before advancing the next candidate.
