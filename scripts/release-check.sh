#!/usr/bin/env bash
# Unified local checks and clean package verification; never publish.
set -euo pipefail
cd "$(dirname "$0")/.."
make test benchmark
uv run --locked --extra dev python scripts/release.py --out "${RELEASE_OUT:-dist/apsa-local-release}"
for sample in "$@"; do
  set +e
  uv run --locked apsa scan "$sample" --json >/dev/null
  rc=$?
  set -e
  case "$rc" in
    0|4) echo "Verified scan: $sample (rc=$rc)" ;;
    *) echo "Incomplete/failed scan: $sample (rc=$rc)" >&2; exit "$rc" ;;
  esac
done
