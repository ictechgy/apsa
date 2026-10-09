"""Extend the exact frozen replay without replacing any earlier input or result."""

from __future__ import annotations

import sys

from benchmarks import coverage_replay
from benchmarks.real_world import sha

PREVIOUS = coverage_replay.CASES.parent / "results/2026-10-09-public-coverage-extension.json"
PREVIOUS_SHA = "499910bb95bbb25bd596a235ec571dfe98f853906f3aa094e1e01a554880267d"


def main():
    if sha(PREVIOUS.read_bytes()) != PREVIOUS_SHA:
        raise ValueError("Frozen development coverage summary changed")
    coverage_replay.main()
    # The existing summary carries development-rerun semantics and original byte guards.
    # This invocation does not contact any upstream application or recapture OSV queries.


if __name__ == "__main__":
    sys.exit(main())
