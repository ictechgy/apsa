"""Unified CLI, retaining the original lint commands and exit contracts."""

from __future__ import annotations

import sys


def main(argv=None, runner=None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in {"apk", "ipa", "device"}:
        from .legacy_cli import main as legacy_main

        return legacy_main(arguments, runner=runner)
    from mobile_audit.cli import main as audit_main

    return audit_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
