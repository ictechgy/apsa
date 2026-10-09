"""Regenerate the packaged OWASP MASWE weakness index from an official release YAML.

The input is the `OWASP_MASWE.yaml` asset of an OWASP MASWE GitHub release. Only
identifiers, titles, platforms, profiles and MASVS/CWE mappings are kept. The
output remains under the source's CC BY-SA 4.0 licence (see THIRD_PARTY_NOTICES.md).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import yaml

OUTPUT = Path(__file__).resolve().parents[1] / "src/mobile_audit/data/maswe.json"


def build(raw: bytes, version: str) -> dict:
    document = yaml.safe_load(raw)
    if document["metadata"]["version"] != version:
        raise ValueError(f"YAML reports {document['metadata']['version']}, expected {version}")
    weaknesses = []
    for identifier, entry in sorted(document["weaknesses"].items()):
        if not re.fullmatch(r"MASWE-\d{4}", identifier) or entry["id"] != identifier:
            raise ValueError(f"Unexpected weakness identifier {identifier}")
        mappings = entry.get("mappings") or {}
        weaknesses.append(
            {
                "id": identifier,
                "title": entry["title"],
                "platform": sorted(entry.get("platform") or []),
                "profiles": list(entry.get("profiles") or []),
                "masvs": list(mappings.get("masvs-v2") or []),
                "cwe": [f"CWE-{value}" for value in mappings.get("cwe") or [] if value != ""],
            }
        )
    return {
        "source": f"OWASP MASWE {version}",
        "url": f"https://github.com/OWASP/maswe/releases/tag/{version}",
        "license": "CC-BY-SA-4.0",
        "license_url": "https://creativecommons.org/licenses/by-sa/4.0/",
        "attribution": "OWASP Mobile Application Security Weakness Enumeration (MASWE), OWASP Foundation; adapted to an identifier/title index.",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "weaknesses": weaknesses,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("yaml", type=Path, help="OWASP_MASWE.yaml from the release")
    parser.add_argument("--version", required=True, help="Release tag, for example v1.0.0")
    parser.add_argument("--out", type=Path, default=OUTPUT)
    args = parser.parse_args()
    index = build(args.yaml.read_bytes(), args.version)
    args.out.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n")
    print(f"{len(index['weaknesses'])} weaknesses written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
