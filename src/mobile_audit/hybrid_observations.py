"""Bounded name-only observations carried across the source staging boundary."""

from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath

MAX_BYTES = 2 * 1024 * 1024
MAX_RECORDS = 256
NOTE_NAME = "hybrid-inputs.json"
PROTOCOL = "staged-hybrid-v1"


def validate(document: object) -> dict:
    from .hybrid_analysis import compiled_hybrid_input

    if (
        not isinstance(document, dict)
        or set(document) != {"version", "inputs", "inventory_complete"}
        or type(document["version"]) is not int
        or document["version"] != 1
        or type(document["inventory_complete"]) is not bool
        or not isinstance(document["inputs"], list)
        or len(document["inputs"]) > MAX_RECORDS
    ):
        raise ValueError("Invalid staged hybrid observation schema")
    paths = set()
    for record in document["inputs"]:
        if not isinstance(record, dict) or not isinstance(record.get("path"), str):
            raise ValueError("Invalid staged hybrid observation record")
        path = record["path"]
        if (
            not path
            or len(path.encode("utf-8")) > 4096
            or "\\" in path
            or any(ord(char) < 32 for char in path)
            or PurePosixPath(path).is_absolute()
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or path in paths
            or record != compiled_hybrid_input(path)
        ):
            raise ValueError("Invalid staged name-only hybrid observation")
        paths.add(path)
    return document


def write(scratch: Path, snapshot: dict) -> None:
    document = validate(
        {
            "version": 1,
            "inputs": snapshot.get("hybrid_inputs", []),
            "inventory_complete": bool(snapshot.get("hybrid_input_inventory_complete", True))
            and not bool(snapshot.get("hybrid_inputs_truncated", False)),
        }
    )
    raw = json.dumps(document, sort_keys=True, ensure_ascii=True).encode("utf-8")
    if len(raw) > MAX_BYTES:
        raise ValueError("Staged hybrid observation byte budget exceeded")
    with (scratch / NOTE_NAME).open("xb") as output:
        os.chmod(output.fileno(), 0o600)
        output.write(raw)


def read(scratch: Path) -> dict:
    from .core import open_file

    def unique(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate staged hybrid observation key")
            result[key] = value
        return result

    with os.fdopen(open_file(scratch / NOTE_NAME), "rb") as source:
        raw = source.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Staged hybrid observation byte budget exceeded")
    return validate(json.loads(raw, object_pairs_hook=unique))


def merge(inventory: dict, observations: dict | None) -> None:
    """Prefer loader observations; parent observations establish presence only."""
    if observations is None:
        return
    observations = validate(observations)
    by_path = {record["path"]: record for record in observations["inputs"]}
    by_path.update({record["path"]: record for record in inventory.get("hybrid_inputs", [])})
    inventory["hybrid_inputs"] = [by_path[path] for path in sorted(by_path)[:MAX_RECORDS]]
    inventory["hybrid_inputs_truncated"] = (
        bool(inventory.get("hybrid_inputs_truncated", False))
        or not observations["inventory_complete"]
        or len(by_path) > MAX_RECORDS
    )
    inventory["hybrid_input_inventory_complete"] = not inventory["hybrid_inputs_truncated"]
