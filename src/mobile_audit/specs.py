"""Project taint specifications: sources and sinks a reviewer or agent declares.

A specification only names exact functions; it never supplies patterns or code.
APSA validates it, then its own function-local analysis decides whether a
declared source reaches a sink without a recognized guard. Findings it causes
stay candidates and record the specification ID and hash.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from .core import digest, read_bounded

MAX_SPEC_BYTES = 64 * 1024
MAX_ENTRIES = 100
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]{0,39}")
NAME = re.compile(r"[A-Za-z_$][\w$]{0,99}")
RECEIVER = re.compile(r"[A-Za-z_$][\w$.]{0,199}")
SOURCE_KINDS = {"url", "text"}
SINK_KINDS = {"webview-load": "AST-WEBVIEW-UNTRUSTED-URL", "sql": "AST-SQL-CONCAT"}


def _text(entry: dict, key: str, pattern: re.Pattern, *, required: bool = True) -> str | None:
    value = entry.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"Specification field {key!r} is missing or invalid")
    return value


def normalize(document: dict) -> dict:
    if not isinstance(document, dict) or type(document.get("version")) is not int or document["version"] != 1:
        raise ValueError("Specification must be a table with version = 1")
    unknown = set(document) - {"version", "source", "sink"}
    if unknown:
        raise ValueError(f"Unknown specification keys: {', '.join(sorted(unknown))}")
    sources, sinks, seen = [], [], set()
    for kind, entries in (("source", document.get("source", [])), ("sink", document.get("sink", []))):
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise ValueError(f"{kind} must be a list of at most {MAX_ENTRIES} entries")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"Each {kind} must be a table")
            allowed = {"id", "method", "receiver", "note"} | (
                {"returns"} if kind == "source" else {"kind", "argument"}
            )
            if set(entry) - allowed:
                raise ValueError(f"Unknown {kind} fields: {', '.join(sorted(set(entry) - allowed))}")
            identifier = _text(entry, "id", IDENTIFIER)
            if identifier in seen:
                raise ValueError(f"Duplicate specification ID {identifier}")
            seen.add(identifier)
            note = entry.get("note", "")
            if not isinstance(note, str) or len(note) > 200:
                raise ValueError("note must be text of at most 200 characters")
            item = {
                "id": identifier,
                "method": _text(entry, "method", NAME),
                "receiver": _text(entry, "receiver", RECEIVER, required=False),
                "note": note,
            }
            if kind == "source":
                returns = entry.get("returns", "text")
                if returns not in SOURCE_KINDS:
                    raise ValueError(f"source returns must be one of {sorted(SOURCE_KINDS)}")
                sources.append({**item, "returns": returns})
            else:
                sink_kind = entry.get("kind")
                argument = entry.get("argument", 0)
                if sink_kind not in SINK_KINDS:
                    raise ValueError(f"sink kind must be one of {sorted(SINK_KINDS)}")
                if type(argument) is not int or not 0 <= argument <= 15:
                    raise ValueError("sink argument must be an integer 0-15")
                sinks.append({**item, "kind": sink_kind, "argument": argument})
    if not sources and not sinks:
        raise ValueError("Specification declares no sources or sinks")
    return {"version": 1, "source": sources, "sink": sinks}


def load_specs(path: Path) -> dict:
    """Validate a TOML or JSON specification file and return it with its SHA-256."""
    raw = read_bounded(path, MAX_SPEC_BYTES)
    try:
        document = json.loads(raw) if path.suffix.lower() == ".json" else tomllib.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError) as error:
        raise ValueError(f"Specification is not valid TOML/JSON: {error}") from None
    specs = normalize(document)
    return {**specs, "sha256": digest(raw)}


def summary(specs: dict) -> dict:
    return {
        "sha256": specs["sha256"],
        "sources": [item["id"] for item in specs["source"]],
        "sinks": [item["id"] for item in specs["sink"]],
    }
