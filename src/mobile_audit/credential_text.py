"""Explicit credential-only text admission; no source-language or validity inference."""

from __future__ import annotations

import codecs
from pathlib import Path

# These formats are admitted only to credential matching, never general source analysis.
CREDENTIAL_ONLY_SUFFIXES = {".properties", ".strings", ".pem", ".key"}
CREDENTIAL_TEXT_SUFFIXES = CREDENTIAL_ONLY_SUFFIXES | {
    ".java",
    ".kt",
    ".kts",
    ".swift",
    ".m",
    ".mm",
    ".h",
    ".xml",
    ".plist",
    ".json",
    ".gradle",
    ".yaml",
    ".yml",
    ".toml",
    ".lock",
    ".lockfile",
    ".resolved",
    ".pbxproj",
    ".xcprivacy",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".dart",
    ".jsbundle",
    ".bundle",
}


def credential_only_input(path: str | Path) -> bool:
    return Path(path).suffix in CREDENTIAL_ONLY_SUFFIXES


def credential_text_input(path: str | Path) -> bool:
    return Path(path).suffix in CREDENTIAL_TEXT_SUFFIXES


def decode_credential_text(raw: bytes) -> str | None:
    """Decode bounded plaintext strictly; binary and unsupported encodings stay unknown."""
    if raw.startswith((b"bplist", codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return None
    encoding = "utf-16" if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
    try:
        text = raw.decode(encoding)
    except UnicodeError:
        return None
    if any(ord(char) < 32 and char not in "\t\n\r" for char in text) or "\x7f" in text:
        return None
    return text
