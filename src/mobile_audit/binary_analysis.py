"""Bounded, in-place APK bytecode and IPA executable inspection.

These checks establish instruction/configuration evidence, not exploitability.
Run this module inside the scanner's resource-limited parser process: Androguard
parses attacker-controlled data and its allocations cannot be bounded here alone.
"""

from __future__ import annotations

import hashlib
import plistlib
import re
import struct
import zipfile
import zlib
from pathlib import Path, PurePosixPath
from typing import Any

from .core import MAX_ARCHIVE_TOTAL, MAX_FILES, finding, redact

MAX_DEX_BYTES = 32 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_PLIST_BYTES = 2 * 1024 * 1024
MAX_SIGNATURE_BYTES = 4 * 1024 * 1024
MAX_METHODS = 100_000
MAX_METHOD_INSTRUCTIONS = 65_536
MAX_INSTRUCTIONS = 1_000_000
MAX_FINDINGS = 200
MAX_SLICES = 16
MAX_COMMANDS = 4096
MAX_LIBRARIES = 128

ANDROID_WEBSETTINGS = "https://developer.android.com/reference/android/webkit/WebSettings"
ANDROID_SSL = "https://developer.android.com/reference/android/webkit/SslErrorHandler"
ANDROID_BRIDGE = "https://developer.android.com/reference/android/webkit/WebView#addJavascriptInterface(java.lang.Object,%20java.lang.String)"
MACHO_FORMAT = "https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h"
ENTITLEMENTS_FORMAT = "https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h"

DEX_RULES = (
    "BINARY-WEBVIEW-SSL-BYPASS",
    "BINARY-WEBVIEW-FILE-ACCESS",
    "BINARY-WEBVIEW-JS-BRIDGE",
    "BINARY-WEBVIEW-DEBUGGING",
    "BINARY-STORAGE-TOKEN-PREFS",
    "BINARY-STORAGE-SENSITIVE-LOG",
)


class BinaryFormatError(ValueError):
    """Malformed or unsupported executable data; report incomplete coverage."""


def _safe_text(value: str, limit: int = 512) -> str:
    return redact(value)[:limit]


def _coverage(rule: str, state: str, method: str, note: str) -> dict:
    return {"rule_id": rule, "state": state, "method": method, "mapping_scope": "partial", "note": note}


def _read_member(archive: zipfile.ZipFile, item: zipfile.ZipInfo, limit: int) -> bytes:
    if item.file_size > limit:
        raise BinaryFormatError(f"member exceeds {limit} byte analysis budget")
    with archive.open(item) as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit or len(raw) != item.file_size:
        raise BinaryFormatError("member length exceeds budget or disagrees with ZIP metadata")
    return raw


def _validate_dex(raw: bytes) -> None:
    if len(raw) < 112 or not re.fullmatch(rb"dex\n0(?:35|37|38|39|40)\x00", raw[:8]):
        raise BinaryFormatError("unsupported DEX header (standard versions 035-040 supported)")
    file_size, header_size, endian = struct.unpack_from("<III", raw, 32)
    if file_size != len(raw) or header_size != 112 or endian != 0x12345678:
        raise BinaryFormatError("invalid DEX size, header, or byte order")
    if struct.unpack_from("<I", raw, 8)[0] != zlib.adler32(raw[12:]) & 0xFFFFFFFF:
        raise BinaryFormatError("DEX checksum mismatch")
    if raw[12:32] != hashlib.sha1(raw[32:]).digest():
        raise BinaryFormatError("DEX signature digest mismatch")
    for position, width in ((56, 4), (64, 4), (72, 12), (80, 8), (88, 8), (96, 32)):
        count, offset = struct.unpack_from("<II", raw, position)
        if count and (offset < header_size or offset + count * width > file_size):
            raise BinaryFormatError("DEX identifier table is outside the file")


def _sensitive_key(text: str) -> bool:
    return bool(
        re.search(
            r"(?:^|[_\s.-])(?:access[_-]?token|refresh[_-]?token|token|password|secret|authorization|session)(?:$|[_\s.-])",
            text,
            re.I,
        )
    )


def _dex_finding(
    rule: str, title: str, severity: str, evidence: dict, remediation: str, masvs: str, reference: str
) -> dict:
    return finding(
        rule,
        title,
        severity,
        "candidate",
        [evidence],
        remediation,
        masvs,
        [reference],
        origin="binary",
        confidence="local-constant-propagation"
        if evidence["basis"] != "dex-call-presence"
        else "direct-call",
        validation="Static call evidence; runtime reachability and trust context remain unverified.",
    )


def _analyze_dex(raw: bytes, path: str, remaining: dict[str, int]) -> dict:
    _validate_dex(raw)
    from loguru import logger

    logger.disable("androguard")
    from androguard.core.dex import DEX, Operand, determineNext

    dex = DEX(raw)
    findings: list[dict] = []
    stats: dict[str, Any] = {
        "path": path,
        "methods": 0,
        "instructions": 0,
        "calls": {},
        "complete": True,
        "methods_without_value_tracking": 0,
        "features": [
            feature
            for api, feature in (
                ("Landroid/webkit/", "webview"),
                ("addJavascriptInterface", "javascript_bridge"),
                ("Landroid/database/sqlite/", "local_database"),
                ("Landroid/util/Log;", "logging"),
            )
            if any(api in value for value in dex.get_strings())
        ],
    }
    warnings = []
    for cls in dex.get_classes():
        for method in cls.get_methods():
            code = method.get_code()
            if code is None:
                continue
            if remaining["methods"] <= 0 or remaining["instructions"] <= 0:
                stats["complete"] = False
                warnings.append(f"DEX instruction/method budget reached: {path}")
                return {"findings": findings, "metadata": stats, "warnings": warnings}
            remaining["methods"] -= 1
            stats["methods"] += 1
            instructions = []
            for offset, ins in method.get_instructions_idx():
                if len(instructions) >= MAX_METHOD_INSTRUCTIONS or remaining["instructions"] <= 0:
                    stats["complete"] = False
                    warnings.append(f"DEX method instruction budget reached: {path}")
                    break
                remaining["instructions"] -= 1
                stats["instructions"] += 1
                instructions.append((offset, ins))
            # Never propagate constants across jumps, joins, exception handlers or
            # unknown writes. This intentionally misses inter-block/dataflow cases.
            boundaries = set()
            for offset, ins in instructions:
                boundaries.update(determineNext(ins, offset, method))
            constants: dict[int, tuple[str, Any]] = {}
            pending_result: tuple[str, Any] | None = None
            track_values = code.get_tries_size() == 0
            if not track_values:
                stats["methods_without_value_tracking"] += 1
            caller = _safe_text(f"{method.get_class_name()}->{method.get_name()}{method.get_descriptor()}")
            for offset, ins in instructions:
                if offset in boundaries:
                    constants.clear()
                    pending_result = None
                opcode = ins.get_name()
                operands = ins.get_operands(offset)
                registers = [operand[1] for operand in operands if operand[0] == Operand.REGISTER]
                reference = next(
                    (
                        str(operand[2]).replace(" ", "")
                        for operand in operands
                        if operand[0] == Operand.KIND and len(operand) > 2
                    ),
                    "",
                )
                if opcode.startswith("invoke-") and reference:
                    if reference.startswith(
                        ("Landroid/webkit/", "Landroid/content/SharedPreferences", "Landroid/util/Log;")
                    ):
                        safe_reference = _safe_text(reference)
                        if safe_reference in stats["calls"] or len(stats["calls"]) < 256:
                            stats["calls"][safe_reference] = stats["calls"].get(safe_reference, 0) + 1
                    evidence = {
                        "path": path,
                        "method": caller,
                        "offset": offset,
                        "api": _safe_text(reference),
                        "basis": "dex-call-presence",
                    }
                    pending_result = None
                    output = None
                    if reference == "Landroid/webkit/SslErrorHandler;->proceed()V":
                        output = _dex_finding(
                            "BINARY-WEBVIEW-SSL-BYPASS",
                            "DEX calls WebView SSL error proceed",
                            "high",
                            evidence,
                            "Cancel certificate errors and validate navigation on a prepared test device.",
                            "MASVS-NETWORK",
                            ANDROID_SSL,
                        )
                    elif (
                        reference
                        == "Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object; Ljava/lang/String;)V".replace(
                            " ", ""
                        )
                    ):
                        output = _dex_finding(
                            "BINARY-WEBVIEW-JS-BRIDGE",
                            "DEX registers a JavaScript bridge",
                            "medium",
                            evidence,
                            "Verify which content can invoke the bridge and restrict exposed methods and navigation.",
                            "MASVS-PLATFORM",
                            ANDROID_BRIDGE,
                        )
                    elif reference in {
                        "Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V",
                        "Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V",
                        "Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V",
                    }:
                        argument = constants.get(registers[-1]) if registers and track_values else None
                        if argument == ("integer", 1):
                            evidence.update(
                                {
                                    "basis": "dex-constant-argument-call",
                                    "argument": True,
                                    "value_scope": "same straight-line block",
                                }
                            )
                            debugging = "setWebContentsDebuggingEnabled" in reference
                            output = _dex_finding(
                                "BINARY-WEBVIEW-DEBUGGING" if debugging else "BINARY-WEBVIEW-FILE-ACCESS",
                                "DEX enables WebView debugging"
                                if debugging
                                else "DEX enables cross-origin file URL access",
                                "medium" if debugging else "high",
                                evidence,
                                "Disable this setting in release builds and load local content through WebViewAssetLoader.",
                                "MASVS-PLATFORM",
                                ANDROID_WEBSETTINGS,
                            )
                    elif (
                        reference
                        == "Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String; Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;".replace(
                            " ", ""
                        )
                    ):
                        if (
                            len(registers) == 3
                            and constants.get(registers[1], ("", None))[0] == "sensitive-key"
                        ):
                            evidence.update(
                                {
                                    "basis": "dex-sensitive-key-write",
                                    "key_category": "credential-like",
                                    "encryption": "not-established",
                                }
                            )
                            output = _dex_finding(
                                "BINARY-STORAGE-TOKEN-PREFS",
                                "DEX writes a credential-like preference key",
                                "medium",
                                evidence,
                                "Verify that the value is encrypted appropriately and removed on logout/account switching.",
                                "MASVS-STORAGE",
                                "https://developer.android.com/reference/android/content/SharedPreferences",
                            )
                    elif reference in {
                        "Landroid/content/SharedPreferences;->getString(Ljava/lang/String; Ljava/lang/String;)Ljava/lang/String;".replace(
                            " ", ""
                        ),
                        "Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;",
                        "Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;",
                    }:
                        if (
                            len(registers) >= 2
                            and constants.get(registers[1], ("", None))[0] == "sensitive-key"
                        ):
                            pending_result = ("sensitive-value", reference)
                    elif re.fullmatch(
                        r"Landroid/util/Log;->(?:v|d|i|w|e|wtf)\(Ljava/lang/String; Ljava/lang/String;(?: Ljava/lang/Throwable;)?\)I".replace(
                            " ", ""
                        ),
                        reference,
                    ):
                        if (
                            len(registers) >= 2
                            and constants.get(registers[1], ("", None))[0] == "sensitive-value"
                        ):
                            evidence.update(
                                {
                                    "basis": "dex-local-sensitive-value-flow",
                                    "source_api": constants[registers[1]][1],
                                    "value_scope": "same straight-line block",
                                }
                            )
                            output = _dex_finding(
                                "BINARY-STORAGE-SENSITIVE-LOG",
                                "DEX passes a credential-like value to Android logging",
                                "high",
                                evidence,
                                "Remove credentials from logs and verify release logging and post-logout residue.",
                                "MASVS-STORAGE",
                                "https://developer.android.com/reference/android/util/Log",
                            )
                    if output is not None:
                        if remaining["findings"] > 0:
                            findings.append(output)
                            remaining["findings"] -= 1
                        else:
                            stats["complete"] = False
                            if not warnings:
                                warnings.append(
                                    "Binary finding budget reached; additional call sites may be omitted"
                                )
                    continue
                if opcode.startswith("move-result"):
                    if registers:
                        constants.pop(registers[0], None)
                        if track_values and pending_result is not None:
                            constants[registers[0]] = pending_result
                    pending_result = None
                    continue
                pending_result = None
                if not track_values:
                    continue
                if opcode.startswith("const-string") and registers:
                    constants.pop(registers[0], None)
                    literal = next(
                        (
                            str(operand[2])
                            for operand in operands
                            if operand[0] == Operand.KIND + 1 and len(operand) > 2
                        ),
                        "",
                    )
                    if _sensitive_key(literal):
                        constants[registers[0]] = ("sensitive-key", True)
                elif (
                    opcode.startswith("const")
                    and not opcode.startswith(("const-class", "const-method"))
                    and registers
                ):
                    constants.pop(registers[0], None)
                    value = next((operand[1] for operand in operands if operand[0] == Operand.LITERAL), None)
                    if isinstance(value, int):
                        constants[registers[0]] = ("integer", value)
                elif opcode.startswith("move") and len(registers) == 2:
                    value = constants.get(registers[1])
                    constants.pop(registers[0], None)
                    if value is not None:
                        constants[registers[0]] = value
                elif opcode != "nop":
                    constants.clear()
            if not stats["complete"]:
                return {"findings": findings, "metadata": stats, "warnings": warnings}
    if remaining["findings"] == 0:
        warnings.append("Binary finding budget reached; additional call sites may be omitted")
    return {"findings": findings, "metadata": stats, "warnings": warnings}


def _entitlement_summary(value: Any) -> dict:
    if not isinstance(value, dict) or len(value) > 256:
        raise BinaryFormatError("entitlements must be a bounded dictionary")
    summary: dict[str, Any] = {"keys": sorted(_safe_text(key, 256) for key in value if isinstance(key, str))}
    for key in ("get-task-allow", "com.apple.security.app-sandbox"):
        if isinstance(value.get(key), bool):
            summary[key] = value[key]
    for key in (
        "keychain-access-groups",
        "com.apple.security.application-groups",
        "com.apple.developer.associated-domains",
    ):
        if isinstance(value.get(key), list):
            summary[key + "-count"] = len(value[key])
    return summary


CODE_HASHES = {1: ("sha1", 20), 2: ("sha256", 32), 3: ("sha256", 20), 4: ("sha384", 48)}
MAX_CODE_SLOTS = 65_536


def _code_directory(blob: bytes, code: bytes | None, entitlement_blobs: dict) -> dict:
    """Recompute CodeDirectory page and entitlement-slot hashes.

    Agreement shows the signed code pages and embedded entitlements match this
    directory; it does not authenticate the CMS signature, certificate chain,
    team or provisioning, so signature_verified stays false.
    """
    if len(blob) < 44:
        raise BinaryFormatError("truncated CodeDirectory")
    version, _, hash_offset, ident_offset, special, slots, code_limit = struct.unpack_from(
        ">IIIIIII", blob, 8
    )
    hash_size, hash_type, _, page_log = struct.unpack_from(">BBBB", blob, 36)
    if hash_type not in CODE_HASHES or CODE_HASHES[hash_type][1] != hash_size:
        return {"hash_type": hash_type, "integrity": "unsupported-hash"}
    if version >= 0x20300 and len(blob) >= 64:
        code_limit = struct.unpack_from(">Q", blob, 56)[0] or code_limit
    if slots > MAX_CODE_SLOTS or special > 64 or not 0 <= page_log <= 24:
        raise BinaryFormatError("CodeDirectory slot or page budget exceeded")
    if hash_offset < special * hash_size or hash_offset + slots * hash_size > len(blob):
        raise BinaryFormatError("CodeDirectory hashes are outside the blob")
    algorithm, _ = CODE_HASHES[hash_type]
    identifier = ""
    if 0 < ident_offset < len(blob):
        identifier = _safe_text(
            blob[ident_offset : blob.find(b"\0", ident_offset, ident_offset + 256)].decode(
                "utf-8", errors="replace"
            )
        )
    result: dict[str, Any] = {
        "version": version,
        "hash_type": algorithm,
        "page_size": 1 << page_log if page_log else 0,
        "code_slots": slots,
        "code_limit": code_limit,
        "identifier": identifier,
        "cdhash": hashlib.new(algorithm, blob).hexdigest()[:40],
    }
    if version >= 0x20200 and len(blob) >= 52:
        team_offset = struct.unpack_from(">I", blob, 48)[0]
        if 0 < team_offset < len(blob):
            end = blob.find(b"\0", team_offset, team_offset + 64)
            result["team_identifier_claim"] = _safe_text(blob[team_offset:end].decode("ascii", "replace"))

    def digest(data: bytes) -> bytes:
        return hashlib.new(algorithm, data).digest()[:hash_size]

    mismatched: list[int] = []
    if code is None or code_limit > len(code) or not page_log:
        result["integrity"] = "unverifiable"
    else:
        page = 1 << page_log
        for index in range(slots):
            expected = blob[hash_offset + index * hash_size : hash_offset + (index + 1) * hash_size]
            chunk = code[index * page : min((index + 1) * page, code_limit)]
            if digest(chunk) != expected:
                mismatched.append(index)
        result["pages_mismatched"] = len(mismatched)
        result["mismatched_pages"] = mismatched[:64]
        result["integrity"] = "consistent" if not mismatched else "modified"
    for slot, name in ((5, "entitlements"), (7, "der_entitlements")):
        if slot <= special and slot in entitlement_blobs:
            expected = blob[hash_offset - slot * hash_size : hash_offset - (slot - 1) * hash_size]
            matches = digest(entitlement_blobs[slot]) == expected
            result[name + "_bound"] = matches
            if not matches:
                result["integrity"] = "modified"
    return result


def _code_signature(raw: bytes, code: bytes | None = None) -> dict:
    if len(raw) < 8 or len(raw) > MAX_SIGNATURE_BYTES:
        raise BinaryFormatError("invalid code signature size")
    magic, length = struct.unpack_from(">II", raw)
    if length < 8 or length > len(raw):
        raise BinaryFormatError("code signature blob length mismatch")
    # Linkers reserve/pad the LC_CODE_SIGNATURE region beyond the superblob.
    raw = raw[:length]
    if magic == 0xFADE7171:
        return {
            "entitlements": _entitlement_summary(plistlib.loads(raw[8:])),
            "source": "embedded-xml",
            "signature_verified": False,
        }
    if magic != 0xFADE0CC0 or len(raw) < 12:
        return {"source": "unsupported-code-signature", "signature_verified": False}
    count = struct.unpack_from(">I", raw, 8)[0]
    if count > 128 or 12 + count * 8 > length:
        raise BinaryFormatError("invalid code signature index table")
    result: dict[str, Any] = {"source": "embedded-signature", "signature_verified": False}
    directories = []
    entitlement_blobs: dict[int, bytes] = {}
    for index in range(count):
        slot_type, offset = struct.unpack_from(">II", raw, 12 + index * 8)
        if offset < 12 + count * 8 or offset + 8 > length:
            raise BinaryFormatError("code signature sub-blob is outside the signature")
        blob_magic, blob_length = struct.unpack_from(">II", raw, offset)
        if blob_length < 8 or offset + blob_length > length:
            raise BinaryFormatError("invalid code signature sub-blob length")
        if blob_magic == 0xFADE7171:
            if "entitlements" in result:
                raise BinaryFormatError("duplicate XML entitlement blobs")
            result["entitlements"] = _entitlement_summary(
                plistlib.loads(raw[offset + 8 : offset + blob_length])
            )
            result["source"] = "embedded-xml"
        elif blob_magic == 0xFADE7172:
            result["der_entitlements_present"] = True
        elif blob_magic == 0xFADE0C02 and (slot_type == 0 or 0x1000 <= slot_type < 0x1005):
            directories.append(raw[offset : offset + blob_length])
        elif blob_magic == 0xFADE0B01:
            result["cms_signature_present"] = blob_length > 8
        if blob_magic in (0xFADE7171, 0xFADE7172) and slot_type in (5, 7):
            entitlement_blobs[slot_type] = raw[offset : offset + blob_length]
    if directories:
        result["code_directories"] = [
            _code_directory(blob, code, entitlement_blobs) for blob in directories[:5]
        ]
        states = {d.get("integrity") for d in result["code_directories"]}
        result["integrity"] = (
            "modified"
            if "modified" in states
            else "consistent"
            if states == {"consistent"}
            else "unverifiable"
        )
    return result


def _macho_slice(raw: bytes, offset: int, size: int) -> dict:
    magic = raw[offset : offset + 4]
    formats = {
        b"\xcf\xfa\xed\xfe": ("<", True),
        b"\xfe\xed\xfa\xcf": (">", True),
        b"\xce\xfa\xed\xfe": ("<", False),
        b"\xfe\xed\xfa\xce": (">", False),
    }
    if magic not in formats:
        raise BinaryFormatError("unsupported Mach-O magic")
    endian, is64 = formats[magic]
    header_size = 32 if is64 else 28
    if size < header_size:
        raise BinaryFormatError("truncated Mach-O header")
    _, cpu, subtype, filetype, ncmds, sizeofcmds, flags = struct.unpack_from(endian + "IiiIIII", raw, offset)
    if ncmds > MAX_COMMANDS or sizeofcmds > size - header_size or ncmds * 8 > sizeofcmds:
        raise BinaryFormatError("invalid Mach-O load command budget/size")
    metadata: dict[str, Any] = {
        "offset": offset,
        "size": size,
        "cpu_type": cpu,
        "cpu_subtype": subtype,
        "bits": 64 if is64 else 32,
        "filetype": filetype,
        "pie": bool(flags & 0x200000),
        "flags": flags,
        "linked_libraries": [],
        "linked_libraries_omitted": 0,
        "encryption": {"state": "not-declared"},
        "code_signature": {"state": "not-declared", "signature_verified": False},
    }
    cursor = offset + header_size
    commands_end = cursor + sizeofcmds
    for _ in range(ncmds):
        if cursor + 8 > commands_end:
            raise BinaryFormatError("truncated load command")
        command, command_size = struct.unpack_from(endian + "II", raw, cursor)
        if command_size < 8 or command_size % (8 if is64 else 4) or cursor + command_size > commands_end:
            raise BinaryFormatError("invalid load command length/alignment")
        if command in (0xC, 0x18 | 0x80000000, 0x1F | 0x80000000, 0x20, 0x23 | 0x80000000):
            if command_size < 24:
                raise BinaryFormatError("truncated dylib command")
            name_offset, _, current_version, compatibility = struct.unpack_from(
                endian + "IIII", raw, cursor + 8
            )
            if name_offset < 24 or name_offset >= command_size:
                raise BinaryFormatError("invalid dylib name offset")
            name_field = raw[cursor + name_offset : min(cursor + command_size, cursor + name_offset + 1024)]
            if b"\0" not in name_field:
                raise BinaryFormatError("unterminated or oversized dylib path")
            name = name_field.split(b"\0", 1)[0]
            if len(metadata["linked_libraries"]) < MAX_LIBRARIES:
                metadata["linked_libraries"].append(
                    {
                        "path": _safe_text(name.decode("utf-8", errors="replace")),
                        "current_version": current_version,
                        "compatibility_version": compatibility,
                    }
                )
            else:
                metadata["linked_libraries_omitted"] += 1
        elif command in (0x21, 0x2C):
            if command_size < (24 if command == 0x2C else 20):
                raise BinaryFormatError("truncated encryption command")
            cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", raw, cursor + 8)
            if cryptoff > size or cryptsize > size - cryptoff:
                raise BinaryFormatError("encrypted region is outside the Mach-O slice")
            if metadata["encryption"]["state"] != "not-declared":
                raise BinaryFormatError("multiple encryption commands")
            metadata["encryption"] = {
                "state": "encrypted" if cryptid else "unencrypted",
                "cryptid": cryptid,
                "offset": cryptoff,
                "size": cryptsize,
            }
        elif command == 0x1D:
            if command_size < 16 or metadata["code_signature"]["state"] != "not-declared":
                raise BinaryFormatError("invalid/duplicate code signature command")
            dataoff, datasize = struct.unpack_from(endian + "II", raw, cursor + 8)
            if dataoff > size or datasize > size - dataoff or datasize > MAX_SIGNATURE_BYTES:
                raise BinaryFormatError("code signature is outside slice or exceeds budget")
            metadata["code_signature"] = {
                "state": "present",
                **_code_signature(
                    raw[offset + dataoff : offset + dataoff + datasize], raw[offset : offset + size]
                ),
            }
        cursor += command_size
    encryption = metadata["encryption"]
    signature = metadata["code_signature"]
    if encryption["state"] == "encrypted" and signature.get("code_directories"):
        # App Store encryption follows signing; the kernel checks decrypted pages.
        start, end = encryption["offset"], encryption["offset"] + encryption["size"]
        for directory in signature["code_directories"]:
            page = directory.get("page_size") or 0
            pages = directory.get("mismatched_pages", [])
            if (
                directory.get("integrity") == "modified"
                and page
                and len(pages) == directory.get("pages_mismatched")
                and all(index * page < end and (index + 1) * page > start for index in pages)
                and directory.get("entitlements_bound", True)
            ):
                directory["integrity"] = "unverifiable-encrypted-pages"
        states = {d.get("integrity") for d in signature["code_directories"]}
        signature["integrity"] = (
            "modified"
            if "modified" in states
            else "consistent"
            if states == {"consistent"}
            else "unverifiable"
        )
    if cursor != commands_end:
        raise BinaryFormatError("Mach-O load command total disagrees with header")
    return metadata


def inspect_macho(raw: bytes) -> list[dict]:
    """Parse thin/fat executable metadata without disassembly or extraction."""
    if len(raw) > MAX_BINARY_BYTES or len(raw) < 4:
        raise BinaryFormatError("Mach-O exceeds size budget or has no header")
    fat_formats = {
        b"\xca\xfe\xba\xbe": (">", False),
        b"\xbe\xba\xfe\xca": ("<", False),
        b"\xca\xfe\xba\xbf": (">", True),
        b"\xbf\xba\xfe\xca": ("<", True),
    }
    if raw[:4] not in fat_formats:
        return [_macho_slice(raw, 0, len(raw))]
    endian, fat64 = fat_formats[raw[:4]]
    if len(raw) < 8:
        raise BinaryFormatError("truncated fat Mach-O header")
    count = struct.unpack_from(endian + "I", raw, 4)[0]
    width = 32 if fat64 else 20
    table_end = 8 + count * width
    if not 1 <= count <= MAX_SLICES or table_end > len(raw):
        raise BinaryFormatError("invalid fat Mach-O slice table")
    slices = []
    regions: list[tuple[int, int]] = []
    for index in range(count):
        values = struct.unpack_from(endian + ("iiQQII" if fat64 else "iiIII"), raw, 8 + index * width)
        cpu, subtype, offset, size, alignment = values[:5]
        if (
            alignment > 31
            or offset % (1 << alignment)
            or offset < table_end
            or size < 28
            or offset + size > len(raw)
        ):
            raise BinaryFormatError("invalid fat Mach-O slice bounds/alignment")
        if any(offset < end and start < offset + size for start, end in regions):
            raise BinaryFormatError("overlapping fat Mach-O slices")
        regions.append((offset, offset + size))
        metadata = _macho_slice(raw, offset, size)
        if metadata["cpu_type"] != cpu or metadata["cpu_subtype"] != subtype:
            raise BinaryFormatError("fat architecture and Mach-O header disagree")
        slices.append(metadata)
    return slices


def _profile_metadata(raw: bytes) -> dict:
    # This observes the CMS payload only. It neither verifies CMS signatures nor
    # treats a provisioning profile's permitted entitlements as signed app values.
    start, end = raw.find(b"<?xml"), raw.find(b"</plist>")
    if start < 0 or end < start:
        raise BinaryFormatError("provisioning profile has no observable XML plist")
    value = plistlib.loads(raw[start : end + len(b"</plist>")])
    if not isinstance(value, dict):
        raise BinaryFormatError("provisioning payload must be a dictionary")
    return {
        "source": "provisioning-profile",
        "signature_verified": False,
        "effective_app_entitlements": False,
        "permitted_entitlements": _entitlement_summary(value.get("Entitlements", {})),
    }


def analyze_binary(path: Path, collected: dict) -> dict:
    """Return serializable findings, coverage, warnings and metadata for an APK/IPA."""
    result: dict[str, Any] = {
        "findings": [],
        "coverage": [],
        "warnings": [],
        "metadata": {"engine": "mobile-audit-binary-v1"},
    }
    kind = path.suffix.lower()
    if kind not in {".apk", ".ipa", ".aab"} or not path.is_file():
        return result
    if path.stat().st_size > MAX_ARCHIVE_TOTAL:
        raise ValueError("Archive exceeds binary analysis size limit")
    with zipfile.ZipFile(path) as archive:
        items = archive.infolist()
        if len(items) > MAX_FILES or sum(item.file_size for item in items) > MAX_ARCHIVE_TOTAL:
            raise ValueError("Archive exceeds binary analysis size/file-count limit")
        names = set()
        for item in items:
            name = item.filename
            if name.startswith("/") or ".." in PurePosixPath(name).parts or "\\" in name or "\0" in name:
                raise ValueError("Unsafe archive member path")
            if name in names:
                raise ValueError("Duplicate archive member path")
            names.add(name)
        if kind in {".apk", ".aab"}:
            dex_items = [
                item
                for item in items
                if re.fullmatch(
                    (r"[^/]+/dex/" if kind == ".aab" else "") + r"classes(?:[2-9]\d*|1\d+)?.dex",
                    item.filename,
                )
            ]
            undeclared = []
            if kind == ".aab":
                modules = {
                    item.filename.split("/")[0]
                    for item in items
                    if re.fullmatch(r"[^/]+/manifest/AndroidManifest.xml", item.filename)
                }
                undeclared = [item for item in dex_items if item.filename.split("/")[0] not in modules]
                dex_items = [item for item in dex_items if item.filename.split("/")[0] in modules]
                result["metadata"]["undeclared_module_dex"] = [item.filename for item in undeclared][:128]
                if undeclared:
                    result["warnings"].append(
                        "AAB DEX under undeclared module paths skipped; coverage partial"
                    )
            metadata = []
            remaining = {"methods": MAX_METHODS, "instructions": MAX_INSTRUCTIONS, "findings": MAX_FINDINGS}
            byte_budget = MAX_BINARY_BYTES
            for item in dex_items:
                try:
                    if item.file_size > byte_budget:
                        raise BinaryFormatError("cumulative DEX byte budget reached")
                    raw = _read_member(archive, item, MAX_DEX_BYTES)
                    byte_budget -= len(raw)
                    analysis = _analyze_dex(raw, item.filename, remaining)
                    if kind == ".aab":
                        analysis["metadata"]["module"] = item.filename.split("/")[0]
                        analysis["metadata"]["installation_state"] = "unknown"
                    result["findings"].extend(analysis["findings"])
                    result["warnings"].extend(analysis["warnings"])
                    metadata.append(analysis["metadata"])
                except Exception as error:
                    result["warnings"].append(
                        f"DEX inspection incomplete for {item.filename}: {type(error).__name__}"
                    )
                    metadata.append({"path": item.filename, "complete": False, "error": type(error).__name__})
            complete = bool(metadata) and not undeclared and all(entry["complete"] for entry in metadata)
            result["metadata"]["dex"] = metadata
            for rule in DEX_RULES:
                result["coverage"].append(
                    _coverage(
                        rule,
                        "checked" if complete else "partial" if metadata else "not-run",
                        "dex-instructions",
                        "Direct invokes and local straight-line constants/credential-value flows only; no interprocedural reachability, reflection, native code or dynamically loaded code analysis.",
                    )
                )
            if not dex_items:
                result["warnings"].append(
                    "APK contains no supported root classes*.dex entries; bytecode checks not run"
                )
        else:
            plist_items = [
                item for item in items if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", item.filename)
            ]
            apps = []
            for item in plist_items[:8]:
                app: dict[str, Any] = {"plist": item.filename}
                try:
                    info_raw = _read_member(archive, item, MAX_PLIST_BYTES)
                    info = plistlib.loads(info_raw)
                    from .core import digest

                    app["info_plist_sha256"] = digest(info_raw)
                    if not isinstance(info, dict):
                        raise BinaryFormatError("Info.plist must be a dictionary")
                    package = info.get("CFBundleIdentifier", "")
                    if collected.get("package") and package != collected["package"]:
                        continue
                    executable = info.get("CFBundleExecutable")
                    if (
                        not isinstance(executable, str)
                        or not executable
                        or executable in {".", ".."}
                        or "/" in executable
                        or "\\" in executable
                    ):
                        raise BinaryFormatError("Info.plist has no safe executable name")
                    executable_path = str(PurePosixPath(item.filename).parent / executable)
                    app["executable"] = executable_path
                    raw = _read_member(archive, archive.getinfo(executable_path), MAX_BINARY_BYTES)
                    from .core import digest

                    app["executable_sha256"] = digest(raw)
                    app["executable_bytes"] = len(raw)
                    app["slices"] = inspect_macho(raw)
                    for index, slice_ in enumerate(app["slices"]):
                        evidence = {
                            "path": executable_path,
                            "slice": index,
                            "architecture": slice_["cpu_type"],
                            "basis": "macho-header",
                        }
                        if slice_["filetype"] == 2 and not slice_["pie"]:
                            result["findings"].append(
                                finding(
                                    "BINARY-IOS-PIE",
                                    "Main executable does not declare position-independent loading",
                                    "medium",
                                    "configuration-confirmed",
                                    [{**evidence, "pie": False}],
                                    "Enable position-independent executables and verify the intended release build configuration.",
                                    "MASVS-RESILIENCE",
                                    [MACHO_FORMAT],
                                    origin="binary",
                                    confidence="header-observation",
                                )
                            )
                        signature = slice_["code_signature"]
                        if signature.get("entitlements", {}).get("get-task-allow") is True:
                            result["findings"].append(
                                finding(
                                    "BINARY-IOS-DEBUG-ENTITLEMENT",
                                    "Embedded XML app entitlements request debugging",
                                    "medium",
                                    "candidate"
                                    if signature.get("der_entitlements_present")
                                    else "configuration-confirmed",
                                    [
                                        {
                                            **evidence,
                                            "basis": "codesign-entitlement-observed",
                                            "get-task-allow": True,
                                            "signature_verified": False,
                                        }
                                    ],
                                    "Remove get-task-allow from the release signing configuration; verify the signed distribution build.",
                                    "MASVS-RESILIENCE",
                                    [ENTITLEMENTS_FORMAT],
                                    origin="binary",
                                    confidence="embedded-entitlement-observation",
                                )
                            )
                    profile_path = str(PurePosixPath(item.filename).parent / "embedded.mobileprovision")
                    if profile_path in names:
                        try:
                            app["provisioning"] = _profile_metadata(
                                _read_member(archive, archive.getinfo(profile_path), MAX_PLIST_BYTES)
                            )
                        except Exception as error:
                            result["warnings"].append(
                                f"Provisioning profile metadata unavailable: {type(error).__name__}"
                            )
                    app["complete"] = all(slice_["linked_libraries_omitted"] == 0 for slice_ in app["slices"])
                    if not app["complete"]:
                        result["warnings"].append(
                            "IPA linked library metadata exceeds per-slice output budget"
                        )
                except Exception as error:
                    app.update({"complete": False, "error": type(error).__name__})
                    result["warnings"].append(
                        f"IPA executable inspection incomplete for {item.filename}: {type(error).__name__}"
                    )
                apps.append(app)
            if len(plist_items) > 8:
                result["warnings"].append("IPA main app count exceeds eight-app metadata budget")
            result["metadata"]["apps"] = apps
            if not apps:
                result["warnings"].append(
                    "IPA contains no matching main app Info.plist; executable checks not run"
                )
            complete = bool(apps) and len(plist_items) <= 8 and all(app["complete"] for app in apps)
            result["coverage"].append(
                _coverage(
                    "BINARY-IOS-MACHO",
                    "checked" if complete else "partial" if apps else "not-run",
                    "macho-metadata",
                    "Main executable headers, load commands, encryption flags and linked libraries only; no native code reachability or vulnerability-absence claim.",
                )
            )
            signatures = [slice_["code_signature"] for app in apps for slice_ in app.get("slices", [])]
            entitlements_complete = bool(signatures) and all(
                "entitlements" in signature and not signature.get("der_entitlements_present")
                for signature in signatures
            )
            result["coverage"].append(
                _coverage(
                    "BINARY-IOS-ENTITLEMENTS",
                    "checked" if entitlements_complete else "partial" if signatures else "not-run",
                    "codesign-metadata",
                    "Embedded XML entitlement observation only. DER entitlements and cryptographic signature verification are not implemented. Provisioning profile values are permissions, not effective app entitlements.",
                )
            )
            integrity = [signature.get("integrity", "unverifiable") for signature in signatures]
            if "modified" in integrity:
                result["warnings"].append(
                    "Main executable code pages or entitlements do not match their CodeDirectory hashes; "
                    "the binary changed after signing or is corrupt."
                )
            result["coverage"].append(
                _coverage(
                    "BINARY-IOS-CODE-INTEGRITY",
                    "checked"
                    if integrity and all(state in {"consistent", "modified"} for state in integrity)
                    else "partial"
                    if integrity
                    else "not-run",
                    "codedirectory-hashes",
                    "Recomputes CodeDirectory page and entitlement-slot hashes. Agreement is internal integrity only; the CMS signature, certificate chain, team identity and provisioning are not authenticated.",
                )
            )
            result["coverage"].append(
                _coverage(
                    "BINARY-IOS-CODE-PATHS",
                    "not-run",
                    "native-code",
                    "Mach-O metadata does not inspect native instructions; source and prepared runtime tests are required for application security flows.",
                )
            )
            if any(
                slice_["encryption"]["state"] == "encrypted"
                for app in apps
                for slice_ in app.get("slices", [])
            ):
                result["warnings"].append(
                    "IPA main executable declares encrypted code; code paths were not inspected"
                )
            from .ios_embedded import analyze_embedded

            embedded = analyze_embedded(
                archive,
                apps,
                names,
                max(0, MAX_BINARY_BYTES - sum(app.get("executable_bytes", 0) for app in apps)),
            )
            result["metadata"]["embedded"] = embedded["metadata"]
            result["findings"].extend(embedded["findings"])
            result["warnings"].extend(embedded["warnings"])
            result["coverage"].append(
                _coverage(
                    "BINARY-IOS-EMBEDDED-MACHO",
                    "checked"
                    if embedded["complete"] and embedded["metadata"]
                    else "partial"
                    if embedded["metadata"] or not embedded["complete"]
                    else "not-run",
                    "embedded-macho-metadata",
                    "Declared nested app/appex/framework and Frameworks dylib headers only; no main identity replacement, native instructions, signature verification or installed reachability proof.",
                )
            )
            if len(result["findings"]) > MAX_FINDINGS:
                result["findings"] = result["findings"][:MAX_FINDINGS]
                result["warnings"].append("IPA executable finding budget reached; coverage incomplete")
                result["coverage"][-1]["state"] = "partial"
    return result
