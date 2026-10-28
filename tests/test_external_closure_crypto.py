"""Fresh instruction-level controls for the R5 bare-AES attribution regression.

The fixture constructs its own DEX tables and accepts literal instruction words;
it does not use the legacy helper's fixed v0 const-string/invoke sequence.
These are parser fixtures, not executable Android applications.
"""

from __future__ import annotations

import struct

import pytest

from quaygate.dexcode import analyze_dex

_STRINGS = (
    "Lfixture/Crypto;",
    "run",
    "Ljavax/crypto/Cipher;",
    "getInstance",
    "AES",
    "AES/GCM/NoPadding",
    "Ljavax/crypto/KeyGenerator;",
    "Ljavax/crypto/spec/SecretKeySpec;",
    "<init>",
    "Ljava/security/MessageDigest;",
    "SHA-256",
)


def _uleb(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _instruction_dex(words: list[int], *, registers: int = 16, handlers: bool = False) -> bytes:
    """Encode one method and four API references without a shared test builder."""
    data = bytearray(0x300)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<II", data, 0x24, 0x70, 0x12345678)
    string_ids = 0x70
    type_ids = string_ids + 4 * len(_STRINGS)
    method_ids = type_ids + 5 * 4
    class_defs = method_ids + 5 * 8
    struct.pack_into("<II", data, 0x38, len(_STRINGS), string_ids)
    struct.pack_into("<II", data, 0x40, 5, type_ids)
    struct.pack_into("<II", data, 0x58, 5, method_ids)
    struct.pack_into("<II", data, 0x60, 1, class_defs)
    for index, string in enumerate((0, 2, 6, 7, 9)):
        struct.pack_into("<I", data, type_ids + 4 * index, string)
    for index, (owner, name) in enumerate(((0, 1), (1, 3), (2, 3), (3, 8), (4, 3))):
        struct.pack_into("<HHI", data, method_ids + 8 * index, owner, 0, name)
    struct.pack_into("<I", data, class_defs + 24, 0x250)
    class_data = b"\0\0\1\0\0\x09" + _uleb(0x300)
    data[0x250 : 0x250 + len(class_data)] = class_data
    data.extend(struct.pack("<HHHHII", registers, 0, 5, int(handlers), 0, len(words)))
    data.extend(struct.pack(f"<{len(words)}H", *words))
    for index, string in enumerate(_STRINGS):
        struct.pack_into("<I", data, string_ids + 4 * index, len(data))
        data.extend(_uleb(len(string)) + string.encode("ascii") + b"\0")
    struct.pack_into("<I", data, 0x20, len(data))
    return bytes(data)


def _weak(words: list[int], *, registers: int = 16, handlers: bool = False) -> list[str]:
    result = analyze_dex(_instruction_dex(words, registers=registers, handlers=handlers))
    assert result is not None
    assert result["complete"] is True
    assert result["scanned"] == 1
    return result["weak_crypto"]


@pytest.mark.parametrize(
    "key_use",
    [
        [],  # An unrelated inlined key-algorithm property.
        [0x1071, 2, 0x0007],  # KeyGenerator.getInstance(v7).
        [0x3070, 3, 0x0765],  # SecretKeySpec.<init>(v5, v6, v7).
    ],
    ids=["property", "key-generator", "secret-key-spec"],
)
def test_unrelated_aes_with_gcm_does_not_invent_call_argument(key_use: list[int]) -> None:
    assert _weak([0x071A, 4, *key_use, 0x021A, 5, 0x1071, 1, 0x0002, 0x000E]) == []


def test_direct_bare_aes_in_nonzero_register_is_preserved() -> None:
    findings = _weak([0x071A, 4, 0x1071, 1, 0x0007, 0x000E])
    assert len(findings) == 1
    assert "Cipher.getInstance('AES')" in findings[0]


@pytest.mark.parametrize(
    ("moves", "invoke", "registers"),
    [
        ([0x7207], [0x1071, 1, 0x0002], 16),  # move-object v2, v7 (12x).
        ([0x0208, 7], [0x1071, 1, 0x0002], 16),  # move-object/from16 v2, v7 (22x).
        ([0x0009, 300, 7], [0x0177, 1, 300], 320),  # move-object/16 + invoke-static/range.
    ],
)
def test_object_moves_and_range_keep_proven_argument(
    moves: list[int], invoke: list[int], registers: int
) -> None:
    findings = _weak([0x071A, 4, *moves, *invoke, 0x000E], registers=registers)
    assert len(findings) == 1
    assert "Cipher.getInstance('AES')" in findings[0]


def test_jumbo_const_string_uses_32_bit_index_and_register() -> None:
    findings = _weak([0x071B, 4, 0, 0x1071, 1, 7, 0x000E])
    assert len(findings) == 1
    assert "Cipher.getInstance('AES')" in findings[0]


@pytest.mark.parametrize(
    "overwrite",
    [
        [0x021A, 5],  # Reassignment to AES/GCM/NoPadding.
        [0x020C],  # move-result-object v2.
        [0x0262, 0],  # sget-object v2, field@0.
        [0x0116, 0],  # const-wide/16 v1 overlaps tracked v2.
        [0x3207],  # move-object v2, v3 (unknown source).
    ],
)
def test_reassigned_register_is_not_proven_aes(overwrite: list[int]) -> None:
    assert _weak([0x021A, 4, *overwrite, 0x1071, 1, 2, 0x000E]) == []


@pytest.mark.parametrize(
    "barrier",
    [
        [0x0038, 4],  # if-eqz v0 skips the following const-string.
        [0x0428],  # goto skips the following const-string.
        [0x0073],  # Unused/unknown opcode.
        [0x000E],  # Unreachable instructions after return-void.
    ],
)
def test_control_flow_and_unknown_instruction_end_proof_prefix(barrier: list[int]) -> None:
    assert _weak([*barrier, 0x021A, 4, 0x1071, 1, 2, 0x000E]) == []


def test_later_control_flow_keeps_already_proven_entry_prefix() -> None:
    findings = _weak([0x021A, 4, 0x1071, 1, 2, 0x0038, 0xFFFD, 0x000E])
    assert len(findings) == 1
    assert "Cipher.getInstance('AES')" in findings[0]


def test_handler_entry_is_outside_linear_proof_scope() -> None:
    assert _weak([0x021A, 4, 0x1071, 1, 2, 0x000E], handlers=True) == []


def test_aes_message_digest_does_not_invent_cipher_call() -> None:
    assert _weak([0x071A, 4, 0x1071, 4, 7, 0x021A, 5, 0x1071, 1, 2, 0x000E]) == []


@pytest.mark.parametrize("invoke", [[0x2071, 1, 0x0076], [0x0277, 1, 6]])
def test_aes_in_second_argument_does_not_replace_first(invoke: list[int]) -> None:
    assert _weak([0x071A, 4, 0x061A, 5, *invoke, 0x000E]) == []


@pytest.mark.parametrize("invoke", [[0x0071, 1, 2], [0x6071, 1, 2], [0x0077, 1, 2]])
def test_invalid_or_empty_argument_layout_is_not_proven(invoke: list[int]) -> None:
    assert _weak([0x021A, 4, *invoke, 0x000E]) == []


@pytest.mark.parametrize("invoke", [[0x2071, 1, 0x00F2], [0x5F71, 1, 0x1112], [0x0277, 1, 7]])
def test_out_of_bounds_argument_registers_are_not_proven(invoke: list[int]) -> None:
    assert _weak([0x021A, 4, 0x071A, 4, *invoke, 0x000E], registers=8) == []


def test_aes_passed_to_another_call_does_not_taint_later_cipher() -> None:
    assert _weak([0x071A, 4, 0x1071, 2, 7, 0x021A, 5, 0x1071, 1, 2, 0x000E]) == []
