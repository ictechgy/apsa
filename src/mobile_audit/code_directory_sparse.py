"""Bounded XNU scatter mapping; relocation semantics are deliberately unsupported."""

from __future__ import annotations

import struct

MAX_SCATTER_ENTRIES = 4096
MAX_SCATTER_PAGES = 65_536


def scatter_pages(
    blob: bytes, offset: int, minimum: int, hash_start: int, slots: int, page_log: int, code_limit: int
) -> list[int]:
    """Map sequential hash slots to file pages, as XNU cs_get_codepage does.

    Only zero targetOffset/spare is modeled. Gaps are returned to the caller,
    which must keep whole-image coverage partial rather than treating gaps as sealed.
    """
    if not page_log or not slots or offset < minimum or offset + 24 > len(blob):
        raise ValueError("scatter header outside blob or unsupported page geometry")
    pages: list[int] = []
    previous_end = 0
    for entry in range(MAX_SCATTER_ENTRIES):
        cursor = offset + entry * 24
        if cursor + 24 > len(blob) or cursor + 24 > hash_start:
            raise ValueError("scatter table unterminated or overlaps hashes")
        count, base, target, spare = struct.unpack_from(">IIQQ", blob, cursor)
        if target or spare:
            raise ValueError("scatter relocation/reserved fields unsupported")
        if not count:
            if base or len(pages) != slots:
                raise ValueError("scatter sentinel or slot count mismatch")
            return pages
        if base < previous_end or count > MAX_SCATTER_PAGES - len(pages):
            raise ValueError("scatter ranges overlap/unordered or page budget exceeded")
        if count > slots - len(pages) or (base + count - 1) << page_log >= code_limit:
            raise ValueError("scatter range exceeds code limit or slots")
        pages.extend(range(base, base + count))
        previous_end = base + count
    raise ValueError("scatter entry budget exceeded")
