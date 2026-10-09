"""Apple CNA branch correlation with matching vendor bulletin evidence."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

APPLE_ORG = "286789f9-fbc2-4510-9f9a-43facdede74c"
PRODUCTS = {"ios": {"ios", "iphone os", "ios and ipados"}, "ipados": {"ipados", "ios and ipados"}}


def apple_cna(cve: dict, product: dict) -> bool:
    return (
        cve.get("assigner_org_id") == APPLE_ORG
        and cve.get("cna_org_id") == APPLE_ORG
        and product.get("vendor", "").casefold() == "apple"
    )


def custom_boundaries(product: dict) -> set[tuple[int, ...]] | None:
    boundaries = set()
    for entry in product.get("versions", []):
        upper = numeric_version(entry.get("lessThan"))
        if (
            upper is None
            or entry.get("version") != "0"
            or entry.get("versionType") != "custom"
            or entry.get("status") != "affected"
            or entry.get("changes")
            or "lessThanOrEqual" in entry
        ):
            return None
        boundaries.add(upper)
    return boundaries or None


def numeric_version(value: object) -> tuple[int, ...] | None:
    if not isinstance(value, str) or not re.fullmatch(
        r"(?:0|[1-9][0-9]{0,3})(?:\.(?:0|[1-9][0-9]{0,3})){1,3}", value
    ):
        return None
    parts = tuple(int(p) for p in value.split("."))
    return parts + (0,) * (4 - len(parts))


def official_reference(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return (
        parsed.scheme == "https"
        and parsed.netloc == "support.apple.com"
        and not parsed.fragment
        and not parsed.query
    )


def apple_branch_range(
    version: str, product: dict, cve: dict, advisory: dict, os_product: str
) -> bool | None:
    """Interpret only one confirmed zero-based custom boundary in the observed major.

    Other majors are not declared safe. A vendor fixed label alone is insufficient:
    the Apple-assigned/CNA-published range, exact product, boundary and reference
    must agree. The result is outside this published branch, not proof of patching.
    """
    current = numeric_version(version)
    if current is None or not apple_cna(cve, product) or advisory.get("source") != "apple":
        return None
    shared = set(cve.get("references", [])) & set(advisory.get("references", []))
    if not any(official_reference(url) for url in shared):
        return None
    published_boundaries = custom_boundaries(product)
    if published_boundaries is None:
        return None
    boundaries = {upper for upper in published_boundaries if upper[0] == current[0]}
    if len(boundaries) != 1:
        return None
    boundary = next(iter(boundaries))
    label = advisory.get("fixed_release", "")
    if not re.fullmatch(
        r"(?:iOS|iPadOS)\s+[0-9]+(?:\.[0-9]+){1,3}(?:\s+and\s+(?:iOS|iPadOS)\s+[0-9]+(?:\.[0-9]+){1,3})?",
        label,
        re.I,
    ):
        return None
    published = {
        numeric_version(number)
        for name, number in re.findall(r"\b(iOS|iPadOS)\s+(\d+(?:\.\d+){1,3})\b", label, re.I)
        if name.casefold() == os_product
    }
    if boundary not in published:
        return None
    return current < boundary
