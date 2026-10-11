"""Generate new synthetic bundletool TOCs and APK sets; never read fixture archives."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path


def integer(value: int) -> bytes:
    output = bytearray()
    while value > 127:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def field(number: int, value: int | bytes | str) -> bytes:
    if isinstance(value, int):
        return integer(number << 3) + integer(value)
    raw = value.encode() if isinstance(value, str) else value
    return integer((number << 3) | 2) + integer(len(raw)) + raw


def dimension(kind: str, values=(), alternatives=()) -> bytes:
    def atom(value):
        if kind == "sdk":
            return field(1, field(1, value))
        if kind == "language":
            return value.encode()
        return field(2 if kind == "density" else 1, value)

    return b"".join(
        field(number, atom(value)) for number, items in ((1, values), (2, alternatives)) for value in items
    )


def targeting(*, variant=False, **dimensions) -> bytes:
    mapping = (
        {"sdk": 1, "abi": 2, "density": 3} if variant else {"abi": 1, "language": 3, "density": 4, "sdk": 5}
    )
    return b"".join(field(mapping[kind], dimension(kind, *values)) for kind, values in dimensions.items())


def description(
    path: str,
    target: bytes = b"",
    *,
    master=False,
    split_id=None,
    standalone=False,
    metadata_extra=b"",
    description_extra=b"",
) -> bytes:
    metadata = (
        field(1, "base")
        if standalone
        else (
            field(1, split_id if split_id is not None else path.rsplit("/", 1)[-1][:-4])
            + field(2, int(master))
        )
    )
    return (
        field(1, target)
        + field(2, path)
        + field(4 if standalone else 3, metadata + metadata_extra)
        + description_extra
    )


def module(apks: list[bytes], name="base", dependencies=(), *, metadata_extra=b"", delivery=1) -> bytes:
    metadata = (
        field(1, name)
        + field(6, delivery)
        + field(7, 1)
        + b"".join(field(4, dep) for dep in dependencies)
        + metadata_extra
    )
    return field(1, metadata) + b"".join(field(2, apk) for apk in apks)


def variant(modules: list[bytes], target: bytes = b"", *, number=0, extra=b"") -> bytes:
    return field(1, target) + b"".join(field(2, item) for item in modules) + field(3, number) + extra


def toc(variants: list[bytes], extra=b"") -> bytes:
    return (
        b"".join(field(1, item) for item in variants)
        + field(2, field(2, "1.18.0"))
        + field(4, "org.synthetic.apks")
        + extra
    )


DEFAULT_PATHS = (
    "splits/base-master.apk",
    "splits/base-arm64.apk",
    "splits/base-x86.apk",
    "splits/base-hdpi.apk",
    "splits/base-xxhdpi.apk",
    "splits/base-en.apk",
    "splits/base-ko.apk",
)
DEFAULT_DEVICE = {
    "sdkVersion": 34,
    "supportedAbis": ["arm64-v8a", "armeabi-v7a"],
    "screenDensity": 480,
    "supportedLocales": ["en-US"],
}


def split_toc() -> tuple[bytes, tuple[str, ...]]:
    """Valid base plus ABI/density/language TOC for coordinator integration tests."""
    apks = [
        description(DEFAULT_PATHS[0], master=True, split_id=""),
        description(DEFAULT_PATHS[1], targeting(abi=((3,), (4,)))),
        description(DEFAULT_PATHS[2], targeting(abi=((4,), (3,)))),
        description(DEFAULT_PATHS[3], targeting(density=((240,), (480,)))),
        description(DEFAULT_PATHS[4], targeting(density=((480,), (240,)))),
        description(DEFAULT_PATHS[5], targeting(language=(("en",), ("ko",)))),
        description(DEFAULT_PATHS[6], targeting(language=(("ko",), ("en",)))),
    ]
    return toc([variant([module(apks)], targeting(variant=True, sdk=((21,), ())))]), DEFAULT_PATHS


def apk_bytes(*, vulnerable=False, config=False, split_id="") -> bytes:
    """Manifest plus fresh synthetic text; cleartext is deliberately confined to one split."""
    root = (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="org.synthetic.apks" android:versionCode="1" android:versionName="1.0"'
    )
    if config:
        manifest = root + f' split="{split_id}" />'
    else:
        manifest = (
            root
            + '><application android:usesCleartextTraffic="'
            + ("true" if vulnerable else "false")
            + '" /></manifest>'
        )
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("assets/synthetic.txt", "http://synthetic.invalid" if vulnerable else "neutral")
    return stream.getvalue()


def write_split_apks(path: Path) -> tuple[bytes, tuple[str, ...]]:
    """Write only to an explicitly supplied fresh temporary fixture destination."""
    raw, paths = split_toc()
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "x", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("toc.pb", raw)
        for name in paths:
            archive.writestr(
                name,
                apk_bytes(
                    vulnerable=name.endswith("base-arm64.apk"),
                    config=not name.endswith("base-master.apk"),
                    split_id=name.rsplit("/", 1)[-1][:-4],
                ),
            )
    return raw, paths
