from __future__ import annotations

import os
import subprocess
import zipfile
from pathlib import Path
from xml.etree import ElementTree as XML

import pytest

from mobile_audit.aab_manifest import decode_manifest
from mobile_audit.aab_resources import build_resources

ANDROID = "http://schemas.android.com/apk/res/android"


def varint(value: int) -> bytes:
    value &= (1 << 64) - 1
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    return bytes(result) + bytes([value])


def field(number: int, value: bytes | int) -> bytes:
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint((number << 3) | 2) + varint(len(value)) + value


def manifest(name: str, declared: str, compiled: bytes) -> bytes:
    attribute = (
        field(1, ANDROID.encode())
        + field(2, name.encode())
        + field(3, declared.encode())
        + field(6, compiled)
    )
    return field(1, field(3, b"manifest") + field(4, attribute))


@pytest.mark.parametrize("with_resources", [False, True])
@pytest.mark.parametrize(
    ("name", "declared", "number", "primitive"),
    [
        ("launchMode", "singleTask", 2, 6),
        ("configChanges", "orientation|keyboardHidden", 160, 7),
        ("protectionLevel", "signature", 2, 7),
        ("screenOrientation", "unspecified", -1, 6),
        ("versionCode", "0x10", 16, 7),
    ],
)
def test_aapt_integer_spelling_preserves_compiled_authority(
    with_resources: bool, name: str, declared: str, number: int, primitive: int
) -> None:
    raw = manifest(name, declared, field(7, field(primitive, number)))
    resources = build_resources({}) if with_resources else None
    xml, warnings = decode_manifest(raw, resources=resources)
    assert warnings == []
    assert XML.fromstring(xml).attrib[f"{{{ANDROID}}}{name}"] == str(number)


def test_symbolic_permission_text_cannot_override_compiled_normal_permission() -> None:
    raw = manifest("protectionLevel", "signature", field(7, field(7, 0)))
    xml, warnings = decode_manifest(raw)
    assert warnings == []
    assert XML.fromstring(xml).attrib[f"{{{ANDROID}}}protectionLevel"] == "0"


@pytest.mark.parametrize("with_resources", [False, True])
@pytest.mark.parametrize(
    ("name", "declared", "compiled"),
    [
        ("debuggable", "true", field(7, field(8, 0))),
        ("name", "declared.name", field(2, field(1, b"compiled.name"))),
    ],
)
def test_conflicting_boolean_and_string_attributes_remain_rejected(
    with_resources: bool, name: str, declared: str, compiled: bytes
) -> None:
    resources = build_resources({}) if with_resources else None
    with pytest.raises(ValueError, match="Conflicting declared and compiled"):
        decode_manifest(manifest(name, declared, compiled), resources=resources)


def test_real_aapt_enum_manifest(tmp_path: Path) -> None:
    sdk_value = os.environ.get("APSA_TEST_ANDROID_SDK")
    if not sdk_value:
        pytest.skip("APSA_TEST_ANDROID_SDK not configured")
    sdk = Path(sdk_value)
    tools = sorted((sdk / "build-tools").glob("*/aapt2"))
    platforms = sorted((sdk / "platforms").glob("android-*/android.jar"))
    if not tools or not platforms:
        pytest.skip("Android SDK aapt2/platform jar unavailable")
    source = tmp_path / "AndroidManifest.xml"
    source.write_text(
        f'<manifest xmlns:android="{ANDROID}" package="test.apsa.synthetic">'
        '<permission android:name="test.apsa.synthetic.INTERNAL" android:protectionLevel="signature"/>'
        '<application android:label="Synthetic" android:debuggable="false">'
        '<activity android:name=".MainActivity" android:exported="true" android:launchMode="singleTask" '
        'android:configChanges="orientation|keyboardHidden"/></application></manifest>'
    )
    archive = tmp_path / "synthetic-proto.apk"
    result = subprocess.run(
        [
            str(tools[-1]),
            "link",
            "--proto-format",
            "-o",
            str(archive),
            "--manifest",
            str(source),
            "-I",
            str(platforms[-1]),
        ],
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    with zipfile.ZipFile(archive) as stream:
        raw = stream.read("AndroidManifest.xml")
    xml, warnings = decode_manifest(raw)
    root = XML.fromstring(xml)
    assert warnings == []
    permission = root.find("permission")
    activity = root.find("application/activity")
    assert permission is not None and activity is not None
    assert permission.attrib[f"{{{ANDROID}}}protectionLevel"] == "2"
    assert activity.attrib[f"{{{ANDROID}}}launchMode"] == "2"
    assert activity.attrib[f"{{{ANDROID}}}configChanges"] == "160"
