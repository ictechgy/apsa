"""Unrelated C/NDK headers do not claim Apple source rule applicability."""

from mobile_audit.inputs import inspect_target
from mobile_audit.rules import static_checks


def test_android_header_without_apple_translation_units_is_not_apple_source(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text('<manifest package="example.synthetic"/>')
    (tmp_path / "native.h").write_text("#pragma once\nint native_operation(void);\n")
    inventory, sources = inspect_target(tmp_path)
    assert inventory["platforms"] == ["android"]
    assert any(path == "native.h" for path, _ in sources)
    _, coverage = static_checks(inventory, sources)
    apple = {
        "IOS-KEYCHAIN-ACCESS",
        "IOS-CRYPTO-WEAK-CIPHER",
        "IOS-ATS-BYPASS-API",
        "IOS-INSECURE-UNARCHIVE",
        "IOS-UIWEBVIEW",
    }
    rows = [row for row in coverage if row["rule_id"] in apple]
    assert len(rows) == len(apple)
    assert {row["state"] for row in rows} == {"not-applicable"}
