"""Pure controls only; never collect a compiler, SDK or device fixture."""

import copy
import json
import plistlib
from xml.etree import ElementTree

import pytest

from mobile_audit.core import digest
from scripts import validate_runtime_xctest_control as control

PACKAGE = "org.apsa.synthetic.p" + "1" * 32
SCHEME = "a" + "2" * 32
NONCES = ("3" * 64, "4" * 64)


def receipt():
    urls = (f"{SCHEME}://callback?nonce={NONCES[0]}", f"{SCHEME}://callback?nonce={NONCES[1]}")
    build = {"executable_sha256": "5" * 64, "info_plist_sha256": "6" * 64}
    value = {
        "schema_version": 1,
        "package": PACKAGE,
        "epoch_sha256": "7" * 64,
        **build,
        "receipts": [
            {
                "uri_sha256": digest(url.encode()),
                "nonce_sha256": digest(nonce.encode()),
                "lifecycle": lifecycle,
            }
            for url, nonce, lifecycle in zip(
                urls, NONCES, ("cold-url-context", "warm-url-context"), strict=True
            )
        ],
    }
    return value, urls, build


def test_project_keeps_exact_new_identity_and_real_ui_callback_assertions(tmp_path):
    root = tmp_path / "new"
    result = control.write_project(root, PACKAGE, SCHEME, NONCES)
    info = plistlib.loads((root / "Info.plist").read_bytes())
    assert info["CFBundleIdentifier"] == PACKAGE
    assert info["CFBundleURLTypes"][0]["CFBundleURLSchemes"] == [SCHEME]
    scheme = ElementTree.parse(root / "Callback.xcodeproj/xcshareddata/xcschemes/Callback.xcscheme")
    testable = scheme.find(".//TestableReference")
    assert testable is not None
    assert testable.get("parallelizable") == "NO"
    test = (root / "CallbackTests.swift").read_text()
    assert test.count("app.open(URL(string:") == 2
    assert test.count("waitForExpectations(timeout: 30)") == 2
    assert "app.terminate()" in test
    assert all(url in test for url in result["urls"])
    assert all(
        digest((root / name).read_bytes()) == checksum
        for name, checksum in result["generated_source_sha256"].items()
    )
    assert len(result["generated_source_sha256"]) == 5


def test_callback_receipt_requires_both_bound_lifecycles_and_installed_build():
    value, urls, build = receipt()
    result = control.verify_receipt(json.dumps(value).encode(), PACKAGE, urls, NONCES, build)
    assert result["state"] == "verified"
    assert [r["lifecycle"] for r in result["receipts"]] == ["cold-url-context", "warm-url-context"]


@pytest.mark.parametrize(
    "mutation",
    [
        "package",
        "executable_sha256",
        "info_plist_sha256",
        "epoch_sha256",
        "schema_version",
        "nonce",
        "uri",
        "lifecycle",
        "missing",
        "extra",
        "reorder",
    ],
)
def test_unbound_or_incomplete_receipt_cannot_pass(mutation):
    value, urls, build = receipt()
    value = copy.deepcopy(value)
    if mutation in {"package", "executable_sha256", "info_plist_sha256", "epoch_sha256"}:
        value[mutation] = "unbound"
    elif mutation == "schema_version":
        value[mutation] = True
    elif mutation == "nonce":
        value["receipts"][0]["nonce_sha256"] = "8" * 64
    elif mutation == "uri":
        value["receipts"][1]["uri_sha256"] = "8" * 64
    elif mutation == "lifecycle":
        value["receipts"][0]["lifecycle"] = "warm-url-context"
    elif mutation == "missing":
        value["receipts"].pop()
    elif mutation == "extra":
        value["receipts"].append(value["receipts"][0])
    else:
        value["receipts"].reverse()
    with pytest.raises(ValueError):
        control.verify_receipt(json.dumps(value).encode(), PACKAGE, urls, NONCES, build)


def test_duplicate_or_oversized_receipts_fail_closed():
    value, urls, build = receipt()
    raw = json.dumps(value)
    duplicate = raw[:-1] + ', "schema_version": 1}'
    for raw in (duplicate.encode(), b" " * 8193):
        with pytest.raises(ValueError):
            control.verify_receipt(raw, PACKAGE, urls, NONCES, build)


@pytest.mark.parametrize(
    "package,scheme,nonces",
    [
        (PACKAGE + "/../other", SCHEME, NONCES),
        (PACKAGE, "https", NONCES),
        (PACKAGE, SCHEME, (NONCES[0], NONCES[0])),
        (PACKAGE, SCHEME, ("not-a-nonce", NONCES[1])),
    ],
)
def test_generation_rejects_external_identity_before_any_file_write(tmp_path, package, scheme, nonces):
    with pytest.raises(ValueError):
        control.write_project(tmp_path / "new", package, scheme, nonces)
    assert list(tmp_path.iterdir()) == []
