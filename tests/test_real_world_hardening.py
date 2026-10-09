import json
import plistlib
import zipfile

import httpx
import pytest

from mobile_audit.audit import correlate
from mobile_audit.inputs import inspect_target, parse_dependencies
from mobile_audit.intel import query_dependencies
from mobile_audit.source_context import osv_package_name


@pytest.mark.parametrize(
    "actual,fixed,state",
    [
        ("2024-99-99", "2024-09-05", "device-info-required"),
        ("2024-02-30", "2024-02-01", "device-info-required"),
        ("2023-02-29", "2023-02-01", "device-info-required"),
        (None, "2024-09-05", "device-info-required"),
        (20240905, "2024-09-05", "device-info-required"),
        ("2024-09-05", "2024-99-99", "device-info-required"),
        ("2024-02-29", "2024-02-29", "vendor-patch-level-satisfied"),
        ("2024-02-28", "2024-02-29", "potentially-affected"),
    ],
)
def test_android_calendar_dates(actual, fixed, state):
    record = {
        "id": "CVE-2024-12345",
        "title": "Synthetic",
        "platform": "android",
        "fixed_patch_level": fixed,
        "updated_aosp_versions": "14",
        "references": [],
    }
    inventory = {"platforms": ["android"], "dependencies": []}
    env = {"platform": "android", "security_patch": actual, "version": "14"}
    assert correlate(inventory, [record], env)[1][0]["state"] == state


def gradle_project(tmp_path, root, module='implementation "org.example:lib:$v"'):
    (tmp_path / "build.gradle").write_text(root)
    folder = tmp_path / "parser/feed"
    folder.mkdir(parents=True)
    (folder / "build.gradle").write_text(module)
    return inspect_target(tmp_path)[0]["dependencies"]


def test_gradle_ancestor_literal_preserves_provenance(tmp_path):
    deps = gradle_project(tmp_path, 'project.ext {\n // synthetic fixture\n v = "1.15.1"\n }')
    assert deps[0]["version"] == "1.15.1" and deps[0]["confidence"] == "declared"
    assert deps[0]["version_expression"] == "$v"
    assert deps[0]["version_source"] == {
        "path": "build.gradle",
        "line": 3,
        "property": "v",
        "value": "1.15.1",
    }


@pytest.mark.parametrize("settings", ["settings.gradle", "settings.gradle.kts"])
def test_independent_nested_project_cannot_inherit_outer_ext(tmp_path, settings):
    gradle_project(tmp_path, 'project.ext { v = "1.0" }')
    (tmp_path / "parser/feed" / settings).write_text('rootProject.name = "independent"')
    dep = inspect_target(tmp_path)[0]["dependencies"][0]
    assert dep["confidence"] == "unknown" and dep["version"] == "$v"
    assert "version_source" not in dep


@pytest.mark.parametrize("text", ["{", "}", "}{", 'project.ext { v = "1.0"'])
def test_malformed_gradle_source_is_partial_and_unresolved(tmp_path, text):
    (tmp_path / "build.gradle").write_text(text)
    inventory, _ = inspect_target(tmp_path)
    assert inventory["partial"] and inventory["warnings"]


@pytest.mark.parametrize("root", ['other.\next { v = "1.0" }', 'project.ext { other.\nv = "1.0" }'])
def test_qualified_properties_do_not_define_project_ext(tmp_path, root):
    assert gradle_project(tmp_path, root)[0]["confidence"] == "unknown"


@pytest.mark.parametrize(
    "module",
    [
        'implementation "a:b:$v" + suffix',
        'implementation("a:b:$v" + suffix)',
        'implementation "a:b:${v}".toString()',
        'implementation("a:b:$v").toString()',
        'implementation "a:b:$v"\n.toString()',
        'implementation "a:b:$v" { version { strictly(other) } }',
        'implementation("a:b:$v", other)',
        'implementation "a:b:1.0" + suffix',
        'implementation "a:b:$v"\n as ComputedDependency',
    ],
)
def test_dynamic_dependency_expressions_never_become_fixed_versions(tmp_path, module):
    deps = gradle_project(tmp_path, 'project.ext { v = "1.0" }', module)
    assert deps[0]["confidence"] == "unknown" and "version_source" not in deps[0]


@pytest.mark.parametrize(
    "root,module",
    [
        ('project.ext { v = "1.0"; v = "2.0" }', 'implementation "a:b:$v"'),
        ('project.ext { v = "1.0" }; v = provider()', 'implementation "a:b:$v"'),
        ('if (false) { project.ext { v = "1.0" } }', 'implementation "a:b:$v"'),
        ('if (false)\nproject.ext { v = "1.0" }', 'implementation "a:b:$v"'),
        ('other.ext { v = "1.0" }', 'implementation "a:b:$v"'),
        ('project.ext { v = "1.0" + suffix }', 'implementation "a:b:$v"'),
        ('project.ext { v = "1.0"\n + suffix }', 'implementation "a:b:$v"'),
        ('project.ext { v = "1.0"\n as ComputedVersion }', 'implementation "a:b:$v"'),
        ('project.ext { v = "1.0" }; apply from: "other.gradle"', 'implementation "a:b:$v"'),
        ('project.ext { v = "1.0" }', 'ext["v"] = provider(); implementation "a:b:$v"'),
        ('project.ext { v = "1.0" }', 'ext { v = "2.0" }; implementation "a:b:$v"'),
        ('project.ext { v = "1.0" }', "implementation 'a:b:$v'"),
    ],
)
def test_gradle_unsafe_or_ambiguous_values_abstain(tmp_path, root, module):
    assert gradle_project(tmp_path, root, module)[0]["confidence"] == "unknown"


def test_gradle_comments_strings_and_sibling_do_not_define_dependencies(tmp_path):
    assert (
        parse_dependencies(
            "build.gradle", b'// implementation "a:b:1.0"\nprintln(\'implementation "a:b:2.0"\')'
        )
        == []
    )
    (tmp_path / "other").mkdir()
    (tmp_path / "other/build.gradle").write_text('ext { v = "2.0" }')
    assert gradle_project(tmp_path, '// ext { v = "1.0" }')[0]["confidence"] == "unknown"


@pytest.mark.parametrize(
    "imported,confidence",
    [
        ("android { compileSdkVersion 34 }", "declared"),
        ('ext["v"] = provider()', "unknown"),
        ('apply from: "missing.gradle"', "unknown"),
        ('apply from: "common.gradle"', "unknown"),
    ],
)
def test_bounded_literal_imports_are_checked_without_execution(tmp_path, imported, confidence):
    (tmp_path / "common.gradle").write_text(imported)
    module = 'apply from: "../../common.gradle"\nimplementation "a:b:${v}"'
    assert gradle_project(tmp_path, 'project.ext { v = "1.0" }', module)[0]["confidence"] == confidence


def test_named_plist_configurations_remain_ambiguous_until_selected(tmp_path):
    named_plist(tmp_path)
    (tmp_path / "Brand/Other.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "org.example.other"}))
    with (tmp_path / "App.xcodeproj/project.pbxproj").open("a") as output:
        output.write('\nINFOPLIST_FILE = "Brand/Other.plist";')
    inventory, _ = inspect_target(tmp_path)
    assert inventory["partial"] and inventory["configuration_ambiguous"] and not inventory["package"]
    selected, _ = inspect_target(tmp_path, configuration="Brand/Client.plist")
    assert selected["package"] == "org.example.synthetic" and len(selected["ios_config"]) == 1


def named_plist(tmp_path, reference='"Brand/Client.plist"'):
    (tmp_path / "Brand").mkdir()
    raw = plistlib.dumps(
        {
            "CFBundleIdentifier": "org.example.synthetic",
            "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        },
        fmt=plistlib.FMT_BINARY,
    )
    (tmp_path / "Brand/Client.plist").write_bytes(raw)
    (tmp_path / "App.xcodeproj").mkdir()
    (tmp_path / "App.xcodeproj/project.pbxproj").write_text(
        '// INFOPLIST_FILE = "wrong.plist";\n{ buildSettings = { INFOPLIST_FILE = ' + reference + "; }; }"
    )


@pytest.mark.parametrize("archive", [False, True])
def test_named_binary_plist_from_literal_xcode_reference(tmp_path, archive):
    named_plist(tmp_path)
    target = tmp_path
    if archive:
        target = tmp_path / "source.zip"
        with zipfile.ZipFile(target, "w") as output:
            for file in [tmp_path / "Brand/Client.plist", tmp_path / "App.xcodeproj/project.pbxproj"]:
                output.write(file, file.relative_to(tmp_path).as_posix())
    inventory, _ = inspect_target(target)
    assert inventory["package"] == "org.example.synthetic"
    assert inventory["ios_config"][0]["ats"]["NSAllowsArbitraryLoads"] is True
    assert inventory["ios_config"][0]["xcode_references"][0]["path"] == "App.xcodeproj/project.pbxproj"


@pytest.mark.parametrize(
    "reference", ['"$(SRCROOT)/Brand/Client.plist"', '"${PROJECT_DIR}/Brand/Client.plist"']
)
def test_xcode_root_prefix(tmp_path, reference):
    named_plist(tmp_path, reference)
    assert inspect_target(tmp_path)[0]["package"] == "org.example.synthetic"


@pytest.mark.parametrize(
    "reference",
    ['"../outside.plist"', '"/private/outside.plist"', '"$(UNKNOWN)/Client.plist"', '"missing.plist"'],
)
def test_xcode_unsafe_unresolved_missing_abstains(tmp_path, reference):
    named_plist(tmp_path, reference)
    inventory, _ = inspect_target(tmp_path)
    assert inventory["partial"] and not inventory["ios_config"]


def test_explicit_named_plist_and_ipa_main_identity(tmp_path):
    named_plist(tmp_path)
    assert (
        inspect_target(tmp_path, configuration="Brand/Client.plist")[0]["package"] == "org.example.synthetic"
    )
    target = tmp_path / "bad.ipa"
    with zipfile.ZipFile(target, "w") as archive:
        archive.write(tmp_path / "Brand/Client.plist", "Payload/App.app/Client.plist")
        archive.write(tmp_path / "App.xcodeproj/project.pbxproj", "App.xcodeproj/project.pbxproj")
    with pytest.raises(ValueError, match="no main"):
        inspect_target(target)


def test_swift_canonical_query_keeps_original_inventory_cache_and_correlation(store):
    dep = {
        "ecosystem": "SwiftURL",
        "name": "https://github.com/example/Library.git",
        "version": "1.0",
        "path": "Package.resolved",
        "confidence": "exact",
    }

    def handler(request):
        assert json.loads(request.content)["package"]["name"] == "github.com/example/Library"
        return httpx.Response(200, json={"vulns": [{"id": "GHSA-synthetic", "aliases": ["CVE-2024-12345"]}]})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        records, errors = query_dependencies(store, [dep], client)
    assert not errors and records[0]["query_match"]["name"] == dep["name"]
    assert store.feeds()[0]["source"] == f"osv:SwiftURL:{dep['name']}:1.0"
    assert correlate({"dependencies": [dep], "platforms": []}, records)[0][0]["status"] == "version-affected"


@pytest.mark.parametrize(
    "name",
    [
        "https://user:pass@github.com/a/b",
        "https://github.com/a/b?x=1",
        "https://github.com/a/../b",
        "https://github.com/a/b#branch",
        "identity",
        "file:///private/example",
        "https://github.com:443/a/b",
        "github.com/a/%62",
    ],
)
def test_unsafe_swift_identity_abstains(name):
    with pytest.raises(ValueError):
        osv_package_name({"ecosystem": "SwiftURL", "name": name})
