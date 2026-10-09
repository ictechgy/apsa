"""Gradle catalog usage and resolved lockfile evidence on newly generated projects."""

from __future__ import annotations

import pytest

from mobile_audit.audit import correlate
from mobile_audit.inputs import inspect_target, parse_dependencies

CATALOG = """
[versions]
okhttp = "4.9.0"

[libraries]
okhttp = { module = "com.squareup.okhttp3:okhttp", version.ref = "okhttp" }
androidx_core-ktx = { group = "androidx.core", name = "core-ktx", version = "1.10.0" }
jsoup = "org.jsoup:jsoup:1.15.3"
junit = { module = "junit:junit", version = "4.13.2" }
leakcanary = { module = "com.squareup.leakcanary:leakcanary-android", version = "2.12" }
compose-bom = { module = "androidx.compose:compose-bom", version = "2024.02.00" }
okio = { module = "com.squareup.okio:okio", version = "3.4.0" }
unused = { module = "org.example:unused", version = "1.0" }
bomManaged = "androidx.compose.ui:ui"

[bundles]
network = ["okio"]
"""


def project(tmp_path, build: str, extra: dict[str, str] | None = None) -> dict[str, dict]:
    (tmp_path / "gradle").mkdir()
    (tmp_path / "gradle/libs.versions.toml").write_text(CATALOG)
    (tmp_path / "settings.gradle.kts").write_text('rootProject.name = "synthetic"\ninclude(":app")\n')
    (tmp_path / "app").mkdir()
    (tmp_path / "app/build.gradle.kts").write_text(build)
    for name, text in (extra or {}).items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    inventory, _ = inspect_target(tmp_path)
    return {dep["name"]: dep for dep in inventory["dependencies"] if dep["path"].endswith(".toml")}


def test_catalog_alias_in_shipped_configuration_becomes_declared_candidate(tmp_path):
    deps = project(
        tmp_path,
        "dependencies {\n"
        "    implementation(libs.okhttp)\n"
        "    api(libs.androidx.core.ktx)\n"
        "    implementation(libs.bundles.network)\n"
        "    testImplementation(libs.junit)\n"
        "    debugImplementation(libs.leakcanary)\n"
        "    implementation(platform(libs.compose.bom))\n"
        "}\n",
    )
    okhttp = deps["com.squareup.okhttp3:okhttp"]
    assert okhttp["confidence"] == "declared" and okhttp["version"] == "4.9.0"
    assert okhttp["version_source"] == "catalog-alias-declared"
    assert okhttp["catalog_usage"]["references"][0] == {
        "path": "app/build.gradle.kts",
        "line": 2,
        "configuration": "implementation",
        "state": "declared",
    }
    assert deps["androidx.core:core-ktx"]["confidence"] == "declared"
    assert deps["com.squareup.okio:okio"]["catalog_usage"]["state"] == "declared"
    for name, state in [
        ("junit:junit", "non-shipping-configuration"),
        ("com.squareup.leakcanary:leakcanary-android", "non-shipping-configuration"),
        ("androidx.compose:compose-bom", "platform-only"),
        ("org.example:unused", "no-reference-found"),
    ]:
        assert deps[name]["confidence"] == "unknown", name
        assert deps[name]["version_source"] == "catalog-declared-unresolved-usage"
        assert deps[name]["catalog_usage"]["state"] == state, name
    assert deps["org.jsoup:jsoup"]["version"] == "1.15.3"
    assert "androidx.compose.ui:ui" not in deps


def test_groovy_command_syntax_and_test_source_sets(tmp_path):
    deps = project(
        tmp_path,
        "kotlin {\n"
        "  sourceSets {\n"
        "    commonMain.dependencies { implementation(libs.okhttp) }\n"
        "    commonTest.dependencies { implementation(libs.junit) }\n"
        "  }\n"
        "}\n",
        {"lib/build.gradle": "dependencies {\n  implementation libs.jsoup\n}\n"},
    )
    assert deps["com.squareup.okhttp3:okhttp"]["confidence"] == "declared"
    assert deps["org.jsoup:jsoup"]["catalog_usage"]["references"][0]["path"] == "lib/build.gradle"
    assert deps["org.jsoup:jsoup"]["confidence"] == "declared"
    assert deps["junit:junit"]["catalog_usage"]["state"] == "non-shipping-configuration"


def test_convention_plugin_lookups_and_unclassified_references(tmp_path):
    plugin = (
        "class Convention : Plugin<Project> {\n"
        "  override fun apply(target: Project) {\n"
        '    val libs = target.extensions.getByType<VersionCatalogsExtension>().named("libs")\n'
        "    target.dependencies {\n"
        '      add("implementation", libs.findLibrary("okhttp").get())\n'
        '      "implementation"(libs.findLibrary("androidx-core-ktx").get())\n'
        '      add("testImplementation", libs.findLibrary("junit").get())\n'
        "    }\n"
        "  }\n"
        "}\n"
    )
    deps = project(
        tmp_path,
        "val shared = libs.okio\ndependencies { }\n",
        {"build-logic/convention/src/main/kotlin/Convention.kt": plugin},
    )
    assert deps["com.squareup.okhttp3:okhttp"]["confidence"] == "declared"
    assert deps["androidx.core:core-ktx"]["confidence"] == "declared"
    assert deps["junit:junit"]["catalog_usage"]["state"] == "non-shipping-configuration"
    okio = deps["com.squareup.okio:okio"]
    assert okio["confidence"] == "unknown"
    assert okio["catalog_usage"]["state"] == "referenced-unclassified"


def test_comments_and_strings_are_not_usage_evidence(tmp_path):
    deps = project(
        tmp_path,
        'dependencies {\n  // implementation(libs.okhttp)\n  val note = "implementation(libs.jsoup)"\n}\n',
    )
    assert deps["com.squareup.okhttp3:okhttp"]["catalog_usage"]["state"] == "no-reference-found"
    assert deps["org.jsoup:jsoup"]["confidence"] == "unknown"


def test_unregistered_catalog_name_stays_unresolved(tmp_path):
    (tmp_path / "gradle").mkdir()
    (tmp_path / "gradle/deps.versions.toml").write_text(CATALOG)
    (tmp_path / "build.gradle.kts").write_text("dependencies { implementation(deps.okhttp) }\n")
    inventory, _ = inspect_target(tmp_path)
    okhttp = next(d for d in inventory["dependencies"] if d["name"] == "com.squareup.okhttp3:okhttp")
    assert okhttp["confidence"] == "unknown"
    assert okhttp["catalog_usage"]["state"] == "catalog-name-unresolved"
    (tmp_path / "settings.gradle.kts").write_text(
        'dependencyResolutionManagement { versionCatalogs { create("deps") { from(files("gradle/deps.versions.toml")) } } }\n'
    )
    inventory, _ = inspect_target(tmp_path)
    okhttp = next(d for d in inventory["dependencies"] if d["name"] == "com.squareup.okhttp3:okhttp")
    assert okhttp["confidence"] == "declared"


LOCKFILE = """# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.squareup.okio:okio:3.6.0=releaseRuntimeClasspath,releaseCompileClasspath
com.squareup.okhttp3:okhttp:4.12.0=fossReleaseRuntimeClasspath
junit:junit:4.13.2=testReleaseRuntimeClasspath,debugUnitTestRuntimeClasspath
com.squareup.leakcanary:leakcanary-android:2.12=debugRuntimeClasspath
com.android.tools:test-engine:1.0.1=unified-test-platform-gradle-work-action
org.jetbrains:annotations:13.0=releaseCompileClasspath
empty=annotationProcessor
"""


def test_gradle_lockfile_keeps_only_release_runtime_coordinates():
    deps = parse_dependencies("app/gradle.lockfile", LOCKFILE.encode())
    assert {(d["name"], d["version"]) for d in deps} == {
        ("com.squareup.okio:okio", "3.6.0"),
        ("com.squareup.okhttp3:okhttp", "4.12.0"),
    }
    okio = next(d for d in deps if d["name"] == "com.squareup.okio:okio")
    assert okio["confidence"] == "exact" and okio["version_source"] == "gradle-lockfile-resolved"
    assert okio["resolved_configurations"] == ["releaseRuntimeClasspath"]
    legacy = parse_dependencies(
        "app/gradle/dependency-locks/releaseRuntimeClasspath.lockfile", b"org.jsoup:jsoup:1.17.2\n"
    )
    assert legacy[0]["confidence"] == "exact" and legacy[0]["version"] == "1.17.2"
    assert parse_dependencies("other/notes.lockfile", b"a:b:1=releaseRuntimeClasspath") == []
    with pytest.raises(ValueError):
        parse_dependencies("app/gradle.lockfile", b"not a coordinate\n")


def test_resolved_lockfile_supersedes_declared_and_catalog_versions(tmp_path):
    deps = project(
        tmp_path,
        'plugins { id("com.android.application") }\n'
        "dependencies {\n  implementation(libs.okhttp)\n  implementation(libs.okio)\n}\n",
        {"app/gradle.lockfile": LOCKFILE},
    )
    for name, resolved in [("com.squareup.okhttp3:okhttp", "4.12.0"), ("com.squareup.okio:okio", "3.6.0")]:
        assert deps[name]["confidence"] == "unknown"
        assert deps[name]["resolution"] == {
            "state": "superseded-by-resolved-build",
            "resolved_versions": [resolved],
        }
    inventory, _ = inspect_target(tmp_path)
    exact = [d for d in inventory["dependencies"] if d.get("version_source") == "gradle-lockfile-resolved"]
    assert {(d["name"], d["version"], d["confidence"]) for d in exact} == {
        ("com.squareup.okio:okio", "3.6.0", "exact"),
        ("com.squareup.okhttp3:okhttp", "4.12.0", "exact"),
    }


def test_malformed_lockfile_is_partial_not_silently_ignored(tmp_path):
    (tmp_path / "gradle.lockfile").write_text("com.example:lib=releaseRuntimeClasspath\n")
    inventory, _ = inspect_target(tmp_path)
    assert inventory["partial"]
    assert any("gradle.lockfile" in warning for warning in inventory["warnings"])


def record(name: str, version: str) -> dict:
    return {
        "id": "CVE-2099-0001",
        "title": "Synthetic advisory",
        "severity": "high",
        "query_match": {"name": name, "ecosystem": "Maven", "version": version},
        "references": [],
    }


def test_correlation_uses_resolved_exact_and_skips_superseded_candidates():
    lock = {
        "name": "com.squareup.okio:okio",
        "version": "3.6.0",
        "ecosystem": "Maven",
        "path": "app/gradle.lockfile",
        "confidence": "exact",
        "version_source": "gradle-lockfile-resolved",
    }
    declared = {
        "name": "com.squareup.okio:okio",
        "version": "3.4.0",
        "ecosystem": "Maven",
        "path": "gradle/libs.versions.toml",
        "confidence": "unknown",
        "version_source": "catalog-alias-declared",
        "resolution": {"state": "superseded-by-resolved-build", "resolved_versions": ["3.6.0"]},
    }
    used = dict(declared, name="org.jsoup:jsoup", confidence="declared")
    del used["resolution"]
    inventory = {"platforms": ["android"], "dependencies": [lock, declared, used]}
    findings, _ = correlate(inventory, [record(lock["name"], "3.6.0")])
    assert [f["status"] for f in findings] == ["version-affected"]
    findings, _ = correlate(inventory, [record(lock["name"], "3.4.0")])
    assert findings == []
    findings, _ = correlate(inventory, [record("org.jsoup:jsoup", "3.4.0")])
    assert [f["status"] for f in findings] == ["candidate"]


def test_module_roles_keep_tooling_test_and_test_support_declarations_out(tmp_path):
    deps = project(
        tmp_path,
        'plugins { id("com.android.application") }\n'
        "dependencies {\n"
        "  implementation(projects.core.data)\n"
        "  testImplementation(projects.core.testing)\n"
        '  testImplementation(project(":core:fixtures"))\n'
        "}\n",
        {
            "core/data/build.gradle.kts": (
                'plugins { id("com.android.library") }\ndependencies { implementation(libs.okhttp) }\n'
            ),
            "core/testing/build.gradle.kts": (
                'plugins { id("com.android.library") }\n'
                'dependencies {\n  api(libs.junit)\n  implementation(project(path: ":core:fixtures"))\n}\n'
            ),
            "core/fixtures/build.gradle": (
                "plugins { id 'com.android.library' }\ndependencies { implementation libs.leakcanary }\n"
            ),
            "benchmarks/build.gradle.kts": (
                "plugins { alias(libs.plugins.synthetic.android.test) }\n"
                "dependencies { implementation(libs.androidx.core.ktx) }\n"
            ),
            "build-logic/convention/build.gradle.kts": (
                "plugins { `kotlin-dsl` }\ndependencies { implementation(libs.jsoup) }\n"
            ),
            "buildSrc/build.gradle": "dependencies { implementation libs.okio }\n",
        },
    )
    assert deps["com.squareup.okhttp3:okhttp"]["catalog_usage"]["state"] == "declared"
    for name, state in [
        ("junit:junit", "non-shipping-module"),
        ("com.squareup.leakcanary:leakcanary-android", "non-shipping-module"),
        ("androidx.core:core-ktx", "non-shipping-module"),
        ("org.jsoup:jsoup", "build-tooling"),
        ("com.squareup.okio:okio", "build-tooling"),
    ]:
        assert deps[name]["confidence"] == "unknown", name
        assert deps[name]["catalog_usage"]["state"] == state, name


def test_unreferenced_modules_remain_possible_applications(tmp_path):
    deps = project(
        tmp_path,
        "dependencies { implementation(libs.okhttp) }\n",
        {"wear/build.gradle.kts": "dependencies { implementation(libs.jsoup) }\n"},
    )
    assert deps["org.jsoup:jsoup"]["confidence"] == "declared"


def test_applications_and_unclassified_consumers_keep_modules_shipping(tmp_path):
    deps = project(
        tmp_path,
        "plugins { alias(libs.plugins.android.application) }\n"
        "dependencies {\n  implementation(libs.okhttp)\n}\n",
        {
            "benchmark/build.gradle.kts": (
                'plugins { id("com.android.test") }\ndependencies { testImplementation(projects.app) }\n'
            ),
            "coverage/build.gradle.kts": "dependencies { kover(projects.core.ui) }\n",
            "core/ui/build.gradle.kts": "dependencies { implementation(libs.jsoup) }\n",
        },
    )
    assert deps["com.squareup.okhttp3:okhttp"]["catalog_usage"]["state"] == "declared"
    assert deps["org.jsoup:jsoup"]["catalog_usage"]["state"] == "declared"


def test_library_module_lockfiles_stay_candidates(tmp_path):
    deps = project(
        tmp_path,
        'plugins { id("io.example.android-compose-application") }\n'
        "dependencies {\n  implementation(projects.core)\n  implementation(libs.okio)\n}\n",
        {
            "app/gradle.lockfile": "com.squareup.okio:okio:3.6.0=releaseRuntimeClasspath\n",
            "core/build.gradle.kts": (
                'plugins { id("com.android.library") }\ndependencies { implementation(libs.okhttp) }\n'
            ),
            "core/gradle.lockfile": "com.squareup.okhttp3:okhttp:4.11.0=releaseRuntimeClasspath\n",
        },
    )
    inventory, _ = inspect_target(tmp_path)
    by_source = {(d["name"], d.get("version_source"), d["confidence"]) for d in inventory["dependencies"]}
    assert ("com.squareup.okio:okio", "gradle-lockfile-resolved", "exact") in by_source
    assert ("com.squareup.okhttp3:okhttp", "gradle-lockfile-non-application-module", "declared") in by_source
    # The app lockfile supersedes the okio catalog candidate; the library lockfile does not.
    assert deps["com.squareup.okio:okio"]["resolution"]["state"] == "superseded-by-resolved-build"
    assert deps["com.squareup.okhttp3:okhttp"]["confidence"] == "declared"
    assert "resolution" not in deps["com.squareup.okhttp3:okhttp"]


def test_unrecognized_application_lockfile_stays_candidate(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app/build.gradle.kts").write_text('plugins { id("custom.convention") }\n')
    (tmp_path / "app/gradle.lockfile").write_text("com.squareup.okio:okio:3.6.0=releaseRuntimeClasspath\n")
    (tmp_path / "wear").mkdir()
    (tmp_path / "wear/build.gradle.kts").write_text('plugins { id("com.android.application") }\n')
    inventory, _ = inspect_target(tmp_path)
    okio = next(d for d in inventory["dependencies"] if d["name"] == "com.squareup.okio:okio")
    assert okio["confidence"] == "declared"
    assert okio["version_source"] == "gradle-lockfile-non-application-module"


def test_application_id_marks_an_application_and_root_apply_false_does_not(tmp_path):
    (tmp_path / "build.gradle.kts").write_text(
        'plugins {\n  // id("com.android.application")\n'
        "  alias(libs.plugins.android.application) apply false\n}\n"
    )
    (tmp_path / "gradle.lockfile").write_text("org.example:root:1.0=runtimeClasspath\n")
    (tmp_path / "app").mkdir()
    (tmp_path / "app/build.gradle").write_text("android { defaultConfig { applicationId 'audit.app' } }\n")
    (tmp_path / "app/gradle.lockfile").write_text("com.squareup.okio:okio:3.6.0=releaseRuntimeClasspath\n")
    inventory, _ = inspect_target(tmp_path)
    state = {d["name"]: (d["confidence"], d["version_source"]) for d in inventory["dependencies"]}
    assert state["com.squareup.okio:okio"] == ("exact", "gradle-lockfile-resolved")
    assert state["org.example:root"] == ("declared", "gradle-lockfile-non-application-module")


def test_resolution_from_one_app_does_not_supersede_another_apps_declaration(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app/build.gradle.kts").write_text('plugins { id("com.android.application") }\n')
    (tmp_path / "app/gradle.lockfile").write_text(
        "com.squareup.okhttp3:okhttp:4.12.0=releaseRuntimeClasspath\n"
    )
    (tmp_path / "wear").mkdir()
    (tmp_path / "wear/build.gradle").write_text(
        "plugins { id 'com.android.application' }\n"
        "dependencies { implementation 'com.squareup.okhttp3:okhttp:3.12.0' }\n"
    )
    inventory, _ = inspect_target(tmp_path)
    wear = next(d for d in inventory["dependencies"] if d["path"] == "wear/build.gradle")
    assert wear["confidence"] == "declared" and wear["version"] == "3.12.0"
    assert wear["resolution"] == {"state": "resolved-in-other-module", "resolved_versions": ["4.12.0"]}
    findings, _ = correlate(inventory, [record("com.squareup.okhttp3:okhttp", "3.12.0")])
    assert [f["status"] for f in findings] == ["candidate"]


def test_constraints_are_not_usage(tmp_path):
    deps = project(
        tmp_path,
        "dependencies {\n  constraints {\n    implementation(libs.okhttp)\n  }\n}\n",
    )
    assert deps["com.squareup.okhttp3:okhttp"]["confidence"] == "unknown"


def test_partial_inventory_does_not_exclude_modules_by_consumption(tmp_path):
    from mobile_audit.source_context import ModuleGraph

    sources = [
        (
            "app/build.gradle.kts",
            'plugins { id("com.android.application") }\ndependencies { testImplementation(projects.core) }',
        ),
        ("core/build.gradle.kts", 'plugins { id("com.android.library") }'),
    ]
    assert ModuleGraph(sources).roles.get("core") == "non-shipping-module"
    partial = ModuleGraph(sources, partial=True)
    assert "core" not in partial.roles and partial.warnings


def test_shared_module_is_not_superseded_by_one_apps_lockfile(tmp_path):
    for name, build in [
        ("a", 'plugins { id("com.android.application") }\ndependencies { implementation(projects.lib) }\n'),
        ("b", 'plugins { id("com.android.application") }\ndependencies { implementation(projects.lib) }\n'),
        (
            "lib",
            'plugins { id("com.android.library") }\n'
            'dependencies { implementation("com.squareup.okhttp3:okhttp:3.12.0") }\n',
        ),
    ]:
        (tmp_path / name).mkdir()
        (tmp_path / name / "build.gradle.kts").write_text(build)
    (tmp_path / "a/gradle.lockfile").write_text(
        "com.squareup.okhttp3:okhttp:4.12.0=releaseRuntimeClasspath\n"
    )
    inventory, _ = inspect_target(tmp_path)
    shared = next(d for d in inventory["dependencies"] if d["path"] == "lib/build.gradle.kts")
    assert shared["confidence"] == "declared"
    assert shared["resolution"]["state"] == "resolved-in-other-module"
    (tmp_path / "b/gradle.lockfile").write_text(
        "com.squareup.okhttp3:okhttp:4.12.0=releaseRuntimeClasspath\n"
    )
    inventory, _ = inspect_target(tmp_path)
    shared = next(d for d in inventory["dependencies"] if d["path"] == "lib/build.gradle.kts")
    assert shared["resolution"]["state"] == "superseded-by-resolved-build"


@pytest.mark.parametrize(
    "root",
    [
        "plugins {\n  id 'com.android.application' version '8.1.0' apply false\n}\n",
        'plugins {\n  id("com.android.application") version "8.1.0" apply false\n}\n',
        'plugins {\n  id("com.android.application").apply(false)\n}\n',
    ],
)
def test_versioned_apply_false_does_not_make_root_an_application(tmp_path, root):
    (tmp_path / "build.gradle.kts").write_text(root)
    (tmp_path / "gradle.lockfile").write_text("org.example:root:1.0=runtimeClasspath\n")
    inventory, _ = inspect_target(tmp_path)
    entry = next(d for d in inventory["dependencies"] if d["name"] == "org.example:root")
    assert entry["confidence"] == "declared"


def test_plugin_id_mentions_and_library_evidence_are_not_applications(tmp_path):
    (tmp_path / "core").mkdir()
    (tmp_path / "core/build.gradle.kts").write_text(
        'plugins { id("com.android.library") }\npluginManager.withPlugin("com.android.application") { }\n'
    )
    (tmp_path / "core/gradle.lockfile").write_text(
        "com.squareup.okhttp3:okhttp:4.9.0=releaseRuntimeClasspath\n"
    )
    inventory, _ = inspect_target(tmp_path)
    entry = next(d for d in inventory["dependencies"] if d["name"] == "com.squareup.okhttp3:okhttp")
    assert entry["confidence"] == "declared"
    assert entry["version_source"] == "gradle-lockfile-non-application-module"


def test_unparsed_project_reference_keeps_shared_declarations(tmp_path):
    for name, build in [
        ("a", 'plugins { id("com.android.application") }\ndependencies { implementation(projects.lib) }\n'),
        (
            "b",
            'plugins { id("com.android.application") }\n'
            'dependencies { implementation(project(mapOf("path" to ":lib"))) }\n',
        ),
        (
            "lib",
            'plugins { id("com.android.library") }\n'
            'dependencies { implementation("com.squareup.okhttp3:okhttp:3.12.0") }\n',
        ),
    ]:
        (tmp_path / name).mkdir()
        (tmp_path / name / "build.gradle.kts").write_text(build)
    (tmp_path / "a/gradle.lockfile").write_text(
        "com.squareup.okhttp3:okhttp:4.12.0=releaseRuntimeClasspath\n"
    )
    inventory, _ = inspect_target(tmp_path)
    shared = next(d for d in inventory["dependencies"] if d["path"] == "lib/build.gradle.kts")
    assert shared["confidence"] == "declared"
    assert shared["resolution"]["state"] == "resolved-in-other-module"


def test_chained_version_apply_false_is_not_applied(tmp_path):
    (tmp_path / "build.gradle.kts").write_text(
        'plugins { id("com.android.application").version("8.1.0").apply(false) }\n'
    )
    (tmp_path / "gradle.lockfile").write_text("org.example:root:1.0=runtimeClasspath\n")
    inventory, _ = inspect_target(tmp_path)
    root = next(d for d in inventory["dependencies"] if d["name"] == "org.example:root")
    assert root["confidence"] == "declared"


def test_partial_inventory_and_refresh_keep_superseded_semantics(store, tmp_path):
    from mobile_audit.audit import dependency_coverage_state
    from mobile_audit.source_context import ModuleGraph, supersede

    sources = [("app/build.gradle.kts", 'plugins { id("com.android.application") }')]
    lock = {
        "name": "com.squareup.okio:okio",
        "version": "3.6.0",
        "ecosystem": "Maven",
        "path": "app/gradle.lockfile",
        "confidence": "exact",
        "version_source": "gradle-lockfile-resolved",
    }
    declared = {
        "name": "com.squareup.okio:okio",
        "version": "3.4.0",
        "ecosystem": "Maven",
        "path": "app/build.gradle.kts",
        "confidence": "declared",
    }
    deps: list[dict] = [dict(lock), dict(declared)]
    supersede(deps, ModuleGraph(sources), partial=True)
    assert "resolution" not in deps[1] and deps[1]["confidence"] == "declared"
    deps = [dict(lock), dict(declared)]
    supersede(deps, ModuleGraph(sources))
    assert deps[1]["resolution"]["state"] == "superseded-by-resolved-build"
    health = {"status": "ok", "stale": False}
    assert dependency_coverage_state(deps[1], health) == "not-applicable"
    assert dependency_coverage_state(deps[0], health) == "checked"
    assert dependency_coverage_state({**declared, "confidence": "unknown"}, health) == "not-run"


def test_unreadable_build_script_counts_as_hidden_reference():
    from mobile_audit.source_context import ModuleGraph

    graph = ModuleGraph([("app/build.gradle.kts", "x " * 200_001), ("lib/build.gradle.kts", "")])
    assert graph.unresolved_project_references and graph.warnings


def test_osv_budget_queries_exact_first_and_counts_unchecked_packages(store):
    import json

    import httpx

    from mobile_audit.audit import dependency_coverage_state
    from mobile_audit.intel import query_dependencies

    def dep(index, confidence, **extra):
        return {
            "ecosystem": "Maven",
            "name": f"com.example:lib{index}",
            "version": "1.0",
            "path": "app/gradle.lockfile",
            "confidence": confidence,
            **extra,
        }

    superseded = dep(0, "declared", resolution={"state": "superseded-by-resolved-build"})
    declared = [dep(index, "declared") for index in range(1, 4)]
    exact = [dep(index, "exact") for index in range(4, 104)]
    queried = []

    def handler(request):
        queried.append(json.loads(request.content)["package"]["name"])
        return httpx.Response(200, json={"vulns": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        _, errors = query_dependencies(store, [superseded, *declared, *exact], client)
    assert sorted(queried) == sorted(item["name"] for item in exact)
    assert errors == ["Dependency query limit of 100 reached; 3 remaining packages not checked"]
    health = {(feed["source"]): feed for feed in store.feeds()}
    for item in declared:
        assert dependency_coverage_state(item, health.get(f"osv:Maven:{item['name']}:1.0")) == "not-run"
