"""Select resolved dependency evidence without claiming an installed build."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from pathlib import PurePosixPath

from .selection import relative_source_path
from .source_context import ModuleGraph


@dataclass(frozen=True)
class ResolvedBuildSelection:
    application_module: str
    runtime_configuration: str
    evidence_paths: tuple[str, ...] = ()

    def __post_init__(self):
        # '.' is the valid root application module; absolute/traversal paths fail.
        if self.application_module != ".":
            relative_source_path(self.application_module)
        if not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]*RuntimeClasspath|runtimeClasspath", self.runtime_configuration
        ):
            raise ValueError("Expected a literal Gradle runtime configuration")
        if not isinstance(self.evidence_paths, (tuple, list)) or len(self.evidence_paths) > 256:
            raise ValueError("Expected bounded dependency evidence paths")
        for path in self.evidence_paths:
            relative_source_path(path)
        object.__setattr__(self, "evidence_paths", tuple(self.evidence_paths))


def lockfile_module(dep: dict) -> str:
    directory = PurePosixPath(dep["path"]).parent
    if directory.name == "dependency-locks":
        directory = directory.parent.parent
    return directory.as_posix()


def select_dependency_evidence(
    dependencies: list[dict], graph: ModuleGraph | None, *, selection: ResolvedBuildSelection | None = None
) -> tuple[list[dict], list[str]]:
    """Return copied candidates and warnings for a particular app/runtime graph.

    Freshness is unverified: this reader does not execute a build verifier.
    Merely choosing a lockfile/configuration is no proof
    of freshness, build execution, installation, or runtime reachability.
    """
    result, warnings = [], []
    available = set(graph.reach.get(selection.application_module, ())) if graph and selection else set()
    selected_app = bool(
        selection and graph and graph.roles.get(selection.application_module) == "application"
    )
    graph_complete = bool(graph and not graph.partial and not graph.unresolved_project_references)
    selected_count = 0
    if selection and (not selected_app or not graph_complete):
        warnings.append(
            "Selected dependency application graph is unresolved or partial; resolved installed-build coverage is not established."
        )
    for original in dependencies:
        dep = deepcopy(original)
        locked = str(dep.get("version_source") or "").startswith("gradle-lockfile")
        if not locked:
            if selection and selected_app and graph_complete and dep.get("ecosystem") == "Maven":
                declaring = (
                    dep.get("declaring_modules")
                    if dep.get("catalog_alias")
                    else [PurePosixPath(dep["path"]).parent.as_posix()]
                )
                if declaring and not any(module in available for module in declaring):
                    continue
            result.append(dep)
            continue
        module = lockfile_module(dep)
        configurations = dep.get("resolved_configurations", [])
        context = {
            "application_module": module,
            "configurations": list(configurations),
            "selection": "unselected",
            "freshness": "unverified",
            "installed_build_verified": False,
            "basis": "Gradle lockfile coordinate; build execution and lock freshness are not verified",
        }
        dep["build_evidence"] = context
        if not selection:
            result.append(dep)
            continue
        if module != selection.application_module or selection.runtime_configuration not in configurations:
            continue
        if selection.evidence_paths and dep["path"] not in selection.evidence_paths:
            continue
        context.update(
            selection="selected" if selected_app and graph_complete else "partial",
            runtime_configuration=selection.runtime_configuration,
        )
        dep["resolved_configurations"] = [selection.runtime_configuration]
        # Multiple applications and flavors cannot stand for one installed app.
        # Invalid selection cannot establish exact application lock resolution.
        if not selected_app or not graph_complete:
            dep["confidence"] = "declared"
            dep["version_source"] = "gradle-lockfile-selection-partial"
        selected_count += 1
        result.append(dep)
    if selection and not selected_count:
        warnings.append(
            "No resolved dependency evidence matches the selected application and runtime configuration."
        )
    if selection:
        versions: dict[tuple[str, str], set[str]] = {}
        for dep in result:
            if (dep.get("build_evidence") or {}).get("selection") in {"selected", "partial"}:
                versions.setdefault((dep["ecosystem"], dep["name"]), set()).add(dep["version"])
        ambiguous = {key for key, values in versions.items() if len(values) > 1}
        if ambiguous:
            warnings.append(
                "Selected runtime evidence contains conflicting versions; exact application resolution is not established."
            )
            for dep in result:
                if (dep["ecosystem"], dep["name"]) in ambiguous and dep.get("build_evidence"):
                    dep["build_evidence"]["selection"] = "partial"
                    dep["confidence"] = "declared"
                    dep["version_source"] = "gradle-lockfile-selection-partial"
    if any(str(d.get("version_source") or "").startswith("gradle-lockfile") for d in result):
        warnings.append(
            "Gradle lockfile freshness and installed build identity are unverified; coordinates describe recorded resolution only."
        )
    return result, warnings
