"""Bounded source declarations, never a substitute for executing a build resolver."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from itertools import islice
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .selection import relative_source_path


def _tokens(text: str) -> Iterator[tuple[str, str, int]]:
    """Keep strings opaque and discard comments; unknown syntax remains visible."""
    pattern = r'''//[^\n]*|/\*[\s\S]*?\*/|"""[\s\S]*?"""|\x27\x27\x27[\s\S]*?\x27\x27\x27|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27|[A-Za-z_]\w*|[^\s]'''
    line, end = 1, 0
    for match in re.finditer(pattern, text):
        line += text[end : match.start()].count("\n")
        value = match.group()
        if not value.startswith(("//", "/*")):
            kind = "string" if value.startswith(('"', "'")) else "code"
            yield kind, value, line
        line += value.count("\n")
        end = match.end()


def tokens(text: str) -> list[tuple[str, str, int]]:
    result = list(islice(_tokens(text), 200_001))
    if len(result) > 200_000:
        raise ValueError("Source declaration token budget exceeded")
    return result


def literal_ext(path: str, text: str) -> tuple[dict, set[str]]:
    """Accept only standalone literals in a top-level Groovy ext closure.

    Every other code occurrence or bracket/string access of the property rejects
    it. Reassignments, nested/conditional closures and computed RHSs abstain.
    """
    stream = tokens(text)
    accepted = {}
    lhs = set()
    depth = 0
    ext_depth = None
    for index, (kind, value, line) in enumerate(stream):
        if kind != "code":
            continue
        if value == "{":
            prefix = [t[1] for t in stream[max(0, index - 3) : index]]
            length = 3 if prefix[-3:] == ["project", ".", "ext"] else 1
            start = index - length
            standalone = start >= 0 and (
                start == 0
                or stream[start - 1][1] in {";", "}"}
                or (stream[start - 1][1] not in {".", "?"} and stream[start - 1][2] < stream[start][2])
            )
            if (
                depth == 0
                and standalone
                and (prefix[-3:] == ["project", ".", "ext"] or prefix[-1:] == ["ext"])
            ):
                ext_depth = 1
            depth += 1
        elif value == "}":
            depth -= 1
            if depth < 0:
                raise ValueError("Malformed Gradle declaration braces; versions remain unresolved")
            if depth == 0:
                ext_depth = None
        elif ext_depth == depth == 1 and re.fullmatch(r"[A-Za-z_]\w*", value):
            if index + 2 >= len(stream) or stream[index + 1][1] != "=":
                continue
            rhs = stream[index + 2]
            tail = stream[index + 3] if index + 3 < len(stream) else None
            start = (
                index == 0
                or stream[index - 1][1] in {"{", ";"}
                or (stream[index - 1][1] not in {".", "?"} and stream[index - 1][2] < line)
            )
            end = (
                tail is None
                or tail[1] in {";", "}"}
                or (
                    tail[2] > rhs[2]
                    and tail[1] not in {"as", "in", "instanceof"}
                    and bool(re.fullmatch(r"[A-Za-z_]\w*", tail[1]))
                )
            )
            literal = re.fullmatch(r"""["']([0-9][A-Za-z0-9_.-]*)["']""", rhs[1])
            if start and end and rhs[0] == "string" and literal:
                accepted.setdefault(value, []).append(
                    {"path": path, "line": line, "property": value, "value": literal[1]}
                )
                lhs.add(index)
    blocked = {
        value.strip("\"'")
        for index, (kind, value, _) in enumerate(stream)
        if index not in lhs and (kind == "code" or re.fullmatch(r"""["'][A-Za-z_]\w*["']""", value))
    }
    # Imported scripts and reflective property setters make this context opaque.
    opaque = any(
        t[0] == "code" and t[1] in {"evaluate", "setProperty", "set", "if", "for", "while", "switch", "try"}
        for t in stream
    )
    if opaque:
        blocked.update(accepted)
    if depth != 0:
        raise ValueError("Malformed Gradle declaration braces; versions remain unresolved")
    if any(t[0] == "code" and t[1] in {"evaluate", "setProperty", "set"} for t in stream):
        blocked.add("*")
    return {key: values[0] for key, values in accepted.items() if len(values) == 1}, blocked | {
        key for key, values in accepted.items() if len(values) != 1
    }


def resolve_gradle(dependencies: list[dict], sources: list[tuple[str, str]]) -> None:
    contexts = {}
    imports = {}
    project_roots = {
        PurePosixPath(path).parent
        for path, _ in sources
        if PurePosixPath(path).name in {"settings.gradle", "settings.gradle.kts"}
    }
    for path, text in sources:
        if path.endswith((".gradle", ".gradle.kts")):
            contexts[path] = literal_ext(path, text)
            stream = tokens(text)
            imports[path] = []
            for i, token in enumerate(stream):
                if token[0] != "code" or token[1] != "apply":
                    continue
                tail = stream[i + 1 : i + 4]
                if tail and tail[0][1] == "from":
                    if len(tail) != 3 or tail[1][1] != ":" or tail[2][0] != "string":
                        contexts[path][1].add("*")
                        continue
                    value = tail[2][1][1:-1]
                    following = stream[i + 4] if i + 4 < len(stream) else None
                    if following and following[1] != ";" and following[2] == tail[2][2]:
                        contexts[path][1].add("*")
                        continue
                    resolved = posixpath.normpath((PurePosixPath(path).parent / value).as_posix())
                    if "$" in value or "\\" in value or resolved.startswith(("/", "../")):
                        contexts[path][1].add("*")
                    else:
                        imports[path].append(resolved)

    def with_imports(path: str, seen: set[str]) -> list[str] | None:
        if path in seen or len(seen) >= 64 or path not in contexts:
            return None
        seen.add(path)
        result = [path]
        for imported in imports[path]:
            children = with_imports(imported, seen)
            if children is None:
                return None
            result.extend(children)
        return result

    for dep in dependencies:
        expression = dep.get("version_expression", "")
        match = re.fullmatch(r"\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})", expression)
        if not match or not dep.get("version_interpolation"):
            continue
        key = match[1] or match[2]
        candidates = []
        blocked = False
        visited = set()
        for parent in [PurePosixPath(dep["path"]).parent, *PurePosixPath(dep["path"]).parent.parents]:
            for filename in ("build.gradle", "build.gradle.kts"):
                path = (parent / filename).as_posix()
                if path not in contexts:
                    continue
                paths = with_imports(path, set())
                if paths is None:
                    blocked = True
                    continue
                for path in paths:
                    if path in visited:
                        continue
                    visited.add(path)
                    context = contexts[path]
                    values, rejected = context
                    blocked |= key in rejected or "*" in rejected
                    if key in values:
                        candidates.append(values[key])
            if parent in project_roots:
                break
        if not blocked and len(candidates) == 1:
            dep["version"] = candidates[0]["value"]
            dep["confidence"] = "declared"
            dep["version_source"] = candidates[0]


def plist_references(sources: list[tuple[str, str]]) -> tuple[dict[str, list[dict]], list[str]]:
    references: dict[str, list[dict]] = {}
    warnings = []
    for path, text in sources:
        if not path.endswith(".xcodeproj/project.pbxproj"):
            continue
        if len(text.encode("utf-8")) > 8 * 1024 * 1024:
            warnings.append(f"INFOPLIST_FILE byte budget exceeded: {path}")
            continue
        stream = iter(_tokens(text))
        declarations = 0
        for kind, key, line in stream:
            if kind == "string" and key.strip('"').startswith("INFOPLIST_FILE["):
                warnings.append(f"Unsupported conditional INFOPLIST_FILE declaration: {path}:{line}")
                continue
            if kind != "code" or key != "INFOPLIST_FILE":
                continue
            declarations += 1
            if declarations > 4096:
                warnings.append(f"INFOPLIST_FILE declaration budget exceeded: {path}")
                break
            tail = []
            terminated = False
            for token in islice(stream, 256):
                if token[1] == ";":
                    terminated = True
                    break
                tail.append(token)
            if not terminated:
                warnings.append(f"INFOPLIST_FILE value budget or terminator missing: {path}:{line}")
                break
            if not tail or tail[0][1] != "=" or len(tail) < 2:
                warnings.append(f"Unsupported INFOPLIST_FILE declaration: {path}:{line}")
                continue
            value = "".join(t[1] for t in tail[1:]).strip('"')
            for prefix in ("$(SRCROOT)/", "$(PROJECT_DIR)/", "${SRCROOT}/", "${PROJECT_DIR}/"):
                if value.startswith(prefix):
                    value = value[len(prefix) :]
                    break
            try:
                value = relative_source_path(value)
                if "$" in value or not value.endswith(".plist"):
                    raise ValueError("Unresolved plist path")
                destination = (PurePosixPath(path).parent.parent / value).as_posix()
                references.setdefault(destination, []).append({"path": path, "line": line})
            except ValueError:
                warnings.append(f"Unsafe or unresolved INFOPLIST_FILE declaration: {path}:{line}")
    return references, warnings


def osv_package_name(dep: dict) -> str:
    if dep["ecosystem"] != "SwiftURL":
        return dep["name"]
    name = dep["name"]
    url = urlsplit(name if "://" in name else "https://" + name)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.port
        or url.query
        or url.fragment
        or "%" in name
        or "\\" in name
    ):
        raise ValueError("Unsupported Swift repository identity")
    path = url.path.rstrip("/").removesuffix(".git")
    if not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", path) or any(
        part in {".", ".."} for part in path.split("/")
    ):
        raise ValueError("Unsupported Swift repository path")
    return url.hostname.lower() + path
