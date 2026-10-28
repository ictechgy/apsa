"""Bounded source declarations, never a substitute for executing a build resolver."""

from __future__ import annotations

import posixpath
import re
from collections.abc import Iterator
from itertools import islice
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from .selection import relative_source_path


def _tokens(text: str, *, token_limit: int | None = 200_000) -> Iterator[tuple[str, str, int]]:
    """Keep literals opaque in one pass; malformed input cannot retry suffixes."""
    identifier = re.compile(r"[A-Za-z_]\w*")
    cursor, line, count = 0, 1, 0
    while cursor < len(text):
        start = cursor
        if text[cursor].isspace():
            line += text[cursor] == "\n"
            cursor += 1
            continue
        if text.startswith("//", cursor):
            end = text.find("\n", cursor + 2)
            cursor = len(text) if end < 0 else end
            continue
        if text.startswith("/*", cursor):
            end = text.find("*/", cursor + 2)
            if end < 0:
                raise ValueError("Unterminated source declaration comment; versions remain unresolved")
            cursor = end + 2
            line += text[start:cursor].count("\n")
            continue
        kind = "code"
        if text[cursor] in {"'", '"'}:
            kind = "string"
            quote = text[cursor]
            if text.startswith(quote * 3, cursor):
                end = text.find(quote * 3, cursor + 3)
                if end < 0:
                    raise ValueError("Unterminated source declaration string; versions remain unresolved")
                cursor = end + 3
            else:
                cursor += 1
                while cursor < len(text):
                    if text[cursor] == "\\":
                        cursor += 2
                    elif text[cursor] == quote:
                        cursor += 1
                        break
                    else:
                        cursor += 1
                else:
                    raise ValueError("Unterminated source declaration string; versions remain unresolved")
        else:
            match = identifier.match(text, cursor)
            cursor = match.end() if match else cursor + 1
        count += 1
        if token_limit is not None and count > token_limit:
            raise ValueError("Source declaration token budget exceeded")
        value = text[start:cursor]
        yield kind, value, line
        line += value.count("\n")


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


def resolve_gradle(
    dependencies: list[dict], sources: list[tuple[str, str]], *, opaque_sources: set[str] | None = None
) -> list[str]:
    # The source inventory can know a script's name while its bytes were
    # omitted or excluded as non-text. Absence must not look like no ancestor.
    opaque_sources = {PurePosixPath(path).as_posix() for path in (opaque_sources or ())}
    script_counts: dict[str, int] = {}
    for path, _ in sources:
        if path.endswith((".gradle", ".gradle.kts")):
            canonical = PurePosixPath(path).as_posix()
            script_counts[canonical] = script_counts.get(canonical, 0) + 1
    collisions = {path for path, count in script_counts.items() if count > 1}
    opaque_sources |= collisions
    contexts = {path: ({}, {"*"}) for path in opaque_sources}
    imports = {path: [] for path in opaque_sources}
    warnings = [f"Gradle declaration context path collision: {path}" for path in sorted(collisions)]
    opaque_roots = {
        PurePosixPath(path).parent
        for path in opaque_sources
        if PurePosixPath(path).name in {"settings.gradle", "settings.gradle.kts"}
    }
    project_roots = {
        PurePosixPath(path).parent
        for path, _ in sources
        if PurePosixPath(path).name in {"settings.gradle", "settings.gradle.kts"}
    } | opaque_roots
    for original_path, text in sources:
        if original_path.endswith((".gradle", ".gradle.kts")):
            path = PurePosixPath(original_path).as_posix()
            if path in opaque_sources:
                continue
            imports[path] = []
            try:
                # Lookup keys are canonical; evidence retains the exact source
                # member spelling that supplied the literal declaration.
                contexts[path] = literal_ext(original_path, text)
                stream = tokens(text)
            except ValueError as error:
                # This file may define or mutate any property. Its descendants
                # and importers must abstain, while independent files can resolve.
                contexts[path] = ({}, {"*"})
                warnings.append(f"Gradle declaration context unavailable: {path} ({error})")
                continue
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
                blocked |= parent in opaque_roots
                break
        if not blocked and len(candidates) == 1:
            dep["version"] = candidates[0]["value"]
            dep["confidence"] = "declared"
            dep["version_source"] = candidates[0]
    return warnings


SHIPPED_CONFIGURATIONS = re.compile(r"(?:[a-z][A-Za-z0-9]*)?(?:[Ii]mplementation|[Aa]pi|[Rr]untimeOnly)")
NON_SHIPPING = re.compile(
    r"(?i).*(?:test|debug|benchmark|compileonly|kapt|ksp|annotationprocessor|lintchecks|classpath|detekt).*"
)
MAX_CATALOG_REFERENCES = 8


def _alias_key(alias: str) -> str:
    return re.sub(r"[-_.]", ".", alias)


def _configuration_state(configuration: str, enclosing: list[str]) -> str:
    if any(re.search(r"(?i)test|buildscript|constraints", block) for block in enclosing):
        return "non-shipping-configuration"
    if NON_SHIPPING.fullmatch(configuration):
        return "non-shipping-configuration"
    if configuration == "coreLibraryDesugaring" or SHIPPED_CONFIGURATIONS.fullmatch(configuration):
        return "declared"
    return "referenced-unclassified"


def _declaration_state(
    stream: list[tuple[str, str, int]], index: int, line: int, blocks: list[str]
) -> tuple[str, str]:
    """Classify the dependency configuration that encloses the expression at index."""
    configuration = ""
    platform = False
    # Walk back over wrappers such as implementation(platform(libs.x)) or add("api", libs.x).
    back = index - 1
    while back >= 0 and stream[back][1] == "(":
        callee = stream[back - 1] if back else None
        if callee and callee[1] in {"platform", "enforcedPlatform"}:
            platform = True
            back -= 2
            continue
        if callee and callee[0] == "string":
            configuration = callee[1][1:-1]
        elif callee and callee[0] == "code" and re.fullmatch(r"[A-Za-z_]\w*", callee[1]):
            configuration = callee[1]
        break
    if not configuration and back >= 3 and stream[back][1] == ",":
        call = stream[back - 3 : back]
        if [t[1] for t in call[:2]] == ["add", "("] and call[2][0] == "string":
            configuration = call[2][1][1:-1]
    if not configuration and back >= 0 and stream[back][0] == "code" and stream[back][2] == line:
        # Groovy command syntax: implementation libs.foo
        if re.fullmatch(r"[A-Za-z_]\w*", stream[back][1]):
            configuration = stream[back][1]
    if platform:
        return "platform-only", configuration
    if not configuration:
        return "referenced-unclassified", configuration
    return _configuration_state(configuration, blocks), configuration


def _module_key(parts: list[str]) -> str:
    return ".".join(re.sub(r"[-_]", "", part).lower() for part in parts if part)


TOOLING = re.compile(
    r"`\s*kotlin\s*-\s*dsl\s*`|`\s*java\s*-\s*gradle\s*-\s*plugin\s*`|[\"']java-gradle-plugin[\"']"
)
# Plugin application syntax only (plugins-block id/alias, apply plugin:); a bare
# string such as pluginManager.withPlugin("com.android.application") is not one.
_APPLY = r"(?:\bid\s*\(?\s*|\bplugin\s*:\s*)"
TEST_MODULE = re.compile(
    _APPLY + r"[\"']com\.android\.test[\"']|\bplugins\s*\.\s*(?:\w+\s*\.\s*)*android\s*\.\s*test\b"
)
APPLICATION = re.compile(
    _APPLY + r"[\"'][\w.-]*application[\"']"
    r"|\bplugins\s*\.\s*(?:\w+\s*\.\s*)*application\b|\bapplicationId\s*(?:=|\(|[\"'])"
)
LIBRARY = re.compile(
    _APPLY + r"[\"'][\w.-]*library[\"']|`\s*java\s*-\s*library\s*`"
    r"|\bplugins\s*\.\s*(?:\w+\s*\.\s*)*library\b|\bkotlin\s*\(\s*[\"']jvm[\"']"
)
NOT_APPLIED = re.compile(
    r"\s*\)?\s*(?:\.?\s*version\s*\(?\s*[\"'][^\"']*[\"']\s*\)?\s*)?"
    r"(?:apply\s+false\b|\.\s*apply\s*\(\s*false\s*\))"
)


def _declares(pattern: re.Pattern[str], code: str) -> bool:
    """A plugin applied to this project; `apply false` only adds it to the classpath."""
    return any(not NOT_APPLIED.match(code, match.end()) for match in pattern.finditer(code))


def _module_mappings(sources, scripts):
    """Read literal settings projectDir mappings; computed or escaping paths abstain."""
    keys = {_module_key(list(directory.parts)): directory for directory in scripts}
    warnings = []
    unresolved = False
    assigned = {}
    for path, text in sources:
        if PurePosixPath(path).name not in {"settings.gradle", "settings.gradle.kts"}:
            continue
        try:
            stream = tokens(text)
        except ValueError:
            warnings.append(f"Gradle settings token budget exceeded: {path}")
            unresolved = True
            continue
        root = PurePosixPath(path).parent
        depth = 0
        for index, (kind, value, line) in enumerate(stream):
            if kind == "code" and value == "{":
                depth += 1
            elif kind == "code" and value == "}":
                depth -= 1
            if kind != "code" or value != "projectDir":
                continue
            # project(":logical").projectDir = file("physical/location")
            head = stream[max(0, index - 5) : index]
            tail = stream[index + 1 : index + 6]
            logical = head[2][1][1:-1] if len(head) == 5 and head[2][0] == "string" else None
            valid = (
                depth == 0
                and len(head) == 5
                and head[0][1] == "project"
                and head[1][1] == "("
                and head[3][1] == ")"
                and head[4][1] == "."
                and len(tail) == 5
                and [t[1] for t in tail[:3]] == ["=", "file", "("]
                and tail[3][0] == "string"
                and tail[4][1] == ")"
            )
            after = stream[index + 6 : index + 7]
            prefix = stream[max(0, index - 64) : max(0, index - 5)]
            for previous_kind, previous, _ in reversed(prefix):
                if previous_kind == "code" and previous in {";", "}"}:
                    break
                if previous_kind == "code" and previous in {"if", "when", "for", "while"}:
                    valid = False
                    break
            if (
                after
                and after[0][1] not in {";", "}"}
                and (after[0][2] <= tail[-1][2] or after[0][1] in {".", "+", "-", "?", "("})
            ):
                valid = False
            key = _module_key(logical.split(":")) if logical else None
            if valid and logical is not None and key is not None:
                destination = tail[3][1][1:-1]
                try:
                    relative_source_path(destination)
                    if (
                        "$" in destination
                        or "\\" in destination
                        or re.match(r"[A-Za-z]:", destination)
                        or not re.fullmatch(r":[A-Za-z0-9_-]+(?::[A-Za-z0-9_-]+)*", logical)
                    ):
                        raise ValueError("Computed or unsafe module mapping")
                    directory = root / destination
                    if directory not in scripts:
                        raise ValueError("Mapped build script is absent")
                    if key in assigned:
                        raise ValueError("Repeated module mapping is ambiguous")
                    assigned[key] = directory
                    keys[key] = directory
                    continue
                except ValueError:
                    pass
            unresolved = True
            if key:
                keys.pop(key, None)
            warnings.append(f"Gradle projectDir mapping unresolved or unsafe: {path}:{line}")
    return keys, warnings, unresolved


class ModuleGraph:
    """Gradle project roles and shipped reachability from build scripts.

    Build tooling (buildSrc, kotlin-dsl or java-gradle-plugin builds) and Android
    test modules never ship. A library module whose every consumer either uses an
    explicitly non-shipping configuration or does not ship itself does not ship
    either, but only when every build script was read and the module positively
    applies a library plugin. Applications, unreferenced modules and modules
    reached through unclassified configurations remain possible shipped code.
    """

    def __init__(self, sources: list[tuple[str, str]], *, partial: bool = False) -> None:
        scripts = {
            PurePosixPath(path).parent: text
            for path, text in sources
            if PurePosixPath(path).name in {"build.gradle", "build.gradle.kts"}
        }
        self.warnings: list[str] = []
        roles: dict[PurePosixPath, str] = {}
        self.applications: set[PurePosixPath] = set()
        libraries: set[PurePosixPath] = set()
        keys, mapping_warnings, mapping_partial = _module_mappings(sources, scripts)
        self.warnings.extend(mapping_warnings)
        edges: dict[PurePosixPath, list[tuple[PurePosixPath, str]]] = {}
        complete = not partial and not mapping_partial
        # An unreadable project reference may hide a consumer of any module.
        self.unresolved_project_references = mapping_partial
        for directory, text in scripts.items():
            try:
                stream = tokens(text)
            except ValueError:
                complete = False
                # An unread script may hide a consumer of any module.
                self.unresolved_project_references = True
                self.warnings.append(f"Gradle module role not resolved: {directory.as_posix() or '.'}")
                continue
            code = " ".join(value for _, value, _ in stream)
            if "buildSrc" in directory.parts or TOOLING.search(code):
                roles[directory] = "build-tooling"
            elif _declares(TEST_MODULE, code):
                roles[directory] = "non-shipping-module"
            library = _declares(LIBRARY, code)
            if library:
                libraries.add(directory)
            elif directory not in roles and _declares(APPLICATION, code):
                # Library plugin evidence wins over an application-looking mention.
                self.applications.add(directory)
            blocks: list[str] = []
            for index, (kind, value, line) in enumerate(stream):
                if kind == "code" and value == "{":
                    blocks.append(" ".join(t[1] for t in stream[max(0, index - 6) : index] if t[2] == line))
                    continue
                if kind == "code" and value == "}":
                    if blocks:
                        blocks.pop()
                    continue
                target = None
                if kind == "code" and value == "projects" and not (index and stream[index - 1][1] == "."):
                    chain = []
                    cursor = index + 1
                    while (
                        cursor + 1 < len(stream)
                        and stream[cursor][1] == "."
                        and stream[cursor + 1][0] == "code"
                    ):
                        chain.append(stream[cursor + 1][1])
                        cursor += 2
                    target = _module_key(chain)
                elif (
                    kind == "code"
                    and value == "project"
                    and stream[index + 1 : index + 2] == [("code", "(", line)]
                ):
                    argument = stream[index + 2 : index + 5]
                    if argument and argument[0][0] == "string":
                        target = _module_key(argument[0][1][1:-1].split(":"))
                    elif (
                        len(argument) == 3
                        and argument[0][1] == "path"
                        and argument[1][1] in {":", "="}
                        and argument[2][0] == "string"
                    ):
                        target = _module_key(argument[2][1][1:-1].split(":"))
                    else:
                        self.unresolved_project_references = True
                if target and target not in keys:
                    self.unresolved_project_references = True
                if target and target in keys and keys[target] != directory:
                    state, _ = _declaration_state(stream, index, line, blocks)
                    edges.setdefault(keys[target], []).append((directory, state))
        live = {directory for directory in scripts if directory not in roles}
        if complete:
            changed = True
            while changed:
                changed = False
                for directory, consumers in edges.items():
                    if (
                        directory in live
                        and directory in libraries
                        and directory not in self.applications
                        and all(
                            consumer not in live or state in {"non-shipping-configuration", "platform-only"}
                            for consumer, state in consumers
                        )
                    ):
                        live.discard(directory)
                        roles.setdefault(directory, "non-shipping-module")
                        changed = True
        elif edges:
            self.warnings.append(
                "Gradle module consumption was not used to exclude modules because the source inventory is partial."
            )
        self.role_resolution_partial = not complete
        self.partial = not complete or self.unresolved_project_references
        self.module_directories = {key: value.as_posix() for key, value in keys.items()}
        self.roles = {directory.as_posix(): role for directory, role in roles.items()}
        for directory in self.applications:
            self.roles[directory.as_posix()] = "application"
        # Shipped reach from every possible app: recognized applications and any
        # live module that no live module consumes (an unrecognized app, perhaps).
        self.reach: dict[str, set[str]] = {}
        shipped: dict[PurePosixPath, set[PurePosixPath]] = {}
        consumed: set[PurePosixPath] = set()
        for target, consumers in edges.items():
            for consumer, state in consumers:
                if state == "declared" and target in live and consumer in live:
                    shipped.setdefault(consumer, set()).add(target)
                    consumed.add(target)
        roots = self.applications | {directory for directory in live if directory not in consumed}
        for root in roots:
            seen = {root}
            pending = [root]
            while pending:
                for target in shipped.get(pending.pop(), set()) - seen:
                    seen.add(target)
                    pending.append(target)
            self.reach[root.as_posix()] = {directory.as_posix() for directory in seen}


def _catalog_references(path: str, text: str, names: set[str]) -> list[dict]:
    """Find catalog accessors in dependency declarations; other uses stay unclassified."""
    stream = tokens(text)
    blocks: list[str] = []
    found = []
    for index, (kind, value, line) in enumerate(stream):
        if kind == "code" and value == "{":
            head = [t[1] for t in stream[max(0, index - 6) : index] if t[2] == line]
            blocks.append(" ".join(head))
            continue
        if kind == "code" and value == "}":
            if blocks:
                blocks.pop()
            continue
        if kind != "code" or value not in names or (index and stream[index - 1][1] == "."):
            continue
        # libs.foo.bar, libs.bundles.x, libs.findLibrary("foo").get()
        chain = []
        cursor = index + 1
        lookup = None
        while cursor + 1 < len(stream) and stream[cursor][1] == "." and stream[cursor + 1][0] == "code":
            part = stream[cursor + 1][1]
            if part in {"findLibrary", "findBundle"}:
                argument = stream[cursor + 2 : cursor + 5]
                if len(argument) == 3 and argument[0][1] == "(" and argument[1][0] == "string":
                    lookup = (part, argument[1][1][1:-1])
                break
            if part in {"get", "asProvider"}:
                break
            chain.append(part)
            cursor += 2
        if lookup:
            kind_name = "bundle" if lookup[0] == "findBundle" else "library"
            key = _alias_key(lookup[1])
        elif chain and chain[0] in {"plugins", "versions"}:
            continue
        elif chain and chain[0] == "bundles":
            kind_name, key = "bundle", ".".join(chain[1:])
        elif chain:
            kind_name, key = "library", ".".join(chain)
        else:
            continue
        state, configuration = _declaration_state(stream, index, line, blocks)
        found.append(
            {
                "kind": kind_name,
                "key": key,
                "catalog": value,
                "path": path,
                "line": line,
                "configuration": configuration,
                "state": state,
            }
        )
    return found


def resolve_catalog_usage(
    dependencies: list[dict], sources: list[tuple[str, str]], graph: ModuleGraph | None = None
) -> list[str]:
    """Link catalog aliases to declared build configurations without claiming resolution.

    A used alias becomes a declared candidate, like a literal Gradle declaration.
    Conflict resolution, variant selection and transitive upgrades still require
    resolved build evidence (Gradle lockfile or SBOM).
    """
    catalogs = [dep for dep in dependencies if dep.get("catalog_alias")]
    if not catalogs:
        return []
    warnings = []
    settings = [text for path, text in sources if PurePosixPath(path).name.startswith("settings.gradle")]
    names = {}
    for dep in catalogs:
        location = PurePosixPath(dep["path"])
        stem = location.name.removesuffix(".versions.toml")
        if stem == "libs" and location.parent.name == "gradle":
            name = "libs"
        elif any(re.search(r"\bcreate\s*\(\s*[\"']" + re.escape(stem) + r"[\"']", text) for text in settings):
            name = stem
        else:
            name = None
        root = location.parent.parent if location.parent.name == "gradle" else location.parent
        names[dep["path"]] = (name, root)
    accessor_names = {name for name, _ in names.values() if name}
    roles = graph.roles if graph else {}
    references: dict[tuple[str, str, str], list[dict]] = {}
    for path, text in sources:
        if not path.endswith((".gradle", ".gradle.kts", ".kt")) or not any(
            name + "." in text for name in accessor_names
        ):
            continue
        try:
            found = _catalog_references(path, text, accessor_names)
        except ValueError as error:
            warnings.append(f"Catalog usage not resolved in {path}: {error}")
            continue
        script = PurePosixPath(path).name in {"build.gradle", "build.gradle.kts"}
        role = roles.get(PurePosixPath(path).parent.as_posix()) if script else None
        for ref in found:
            if role in {"build-tooling", "non-shipping-module"} and ref["state"] == "declared":
                ref["state"] = role
            ref["module"] = PurePosixPath(path).parent.as_posix() if script else None
            references.setdefault((ref["catalog"], ref["kind"], ref["key"]), []).append(ref)
    for dep in catalogs:
        name, root = names[dep["path"]]
        usage = {"state": "catalog-name-unresolved" if not name else "no-reference-found", "references": []}
        matched: list[dict] = []
        if name:
            alias = _alias_key(dep["catalog_alias"])
            bundles = {_alias_key(bundle) for bundle in dep.get("catalog_bundles", [])}
            candidates = list(references.get((name, "library", alias), []))
            for bundle in bundles:
                candidates.extend(references.get((name, "bundle", bundle), []))
            matched = [
                ref
                for ref in candidates
                if root == PurePosixPath(".") or PurePosixPath(ref["path"]).is_relative_to(root)
            ]
            for state in (
                "declared",
                "platform-only",
                "non-shipping-configuration",
                "non-shipping-module",
                "build-tooling",
                "referenced-unclassified",
            ):
                if any(ref["state"] == state for ref in matched):
                    usage["state"] = state
                    break
            usage["references"] = [
                {k: ref[k] for k in ("path", "line", "configuration", "state")}
                for ref in sorted(matched, key=lambda r: (r["state"] != "declared", r["path"], r["line"]))
            ][:MAX_CATALOG_REFERENCES]
            usage["reference_count"] = len(matched)
        dep["catalog_usage"] = usage
        if name:
            declaring = [ref["module"] for ref in matched if ref["state"] == "declared"]
            # Modules whose shipped configurations name this alias; None when a
            # convention plugin or script plugin declares it on others' behalf.
            dep["declaring_modules"] = (
                sorted(set(declaring))[:32] if declaring and all(m is not None for m in declaring) else None
            )
        if usage["state"] == "declared":
            dep["confidence"] = "declared"
            dep["version_source"] = "catalog-alias-declared"
    return warnings


def superseded(dep: dict) -> bool:
    return (dep.get("resolution") or {}).get("state") == "superseded-by-resolved-build"


def supersede(dependencies: list[dict], graph: ModuleGraph | None, *, partial: bool = False) -> None:
    """Resolved application lockfiles replace declared candidates they cover.

    Only an application module's lockfile records what that app ships; other
    lockfiles are resolved in their own module's context and stay candidates.
    A declared candidate is superseded only when every possible app that ships
    a declaring module (recognized applications and unconsumed modules) resolved
    that package in its own lockfile. Without a module graph nothing is exact and
    nothing is superseded.
    """
    roles = graph.roles if graph else {}
    resolved: dict[str, dict[str, set[str]]] = {}
    for dep in dependencies:
        if dep.get("version_source") != "gradle-lockfile-resolved":
            continue
        module = PurePosixPath(dep["path"]).parent
        if module.name == "dependency-locks":
            module = module.parent.parent
        if roles.get(module.as_posix()) != "application":
            dep["confidence"] = "declared"
            dep["version_source"] = "gradle-lockfile-non-application-module"
            continue
        resolved.setdefault(dep["name"], {}).setdefault(module.as_posix(), set()).add(dep["version"])
    if not graph or partial or graph.role_resolution_partial:
        # Omitted build scripts could hide another shipping consumer.
        return
    for dep in dependencies:
        if dep["ecosystem"] != "Maven" or dep["name"] not in resolved or dep.get("confidence") != "declared":
            continue
        if dep.get("version_source") == "gradle-lockfile-non-application-module":
            continue
        apps = resolved[dep["name"]]
        versions = sorted({v for found in apps.values() for v in found})[:16]
        if dep.get("catalog_alias"):
            declaring = dep.get("declaring_modules")
        else:
            declaring = [PurePosixPath(dep["path"]).parent.as_posix()]
        shippers = {
            root for module in declaring or [] for root, reach in graph.reach.items() if module in reach
        }
        if graph.unresolved_project_references:
            # A hidden consumer could ship a declaring module; only an app's own
            # declarations are then covered by its lockfile.
            shippers |= set(declaring or [])
        if declaring and shippers and shippers <= set(apps):
            dep["confidence"] = "unknown"
            dep["resolution"] = {"state": "superseded-by-resolved-build", "resolved_versions": versions}
        else:
            dep["resolution"] = {"state": "resolved-in-other-module", "resolved_versions": versions}


def plist_references(sources: list[tuple[str, str]]) -> tuple[dict[str, list[dict]], list[str]]:
    references: dict[str, list[dict]] = {}
    warnings = []
    for path, text in sources:
        if not path.endswith(".xcodeproj/project.pbxproj"):
            continue
        if len(text.encode("utf-8")) > 8 * 1024 * 1024:
            warnings.append(f"INFOPLIST_FILE byte budget exceeded: {path}")
            continue
        # This parser streams under its existing byte/declaration/value limits;
        # it need not retain the full declaration token list used by Gradle.
        declarations = 0
        try:
            stream = iter(_tokens(text, token_limit=None))
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
        except ValueError as error:
            warnings.append(f"INFOPLIST_FILE tokenization incomplete: {path}: {error}")
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
