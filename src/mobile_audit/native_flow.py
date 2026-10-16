"""Bounded direct native call summaries; uncertainty never supplies a sanitizer."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .source_analysis import (
    FILE_SINKS,
    FUNCTIONS,
    INTENT_LAUNCHERS,
    NESTED_INTENT_GETTERS,
    RULES,
    SQL_SINKS,
    TRACE_PARTIAL,
    Analyzer,
    Call,
    Frame,
    Trace,
    Value,
    _field,
    _union,
)

MAX_CALL_DEPTH = 8
MAX_CALL_EVALUATIONS = 1024
MAX_CALLABLES = 4096
MAX_FIELD_ROUNDS = 4
MAX_PARTIAL_DETAILS = 256


class StorageKey(Enum):
    UNKNOWN_FIELDS = "unknown-fields"
    STATIC_FIELDS = "static-fields"
    UNRESOLVED_FIELDS = "unresolved-fields"


SCALAR_STRING_TYPES = {"java": "java.lang.String", "kotlin": "kotlin.String", "swift": "Swift.String"}
NOMINAL_DECLARATIONS = {
    "class_declaration",
    "object_declaration",
    "interface_declaration",
    "enum_declaration",
    "record_declaration",
    "annotation_type_declaration",
    "protocol_declaration",
}
NOMINAL_BODIES = {
    "class_body",
    "interface_body",
    "enum_body",
    "enum_class_body",
    "annotation_type_body",
    "protocol_body",
    "struct_body",
    "actor_body",
    "extension_body",
    "object_body",
}
UNAVAILABLE_NOMINAL_DECLARATIONS = {
    "companion_object",
    "class_interface",
    "class_implementation",
    "category_interface",
    "category_implementation",
}
INHERITED_TYPE_SCOPES = {
    "superclass",
    "super_interfaces",
    "extends_interfaces",
    "delegation_specifiers",
    "inheritance_specifier",
}
# These exact platform identities already have value/sink models in Analyzer.
# An import is evidence for deferring to those models, not for inferring a body.
MODELED_EXTERNAL_CONSTRUCTORS = {
    "android.content.Intent",
    "android.webkit.WebView",
    "java.io.File",
    "java.io.FileInputStream",
    "java.io.FileOutputStream",
    "java.io.FileReader",
    "java.io.FileWriter",
    "java.io.RandomAccessFile",
    "java.net.URI",
    "java.net.URL",
    "javax.crypto.spec.SecretKeySpec",
    "javax.crypto.spec.DESKeySpec",
    "javax.crypto.spec.DESedeKeySpec",
    "javax.crypto.spec.PBEKeySpec",
    "javax.crypto.spec.IvParameterSpec",
    "javax.crypto.spec.GCMParameterSpec",
}
MODELED_EXTERNAL_METHODS = {
    "android.content.Intent": {
        "getData",
        "getDataString",
        "getStringExtra",
        "getCharSequenceExtra",
        "getExtras",
        "getParcelableExtra",
        "getParcelable",
        "getSerializableExtra",
    },
    "android.net.Uri": {
        "parse",
        "getHost",
        "getScheme",
        "getQueryParameter",
        "getQueryParameters",
        "toString",
    },
    "android.webkit.WebView": {
        "loadUrl",
        "loadData",
        "loadDataWithBaseURL",
        "evaluateJavascript",
        "evaluateJavaScript",
        "addJavascriptInterface",
        "removeJavascriptInterface",
        "getSettings",
        "setJavaScriptEnabled",
    },
    "android.webkit.SslErrorHandler": {"proceed"},
    "android.util.Log": {"d", "i", "v", "e", "w"},
    "android.app.PendingIntent": {
        "getActivity",
        "getActivities",
        "getBroadcast",
        "getService",
        "getForegroundService",
    },
    "javax.crypto.Cipher": {"getInstance"},
    "java.security.MessageDigest": {"getInstance"},
    "androidx.core.content.IntentCompat": {"getParcelableExtra", "getParcelable", "getSerializableExtra"},
    "androidx.core.os.BundleCompat": {"getParcelableExtra", "getParcelable", "getSerializableExtra"},
    "java.io.File": {
        "getName",
        "getCanonicalPath",
        "getCanonicalFile",
        "toPath",
        "toString",
        "writeText",
        "writeBytes",
        "appendText",
        "appendBytes",
        "readText",
        "readBytes",
    },
    "java.net.URI": {"getHost", "getScheme", "getQueryParameter", "getQueryParameters", "toString"},
    "java.net.URL": {"getHost", "getScheme", "toString"},
    "java.nio.file.Path": {"getFileName", "toRealPath", "toString"},
    "java.nio.file.Files": {
        "newOutputStream",
        "newInputStream",
        "write",
        "writeString",
        "readAllBytes",
        "readString",
        "copy",
        "move",
    },
}
for _sdk_type, _sdk_method in SQL_SINKS:
    MODELED_EXTERNAL_METHODS.setdefault(_sdk_type, set()).add(_sdk_method)
CONTEXT = (
    "scope",
    "function",
    "function_source",
    "field_types",
    "static_fields",
    "unavailable_fields",
    "parameter_types",
    "activity_scope",
    "path_guarded",
    "action_hint",
    "intent_checks",
    "aliases",
    "literal_table",
    "private_keys",
    "target_names",
    "return_values",
    "guarded_paths",
    "unguarded_paths",
    "finding_start",
    "pending_paths",
    "active_guards",
)


@dataclass(frozen=True)
class Callable:
    analyzer: Analyzer
    node: Any
    owner: str
    name: str
    parameters: tuple
    body: Any

    @property
    def key(self) -> tuple:
        return self.analyzer.path, self.node.start_byte


@dataclass(frozen=True)
class ScopeBoundary:
    kind: str
    node: Any
    name: Any = None


class NativeFlow:
    def __init__(self, files: list[tuple[Analyzer, Any, list[Any]]]):
        self.by_name: dict[str, list[Callable]] = {}
        self.classes: dict[str, set[str]] = {}
        self.class_definitions: dict[str, list[tuple[Analyzer, Any]]] = {}
        self.namespaces: dict[int, str] = {}
        self.stack: list[tuple] = []
        self.receiver_context: list[tuple[str, str] | None] = []
        self.receiver_field_context: list[str | None] = []
        self.field_inputs: list[tuple[Analyzer, Call, Value]] = []
        self.allocations: dict[str, str] = {}
        self.call_sites: list[str] = []
        self.evaluations = 0
        self.reasons: set[str] = set()
        self.partial_details: set[tuple] = set()
        self.partial_details_truncated = False
        self.fields: dict[str, dict[str, Value]] = {}
        self.owner_cache: dict[tuple[int, int], str] = {}
        self.type_scope_cache: dict[tuple[int, int], list[tuple[str, Any]]] = {}
        self.type_parameter_cache: dict[tuple[int, int], dict[str, Any]] = {}
        self.active_guards: dict[int | tuple[int, str], set[str]] = {}
        self.active_conditions: list[Any] = []
        self.files = sorted(files, key=lambda item: item[0].path)
        count = 0
        for analyzer, root, nodes in self.files:
            analyzer.prepare(root, nodes)
            analyzer.native_flow = self
            packages = [
                node for node in root.named_children if node.type in {"package_declaration", "package_header"}
            ]
            namespace = ""
            if packages:
                match = re.fullmatch(r"package\s+([\w.]+)\s*;?", analyzer.text(packages[0]))
                if len(packages) != 1 or packages[0].has_error or match is None:
                    self.partial("package identity unavailable", analyzer, node=packages[0])
                    namespace = "@file:" + analyzer.path
                else:
                    namespace = match[1]
            self.namespaces[id(analyzer)] = namespace
            for node in nodes:
                boundary = self.scope_boundary(node)
                if boundary is not None and boundary.kind == "nominal":
                    name = boundary.name
                    if name is not None and self.unavailable_scope(node) is None:
                        owner = self.owner(analyzer, name)
                        self.classes.setdefault(analyzer.text(name), set()).add(owner)
                        self.class_definitions.setdefault(owner, []).append((analyzer, node))
                if node.type not in FUNCTIONS or node.has_error:
                    continue
                unavailable = self.unavailable_scope(node)
                if unavailable is not None:
                    self.partial(
                        "anonymous callable scope unavailable"
                        if unavailable.kind == "anonymous"
                        else "nominal callable scope unavailable",
                        analyzer,
                        node=node,
                    )
                    continue
                count += 1
                if count > MAX_CALLABLES:
                    self.partial("callable inventory budget", analyzer, node=node)
                    continue
                owner = self.owner(analyzer, node)
                if owner:
                    self.classes.setdefault(owner.rsplit(".", 1)[-1], set()).add(owner)
                name = analyzer.text(_field(node, "name"))
                body = _field(node, "body") or next(
                    (child for child in node.named_children if child.type == "function_body"), None
                )
                self.by_name.setdefault(name, []).append(
                    Callable(analyzer, node, owner, name, tuple(analyzer.parameters(node)), body)
                )

    def owner(self, analyzer: Analyzer, function: Any) -> str:
        key = (id(analyzer), function.id)
        if key in self.owner_cache:
            return self.owner_cache[key]
        scope = self.enclosing_scope(function)
        names = []
        while scope is not None:
            if scope.kind != "nominal":
                names.append(f"@{scope.kind}:{analyzer.path}:{scope.node.start_byte}")
                break
            names.append(analyzer.text(scope.name))
            scope = self.enclosing_scope(scope.node)
        if not names:
            owner = ""
        else:
            owner = ".".join(
                ([self.namespaces[id(analyzer)]] if self.namespaces[id(analyzer)] else [])
                + list(reversed(names))
            )
        self.owner_cache[key] = owner
        return owner

    def partial(
        self,
        reason: str,
        analyzer: Analyzer | None = None,
        *,
        node: Any = None,
        call: Call | None = None,
    ) -> None:
        """Record diagnostic scope without narrowing conservative rule coverage."""
        self.reasons.add(reason)
        if analyzer is not None:
            analyzer.truncated_rules.update(RULES)
        node = call.node if call is not None else node
        if node is None and analyzer is not None:
            node = analyzer.function
        category = (
            "budget"
            if "budget" in reason
            else "dispatch"
            if "dispatch" in reason or "ambiguous" in reason or "signature" in reason
            else "inventory"
            if "inventory" in reason
            else "unavailable-flow"
        )
        detail = (
            reason,
            analyzer.path if analyzer is not None else "",
            node.start_point[0] + 1 if node is not None else 0,
            node.start_point[1] + 1 if node is not None else 0,
            call.name if call is not None else "",
            category,
        )
        self.partial_details.add(detail)
        if len(self.partial_details) > MAX_PARTIAL_DETAILS:
            # Keep the same lexicographically first records regardless of visit order.
            self.partial_details.remove(max(self.partial_details))
            self.partial_details_truncated = True

    def receiver_identity(self, analyzer: Analyzer, receiver: Any, frame: Frame) -> str:
        if receiver is None or analyzer.key(receiver) in {"this", "self"}:
            if self.receiver_field_context and self.receiver_field_context[-1] is not None:
                return self.receiver_field_context[-1]
            if self.receiver_context and self.receiver_context[-1] is not None:
                return self.receiver_context[-1][1]
            return self.owner(analyzer, analyzer.function) + ":self"
        value = analyzer.value(receiver, frame)
        return value.identity or analyzer.path + ":" + analyzer.key(receiver)

    def initial_fields(self, analyzer: Analyzer, function: Any) -> dict[str, Value]:
        return self.fields.get(self.owner(analyzer, function), {}).copy()

    def field_identity(self, analyzer: Analyzer, name: str, frame: Frame) -> Any:
        if name in analyzer.static_fields:
            return (StorageKey.STATIC_FIELDS, self.owner(analyzer, analyzer.function))
        return self.receiver_identity(analyzer, None, frame)

    def initialize_fields(self, analyzer: Analyzer, frame: Frame) -> None:
        initial = self.initial_fields(analyzer, analyzer.function)
        receiver_fields = frame.object_fields.get(self.receiver_identity(analyzer, None, frame), {})
        unknown = receiver_fields.get(StorageKey.UNKNOWN_FIELDS)
        for name, type_name in analyzer.field_types.items():
            storage = frame.object_fields.setdefault(self.field_identity(analyzer, name, frame), {})
            if name not in storage:
                storage[name] = (
                    unknown
                    if unknown is not None and name not in analyzer.static_fields
                    else initial.get(name, Value(type_name=type_name))
                )
            if name not in frame.local_names:
                frame.values[name] = storage[name]

    def unavailable_field(self, analyzer: Analyzer, frame: Frame, node: Any) -> Value:
        node = node if node is not None else analyzer.function
        caller, call, incoming = self.field_inputs[-1] if self.field_inputs else (analyzer, None, Value())
        self.partial("receiver field inventory unavailable", caller, call=call, node=node)
        values = [
            incoming,
            *frame.object_fields.get(self.receiver_identity(analyzer, None, frame), {}).values(),
        ]
        values.extend(frame.object_fields.get(StorageKey.UNRESOLVED_FIELDS, {}).values())
        for key, fields in frame.object_fields.items():
            if isinstance(key, tuple) and key[0] is StorageKey.STATIC_FIELDS:
                values.extend(fields.values())
        return analyzer.changed(node, self.merge(values))

    def identifier(self, analyzer: Analyzer, name: str, frame: Frame, node: Any = None) -> Value | None:
        if name in frame.local_names:
            return None
        if name in analyzer.unavailable_fields:
            return self.unavailable_field(analyzer, frame, node)
        if name in analyzer.field_types:
            storage = frame.object_fields.get(self.field_identity(analyzer, name, frame), {})
            return storage.get(name, frame.values.get(name))
        if name not in frame.values and name not in frame.types:
            unknown = frame.object_fields.get(self.receiver_identity(analyzer, None, frame), {}).get(
                StorageKey.UNKNOWN_FIELDS
            )
            if unknown is not None:
                return unknown
            if (
                self.field_inputs
                and node is not None
                and not analyzer.type_reference(node)
                and analyzer.string_value(node, frame) is None
            ):
                return self.unavailable_field(analyzer, frame, node)
        return None

    def assign_identifier(self, analyzer: Analyzer, name: str, value: Value, frame: Frame) -> None:
        if name in analyzer.field_types and name not in frame.local_names:
            frame.object_fields.setdefault(self.field_identity(analyzer, name, frame), {})[name] = value
            if name in analyzer.static_fields:
                self.remember_static(self.owner(analyzer, analyzer.function), name, value)

    def remember_static(self, owner: str, name: str, value: Value) -> None:
        if value.traces:
            fields = self.fields.setdefault(owner, {})
            fields[name] = self.merge([fields.get(name, Value()), value])

    def static_owner(self, analyzer: Analyzer, base: Any, member: str, frame: Frame) -> str | None:
        value = analyzer.value(base, frame)
        declared = value.type_name or analyzer.key(base)
        for owner in self.class_owners(analyzer, declared, base):
            for source, nominal in self.class_definitions[owner]:
                if any(
                    name == member and static for name, _expr, _type, static in source.nominal_fields(nominal)
                ):
                    return owner
        return None

    def unavailable_result(
        self, analyzer: Analyzer, call: Call, receiver: Value, args: list[Value], frame: Frame
    ) -> Value:
        identity = self.receiver_identity(analyzer, call.receiver, frame)
        stored = list(frame.object_fields.get(identity, {}).values())
        declared = receiver.type_name or (analyzer.key(call.receiver) if call.receiver is not None else "")
        for owner in self.class_owners(analyzer, declared, call.node):
            stored.extend(frame.object_fields.get((StorageKey.STATIC_FIELDS, owner), {}).values())
        stored.extend(frame.object_fields.get(StorageKey.UNRESOLVED_FIELDS, {}).values())
        return analyzer.changed(call.node, _union([receiver, *args, *stored]))

    def unavailable_write(
        self, analyzer: Analyzer, call: Call, receiver: Value, args: list[Value], frame: Frame
    ) -> None:
        value = self.unavailable_result(analyzer, call, receiver, args, frame)
        if not value.traces:
            return
        identity = self.receiver_identity(analyzer, call.receiver, frame)
        fields = frame.object_fields.setdefault(identity, {})
        for name, previous in list(fields.items()):
            fields[name] = self.weak_write(analyzer, call, previous, value, value)
        fields[StorageKey.UNKNOWN_FIELDS] = value
        shared = frame.object_fields.setdefault(StorageKey.UNRESOLVED_FIELDS, {})
        shared[StorageKey.UNKNOWN_FIELDS] = self.merge(
            [shared.get(StorageKey.UNKNOWN_FIELDS, Value()), value]
        )

    def finish(self, analyzer: Analyzer, function: Any, frame: Frame) -> None:
        owner = self.owner(analyzer, function)
        fields = self.fields.setdefault(owner, {})
        for name in analyzer.field_types:
            value = frame.object_fields.get(self.field_identity(analyzer, name, frame), {}).get(
                name, frame.values.get(name, Value())
            )
            if value.traces:
                previous = fields.get(name, Value())
                fields[name] = _union([previous, value], value.category, value.type_name)

    def member(self, analyzer: Analyzer, base: Any, member: str, frame: Frame) -> Value | None:
        if analyzer.key(base) in {"this", "self"}:
            if member in analyzer.unavailable_fields:
                return self.unavailable_field(analyzer, frame, base)
            identity = self.field_identity(analyzer, member, frame)
        else:
            static = self.static_owner(analyzer, base, member, frame)
            identity = (
                (StorageKey.STATIC_FIELDS, static)
                if static is not None
                else self.receiver_identity(analyzer, base, frame)
            )
        fields = frame.object_fields.get(identity, {})
        result = fields.get(member, fields.get(StorageKey.UNKNOWN_FIELDS))
        if result is None and isinstance(identity, tuple) and identity[0] is StorageKey.STATIC_FIELDS:
            return self.fields.get(identity[1], {}).get(member)
        if (
            result is None
            and analyzer.key(base) in {"this", "self"}
            and member not in analyzer.field_types
            and self.field_inputs
        ):
            return self.unavailable_field(analyzer, frame, base)
        return result

    def assign_member(self, analyzer: Analyzer, left: Any, value: Value, frame: Frame) -> None:
        navigation = analyzer.navigation(left)
        if not navigation:
            name = analyzer.key(left)
            if name and name not in frame.local_names:
                frame.object_fields.setdefault(self.receiver_identity(analyzer, None, frame), {})[name] = (
                    value
                )
                frame.object_fields.setdefault(StorageKey.UNRESOLVED_FIELDS, {})[name] = value
                storage = frame.object_fields.setdefault(self.receiver_identity(analyzer, None, frame), {})
                storage[StorageKey.UNKNOWN_FIELDS] = self.merge(
                    [storage.get(StorageKey.UNKNOWN_FIELDS, Value()), value]
                )
                caller, call, _incoming = (
                    self.field_inputs[-1] if self.field_inputs else (analyzer, None, Value())
                )
                self.partial("receiver field inventory unavailable", caller, call=call, node=left)
            return
        base, member = navigation
        if analyzer.key(base) in {"this", "self"}:
            identity = self.field_identity(analyzer, member, frame)
            if member in analyzer.field_types and member not in frame.local_names:
                frame.values[member] = value
            if member not in analyzer.field_types:
                frame.object_fields.setdefault(StorageKey.UNRESOLVED_FIELDS, {})[member] = value
                caller, call, _incoming = (
                    self.field_inputs[-1] if self.field_inputs else (analyzer, None, Value())
                )
                self.partial("receiver field inventory unavailable", caller, call=call, node=left)
        else:
            static = self.static_owner(analyzer, base, member, frame)
            identity = (
                (StorageKey.STATIC_FIELDS, static)
                if static is not None
                else self.receiver_identity(analyzer, base, frame)
            )
        frame.object_fields.setdefault(identity, {})[member] = value
        if isinstance(identity, tuple) and identity[0] is StorageKey.STATIC_FIELDS:
            self.remember_static(identity[1], member, value)

    @staticmethod
    def enclosing(node: Any, types: set[str]) -> Any:
        parent = node.parent
        while parent is not None:
            if parent.type in types:
                return parent
            parent = parent.parent
        return None

    @staticmethod
    def scope_boundary(node: Any) -> ScopeBoundary | None:
        """Use one callable/nominal boundary, including unsupported ownership fences."""
        if node.type in FUNCTIONS:
            return ScopeBoundary("callable", node)
        if node.type in {"object_literal", "object_creation_expression", "enum_constant"}:
            if node.type == "object_literal" or any(
                child.type in NOMINAL_BODIES for child in node.named_children
            ):
                return ScopeBoundary("anonymous", node)
        if node.type in UNAVAILABLE_NOMINAL_DECLARATIONS:
            return ScopeBoundary("unavailable", node)
        if node.type in NOMINAL_DECLARATIONS:
            name = _field(node, "name") or next(
                (
                    child
                    for child in node.named_children
                    if child.type in {"identifier", "simple_identifier", "type_identifier"}
                ),
                None,
            )
            if name is None or any(child.type == "extension" for child in node.children):
                return ScopeBoundary("unavailable", node)
            return ScopeBoundary("nominal", node, name)
        if node.type in NOMINAL_BODIES:
            parent = node.parent
            boundary = NativeFlow.scope_boundary(parent) if parent is not None else None
            if boundary is None or boundary.kind != "nominal":
                return ScopeBoundary(
                    boundary.kind if boundary is not None and boundary.kind != "callable" else "unavailable",
                    parent if parent is not None else node,
                )
        return None

    @classmethod
    def enclosing_scope(cls, node: Any, *, callables: bool = False) -> ScopeBoundary | None:
        parent = node.parent
        while parent is not None:
            boundary = cls.scope_boundary(parent)
            if boundary is not None and (callables or boundary.kind != "callable"):
                return boundary
            parent = parent.parent
        return None

    @classmethod
    def lexical_function(cls, node: Any) -> bool:
        boundary = cls.enclosing_scope(node, callables=True)
        return boundary is not None and boundary.kind == "callable"

    @classmethod
    def unavailable_scope(cls, node: Any) -> ScopeBoundary | None:
        boundary = cls.enclosing_scope(node)
        while boundary is not None:
            if boundary.kind != "nominal":
                return boundary
            boundary = cls.enclosing_scope(boundary.node)
        return None

    @classmethod
    def anonymous_scope(cls, node: Any) -> Any:
        boundary = cls.unavailable_scope(node)
        return boundary.node if boundary is not None and boundary.kind == "anonymous" else None

    @staticmethod
    def imported_symbols(analyzer: Analyzer, name: str, *, classes: bool = False) -> set[str]:
        """Exact source imports only; aliases bind to their declared symbol."""
        result = set()
        for declaration in analyzer.imports:
            declaration = declaration.strip()
            if analyzer.language == "java":
                static = declaration.startswith("static ")
                if static == classes:
                    continue
                declaration = declaration.removeprefix("static ")
            elif analyzer.language == "swift":
                scoped = re.fullmatch(r"(func|class|struct|enum|protocol|typealias)\s+([\w.]+)", declaration)
                if not scoped or (scoped[1] == "func") == classes:
                    continue
                declaration = scoped[2]
            match = re.fullmatch(r"([\w.]+)(?:\s+as\s+(\w+))?", declaration)
            if match and (match[2] or match[1].rsplit(".", 1)[-1]) == name:
                result.add(match[1])
        return result

    def lexical_type(self, analyzer: Analyzer, declared: str, use: Any = None) -> Any:
        """Find source type bindings before interpreting a spelling as an import/package."""
        match = re.match(r"[A-Za-z_]\w*", declared)
        if match is None:
            return None
        root = match[0]
        use = use if use is not None else analyzer.function
        scope = use
        declarations = NOMINAL_DECLARATIONS | {
            "type_alias",
            "typealias_declaration",
            "associatedtype_declaration",
        }
        scopes = NOMINAL_BODIES | {
            "block",
            "statements",
            "function_body",
            "program",
            "source_file",
        }
        while scope is not None:
            boundary = self.scope_boundary(scope)
            if boundary is not None and boundary.kind in {"anonymous", "unavailable"}:
                return boundary.node
            key = (id(analyzer), scope.id)
            if scope.type in FUNCTIONS | declarations:
                if key not in self.type_parameter_cache:
                    names = {}
                    for parameters in scope.named_children:
                        if parameters.type != "type_parameters":
                            continue
                        for parameter in parameters.named_children:
                            name = next(
                                (
                                    child
                                    for child in parameter.named_children
                                    if child.type
                                    in {
                                        "identifier",
                                        "simple_identifier",
                                        "type_identifier",
                                    }
                                ),
                                None,
                            )
                            if name is not None:
                                names[analyzer.text(name)] = parameter
                    self.type_parameter_cache[key] = names
                if root in self.type_parameter_cache[key]:
                    return self.type_parameter_cache[key][root]
                inherited = next(
                    (child for child in scope.named_children if child.type in INHERITED_TYPE_SCOPES), None
                )
                if inherited is not None:
                    # The represented superclass/protocol may supply a member
                    # type before an enclosing/package/import binding. No
                    # complete inherited type lookup is available here.
                    return inherited
            if scope.type in scopes:
                if scope.type == "program" and analyzer.language == "java":
                    for declaration in analyzer.imports:
                        if declaration.startswith("static ") and (
                            declaration.endswith(".*") or declaration.rsplit(".", 1)[-1] == root
                        ):
                            # A static import may name a nested type. Treat it
                            # as unresolved rather than falling back to a
                            # same-package class with the same spelling.
                            return scope
                if key not in self.type_scope_cache:
                    entries = []
                    for declaration in scope.named_children:
                        if declaration.type not in declarations:
                            continue
                        name = (
                            _field(declaration, "name")
                            or (_field(declaration, "type") if declaration.type == "type_alias" else None)
                            or next(
                                (
                                    child
                                    for child in declaration.named_children
                                    if child.type
                                    in {
                                        "identifier",
                                        "simple_identifier",
                                        "type_identifier",
                                    }
                                ),
                                None,
                            )
                        )
                        if name is not None:
                            entries.append((analyzer.text(name), declaration))
                    self.type_scope_cache[key] = entries
                for name, declaration in self.type_scope_cache[key]:
                    if name != root:
                        continue
                    if (
                        scope.type in {"block", "statements", "function_body"}
                        and analyzer.language != "swift"
                        and declaration.start_byte > use.start_byte
                    ):
                        continue
                    return declaration
            scope = scope.parent
        return None

    def class_owners(self, analyzer: Analyzer, declared: str, use: Any = None) -> set[str]:
        """Class identity is package/import/file based, never globally unique by leaf."""
        binding = self.lexical_type(analyzer, declared, use)
        if binding is not None:
            # Same-file top-level nominal declarations (including qualified
            # named nested types) are source identities. Local/member aliases,
            # classes and type parameters are deliberately unresolved here.
            if (
                binding.type not in NOMINAL_DECLARATIONS
                or binding.parent is None
                or binding.parent.type not in {"program", "source_file"}
            ):
                return set()
            name = _field(binding, "name")
            if name is None:
                return set()
            owner = self.owner(analyzer, name)
            imported = self.imported_symbols(analyzer, declared.partition(".")[0], classes=True)
            if imported and imported != {owner}:
                return set()
            suffix = declared.partition(".")[2]
            reference = owner + ("." + suffix if suffix else "")
            return {reference} if self.class_definitions.get(reference) else set()
        root, _, remainder = declared.partition(".")
        imported = self.imported_symbols(analyzer, root, classes=True)
        references = {symbol + ("." + remainder if remainder else "") for symbol in imported}
        if not imported:
            namespace = self.namespaces[id(analyzer)]
            if "." in declared or not namespace or analyzer.language == "swift":
                references.add(declared)
            if namespace and analyzer.language in {"java", "kotlin"}:
                references.add(namespace + "." + declared)
            for declaration in analyzer.imports:
                if declaration.endswith(".*") and not declaration.startswith("static "):
                    references.add(declaration[:-1] + declared)
        owners = set()
        for owner in references:
            definitions = self.class_definitions.get(owner, [])
            if any(
                source.language == analyzer.language
                and (analyzer.language != "swift" or source.path == analyzer.path)
                and (
                    not self.namespaces[id(analyzer)]
                    or self.namespaces[id(source)]
                    or source.path == analyzer.path
                )
                and (
                    analyzer.language != "kotlin"
                    or self.namespaces[id(source)]
                    or source.path == analyzer.path
                    or bool(imported)
                )
                for source, _ in definitions
            ):
                owners.add(owner)
        return owners

    def constructor_type(self, analyzer: Analyzer, call: Call, frame: Frame) -> str | None:
        if self.value_binding(analyzer, call, frame) is not None:
            return None
        name = call.name
        if call.receiver is not None:
            namespace = analyzer.key(call.receiver)
            if (
                namespace in frame.values
                or namespace in analyzer.parameter_types
                or namespace in analyzer.field_types
            ):
                return None
            name = namespace + "." + name
        leaf = name.rsplit(".", 1)[-1]
        if call.node.type == "object_creation_expression" or (
            leaf[:1].isupper()
            and (
                self.class_name_present(analyzer, leaf)
                or self.imported_symbols(analyzer, leaf, classes=True)
                or self.lexical_type(analyzer, name, call.node) is not None
            )
        ):
            # Preserve the original source root for lexical checks; only the
            # identity lookup may expand an import after that check succeeds.
            return name
        return None

    def class_name_present(self, analyzer: Analyzer, name: str) -> bool:
        """A class from another source language supplies no constructor identity."""
        return any(
            source.language == analyzer.language
            for owner in self.classes.get(name, set())
            for source, _node in self.class_definitions.get(owner, [])
        )

    @staticmethod
    def value_binding(analyzer: Analyzer, call: Call, frame: Frame) -> Value | None:
        """A current lexical value binds an unqualified callee before a member/type name."""
        if (
            analyzer.language not in {"kotlin", "swift"}
            or call.receiver is not None
            or not (
                call.name in frame.values
                or call.name in analyzer.parameter_types
                or call.name in analyzer.field_types
            )
        ):
            return None
        return frame.values.get(call.name, Value(type_name=frame.types.get(call.name, "")))

    def lexical_visible(self, analyzer: Analyzer, target: Callable, call: Call) -> bool:
        if target.analyzer.language == "kotlin":
            name = _field(target.node, "name")
            if name is not None and any(
                child.type == "." for child in target.node.children if child.end_byte <= name.start_byte
            ):
                # An extension receiver is not an ordinary top-level argument.
                return False
        parent = self.enclosing(target.node, FUNCTIONS) if self.lexical_function(target.node) else None
        if parent is not None:
            if target.analyzer.path != analyzer.path:
                return False
            current = analyzer.function
            while current is not None:
                if current.id == parent.id:
                    break
                current = self.enclosing(current, FUNCTIONS)
            else:
                return False
            # A function-local declaration belongs to its declaration block,
            # not every block of the enclosing function or class.
            scope = self.enclosing(target.node, {"block", "statements", "function_body"})
            current = call.node
            while current is not None and current != scope:
                current = current.parent
            if scope is None or current is None or target.node.start_byte > call.node.start_byte:
                return False
        if target.analyzer.path != analyzer.path and re.search(
            r"\b(?:private|fileprivate)\b", target.analyzer.text(target.node).split("{", 1)[0]
        ):
            return False
        return True

    def modeled_external(
        self,
        analyzer: Analyzer,
        declared: str,
        call: Call,
        *,
        constructor: bool = False,
        receiver: Value | None = None,
    ) -> bool:
        if self.lexical_type(analyzer, declared, call.node) is not None:
            return False
        if self.class_owners(analyzer, declared, call.node):
            return False
        root, _, remainder = declared.partition(".")
        imported = self.imported_symbols(analyzer, root, classes=True)
        identities = {symbol + ("." + remainder if remainder else "") for symbol in imported}
        if not imported and "." in declared:
            identities.add(declared)
        if len(identities) != 1:
            return False
        identity = next(iter(identities))
        if (
            not constructor
            and identity in {"java.io.File", "java.nio.file.Path"}
            and receiver is not None
            and receiver.category in {"canonical-path", "text"}
            and call.name in {"startsWith", "endsWith", "contains"}
        ):
            # Canonical path strings retain the originating File/Path type.
            return True
        return (
            identity in MODELED_EXTERNAL_CONSTRUCTORS
            if constructor
            else call.name in MODELED_EXTERNAL_METHODS.get(identity, set())
        )

    def implicit_constructor(self, analyzer: Analyzer, declared: str, call: Call) -> bool:
        """A unique source class with no declared constructor permits a no-arg allocation."""
        owners = self.class_owners(analyzer, declared, call.node)
        if call.args or analyzer.language not in {"java", "kotlin"} or len(owners) != 1:
            return False
        owner = next(iter(owners))
        definitions = self.class_definitions[owner]
        if len(definitions) != 1 or any(
            target.owner == owner and target.node.type == "constructor_declaration"
            for targets in self.by_name.values()
            for target in targets
        ):
            return False
        _source, node = definitions[0]
        if analyzer.language == "java" and node.type != "class_declaration":
            return False
        primary = next((child for child in node.named_children if child.type == "primary_constructor"), None)
        return primary is None or not any(
            child.named_children for child in primary.named_children if child.type == "class_parameters"
        )

    @staticmethod
    def declaration_tokens(node: Any) -> set[str]:
        """Read declaration keywords from AST tokens, excluding bodies/comments."""
        name = _field(node, "name")
        pending = [child for child in node.children if name is not None and child.end_byte <= name.start_byte]
        tokens = set()
        while pending:
            child = pending.pop()
            if not child.children:
                tokens.add(child.type)
            pending.extend(child.children)
        return tokens

    def closed_dispatch(self, target: Callable) -> bool:
        if self.unavailable_scope(target.node) is not None:
            return False
        if target.node.type == "constructor_declaration" or self.lexical_function(target.node):
            return True
        if not target.owner and target.analyzer.language != "java":
            return True
        modifiers = self.declaration_tokens(target.node)
        if modifiers & {"private", "final", "static"}:
            return True
        boundary = self.enclosing_scope(target.node)
        if boundary is not None and boundary.kind != "nominal":
            return False
        owner = boundary.node if boundary is not None else None
        owner_tokens = self.declaration_tokens(owner) if owner is not None else set()
        if "final" in owner_tokens:
            return True
        if target.analyzer.language == "kotlin":
            if owner is not None and owner.type == "object_declaration":
                return True
            if "class" in owner_tokens and not owner_tokens & {"open", "abstract", "sealed"}:
                return True
            return not bool(modifiers & {"open", "override", "abstract"} or "interface" in owner_tokens)
        if target.analyzer.language == "swift":
            return bool(owner_tokens & {"struct", "enum", "actor"})
        return False

    def allocation(self, analyzer: Analyzer, call: Call, declared: str, identity: str) -> None:
        # A non-anonymous Java `new` proves the concrete nominal type. Other forms
        # retain field identity but do not establish exact dispatch here.
        if analyzer.language == "java" and call.node.type == "object_creation_expression":
            if any(child.type == "class_body" for child in call.node.named_children):
                self.allocations.pop(identity, None)
                self.partial("anonymous allocation dispatch unresolved", analyzer, call=call)
                return
            owners = self.class_owners(analyzer, declared, call.node)
            if len(owners) == 1:
                owner = next(iter(owners))
                if len(self.class_definitions[owner]) == 1:
                    self.allocations[identity] = owner

    def concrete_receiver(self, analyzer: Analyzer, call: Call, receiver: Value) -> tuple[str, str] | None:
        if call.receiver is None or analyzer.key(call.receiver) in {"this", "self"}:
            return self.receiver_context[-1] if self.receiver_context else None
        owner = self.allocations.get(receiver.identity)
        return (owner, receiver.identity) if owner else None

    def weak_write(
        self, analyzer: Analyzer, call: Call, previous: Value, written: Value, unknown: Value
    ) -> Value:
        value = self.merge([previous, written, unknown])
        # Dispatch uncertainty invalidates value/identity safety, not a known
        # field's nominal type needed to recognize subsequent sinks.
        return analyzer.changed(
            call.node, Value(value.traces, type_name=previous.type_name or written.type_name)
        )

    def type_member(self, target: Callable) -> bool:
        """Only source-declared static/class/object members permit type receivers."""
        if self.unavailable_scope(target.node) is not None:
            return False
        if target.analyzer.language == "kotlin":
            boundary = self.enclosing_scope(target.node)
            return (
                boundary is not None
                and boundary.kind == "nominal"
                and boundary.node.type == "object_declaration"
            )
        name = _field(target.node, "name")
        if name is None:
            return False
        pending = [child for child in target.node.children if child.end_byte <= name.start_byte]
        while pending:
            node = pending.pop()
            if node.type in {"static", "class"}:
                return True
            pending.extend(node.children)
        return False

    @staticmethod
    def signature_visible(analyzer: Analyzer, target: Callable, call: Call) -> bool:
        if len(target.parameters) != len(call.args):
            return False
        if target.analyzer.language == "swift":
            for (name, _type, parameter), argument in zip(target.parameters, call.args, strict=True):
                external = _field(parameter, "external_name")
                label = target.analyzer.text(external) if external is not None else name
                actual = _field(argument.parent, "name") if argument.parent is not None else None
                actual_label = analyzer.text(actual) if actual is not None else ""
                if ("" if label == "_" else label) != actual_label:
                    return False
        return True

    def signature_type(self, analyzer: Analyzer, declared: str, use: Any) -> tuple | None:
        """A bounded nominal or identical lexical binding, without assignability guesses."""
        declared = declared.strip()
        if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", declared):
            return None
        binding = self.lexical_type(analyzer, declared, use)
        if binding is not None:
            # An inherited type can be unavailable nominally yet both
            # declarations can refer to the identical lexical binding. A
            # caller's method type parameter/local type is a different node.
            return ("lexical", analyzer.path, binding.id, declared)
        owners = self.class_owners(analyzer, declared, use)
        if len(owners) == 1:
            return ("nominal", next(iter(owners)))
        root, _, remainder = declared.partition(".")
        imported = self.imported_symbols(analyzer, root, classes=True)
        if len(imported) == 1:
            return ("nominal", next(iter(imported)) + ("." + remainder if remainder else ""))
        if analyzer.language == "java" and declared in {
            "boolean",
            "byte",
            "char",
            "short",
            "int",
            "long",
            "float",
            "double",
        }:
            return ("primitive", declared)
        if declared == "String" and analyzer.language in SCALAR_STRING_TYPES:
            return ("nominal", SCALAR_STRING_TYPES[analyzer.language])
        # With no lexical/import/inheritance binding difference, equal type
        # spellings in this source share its unresolved external lookup scope.
        # This supplies no identity across Swift files or unrelated packages.
        return ("file-type", analyzer.language, analyzer.path, declared)

    def argument_signature_type(
        self, analyzer: Analyzer, argument: Any, value: Value, frame: Frame
    ) -> tuple | None:
        actual_type = frame.types.get(analyzer.key(argument), value.type_name)
        if actual_type:
            return self.signature_type(analyzer, actual_type, argument)
        node = analyzer.unwrap(argument)
        call = analyzer.call(node)
        if analyzer.language in SCALAR_STRING_TYPES and (
            node.type in {"string_literal", "line_string_literal", "multi_line_string_literal"}
            or (
                call is not None
                and call.name in {"getDataString", "getStringExtra", "getQueryParameter"}
                and value.category == "text"
            )
        ):
            # These existing Analyzer input models/literals produce a scalar
            # String. Unknown helper results have category unknown and cannot
            # borrow this evidence from their tainted arguments.
            return ("nominal", SCALAR_STRING_TYPES[analyzer.language])
        return None

    def summary_signature_reason(
        self, analyzer: Analyzer, target: Callable, call: Call, args: list[Value], frame: Frame
    ) -> str | None:
        if self.unavailable_scope(target.node) is not None:
            return "nominal callable scope unavailable"
        lexical = self.lexical_function(target.node)
        inherited = False
        if not lexical and target.node.type != "constructor_declaration":
            for context in (call.node, target.node):
                current = context
                while current is not None:
                    if any(child.type in INHERITED_TYPE_SCOPES for child in current.named_children):
                        inherited = True
                        break
                    current = current.parent
        for (_name, expected_type, parameter), argument, value in zip(
            target.parameters, call.args, args, strict=True
        ):
            actual = self.argument_signature_type(analyzer, argument, value, frame)
            expected = self.signature_type(target.analyzer, expected_type, parameter)
            if (inherited or lexical) and (actual is None or expected is None or actual != expected):
                return (
                    "inherited overload signature unresolved"
                    if inherited
                    else "lexical overload signature unresolved"
                )
            if (
                actual is not None
                and expected is not None
                and actual[0] != "file-type"
                and expected[0] != "file-type"
                and actual != expected
            ):
                # Assignability/overload priority is unavailable for different
                # bindings. An arity match cannot justify a sanitizer summary.
                return "callable argument type identity unresolved"
        return None

    def resolve(
        self, analyzer: Analyzer, call: Call, receiver: Value, frame: Frame
    ) -> tuple[list[Callable], bool]:
        if self.value_binding(analyzer, call, frame) is not None:
            return [], True
        imported = self.imported_symbols(analyzer, call.name)
        names = {call.name, *(symbol.rsplit(".", 1)[-1] for symbol in imported)}
        constructor_type = self.constructor_type(analyzer, call, frame)
        if constructor_type is not None:
            names.add(constructor_type.rsplit(".", 1)[-1])
        named_choices = [
            target
            for name in names
            for target in self.by_name.get(name, [])
            if target.analyzer.language == analyzer.language
        ]
        choices = [
            target
            for target in named_choices
            if self.signature_visible(analyzer, target, call) and self.lexical_visible(analyzer, target, call)
        ]
        if constructor_type is not None:
            if self.modeled_external(analyzer, constructor_type, call, constructor=True):
                return [], False
            owners = self.class_owners(analyzer, constructor_type, call.node)
            if any(len(self.class_definitions[owner]) > 1 for owner in owners):
                self.partial("ambiguous class identity", analyzer, call=call)
                return [], True
            constructors = [
                target
                for target in choices
                if target.node.type == "constructor_declaration" and target.owner in owners
            ]
            return constructors, bool(
                named_choices
                or owners
                or self.class_name_present(analyzer, constructor_type.rsplit(".", 1)[-1])
                or self.imported_symbols(analyzer, call.name, classes=True)
                or self.lexical_type(analyzer, constructor_type, call.node) is not None
            )
        owner = self.owner(analyzer, analyzer.function)
        receiver_key = analyzer.key(call.receiver) if call.receiver is not None else ""
        if call.receiver is None or receiver_key in {"this", "self"}:
            local = [
                target
                for target in choices
                if target.owner == owner
                and target.analyzer.path == analyzer.path
                and self.enclosing_scope(target.node) == self.enclosing_scope(analyzer.function)
            ]
            # Top-level imports must be checked before a same-file top-level match.
            if local and (owner or not imported):
                return local, True
            if receiver_key in {"this", "self"}:
                return [], bool(named_choices)
            visible = []
            for target in choices:
                if imported:
                    if analyzer.language == "swift":
                        # Source inputs do not include the compiler's Swift module membership.
                        continue
                    identity = (target.owner or self.namespaces[id(target.analyzer)]) + "." + target.name
                    if identity in imported and (not target.owner or self.type_member(target)):
                        visible.append(target)
                elif not target.owner and not self.lexical_function(target.node):
                    if (
                        analyzer.language == "kotlin"
                        and bool(self.namespaces[id(analyzer)])
                        and self.namespaces[id(target.analyzer)] == self.namespaces[id(analyzer)]
                    ):
                        visible.append(target)
                    elif target.analyzer.path == analyzer.path:
                        visible.append(target)
                    elif (
                        analyzer.language == "kotlin"
                        and self.namespaces[id(target.analyzer)] + ".*" in analyzer.imports
                    ):
                        visible.append(target)
            if any(
                target.owner and len(self.class_definitions.get(target.owner, [])) > 1 for target in visible
            ):
                self.partial("ambiguous class identity", analyzer, call=call)
                return [], True
            return visible, bool(named_choices or imported)
        # A fully qualified Kotlin package call is source evidence of top-level identity.
        if (
            analyzer.language == "kotlin"
            and not receiver.type_name
            and not receiver.identity
            and receiver_key not in frame.values
            and receiver_key not in analyzer.parameter_types
            and receiver_key not in analyzer.field_types
            and self.lexical_type(analyzer, receiver_key, call.node) is None
        ):
            top_level = [
                target
                for target in choices
                if not target.owner
                and not self.lexical_function(target.node)
                and self.namespaces[id(target.analyzer)] == receiver_key
            ]
            if top_level:
                return top_level, True
        declared = re.sub(r"[?!<>].*", "", receiver.type_name).strip() or receiver_key
        source_receiver = analyzer.unwrap(call.receiver) if call.receiver is not None else None
        receiver_call = analyzer.call(source_receiver) if source_receiver is not None else None
        if receiver_call is not None and receiver_call.node.type == "object_creation_expression":
            # The direct `new java.io.File(...)` spelling remains qualified
            # even though Analyzer's path value uses the simple File type.
            declared = receiver_call.name
        if self.modeled_external(analyzer, declared, call, receiver=receiver):
            return [], False
        owners = self.class_owners(analyzer, declared, call.node)
        if any(len(self.class_definitions[identity]) > 1 for identity in owners):
            self.partial("ambiguous class identity", analyzer, call=call)
            return [], True
        resolved = [target for target in choices if target.owner in owners]
        if (
            analyzer.type_reference(call.receiver)
            and receiver_key not in frame.values
            and not receiver.identity
        ):
            resolved = [target for target in resolved if self.type_member(target)]
        imported_class = self.imported_symbols(analyzer, declared.partition(".")[0], classes=True)
        namespace = bool(
            "." in receiver_key
            and re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", receiver_key)
            and receiver_key.partition(".")[0] not in frame.values
            and receiver_key.partition(".")[0] not in analyzer.parameter_types
            and receiver_key.partition(".")[0] not in analyzer.field_types
        )
        # A compatible signature without receiver identity remains uncertain;
        # a same-name declaration with a different signature is irrelevant.
        # Neither case permits a global leaf-name target match.
        binding = self.lexical_type(analyzer, declared, call.node)
        return resolved, bool(
            choices
            or owners
            or imported_class
            or namespace
            or binding is not None
            and (
                binding.type not in INHERITED_TYPE_SCOPES
                or analyzer.type_reference(call.receiver)
                and receiver_key not in frame.values
                and receiver_key not in analyzer.parameter_types
                and receiver_key not in analyzer.field_types
            )
        )

    @staticmethod
    def signature(value: Value) -> tuple:
        return (
            tuple((trace.origin, trace.path_safe, trace.path_route) for trace in value.traces),
            value.category,
            value.type_name,
            value.identity,
        )

    @staticmethod
    def merge(values: list[Value]) -> Value:
        categories = {value.category for value in values}
        types = {value.type_name for value in values}
        return _union(
            values,
            categories.pop() if len(categories) == 1 else "unknown",
            types.pop() if len(types) == 1 else "",
        )

    @staticmethod
    def incomplete(value: Value) -> Value:
        return Value(
            tuple(
                Trace(
                    trace.origin,
                    trace.source,
                    trace.description + TRACE_PARTIAL,
                    trace.steps,
                    False,
                    trace.path_route,
                )
                for trace in value.traces
            ),
            value.category,
            value.type_name,
            value.identity,
        )

    def call(
        self, analyzer: Analyzer, call: Call, frame: Frame, receiver: Value, args: list[Value]
    ) -> Value | None:
        if any(TRACE_PARTIAL in trace.description for value in [receiver, *args] for trace in value.traces):
            self.partial("source trace budget", analyzer, call=call)
        binding = self.value_binding(analyzer, call, frame)
        if binding is not None:
            if (
                analyzer.language == "swift"
                and analyzer.scope == "webView"
                and any("WKNavigationAction" in kind for kind in analyzer.parameter_types.values())
                and "WKNavigationActionPolicy" in analyzer.parameter_types.get(call.name, "")
                and len(call.args) == 1
                and analyzer.text(call.args[0]).strip() in {".allow", ".cancel"}
            ):
                # Analyzer already models this typed WebKit policy callback;
                # its lexical binding still must not resolve to a helper body.
                return None
            self.partial("callable value binding unresolved", analyzer, call=call)
            return analyzer.changed(call.node, _union([binding, *args]))
        targets, relevant = self.resolve(analyzer, call, receiver, frame)
        admitted = []
        for target in targets:
            reason = self.summary_signature_reason(analyzer, target, call, args, frame)
            if reason is None:
                admitted.append(target)
            else:
                self.partial(reason, analyzer, call=call)
                relevant = True
        targets = admitted
        if not relevant:
            constructor_type = self.constructor_type(analyzer, call, frame)
            if constructor_type is not None and self.modeled_external(
                analyzer, constructor_type, call, constructor=True
            ):
                return None
            # A source-identified constructor supplies allocation identity, never a global leaf match.
            if constructor_type is not None and self.class_owners(analyzer, constructor_type, call.node):
                identity = f"{analyzer.path}:{call.node.start_byte}"
                self.allocation(analyzer, call, constructor_type, identity)
                if args:
                    self.partial("constructor field mapping unavailable", analyzer, call=call)
                    unknown = self.incomplete(analyzer.changed(call.node, _union(args)))
                    frame.object_fields[identity] = {StorageKey.UNKNOWN_FIELDS: unknown}
                    return Value(unknown.traces, type_name=constructor_type, identity=identity)
                return Value(type_name=constructor_type, identity=identity)
            if (
                call.node.type == "object_creation_expression"
                and any(argument.traces for argument in args)
                and call.name not in {*FILE_SINKS, "Intent", "URI", "URL", "WebView"}
            ):
                # Java's `new` establishes allocation syntax even when the
                # source inventory contains no definition at all. Keep its
                # unknown field provenance independent of unrelated classes.
                self.partial("constructor field mapping unavailable", analyzer, call=call)
                identity = f"{analyzer.path}:{call.node.start_byte}"
                unknown = self.incomplete(analyzer.changed(call.node, _union(args)))
                frame.object_fields[identity] = {StorageKey.UNKNOWN_FIELDS: unknown}
                return Value(unknown.traces, type_name=constructor_type or call.name, identity=identity)
            if (
                any(argument.traces for argument in args)
                and call.receiver is None
                and call.name[:1].islower()
                and not (
                    analyzer.language in {"java", "kotlin"}
                    and call.name in INTENT_LAUNCHERS
                    and args
                    and args[0].category in {"intent", "nested-intent"}
                )
            ):
                self.partial("unresolved callable identity", analyzer, call=call)
            return None
        if not targets:
            if (
                receiver.category == "intent"
                and call.name
                in {"getData", "getDataString", "getStringExtra", "getCharSequenceExtra", "getExtras"}
                or receiver.category in {"intent", "bundle"}
                and call.name in NESTED_INTENT_GETTERS
                or analyzer.key(call.receiver) in {"IntentCompat", "BundleCompat"}
                and call.name in NESTED_INTENT_GETTERS
                and args
                and args[0].category in {"intent", "bundle"}
                or receiver.traces
                and call.name in {"getQueryParameter", "getQueryParameters"}
                or receiver.category in {"request", "navigation"}
                and call.name in {"getUrl", "getURL"}
            ):
                # Unavailable type identity must not erase Analyzer's existing
                # conservative platform input provenance. These models add or
                # retain taint; they transfer no sanitizer or guard assertion.
                self.partial("source receiver type identity unresolved", analyzer, call=call)
                return None
            constructor_type = self.constructor_type(analyzer, call, frame)
            if constructor_type is not None:
                if self.implicit_constructor(analyzer, constructor_type, call):
                    identity = f"{analyzer.path}:{call.node.start_byte}"
                    self.allocation(analyzer, call, constructor_type, identity)
                    return Value(type_name=constructor_type, identity=identity)
                self.partial("constructor field mapping unavailable", analyzer, call=call)
                identity = f"{analyzer.path}:{call.node.start_byte}"
                self.allocation(analyzer, call, constructor_type, identity)
                unknown = self.incomplete(analyzer.changed(call.node, _union([receiver, *args])))
                frame.object_fields[identity] = {StorageKey.UNKNOWN_FIELDS: unknown}
                return Value(unknown.traces, type_name=constructor_type, identity=identity)
            self.partial("unresolved callable identity or argument signature", analyzer, call=call)
            self.unavailable_write(analyzer, call, receiver, args, frame)
            return self.unavailable_result(analyzer, call, receiver, args, frame)
        if len(targets) > 1:
            self.partial("ambiguous direct call", analyzer, call=call)
        constructor = all(target.node.type == "constructor_declaration" for target in targets)
        identity = (
            f"{analyzer.path}:{call.node.start_byte}"
            if constructor
            else self.receiver_identity(analyzer, call.receiver, frame)
        )
        if constructor:
            self.allocation(
                analyzer, call, self.constructor_type(analyzer, call, frame) or call.name, identity
            )
            concrete = (self.allocations[identity], identity) if identity in self.allocations else None
        else:
            concrete = self.concrete_receiver(analyzer, call, receiver)
        dynamic = any(
            not self.closed_dispatch(target) and (concrete is None or concrete[0] != target.owner)
            for target in targets
        )
        if dynamic:
            self.partial("receiver runtime dispatch unresolved", analyzer, call=call)
        local_receiver = (call.receiver is None or analyzer.key(call.receiver) in {"this", "self"}) and all(
            target.owner == self.owner(analyzer, analyzer.function) for target in targets
        )
        affected = {identity, *(argument.identity for argument in args if argument.identity)}
        if local_receiver:
            affected.update(
                value.identity
                for name in analyzer.field_types
                if (value := frame.values.get(name, Value())).identity
            )
        prior_objects = {key: fields.copy() for key, fields in frame.object_fields.items()}
        uncertain_values = [receiver, *args]
        if local_receiver:
            uncertain_values.extend(frame.values.get(name, Value()) for name in analyzer.field_types)
        for object_identity in affected:
            uncertain_values.extend(prior_objects.get(object_identity, {}).values())
        unknown_write = analyzer.changed(call.node, _union(uncertain_values))
        state = tuple(
            sorted(
                (
                    (name, self.signature(value))
                    for name, value in frame.object_fields.get(identity, {}).items()
                ),
                key=repr,
            )
        )
        shared_state = tuple(
            sorted(
                (
                    (key, name, self.signature(value))
                    for key, fields in frame.object_fields.items()
                    if key is StorageKey.UNRESOLVED_FIELDS
                    or isinstance(key, tuple)
                    and key[0] is StorageKey.STATIC_FIELDS
                    for name, value in fields.items()
                ),
                key=repr,
            )
        )
        guards = tuple(
            sorted(
                ((origin, tuple(sorted(checks))) for origin, checks in self.active_guards.items()),
                key=lambda item: repr(item[0]),
            )
        )
        cache_key = (
            call.node.start_byte,
            tuple(self.signature(value) for value in [receiver, *args]),
            state,
            shared_state,
            guards,
            concrete,
        )
        if cache_key in frame.call_results:
            return frame.call_results[cache_key]
        results = []
        writes = []
        for target in targets[:8]:
            if (
                target.key in self.stack
                or len(self.stack) >= MAX_CALL_DEPTH
                or self.evaluations >= MAX_CALL_EVALUATIONS
            ):
                self.partial("recursion or call evaluation budget", analyzer, call=call)
                self.unavailable_write(analyzer, call, receiver, args, frame)
                results.append(self.unavailable_result(analyzer, call, receiver, args, frame))
                continue
            if target.body is None:
                self.partial("callable body unavailable", analyzer, call=call)
                self.unavailable_write(analyzer, call, receiver, args, frame)
                results.append(self.unavailable_result(analyzer, call, receiver, args, frame))
                continue
            callee = target.analyzer
            saved = {name: getattr(callee, name) for name in CONTEXT}
            saved_guards = self.active_guards
            saved_conditions = self.active_conditions
            self.stack.append(target.key)
            context = concrete
            if "static" in self.declaration_tokens(target.node) or (
                not target.owner and not self.lexical_function(target.node)
            ):
                context = None
            self.receiver_context.append(context)
            self.receiver_field_context.append(
                None if self.declaration_tokens(target.node) & {"static", "class"} else identity
            )
            self.field_inputs.append((analyzer, call, unknown_write))
            self.call_sites.append(f"{analyzer.path}:{call.node.start_byte}")
            self.evaluations += 1
            try:
                local = callee.start_function(target.node)
                local.object_fields = {key: fields.copy() for key, fields in frame.object_fields.items()}
                if self.lexical_function(target.node) and callee is analyzer:
                    # The lexical ancestor check above proves these captures are
                    # caller-local values, not similarly named values in another file.
                    local.values.update(frame.values)
                    local.types.update(frame.types)
                    local.constants.update(frame.constants)
                    local.local_names.update(frame.local_names)
                # Populate from the actual receiver, retaining the unknown-field
                # sentinel and explicit field overrides. Parameters remain
                # separate from `this`/`self` even when names coincide.
                self.initialize_fields(callee, local)
                for (name, type_name, parameter), argument in zip(target.parameters, args, strict=True):
                    bound = argument.bind(analyzer.point(call.node)).bind(callee.point(parameter))
                    local.values[name] = Value(
                        bound.traces, bound.category, type_name or bound.type_name, bound.identity
                    )
                # Ambiguous calls must never transfer a safety assertion.
                inherited = (
                    {origin: checks.copy() for origin, checks in saved_guards.items()}
                    if len(targets) == 1 and not dynamic
                    else {}
                )
                self.active_guards = inherited
                self.active_conditions = []
                callee.visit(target.body, local, inherited, [])
                callee.finish_paths()
                outer_unsafe = saved["unguarded_paths"] if callee is analyzer else analyzer.unguarded_paths
                outer_safe = saved["guarded_paths"] if callee is analyzer else analyzer.guarded_paths
                outer_unsafe.update(callee.unguarded_paths)
                if not saved_conditions and len(targets) == 1 and not dynamic and not self.reasons:
                    outer_safe.update(callee.guarded_paths)
                returned = self.merge(callee.return_values)
                if (
                    not callee.return_values
                    and target.analyzer.language == "kotlin"
                    and re.search(r"\)\s*(?::[^=\n]+)?=", callee.text(target.node))
                ):
                    returned = callee.value(target.body.named_children[-1], local)
                if not callee.return_values and not constructor:
                    statements = target.body.named_children
                    if len(statements) == 1 and statements[0].type in {"block", "statements"}:
                        statements = statements[0].named_children
                    if (
                        callee.language == "swift"
                        and len(statements) == 1
                        and statements[0].type == "call_expression"
                    ):
                        returned = callee.value(statements[0], local)
                    elif (
                        callee.language == "java"
                        and not re.search(r"\bvoid\b", callee.text(target.node).split("{", 1)[0])
                        or callee.language == "swift"
                        and re.search(r"->\s*(?!Void\b)", callee.text(target.node).split("{", 1)[0])
                        or callee.language == "kotlin"
                        and not re.search(r"\)\s*(?::[^=\n]+)?=", callee.text(target.node))
                        and re.search(r"\)\s*:\s*(?!Unit\b)", callee.text(target.node).split("{", 1)[0])
                    ):
                        self.partial("return flow unavailable", analyzer, call=call)
                        returned = analyzer.changed(call.node, _union([receiver, *args]))
                results.append(returned.bind(analyzer.point(call.node)))
                if returned.category in {"path", "canonical-path"} and len(targets) == 1 and not dynamic:
                    returned_origins = {(trace.origin, trace.path_route) for trace in returned.traces}
                    pending = saved["pending_paths"] if callee is analyzer else analyzer.pending_paths
                    for item in callee.findings:
                        if item["rule_id"] != "AST-PATH-TRAVERSAL":
                            continue
                        for evidence in item["evidence"]:
                            origins = set(evidence.get("modeled_routes", []))
                            if (
                                evidence.get("path_operation") == "construction"
                                and origins
                                and origins <= returned_origins
                            ):
                                pending.append((callee, item["id"], origins))
                    pending.extend(
                        (owner, identity, origins)
                        for owner, identity, origins in callee.pending_paths
                        if origins <= returned_origins
                    )
                writes.append(local.object_fields.get(identity, {}).copy())
                if dynamic:
                    for object_identity, fields in local.object_fields.items():
                        previous = prior_objects.get(object_identity, {})
                        if fields != previous or object_identity in affected:
                            frame.object_fields[object_identity] = {
                                name: self.weak_write(
                                    analyzer,
                                    call,
                                    previous.get(name, Value()),
                                    fields.get(name, Value()),
                                    unknown_write,
                                )
                                for name in set(previous) | set(fields) | {StorageKey.UNKNOWN_FIELDS}
                            }
                        else:
                            frame.object_fields[object_identity] = fields
                else:
                    frame.object_fields.update(local.object_fields)
            finally:
                self.stack.pop()
                self.receiver_context.pop()
                self.receiver_field_context.pop()
                self.field_inputs.pop()
                self.call_sites.pop()
                self.active_guards = saved_guards
                self.active_conditions = saved_conditions
                for name, value in saved.items():
                    setattr(callee, name, value)
        if len(targets) > 8:
            self.partial("ambiguous target budget", analyzer, call=call)
            results.append(analyzer.changed(call.node, _union([receiver, *args])))
        merged = {
            name: self.merge([write.get(name, Value()) for write in writes])
            for name in set().union(*(write.keys() for write in writes))
        }
        if dynamic:
            previous = prior_objects.get(identity, {})
            if local_receiver:
                previous = {
                    **previous,
                    **{name: frame.values.get(name, Value()) for name in analyzer.field_types},
                }
            merged = {
                name: self.weak_write(
                    analyzer, call, previous.get(name, Value()), merged.get(name, Value()), unknown_write
                )
                for name in set(previous) | set(merged) | {StorageKey.UNKNOWN_FIELDS}
            }
        frame.object_fields[identity] = merged
        if not constructor and local_receiver:
            frame.values.update(
                {
                    name: value
                    for name, value in merged.items()
                    if isinstance(name, str)
                    and name in analyzer.field_types
                    and name not in frame.local_names
                }
            )
        result = (
            Value(type_name=targets[0].owner if len(targets) == 1 else call.name, identity=identity)
            if constructor
            else self.merge(results)
        )
        if len(targets) != 1 or dynamic:
            result = analyzer.changed(call.node, _union([result, receiver, *args, unknown_write]))
        frame.call_results[cache_key] = result
        return result

    def run(self) -> None:
        previous = None
        for _round_index in range(MAX_FIELD_ROUNDS):
            for analyzer, root, nodes in self.files:
                analyzer.function_counts = {"observed": 0, "analyzed": 0, "skipped": 0, "without_body": 0}
                analyzer.analyze(root, nodes, prepared=True)
            state = tuple(
                sorted(
                    (owner, name, self.signature(value))
                    for owner, fields in self.fields.items()
                    for name, value in fields.items()
                )
            )
            if state == previous or not state:
                return
            previous = state
        self.partial("field summary fixed-point budget")

    def metadata(self) -> dict:
        return {
            "method": "bounded-direct-native-calls",
            "state": "partial" if self.reasons else "checked",
            "reasons": sorted(self.reasons),
            "partial_details": [
                {
                    "reason": reason,
                    "path": path or None,
                    "line": line or None,
                    "column": column or None,
                    "call": call or None,
                    "category": category,
                    "scope": "file-call" if call else "file" if path else "analysis",
                    "rule_ids": sorted(RULES),
                    "rule_scope": "conservative-all-native-rules",
                }
                for reason, path, line, column, call, category in sorted(self.partial_details)
            ],
            "partial_details_truncated": self.partial_details_truncated,
            "max_partial_details": MAX_PARTIAL_DETAILS,
            "evaluations": self.evaluations,
            "max_depth": MAX_CALL_DEPTH,
            "max_evaluations": MAX_CALL_EVALUATIONS,
            "max_field_rounds": MAX_FIELD_ROUNDS,
            "dynamic_dispatch": "not-modeled",
        }
