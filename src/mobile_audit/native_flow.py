"""Bounded direct native call summaries; uncertainty never supplies a sanitizer."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .source_analysis import (
    FILE_SINKS,
    FUNCTIONS,
    IDENTIFIERS,
    INTENT_LAUNCHERS,
    NESTED_INTENT_GETTERS,
    RULES,
    SQL_SINKS,
    STRINGS,
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
MAX_EFFECT_DEPTH = 8
MAX_EFFECT_OBJECTS = 128
MAX_EMPTY_BASE_DEPTH = 8
MAX_EXTENSION_TYPES = 4096


class StorageKey(Enum):
    UNKNOWN_FIELDS = "unknown-fields"
    STATIC_FIELDS = "static-fields"
    UNRESOLVED_FIELDS = "unresolved-fields"
    AGGREGATE_ELEMENT = "aggregate-element"
    AGGREGATE_COMPLETE = "aggregate-complete"


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
    "Foundation.URL",
    "Foundation.URLRequest",
    "WebKit.WKWebView",
}
MODELED_EXTERNAL_METHODS = {
    "WebKit.WKWebView": {"load", "evaluateJavaScript"},
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
        # Storage reachability survives upcasts; it confers no dispatch proof.
        self.effect_nominals: dict[str, set[str]] = {}
        self.effect_aggregates: set[str] = set()
        self.reference_aggregates: set[str] = set()
        self.scalar_aggregates: set[str] = set()
        self.uncertain_objects: set[Any] = set()
        self.call_sites: list[str] = []
        self.evaluations = 0
        self.reasons: set[str] = set()
        self.partial_details: set[tuple] = set()
        self.partial_details_truncated = False
        self.fields: dict[str, dict[str, Value]] = {}
        self.owner_cache: dict[tuple[int, int], str] = {}
        self.type_scope_cache: dict[tuple[int, int], list[tuple[str, Any]]] = {}
        self.type_parameter_cache: dict[tuple[int, int], dict[str, Any]] = {}
        self.empty_base_cache: dict[tuple[int, int, str], bool] = {}
        self.module_values: dict[str, list[tuple[Analyzer, Any]]] = {}
        self.module_type_aliases: dict[str, list[tuple[Analyzer, Any]]] = {}
        self.swift_extensions_present = False
        # Member types added by an extension are lookup uncertainty, never
        # ordinary module classes or source constructor summaries.
        self.swift_extension_types: dict[str, dict[str, Any]] = {}
        self.swift_extension_conformances: dict[str, Any] = {}
        self.swift_extension_types_exhausted = False
        self.active_guards: dict[int | tuple[int, str], set[str]] = {}
        self.active_conditions: list[Any] = []
        self.files = sorted(files, key=lambda item: item[0].path)
        count = 0
        extension_type_count = 0
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
                if (
                    analyzer.language in {"kotlin", "swift"}
                    and node.type in {"type_alias", "typealias_declaration"}
                    and node.parent is not None
                    and node.parent.type in {"program", "source_file"}
                ):
                    name = (
                        _field(node, "name")
                        or _field(node, "type")
                        or next((child for child in node.named_children if child.type in IDENTIFIERS), None)
                    )
                    if name is not None:
                        self.module_type_aliases.setdefault(analyzer.text(name), []).append((analyzer, node))
                if (
                    analyzer.language in {"kotlin", "swift"}
                    and node.type == "property_declaration"
                    and node.parent is not None
                    and node.parent.type in {"program", "source_file"}
                ):
                    for name in self.property_binding_names(analyzer, node):
                        self.module_values.setdefault(name, []).append((analyzer, node))
                if analyzer.language == "swift" and any(child.type == "extension" for child in node.children):
                    self.swift_extensions_present = True
                    target = _field(node, "name")
                    body = _field(node, "body")
                    if target is not None and body is not None:
                        owner = analyzer.text(target).strip()
                        inherited = next(
                            (child for child in node.named_children if child.type in INHERITED_TYPE_SCOPES),
                            None,
                        )
                        if inherited is not None and owner not in self.swift_extension_conformances:
                            if extension_type_count >= MAX_EXTENSION_TYPES:
                                self.swift_extension_types_exhausted = True
                                self.partial(
                                    "Swift extension member type inventory budget", analyzer, node=node
                                )
                            else:
                                extension_type_count += 1
                                self.swift_extension_conformances[owner] = inherited
                        for declaration in body.named_children:
                            if self.swift_extension_types_exhausted:
                                break
                            if declaration.type not in NOMINAL_DECLARATIONS | {
                                "type_alias",
                                "typealias_declaration",
                                "associatedtype_declaration",
                            }:
                                continue
                            name = (
                                _field(declaration, "name")
                                or (_field(declaration, "type") if declaration.type == "type_alias" else None)
                                or next(
                                    (
                                        child
                                        for child in declaration.named_children
                                        if child.type in IDENTIFIERS
                                    ),
                                    None,
                                )
                            )
                            if name is None:
                                continue
                            members = self.swift_extension_types.get(analyzer.text(name), {})
                            if owner in members:
                                continue
                            if extension_type_count >= MAX_EXTENSION_TYPES:
                                self.swift_extension_types_exhausted = True
                                self.partial(
                                    "Swift extension member type inventory budget", analyzer, node=node
                                )
                                break
                            extension_type_count += 1
                            self.swift_extension_types.setdefault(analyzer.text(name), {})[owner] = (
                                declaration
                            )
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

    def binding_identity(self, analyzer: Analyzer, node: Any, kind: str) -> str:
        """A source binding/allocation site, disjoint from user-written names."""
        scope = self.enclosing_scope(node, callables=True)
        return "@native-object:" + repr(
            (
                analyzer.path,
                scope.node.start_byte if scope is not None else None,
                kind,
                node.start_byte,
                node.end_byte,
                tuple(self.call_sites),
            )
        )

    def object_type(self, analyzer: Analyzer, declared: str, node: Any) -> str | None:
        owners = self.class_owners(analyzer, declared, node)
        if len(owners) != 1:
            return None
        definitions = self.class_definitions[next(iter(owners))]
        if len(definitions) != 1:
            return None
        source, nominal = definitions[0]
        if source.language == "swift" and not self.declaration_tokens(nominal) & {"class", "actor"}:
            return "value"
        return "reference"

    def reference_type(self, analyzer: Analyzer, declared: str, node: Any) -> bool:
        return self.object_type(analyzer, declared, node) == "reference"

    def remember_effect_type(self, analyzer: Analyzer, declared: str, node: Any, identity: str) -> None:
        if not identity:
            return
        owners = self.class_owners(analyzer, declared, node)
        if len(owners) == 1 and len(self.class_definitions[next(iter(owners))]) == 1:
            self.effect_nominals.setdefault(identity, set()).update(owners)
        if self.aggregate_type(analyzer, declared):
            self.effect_aggregates.add(identity)
            if analyzer.language != "swift":
                self.reference_aggregates.add(identity)
            elif self.scalar_aggregate_type(analyzer, declared, node):
                self.scalar_aggregates.add(identity)

    def scalar_aggregate_type(self, analyzer: Analyzer, declared: str, use: Any, depth: int = 0) -> bool:
        """Prove only copied Swift scalar contents, with lexical identity checks."""
        if analyzer.language != "swift" or depth >= MAX_EFFECT_DEPTH:
            return False
        declared = declared.strip().rstrip("?!")
        signature = self.signature_type(analyzer, declared, use)
        if signature == ("nominal", SCALAR_STRING_TYPES["swift"]):
            return True
        if signature == ("file-type", "swift", analyzer.path, declared) and declared.removeprefix(
            "Swift."
        ) in {
            "Int",
            "Int8",
            "Int16",
            "Int32",
            "Int64",
            "UInt",
            "UInt8",
            "UInt16",
            "UInt32",
            "UInt64",
            "Bool",
            "Float",
            "Double",
            "Character",
        }:
            return True
        inner = ""
        if (
            declared.startswith("[")
            and declared.endswith("]")
            or declared.startswith("(")
            and self.aggregate_type(analyzer, declared)
        ):
            inner = declared[1:-1]
        elif match := re.fullmatch(r"((?:Swift\.)?(?:Array|Dictionary|Set))\s*<(.*)>", declared):
            root = match[1]
            if (
                self.lexical_type(analyzer, root, use) is not None
                or self.class_owners(analyzer, root, use)
                or self.imported_symbols(analyzer, root.partition(".")[0], classes=True)
            ):
                return False
            inner = match[2]
        else:
            return False
        parts = []
        start = level = 0
        for index, token in enumerate(inner):
            level += token in "([<"
            level -= token in ")]>"
            if token in ",:" and level == 0:
                # Tuple labels are syntactic identifiers, not contained types.
                part = inner[start:index].strip()
                if token != ":" or not declared.startswith("("):
                    parts.append(part)
                start = index + 1
        parts.append(inner[start:].strip())
        return bool(inner) and all(
            self.scalar_aggregate_type(analyzer, part, use, depth + 1) for part in parts
        )

    @staticmethod
    def aggregate_type(analyzer: Analyzer, declared: str) -> bool:
        declared = declared.strip().rstrip("?!")
        if analyzer.language in {"java", "kotlin"}:
            return (
                declared.endswith("[]")
                or re.fullmatch(
                    r"(?:[\w.]+\.)?(?:Array|List|MutableList|Collection|MutableCollection|Set|MutableSet|Map|MutableMap)(?:<.*>)?"
                    r"|(?:Byte|Short|Int|Long|Float|Double|Boolean|Char)Array",
                    declared,
                )
                is not None
            )
        if analyzer.language != "swift":
            return False
        if declared in {"Any", "AnyObject", "Swift.Any", "Swift.AnyObject"}:
            return True
        if declared.startswith("[") and declared.endswith("]"):
            return True
        if re.match(r"(?:Swift\.)?(?:Array|Dictionary|Set)\s*<", declared):
            return True
        if declared.startswith("("):
            depth = 0
            for index, token in enumerate(declared):
                depth += token == "("
                depth -= token == ")"
                if depth == 0:
                    return index == len(declared) - 1
        return False

    def aggregate_value(self, analyzer: Analyzer, node: Any, frame: Frame) -> Value | None:
        """Keep effect-only element edges, never a tuple/collection nominal type."""
        if node.type not in {
            "tuple_expression",
            "array_literal",
            "dictionary_literal",
            "array_initializer",
            "array_creation_expression",
        }:
            return None
        if (
            node.type in {"tuple_expression", "array_literal", "dictionary_literal"}
            and analyzer.language != "swift"
        ):
            return None
        if node.type in {"array_initializer", "array_creation_expression"} and analyzer.language != "java":
            return None
        if node.type == "tuple_expression" and analyzer.unwrap(node) is not node:
            return None
        if analyzer.language == "java":
            initializer = node if node.type == "array_initializer" else _field(node, "value")
            elements = list(initializer.named_children) if initializer is not None else []
        else:
            names = {
                "tuple_expression": {"value"},
                "array_literal": {"element"},
                "dictionary_literal": {"key", "value"},
            }[node.type]
            elements = [
                child
                for index, child in enumerate(node.children)
                if node.field_name_for_child(index) in names
            ]
        identity = self.binding_identity(analyzer, node, "aggregate")
        self.effect_aggregates.add(identity)
        if analyzer.language != "swift":
            self.reference_aggregates.add(identity)
        fields = {}
        complete = len(elements) <= MAX_EFFECT_OBJECTS
        if not complete:
            self.partial("aggregate element inventory budget", analyzer, node=node)
        values = []
        for index, element in enumerate(elements):
            value = analyzer.value(element, frame)
            values.append(value)
            # The edge inventory is bounded independently of ordinary value
            # flow. Later elements still contribute their actual taint.
            if index < MAX_EFFECT_OBJECTS:
                fields[(StorageKey.AGGREGATE_ELEMENT, index)] = value
            signature = self.signature_type(analyzer, value.type_name, element)
            scalar = (
                value.category == "text"
                or element.type in STRINGS
                or signature is not None
                and (
                    signature[0] == "primitive"
                    or signature == ("nominal", SCALAR_STRING_TYPES.get(analyzer.language))
                )
                or re.fullmatch(r"(?:true|false|\d+(?:\.\d+)?)", analyzer.text(element)) is not None
            )
            if (
                not scalar
                and value.identity not in self.effect_nominals
                and value.identity not in self.effect_aggregates
            ):
                complete = False
        if complete:
            fields[StorageKey.AGGREGATE_COMPLETE] = Value()
        frame.object_fields[identity] = fields
        return Value(_union(values).traces, identity=identity)

    def materialize_object(
        self, analyzer: Analyzer, node: Any, declared: str, value: Value, kind: str, *, binding: bool = False
    ) -> Value:
        classification = self.object_type(analyzer, declared, node)
        if classification is None and not binding:
            return value
        identity = value.identity or self.binding_identity(analyzer, node, kind)
        self.remember_effect_type(analyzer, declared, node, identity)
        if classification == "value":
            # These IDs preserve possible storage relationships, never a proof
            # of Swift value-copy/inout semantics. All their effects stay weak.
            self.uncertain_objects.add(identity)
        return Value(value.traces, value.category, declared, identity)

    def parameter_value(self, analyzer: Analyzer, node: Any, declared: str) -> Value:
        return self.materialize_object(
            analyzer, node, declared, Value(type_name=declared), "parameter", binding=True
        )

    def local_value(
        self, analyzer: Analyzer, node: Any, declared: str, value: Value, frame: Frame, *, initialized: bool
    ) -> Value:
        explicit_type = bool(declared)
        declared = declared or value.type_name
        if value.identity or not declared:
            return value
        if self.aggregate_type(analyzer, declared):
            return self.materialize_object(analyzer, node, declared, value, "aggregate-binding", binding=True)
        signature = self.signature_type(analyzer, declared, node)
        if signature == ("nominal", SCALAR_STRING_TYPES.get(analyzer.language)) or (
            signature is not None and signature[0] == "primitive"
        ):
            return value
        classification = self.object_type(analyzer, declared, node)
        if classification is None and (
            not explicit_type
            or value.category != "unknown"
            or not re.fullmatch(r"[A-Za-z_]\w*(?:\.\w+)*", declared)
            or declared in {"Int", "Long", "Short", "Byte", "Float", "Double", "Boolean", "Bool", "Char"}
        ):
            return value
        result = self.materialize_object(analyzer, node, declared, value, "local", binding=True)
        self.uncertain_objects.add(result.identity)
        if initialized:
            self.partial("object alias identity unavailable", analyzer, node=node)
        if value.traces:
            frame.object_fields.setdefault(result.identity, {})[StorageKey.UNKNOWN_FIELDS] = value
        return result

    def self_value(self, analyzer: Analyzer, frame: Frame) -> Value:
        owner = self.owner(analyzer, analyzer.function)
        return self.materialize_object(
            analyzer,
            analyzer.function,
            owner,
            Value(type_name=owner, identity=self.receiver_identity(analyzer, None, frame)),
            "receiver",
        )

    def indexed_value(self, analyzer: Analyzer, node: Any, frame: Frame) -> Value | None:
        base = index = None
        if node.type in {"array_access", "index_expression"} and len(node.named_children) >= 2:
            base = _field(node, "array") or node.named_children[0]
            index = _field(node, "index") or node.named_children[-1]
        elif node.type == "call_expression" and node.named_children:
            call = analyzer.call(node)
            arguments = analyzer.call_arguments(call) if call is not None else None
            if (
                call is not None
                and arguments is not None
                and analyzer.text(arguments).lstrip().startswith("[")
                and call.args
            ):
                base, index = node.named_children[0], call.args[0]
        if base is None or index is None:
            return None
        root = analyzer.value(base, frame)
        identity = root.identity or self.receiver_identity(analyzer, base, frame)
        literal = analyzer.text(index).strip()
        if not re.fullmatch(r"\d+", literal):
            literal = "*"
        identity = "@native-access:" + repr((identity, "index", literal))
        self.uncertain_objects.add(identity)
        self.partial("indexed object alias unavailable", analyzer, node=node)
        declared = root.type_name
        if declared.endswith("[]"):
            declared = declared[:-2]
        elif match := re.fullmatch(r"(?:Array|List|MutableList)<([^<>]+)>|\[([^\[\]]+)\]", declared):
            declared = match[1] or match[2]
        else:
            declared = ""
        stored = frame.object_fields.get(identity, {}).get(StorageKey.UNKNOWN_FIELDS, Value())
        parent_unknown = (
            frame.object_fields.get(root.identity, {}).get(StorageKey.UNKNOWN_FIELDS, Value())
            if root.identity in self.effect_aggregates
            else Value()
        )
        self.remember_effect_type(analyzer, declared, node, identity)
        return Value(_union([root, stored, parent_unknown]).traces, type_name=declared, identity=identity)

    def receiver_identity(self, analyzer: Analyzer, receiver: Any, frame: Frame) -> str:
        if receiver is None or analyzer.key(receiver) in {"this", "self"}:
            if self.receiver_field_context and self.receiver_field_context[-1] is not None:
                return self.receiver_field_context[-1]
            if self.receiver_context and self.receiver_context[-1] is not None:
                return self.receiver_context[-1][1]
            boundary = self.enclosing_scope(analyzer.function)
            nominal = boundary.node if boundary is not None else analyzer.function
            identity = self.binding_identity(analyzer, nominal, "receiver")
            if (
                self.object_type(analyzer, self.owner(analyzer, analyzer.function), analyzer.function)
                == "value"
            ):
                self.uncertain_objects.add(identity)
            return identity
        value = analyzer.value(receiver, frame)
        if value.identity:
            return value.identity
        key = analyzer.key(receiver)
        if key not in frame.values and key not in frame.types:
            owners = self.class_owners(analyzer, key, receiver)
            if len(owners) == 1:
                return "@native-type:" + next(iter(owners))
            if key in self.namespaces.values():
                return "@native-namespace:" + repr((analyzer.path, key))
        self.partial("object alias identity unavailable", analyzer, node=receiver)
        # Unsupported expressions may refer to the same storage. Keep a weak,
        # function-scoped bucket rather than falsely separating occurrences.
        identity = self.binding_identity(analyzer, analyzer.function, "unavailable-storage")
        self.uncertain_objects.add(identity)
        return identity

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
                value = storage[name]
                if not value.identity and type_name:
                    storage[name] = self.materialize_object(
                        analyzer,
                        analyzer.function,
                        type_name,
                        Value(
                            value.traces,
                            value.category,
                            type_name,
                            "@native-field:" + repr((self.field_identity(analyzer, name, frame), name)),
                        ),
                        "field",
                        binding=True,
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
            value = self.store_field(
                analyzer, self.field_identity(analyzer, name, frame), name, value, frame, analyzer.function
            )
            frame.values[name] = value
            if name in analyzer.static_fields:
                self.remember_static(self.owner(analyzer, analyzer.function), name, value)

    def store_field(
        self, analyzer: Analyzer, identity: Any, name: str, value: Value, frame: Frame, node: Any
    ) -> Value:
        fields = frame.object_fields.setdefault(identity, {})
        if identity in self.uncertain_objects:
            self.partial("object storage alias unavailable", analyzer, node=node)
            previous = fields.get(name, fields.get(StorageKey.UNKNOWN_FIELDS, Value()))
            value = self.weak_write(analyzer, Call(node, "assignment", None, ()), previous, value, Value())
        fields[name] = value
        return value

    def remember_static(self, owner: str, name: str, value: Value) -> None:
        if value.traces:
            fields = self.fields.setdefault(owner, {})
            fields[name] = self.merge([fields.get(name, Value()), value])

    def static_owner(self, analyzer: Analyzer, base: Any, member: str, frame: Frame) -> str | None:
        if analyzer.language == "swift" and analyzer.text(base).strip() == "Self":
            return self.owner(analyzer, analyzer.function) if member in analyzer.static_fields else None
        value = analyzer.value(base, frame)
        declared = value.type_name or analyzer.key(base)
        for owner in self.class_owners(analyzer, declared, base):
            for source, nominal in self.class_definitions[owner]:
                if any(
                    name == member and static for name, _expr, _type, static in source.nominal_fields(nominal)
                ):
                    return owner
        return None

    def member_type(self, analyzer: Analyzer, base: Any, member: str, frame: Frame) -> str:
        if analyzer.key(base) in {"this", "self"} or (
            analyzer.language == "swift" and analyzer.text(base).strip() == "Self"
        ):
            return analyzer.field_types.get(member, "")
        value = analyzer.value(base, frame)
        owners = self.class_owners(analyzer, value.type_name or analyzer.key(base), base)
        if len(owners) == 1:
            definitions = self.class_definitions[next(iter(owners))]
            if len(definitions) == 1:
                source, nominal = definitions[0]
                return next(
                    (kind for name, _expr, kind, _static in source.nominal_fields(nominal) if name == member),
                    "",
                )
        return ""

    def unavailable_result(
        self, analyzer: Analyzer, call: Call, receiver: Value, args: list[Value], frame: Frame
    ) -> Value:
        stored = [
            value
            for identity in self.affected_objects(analyzer, call, args, frame)
            | self.reachable_reference_objects(analyzer, call, receiver, args, frame)
            for value in frame.object_fields.get(identity, {}).values()
        ]
        declared = receiver.type_name or (analyzer.key(call.receiver) if call.receiver is not None else "")
        for owner in self.class_owners(analyzer, declared, call.node):
            stored.extend(frame.object_fields.get((StorageKey.STATIC_FIELDS, owner), {}).values())
        stored.extend(frame.object_fields.get(StorageKey.UNRESOLVED_FIELDS, {}).values())
        return analyzer.changed(call.node, _union([receiver, *args, *stored]))

    def affected_objects(self, analyzer: Analyzer, call: Call, args: list[Value], frame: Frame) -> set[str]:
        """Track only the receiver and source-bound object arguments/captured fields."""
        affected = {self.receiver_identity(analyzer, call.receiver, frame)}
        for node, argument in zip(call.args, args, strict=True):
            if argument.identity:
                affected.add(argument.identity)
            else:
                # A materialized source object carries its identity through
                # binding/aliases. An unknown expression supplies no alias proof.
                if self.object_type(analyzer, argument.type_name, node) is not None:
                    affected.add(self.receiver_identity(analyzer, node, frame))
        if call.receiver is None or analyzer.key(call.receiver) in {"this", "self"}:
            affected.update(
                value.identity
                for name in analyzer.field_types
                if (value := frame.values.get(name, Value())).identity
            )
        return affected

    def reachable_reference_objects(
        self, analyzer: Analyzer, call: Call, receiver: Value, args: list[Value], frame: Frame
    ) -> set[str]:
        """Inventory possible reference effects, without evaluating field initializers/getters.

        A Swift value copy can still contain shared references. Conversely its
        scalar slots are not caller writeback. Nominal evidence belongs to the
        storage ID, so an Object/Any alias cannot erase reachable storage.
        """
        objects = [*zip(call.args, args, strict=True)]
        if call.receiver is not None:
            objects.append((call.receiver, receiver))
        pending = []
        for node, value in objects:
            identity = value.identity
            if not identity and self.object_type(analyzer, value.type_name, node) is not None:
                identity = self.receiver_identity(analyzer, node, frame)
            self.remember_effect_type(analyzer, value.type_name, node, identity)
            if identity in self.effect_nominals or identity in self.effect_aggregates:
                pending.append((identity, 0, frozenset()))
        affected: set[str] = set()
        visited: set[str] = set()
        while pending:
            identity, depth, ancestors = pending.pop()
            if identity in ancestors:
                self.partial("cyclic reference effect inventory", analyzer, call=call)
                affected.add(identity)
                continue
            if identity in visited:
                continue
            if depth >= MAX_EFFECT_DEPTH or len(visited) >= MAX_EFFECT_OBJECTS:
                # Weakly taint the frontier as well: merely marking partial
                # would leave later lazy field reads falsely clean.
                self.partial("reference effect inventory budget", analyzer, call=call)
                affected.add(identity)
                continue
            visited.add(identity)
            fields = frame.object_fields.setdefault(identity, {})
            if identity in self.effect_aggregates:
                if identity in self.reference_aggregates:
                    affected.add(identity)
                if StorageKey.AGGREGATE_COMPLETE not in fields and identity not in self.scalar_aggregates:
                    self.partial("aggregate reference ownership unavailable", analyzer, call=call)
                    affected.add(identity)
                for key, value in fields.items():
                    if isinstance(key, tuple) and key[0] is StorageKey.AGGREGATE_ELEMENT:
                        if value.identity in self.effect_nominals or value.identity in self.effect_aggregates:
                            pending.append((value.identity, depth + 1, ancestors | {identity}))
                        elif value.identity:
                            self.partial("aggregate reference ownership unavailable", analyzer, call=call)
                            affected.add(value.identity)
            for owner in sorted(self.effect_nominals.get(identity, set())):
                source, nominal = self.class_definitions[owner][0]
                if source.language == "swift" and (
                    nominal.type == "protocol_declaration"
                    or any(
                        child.type == "enum_type_parameters"
                        for body in nominal.named_children
                        if body.type in NOMINAL_BODIES
                        for entry in body.named_children
                        if entry.type == "enum_entry"
                        for child in entry.named_children
                    )
                ):
                    # Protocol conformers and enum payloads can hide shared
                    # references outside the represented stored-field inventory.
                    self.partial("reachable field ownership unavailable", analyzer, call=call)
                    affected.add(identity)
                if source.language != "swift" or self.declaration_tokens(nominal) & {"class", "actor"}:
                    affected.add(identity)
                for offset, (name, expression, declared, static) in enumerate(source.nominal_fields(nominal)):
                    if static:
                        continue
                    if offset >= MAX_EFFECT_OBJECTS:
                        self.partial("reference effect inventory budget", analyzer, call=call)
                        affected.add(identity)
                        break
                    previous = fields.get(name, Value(type_name=declared))
                    kind = declared or previous.type_name
                    # Constructor syntax can identify an inferred field type;
                    # no initializer body is executed to build this inventory.
                    if not kind and expression is not None:
                        initializer = source.call(source.unwrap(expression))
                        if initializer is not None:
                            kind = self.constructor_type(source, initializer, Frame()) or ""
                    signature = self.signature_type(source, kind, nominal)
                    scalar = (
                        signature is not None
                        and (
                            signature[0] == "primitive"
                            or signature == ("nominal", SCALAR_STRING_TYPES.get(source.language))
                        )
                    ) or (
                        not kind
                        and expression is not None
                        and (
                            source.literal(source.unwrap(expression)) is not None
                            or re.fullmatch(r"(?:true|false|\d+(?:\.\d+)?)", source.text(expression))
                            is not None
                        )
                    )
                    if scalar:
                        continue
                    child = previous.identity
                    if self.object_type(source, kind, nominal) is not None:
                        child = child or "@native-field:" + repr((identity, name))
                        self.remember_effect_type(source, kind, nominal, child)
                        fields[name] = Value(previous.traces, previous.category, kind, child)
                    if child in self.effect_nominals:
                        pending.append((child, depth + 1, ancestors | {identity}))
                    else:
                        # Optional/container/protocol/external field ownership
                        # is unavailable. Fence this containing storage rather
                        # than assuming it holds only copied scalar values.
                        self.partial("reachable field ownership unavailable", analyzer, call=call)
                        affected.add(identity)
            # Explicit field/index aliases can carry stronger effect provenance
            # than their current declaration (including an erased field type).
            for value in list(fields.values()):
                if value.identity in self.effect_nominals or value.identity in self.effect_aggregates:
                    pending.append((value.identity, depth + 1, ancestors | {identity}))
        return affected

    def unavailable_write(
        self,
        analyzer: Analyzer,
        call: Call,
        receiver: Value,
        args: list[Value],
        frame: Frame,
        *,
        affected: set[str] | None = None,
    ) -> None:
        value = self.unavailable_result(analyzer, call, receiver, args, frame)
        if not value.traces:
            return
        if affected is None:
            affected = self.affected_objects(analyzer, call, args, frame) | self.reachable_reference_objects(
                analyzer, call, receiver, args, frame
            )
        for identity in affected:
            fields = frame.object_fields.setdefault(identity, {})
            for name, previous in list(fields.items()):
                if isinstance(name, tuple) and name[0] is StorageKey.AGGREGATE_ELEMENT:
                    # These are possible reachable references, not modeled
                    # index storage. Unknown mutation cannot prove their old
                    # aliases were removed from a reference container.
                    continue
                written = self.weak_write(analyzer, call, previous, value, value)
                if isinstance(name, str) and previous.identity in self.effect_nominals:
                    # An unknown mutator may replace a reference field. Keep a
                    # weak slot identity (never its old exact allocation proof)
                    # so a subsequent known reader sees possible child effects.
                    slot = "@native-field:" + repr((identity, name))
                    self.effect_nominals.setdefault(slot, set()).update(
                        self.effect_nominals[previous.identity]
                    )
                    frame.object_fields.setdefault(slot, {})[StorageKey.UNKNOWN_FIELDS] = value
                    written = Value(written.traces, written.category, written.type_name, slot)
                fields[name] = written
            if identity in self.effect_aggregates:
                fields.pop(StorageKey.AGGREGATE_COMPLETE, None)
            fields[StorageKey.UNKNOWN_FIELDS] = value
        shared = frame.object_fields.setdefault(StorageKey.UNRESOLVED_FIELDS, {})
        shared[StorageKey.UNKNOWN_FIELDS] = self.merge(
            [shared.get(StorageKey.UNKNOWN_FIELDS, Value()), value]
        )

    def unresolved_reference_effects(
        self, analyzer: Analyzer, call: Call, receiver: Value, args: list[Value], frame: Frame
    ) -> Value | None:
        affected = self.reachable_reference_objects(analyzer, call, receiver, args, frame)
        if not affected:
            return None
        self.partial("unresolved reference argument effects", analyzer, call=call)
        value = self.unavailable_result(analyzer, call, receiver, args, frame)
        self.unavailable_write(analyzer, call, receiver, args, frame, affected=affected)
        return value

    def compound_value(
        self,
        analyzer: Analyzer,
        node: Any,
        left: Any,
        right: Any,
        previous: Value,
        written: Value,
        operator: str,
        frame: Frame,
    ) -> Value:
        signature = self.signature_type(analyzer, previous.type_name, left)
        scalar_string = signature == ("nominal", SCALAR_STRING_TYPES.get(analyzer.language)) or (
            not previous.type_name and previous.category == "text"
        )
        primitive = signature is not None and signature[0] == "primitive"
        known = (
            operator == "+="
            and scalar_string
            or primitive
            and operator in {"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", ">>>="}
        )
        if known:
            return analyzer.changed(node, _union([previous, written], type_name=previous.type_name))
        self.partial("compound assignment operator dispatch unavailable", analyzer, node=node)
        call = Call(node, operator, left, (right,))
        result = self.unavailable_result(analyzer, call, previous, [written], frame)
        self.unavailable_write(analyzer, call, previous, [written], frame)
        # An unmodeled in-place operator may mutate the existing reference.
        # Retain that possible alias and weaken its fields; confer no safety.
        return Value(result.traces, type_name=previous.type_name, identity=previous.identity)

    def inout_writeback(
        self, analyzer: Analyzer, call: Call, argument: Any, value: Value, frame: Frame
    ) -> None:
        target = analyzer.unwrap(argument)
        if (
            target is not None
            and target.type == "prefix_expression"
            and analyzer.text(target).lstrip().startswith("&")
        ):
            target = _field(target, "target") or target.named_children[-1]
        target = analyzer.assignment_target(target)
        if target is None:
            return
        previous = analyzer.value(target, frame)
        written = self.weak_write(analyzer, call, previous, value, value)
        if previous.identity:
            self.uncertain_objects.add(previous.identity)
            written = Value(written.traces, type_name=previous.type_name, identity=previous.identity)
        if target.type in {"identifier", "simple_identifier"}:
            name = analyzer.text(target)
            frame.values[name] = written
            frame.constants.pop(name, None)
            self.assign_identifier(analyzer, name, written, frame)
        elif analyzer.navigation(target) is not None:
            self.assign_member(analyzer, target, written, frame)
        elif self.indexed_value(analyzer, target, frame) is not None and previous.identity:
            frame.object_fields.setdefault(previous.identity, {})[StorageKey.UNKNOWN_FIELDS] = written
        else:
            self.partial("inout storage target unavailable", analyzer, call=call)

    @staticmethod
    def syntactic_inout(analyzer: Analyzer, argument: Any) -> bool:
        target = analyzer.unwrap(argument)
        # Swift's grammar attaches `&` to the head of a postfix chain, so
        # `&values[0]` is a subscript call whose callee is a prefix expression.
        while target is not None and target.type in {
            "navigation_expression",
            "call_expression",
            "postfix_expression",
        }:
            target = _field(target, "target") or next(iter(target.named_children), None)
        return bool(
            analyzer.language == "swift"
            and target is not None
            and target.type == "prefix_expression"
            and analyzer.text(target).lstrip().startswith("&")
        )

    def inout_effects(
        self,
        analyzer: Analyzer,
        call: Call,
        receiver: Value,
        args: list[Value],
        arguments: list[Any],
        frame: Frame,
    ) -> Value:
        self.partial("Swift inout writeback unavailable", analyzer, call=call)
        value = self.unavailable_result(analyzer, call, receiver, args, frame)
        self.unavailable_write(analyzer, call, receiver, args, frame)
        for argument in arguments:
            self.inout_writeback(analyzer, call, argument, value, frame)
        return value

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
            if static is None:
                value = analyzer.value(base, frame)
                bucket = self.binding_identity(analyzer, analyzer.function, "unavailable-storage")
                if not value.identity and (
                    value.category != "unknown"
                    or self.object_type(analyzer, value.type_name, base) is None
                    and bucket not in frame.object_fields
                ):
                    # No native storage was materialized here. Let Analyzer's
                    # platform property/source models handle this expression.
                    return None
            identity = (
                (StorageKey.STATIC_FIELDS, static)
                if static is not None
                else self.receiver_identity(analyzer, base, frame)
            )
        fields = frame.object_fields.get(identity, {})
        result = fields.get(member, fields.get(StorageKey.UNKNOWN_FIELDS))
        if identity in self.uncertain_objects:
            self.partial("object storage alias unavailable", analyzer, node=base)
        if result is None and isinstance(identity, tuple) and identity[0] is StorageKey.STATIC_FIELDS:
            return self.fields.get(identity[1], {}).get(member)
        if (
            result is None
            and analyzer.key(base) in {"this", "self"}
            and member not in analyzer.field_types
            and self.field_inputs
        ):
            return self.unavailable_field(analyzer, frame, base)
        if result is None and (declared := self.member_type(analyzer, base, member, frame)):
            value = analyzer.value(base, frame)
            result = Value(value.traces, type_name=declared)
            if self.object_type(analyzer, declared, base) is not None:
                result = self.materialize_object(
                    analyzer,
                    base,
                    declared,
                    Value(
                        value.traces,
                        type_name=declared,
                        identity="@native-field:" + repr((identity, member)),
                    ),
                    "field",
                )
                frame.object_fields.setdefault(identity, {})[member] = result
            return result
        return result

    def assign_member(self, analyzer: Analyzer, left: Any, value: Value, frame: Frame) -> None:
        left = analyzer.assignment_target(left)
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
        fields = frame.object_fields.setdefault(identity, {})
        member_type = self.member_type(analyzer, base, member, frame)
        if not member_type:
            self.partial("receiver field inventory unavailable", analyzer, node=left)
            self.uncertain_objects.add(identity)
        value = Value(
            value.traces,
            value.category,
            member_type or fields.get(member, Value()).type_name or value.type_name,
            value.identity,
        )
        if member_type and self.object_type(analyzer, member_type, base) is not None:
            value = self.local_value(analyzer, left, member_type, value, frame, initialized=True)
        value = self.store_field(analyzer, identity, member, value, frame, left)
        if (
            analyzer.key(base) in {"this", "self"}
            and member in analyzer.field_types
            and member not in frame.local_names
        ):
            frame.values[member] = value
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

    def empty_source_ancestry(self, analyzer: Analyzer, nominal: Any, root: str) -> bool:
        """Discharge member lookup only for a unique, same-file empty class chain.

        This supplies no constructor, dispatch or external SDK ancestry proof.
        Any unrepresented member, alias, extension or base retains the fence.
        """
        key = (id(analyzer), nominal.id, root)
        if key in self.empty_base_cache:
            return self.empty_base_cache[key]
        self.empty_base_cache[key] = False
        if "class" not in self.declaration_tokens(nominal):
            return False
        if analyzer.language == "swift" and self.swift_extensions_present:
            return False
        seen = set()
        current = nominal
        for _ in range(MAX_EMPTY_BASE_DEPTH):
            if (
                current.id in seen
                or current.has_error
                or current.parent is None
                or current.parent.type not in {"program", "source_file"}
                or any(child.type == "type_parameters" for child in current.named_children)
                or "@" in analyzer.text(current).split("{", 1)[0]
            ):
                return False
            seen.add(current.id)
            inherited = [child for child in current.named_children if child.type in INHERITED_TYPE_SCOPES]
            if not inherited:
                self.empty_base_cache[key] = True
                return True
            if len(inherited) != 1:
                return False
            text = analyzer.text(inherited[0]).strip()
            pattern = (
                r"extends\s+([A-Za-z_]\w*)" if analyzer.language == "java" else r"([A-Za-z_]\w*)(?:\(\))?"
            )
            match = re.fullmatch(pattern, text)
            if match is None:
                return False
            name = match[1]
            # A member/value with the base spelling can change the header's
            # binding. Keep that case unresolved instead of selecting the
            # convenient top-level class by leaf name.
            current_body = next(
                (child for child in current.named_children if child.type in NOMINAL_BODIES), None
            )
            if current_body is not None and re.search(
                r"\b" + re.escape(name) + r"\b", analyzer.text(current_body)
            ):
                return False
            # Do not infer a package/import identity from a globally unique
            # leaf, or recurse through the use site's inherited lookup.
            namespace = self.namespaces[id(analyzer)]
            owner = namespace + "." + name if namespace else name
            imported = self.imported_symbols(analyzer, name, classes=True)
            if (
                imported
                and imported != {owner}
                or any(
                    declaration.endswith(".*") or declaration.startswith("static ")
                    for declaration in analyzer.imports
                )
            ):
                return False
            definitions = self.class_definitions.get(owner, [])
            if len(definitions) != 1 or definitions[0][0] is not analyzer:
                return False
            file_root = current
            while file_root.parent is not None:
                file_root = file_root.parent
            if any(
                child.type in {"type_alias", "typealias_declaration"} for child in file_root.named_children
            ):
                return False
            base = definitions[0][1]
            header = analyzer.text(base).split("{", 1)[0].strip()
            if not re.fullmatch(
                r"(?:(?:public|protected|private|internal|fileprivate|open|abstract|final|static)\s+)*"
                r"class\s+" + re.escape(name) + r"\s*(?:(?:extends\s+|:\s*)[A-Za-z_]\w*(?:\(\))?)?\s*",
                header,
            ):
                return False
            body = next((child for child in base.named_children if child.type in NOMINAL_BODIES), None)
            if (
                body is None
                and analyzer.language != "kotlin"
                or body is not None
                and any("comment" not in child.type for child in body.named_children)
            ):
                return False
            current = base
        return False

    def swift_extension_owner_matches(self, owner: str, target: str) -> bool:
        """Unresolved Swift extension targets cannot establish imported type identity."""
        return (
            target == owner
            or target.endswith("." + owner)
            or owner.endswith("." + target)
            or any(
                source.language == "swift"
                for source, _ in self.module_type_aliases.get(target.partition(".")[0], [])
            )
            or "." in target
            and not any(source.language == "swift" for source, _ in self.class_definitions.get(target, []))
            or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", target) is None
        )

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
                if analyzer.language == "swift" and boundary is not None and boundary.kind == "nominal":
                    if self.swift_extension_types_exhausted:
                        return boundary.name
                    owner = self.owner(analyzer, boundary.name)
                    for target, inherited in self.swift_extension_conformances.items():
                        if self.swift_extension_owner_matches(owner, target):
                            # A protocol may supply any member type, including
                            # the root of a qualified SDK spelling, through an
                            # otherwise empty conformance extension.
                            return inherited
                    for target, declaration in self.swift_extension_types.get(root, {}).items():
                        if self.swift_extension_owner_matches(owner, target):
                            # Supplied Swift module membership and extension
                            # aliases are unresolved; their bodies confer no
                            # SDK identity. Exact unrelated owners stay apart.
                            return declaration
                inherited = next(
                    (child for child in scope.named_children if child.type in INHERITED_TYPE_SCOPES), None
                )
                if inherited is not None and not self.empty_source_ancestry(analyzer, scope, root):
                    # Unknown or nonempty ancestry may supply a member before
                    # an enclosing/package/import binding.
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
    def property_binding_names(analyzer: Analyzer, node: Any) -> set[str]:
        """Read binding patterns without mistaking receiver/types/initializers for names."""
        if analyzer.language == "kotlin":
            declarations = []
            for child in node.named_children:
                if child.type == "variable_declaration":
                    declarations.append(child)
                elif child.type == "multi_variable_declaration":
                    declarations.extend(child.named_children)
            return {
                analyzer.text(name)
                for declaration in declarations
                for name in declaration.named_children[:1]
                if name.type in IDENTIFIERS
            }
        pending = [
            child
            for index, child in enumerate(node.children)
            if node.field_name_for_child(index) == "name" and child.type == "pattern"
        ]
        names = set()
        while pending:
            child = pending.pop()
            if child.type in IDENTIFIERS:
                names.add(analyzer.text(child))
            elif child.type not in {"type_annotation", "computed_value"}:
                pending.extend(child.named_children)
        return names

    def module_value_present(self, analyzer: Analyzer, name: str, *, aliases: bool = False) -> bool:
        """A potential expression binding supplies uncertainty, never a value/type proof."""
        imported = self.imported_symbols(analyzer, name)
        names = {name, *(symbol.rsplit(".", 1)[-1] for symbol in imported)}
        for source_name in names:
            bindings = self.module_type_aliases if aliases else self.module_values
            for source, node in bindings.get(source_name, []):
                if source.language != analyzer.language:
                    continue
                if source is analyzer:
                    if source_name == name:
                        return True
                    continue
                if self.declaration_tokens(node) & {"private", "fileprivate"}:
                    continue
                if analyzer.language == "swift":
                    # Compiler module membership is not represented by source inputs.
                    if source_name == name:
                        return True
                    continue
                namespace = self.namespaces[id(source)]
                identity = (namespace + "." if namespace else "") + source_name
                if source_name == name and (
                    namespace == self.namespaces[id(analyzer)] or namespace + ".*" in analyzer.imports
                ):
                    return True
                if identity in imported:
                    return True
        return False

    def value_binding(self, analyzer: Analyzer, call: Call, frame: Frame) -> Value | None:
        """A current lexical value binds an unqualified callee before a member/type name."""
        if (
            analyzer.language not in {"kotlin", "swift"}
            or call.receiver is not None
            or not (
                call.name in frame.values
                or call.name in analyzer.parameter_types
                or call.name in analyzer.field_types
                or self.module_value_present(analyzer, call.name)
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
        if analyzer.language == "swift" and (
            self.module_value_present(analyzer, root, aliases=True) or self.class_name_present(analyzer, root)
        ):
            # A supplied source nominal can shadow a module/type spelling in
            # another file. Unknown module membership is not proof of absence.
            return False
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
        if name is None and node.type == "type_alias":
            name = _field(node, "type") or next(
                (child for child in node.named_children if child.type in IDENTIFIERS), None
            )
        if name is None and node.type == "property_declaration":
            name = next(
                (
                    child
                    for child in node.named_children
                    if child.type in {"variable_declaration", "multi_variable_declaration"}
                ),
                None,
            )
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
        self.remember_effect_type(analyzer, declared, call.node, identity)
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
                if NativeFlow.syntactic_inout(analyzer, argument) != bool(
                    re.search(r"\binout\b", target.analyzer.text(parameter))
                ):
                    return False
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
        if call.receiver is None and self.module_value_present(analyzer, call.name, aliases=True):
            return [], True
        receiver_root = analyzer.key(call.receiver).partition(".")[0] if call.receiver is not None else ""
        if (
            receiver_root
            and receiver_root not in frame.values
            and receiver_root not in analyzer.parameter_types
            and receiver_root not in analyzer.field_types
            and (
                self.module_value_present(analyzer, receiver_root)
                or self.module_value_present(analyzer, receiver_root, aliases=True)
            )
        ):
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
            if (
                analyzer.language in {"kotlin", "swift"}
                and call.receiver is None
                and (
                    (imported if analyzer.language == "swift" else imported - MODELED_EXTERNAL_CONSTRUCTORS)
                    or any(
                        target.node.type != "constructor_declaration"
                        and (
                            target.analyzer.path == analyzer.path
                            or analyzer.language == "swift"
                            and not target.owner
                        )
                        and (not target.owner or target.owner == self.owner(analyzer, analyzer.function))
                        for target in choices
                    )
                )
            ):
                # A visible source function can shadow an imported type's
                # constructor spelling. Its presence must precede SDK models.
                return [], True
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
        syntactic_inout = [argument for argument in call.args if self.syntactic_inout(analyzer, argument)]
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
            if syntactic_inout:
                return self.inout_effects(analyzer, call, receiver, args, syntactic_inout, frame)
            self.partial("callable value binding unresolved", analyzer, call=call)
            effects = self.unresolved_reference_effects(analyzer, call, receiver, args, frame)
            return analyzer.changed(call.node, _union([binding, *args, effects or Value()]))
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
        if not targets and syntactic_inout:
            # `&actual` is a mutation boundary even without a callee inventory.
            # It precedes relevance shortcuts; admitted bodies keep their own
            # summary path rather than receiving this unknown-call fallback.
            return self.inout_effects(analyzer, call, receiver, args, syntactic_inout, frame)
        if not relevant:
            constructor_type = self.constructor_type(analyzer, call, frame)
            if constructor_type is not None and self.modeled_external(
                analyzer, constructor_type, call, constructor=True
            ):
                return None
            # A source-identified constructor supplies allocation identity, never a global leaf match.
            if constructor_type is not None and self.class_owners(analyzer, constructor_type, call.node):
                identity = self.binding_identity(analyzer, call.node, "allocation")
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
                identity = self.binding_identity(analyzer, call.node, "allocation")
                unknown = self.incomplete(analyzer.changed(call.node, _union(args)))
                frame.object_fields[identity] = {StorageKey.UNKNOWN_FIELDS: unknown}
                return Value(unknown.traces, type_name=constructor_type or call.name, identity=identity)
            effects = self.unresolved_reference_effects(analyzer, call, receiver, args, frame)
            if effects is not None:
                return effects
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
                    identity = self.binding_identity(analyzer, call.node, "allocation")
                    self.allocation(analyzer, call, constructor_type, identity)
                    return Value(type_name=constructor_type, identity=identity)
                self.partial("constructor field mapping unavailable", analyzer, call=call)
                identity = self.binding_identity(analyzer, call.node, "allocation")
                self.allocation(analyzer, call, constructor_type, identity)
                unknown = self.incomplete(analyzer.changed(call.node, _union([receiver, *args])))
                frame.object_fields[identity] = {StorageKey.UNKNOWN_FIELDS: unknown}
                return Value(unknown.traces, type_name=constructor_type, identity=identity)
            self.partial("unresolved callable identity or argument signature", analyzer, call=call)
            self.unavailable_write(analyzer, call, receiver, args, frame)
            return self.unavailable_result(analyzer, call, receiver, args, frame)
        if len(targets) > 1:
            self.partial("ambiguous direct call", analyzer, call=call)
        inout_arguments = [
            argument
            for target in targets
            if target.analyzer.language == "swift"
            for (_name, _type, parameter), argument in zip(target.parameters, call.args, strict=True)
            if re.search(r"\binout\b", target.analyzer.text(parameter))
        ]
        if inout_arguments:
            return self.inout_effects(analyzer, call, receiver, args, inout_arguments, frame)
        constructor = all(target.node.type == "constructor_declaration" for target in targets)
        identity = (
            self.binding_identity(analyzer, call.node, "allocation")
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
        dispatch_dynamic = any(
            not self.closed_dispatch(target) and (concrete is None or concrete[0] != target.owner)
            for target in targets
        )
        if dispatch_dynamic:
            self.partial("receiver runtime dispatch unresolved", analyzer, call=call)
        dynamic = dispatch_dynamic
        local_receiver = (call.receiver is None or analyzer.key(call.receiver) in {"this", "self"}) and all(
            target.owner == self.owner(analyzer, analyzer.function) for target in targets
        )
        affected = self.affected_objects(analyzer, call, args, frame)
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
                    (object_identity, name, self.signature(value))
                    for object_identity in affected
                    for name, value in frame.object_fields.get(object_identity, {}).items()
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
                writes.append(frame.object_fields.get(identity, {}).copy())
                continue
            if target.body is None:
                self.partial("callable body unavailable", analyzer, call=call)
                self.unavailable_write(analyzer, call, receiver, args, frame)
                results.append(self.unavailable_result(analyzer, call, receiver, args, frame))
                writes.append(frame.object_fields.get(identity, {}).copy())
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
                                name: fields.get(name, previous.get(name, Value()))
                                if isinstance(name, tuple) and name[0] is StorageKey.AGGREGATE_ELEMENT
                                else self.weak_write(
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
        if dynamic:
            # A bodyless target and an overridable no-op have the same unknown
            # argument effects, including objects not yet read/materialized.
            self.unavailable_write(analyzer, call, receiver, args, frame)
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
        if len(targets) != 1 or dispatch_dynamic:
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
            "max_effect_depth": MAX_EFFECT_DEPTH,
            "max_effect_objects": MAX_EFFECT_OBJECTS,
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
