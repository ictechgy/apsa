"""Bounded direct native call summaries; uncertainty never supplies a sanitizer."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .source_analysis import (
    FUNCTIONS,
    RULES,
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
CONTEXT = (
    "scope",
    "function",
    "function_source",
    "field_types",
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


class NativeFlow:
    def __init__(self, files: list[tuple[Analyzer, Any, list[Any]]]):
        self.by_name: dict[str, list[Callable]] = {}
        self.classes: dict[str, set[str]] = {}
        self.stack: list[tuple] = []
        self.call_sites: list[str] = []
        self.evaluations = 0
        self.reasons: set[str] = set()
        self.fields: dict[str, dict[str, Value]] = {}
        self.owner_cache: dict[tuple[int, int], str] = {}
        self.active_guards: dict[int | tuple[int, str], set[str]] = {}
        self.active_conditions: list[Any] = []
        self.files = sorted(files, key=lambda item: item[0].path)
        count = 0
        for analyzer, root, nodes in self.files:
            analyzer.prepare(root, nodes)
            analyzer.native_flow = self
            for node in nodes:
                if node.type in {"class_declaration", "object_declaration"}:
                    name = _field(node, "name") or next(
                        (
                            child
                            for child in node.named_children
                            if child.type in {"identifier", "simple_identifier", "type_identifier"}
                        ),
                        None,
                    )
                    if name is not None:
                        owner = self.owner(analyzer, name)
                        self.classes.setdefault(analyzer.text(name), set()).add(owner)
                if node.type not in FUNCTIONS or node.has_error:
                    continue
                count += 1
                if count > MAX_CALLABLES:
                    self.partial("callable inventory budget")
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
        parent = function.parent
        names = []
        while parent:
            if parent.type in {"class_declaration", "object_declaration"}:
                name = _field(parent, "name") or next(
                    (
                        child
                        for child in parent.named_children
                        if child.type in {"identifier", "simple_identifier", "type_identifier"}
                    ),
                    None,
                )
                names.append(analyzer.text(name))
            parent = parent.parent
        if not names:
            owner = ""
        else:
            owner = ".".join(
                ([analyzer.package_name] if analyzer.package_name else []) + list(reversed(names))
            )
        self.owner_cache[key] = owner
        return owner

    def partial(self, reason: str, analyzer: Analyzer | None = None) -> None:
        self.reasons.add(reason)
        if analyzer is not None:
            analyzer.truncated_rules.update(RULES)

    def receiver_identity(self, analyzer: Analyzer, receiver: Any, frame: Frame) -> str:
        if receiver is None or analyzer.key(receiver) in {"this", "self"}:
            return self.owner(analyzer, analyzer.function) + ":self"
        value = analyzer.value(receiver, frame)
        return value.identity or analyzer.path + ":" + analyzer.key(receiver)

    def initial_fields(self, analyzer: Analyzer, function: Any) -> dict[str, Value]:
        return self.fields.get(self.owner(analyzer, function), {}).copy()

    def finish(self, analyzer: Analyzer, function: Any, frame: Frame) -> None:
        owner = self.owner(analyzer, function)
        fields = self.fields.setdefault(owner, {})
        for name in analyzer.field_types:
            value = frame.values.get(name, Value())
            if value.traces:
                previous = fields.get(name, Value())
                fields[name] = _union([previous, value], value.category, value.type_name)

    def member(self, analyzer: Analyzer, base: Any, member: str, frame: Frame) -> Value | None:
        if analyzer.key(base) in {"this", "self"}:
            return None
        identity = self.receiver_identity(analyzer, base, frame)
        fields = frame.object_fields.get(identity, {})
        return fields.get(member, fields.get("__unknown_fields__"))

    def assign_member(self, analyzer: Analyzer, left: Any, value: Value, frame: Frame) -> None:
        navigation = analyzer.navigation(left)
        if not navigation:
            return
        base, member = navigation
        if analyzer.key(base) in {"this", "self"} and member in analyzer.field_types:
            frame.values[member] = value
        else:
            identity = self.receiver_identity(analyzer, base, frame)
            frame.object_fields.setdefault(identity, {})[member] = value

    def resolve(self, analyzer: Analyzer, call: Call, receiver: Value) -> tuple[list[Callable], bool]:
        choices = self.by_name.get(call.name, [])
        if not choices:
            return [], False
        named_choices = choices
        choices = [
            target
            for target in choices
            if target.analyzer.language == analyzer.language and len(target.parameters) == len(call.args)
        ]
        owner = self.owner(analyzer, analyzer.function)
        if call.receiver is None or analyzer.key(call.receiver) in {"this", "self"}:
            constructors = [
                target
                for target in choices
                if target.node.type == "constructor_declaration"
                and target.owner.rsplit(".", 1)[-1] == call.name
            ]
            if constructors:
                return constructors, True
            local = [
                target
                for target in choices
                if target.owner == owner and (owner or target.analyzer.path == analyzer.path)
            ]
            if local:
                return local, True
            if any(
                target.owner == owner and (owner or target.analyzer.path == analyzer.path)
                for target in named_choices
            ):
                return [], True
            # Kotlin and Swift top-level functions are directly callable in the same module.
            choices = [target for target in choices if not target.owner]
            return choices, bool(choices)
        declared = re.sub(r"[?!<>].*", "", receiver.type_name).strip() or analyzer.key(call.receiver)
        owners = self.classes.get(declared.rsplit(".", 1)[-1], set())
        if "." in declared:
            owners = {candidate for candidate in owners if candidate == declared}
        else:
            imported = {item for item in analyzer.imports if item.rsplit(".", 1)[-1] == declared}
            if imported:
                owners = owners & imported
            elif owner and "." in owner:
                package = owner.rsplit(".", 1)[0]
                local_owners = {candidate for candidate in owners if candidate.rsplit(".", 1)[0] == package}
                if local_owners:
                    owners = local_owners
        resolved = [target for target in choices if target.owner in owners]
        # Unknown receiver identity with a known local method is explicitly unresolved.
        return resolved, bool(resolved) or (not owners and bool(choices))

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
            self.partial("source trace budget", analyzer)
        targets, relevant = self.resolve(analyzer, call, receiver)
        if not relevant:
            # A known source-local constructor supplies receiver type and allocation identity.
            if call.receiver is None and call.name in self.classes:
                identity = f"{analyzer.path}:{call.node.start_byte}"
                if args:
                    self.partial("constructor field mapping unavailable", analyzer)
                    unknown = self.incomplete(analyzer.changed(call.node, _union(args)))
                    frame.object_fields[identity] = {"__unknown_fields__": unknown}
                    return Value(unknown.traces, type_name=call.name, identity=identity)
                return Value(type_name=call.name, identity=identity)
            return None
        if not targets:
            self.partial("unresolved receiver or argument signature", analyzer)
            return analyzer.changed(call.node, _union([receiver, *args]))
        if len(targets) > 1:
            self.partial("ambiguous direct call", analyzer)
        dynamic = bool(
            call.receiver is not None
            and not receiver.identity
            and not analyzer.type_reference(call.receiver)
            and analyzer.key(call.receiver) not in {"this", "self"}
        )
        dynamic &= any(
            not re.search(r"\bstatic\b", target.analyzer.text(target.node).split("{", 1)[0])
            for target in targets
        )
        if dynamic:
            self.partial("receiver runtime dispatch unresolved", analyzer)
        constructor = all(target.node.type == "constructor_declaration" for target in targets)
        identity = (
            f"{analyzer.path}:{call.node.start_byte}"
            if constructor
            else self.receiver_identity(analyzer, call.receiver, frame)
        )
        state = tuple(
            sorted(
                (name, self.signature(value)) for name, value in frame.object_fields.get(identity, {}).items()
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
            guards,
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
                self.partial("recursion or call evaluation budget", analyzer)
                results.append(analyzer.changed(call.node, _union([receiver, *args])))
                continue
            if target.body is None:
                self.partial("callable body unavailable", analyzer)
                results.append(analyzer.changed(call.node, _union([receiver, *args])))
                continue
            callee = target.analyzer
            saved = {name: getattr(callee, name) for name in CONTEXT}
            saved_guards = self.active_guards
            saved_conditions = self.active_conditions
            self.stack.append(target.key)
            self.call_sites.append(f"{analyzer.path}:{call.node.start_byte}")
            self.evaluations += 1
            try:
                local = callee.start_function(target.node)
                local.object_fields = {key: fields.copy() for key, fields in frame.object_fields.items()}
                if not constructor and (
                    call.receiver is None or analyzer.key(call.receiver) in {"this", "self"}
                ):
                    local.values.update(
                        {name: frame.values[name] for name in callee.field_types if name in frame.values}
                    )
                else:
                    local.values.update(frame.object_fields.get(identity, {}))
                    unknown = local.values.pop("__unknown_fields__", None)
                    if unknown is not None:
                        for name in callee.field_types:
                            local.values[name] = unknown
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
                        self.partial("return flow unavailable", analyzer)
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
                writes.append(
                    {name: local.values[name] for name in callee.field_types if name in local.values}
                )
                frame.object_fields.update(local.object_fields)
            finally:
                self.stack.pop()
                self.call_sites.pop()
                self.active_guards = saved_guards
                self.active_conditions = saved_conditions
                for name, value in saved.items():
                    setattr(callee, name, value)
        if len(targets) > 8:
            self.partial("ambiguous target budget", analyzer)
            results.append(analyzer.changed(call.node, _union([receiver, *args])))
        merged = {
            name: self.merge([write.get(name, Value()) for write in writes])
            for name in set().union(*(write.keys() for write in writes))
        }
        frame.object_fields[identity] = merged
        if not constructor and (call.receiver is None or analyzer.key(call.receiver) in {"this", "self"}):
            frame.values.update(merged)
        result = Value(type_name=call.name, identity=identity) if constructor else self.merge(results)
        if len(targets) != 1 or dynamic:
            result = analyzer.changed(call.node, _union([result, receiver, *args]))
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
            "evaluations": self.evaluations,
            "max_depth": MAX_CALL_DEPTH,
            "max_evaluations": MAX_CALL_EVALUATIONS,
            "max_field_rounds": MAX_FIELD_ROUNDS,
            "dynamic_dispatch": "not-modeled",
        }
