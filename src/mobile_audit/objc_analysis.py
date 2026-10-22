"""Objective-C CST checks with straight-line def-use; every result is a candidate."""

from __future__ import annotations

import re
from bisect import bisect_left
from typing import Any

from .core import code_excerpt, finding

RULES = ("OBJC-WEBVIEW-UNTRUSTED-REQUEST", "OBJC-CRYPTO-WEAK-HASH")
FUNCTIONS = {"method_definition", "function_definition", "method_declaration"}
API_NAMES = {"WKWebView", "WKNavigationAction", "NSURLRequest", "CC_MD5", "CC_SHA1"}


def walk(node: Any):
    pending = [node]
    while pending:
        value = pending.pop()
        yield value
        if value.type != "comment":
            pending.extend(reversed(value.named_children))


class ObjCAnalyzer:
    def __init__(self, path: str, text: str, uncertain_spans: list[list[int]] | None = None):
        self.path = path
        # Byte spans blanked by preprocessor normalization; overlapping functions
        # may have lost a guard in a dropped branch and are not analyzed.
        spans = sorted(uncertain_spans or [])
        self.span_starts = [start for start, _ in spans]
        self.span_ends = [end for _, end in spans]
        self.raw = text.encode()
        self.lines = text.split("\n")
        self.findings: list[dict] = []
        self.pattern_exclusions: dict = {}
        self.function_counts = {"observed": 0, "analyzed": 0, "skipped": 0, "without_body": 0}
        self.scope = ""
        self.webkit = False
        self.crypto = False
        # File-level API homonyms stay conservative; lexical bindings also carry
        # their declaration position so later or sibling locals cannot leak.
        self.shadowed: set[str] = set()
        self.scoped_shadowed: dict[int, dict[str, int]] = {}

    def text(self, node):
        return self.raw[node.start_byte : node.end_byte].decode("utf-8", errors="replace") if node else ""

    def location(self, node):
        prefix = self.raw[: node.start_byte]
        return {
            "path": self.path,
            "line": prefix.count(b"\n") + 1,
            "column": node.start_byte - prefix.rfind(b"\n"),
            "offset": node.start_byte,
        }

    def emit(self, rule, node, source=None):
        crypto = rule == "OBJC-CRYPTO-WEAK-HASH"
        evidence = {
            **self.location(node),
            "basis": "objc-cst-direct-call" if crypto else "objc-cst-local-def-use",
            "language": "objc",
            "function": self.scope,
            "excerpt": code_excerpt(self.lines[self.location(node)["line"] - 1]),
            "reachability": "unknown",
            "dispatch_resolution": "unverified",
        }
        if source:
            evidence["sources"] = [{**self.location(source), "kind": "WKNavigationAction callback parameter"}]
        self.findings.append(
            finding(
                rule,
                "Objective-C calls a weak digest primitive"
                if crypto
                else "Navigation callback input reaches an Objective-C WKWebView",
                "medium" if crypto else "high",
                "candidate",
                [evidence],
                "Review security use and replace collision-sensitive MD5/SHA-1."
                if crypto
                else "Validate navigation trust and redirects on the owned test build; review the declared receiver type.",
                "MASVS-CRYPTO" if crypto else "MASVS-NETWORK",
                ["https://developer.apple.com/documentation/webkit/wkwebview"],
                origin="source",
                confidence="local-syntax-and-declared-types",
                validation="Macros, preprocessing, ObjC dispatch/swizzling, interprocedural flow and runtime reachability remain unverified.",
            )
        )

    def message(self, node):
        if node.type != "message_expression":
            return None
        receiver = node.child_by_field_name("receiver")
        methods = [c for i, c in enumerate(node.children) if node.field_name_for_child(i) == "method"]
        args = [c for c in node.named_children if c != receiver and c not in methods]
        return receiver, ":".join(self.text(c) for c in methods), args

    def value(self, node, values):
        if node is None:
            return None
        if node.type == "identifier":
            return values.get(self.text(node))
        if node.type in {"parenthesized_expression", "cast_expression"}:
            child = node.child_by_field_name("value") or node.child_by_field_name("argument")
            if child is None and node.named_children:
                child = node.named_children[-1]
            return self.value(child, values)
        if node.type == "field_expression":
            base = self.value(node.child_by_field_name("argument"), values)
            name = self.text(node.child_by_field_name("field"))
            if base and (
                (base[0], name) == ("navigation", "request") or (base[0], name) == ("request", "URL")
            ):
                return ("request" if name == "request" else "url", base[1])
        message = self.message(node)
        if message:
            receiver, name, args = message
            base = self.value(receiver, values)
            if base and name in {"request", "URL"}:
                if (base[0], name) in {("navigation", "request"), ("request", "URL")}:
                    return ("request" if name == "request" else "url", base[1])
            if (
                self.text(receiver) == "NSURLRequest"
                and not self.is_shadowed("NSURLRequest", receiver)
                and name == "requestWithURL"
                and len(args) == 1
            ):
                value = self.value(args[0], values)
                if value and value[0] == "url":
                    return "request", value[1]
        return None

    def declarator_identifier(self, node):
        if node is None:
            return None
        if node.type in {"identifier", "type_identifier"}:
            return node
        child = node.child_by_field_name("declarator")
        if child is None and node.type == "parenthesized_declarator" and len(node.named_children) == 1:
            child = node.named_children[0]
        return self.declarator_identifier(child)

    def declarator_name(self, node):
        return self.text(self.declarator_identifier(node))

    def add_shadow(self, identifier, owner=None):
        name = self.text(identifier)
        if name not in API_NAMES:
            return
        if owner is None:
            self.shadowed.add(name)
        else:
            bindings = self.scoped_shadowed.setdefault(owner.id, {})
            previous = bindings.get(name)
            if previous is None or identifier.end_byte < previous:
                bindings[name] = identifier.end_byte

    def is_shadowed(self, name, node):
        if name in self.shadowed:
            return True
        position = node.start_byte
        while node:
            declared = self.scoped_shadowed.get(node.id, {}).get(name)
            if declared is not None and declared <= position:
                return True
            node = node.parent
        return False

    def declaration_scope(self, node):
        parent = node.parent
        while parent:
            if parent.type in FUNCTIONS | {"compound_statement", "for_statement"}:
                return parent
            parent = parent.parent
        return None

    def parameter_scope(self, node):
        owner = node.parent.parent  # parameter_list's function declarator or block literal
        parent = owner
        while parent and parent.type not in FUNCTIONS | {
            "declaration",
            "type_definition",
            "parameter_declaration",
            "block_literal",
        }:
            parent = parent.parent
        if parent and parent.type == "function_definition":
            # Only the defining parameter list owns the function body. Names in
            # nested callback prototypes and returned function types do not.
            declarator = parent.child_by_field_name("declarator")
            defining = None
            while declarator:
                if declarator.type == "function_declarator":
                    defining = declarator
                child = declarator.child_by_field_name("declarator")
                if child is None and declarator.type == "parenthesized_declarator":
                    child = next(iter(declarator.named_children), None)
                declarator = child
            if defining == owner:
                return parent
        return owner

    def inspect_expression(self, node, values, types):
        for child in walk(node):
            message = self.message(child)
            if message and self.webkit:
                receiver, name, args = message
                if name == "loadRequest" and len(args) == 1 and types.get(self.text(receiver)) == "WKWebView":
                    value = self.value(args[0], values)
                    if value and value[0] == "request":
                        self.emit("OBJC-WEBVIEW-UNTRUSTED-REQUEST", child, value[1])

    def analyze(self, root):
        nodes = list(walk(root))
        for node in nodes:
            if node.type == "preproc_include":
                parent = node.parent
                conditional = False
                while parent:
                    conditional |= parent.type.startswith("preproc_") or parent.type == "ERROR"
                    parent = parent.parent
                if conditional:
                    continue
                header = self.text(node.child_by_field_name("path"))
                self.webkit |= header in {"<WebKit/WebKit.h>", '"WebKit/WebKit.h"'}
                self.crypto |= header in {
                    "<CommonCrypto/CommonDigest.h>",
                    '"CommonCrypto/CommonDigest.h"',
                    "<CommonCrypto/CommonCrypto.h>",
                    '"CommonCrypto/CommonCrypto.h"',
                }
            if node.type in {"class_interface", "class_implementation"}:
                # Local homonyms cannot establish platform API identity.
                name = self.text(next((c for c in node.named_children if c.type == "identifier"), None))
                if name:
                    self.shadowed.add(name)
            elif node.type in {"preproc_def", "preproc_function_def"}:
                self.shadowed.add(self.text(node.child_by_field_name("name")))
            elif node.type in {"declaration", "type_definition", "parameter_declaration"}:
                owner = (
                    self.parameter_scope(node)
                    if node.type == "parameter_declaration"
                    else self.declaration_scope(node)
                )
                for index, child in enumerate(node.children):
                    if node.field_name_for_child(index) == "declarator":
                        self.add_shadow(self.declarator_identifier(child), owner)
            elif node.type == "method_parameter":
                identifier = next((c for c in node.named_children if c.type == "identifier"), None)
                self.add_shadow(identifier, node.parent)
            elif node.type == "for_statement" and node.child_by_field_name("type"):
                # Objective-C fast enumeration has no declaration wrapper.
                declared_type = node.child_by_field_name("type")
                declarator = next((c for c in node.named_children if c != declared_type), None)
                self.add_shadow(self.declarator_identifier(declarator), node)
            elif node.type == "function_definition":
                self.add_shadow(
                    self.declarator_identifier(node.child_by_field_name("declarator")),
                    self.declaration_scope(node),
                )
        self.webkit &= not {"WKWebView", "WKNavigationAction"} & self.shadowed
        for function in nodes:
            if function.type not in FUNCTIONS:
                continue
            self.function_counts["observed"] += 1
            parent = function.parent
            # Spans are merged and disjoint: the last one starting before the
            # function end is the only candidate for overlap.
            index = bisect_left(self.span_starts, function.end_byte) - 1
            uncertain = function.has_error or (index >= 0 and self.span_ends[index] > function.start_byte)
            while parent:
                uncertain |= parent.type in {
                    "ERROR",
                    "preproc_if",
                    "preproc_ifdef",
                    "preproc_else",
                    "preproc_elif",
                }
                parent = parent.parent
            if uncertain:
                self.function_counts["skipped"] += 1
                continue
            body = function.child_by_field_name("body") or next(
                (c for c in function.named_children if c.type == "compound_statement"), None
            )
            if body is None:
                self.function_counts["without_body"] += 1
                continue
            self.function_counts["analyzed"] += 1
            self.scope = self.text(function).split("{", 1)[0].strip()[:160]
            values = {}
            types = {}
            for parameter in (c for c in function.named_children if c.type == "method_parameter"):
                match = re.fullmatch(
                    r":\s*\(\s*(WKWebView|WKNavigationAction)\s*\*\s*\)\s*([A-Za-z_]\w*)",
                    self.text(parameter),
                )
                if match and not self.is_shadowed(match[1], parameter):
                    types[match[2]] = match[1]
                    if match[1] == "WKNavigationAction" and self.webkit:
                        values[match[2]] = ("navigation", parameter)
            if self.crypto:
                for node in walk(body):
                    if node.type == "call_expression":
                        name = self.text(node.child_by_field_name("function"))
                        if name in {"CC_MD5", "CC_SHA1"} and not self.is_shadowed(name, node):
                            self.emit("OBJC-CRYPTO-WEAK-HASH", node)
            for statement in body.named_children:
                if statement.type == "declaration":
                    declared_type = self.text(statement.child_by_field_name("type"))
                    if self.is_shadowed(declared_type, statement):
                        declared_type = ""
                    for declarator in (c for c in statement.named_children if c.type == "init_declarator"):
                        name = self.declarator_name(declarator.child_by_field_name("declarator"))
                        expression = declarator.child_by_field_name("value")
                        values.pop(name, None)
                        types[name] = declared_type
                        value = self.value(expression, values)
                        if value:
                            values[name] = value
                        if expression:
                            self.inspect_expression(expression, values, types)
                elif statement.type == "expression_statement":
                    for expression in statement.named_children:
                        if expression.type == "assignment_expression":
                            left = self.text(expression.child_by_field_name("left"))
                            value = self.value(expression.child_by_field_name("right"), values)
                            values.pop(left, None)
                            if value:
                                values[left] = value
                        self.inspect_expression(expression, values, types)
                else:
                    # Joins, loops, blocks, macros and unknown writes terminate straight-line tracking.
                    values.clear()
