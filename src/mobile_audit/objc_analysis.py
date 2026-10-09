"""Objective-C CST checks with straight-line def-use; every result is a candidate."""

from __future__ import annotations

import re
from typing import Any

from .core import code_excerpt, finding

RULES = ("OBJC-WEBVIEW-UNTRUSTED-REQUEST", "OBJC-CRYPTO-WEAK-HASH")
FUNCTIONS = {"method_definition", "function_definition", "method_declaration"}


def walk(node: Any):
    pending = [node]
    while pending:
        value = pending.pop()
        yield value
        if value.type != "comment":
            pending.extend(reversed(value.named_children))


class ObjCAnalyzer:
    def __init__(self, path: str, text: str):
        self.path = path
        self.raw = text.encode()
        self.lines = text.split("\n")
        self.findings: list[dict] = []
        self.pattern_exclusions: dict = {}
        self.function_counts = {"observed": 0, "analyzed": 0, "skipped": 0, "without_body": 0}
        self.scope = ""
        self.webkit = False
        self.crypto = False
        self.shadowed: set[str] = set()

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
                and "NSURLRequest" not in self.shadowed
                and name == "requestWithURL"
                and len(args) == 1
            ):
                value = self.value(args[0], values)
                if value and value[0] == "url":
                    return "request", value[1]
        return None

    def declarator_name(self, node):
        if node is None:
            return ""
        if node.type == "identifier":
            return self.text(node)
        child = node.child_by_field_name("declarator")
        return self.declarator_name(child) if child else ""

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
                for index, child in enumerate(node.children):
                    if node.field_name_for_child(index) == "declarator":
                        name = self.declarator_name(child)
                        if name:
                            self.shadowed.add(name)
            elif node.type == "function_definition":
                name = self.declarator_name(node.child_by_field_name("declarator"))
                if name:
                    self.shadowed.add(name)
        self.webkit &= not {"WKWebView", "WKNavigationAction"} & self.shadowed
        for function in nodes:
            if function.type not in FUNCTIONS:
                continue
            self.function_counts["observed"] += 1
            parent = function.parent
            uncertain = function.has_error
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
                if match:
                    types[match[2]] = match[1]
                    if match[1] == "WKNavigationAction" and self.webkit:
                        values[match[2]] = ("navigation", parameter)
            local_names = {
                self.text(n)
                for n in walk(body)
                if n.type == "identifier"
                and n.parent
                and n.parent.type in {"pointer_declarator", "init_declarator"}
            }
            if self.crypto:
                for node in walk(body):
                    if node.type == "call_expression":
                        name = self.text(node.child_by_field_name("function"))
                        if name in {"CC_MD5", "CC_SHA1"} and name not in self.shadowed | local_names:
                            self.emit("OBJC-CRYPTO-WEAK-HASH", node)
            for statement in body.named_children:
                if statement.type == "declaration":
                    declared_type = self.text(statement.child_by_field_name("type"))
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
