"""Conservative path predicates: value identity, branch polarity and exit dominance."""

from __future__ import annotations

import re
from typing import Any


def lexical_constraints(value: Any) -> dict[int | tuple[int, str], set[str]]:
    if value.category == "canonical-path":
        # Canonicalization already removed parent segments; their absence proves no containment.
        return {}
    return {
        (trace.origin, trace.path_route) if trace.path_route else trace.origin: {"path-contained"}
        for trace in value.traces
    }


def exits(analyzer: Any, node: Any) -> bool:
    """Recognize an unconditional return/throw, never an exit in a nested branch."""
    if node is None:
        return False
    if node.type in {
        "return_statement",
        "return_expression",
        "throw_statement",
        "throw_expression",
        "control_transfer_statement",
        "jump_expression",
    }:
        return bool(re.match(r"\s*(?:return|throw)\b", analyzer.text(node)))
    if node.type in {"block", "statements", "function_body"}:
        return any(
            exits(analyzer, part)
            for part in node.named_children
            if part.type not in {"if_statement", "if_expression"}
        )
    return False


def _negated_operand(analyzer: Any, expression: Any) -> Any:
    if expression is None or expression.type not in {"unary_expression", "prefix_expression"}:
        return None
    operator = expression.child_by_field_name("operator") or expression.child_by_field_name("operation")
    if operator is None or analyzer.text(operator).strip() != "!":
        return None
    return (
        expression.child_by_field_name("operand")
        or expression.child_by_field_name("argument")
        or expression.child_by_field_name("target")
    )


def receiver_negated(analyzer: Any, node: Any) -> bool:
    """Predicate negation attached by Kotlin/Swift to the head of a receiver chain."""
    negated = False
    while node is not None:
        node = analyzer.unwrap(node)
        if node is None:
            break
        operator = node.child_by_field_name("operator")
        if node.type == "unary_expression" and operator is not None and analyzer.text(operator) == "!!":
            # Kotlin's postfix non-null assertion is transparent, not two
            # logical negations, and can wrap a receiver carrying the real !.
            node = node.child_by_field_name("argument")
            continue
        operand = _negated_operand(analyzer, node)
        if operand is not None:
            negated = not negated
            node = operand
        elif node.type in {"navigation_expression", "postfix_expression", "call_expression"}:
            # Only the target/callee: an argument, suffix or binary operand
            # cannot supply polarity for its containing method invocation.
            node = node.child_by_field_name("target") or next(iter(node.named_children), None)
        else:
            break
    return negated


def path_predicate(
    analyzer: Any, node: Any, frame: Any, *, positive: bool = True
) -> dict[int | tuple[int, str], set[str]]:
    node = analyzer.unwrap(node)
    if node is None:
        return {}
    text = analyzer.text(node).strip()
    left = node.child_by_field_name("left") or node.child_by_field_name("lhs")
    right = node.child_by_field_name("right") or node.child_by_field_name("rhs")
    if node.type == "in_expression" and len(node.named_children) == 2:
        left, right = node.named_children
    if left is not None and right is not None:
        operator = analyzer.raw[left.end_byte : right.start_byte].decode().strip()
        # A positive conjunction or negative disjunction establishes both predicates.
        if (operator == "&&" and positive) or (operator == "||" and not positive):
            if re.search(r"\bfalse\b", text) and positive:
                return {}
            result = path_predicate(analyzer, left, frame, positive=positive)
            for origin, checks in path_predicate(analyzer, right, frame, positive=positive).items():
                result.setdefault(origin, set()).update(checks)
            return result
        if operator in {"==", "!="} and analyzer.text(right).strip() in {"true", "false"}:
            polarity = positive == (analyzer.text(right).strip() == "true")
            return path_predicate(
                analyzer, left, frame, positive=polarity if operator == "==" else not polarity
            )
        if operator in {"in", "!in"} and analyzer.literal(left) == ".." and positive == (operator == "!in"):
            value = analyzer.value(right, frame)
            return lexical_constraints(value)
        return {}

    # A leading bang in the text of a binary condition does not negate the
    # complete condition. Classify conjunction/disjunction before unary nodes.
    operand = _negated_operand(analyzer, node)
    if operand is not None:
        return path_predicate(analyzer, operand, frame, positive=not positive)
    call = analyzer.call(node)
    if call is None or len(call.args) != 1:
        return {}
    receiver = call.receiver
    if receiver_negated(analyzer, receiver):
        positive = not positive
    value = analyzer.value(receiver, frame)
    # Rejecting every '..' component is supported; checking only '../' misses a bare '..'.
    if call.name == "contains" and analyzer.literal(call.args[0]) == ".." and not positive:
        return lexical_constraints(value)
    if not positive or call.name not in {"startsWith", "hasPrefix"} or value.category != "canonical-path":
        return {}
    prefix = call.args[0]
    prefix_value = analyzer.value(prefix, frame)
    if prefix_value.traces:
        return {}  # The intended root must not itself be externally controlled.
    literal = analyzer.literal(prefix)
    if literal is not None:
        boundary = literal.startswith("/") and literal.endswith("/") and literal != "/"
    else:
        # Prefix equality without a separator also accepts sibling directories (root-evil).
        prefix_text = analyzer.text(prefix)
        boundary = bool(re.search(r'(?:\+\s*(?:File\.separator|"/"))\s*$', prefix_text))
        boundary &= bool(
            re.search(
                r"canonicalPath|getCanonicalPath\(|standardizedFileURL\.path|resolvingSymlinksInPath\(\)\.path",
                prefix_text,
            )
        )
    return (
        {(trace.origin, trace.path_route): {"path-contained"} for trace in value.traces if trace.path_route}
        if boundary
        else {}
    )
