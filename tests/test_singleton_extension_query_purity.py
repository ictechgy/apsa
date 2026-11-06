"""Natural singleton scope queries preserve state, including cold declaration order."""

import dataclasses
import enum
import functools

import pytest

from mobile_audit import source_analysis as sa
from mobile_audit.native_flow import NativeFlow


def _snapshot(root):
    """Include every retained attribute, including aliases and recursive flow references."""
    seen = {}

    def walk(value):
        if isinstance(value, enum.Enum):
            return type(value).__name__, value.value
        if value is None or isinstance(value, (bool, int, float, str, bytes)):
            return value
        if type(value).__module__.startswith("tree_sitter"):
            return (
                type(value).__name__,
                getattr(value, "type", None),
                getattr(value, "start_byte", None),
                getattr(value, "end_byte", None),
            )
        identity = id(value)
        if identity in seen:
            return "ref", seen[identity]
        seen[identity] = len(seen)
        if isinstance(value, dict):
            return "dict", tuple((walk(key), walk(item)) for key, item in value.items())
        if isinstance(value, (set, frozenset)):
            return type(value).__name__, tuple(sorted((walk(item) for item in value), key=repr))
        if isinstance(value, (list, tuple)):
            return type(value).__name__, tuple(walk(item) for item in value)
        if hasattr(value, "__dict__"):
            return type(value).__name__, walk(vars(value))
        if dataclasses.is_dataclass(value):
            return type(value).__name__, tuple(
                (field.name, walk(getattr(value, field.name))) for field in dataclasses.fields(value)
            )
        return type(value).__name__, repr(value)

    return walk(root)


HEADS = [
    ("zero", "", "", ""),
    ("incompatible-literal", "arg: Int", "arg: String", '"literal"'),
    ("string-literal", "arg: String", "arg: String", '"literal"'),
    ("any-literal", "arg: Any", "arg: String", '"literal"'),
    ("int-literal", "arg: Int", "arg: Int", "7"),
    ("long-literal", "arg: Long", "arg: Long", "7L"),
    ("incompatible-number", "arg: String", "arg: Int", "7"),
]


def _source(ordinary, extension, argument, declarations_first):
    declarations = f"object Host {{ fun go({ordinary}) {{}}; fun String.go({extension}) {{}} }}\n"
    caller = (
        f'fun scan(intent: Intent) {{ with(Host) {{ (intent.getStringExtra("q") ?: "").go({argument}) }} }}\n'
    )
    return "package singleton57\nimport android.content.Intent\n" + (
        declarations + caller if declarations_first else caller + declarations
    )


def _assert_query_pure(files, monkeypatch):
    expected = sa.analyze_sources(files)
    boundary = NativeFlow.kotlin_extension_receiver_unavailable
    active = False
    observed = []

    @functools.wraps(boundary)
    def query(flow, analyzer, call, receiver, frame):
        nonlocal active
        before = _snapshot((flow, analyzer, frame))
        active = True
        try:
            result = boundary(flow, analyzer, call, receiver, frame)
        finally:
            active = False
        assert _snapshot((flow, analyzer, frame)) == before
        if call.name == "go" and receiver.traces:
            observed.append(result)
        return result

    monkeypatch.setattr(NativeFlow, "kotlin_extension_receiver_unavailable", query)
    for cls, methods in (
        (sa.Frame, ("__init__",)),
        (sa.Analyzer, ("value", "visit", "start_function", "source", "known_value_type")),
        (NativeFlow, ("call", "resolve", "partial")),
    ):
        for method in methods:
            original = getattr(cls, method)

            @functools.wraps(original)
            def guarded(*args, _original=original, _entry=cls.__name__ + "." + method, **kwargs):
                assert not active, f"singleton query entered {_entry}"
                return _original(*args, **kwargs)

            monkeypatch.setattr(cls, method, guarded)
    assert sa.analyze_sources(files) == expected
    assert observed


@pytest.mark.parametrize("declarations_first", [True, False], ids=["warm-order", "cold-order"])
@pytest.mark.parametrize("_case,ordinary,extension,argument", HEADS, ids=[row[0] for row in HEADS])
def test_singleton_query_uses_no_frames_or_retained_state(
    _case, ordinary, extension, argument, declarations_first, monkeypatch
):
    _assert_query_pure(
        [("Fresh.kt", _source(ordinary, extension, argument, declarations_first))], monkeypatch
    )


@pytest.mark.parametrize("kind,literal", [("Int", "1"), ("Long", "1L")])
def test_top_level_numeric_extension_query_allocates_no_frame(kind, literal, monkeypatch):
    source = (
        "package singleton57\nimport android.content.Intent\n"
        f"fun String.go(arg: {kind}) {{}}\n"
        "fun scan(intent: Intent) { "
        f'(intent.getStringExtra("q") ?: "").go({literal})'
        " }\n"
    )
    _assert_query_pure([("Fresh.kt", source)], monkeypatch)


def test_ordinary_argument_proof_retains_default_cache_call_shape(monkeypatch):
    boundary = NativeFlow.kotlin_extension_receiver_unavailable
    checked = []

    def inspect(flow, analyzer, call, receiver, frame):
        result = boundary(flow, analyzer, call, receiver, frame)
        if call.name != "go" or not receiver.traces or checked:
            return result
        ordinary = next(
            target for target in flow.by_name["go"] if flow.lexical_visible(analyzer, target, call)
        )
        library = sa.Analyzer.library_reference_type
        argument = sa.Analyzer.established_argument_type

        def compatible_library(self, *args, **kwargs):
            assert "cache" not in kwargs
            return library(self, *args, **kwargs)

        def compatible_argument(self, *args, **kwargs):
            assert "cache" not in kwargs
            return argument(self, *args, **kwargs)

        with monkeypatch.context() as ordinary_mode:
            ordinary_mode.setattr(sa.Analyzer, "library_reference_type", compatible_library)
            ordinary_mode.setattr(sa.Analyzer, "established_argument_type", compatible_argument)
            assert analyzer.established_call_arguments(ordinary.analyzer, ordinary.node, call, frame=frame)
        assert flow.type_scope_cache
        checked.append(True)
        return result

    monkeypatch.setattr(NativeFlow, "kotlin_extension_receiver_unavailable", inspect)
    sa.analyze_sources([("Fresh.kt", _source("arg: String", "arg: String", '"literal"', False))])
    assert checked


EXTENSION_REASON = "Kotlin project extension receiver flow unavailable"


@pytest.mark.parametrize("declarations_first", [True, False], ids=["warm-order", "cold-order"])
@pytest.mark.parametrize("_case,ordinary,extension,argument", HEADS, ids=[row[0] for row in HEADS])
def test_explicit_string_extension_keeps_its_affected_boundary(
    _case, ordinary, extension, argument, declarations_first, monkeypatch
):
    source = _source(ordinary, extension, argument, declarations_first)
    files = [("Fresh.kt", source)]
    boundary = NativeFlow.kotlin_extension_receiver_unavailable
    answers = []

    def observe(flow, analyzer, call, receiver, frame):
        result = boundary(flow, analyzer, call, receiver, frame)
        if call.name == "go" and receiver.traces:
            answers.append(result)
        return result

    monkeypatch.setattr(NativeFlow, "kotlin_extension_receiver_unavailable", observe)
    _assert_query_pure(files, monkeypatch)
    assert answers and all(answers)
    report = sa.analyze_sources(files)
    native = report["metadata"]["native_flow"]
    affected_line = next(index for index, line in enumerate(source.splitlines(), 1) if "with(Host)" in line)
    details = [row for row in native["partial_details"] if row["reason"] == EXTENSION_REASON]
    assert details and all(
        row["path"] == "Fresh.kt"
        and row["line"] == affected_line
        and row["call"] == "go"
        and row["kind"] == "precision"
        and row["scope"] == "file-call"
        and "AST-SQL-CONCAT" in row["rule_ids"]
        for row in details
    )
    assert native["budget_reasons"] == []
    assert not report["findings"]
    assert next(row["state"] for row in report["coverage"] if row["rule_id"] == "AST-SQL-CONCAT") == "limited"


ORDINARY_CONTROLS = [
    (
        "explicit-Host",
        "object Host { fun String.go() {}; fun go() {} }\n"
        "fun scan(intent: Intent) { with(Host) { Host.go() } }\n",
    ),
    (
        "receiverless-Host",
        "object Host { fun String.go() {}; fun go() {} }\nfun scan(intent: Intent) { with(Host) { go() } }\n",
    ),
    (
        "receiverless-builder",
        "object Host { fun StringBuilder.go(arg: String) {}; fun go(arg: String) {} }\n"
        'fun scan(intent: Intent) { val q = buildString { with(Host) { go("literal") } } }\n',
    ),
]


@pytest.mark.parametrize("case,body", ORDINARY_CONTROLS, ids=[row[0] for row in ORDINARY_CONTROLS])
def test_ordinary_and_receiverless_heads_keep_their_existing_precedence(case, body, monkeypatch):
    visibility = sa.Analyzer.active_object_extension_visibility
    answers = []

    def observe(analyzer, target, call, receivers, **kwargs):
        result = visibility(analyzer, target, call, receivers, **kwargs)
        if call.name == "go":
            answers.append((call.receiver is None, result))
        return result

    monkeypatch.setattr(sa.Analyzer, "active_object_extension_visibility", observe)
    report = sa.analyze_sources(
        [("Fresh.kt", "package visibility57\nimport android.content.Intent\n" + body)]
    )
    assert EXTENSION_REASON not in report["metadata"]["native_flow"]["reasons"]
    assert report["metadata"]["native_flow"]["budget_reasons"] == []
    assert report["findings"] == []
    if case == "receiverless-builder":
        assert (True, False) in answers


@pytest.mark.parametrize("declarations_first", [True, False], ids=["warm-order", "cold-order"])
@pytest.mark.parametrize(
    "parameters,argument", [("", ""), ("arg: String", '"literal"'), ("arg: Int", "7"), ("arg: Long", "7L")]
)
def test_receiverless_ordinary_competition_readonly_query_still_checks_nested_helpers(
    declarations_first, parameters, argument, monkeypatch
):
    declarations = f"object Host {{ fun StringBuilder.go({parameters}) {{}}; fun go({parameters}) {{}} }}\n"
    caller = f"fun scan(intent: Intent) {{ val q = buildString {{ with(Host) {{ go({argument}) }} }} }}\n"
    source = "package receiverless57\nimport android.content.Intent\n" + (
        declarations + caller if declarations_first else caller + declarations
    )
    files = [("Fresh.kt", source)]
    expected = sa.analyze_sources(files)
    visibility = sa.Analyzer.active_object_extension_visibility
    active = False
    queried = []
    helpers = []

    def inspect(analyzer, target, call, receivers, **kwargs):
        nonlocal active
        if call.name == "go" and call.receiver is None and not queried:
            before = _snapshot((analyzer.native_flow, analyzer))
            active = True
            try:
                result = visibility(analyzer, target, call, receivers, lexical=kwargs["lexical"], cache=False)
            finally:
                active = False
            assert result is False
            assert _snapshot((analyzer.native_flow, analyzer)) == before
            queried.append(result)
        return visibility(analyzer, target, call, receivers, **kwargs)

    monkeypatch.setattr(sa.Analyzer, "active_object_extension_visibility", inspect)
    for method in ("literal_string_argument_conflict", "established_call_arguments"):
        original = getattr(sa.Analyzer, method)

        @functools.wraps(original)
        def observed(*args, _original=original, _entry=method, **kwargs):
            if active:
                assert kwargs.get("cache") is False
                assert kwargs.get("frame") is None
                helpers.append(_entry)
            return _original(*args, **kwargs)

        monkeypatch.setattr(sa.Analyzer, method, observed)
    for cls, methods in (
        (sa.Frame, ("__init__",)),
        (sa.Analyzer, ("value", "visit", "start_function", "source", "known_value_type")),
        (NativeFlow, ("call", "resolve", "partial")),
    ):
        for method in methods:
            original = getattr(cls, method)

            @functools.wraps(original)
            def guarded(*args, _original=original, _entry=cls.__name__ + "." + method, **kwargs):
                assert not active, f"receiverless query entered {_entry}"
                return _original(*args, **kwargs)

            monkeypatch.setattr(cls, method, guarded)
    assert sa.analyze_sources(files) == expected
    assert queried
    assert set(helpers) == {"literal_string_argument_conflict", "established_call_arguments"}
    assert EXTENSION_REASON not in expected["metadata"]["native_flow"]["reasons"]
