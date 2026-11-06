"""Natural stored String aliases preserve readonly extension-query state."""

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


CASES = [
    (kind, receiver, alias_first)
    for kind in ("String", "String?", "Text", "Text?")
    for receiver in ("q", "this.q")
    for alias_first in ((True, False) if kind.startswith("Text") else (True,))
]


def _source(kind, receiver, alias_first):
    header = (
        "package storedalias58\n"
        "import android.content.Intent\n"
        "import android.database.sqlite.SQLiteDatabase\n"
    )
    alias = "typealias Text = kotlin.String\n" if kind.startswith("Text") else ""
    access = "?." if kind.endswith("?") else "."
    declarations = (
        'fun String.bound(db: SQLiteDatabase) { db.execSQL("SELECT " + this) }\n'
        "class Storage(val intent: Intent, val db: SQLiteDatabase) {\n"
        f' val q: {kind} = intent.getStringExtra("fresh-key") ?: ""\n'
        f" fun inspect() {{ {receiver}{access}bound(db) }}\n"
        "}\n"
    )
    return header + (alias + declarations if alias_first else declarations + alias)


@pytest.mark.parametrize("kind,receiver,alias_first", CASES)
def test_stored_string_alias_boundary_is_readonly(kind, receiver, alias_first, monkeypatch):
    files = [("Fresh.kt", _source(kind, receiver, alias_first))]
    expected = sa.analyze_sources(files)
    boundary = NativeFlow.kotlin_extension_receiver_unavailable
    active = False
    observed = []

    @functools.wraps(boundary)
    def query(flow, analyzer, call, value, frame):
        nonlocal active
        before = _snapshot((flow, analyzer, frame))
        active = True
        try:
            result = boundary(flow, analyzer, call, value, frame)
        finally:
            active = False
        assert _snapshot((flow, analyzer, frame)) == before
        if call.name == "bound" and value.traces:
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
                assert not active, f"stored alias query entered {_entry}"
                return _original(*args, **kwargs)

            monkeypatch.setattr(cls, method, guarded)
    assert sa.analyze_sources(files) == expected
    assert observed and all(observed)


def test_ordinary_alias_proof_keeps_default_cache_mode(monkeypatch):
    boundary = NativeFlow.kotlin_extension_receiver_unavailable
    observed = []

    def query(flow, analyzer, call, value, frame):
        if call.name == "bound" and value.traces and not observed:
            before = dict(flow.type_parameter_cache)
            library = sa.Analyzer.library_reference_type
            depth = 0

            def ordinary(self, *args, **kwargs):
                nonlocal depth
                if depth == 0:
                    assert "cache" not in kwargs
                else:
                    assert kwargs.get("cache", True) is True
                depth += 1
                try:
                    return library(self, *args, **kwargs)
                finally:
                    depth -= 1

            with monkeypatch.context() as normal:
                normal.setattr(sa.Analyzer, "library_reference_type", ordinary)
                assert analyzer.library_reference_type(
                    "Text", call.node, "kotlin.String", default_import=True
                )
            assert flow.type_parameter_cache != before
            observed.append(True)
        return boundary(flow, analyzer, call, value, frame)

    monkeypatch.setattr(NativeFlow, "kotlin_extension_receiver_unavailable", query)
    sa.analyze_sources([("Fresh.kt", _source("Text", "q", True))])
    assert observed
