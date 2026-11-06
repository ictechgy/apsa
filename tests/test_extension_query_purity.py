"""The actual Kotlin extension boundary reads declarations without publishing query state."""

from __future__ import annotations

import dataclasses
import enum
import functools
import hashlib
import json

import pytest

from mobile_audit import source_analysis as sa
from mobile_audit.native_flow import NativeFlow

HEADER = (
    "package synthetic.reviewpurity\n"
    "import android.content.Intent\n"
    "import android.database.sqlite.SQLiteDatabase\n"
)
INPUT = '(intent.getStringExtra("q") ?: "")'
MEMBER = HEADER + (
    "class MemberExtension(private val db: SQLiteDatabase) {\n"
    '    fun String.go() { db.execSQL("SELECT " + this) }\n'
    f"    fun run(intent: Intent) {{ {INPUT}.go() }}\n"
    "}\n"
)
CASES = [
    ("member", [("Fresh.kt", MEMBER)]),
    (
        "top-level",
        [("Top.kt", HEADER + "fun String.go() {}\n" + f"fun run(intent: Intent) {{ {INPUT}.go() }}\n")],
    ),
    (
        "inherited-member",
        [
            (
                "Inherited.kt",
                HEADER
                + "open class Base { fun String.go() {} }\n"
                + f"class Child : Base() {{ fun run(intent: Intent) {{ {INPUT}.go() }} }}\n",
            )
        ],
    ),
    (
        "same-package",
        [
            ("Caller.kt", HEADER + f"fun run(intent: Intent) {{ {INPUT}.go() }}\n"),
            ("Extension.kt", "package synthetic.reviewpurity\nfun String.go() {}\n"),
        ],
    ),
    (
        "imported-alias",
        [
            (
                "Caller.kt",
                HEADER + "import ext.go as hop\n" + f"fun run(intent: Intent) {{ {INPUT}.hop() }}\n",
            ),
            ("Extension.kt", "package ext\ntypealias Text = String\nfun Text.go() {}\n"),
        ],
    ),
    (
        "unimported-package",
        [
            ("Caller.kt", HEADER + f"fun run(intent: Intent) {{ {INPUT}.go() }}\n"),
            ("Extension.kt", "package ext\nfun String.go() {}\n"),
        ],
    ),
    (
        "private-other-file",
        [
            ("Caller.kt", HEADER + "import ext.go\n" + f"fun run(intent: Intent) {{ {INPUT}.go() }}\n"),
            ("Extension.kt", "package ext\nprivate fun String.go() {}\n"),
        ],
    ),
    (
        "unrelated-member",
        [
            (
                "Unrelated.kt",
                HEADER
                + "class Other { fun String.go() {} }\n"
                + f"fun run(intent: Intent) {{ {INPUT}.go() }}\n",
            )
        ],
    ),
    (
        "source-String",
        [
            (
                "SourceType.kt",
                HEADER
                + "class String\nfun String.go() {}\n"
                + f"fun run(intent: Intent) {{ {INPUT}.go() }}\n",
            )
        ],
    ),
    (
        "incompatible-bound",
        [
            (
                "Bound.kt",
                HEADER + "fun <T : Number> T.go() {}\n" + f"fun run(intent: Intent) {{ {INPUT}.go() }}\n",
            )
        ],
    ),
    (
        "object-scope",
        [
            (
                "Scoped.kt",
                HEADER
                + "class Host { fun String.go() {} }\n"
                + f"fun run(intent: Intent) {{ with(Host()) {{ {INPUT}.go() }} }}\n",
            )
        ],
    ),
]


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


@pytest.mark.parametrize(("case", "files"), CASES, ids=[case for case, _files in CASES])
def test_actual_extension_boundary_is_read_only(case, files, monkeypatch):
    expected = sa.analyze_sources(files)
    if case == "member":
        assert hashlib.sha256(
            json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest() == ("b24c4d3e3ab3ddf4122fc59061e07fd07fff4284ce5c225a718a89f84de52d7c")
    active = False
    observations = []
    boundary = NativeFlow.kotlin_extension_receiver_unavailable

    @functools.wraps(boundary)
    def checked(flow, analyzer, call, receiver, frame):
        nonlocal active
        before = _snapshot((flow, analyzer, frame))
        frame_before = _snapshot(frame)
        active = True
        try:
            result = boundary(flow, analyzer, call, receiver, frame)
        finally:
            active = False
        assert _snapshot(frame) == frame_before
        assert _snapshot((flow, analyzer, frame)) == before, case
        if call.name in {"go", "hop"} and receiver.traces:
            observations.append(result)
        return result

    monkeypatch.setattr(NativeFlow, "kotlin_extension_receiver_unavailable", checked)
    for cls, names in [
        (
            sa.Analyzer,
            [
                "value",
                "visit",
                "start_function",
                "source",
                "known_value_type",
                "kotlin_parameterless_callback",
                "kotlin_parameterless_callback_result",
            ],
        ),
        (NativeFlow, ["call", "resolve", "partial"]),
        (sa.Frame, ["__init__"]),
    ]:
        for name in names:
            original = getattr(cls, name)

            @functools.wraps(original)
            def guarded(*args, _original=original, _entry=cls.__name__ + "." + name, **kwargs):
                assert not active, f"extension query entered {_entry}"
                return _original(*args, **kwargs)

            monkeypatch.setattr(cls, name, guarded)
    assert sa.analyze_sources(files) == expected
    assert observations


def test_ordinary_extension_declaration_helpers_still_publish_caches(monkeypatch):
    boundary = NativeFlow.kotlin_extension_receiver_unavailable
    observed = []

    def inspect(flow, analyzer, call, receiver, frame):
        result = boundary(flow, analyzer, call, receiver, frame)
        if call.name == "go" and analyzer.scope == "run" and not observed:
            assert result
            bodies = analyzer.class_bodies(call.node, cache=False)
            assert bodies
            key = (id(analyzer), bodies[0].id)
            assert key not in flow.owner_cache
            assert not flow.ancestry_cache
            assert not analyzer.enclosing_bodies
            owner = NativeFlow.owner
            lexical_type = NativeFlow.lexical_type

            # The ordinary route retains positional wrapper compatibility as
            # well as its default cache publication.
            def positional_owner(self, source, node):
                return owner(self, source, node)

            def positional_lexical_type(self, source, declared, use=None):
                return lexical_type(self, source, declared, use)

            with monkeypatch.context() as ordinary:
                ordinary.setattr(NativeFlow, "owner", positional_owner)
                ordinary.setattr(NativeFlow, "lexical_type", positional_lexical_type)
                assert analyzer.project_extension(
                    call.name,
                    call,
                    {"String", "CharSequence", "Any", "Comparable", "Serializable"},
                    visible=True,
                    standard_string=True,
                )
            assert key in flow.owner_cache
            assert analyzer.enclosing_bodies
            enclosing_owner = flow.owner_cache[key]
            assert flow.project_ancestry(enclosing_owner) is flow.ancestry_cache[enclosing_owner]
            assert flow.type_scope_cache
            observed.append(True)
        return result

    monkeypatch.setattr(NativeFlow, "kotlin_extension_receiver_unavailable", inspect)
    sa.analyze_sources([("Fresh.kt", MEMBER)])
    assert observed
