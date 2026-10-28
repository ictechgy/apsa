from __future__ import annotations

import subprocess
import sys

import pytest

from mobile_audit.source_context import plist_references, tokens


@pytest.mark.parametrize(
    "source",
    ["/* " * 1000, '"' + '\\"' * 1000, "'" + "\\'" * 1000, '"""no closing delimiter'],
)
def test_unterminated_declarations_fail_explicitly(source: str) -> None:
    with pytest.raises(ValueError, match="Unterminated source declaration"):
        tokens(source)


def test_literal_comment_markers_and_line_locations_remain_opaque() -> None:
    source = (
        "/* ignored\ncomment */\nimplementation(\"g:a:1.0\") // ignored\n\"/* text */\"\n'''line1\nline2'''"
    )
    assert tokens(source) == [
        ("code", "implementation", 3),
        ("code", "(", 3),
        ("string", '"g:a:1.0"', 3),
        ("code", ")", 3),
        ("string", '"/* text */"', 4),
        ("string", "'''line1\nline2'''", 5),
    ]


def test_pbxproj_stream_keeps_existing_byte_and_declaration_bounds() -> None:
    references, warnings = plist_references([("App.xcodeproj/project.pbxproj", "; " * 200_001)])
    assert references == {}
    assert warnings == []


def test_malformed_pbxproj_does_not_discard_another_projects_reference() -> None:
    references, warnings = plist_references(
        [
            ("Broken.xcodeproj/project.pbxproj", "/* no closing delimiter"),
            ("Valid.xcodeproj/project.pbxproj", 'INFOPLIST_FILE = "Config/Release.plist";'),
        ]
    )
    assert list(references) == ["Config/Release.plist"]
    assert references["Config/Release.plist"] == [{"path": "Valid.xcodeproj/project.pbxproj", "line": 1}]
    assert len(warnings) == 1 and "Broken.xcodeproj/project.pbxproj" in warnings[0]


def test_large_unclosed_comment_finishes_with_explicit_partial_reason() -> None:
    code = (
        "from mobile_audit.source_context import tokens\n"
        "try: tokens('/* ' * 100000)\n"
        "except ValueError as error: print(error)\n"
        "else: raise AssertionError('malformed source silently accepted')\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stderr
    assert "Unterminated source declaration comment" in result.stdout
