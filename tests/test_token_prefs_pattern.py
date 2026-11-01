"""STORAGE-TOKEN-PREFS stays linear on crafted input and keeps its ordinary matches.

The pattern bounds each line of a `UserDefaults` chain, the number of
continuation lines and the distance to the credential word, and commits to the
first `.set` on a line, so no crafted file makes a scan quadratic.
"""

from __future__ import annotations

import re
import time

import pytest

from mobile_audit.rules import rules

RULE = next(rule for rule in rules() if rule["id"] == "STORAGE-TOKEN-PREFS")
PATTERN = re.compile(RULE["pattern"], 0 if RULE.get("case_sensitive") else re.I)


def matched_lines(text: str) -> list[int]:
    return [text.count("\n", 0, match.start()) + 1 for match in PATTERN.finditer(text)]


def repeat(unit: str, size: int) -> str:
    return unit * (size // len(unit))


CRAFTED = {
    "one-receiver-many-set-calls": lambda size: "UserDefaults" + repeat(".set(x)", size),
    "continuation-lines": lambda size: repeat("UserDefaults.standard\n    .x", size),
    "receivers-on-one-line": lambda size: repeat("UserDefaults.set(x)", size),
    "receivers-on-continuation-lines": lambda size: repeat("UserDefaults.set(" * 11 + "\n.", size),
    "editor-calls": lambda size: repeat("putString(", size),
    "objective-c-receivers": lambda size: repeat("NSUserDefaults setObject: x", size),
    "trailing-whitespace": lambda size: "putString" + " " * size,
}


@pytest.mark.parametrize("shape", sorted(CRAFTED))
def test_token_preference_pattern_is_linear_on_crafted_input(shape):
    # Small inputs fail a quadratic or cubic pattern in seconds rather than minutes.
    for size, budget in ((5_000, 0.05), (25_000, 0.25), (200_000, 1.0)):
        text = CRAFTED[shape](size)
        started = time.perf_counter()
        assert matched_lines(text) == []
        assert time.perf_counter() - started < budget, (shape, size)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ('UserDefaults.standard.set(token, forKey: "authToken")', [1]),
        ('UserDefaults.standard.setValue(token, forKey: "authToken")', [1]),
        ('UserDefaults(suiteName: "group.example")?.set(secret, forKey: "k")', [1]),
        ('UserDefaults.standard\n    .set(token, forKey: "sessionToken")', [1]),
        ('UserDefaults\n    .standard\n    .set(password, forKey: "pw")', [1]),
        ("UserDefaults\n  .standard\n  .dictionaryRepresentation()\n  .description\n  .set(token)", [1]),
        (
            'UserDefaults.standard.set(true, forKey: "a")\nUserDefaults.standard\n    .set(token, forKey: "t")',
            [2],
        ),
        ('UserDefaults.standard.set(true, forKey: "a"); UserDefaults.standard.set(token, forKey: "t")', [1]),
        ('[[NSUserDefaults standardUserDefaults] setObject:token forKey:@"authToken"];', [1]),
        ('[[NSUserDefaults standardUserDefaults] setValue:session forKey:@"s"];', [1]),
        ('[[NSUserDefaults standardUserDefaults] setObject:\n    token forKey:@"authToken"];', [1]),
        ('prefs.edit().putString("token", token).apply()', [1]),
        ('editor.setString("password", value)', [1]),
        ('UserDefaults.standard.set(true, forKey: "onboarded")', []),
        ('[[NSUserDefaults standardUserDefaults] setBool:YES forKey:@"onboarded"];', []),
        ("UserDefaults.standard; let token = 1", []),
        ("UserDefaults.standard\nlet token = value", []),
        ('UserDefaults.standard.set(value, forKey: "k")\nlet token = value', []),
    ],
)
def test_token_preference_pattern_keeps_ordinary_matches(text, expected):
    assert matched_lines(text) == expected
