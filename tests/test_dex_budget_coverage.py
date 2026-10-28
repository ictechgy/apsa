from __future__ import annotations

import zipfile
from types import SimpleNamespace

import pytest
from androguard.core.dex import Operand

import mobile_audit.binary_analysis as binary


class Instruction:
    def __init__(self, *, proceed=False):
        self.proceed = proceed
        self.inspections = 0

    def get_name(self):
        return "invoke-virtual" if self.proceed else "nop"

    def get_operands(self, offset):
        self.inspections += 1
        if self.proceed:
            return [(Operand.KIND, 0, "Landroid/webkit/SslErrorHandler;->proceed()V")]
        return []


class Method:
    def __init__(self, *instructions):
        self.instructions = instructions
        self.yielded = 0

    def get_code(self):
        return SimpleNamespace(get_tries_size=lambda: 0)

    def get_instructions_idx(self):
        for index, instruction in enumerate(self.instructions):
            self.yielded += 1
            yield index * 2, instruction

    def get_class_name(self):
        return "Lfixture/Budgets;"

    def get_name(self):
        return "example"

    def get_descriptor(self):
        return "()V"


def fake_dex(monkeypatch, methods_by_raw):
    import androguard.core.dex

    def parser(raw):
        return SimpleNamespace(
            get_strings=lambda: [],
            get_classes=lambda: [SimpleNamespace(get_methods=lambda: methods_by_raw[raw])],
        )

    monkeypatch.setattr(binary, "_validate_dex", lambda raw: None)
    monkeypatch.setattr(androguard.core.dex, "DEX", parser)
    monkeypatch.setattr(androguard.core.dex, "determineNext", lambda ins, offset, method: [])


def test_per_method_cap_preserves_later_independent_finding(monkeypatch):
    oversized = Method(*(Instruction() for _ in range(5)))
    later = Method(Instruction(proceed=True))
    fake_dex(monkeypatch, {b"dex": [oversized, later]})
    monkeypatch.setattr(binary, "MAX_METHOD_INSTRUCTIONS", 2)
    remaining = {"methods": 5, "instructions": 10, "findings": 5}

    report = binary._analyze_dex(b"dex", "classes.dex", remaining)

    assert [finding["rule_id"] for finding in report["findings"]] == ["BINARY-WEBVIEW-SSL-BYPASS"]
    assert report["metadata"]["complete"] is False
    assert report["metadata"]["budget_reasons"] == ["per-method-instruction-limit"]
    assert report["metadata"]["methods_truncated"] == 1
    assert report["metadata"]["methods"] == 2
    assert report["metadata"]["instructions"] == 3
    assert remaining == {"methods": 3, "instructions": 7, "findings": 4}
    assert oversized.yielded == 3  # One lookahead proves that work was omitted.
    assert later.yielded == 1
    assert len(report["warnings"]) == 1


def test_many_oversized_methods_keep_global_work_and_diagnostics_bounded(monkeypatch):
    methods = [Method(*(Instruction() for _ in range(100))) for _ in range(20)]
    fake_dex(monkeypatch, {b"dex": methods})
    monkeypatch.setattr(binary, "MAX_METHOD_INSTRUCTIONS", 2)
    remaining = {"methods": 10, "instructions": 5, "findings": 10}

    report = binary._analyze_dex(b"dex", "classes.dex", remaining)

    assert report["metadata"]["budget_reasons"] == [
        "per-method-instruction-limit",
        "global-instruction-limit",
    ]
    assert report["metadata"]["methods_truncated"] == 3
    assert report["metadata"]["methods"] == 3
    assert report["metadata"]["instructions"] == 5
    assert [method.yielded for method in methods[:4]] == [3, 3, 2, 0]
    assert remaining["instructions"] == 0
    assert len(report["warnings"]) == 2


@pytest.mark.parametrize(
    ("limit", "first", "reason", "truncated", "instructions"),
    [
        ("methods", [Instruction()], "global-method-limit", 0, 1),
        ("instructions", [Instruction(), Instruction()], "global-instruction-limit", 1, 1),
        ("findings", [Instruction(proceed=True), Instruction()], "finding-limit", 1, 2),
    ],
)
def test_global_limits_have_distinct_reasons_and_stop_later_methods(
    monkeypatch, limit, first, reason, truncated, instructions
):
    later = Method(Instruction(proceed=True))
    fake_dex(monkeypatch, {b"dex": [Method(*first), later]})
    remaining = {"methods": 10, "instructions": 10, "findings": 10}
    remaining[limit] = 1

    report = binary._analyze_dex(b"dex", "classes.dex", remaining)

    assert report["metadata"]["complete"] is False
    assert report["metadata"]["budget_reasons"] == [reason]
    assert report["metadata"]["methods_truncated"] == truncated
    assert report["metadata"]["methods"] == 1
    assert report["metadata"]["instructions"] == instructions
    assert later.yielded == 0
    assert len(report["warnings"]) == 1
    if limit == "findings":
        assert len(report["findings"]) == 1
        assert first[1].inspections == 0


@pytest.mark.parametrize("limit", ["methods", "instructions", "findings", "per-method"])
def test_exact_final_boundary_is_complete(monkeypatch, limit):
    instruction = Instruction(proceed=limit == "findings")
    fake_dex(monkeypatch, {b"dex": [Method(instruction)]})
    remaining = {"methods": 10, "instructions": 10, "findings": 10}
    if limit == "per-method":
        monkeypatch.setattr(binary, "MAX_METHOD_INSTRUCTIONS", 1)
    else:
        remaining[limit] = 1

    report = binary._analyze_dex(b"dex", "classes.dex", remaining)

    assert report["metadata"]["complete"] is True
    assert report["metadata"]["budget_reasons"] == []
    assert report["metadata"]["methods_truncated"] == 0
    assert report["metadata"]["instructions"] == 1
    assert report["warnings"] == []


@pytest.mark.parametrize(
    ("constant", "reason"),
    [
        ("MAX_METHODS", "global-method-limit"),
        ("MAX_INSTRUCTIONS", "global-instruction-limit"),
        ("MAX_FINDINGS", "finding-limit"),
    ],
)
def test_global_budgets_are_shared_across_dex_entries(tmp_path, monkeypatch, constant, reason):
    first = Method(Instruction(proceed=constant == "MAX_FINDINGS"))
    second = Method(Instruction(proceed=True))
    fake_dex(monkeypatch, {b"first": [first], b"second": [second]})
    monkeypatch.setattr(binary, constant, 1)
    apk = tmp_path / "multidex.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", b"first")
        archive.writestr("classes2.dex", b"second")

    report = binary.analyze_binary(apk, {})

    first_metadata, second_metadata = report["metadata"]["dex"]
    assert first_metadata["complete"] is True
    assert first_metadata["budget_reasons"] == []
    assert second_metadata["complete"] is False
    assert second_metadata["budget_reasons"] == [reason]
    assert second_metadata["methods"] == second_metadata["instructions"] == 0
    assert second_metadata["methods_truncated"] == 0
    assert second.yielded == 0
    assert len(report["findings"]) == (1 if constant == "MAX_FINDINGS" else 0)
    assert all(row["state"] == "partial" for row in report["coverage"])
