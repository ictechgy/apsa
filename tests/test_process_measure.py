"""Owned process execution must preserve failures and abstain from unavailable RSS."""

from __future__ import annotations

import sys

import psutil

from benchmarks.process_measure import RssSampler, capture


def test_missing_process_does_not_claim_zero_memory(monkeypatch):
    def denied(_):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "Process", denied)
    result = RssSampler(42).result()
    assert result["state"] == "unmeasured"
    assert result["sampled_max_rss_bytes"] is None


def test_owned_child_timeout_is_a_failed_measurement_with_bounded_output(tmp_path):
    result = capture(
        [sys.executable, "-c", "import time; print('fresh', flush=True); time.sleep(2)"],
        tmp_path,
        {},
        timeout=1,
    )
    assert result["incomplete"]
    assert result["status"] != 0
    assert result["stdout"] == "fresh\n"
    assert result["rss"]["state"] in {"measured", "unmeasured"}
    if result["rss"]["state"] == "measured":
        assert result["rss"]["samples"] > 0
        assert result["rss"]["sampled_max_rss_bytes"] > 0
