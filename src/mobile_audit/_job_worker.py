from __future__ import annotations

import os
import signal
import sys
from contextlib import contextmanager
from pathlib import Path

import psutil

from . import jobs
from .audit import scan
from .core import redact
from .runtime import run
from .store import Store


class JobCancelled(KeyboardInterrupt):
    """A committed cancellation request observed at a worker checkpoint."""


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


@contextmanager
def report_commit_signals():
    """Defer worker SIGTERM only during persistence and terminal job publication."""
    prior = (
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})
        if hasattr(signal, "pthread_sigmask")
        else None
    )
    try:
        yield
    finally:
        if prior is not None:
            signal.pthread_sigmask(signal.SIG_SETMASK, prior)


def main() -> None:
    store = Store(Path(sys.argv[1]))
    identifier = sys.argv[2]
    signal.signal(signal.SIGTERM, interrupted)
    claimed = False
    try:
        row = jobs.get(store, identifier, private=True)
        if not jobs.claim(store, identifier, os.getpid(), psutil.Process().create_time()):
            return
        claimed = True
        payload = row["payload"]

        def progress(stage, percent):
            if not jobs.update(store, identifier, stage=stage, progress=percent):
                raise JobCancelled

        original_save = store.save_report

        def commit_report(report: dict) -> dict:
            # Cancellation wins before persistence starts. Once a report commits,
            # publish its ID even if a later cancellation request arrives.
            with report_commit_signals():
                if not jobs.update(store, identifier, stage="evidence-report", progress=95):
                    raise JobCancelled
                saved = original_save(report)
                jobs.finish(store, identifier, "completed", report_id=saved["id"], persisted=True)
                return saved

        store.save_report = commit_report
        if payload["kind"] == "scan":
            report = scan(
                store,
                Path(payload["target"]),
                online=payload.get("online", False),
                sbom=Path(payload["sbom"]) if payload.get("sbom") else None,
                environment=payload.get("environment"),
                progress=progress,
                expected_target=Path(row["target"]),
                configuration=payload.get("configuration"),
                source_module=payload.get("source_module"),
                specs=payload.get("specs"),
                dependency_selection=payload.get("dependency_selection"),
                osv_policy=payload.get("osv_policy"),
                osv_query_mode=payload.get("osv_query_mode", "auto"),
                apk_set_device=payload.get("apk_set_device"),
                ipa_trust_policy=payload.get("ipa_trust_policy"),
            )
        else:
            progress("device-scenario", 10)
            report = run(
                store,
                Path(payload["scenario"]),
                payload["report_id"],
                screenshots=payload.get("screenshots", False),
                scenario=payload.get("scenario_value"),
                progress=progress,
            )
        jobs.finish(store, identifier, "completed", report_id=report["id"])
    except KeyboardInterrupt:
        if claimed:
            jobs.finish(store, identifier, "cancelled")
    except Exception as error:
        if claimed:
            jobs.finish(store, identifier, "failed", error=redact(str(error))[:800])
    finally:
        store.close()


if __name__ == "__main__":
    main()
