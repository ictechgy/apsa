from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

import psutil

from . import jobs
from .audit import scan
from .core import redact
from .runtime import run
from .store import Store


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main() -> None:
    store = Store(Path(sys.argv[1]))
    identifier = sys.argv[2]
    signal.signal(signal.SIGTERM, interrupted)
    try:
        row = jobs.get(store, identifier, private=True)
        if row["state"] in jobs.TERMINAL:
            return
        jobs.update(
            store,
            identifier,
            state="running",
            pid=os.getpid(),
            process_started=psutil.Process().create_time(),
        )
        payload = row["payload"]
        if payload["kind"] == "scan":

            def progress(stage, percent):
                jobs.update(store, identifier, stage=stage, progress=percent)

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
            )
        else:
            jobs.update(store, identifier, stage="device-scenario", progress=10)
            report = run(
                store,
                Path(payload["scenario"]),
                payload["report_id"],
                screenshots=payload.get("screenshots", False),
                scenario=payload.get("scenario_value"),
            )
        jobs.update(
            store, identifier, state="completed", progress=100, stage="completed", report_id=report["id"]
        )
    except KeyboardInterrupt:
        jobs.update(store, identifier, state="cancelled", stage="cancelled")
    except Exception as error:
        jobs.update(store, identifier, state="failed", stage="failed", error=redact(str(error))[:800])
    finally:
        store.close()


if __name__ == "__main__":
    main()
