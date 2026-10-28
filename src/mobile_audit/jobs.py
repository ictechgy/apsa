from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import psutil

from .core import now, uid
from .store import Store

TERMINAL = {"completed", "failed", "cancelled", "interrupted"}


class WorkerInspection(Enum):
    UNINSPECTABLE = "uninspectable"


def initialize(store: Store) -> None:
    store.db.execute("""CREATE TABLE IF NOT EXISTS jobs(
        id TEXT PRIMARY KEY, state TEXT, created TEXT, updated TEXT, target TEXT,
        payload TEXT, progress INTEGER, stage TEXT, pid INTEGER, process_started REAL,
        report_id TEXT, error TEXT)""")
    store.db.commit()


def update(store: Store, job_id: str, **fields) -> bool:
    permitted = {"state", "progress", "stage", "pid", "process_started", "report_id", "error"}
    if not fields or set(fields) - permitted:
        raise ValueError("Invalid job update")
    fields["updated"] = now()
    with store.db:
        changed = store.db.execute(
            "UPDATE jobs SET "
            + ",".join(f"{key}=?" for key in fields)
            + " WHERE id=? AND state IN ('queued','running') AND stage!='cancellation-requested'",
            (*fields.values(), job_id),
        )
        return changed.rowcount == 1


def claim(store: Store, job_id: str, pid: int, process_started: float) -> bool:
    """Only one worker may claim a queued job; cancellation wins if committed first."""
    with store.db:
        changed = store.db.execute(
            "UPDATE jobs SET state='running',pid=?,process_started=?,updated=? "
            "WHERE id=? AND state='queued' AND stage!='cancellation-requested'",
            (pid, process_started, now(), job_id),
        )
        return changed.rowcount == 1


def finish(
    store: Store,
    job_id: str,
    state: str,
    *,
    report_id: str | None = None,
    error: str = "",
    persisted: bool = False,
) -> bool:
    """Finish active work without overriding a committed cancellation or terminal state."""
    if state not in {"completed", "failed", "cancelled"}:
        raise ValueError("Invalid worker completion state")
    with store.db:
        if persisted:
            if (
                state != "completed"
                or not report_id
                or not store.db.execute("SELECT 1 FROM reports WHERE id=?", (report_id,)).fetchone()
            ):
                raise ValueError("Committed completion requires an existing report")
            changed = store.db.execute(
                "UPDATE jobs SET state='completed',stage='completed',progress=100,report_id=?,error='',updated=? "
                "WHERE id=? AND state='running'",
                (report_id, now(), job_id),
            )
            return changed.rowcount == 1
        changed = store.db.execute(
            "UPDATE jobs SET "
            "state=CASE WHEN stage='cancellation-requested' THEN 'cancelled' ELSE ? END,"
            "stage=CASE WHEN stage='cancellation-requested' THEN 'cancelled' ELSE ? END,"
            "progress=CASE WHEN stage!='cancellation-requested' AND ?='completed' THEN 100 ELSE progress END,"
            "report_id=CASE WHEN stage!='cancellation-requested' AND ?='completed' THEN ? ELSE NULL END,"
            "error=CASE WHEN stage!='cancellation-requested' AND ?='failed' THEN ? ELSE '' END,"
            "updated=? WHERE id=? AND state='running'",
            (state, state, state, state, report_id, state, error, now(), job_id),
        )
        return changed.rowcount == 1


def worker_process(row: dict) -> psutil.Process | WorkerInspection | None:
    if not row.get("pid") or not row.get("process_started"):
        return None
    try:
        process = psutil.Process(row["pid"])
        if abs(process.create_time() - row["process_started"]) > 0.01:
            return None
        argv = process.cmdline()
        if "mobile_audit._job_worker" not in argv or row["id"] not in argv:
            return None
        return process
    except psutil.AccessDenied:
        return WorkerInspection.UNINSPECTABLE
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return None


def get(store: Store, job_id: str, private=False) -> dict:
    initialize(store)
    row = store.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if row is None:
        raise ValueError("Job not found")
    result = dict(row)
    if (
        result["state"] == "queued"
        and not result["pid"]
        and (datetime.now(timezone.utc) - datetime.fromisoformat(result["created"])).total_seconds() > 120
    ):
        with store.db:
            store.db.execute(
                "UPDATE jobs SET state='interrupted',stage='launch-interrupted',error=?,updated=? "
                "WHERE id=? AND state='queued' AND pid IS NULL",
                ("Worker launch was interrupted; restart this audit.", now(), job_id),
            )
        result = dict(store.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())
    if result["state"] not in TERMINAL and result["pid"] and worker_process(result) is None:
        with store.db:
            store.db.execute(
                "UPDATE jobs SET "
                "state=CASE WHEN stage='cancellation-requested' THEN 'cancelled' ELSE 'interrupted' END,"
                "stage=CASE WHEN stage='cancellation-requested' THEN 'cancelled' ELSE 'worker-exited' END,"
                "error=CASE WHEN stage='cancellation-requested' THEN '' ELSE ? END,updated=? "
                "WHERE id=? AND state IN ('queued','running') AND pid IS ? AND process_started IS ?",
                (
                    "Worker exited before completion; no successful audit result is claimed.",
                    now(),
                    job_id,
                    result["pid"],
                    result["process_started"],
                ),
            )
        result = dict(store.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())
    if private:
        result["payload"] = json.loads(result["payload"])
    else:
        result["requested_target"] = json.loads(result["payload"]).get("requested_target", result["target"])
        if result.get("report_id"):
            from .core import report_incomplete

            result["audit_incomplete"] = report_incomplete(store.report(result["report_id"]))
        for key in ("payload", "pid", "process_started"):
            result.pop(key, None)
    return result


def start(store: Store, payload: dict) -> dict:
    payload = dict(payload)
    if payload.get("kind") == "runtime":
        from .core import read_json
        from .runtime import validate_scenario

        payload["scenario_value"] = validate_scenario(
            payload["scenario_value"] if "scenario_value" in payload else read_json(Path(payload["scenario"]))
        )
    initialize(store)
    if payload.get("kind") not in {"scan", "runtime"}:
        raise ValueError("Job kind must be scan or runtime")
    path = Path(payload["target"]).expanduser()
    target = str(path.resolve() if payload["kind"] == "scan" else path.absolute())
    if payload.get("expected_target") and payload["expected_target"] != target:
        raise ValueError("Authorized job input moved or became a symlink")
    payload = dict(
        payload, target=target, requested_target=str(Path(payload["target"]).expanduser().absolute())
    )
    if payload["kind"] == "scan":
        payload["expected_target"] = target
    job_id = uid("job")
    stamp = now()
    for row in store.db.execute("SELECT id FROM jobs WHERE state IN ('queued','running')").fetchall():
        get(store, row["id"])
    store.db.execute("BEGIN IMMEDIATE")
    try:
        active = store.db.execute("SELECT count(*) FROM jobs WHERE state IN ('queued','running')").fetchone()[
            0
        ]
        if active >= 2:
            raise ValueError("Two audits are already active in this home; wait or cancel a job")
        store.db.execute(
            "INSERT INTO jobs VALUES(?,?,?,?,?,?,?, ?,NULL,NULL,NULL,'')",
            (job_id, "queued", stamp, stamp, target, json.dumps(payload), 0, "queued"),
        )
        store.db.commit()
    except Exception:
        store.db.rollback()
        raise
    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-m", "mobile_audit._job_worker", str(store.home.resolve()), job_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name == "posix",
            cwd=store.home.resolve(),
        )
        # The child sets its own identity before entering running state. The parent
        # returns immediately and never keeps pipe handles to long-running work.
        try:
            update(store, job_id, pid=process.pid, process_started=psutil.Process(process.pid).create_time())
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            # The worker claims its own identity. Parent inspection failure is not
            # launch failure, and an unverified PID must not be recorded as dead.
            pass
    except OSError:
        update(store, job_id, state="failed", stage="launch-failed", error="Could not start audit worker")
        raise
    return get(store, job_id)


def cancel(store: Store, job_id: str) -> dict:
    # Read and decide under the same write lock as worker claims/completions.
    # In particular, a worker cannot claim a queued job after cancellation wins.
    get(store, job_id, private=True)
    store.db.execute("BEGIN IMMEDIATE")
    try:
        row = dict(store.db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone())
        if row["state"] not in TERMINAL:
            store.db.execute(
                "UPDATE jobs SET state=?,stage=?,updated=? WHERE id=?",
                (
                    "cancelled" if row["state"] == "queued" else row["state"],
                    "cancelled" if row["state"] == "queued" else "cancellation-requested",
                    now(),
                    job_id,
                ),
            )
        store.db.commit()
    except BaseException:
        store.db.rollback()
        raise
    process = worker_process(row) if row["state"] not in TERMINAL else None
    if process is WorkerInspection.UNINSPECTABLE:
        # Leave the committed cancellation request for the worker to observe;
        # neither signal an unverified process nor claim it has already stopped.
        pass
    elif process is not None:
        try:
            process.send_signal(signal.SIGTERM)
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            pass
    elif row["state"] == "running":
        finish(store, job_id, "cancelled")
    return get(store, job_id)


def listing(store: Store, limit=30, roots: list[Path] | None = None) -> list[dict]:
    initialize(store)
    if not 1 <= limit <= 1000:
        raise ValueError("Job limit must be 1–1000")
    conditions, parameters = [], []
    for root in roots or []:
        conditions.append("(target=? OR instr(target,?)=1)")
        parameters.extend((str(root), str(root).rstrip(os.sep) + os.sep))
    where = " WHERE " + " OR ".join(conditions) if conditions else ""
    ids = store.db.execute(
        "SELECT id FROM jobs" + where + " ORDER BY rowid DESC LIMIT ?", (*parameters, limit)
    ).fetchall()
    return [get(store, row["id"]) for row in ids]
