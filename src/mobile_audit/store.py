from __future__ import annotations

import errno
import json
import os
import re
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .core import MAX_FILE, canonical_json, digest, now, read_json, uid, write_json


def _restrict(path: Path) -> None:
    """Set 0600 without closing a lock-bearing descriptor of a live SQLite file.

    Closing any ordinary descriptor drops this process's POSIX locks on that file,
    including SQLite's WAL-index locks; another process may then reinitialize the
    shared-memory file under a live mapping. lchmod and O_PATH avoid that.
    """
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise OSError(errno.ELOOP, "Audit database files must not be symlinks", str(path))
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Audit database files must be regular files")
    try:
        # macOS lchmod; glibc emulates this for regular files through O_PATH.
        os.chmod(path, 0o600, follow_symlinks=False)
        return
    except NotImplementedError:
        pass
    descriptor = os.open(path, getattr(os, "O_PATH", 0) | os.O_NOFOLLOW | os.O_RDONLY)
    try:
        if not getattr(os, "O_PATH", 0):
            raise OSError(errno.ENOTSUP, "Lock-safe permission repair is unavailable", str(path))
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Audit database files must be regular files")
        os.chmod(f"/proc/self/fd/{descriptor}", 0o600)
    finally:
        os.close(descriptor)


def default_home() -> Path:
    return Path(
        os.environ.get(
            "APSA_HOME",
            os.environ.get(
                "QUAYGATE_HOME",
                os.environ.get("MOBILE_AUDIT_HOME", Path.home() / ".local/share/mobile-audit"),
            ),
        )
    ).expanduser()


class Store:
    def __init__(self, home: Path | None = None):
        self.home = home or default_home()
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)
        # SQLite derives newly created WAL/SHM modes from the database. Secure
        # the main file before connecting, and repair sidecars from older runs.
        main = self.home / "audit.sqlite3"
        if not os.path.lexists(main):
            try:
                # A new inode cannot carry locks of an existing connection.
                os.close(os.open(main, os.O_RDONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
            except FileExistsError:
                pass
        for name in ("audit.sqlite3", "audit.sqlite3-wal", "audit.sqlite3-shm"):
            try:
                _restrict(self.home / name)
            except FileNotFoundError:
                if name == "audit.sqlite3":
                    raise
        self.db = sqlite3.connect(self.home / "audit.sqlite3", timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY, created TEXT, target TEXT, body TEXT);
        CREATE TABLE IF NOT EXISTS intel(id TEXT, source TEXT, modified TEXT, body TEXT,
          PRIMARY KEY(id,source));
        CREATE TABLE IF NOT EXISTS feeds(source TEXT PRIMARY KEY, attempted TEXT, succeeded TEXT,
          status TEXT, count INTEGER, error TEXT, content_hash TEXT);
        CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, created TEXT, kind TEXT, body TEXT);
        CREATE TABLE IF NOT EXISTS cve_queue(id TEXT, revision TEXT, priority INTEGER, state TEXT,
          PRIMARY KEY(id, revision));
        CREATE TABLE IF NOT EXISTS cursors(source TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS intel_branches(id TEXT, source TEXT, branch TEXT, modified TEXT,
          body TEXT, PRIMARY KEY(id,source,branch));
        CREATE TABLE IF NOT EXISTS intel_revisions(snapshot_hash TEXT PRIMARY KEY, id TEXT, source TEXT,
          branch TEXT, modified TEXT, observed TEXT, body TEXT);
        """)

        self.db.execute("BEGIN IMMEDIATE")
        try:
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            columns = {r[1] for r in self.db.execute("PRAGMA table_info(reports)")}
            if "body_hash" not in columns:
                self.db.execute("ALTER TABLE reports ADD COLUMN body_hash TEXT")
                for row in self.db.execute("SELECT id,body FROM reports").fetchall():
                    self.db.execute(
                        "UPDATE reports SET body_hash=? WHERE id=?", (digest(row["body"].encode()), row["id"])
                    )
            queue_columns = {r[1] for r in self.db.execute("PRAGMA table_info(cve_queue)")}
            for column, definition in (
                ("attempts", "INTEGER NOT NULL DEFAULT 0"),
                ("queued_at", "TEXT NOT NULL DEFAULT ''"),
                ("last_attempt", "TEXT"),
                ("next_attempt", "TEXT NOT NULL DEFAULT ''"),
                ("last_error", "TEXT NOT NULL DEFAULT ''"),
            ):
                if column not in queue_columns:
                    self.db.execute(f"ALTER TABLE cve_queue ADD COLUMN {column} {definition}")
            self.db.execute("UPDATE cve_queue SET queued_at=? WHERE queued_at=''", (now(),))
            feed_columns = {r[1] for r in self.db.execute("PRAGMA table_info(feeds)")}
            if "fetched_ok" not in feed_columns:
                self.db.execute("ALTER TABLE feeds ADD COLUMN fetched_ok TEXT")
                self.db.execute("UPDATE feeds SET fetched_ok=succeeded")
            # A vendor CVE may be patched on multiple OS branches/components.
            # Preserve the original source name while giving each branch its own row.
            for row in self.db.execute("SELECT * FROM intel WHERE source IN ('apple','android')").fetchall():
                record = json.loads(row["body"])
                branch = self._intel_branch(record)
                self.db.execute(
                    "INSERT OR IGNORE INTO intel_branches VALUES(?,?,?,?,?)",
                    (row["id"], row["source"], branch, row["modified"], row["body"]),
                )
                self.db.execute("DELETE FROM intel WHERE id=? AND source=?", (row["id"], row["source"]))
            if version < 2:
                for table in ("intel", "intel_branches"):
                    for row in self.db.execute(f"SELECT * FROM {table}").fetchall():
                        snapshot_hash = digest(row["body"].encode())
                        snapshot = self.home / "intel-records" / f"{snapshot_hash}.json"
                        if not snapshot.exists():
                            write_json(snapshot, json.loads(row["body"]))
                        self.db.execute(
                            "INSERT OR IGNORE INTO intel_revisions VALUES(?,?,?,?,?,?,?)",
                            (
                                snapshot_hash,
                                row["id"],
                                row["source"],
                                row["branch"] if table == "intel_branches" else "",
                                row["modified"],
                                now(),
                                row["body"],
                            ),
                        )
            self.db.execute(f"PRAGMA user_version={max(version, 2)}")
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def close(self):
        self.db.close()

    def save_report(self, report: dict) -> dict:
        body = canonical_json(report)
        body_hash = digest(body.encode())
        self.db.execute("BEGIN IMMEDIATE")
        try:
            existing = self.db.execute(
                "SELECT body,body_hash FROM reports WHERE id=?", (report["id"],)
            ).fetchone()
            if existing:
                if digest(existing["body"].encode()) != existing["body_hash"]:
                    raise ValueError("Report integrity check failed")
                if canonical_json(json.loads(existing["body"])) != body:
                    raise ValueError("Reports are immutable; create a new report ID")
            else:
                self.db.execute(
                    "INSERT INTO reports(id,created,target,body,body_hash) VALUES(?,?,?,?,?)",
                    (report["id"], report["created"], report["target"], body, body_hash),
                )
            write_json(self.home / "reports" / f"{report['id']}.json", report)
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        return report

    def report(self, report_id: str) -> dict:
        if report_id == "latest":
            row = self.db.execute(
                "SELECT body,body_hash FROM reports ORDER BY created DESC,rowid DESC LIMIT 1"
            ).fetchone()
        else:
            row = self.db.execute("SELECT body,body_hash FROM reports WHERE id=?", (report_id,)).fetchone()
        if row is None:
            raise ValueError(f"Report not found: {report_id}. Run scan or demo first.")
        if digest(row["body"].encode()) != row["body_hash"]:
            raise ValueError("Report integrity check failed")
        return json.loads(row["body"])

    def verify_reports(self) -> dict:
        failures = []
        count = 0
        for row in self.db.execute("SELECT id,body,body_hash FROM reports"):
            count += 1
            try:
                if digest(row["body"].encode()) != row["body_hash"]:
                    raise ValueError("database body hash mismatch")
                exported = self.home / "reports" / f"{row['id']}.json"
                if not exported.is_file():
                    raise ValueError("export missing")
                if canonical_json(read_json(exported)) != canonical_json(json.loads(row["body"])):
                    raise ValueError("export differs from immutable database report")
            except (ValueError, OSError) as error:
                failures.append({"id": row["id"], "error": str(error)})
        return {"checked": count, "failures": failures, "state": "passed" if not failures else "failed"}

    def reports(self, limit=30, roots: list[Path] | None = None) -> list[dict]:
        conditions = []
        parameters: list = []
        for root in roots or []:
            conditions.append("(target=? OR instr(target,?)=1)")
            parameters.extend([str(root), str(root).rstrip(os.sep) + os.sep])
        where = " WHERE " + " OR ".join(conditions) if conditions else ""
        return [
            dict(r)
            for r in self.db.execute(
                "SELECT id,created,target FROM reports" + where + " ORDER BY created DESC,rowid DESC LIMIT ?",
                (*parameters, limit),
            )
        ]

    @staticmethod
    def _intel_branch(record: dict) -> str:
        if record.get("source") not in {"apple", "android"}:
            return ""
        branch = {
            key: record.get(key, "")
            for key in (
                "source",
                "platform",
                "component",
                "fixed_release",
                "fixed_patch_level",
                "updated_aosp_versions",
            )
        }
        branch["references"] = record.get("references", [])[:1]
        return digest(canonical_json(branch).encode())[:24]

    def _prepare_intel(self, records: list[dict]) -> list[tuple[dict, str, str]]:
        if not isinstance(records, list) or len(records) > 100_000:
            raise ValueError("Invalid intelligence batch size")
        prepared = []
        for record in records:
            if not isinstance(record, dict) or any(
                not isinstance(record.get(key), str) or not record[key] for key in ("id", "source")
            ):
                raise ValueError("Intelligence records require string id/source")
            if (
                len(record["id"]) > 200
                or len(record["source"]) > 512
                or not isinstance(record.get("modified", ""), str)
            ):
                raise ValueError("Invalid intelligence identity or revision")
            references = record.get("references", [])
            if not isinstance(references, list) or any(
                not isinstance(reference, str) for reference in references
            ):
                raise ValueError("Intelligence references must be strings")
            # Snapshot hashes/retrieval state are projections, never stored content.
            clean = {
                key: value
                for key, value in record.items()
                if key not in {"snapshot_hash", "branch_id", "observed_at"}
            }
            body = canonical_json(clean)
            if len(body.encode()) > MAX_FILE:
                raise ValueError("Intelligence record exceeds local snapshot limit")
            prepared.append((clean, body, self._intel_branch(clean)))
        # Validate the whole batch before touching cache or snapshot files.
        for record, body, _ in prepared:
            snapshot = self.home / "intel-records" / f"{digest(body.encode())}.json"
            if snapshot.exists():
                if canonical_json(read_json(snapshot)) != body:
                    raise ValueError("Intelligence snapshot integrity check failed")
            else:
                write_json(snapshot, record)
        return prepared

    def _write_intel(self, prepared: list[tuple[dict, str, str]]) -> list[str]:
        changed = []
        for record, body, branch in prepared:
            if branch:
                old = self.db.execute(
                    "SELECT body FROM intel_branches WHERE id=? AND source=? AND branch=?",
                    (record["id"], record["source"], branch),
                ).fetchone()
            else:
                old = self.db.execute(
                    "SELECT body FROM intel WHERE id=? AND source=?", (record["id"], record["source"])
                ).fetchone()
            if old is None or canonical_json(json.loads(old[0])) != body:
                changed.append(record["id"])
                if branch:
                    self.db.execute(
                        "INSERT OR REPLACE INTO intel_branches VALUES(?,?,?,?,?)",
                        (record["id"], record["source"], branch, record.get("modified", ""), body),
                    )
                else:
                    self.db.execute(
                        "INSERT OR REPLACE INTO intel VALUES(?,?,?,?)",
                        (record["id"], record["source"], record.get("modified", ""), body),
                    )
                self.db.execute(
                    "INSERT OR IGNORE INTO intel_revisions VALUES(?,?,?,?,?,?,?)",
                    (
                        digest(body.encode()),
                        record["id"],
                        record["source"],
                        branch,
                        record.get("modified", ""),
                        now(),
                        body,
                    ),
                )
        return sorted(set(changed))

    def upsert_intel(self, records: list[dict]) -> list[str]:
        prepared = self._prepare_intel(records)
        with self.db:
            return self._write_intel(prepared)

    def replace_source(self, source: str, records: list[dict]) -> list[str]:
        if any(not isinstance(record, dict) or record.get("source") != source for record in records):
            raise ValueError("Replacement intelligence batch has a different source")
        prepared = self._prepare_intel(records)
        old = {
            (row["id"], row["branch"]): canonical_json(json.loads(row["body"]))
            for row in self.db.execute(
                "SELECT id,body,'' AS branch FROM intel WHERE source=? UNION ALL SELECT id,body,branch FROM intel_branches WHERE source=?",
                (source, source),
            )
        }
        current = {(record["id"], branch): body for record, body, branch in prepared}
        changed = {key[0] for key in old.keys() | current.keys() if old.get(key) != current.get(key)}
        with self.db:
            self.db.execute("DELETE FROM intel WHERE source=?", (source,))
            self.db.execute("DELETE FROM intel_branches WHERE source=?", (source,))
            self._write_intel(prepared)
        return sorted(changed)

    def replace_vendor_documents(self, source: str, records: list[dict], urls: list[str]) -> list[str]:
        if source not in {"apple", "android"} or any(
            record.get("source") != source or record.get("provenance", {}).get("document_url") not in urls
            for record in records
        ):
            raise ValueError("Vendor replacement records require matching document provenance")
        prepared = self._prepare_intel(records)
        old = {}
        for row in self.db.execute("SELECT * FROM intel_branches WHERE source=?", (source,)):
            record = json.loads(row["body"])
            document = record.get("provenance", {}).get("document_url") or next(
                iter(record.get("references", [])), ""
            )
            if document in urls:
                old[(row["id"], row["branch"])] = canonical_json(record)
        current = {(record["id"], branch): body for record, body, branch in prepared}
        changed = {key[0] for key in old.keys() | current.keys() if old.get(key) != current.get(key)}
        with self.db:
            self.db.executemany(
                "DELETE FROM intel_branches WHERE id=? AND source=? AND branch=?",
                [(identifier, source, branch) for identifier, branch in old],
            )
            self._write_intel(prepared)
        return sorted(changed)

    def enqueue_cves(self, items: list[tuple[str, str, int]]):
        if any(
            not isinstance(identifier, str)
            or not re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier)
            or not isinstance(revision, str)
            or not isinstance(priority, int)
            for identifier, revision, priority in items
        ):
            raise ValueError("Invalid CVE queue identity or revision")
        with self.db:
            self.db.executemany(
                "INSERT OR IGNORE INTO cve_queue(id,revision,priority,state,queued_at) VALUES(?,?,?,'pending',?)",
                [(*item, now()) for item in items],
            )

    def pending_cves(self, limit: int, at: str | None = None) -> list[dict]:
        stamp = at or now()
        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise ValueError("CVE queue timestamps need a timezone")
        stamp = moment.astimezone(timezone.utc).isoformat(timespec="seconds")
        if limit < 1:
            return []
        # Reserve capacity for both vendor/KEV and global-delta work. FIFO inside
        # each lane prevents a stream of newer revisions from starving old jobs.
        due = "state='pending' AND (next_attempt='' OR next_attempt<=?)"
        order = " ORDER BY queued_at,rowid LIMIT ?"
        if limit == 1:
            return [
                dict(row)
                for row in self.db.execute("SELECT * FROM cve_queue WHERE " + due + order, (stamp, 1))
            ]
        selected = []
        for condition, quota in (("priority<=0", (limit + 1) // 2), ("priority>0", limit // 2)):
            selected.extend(
                dict(row)
                for row in self.db.execute(
                    "SELECT * FROM cve_queue WHERE " + due + " AND " + condition + order, (stamp, quota)
                )
            )
        if len(selected) < limit:
            keys = {(row["id"], row["revision"]) for row in selected}
            for row in self.db.execute("SELECT * FROM cve_queue WHERE " + due + order, (stamp, limit)):
                if (row["id"], row["revision"]) not in keys:
                    selected.append(dict(row))
                if len(selected) == limit:
                    break
        return selected

    def finish_cve(self, identifier: str, revision: str):
        with self.db:
            self.db.execute(
                "UPDATE cve_queue SET state='done',attempts=attempts+1,last_attempt=?,last_error='' WHERE id=? AND revision=?",
                (now(), identifier, revision),
            )

    def retry_cve(
        self,
        identifier: str,
        revision: str,
        error: str,
        retry_after: int | None = None,
        at: str | None = None,
    ):
        stamp = at or now()
        moment = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        if moment.tzinfo is None:
            raise ValueError("CVE queue timestamps need a timezone")
        old = self.db.execute(
            "SELECT attempts FROM cve_queue WHERE id=? AND revision=?", (identifier, revision)
        ).fetchone()
        if old is None:
            return
        attempts = old["attempts"] + 1
        delay = min(86_400, max(60 * 2 ** min(attempts - 1, 11), retry_after or 0))
        next_attempt = (
            (moment + timedelta(seconds=delay)).astimezone(timezone.utc).isoformat(timespec="seconds")
        )
        with self.db:
            self.db.execute(
                "UPDATE cve_queue SET state='pending',attempts=?,last_attempt=?,next_attempt=?,last_error=? WHERE id=? AND revision=?",
                (attempts, stamp, next_attempt, error[:300], identifier, revision),
            )

    def pending_count(self) -> int:
        return self.db.execute("SELECT count(*) FROM cve_queue WHERE state='pending'").fetchone()[0]

    def cursor(self, source: str) -> str | None:
        row = self.db.execute("SELECT value FROM cursors WHERE source=?", (source,)).fetchone()
        return row[0] if row else None

    def set_cursor(self, source: str, value: str):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO cursors VALUES(?,?)", (source, value))

    def intelligence(self, query="", limit=100) -> list[dict]:
        # Search literal input: SQL parameters and LIKE escaping are separate concerns.
        escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = self.db.execute(
            "SELECT body,branch FROM (SELECT body,modified,'' AS branch FROM intel UNION ALL SELECT body,modified,branch FROM intel_branches) WHERE body LIKE ? ESCAPE '\\' ORDER BY modified DESC LIMIT ?",
            (f"%{escaped}%", limit),
        )
        return [
            dict(
                json.loads(row["body"]),
                snapshot_hash=digest(row["body"].encode()),
                **({"branch_id": row["branch"]} if row["branch"] else {}),
            )
            for row in rows
        ]

    def intel_by_id(self, identifier: str) -> list[dict]:
        return [
            dict(
                json.loads(r["body"]),
                snapshot_hash=digest(r["body"].encode()),
                **({"branch_id": r["branch"]} if r["branch"] else {}),
            )
            for r in self.db.execute(
                "SELECT body,'' AS branch FROM intel WHERE id=? UNION ALL SELECT body,branch FROM intel_branches WHERE id=?",
                (identifier, identifier),
            )
        ]

    def intel_history(self, identifier: str, limit=100) -> list[dict]:
        return [
            dict(
                json.loads(row["body"]),
                snapshot_hash=row["snapshot_hash"],
                observed_at=row["observed"],
                **({"branch_id": row["branch"]} if row["branch"] else {}),
            )
            for row in self.db.execute(
                "SELECT * FROM intel_revisions WHERE id=? ORDER BY observed DESC,rowid DESC LIMIT ?",
                (identifier, limit),
            )
        ]

    def feed(self, source: str, status: str, count=0, error="", content_hash="", *, fetched=False):
        old = self.db.execute("SELECT * FROM feeds WHERE source=?", (source,)).fetchone()
        stamp = now()
        succeeded = stamp if status == "ok" else (old["succeeded"] if old else None)
        fetched_ok = stamp if fetched or status == "ok" else (old["fetched_ok"] if old else None)
        if status != "ok" and not fetched and old:
            count = old["count"]
            content_hash = old["content_hash"]
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO feeds(source,attempted,succeeded,status,count,error,content_hash,fetched_ok) VALUES(?,?,?,?,?,?,?,?)",
                (source, stamp, succeeded, status, count, error, content_hash, fetched_ok),
            )

    def feeds(self) -> list[dict]:
        return [dict(r) for r in self.db.execute("SELECT * FROM feeds ORDER BY source")]

    def event(self, kind: str, body: dict):
        with self.db:
            self.db.execute("INSERT INTO events VALUES(?,?,?,?)", (uid("evt"), now(), kind, json.dumps(body)))

    def config(self) -> dict:
        path = self.home / "config.json"
        return json.loads(path.read_text()) if path.exists() else {}

    def save_config(self, config: dict):
        write_json(self.home / "config.json", config)
        (self.home / "config.json").chmod(0o600)
