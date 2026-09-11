from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from typing import Any

from .models import utc_now


@dataclass(frozen=True, slots=True)
class WorkItem:
    id: str
    kind: str
    reason: str
    objective: str | None
    priority: int
    status: str
    attempts: int
    created_at: str
    updated_at: str
    last_error: str | None = None
    depends_on: tuple[str, ...] = ()
    context_key: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "reason": self.reason,
            "objective": self.objective, "priority": self.priority,
            "status": self.status, "attempts": self.attempts,
            "created_at": self.created_at, "updated_at": self.updated_at,
            "last_error": self.last_error, "depends_on": list(self.depends_on),
            "context_key": self.context_key,
        }


class WorkQueue:
    """Durable, deterministic work state backed by the runtime SQLite connection."""

    def __init__(self, db: sqlite3.Connection) -> None:
        self.db = db
        self._init()

    def _init(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS work_items (
                id TEXT PRIMARY KEY, kind TEXT NOT NULL, reason TEXT NOT NULL,
                objective TEXT, priority INTEGER NOT NULL, status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, last_error TEXT,
                depends_on TEXT NOT NULL DEFAULT '[]', context_key TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_work_status_priority
                ON work_items(status, priority DESC, created_at ASC);
            """
        )
        self.db.commit()

    @staticmethod
    def make_id(kind: str, reason: str, objective: str | None, context_key: str = "") -> str:
        raw = json.dumps([kind, reason, objective, context_key], sort_keys=True)
        return "W-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()

    def enqueue(self, *, kind: str, reason: str, priority: int,
                objective: str | None = None, depends_on: tuple[str, ...] = (),
                context_key: str = "") -> WorkItem:
        item_id = self.make_id(kind, reason, objective, context_key)
        now = utc_now()
        existing = self.get(item_id)
        if existing:
            if existing.status in {"failed", "cancelled"}:
                self.db.execute(
                    "UPDATE work_items SET status='queued', priority=?, updated_at=?, last_error=NULL WHERE id=?",
                    (max(priority, existing.priority), now, item_id),
                )
                self.db.commit()
                return self.get(item_id)  # type: ignore[return-value]
            if priority > existing.priority:
                self.db.execute("UPDATE work_items SET priority=?, updated_at=? WHERE id=?", (priority, now, item_id))
                self.db.commit()
            return existing
        self.db.execute(
            "INSERT INTO work_items(id,kind,reason,objective,priority,status,attempts,created_at,updated_at,last_error,depends_on,context_key) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (item_id, kind, reason, objective, priority, "queued", 0, now, now, None, json.dumps(list(depends_on)), context_key),
        )
        self.db.commit()
        return self.get(item_id)  # type: ignore[return-value]

    def get(self, item_id: str) -> WorkItem | None:
        row = self.db.execute("SELECT * FROM work_items WHERE id=?", (item_id,)).fetchone()
        return self._row(row) if row else None

    def pending(self, limit: int = 50) -> list[WorkItem]:
        rows = self.db.execute("SELECT * FROM work_items WHERE status IN ('queued','running','blocked') ORDER BY priority DESC, created_at ASC LIMIT ?", (limit,))
        return [self._row(row) for row in rows]

    def all(self, limit: int = 200) -> list[WorkItem]:
        rows = self.db.execute("SELECT * FROM work_items ORDER BY updated_at DESC LIMIT ?", (limit,))
        return [self._row(row) for row in rows]

    def claim_next(self, max_attempts: int = 3) -> WorkItem | None:
        """Atomically claim the highest-priority runnable item."""
        self.db.execute("BEGIN IMMEDIATE")
        try:
            rows = self.db.execute("SELECT * FROM work_items WHERE status='queued' AND attempts < ? ORDER BY priority DESC, created_at ASC", (max_attempts,)).fetchall()
            selected = next((row for row in rows if all(self._dependency_satisfied(dep) for dep in json.loads(row["depends_on"]))), None)
            if selected is None:
                self.db.commit()
                return None
            self.db.execute("UPDATE work_items SET status='running', attempts=attempts+1, updated_at=? WHERE id=? AND status='queued'", (utc_now(), selected["id"]))
            self.db.commit()
            return self.get(selected["id"])
        except Exception:
            self.db.rollback()
            raise

    def complete(self, item_id: str) -> WorkItem:
        self._set_status(item_id, "completed")
        return self.get(item_id)  # type: ignore[return-value]

    def fail(self, item_id: str, error: str, *, retry: bool = True, max_attempts: int = 3) -> WorkItem:
        current = self.get(item_id)
        if current is None:
            raise KeyError(item_id)
        status = "queued" if retry and current.attempts < max_attempts else "failed"
        self.db.execute("UPDATE work_items SET status=?, last_error=?, updated_at=? WHERE id=?", (status, error[:2000], utc_now(), item_id))
        self.db.commit()
        return self.get(item_id)  # type: ignore[return-value]

    def block(self, item_id: str, reason: str) -> WorkItem:
        self.db.execute("UPDATE work_items SET status='blocked', last_error=?, updated_at=? WHERE id=?", (reason[:2000], utc_now(), item_id))
        self.db.commit()
        return self.get(item_id)  # type: ignore[return-value]

    def resume(self, item_id: str | None = None) -> list[WorkItem]:
        if item_id:
            self.db.execute("UPDATE work_items SET status='queued', last_error=NULL, updated_at=? WHERE id=? AND status IN ('blocked','failed')", (utc_now(), item_id))
        else:
            self.db.execute("UPDATE work_items SET status='queued', last_error=NULL, updated_at=? WHERE status IN ('blocked','failed')", (utc_now(),))
        self.db.commit()
        return self.pending()

    def _dependency_satisfied(self, item_id: str) -> bool:
        row = self.db.execute("SELECT status FROM work_items WHERE id=?", (item_id,)).fetchone()
        return bool(row and row["status"] == "completed")

    def _set_status(self, item_id: str, status: str) -> None:
        self.db.execute("UPDATE work_items SET status=?, last_error=NULL, updated_at=? WHERE id=?", (status, utc_now(), item_id))
        self.db.commit()

    @staticmethod
    def _row(row: sqlite3.Row) -> WorkItem:
        return WorkItem(
            id=row["id"], kind=row["kind"], reason=row["reason"], objective=row["objective"],
            priority=row["priority"], status=row["status"], attempts=row["attempts"],
            created_at=row["created_at"], updated_at=row["updated_at"], last_error=row["last_error"],
            depends_on=tuple(json.loads(row["depends_on"])), context_key=row["context_key"],
        )
