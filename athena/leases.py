from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import uuid



@dataclass(frozen=True, slots=True)
class WorkLease:
    work_id: str
    owner: str
    expires_at: str


class WorkLeaseStore:
    """SQLite-backed short leases preventing concurrent workers from stealing work."""

    def __init__(self, db: sqlite3.Connection, owner: str | None = None) -> None:
        self.db = db
        self.owner = owner or uuid.uuid4().hex
        self.db.execute("CREATE TABLE IF NOT EXISTS work_leases (work_id TEXT PRIMARY KEY, owner TEXT NOT NULL, expires_at TEXT NOT NULL)")
        self.db.commit()

    def acquire(self, work_id: str, ttl_seconds: int = 300) -> WorkLease | None:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=max(1, ttl_seconds))
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT owner, expires_at FROM work_leases WHERE work_id=?", (work_id,)).fetchone()
            if row and row["owner"] != self.owner and self._parse(row["expires_at"]) > now:
                self.db.commit()
                return None
            value = expires.isoformat()
            self.db.execute("INSERT INTO work_leases(work_id,owner,expires_at) VALUES(?,?,?) ON CONFLICT(work_id) DO UPDATE SET owner=excluded.owner, expires_at=excluded.expires_at", (work_id, self.owner, value))
            self.db.commit()
            return WorkLease(work_id, self.owner, value)
        except Exception:
            self.db.rollback()
            raise

    def release(self, work_id: str) -> bool:
        cursor = self.db.execute("DELETE FROM work_leases WHERE work_id=? AND owner=?", (work_id, self.owner))
        self.db.commit()
        return cursor.rowcount > 0

    def renew(self, work_id: str, ttl_seconds: int = 300) -> WorkLease | None:
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(seconds=max(1, ttl_seconds))).isoformat()
        cursor = self.db.execute("UPDATE work_leases SET expires_at=? WHERE work_id=? AND owner=?", (expires, work_id, self.owner))
        self.db.commit()
        return WorkLease(work_id, self.owner, expires) if cursor.rowcount else None

    def reclaim_expired(self) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cursor = self.db.execute("DELETE FROM work_leases WHERE expires_at<=?", (now,))
        self.db.commit()
        return cursor.rowcount

    @staticmethod
    def _parse(value: str) -> datetime:
        return datetime.fromisoformat(value)
