from __future__ import annotations

import os
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class HealthReport:
    database_ok: bool
    graph_ok: bool
    writable: bool
    disk_free_bytes: int
    issues: tuple[str, ...] = ()

    @property
    def healthy(self) -> bool:
        return not self.issues


def check_runtime(root: Path, db: sqlite3.Connection, graph_path: Path) -> HealthReport:
    """Check operational dependencies without treating a fresh runtime as broken."""
    issues: list[str] = []
    database_ok = True
    try:
        db.execute("SELECT 1").fetchone()
    except sqlite3.Error:
        database_ok = False
        issues.append("database_unavailable")

    graph_ok = graph_path.exists() and graph_path.is_file()
    if not graph_ok:
        # A graph is legitimately absent before the first successful initialize().
        if not db_path_ready(db):
            issues.append("graph_snapshot_missing")

    writable = root.exists() and os.access(root, os.W_OK)
    if not writable:
        issues.append("project_not_writable")

    try:
        disk_free = shutil.disk_usage(root).free
    except OSError:
        disk_free = 0
        issues.append("disk_usage_unavailable")

    return HealthReport(database_ok, graph_ok, writable, disk_free, tuple(issues))


def db_path_ready(db: sqlite3.Connection) -> bool:
    """Return whether ATHENA's database has been initialized enough to run."""
    try:
        row = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='events' LIMIT 1"
        ).fetchone()
        return row is not None
    except sqlite3.Error:
        return False
