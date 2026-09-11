from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import Decision, Finding, Objective, utc_now


class Memory:
    """Durable, dependency-free project memory backed by SQLite."""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS facts (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS objectives (
                id TEXT PRIMARY KEY,
                text TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS decisions (
                id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
            CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
            """
        )
        self.db.commit()

    def remember(self, kind: str, payload: dict) -> None:
        self.db.execute(
            "INSERT INTO events(kind,payload,created_at) VALUES(?,?,?)",
            (kind, json.dumps(payload, sort_keys=True), utc_now()),
        )
        self.db.commit()

    def fact(self, key: str, value: object) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO facts(key,value,updated_at) VALUES(?,?,?)",
            (key, json.dumps(value, sort_keys=True), utc_now()),
        )
        self.db.commit()

    def facts(self) -> dict[str, object]:
        return {row["key"]: json.loads(row["value"]) for row in self.db.execute("SELECT * FROM facts")}

    def search_events(self, term: str, limit: int = 20) -> list[dict]:
        pattern = f"%{term}%"
        rows = self.db.execute(
            "SELECT * FROM events WHERE kind LIKE ? OR payload LIKE ? ORDER BY id DESC LIMIT ?",
            (pattern, pattern, limit),
        )
        return [dict(row) for row in rows]

    def recent_events(self, limit: int = 20) -> list[dict]:
        return [dict(row) for row in self.db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))]

    def add_objective(self, objective: Objective) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO objectives VALUES(?,?,?,?)",
            (objective.id, objective.text, objective.status, objective.created_at),
        )
        self.db.commit()
        self.remember("objective", {"id": objective.id, "text": objective.text, "status": objective.status})

    def add_finding(self, finding: Finding) -> None:
        payload = {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "status": finding.status,
            "created_at": finding.created_at,
        }
        self.db.execute(
            "INSERT OR REPLACE INTO findings(id,payload,updated_at) VALUES(?,?,?)",
            (finding.id, json.dumps(payload, sort_keys=True), utc_now()),
        )
        self.db.commit()
        self.remember("finding", payload)

    def add_decision(self, decision: Decision) -> None:
        payload = {
            "id": decision.id,
            "finding_id": decision.finding_id,
            "action": decision.action.value,
            "approved": decision.approved,
            "rationale": decision.rationale,
            "created_at": decision.created_at,
        }
        self.db.execute(
            "INSERT OR REPLACE INTO decisions(id,payload,updated_at) VALUES(?,?,?)",
            (decision.id, json.dumps(payload, sort_keys=True), utc_now()),
        )
        self.db.commit()
        self.remember("decision", payload)

    def findings(self) -> list[dict]:
        return [json.loads(row["payload"]) for row in self.db.execute("SELECT * FROM findings ORDER BY rowid DESC")]

    def decisions(self) -> list[dict]:
        return [json.loads(row["payload"]) for row in self.db.execute("SELECT * FROM decisions ORDER BY rowid DESC")]

    def objectives(self) -> list[dict]:
        return [dict(row) for row in self.db.execute("SELECT * FROM objectives ORDER BY rowid DESC")]

    def close(self) -> None:
        self.db.close()
