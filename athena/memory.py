from __future__ import annotations

from pathlib import Path
import json
import sqlite3

from .models import Decision, Finding, Objective, utc_now


class Memory:
    """Durable structured memory; intentionally dependency-free for local-first use."""

    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self._init()

    def _init(self) -> None:
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS objectives (
            id TEXT PRIMARY KEY, text TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY, payload TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS decisions (
            id TEXT PRIMARY KEY, payload TEXT NOT NULL
        );
        """)
        self.db.commit()

    def remember(self, kind: str, payload: dict) -> None:
        self.db.execute("INSERT INTO events(kind,payload,created_at) VALUES(?,?,?)", (kind, json.dumps(payload), utc_now()))
        self.db.commit()

    def add_objective(self, objective: Objective) -> None:
        self.db.execute("INSERT OR REPLACE INTO objectives VALUES(?,?,?,?)", (objective.id, objective.text, objective.status, objective.created_at))
        self.db.commit()
        self.remember("objective", objective.__dict__ if hasattr(objective, "__dict__") else {"id": objective.id, "text": objective.text})

    def add_finding(self, finding: Finding) -> None:
        payload = {"id": finding.id, "title": finding.title, "description": finding.description, "severity": finding.severity.value, "confidence": finding.confidence, "evidence": finding.evidence, "remediation": finding.remediation, "status": finding.status, "created_at": finding.created_at}
        self.db.execute("INSERT OR REPLACE INTO findings VALUES(?,?)", (finding.id, json.dumps(payload)))
        self.db.commit()
        self.remember("finding", payload)

    def add_decision(self, decision: Decision) -> None:
        payload = {"id": decision.id, "finding_id": decision.finding_id, "action": decision.action.value, "approved": decision.approved, "rationale": decision.rationale, "created_at": decision.created_at}
        self.db.execute("INSERT OR REPLACE INTO decisions VALUES(?,?)", (decision.id, json.dumps(payload)))
        self.db.commit()
        self.remember("decision", payload)

    def findings(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.db.execute("SELECT payload FROM findings ORDER BY rowid DESC")]

    def objectives(self) -> list[dict]:
        return [dict(row) for row in self.db.execute("SELECT * FROM objectives ORDER BY rowid DESC")]

    def close(self) -> None:
        self.db.close()
