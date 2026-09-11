from __future__ import annotations

import json
from pathlib import Path


class AssuranceExporter:
    """Export a stable, portable assurance bundle without exposing the SQLite internals."""

    def __init__(self, runtime) -> None:
        self.runtime = runtime

    def bundle(self) -> dict:
        return {
            "schema_version": 1,
            "runtime": {"version": "0.1.0"},
            "project": str(self.runtime.root),
            "objectives": self.runtime.memory.objectives(),
            "findings": self.runtime.memory.findings(),
            "decisions": self.runtime.memory.decisions(),
            "work": self.runtime.work_status(include_completed=True),
            "graph": {
                "entities": [e.to_dict() for e in self.runtime.graph.entities.values()],
                "relationships": [r.to_dict() for r in self.runtime.graph.relationships],
            },
            "recent_events": self.runtime.memory.recent_events(limit=100),
        }

    def write(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.bundle(), indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        temporary.replace(path)
        return path
