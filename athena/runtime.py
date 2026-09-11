from __future__ import annotations

import hashlib
from pathlib import Path

from .detectors import default_detectors
from .graph import KnowledgeGraph
from .memory import Memory
from .models import Objective
from .planner import Planner
from .policy import Authority, PolicyEngine


class AthenaRuntime:
    """Local-first autonomous assurance runtime."""

    def __init__(self, root: str | Path, authority: Authority | None = None) -> None:
        self.root = Path(root).resolve()
        self.state = self.root / ".athena"
        self.graph_path = self.state / "graph.json"
        self.memory = Memory(self.state / "memory.sqlite3")
        self.graph = KnowledgeGraph.load(self.graph_path)
        self.policy = PolicyEngine(authority)
        self.planner = Planner()

    def initialize(self) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        self.graph.discover_project(self.root)
        self.graph.save(self.graph_path)
        self.memory.fact("project.root", str(self.root))
        self.memory.fact("graph.entities", len(self.graph.entities))
        self.memory.remember(
            "project_initialized", {"root": str(self.root), "entities": len(self.graph.entities)}
        )

    def set_objective(self, text: str) -> Objective:
        objective = Objective("O-" + hashlib.sha256(text.encode()).hexdigest()[:10].upper(), text)
        self.memory.add_objective(objective)
        return objective

    def autonomous_plan(self):
        self.initialize()
        rows = self.memory.objectives()
        objective = (
            Objective(rows[0]["id"], rows[0]["text"], rows[0]["status"], rows[0]["created_at"])
            if rows
            else None
        )
        tasks = self.planner.plan(objective, self.graph, self.memory.findings())
        self.memory.remember(
            "plan",
            {
                "objective": objective.text if objective else None,
                "tasks": [
                    {"kind": t.kind, "reason": t.reason, "priority": t.priority} for t in tasks
                ],
            },
        )
        return tasks

    def inspect(self) -> list[dict]:
        """Run deterministic detectors and persist every finding as durable evidence."""
        self.initialize()
        results = []
        for detector in default_detectors():
            for finding in detector.scan(self.root):
                self.memory.add_finding(finding)
                results.append(
                    {
                        "id": finding.id,
                        "title": finding.title,
                        "description": finding.description,
                        "severity": finding.severity.value,
                        "confidence": finding.confidence,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                        "status": finding.status,
                        "recommended_action": self.policy.next_action(finding).value,
                    }
                )
        self.memory.remember("inspection", {"finding_count": len(results)})
        return results

    def status(self) -> dict:
        return {
            "root": str(self.root),
            "graph_entities": len(self.graph.entities),
            "graph_relationships": len(self.graph.relationships),
            "objectives": self.memory.objectives(),
            "findings": self.memory.findings(),
            "recent_events": self.memory.recent_events(),
        }

    def close(self) -> None:
        self.memory.close()
