from __future__ import annotations

from pathlib import Path
import hashlib
import json

from .detectors import default_detectors
from .graph import KnowledgeGraph
from .memory import Memory
from .models import Objective
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

    def initialize(self) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        self.graph.discover_project(self.root)
        self.graph.save(self.graph_path)
        self.memory.remember("project_initialized", {"root": str(self.root), "entities": len(self.graph.entities)})

    def set_objective(self, text: str) -> Objective:
        objective = Objective("O-" + hashlib.sha256(text.encode()).hexdigest()[:10].upper(), text)
        self.memory.add_objective(objective)
        return objective

    def inspect(self) -> list[dict]:
        self.initialize()
        all_findings = []
        for detector in default_detectors():
            findings = detector.scan(self.root)
            for finding in findings:
                self.memory.add_finding(finding)
                all_findings.append(finding)
        self.memory.remember("inspection", {"detectors": [d.name for d in default_detectors()], "finding_count": len(all_findings)})
        return [self._finding_dict(f) for f in all_findings]

    @staticmethod
    def _finding_dict(finding) -> dict:
        return {
            "id": finding.id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "evidence": finding.evidence,
            "remediation": finding.remediation,
            "status": finding.status,
        }

    def status(self) -> dict:
        return {
            "root": str(self.root),
            "graph_entities": len(self.graph.entities),
            "graph_relationships": len(self.graph.relationships),
            "objectives": self.memory.objectives(),
            "findings": self.memory.findings(),
        }

    def close(self) -> None:
        self.memory.close()
