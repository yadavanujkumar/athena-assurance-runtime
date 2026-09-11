from __future__ import annotations

import hashlib
from pathlib import Path

from .ai_graph import AIGraphBuilder
from .assurance import AssuranceEngine
from .change import ChangeAnalyzer
from .detectors import default_detectors
from .graph import KnowledgeGraph
from .investigation import InvestigationEngine
from .memory import Memory
from .models import Objective
from .planner import Planner
from .policy import Authority, PolicyEngine
from .snapshot import Snapshotter


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
        self.investigator = InvestigationEngine(self.root, self.memory)
        self.assurance = AssuranceEngine(self.memory, self.policy)
        self.snapshotter = Snapshotter(self.root)
        self.change_analyzer = ChangeAnalyzer()
        self.ai_graph = AIGraphBuilder()

    def initialize(self) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        self.graph.discover_project(self.root)
        ai_signals = self.ai_graph.build(self.graph, self.root)
        self.graph.save(self.graph_path)
        self.memory.fact("project.root", str(self.root))
        self.memory.fact("graph.entities", len(self.graph.entities))
        self.memory.fact("ai.signals", ai_signals)
        snapshot = self.snapshotter.capture()
        self.memory.fact("project.snapshot", snapshot.fingerprint)
        self.memory.remember("project_initialized", {"root": str(self.root), "entities": len(self.graph.entities), "ai_signals": len(ai_signals), "snapshot": snapshot.fingerprint})

    def set_objective(self, text: str) -> Objective:
        objective = Objective("O-" + hashlib.sha256(text.encode()).hexdigest()[:10].upper(), text)
        self.memory.add_objective(objective)
        return objective

    def proposed_objectives(self) -> list[dict]:
        self.initialize()
        rows = self.memory.objectives()
        if rows:
            return [{"id": r["id"], "text": r["text"], "source": "user"} for r in rows]
        proposals = [
            (100, "Establish a security and trust-boundary baseline for the project."),
            (98, "Identify AI, agent, model, prompt and tool-use components and their risks."),
            (95, "Identify dependency and software supply-chain exposure."),
            (90, "Map discovered risks and evidence to applicable governance controls."),
        ]
        return [{"priority": p, "text": t, "source": "athena"} for p, t in proposals]

    def _change_classes(self) -> tuple[list[dict], set[str]]:
        previous = self.memory.fact("project.inventory")
        current = self.change_analyzer.inventory(self.root)
        previous = {k: tuple(v) for k, v in previous.items()} if previous else {}
        changes = self.change_analyzer.compare(previous, current)
        classes = self.change_analyzer.classify(changes)
        self.memory.fact("project.inventory", current)
        if changes:
            self.memory.remember("project_drift", {"changes": [{"path": c.path, "kind": c.kind} for c in changes], "classes": sorted(classes)})
        return ([{"path": c.path, "kind": c.kind} for c in changes], classes)

    def autonomous_plan(self):
        self.initialize()
        rows = self.memory.objectives()
        objective = Objective(rows[0]["id"], rows[0]["text"], rows[0]["status"], rows[0]["created_at"]) if rows else None
        _, change_classes = self._change_classes()
        tasks = self.planner.plan(objective, self.graph, self.memory.findings(), change_classes)
        self.memory.remember("plan", {"objective": objective.text if objective else None, "change_classes": sorted(change_classes), "tasks": [{"kind": t.kind, "reason": t.reason, "priority": t.priority} for t in tasks]})
        return tasks

    def inspect(self) -> list[dict]:
        self.initialize()
        results = []
        for detector in default_detectors():
            for finding in detector.scan(self.root):
                self.memory.add_finding(finding)
                results.append(self._finding_dict(finding) | {"recommended_action": self.policy.next_action(finding).value})
        self.memory.remember("inspection", {"finding_count": len(results)})
        return results

    def run_autonomous_cycle(self, objective: str | None = None) -> dict:
        self.initialize()
        if objective:
            self.set_objective(objective)
        tasks = self.autonomous_plan()
        selected = tasks[:5]
        cycle_objective = objective or (selected[0].reason if selected else "baseline assurance")
        result = self.investigator.run(cycle_objective)
        decisions = self.assurance.assess(result.findings)
        snapshot = self.snapshotter.capture()
        self.memory.fact("project.snapshot", snapshot.fingerprint)
        self.memory.remember("autonomous_cycle", {"objective": cycle_objective, "tasks": [t.kind for t in selected], "findings": len(result.findings), "decisions": len(decisions)})
        return {"objective": cycle_objective, "plan": [{"kind": t.kind, "reason": t.reason, "priority": t.priority} for t in selected], "findings": [self._finding_dict(f) for f in result.findings], "decisions": [{"id": d.id, "finding_id": d.finding_id, "action": d.action.value, "approved": d.approved, "rationale": d.rationale} for d in decisions], "snapshot": snapshot.fingerprint}

    @staticmethod
    def _finding_dict(finding) -> dict:
        return {"id": finding.id, "title": finding.title, "description": finding.description, "severity": finding.severity.value, "confidence": finding.confidence, "evidence": finding.evidence, "remediation": finding.remediation, "status": finding.status}

    def status(self) -> dict:
        return {"root": str(self.root), "graph_entities": len(self.graph.entities), "graph_relationships": len(self.graph.relationships), "objectives": self.memory.objectives(), "findings": self.memory.findings(), "recent_events": self.memory.recent_events()}

    def close(self) -> None:
        self.memory.close()
