from __future__ import annotations

import hashlib
from pathlib import Path

from .ai_graph import AIGraphBuilder
from .assurance import AssuranceEngine
from .change import ChangeAnalyzer
from .dependency_graph import DependencyGraphBuilder
from .detectors import default_detectors
from .graph import KnowledgeGraph
from .investigation import InvestigationEngine
from .lifecycle import FindingLifecycle
from .memory import Memory
from .models import Objective, Relationship
from .planner import Planner
from .policy import Authority, PolicyEngine
from .reasoning import ReasoningEngine
from .remediation import SafeRemediationEngine
from .remediation_loop import RemediationLoop
from .snapshot import Snapshotter
from .work import WorkQueue


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
        self.dependency_graph = DependencyGraphBuilder()
        self.lifecycle = FindingLifecycle(self.memory)
        self.reasoning = ReasoningEngine(self.memory)
        self.remediation = SafeRemediationEngine()
        self.remediation_loop = RemediationLoop(self.root, self.remediation)
        self.work = WorkQueue(self.memory.db)

    def initialize(self) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        self.graph.discover_project(self.root)
        ai_signals = self.ai_graph.build(self.graph, self.root)
        dependencies = self.dependency_graph.build(self.graph, self.root)
        self.graph.save(self.graph_path)
        self.memory.fact("project.root", str(self.root))
        self.memory.fact("graph.entities", len(self.graph.entities))
        self.memory.fact("graph.relationships", len(self.graph.relationships))
        self.memory.fact("ai.signals", ai_signals)
        self.memory.fact("dependencies.graph", dependencies)
        if self.memory.fact("project.initialized") is None:
            snapshot = self.snapshotter.capture()
            self.memory.fact("project.snapshot", snapshot.fingerprint)
            self.memory.fact("project.initialized", True)
            self.memory.remember("project_initialized", {"root": str(self.root), "entities": len(self.graph.entities), "ai_signals": len(ai_signals), "dependencies": len(dependencies), "snapshot": snapshot.fingerprint})

    def set_objective(self, text: str) -> Objective:
        objective = Objective("O-" + hashlib.sha256(text.encode()).hexdigest()[:10].upper(), text)
        self.memory.add_objective(objective)
        return objective

    def proposed_objectives(self) -> list[dict]:
        self.initialize()
        rows = self.memory.objectives()
        if rows:
            return [{"id": r["id"], "text": r["text"], "source": "user"} for r in rows]
        proposals = [(100, "Establish a security and trust-boundary baseline for the project."), (98, "Identify AI, agent, model, prompt and tool-use components and their risks."), (95, "Identify dependency and software supply-chain exposure."), (90, "Map discovered risks and evidence to applicable governance controls.")]
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

    def _sync_work(self, tasks, objective: str | None, changes: list[dict]) -> None:
        """Materialize the current plan without duplicating durable work."""
        context = hashlib.sha256(str(changes).encode()).hexdigest()[:12] if changes else "stable"
        ids: dict[str, str] = {}
        for task in tasks:
            dependency_ids = tuple(ids[d] for d in task.depends_on if d in ids)
            item = self.work.enqueue(
                kind=task.kind,
                reason=task.reason,
                priority=task.priority,
                objective=objective,
                depends_on=dependency_ids,
                context_key=context,
            )
            ids[task.kind] = item.id
        self.memory.fact("work.pending", [item.to_dict() for item in self.work.pending()])

    def autonomous_plan(self):
        self.initialize()
        rows = self.memory.objectives()
        objective = Objective(rows[0]["id"], rows[0]["text"], rows[0]["status"], rows[0]["created_at"]) if rows else None
        changes, change_classes = self._change_classes()
        tasks = self.planner.plan(objective, self.graph, self.memory.findings(), change_classes)
        self._sync_work(tasks, objective.text if objective else None, changes)
        self.memory.remember("plan", {"objective": objective.text if objective else None, "change_classes": sorted(change_classes), "tasks": [{"kind": t.kind, "reason": t.reason, "priority": t.priority} for t in tasks]})
        return tasks

    def inspect(self) -> list[dict]:
        self.initialize()
        results = []
        for detector in default_detectors():
            for finding in detector.scan(self.root):
                self.memory.add_finding(finding)
                self._project_finding(finding)
                reasoning = self.reasoning.reason(finding, self.graph)
                proposal = self.remediation.propose(self.root, finding)
                self.memory.remember("assurance_reasoning", reasoning.to_dict())
                if proposal:
                    self.memory.remember("remediation_proposal", {"finding_id": finding.id, "path": proposal.path, "before_sha256": proposal.before_sha256, "diff": proposal.diff, "rationale": proposal.rationale})
                results.append(self._finding_dict(finding) | {"recommended_action": self.policy.next_action(finding).value, "reasoning": reasoning.to_dict(), "remediation_proposal": self._proposal_dict(proposal)})
        self.graph.save(self.graph_path)
        self.memory.remember("inspection", {"finding_count": len(results)})
        return results

    def run_autonomous_cycle(self, objective: str | None = None, max_work: int = 5) -> dict:
        self.initialize()
        if objective:
            self.set_objective(objective)
        tasks = self.autonomous_plan()
        rows = self.memory.objectives()
        active_objective = objective or (rows[0]["text"] if rows else None)
        changes, change_classes = self._change_classes()
        selected = []
        for _ in range(max_work):
            item = self.work.claim_next()
            if item is None:
                break
            selected.append(item)
            try:
                result = self.investigator.run(item.reason, item.kind, reconcile_lifecycle=False)
                item_result = result
                self.work.complete(item.id)
                self.memory.remember("work_completed", {"work_id": item.id, "kind": item.kind, "attempts": item.attempts, "findings": len(result.findings), "evidence": len(result.evidence)})
            except Exception as exc:
                self.work.fail(item.id, f"{type(exc).__name__}: {exc}")
                self.memory.remember("work_failed", {"work_id": item.id, "kind": item.kind, "error": str(exc)})
                continue
            findings = item_result.findings
            evidence = item_result.evidence
            if "_findings" not in locals():
                _findings, _evidence = [], []
            _findings.extend(findings)
            _evidence.extend(evidence)
        findings = locals().get("_findings", [])
        evidence = locals().get("_evidence", [])
        validation = self.investigator.run("Validate the current project state with available tests.", "validation", reconcile_lifecycle=False)
        findings.extend(validation.findings)
        evidence.extend(validation.evidence)
        reasoning = []
        remediation = []
        reasoning_by_id = {}
        for finding in findings:
            self._project_finding(finding)
            context = self.reasoning.reason(finding, self.graph, change_classes=change_classes)
            reasoning_by_id[finding.id] = context.to_dict()
            reasoning.append(context.to_dict())
            self.memory.remember("assurance_reasoning", context.to_dict())
            proposal = self.remediation.propose(self.root, finding)
            if proposal:
                item = self._proposal_dict(proposal)
                remediation.append(item)
                self.memory.remember("remediation_proposal", item)
        lifecycle = self.lifecycle.reconcile(findings)
        decisions = self.assurance.assess(findings, reasoning_by_id)
        snapshot = self.snapshotter.capture()
        self.memory.fact("project.snapshot", snapshot.fingerprint)
        pending = self.work.pending()
        self.memory.fact("work.pending", [item.to_dict() for item in pending])
        self.memory.remember("autonomous_cycle", {"objective": active_objective, "tasks": [item.kind for item in selected], "findings": len(findings), "decisions": len(decisions), "evidence": len(evidence), "remediation_proposals": len(remediation), "lifecycle": lifecycle, "pending_work": len(pending)})
        self.graph.save(self.graph_path)
        return {"objective": active_objective, "plan": [{"kind": t.kind, "reason": t.reason, "priority": t.priority} for t in tasks], "work": [item.to_dict() for item in selected], "pending_work": [item.to_dict() for item in pending], "findings": [self._finding_dict(f) for f in findings], "reasoning": reasoning, "remediation_proposals": remediation, "decisions": [{"id": d.id, "finding_id": d.finding_id, "action": d.action.value, "approved": d.approved, "rationale": d.rationale} for d in decisions], "validation": [{"source": e.source, "kind": e.kind, "detail": e.detail} for e in validation.evidence], "snapshot": snapshot.fingerprint}

    def resume(self, max_work: int = 5) -> dict:
        """Resume durable queued/blocked/failed work without rebuilding a new objective."""
        self.work.resume()
        return self.run_autonomous_cycle(max_work=max_work)

    def work_status(self, include_completed: bool = False) -> list[dict]:
        items = self.work.all() if include_completed else self.work.pending()
        return [item.to_dict() for item in items]

    def remediate(self, proposal, *, approved: bool = False, validate: bool = True) -> dict:
        """Execute one previously generated proposal through the approval and validation gates."""
        outcome = self.remediation_loop.execute(proposal, approved=approved, validate=validate)
        payload = outcome.to_dict()
        self.memory.remember("remediation_outcome", payload)
        if outcome.status == "accepted":
            self.memory.remember("project_changed", {"finding_id": proposal.finding_id, "path": proposal.path, "status": "accepted"})
        elif outcome.status == "rolled_back":
            self.memory.remember("project_changed", {"finding_id": proposal.finding_id, "path": proposal.path, "status": "rolled_back"})
        return payload

    def _project_finding(self, finding) -> None:
        entity = self.graph.upsert_entity("finding", finding.id, name=finding.id, attributes={"finding_id": finding.id, "title": finding.title, "severity": finding.severity.value, "confidence": finding.confidence, "status": finding.status})
        evidence_text = " ".join(str(x) for x in finding.evidence).lower()
        for candidate in self.graph.entities.values():
            if candidate.kind in {"file", "python_file"} and candidate.path and candidate.path.lower() in evidence_text:
                self.graph.add_relationship(Relationship(entity.id, "detected_in", candidate.id))
            if candidate.kind == "dependency" and candidate.name.lower() in evidence_text:
                self.graph.add_relationship(Relationship(entity.id, "affects", candidate.id))
            if candidate.kind.startswith("ai_") and candidate.path and candidate.path.lower() in evidence_text:
                self.graph.add_relationship(Relationship(entity.id, "targets", candidate.id))

    @staticmethod
    def _proposal_dict(proposal):
        if proposal is None:
            return None
        return {"finding_id": proposal.finding_id, "path": proposal.path, "before_sha256": proposal.before_sha256, "diff": proposal.diff, "rationale": proposal.rationale}

    @staticmethod
    def _finding_dict(finding) -> dict:
        return {"id": finding.id, "title": finding.title, "description": finding.description, "severity": finding.severity.value, "confidence": finding.confidence, "evidence": finding.evidence, "remediation": finding.remediation, "status": finding.status}

    def status(self) -> dict:
        return {"root": str(self.root), "graph_entities": len(self.graph.entities), "graph_relationships": len(self.graph.relationships), "objectives": self.memory.objectives(), "findings": self.memory.findings(), "work": self.work_status(), "recent_events": self.memory.recent_events()}

    def close(self) -> None:
        self.memory.close()
