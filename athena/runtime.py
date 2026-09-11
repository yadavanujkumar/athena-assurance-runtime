from __future__ import annotations

import hashlib
import os

from .ai_graph import AIGraphBuilder
from .ai_inventory import AIInventory
from .assurance import AssuranceEngine
from .change import ChangeAnalyzer
from .config import RuntimeConfig
from .dependencies import DependencyAnalyzer
from .dependency_graph import DependencyGraphBuilder
from .evidence import EvidenceLedger
from .graph import ProjectGraph, Relationship
from .investigation import Investigator
from .lifecycle import FindingLifecycle
from .memory import MemoryStore
from .models import Action, Finding, Objective, utc_now
from .planner import Planner
from .policy import Authority, PolicyEngine
from .remediation import RemediationPlanner
from .remediation_loop import RemediationLoop
from .reasoning import ReasoningEngine
from .snapshot import Snapshotter
from .validation import ValidationEngine
from .work import WorkQueue
from .leases import WorkLeaseStore


class AthenaRuntime:
    """Local-first autonomous assurance runtime."""

    def __init__(self, root, *, authority: Authority | None = None) -> None:
        self.root = root
        self.athena_dir = root / ".athena"
        self.athena_dir.mkdir(exist_ok=True)
        self.config = RuntimeConfig.load(root)
        configured_authority = Authority(**self.config.authority)
        self.db_path = self.athena_dir / "athena.db"
        self.graph_path = self.athena_dir / "graph.json"
        self.memory = MemoryStore(self.db_path)
        self.graph = ProjectGraph()
        self.planner = Planner()
        self.investigator = Investigator(root, self.graph, self.memory)
        self.ai_inventory = AIInventory()
        self.ai_graph = AIGraphBuilder()
        self.dependency_graph = DependencyGraphBuilder()
        self.dependency_analyzer = DependencyAnalyzer(root)
        self.validation = ValidationEngine(root)
        self.lifecycle = FindingLifecycle(self.memory)
        self.reasoning = ReasoningEngine(self.memory)
        self.policy = PolicyEngine(authority or configured_authority)
        self.assurance = AssuranceEngine(self.memory, self.policy)
        self.remediation = RemediationPlanner()
        self.remediation_loop = RemediationLoop(self.root, self.validation)
        self.change_analyzer = ChangeAnalyzer(root)
        self.snapshotter = Snapshotter(root)
        self.evidence = EvidenceLedger()
        self.work = WorkQueue(self.memory.db)
        self.leases = WorkLeaseStore(self.memory.db, owner=f"pid:{os.getpid()}")

    def initialize(self) -> None:
        self.graph.load(self.graph_path)
        self.graph.discover_project(self.root)
        self.ai_graph.build(self.graph, self.root)
        self.dependency_graph.build(self.graph, self.root)
        self.graph.save(self.graph_path)

    def set_objective(self, text: str) -> Objective:
        objective = Objective("OBJ-" + hashlib.sha256(text.encode()).hexdigest()[:12].upper(), text, utc_now())
        self.memory.add_objective(objective)
        return objective

    def _change_classes(self) -> tuple[list[dict], set[str]]:
        previous = self.memory.fact("project.inventory") or {}
        current = self.change_analyzer.inventory(self.root)
        previous = {k: tuple(v) if not isinstance(v, dict) else (v.get("sha256", ""), v.get("size", 0), v.get("mtime_ns", 0)) for k, v in previous.items()} if previous else {}
        changes = self.change_analyzer.compare(previous, current)
        classes = self.change_analyzer.classify(changes)
        self.memory.fact("project.inventory", {k: {"sha256": v.sha256, "size": v.size, "mtime_ns": v.mtime_ns} for k, v in current.items()})
        self.memory.fact("project.last_changes", [{"path": c.path, "kind": c.kind} for c in changes])
        self.memory.fact("project.last_change_classes", sorted(classes))
        if changes:
            self.memory.remember("project_drift", {"changes": [{"path": c.path, "kind": c.kind} for c in changes], "classes": sorted(classes)})
        return ([{"path": c.path, "kind": c.kind} for c in changes], classes)

    def _sync_work(self, tasks, objective: str | None, changes: list[dict]) -> None:
        context_key = hashlib.sha256(repr(changes).encode()).hexdigest()[:16] if changes else "stable"
        for task in tasks:
            self.work.enqueue(kind=task.kind, reason=task.reason, priority=task.priority, objective=objective, context_key=context_key)

    def autonomous_plan(self, objective: str | None = None):
        changes, change_classes = self._change_classes()
        tasks = self.planner.plan(objective or self._active_objective(), self.graph, self.memory.findings(), change_classes=change_classes)
        self._sync_work(tasks, objective or self._active_objective(), changes)
        return tasks

    def _active_objective(self) -> str | None:
        rows = self.memory.objectives()
        return rows[0]["text"] if rows else None

    def inspect(self):
        self.initialize()
        return self.investigator.run("Inspect the project for assurance findings.", "security_review").findings

    def _refresh_dependency_advisories(self) -> list[dict]:
        advisories: list[dict] = []
        for ecosystem in ("python", "node"):
            advisories.extend(self.dependency_graph.add_advisories(self.graph, self.root, ecosystem))
        self.memory.fact("dependencies.advisories", advisories)
        return advisories

    def _sync_advisory_work(self, objective: str | None) -> list:
        active_contexts: set[str] = set()
        created = []
        for entity in self.graph.entities.values():
            if entity.kind != "advisory":
                continue
            risk = float(entity.attributes.get("risk", 0))
            if risk < 80:
                continue
            advisory_id = entity.id
            ecosystem = str(entity.attributes.get("ecosystem", "unknown"))
            package = str(entity.attributes.get("package", entity.name or "unknown"))
            identifiers = entity.attributes.get("identifiers", [])
            fixed = entity.attributes.get("fixed_version") or "unknown"
            vulnerable = entity.attributes.get("vulnerable_range") or "unknown"
            context_key = "advisory:" + advisory_id
            active_contexts.add(context_key)
            reason = f"Review active {ecosystem} advisory for {package}; risk={risk:.0f}; identifiers={identifiers}; vulnerable_range={vulnerable}; fixed_version={fixed}. Confirm impact, upgrade/remediation path, and rerun dependency audit."
            created.append(self.work.enqueue(kind="dependency_advisory_review", reason=reason, priority=130 if risk >= 100 else 125, objective=objective, context_key=context_key))
        self.work.cancel_stale_contexts(kind="dependency_advisory_review", context_prefix="advisory:", active_contexts=active_contexts, reason="Advisory is no longer present in the latest successful dependency audit.")
        if created:
            self.memory.remember("advisory_work_synced", {"count": len(created), "work_ids": [item.id for item in created]})
        return created

    def run_autonomous_cycle(self, objective: str | None = None, max_work: int | None = None) -> dict:
        self.initialize()
        if objective:
            self.set_objective(objective)
        self._refresh_dependency_advisories()
        advisory_work = self._sync_advisory_work(objective or self._active_objective())
        tasks = self.autonomous_plan()
        rows = self.memory.objectives()
        active_objective = objective or (rows[0]["text"] if rows else None)
        change_classes = set(self.memory.fact("project.last_change_classes") or [])
        selected = []
        findings, evidence = [], []
        self.work.unblock_ready()
        self.leases.reclaim_expired()
        cycle_limit = self.config.max_work_per_cycle if max_work is None else max(1, int(max_work))
        for _ in range(cycle_limit):
            work_item = self.work.claim_next(max_attempts=self.config.max_attempts)
            if work_item is None:
                break
            lease = self.leases.acquire(work_item.id, ttl_seconds=self.config.lease_ttl_seconds)
            if lease is None:
                self.work.fail(work_item.id, "Work lease is held by another active worker.", retry=True, max_attempts=self.config.max_attempts)
                continue
            selected.append(work_item)
            try:
                result = self.investigator.run(work_item.reason, work_item.kind, reconcile_lifecycle=False)
                findings.extend(result.findings)
                evidence.extend(result.evidence)
                self.work.complete(work_item.id)
                self.memory.remember("work_completed", {"work_id": work_item.id, "kind": work_item.kind, "attempts": work_item.attempts, "findings": len(result.findings), "evidence": len(result.evidence), "worker": lease.owner})
            except Exception as exc:
                self.work.fail(work_item.id, f"{type(exc).__name__}: {exc}", max_attempts=self.config.max_attempts)
                self.memory.remember("work_failed", {"work_id": work_item.id, "kind": work_item.kind, "error": str(exc), "worker": lease.owner})
            finally:
                self.leases.release(work_item.id)
        validation = self.investigator.run("Validate the current project state with available tests.", "validation", reconcile_lifecycle=False) if self.config.validation_enabled else None
        if validation:
            findings.extend(validation.findings)
            evidence.extend(validation.evidence)
        lifecycle = self.lifecycle.reconcile(findings)
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
        decisions = self.assurance.assess(findings, reasoning_by_id)
        snapshot = self.snapshotter.capture()
        self.memory.fact("project.snapshot", snapshot.fingerprint)
        pending = self.work.pending()
        self.memory.fact("work.pending", [item.to_dict() for item in pending])
        self.memory.remember("autonomous_cycle", {"objective": active_objective, "tasks": [item.kind for item in selected], "advisory_work": [item.id for item in advisory_work], "findings": len(findings), "decisions": len(decisions), "evidence": len(evidence), "remediation_proposals": len(remediation), "lifecycle": lifecycle, "pending_work": len(pending)})
        self.graph.save(self.graph_path)
        return {"objective": active_objective, "plan": [{"kind": t.kind, "reason": t.reason, "priority": t.priority} for t in tasks], "work": [item.to_dict() for item in selected], "pending_work": [item.to_dict() for item in pending], "findings": [self._finding_dict(f) for f in findings], "reasoning": reasoning, "remediation_proposals": remediation, "decisions": [{"id": d.id, "finding_id": d.finding_id, "action": d.action.value, "approved": d.approved, "rationale": d.rationale} for d in decisions], "validation": ([{"source": e.source, "kind": e.kind, "detail": e.detail} for e in validation.evidence] if validation else []), "snapshot": snapshot.fingerprint}

    def resume(self, max_work: int | None = None) -> dict:
        self.work.resume()
        return self.run_autonomous_cycle(max_work=max_work)

    def work_status(self, include_completed: bool = False) -> list[dict]:
        items = self.work.all() if include_completed else self.work.pending()
        return [item.to_dict() for item in items]

    def remediate(self, proposal, *, approved: bool = False, validate: bool = True) -> dict:
        finding = next((f for f in self.memory.findings() if f["id"] == proposal.finding_id), None)
        if finding is None:
            payload = {"finding_id": proposal.finding_id, "status": "policy_denied", "path": proposal.path, "validation": None, "rollback_available": False, "reason": "Finding is not present in durable memory; remediation is denied conservatively."}
            self.memory.remember("remediation_denied", payload)
            return payload
        if not self.policy.can_remediate_record(finding):
            payload = {"finding_id": proposal.finding_id, "status": "policy_denied", "path": proposal.path, "validation": None, "rollback_available": False, "reason": "Policy does not grant MODIFY authority for this finding."}
            self.memory.remember("remediation_denied", payload)
            return payload
        outcome = self.remediation_loop.execute(proposal, approved=approved, validate=validate)
        payload = outcome.to_dict()
        self.memory.remember("remediation_outcome", payload)
        if outcome.status in {"accepted", "rolled_back", "rollback_blocked"}:
            self.memory.remember("project_changed", {"finding_id": proposal.finding_id, "path": proposal.path, "status": outcome.status})
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
        return {"root": str(self.root), "graph_entities": len(self.graph.entities), "graph_relationships": len(self.graph.relationships), "objectives": self.memory.objectives(), "findings": self.memory.findings(), "work": self.work_status(), "recent_events": self.memory.recent_events(), "config": {"max_work_per_cycle": self.config.max_work_per_cycle, "max_attempts": self.config.max_attempts, "lease_ttl_seconds": self.config.lease_ttl_seconds, "validation_enabled": self.config.validation_enabled, "authority": dict(self.config.authority)}}

    def close(self) -> None:
        self.memory.close()
