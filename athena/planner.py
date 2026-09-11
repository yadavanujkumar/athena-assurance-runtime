from __future__ import annotations

from dataclasses import dataclass

from .models import Objective


@dataclass(frozen=True, slots=True)
class InvestigationTask:
    kind: str
    reason: str
    priority: int
    depends_on: tuple[str, ...] = ()


class Planner:
    """Deterministic planning kernel; an LLM may enrich plans later."""

    def plan(self, objective: Objective | None, graph, findings: list[dict]) -> list[InvestigationTask]:
        tasks: list[InvestigationTask] = []
        if objective:
            text = objective.text.lower()
            tasks.append(InvestigationTask("scope_objective", f"Translate objective into evidence requirements: {objective.text}", 100))
            if any(word in text for word in ("security", "secure", "vulnerability", "secret")):
                tasks.append(InvestigationTask("security_review", "Objective indicates security assurance is required.", 95, ("scope_objective",)))
            if any(word in text for word in ("ai", "model", "agent", "llm", "prompt")):
                tasks.append(InvestigationTask("ai_system_review", "Objective indicates AI/agent assurance is required.", 95, ("scope_objective",)))
            if any(word in text for word in ("compliance", "governance", "nist", "iso", "eu", "owasp")):
                tasks.append(InvestigationTask("governance_review", "Objective indicates governance/control mapping is required.", 90, ("scope_objective",)))
            tasks.append(InvestigationTask("evidence_validation", "Validate conclusions against project evidence and tests.", 80, ("scope_objective",)))
            return tasks

        tasks.extend([
            InvestigationTask("architecture_review", "No objective was supplied; establish the project's architecture and trust boundaries.", 100),
            InvestigationTask("security_review", "Establish a security baseline before deeper autonomous analysis.", 95),
            InvestigationTask("dependency_review", "Identify dependency and supply-chain exposure.", 90),
        ])
        if any(e.kind in {"python_file", "file"} and e.path and any(x in e.path.lower() for x in ("model", "agent", "prompt", "llm", "ai")) for e in graph.entities.values()):
            tasks.append(InvestigationTask("ai_system_review", "Project signals suggest AI/agent components; inspect their boundaries and controls.", 98))
        if findings:
            tasks.append(InvestigationTask("finding_triage", f"Re-evaluate {len(findings)} persisted findings against current project evidence.", 97))
        tasks.append(InvestigationTask("governance_review", "Map discovered risks to applicable governance controls.", 85))
        return sorted(tasks, key=lambda task: task.priority, reverse=True)
