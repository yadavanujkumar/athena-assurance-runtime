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
    """Deterministic planning kernel that adapts assurance work to project signals."""

    def plan(self, objective: Objective | None, graph, findings: list[dict], change_classes: set[str] | None = None) -> list[InvestigationTask]:
        tasks: list[InvestigationTask] = []
        change_classes = change_classes or set()
        if objective:
            text = objective.text.lower()
            tasks.append(InvestigationTask("scope_objective", f"Translate objective into evidence requirements: {objective.text}", 100))
            if any(word in text for word in ("security", "secure", "vulnerability", "secret")):
                tasks.append(InvestigationTask("security_review", "Objective indicates security assurance is required.", 95, ("scope_objective",)))
            if any(word in text for word in ("ai", "model", "agent", "llm", "prompt")):
                tasks.append(InvestigationTask("ai_system_review", "Objective indicates AI/agent assurance is required.", 95, ("scope_objective",)))
            if any(word in text for word in ("compliance", "governance", "nist", "iso", "eu", "owasp")):
                tasks.append(InvestigationTask("governance_review", "Objective indicates governance/control mapping is required.", 90, ("scope_objective",)))
            if "dependency" in text or "supply" in text:
                tasks.append(InvestigationTask("dependency_review", "Objective indicates supply-chain assurance is required.", 92, ("scope_objective",)))
            tasks.append(InvestigationTask("evidence_validation", "Validate conclusions against project evidence and tests.", 80, ("scope_objective",)))
        else:
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

        # Drift overrides the generic baseline: changed surfaces get focused assurance first.
        focused: list[InvestigationTask] = []
        if "security" in change_classes:
            focused.append(InvestigationTask("security_review", "Recent changes touch security-sensitive configuration or authorization surfaces.", 120))
        if "ai" in change_classes:
            focused.append(InvestigationTask("ai_system_review", "Recent changes touch AI/agent/model/prompt surfaces.", 118))
        if "dependency" in change_classes:
            focused.append(InvestigationTask("dependency_review", "Recent changes touch dependency manifests or lockfiles.", 116))
        if "deployment" in change_classes:
            focused.append(InvestigationTask("deployment_review", "Recent changes touch deployment or infrastructure surfaces.", 114))
        if "source" in change_classes:
            focused.append(InvestigationTask("change_validation", "Source changed; validate affected behavior before accepting the new state.", 112))
        if focused:
            tasks.extend(focused)

        deduped: dict[str, InvestigationTask] = {}
        for task in tasks:
            existing = deduped.get(task.kind)
            if existing is None or task.priority > existing.priority:
                deduped[task.kind] = task
        return sorted(deduped.values(), key=lambda task: task.priority, reverse=True)
