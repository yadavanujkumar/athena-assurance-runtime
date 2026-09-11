from __future__ import annotations

import hashlib

from .governance import GovernanceCatalog
from .models import Action, Decision, Finding, Severity, utc_now
from .remediation import RemediationPlanner


class AssuranceEngine:
    """Turns findings into risk decisions and bounded remediation plans."""

    def __init__(self, memory, policy) -> None:
        self.memory = memory
        self.policy = policy
        self.governance = GovernanceCatalog()
        self.remediation = RemediationPlanner()

    def assess(self, findings: list[Finding]) -> list[Decision]:
        decisions: list[Decision] = []
        for finding in findings:
            action = self.policy.next_action(finding)
            approved = action in {Action.OBSERVE, Action.INVESTIGATE, Action.RECOMMEND}
            if finding.severity is Severity.CRITICAL and not self.policy.authority.block:
                approved = False
            rationale = self._rationale(finding, action, approved)
            decision_id = "D-" + hashlib.sha256(f"{finding.id}:{action.value}".encode()).hexdigest()[:12].upper()
            decision = Decision(decision_id, finding.id, action, approved, rationale, utc_now())
            self.memory.add_decision(decision)
            controls = self.governance.map_finding(finding)
            plan = [
                {"action": step.action, "rationale": step.rationale, "requires_approval": step.requires_approval}
                for step in self.remediation.plan(finding, action)
            ]
            self.memory.remember("governance_mapping", {"finding_id": finding.id, "controls": controls})
            self.memory.remember("remediation_plan", {"finding_id": finding.id, "decision_id": decision.id, "steps": plan})
            decisions.append(decision)
        return decisions

    @staticmethod
    def _rationale(finding: Finding, action: Action, approved: bool) -> str:
        if action is Action.MODIFY:
            return "Modification authority is enabled; execution must still pass validation gates."
        if action is Action.BLOCK:
            return "Critical risk meets the configured blocking threshold."
        if finding.severity in {Severity.HIGH, Severity.CRITICAL}:
            return "High-impact risk is surfaced for human-controlled remediation."
        return "Low-impact finding can be investigated and recommended without write authority."
