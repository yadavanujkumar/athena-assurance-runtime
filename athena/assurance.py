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

    def assess(self, findings: list[Finding], reasoning: dict[str, dict] | None = None) -> list[Decision]:
        decisions: list[Decision] = []
        reasoning = reasoning or {}
        for finding in findings:
            context = reasoning.get(finding.id) or {}
            action = self._action_for_context(finding, context)
            approved = action in {Action.OBSERVE, Action.INVESTIGATE, Action.RECOMMEND}
            if action is Action.BLOCK or finding.severity is Severity.CRITICAL and not self.policy.authority.block:
                approved = False
            rationale = self._rationale(finding, action, context)
            decision_id = "D-" + hashlib.sha256(f"{finding.id}:{action.value}".encode()).hexdigest()[:12].upper()
            decision = Decision(decision_id, finding.id, action, approved, rationale, utc_now())
            self.memory.add_decision(decision)
            if not approved and action in {Action.MODIFY, Action.BLOCK}:
                request_id = "REQ-" + hashlib.sha256(f"{finding.id}:{action.value}".encode()).hexdigest()[:12].upper()
                self.memory.create_decision_request(request_id, finding.id, action.value, rationale)
            controls = self.governance.map_finding(finding)
            plan = [{"action": step.action, "rationale": step.rationale, "requires_approval": step.requires_approval} for step in self.remediation.plan(finding, action)]
            self.memory.remember("governance_mapping", {"finding_id": finding.id, "controls": controls})
            self.memory.remember("remediation_plan", {"finding_id": finding.id, "decision_id": decision.id, "steps": plan})
            decisions.append(decision)
        return decisions

    def _action_for_context(self, finding: Finding, context: dict) -> Action:
        """Use lifecycle and graph risk to prioritize action inside policy authority."""
        action = self.policy.next_action(finding)
        band = str(context.get("risk_band", "")).lower()
        lifecycle = str((context.get("lifecycle") or {}).get("state", "new")).lower()
        if lifecycle == "resolved":
            return Action.OBSERVE if self.policy.can_execute(Action.OBSERVE) else action
        if lifecycle in {"reopened", "worsening"} and band in {"critical", "high"}:
            if self.policy.can_execute(Action.INVESTIGATE):
                return Action.INVESTIGATE
        if lifecycle == "new" and band in {"critical", "high"}:
            if self.policy.can_execute(Action.INVESTIGATE):
                return Action.INVESTIGATE
        if band == "critical" and self.policy.authority.block:
            return Action.BLOCK
        if band in {"critical", "high"} and self.policy.authority.modify and action is Action.RECOMMEND:
            return Action.MODIFY
        return action

    @staticmethod
    def _rationale(finding: Finding, action: Action, context: dict | None) -> str:
        prefix = ""
        lifecycle = str((context or {}).get("lifecycle", {}).get("state", "unknown"))
        if context:
            prefix = f"Graph context identifies {len(context.get('affected_components', []))} affected component(s) with risk band {context.get('risk_band', 'unknown')}. "
            if lifecycle != "unknown":
                prefix += f"Lifecycle state is {lifecycle}. "
            if context.get("supply_chain_risk"):
                prefix += f"Supply-chain advisory risk is {context['supply_chain_risk']}/100. "
            if context.get("uncertainties"):
                prefix += "Uncertainty remains, so validation is required. "
        if lifecycle == "resolved":
            return prefix + "The finding is resolved; assurance is limited to observation and recurrence detection."
        if lifecycle == "reopened":
            return prefix + "The finding has regressed after resolution; immediate investigation is warranted."
        if lifecycle == "worsening":
            return prefix + "The finding is worsening; assurance escalates investigation before remediation."
        if lifecycle == "recurring":
            return prefix + "The finding is recurring; avoid redundant investigation unless evidence or risk changes."
        if action is Action.MODIFY:
            return prefix + "Modification authority is enabled; execution must still pass validation gates."
        if action is Action.BLOCK:
            return prefix + "Critical risk meets the configured blocking threshold."
        if finding.severity in {Severity.HIGH, Severity.CRITICAL} or context.get("risk_band") in {"high", "critical"}:
            return prefix + "High-impact risk is surfaced for human-controlled remediation."
        return prefix + "Low-impact finding can be investigated and recommended without write authority."
