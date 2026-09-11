from __future__ import annotations

from dataclasses import dataclass

from .models import Action, Finding


@dataclass(frozen=True, slots=True)
class RemediationStep:
    action: str
    rationale: str
    requires_approval: bool


class RemediationPlanner:
    """Produces bounded remediation plans; it never changes project files itself."""

    def plan(self, finding: Finding, action: Action) -> list[RemediationStep]:
        steps: list[RemediationStep] = []
        if finding.remediation:
            steps.append(RemediationStep(finding.remediation, "Use the detector's evidence-backed remediation guidance.", action is Action.MODIFY))
        if action is Action.MODIFY:
            steps.append(RemediationStep("create_patch", "Prepare a minimal, reviewable change rather than mutating the working tree directly.", True))
            steps.append(RemediationStep("run_validation", "Run relevant tests and assurance checks before accepting the change.", True))
        elif action is Action.RECOMMEND:
            steps.append(RemediationStep("request_approval", "Present the evidence, risk, proposed change and validation plan to an authorized human.", True))
        return steps
