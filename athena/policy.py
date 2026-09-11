from __future__ import annotations

from dataclasses import dataclass

from .models import Action, Finding, Severity


@dataclass(slots=True)
class Authority:
    observe: bool = True
    investigate: bool = True
    recommend: bool = True
    modify: bool = False
    block: bool = False

    def allowed(self, action: Action) -> bool:
        return getattr(self, action.value)


class PolicyEngine:
    """Enforces an explicit autonomy boundary; no write authority is implicit."""

    def __init__(self, authority: Authority | None = None) -> None:
        self.authority = authority or Authority()

    def next_action(self, finding: Finding) -> Action:
        if finding.severity is Severity.CRITICAL and self.authority.block:
            return Action.BLOCK
        if finding.severity in {Severity.HIGH, Severity.CRITICAL}:
            return Action.MODIFY if self.authority.modify else Action.RECOMMEND
        return Action.RECOMMEND

    def can_execute(self, action: Action) -> bool:
        return self.authority.allowed(action)

    def can_remediate(self, finding: Finding) -> bool:
        """A write is permitted only when policy grants MODIFY authority."""
        return self.authority.allowed(Action.MODIFY) and self.next_action(finding) is Action.MODIFY
