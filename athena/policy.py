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
    """Maps risk to a bounded action without silently granting write authority."""

    def __init__(self, authority: Authority | None = None) -> None:
        self.authority = authority or Authority()

    def next_action(self, finding: Finding) -> Action:
        if finding.severity is Severity.CRITICAL and self.authority.block:
            return Action.BLOCK
        if finding.severity in {Severity.HIGH, Severity.CRITICAL}:
            return Action.MODIFY if self.authority.modify else Action.RECOMMEND
        return Action.RECOMMEND
