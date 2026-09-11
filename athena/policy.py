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

    def can_remediate_record(self, record: dict) -> bool:
        """Apply the same policy decision to a finding persisted in durable memory."""
        try:
            severity = Severity(record["severity"])
        except (KeyError, ValueError):
            return False
        finding = Finding(
            id=str(record.get("id", "")),
            title=str(record.get("title", "")),
            description=str(record.get("description", "")),
            severity=severity,
            confidence=float(record.get("confidence", 0.0)),
            evidence=[str(item) for item in record.get("evidence", [])],
            remediation=record.get("remediation"),
            status=str(record.get("status", "open")),
            created_at=str(record.get("created_at", "")),
        )
        return self.can_remediate(finding)
