from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

from .remediation import PatchProposal, SafeRemediationEngine
from .validation import ValidationEngine


@dataclass(frozen=True, slots=True)
class RemediationOutcome:
    finding_id: str
    status: str
    path: str | None = None
    validation: list[dict] | None = None
    rollback_available: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class RemediationLoop:
    """Approval-gated remediation loop: propose, apply, validate, and rollback on failure."""

    def __init__(self, root: str | Path, remediation: SafeRemediationEngine | None = None, validation: ValidationEngine | None = None) -> None:
        self.root = Path(root).resolve()
        self.remediation = remediation or SafeRemediationEngine()
        self.validation = validation or ValidationEngine()

    def execute(self, proposal: PatchProposal, *, approved: bool = False, validate: bool = True) -> RemediationOutcome:
        if not approved:
            return RemediationOutcome(proposal.finding_id, "approval_required", proposal.path, reason="Explicit approval is required before any write.")
        path = self.remediation.apply(self.root, proposal, approved=True)
        results: list[dict] = []
        if validate:
            for command in self.validation.detect_commands(self.root):
                result = self.validation.run(self.root, command)
                results.append(result.to_dict())
            if results and not all(item["passed"] for item in results if item["available"]):
                path.write_text(proposal.before, encoding="utf-8")
                return RemediationOutcome(proposal.finding_id, "rolled_back", proposal.path, results, True, "Validation failed; the exact pre-remediation content was restored.")
        return RemediationOutcome(proposal.finding_id, "accepted", proposal.path, results, True, "Patch applied and validation gates passed or no validation command was available.")
