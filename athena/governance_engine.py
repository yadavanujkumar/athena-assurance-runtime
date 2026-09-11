from __future__ import annotations

from dataclasses import dataclass

from .governance import GovernanceCatalog
from .models import Finding, Severity


@dataclass(frozen=True, slots=True)
class ControlAssessment:
    framework: str
    control_id: str
    status: str
    rationale: str
    evidence: tuple[str, ...] = ()
    gap: str | None = None

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "control_id": self.control_id,
            "status": self.status,
            "rationale": self.rationale,
            "evidence": list(self.evidence),
            "gap": self.gap,
        }


class GovernanceEngine:
    """Deterministic control assessment; absence of evidence never becomes compliance."""

    def __init__(self, catalog: GovernanceCatalog | None = None) -> None:
        self.catalog = catalog or GovernanceCatalog()

    def assess(self, finding: Finding, *, extra_evidence: list[str] | None = None) -> list[ControlAssessment]:
        evidence = tuple(dict.fromkeys([*(str(x) for x in finding.evidence), *(extra_evidence or [])]))
        mappings = set(self.catalog.map_finding(finding))
        assessments: list[ControlAssessment] = []
        for control in self.catalog.controls():
            key = f"{control.framework}:{control.control_id}"
            if key not in mappings:
                continue
            if finding.status == "resolved":
                assessments.append(ControlAssessment(control.framework, control.control_id, "addressed", "The mapped finding is resolved in the current lifecycle state.", evidence))
            elif finding.severity in {Severity.CRITICAL, Severity.HIGH} and not evidence:
                assessments.append(ControlAssessment(control.framework, control.control_id, "gap", "A material risk is mapped to this control but no supporting evidence was retained.", evidence, "Collect and retain objective evidence before claiming control effectiveness."))
            else:
                assessments.append(ControlAssessment(control.framework, control.control_id, "attention", "The control is implicated by the current finding and requires risk treatment or documented acceptance.", evidence, "Establish ownership, treatment, validation evidence and closure criteria."))
        return assessments

    def summary(self, assessments: list[ControlAssessment]) -> dict:
        counts = {status: 0 for status in ("addressed", "attention", "gap")}
        for item in assessments:
            counts[item.status] = counts.get(item.status, 0) + 1
        return {"total": len(assessments), "counts": counts, "assessments": [item.to_dict() for item in assessments]}
