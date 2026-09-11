from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .detectors import default_detectors
from .models import Finding, Severity, utc_now


@dataclass(slots=True)
class Evidence:
    source: str
    kind: str
    detail: str
    collected_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class InvestigationResult:
    objective: str
    findings: list[Finding]
    evidence: list[Evidence]
    completed: bool = True


class InvestigationEngine:
    """Runs bounded, deterministic investigations and produces an evidence ledger."""

    def __init__(self, root: Path, memory, governance=None) -> None:
        self.root = root
        self.memory = memory
        self.governance = governance

    def run(self, objective: str) -> InvestigationResult:
        evidence = [Evidence(str(self.root), "scope", objective)]
        findings: list[Finding] = []
        detectors = default_detectors()
        for detector in detectors:
            for finding in detector.scan(self.root):
                findings.append(finding)
                self.memory.add_finding(finding)
                for item in finding.evidence:
                    evidence.append(Evidence(item, "finding", finding.title))
        self.memory.remember(
            "investigation_completed",
            {
                "objective": objective,
                "detectors": [d.name for d in detectors],
                "finding_count": len(findings),
                "critical_count": sum(f.severity is Severity.CRITICAL for f in findings),
                "high_count": sum(f.severity is Severity.HIGH for f in findings),
            },
        )
        return InvestigationResult(objective, findings, evidence)
