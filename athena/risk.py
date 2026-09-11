from __future__ import annotations

from dataclasses import dataclass
from .models import Finding, Severity


@dataclass(frozen=True, slots=True)
class RiskScore:
    score: float
    band: str
    rationale: str


class RiskEngine:
    """Transparent risk prioritisation, deliberately avoiding fake statistical precision."""

    _weights = {Severity.INFO: 0.05, Severity.LOW: 0.2, Severity.MEDIUM: 0.45, Severity.HIGH: 0.75, Severity.CRITICAL: 1.0}

    def score(self, finding: Finding) -> RiskScore:
        severity = self._weights[finding.severity]
        confidence = max(0.0, min(1.0, finding.confidence))
        exposure = 1.0 if finding.evidence else 0.7
        score = round(100 * severity * (0.5 + 0.5 * confidence) * exposure, 2)
        band = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
        return RiskScore(score, band, f"severity={finding.severity.value}; confidence={confidence:.2f}; evidence={'present' if finding.evidence else 'limited'}")
