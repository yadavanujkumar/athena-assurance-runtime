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

    @staticmethod
    def _band(score: float) -> str:
        return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"

    def score(self, finding: Finding) -> RiskScore:
        severity = self._weights[finding.severity]
        confidence = max(0.0, min(1.0, finding.confidence))
        exposure = 1.0 if finding.evidence else 0.7
        score = round(100 * severity * (0.5 + 0.5 * confidence) * exposure, 2)
        band = self._band(score)
        return RiskScore(score, band, f"severity={finding.severity.value}; confidence={confidence:.2f}; evidence={'present' if finding.evidence else 'limited'}")

    def with_supply_chain(self, base: RiskScore, advisory_risk: int) -> RiskScore:
        """Blend independent advisory exposure into finding risk without changing its severity."""
        advisory = max(0, min(100, int(advisory_risk)))
        if advisory == 0:
            return base
        # Supply-chain evidence contributes up to 30% of the final score; the finding remains
        # the primary signal and an advisory cannot manufacture more than critical-band risk.
        score = round(min(100.0, base.score * 0.7 + advisory * 0.3), 2)
        band = self._band(score)
        rationale = f"{base.rationale}; supply_chain_risk={advisory}; adjusted_score={score:.2f}"
        return RiskScore(score, band, rationale)
