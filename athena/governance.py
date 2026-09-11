from __future__ import annotations

from dataclasses import dataclass, asdict

from .models import Finding, Severity


@dataclass(frozen=True, slots=True)
class Control:
    framework: str
    control_id: str
    title: str
    intent: str

    def to_dict(self) -> dict:
        return asdict(self)


OPEN_CONTROLS = (
    Control("NIST AI RMF", "GOVERN", "Governance", "Establish accountability, policies, roles and oversight for AI risk."),
    Control("NIST AI RMF", "MAP", "Context and risk mapping", "Identify intended use, stakeholders, impacts, dependencies and risks."),
    Control("NIST AI RMF", "MEASURE", "Risk measurement", "Measure, analyze and document AI risks using evidence."),
    Control("NIST AI RMF", "MANAGE", "Risk management", "Prioritize, respond to and monitor identified AI risks."),
    Control("ISO/IEC 42001", "AIMS", "AI management system", "Maintain an accountable management system for AI governance."),
    Control("EU AI Act", "RISK", "AI risk classification", "Determine applicable obligations based on the system and intended use."),
    Control("OWASP", "AI-SECURITY", "AI security", "Assess application and AI-specific attack surfaces, including prompts, tools and data."),
)


class GovernanceCatalog:
    def controls(self, framework: str | None = None) -> list[Control]:
        return [c for c in OPEN_CONTROLS if framework is None or c.framework.lower() == framework.lower()]

    def map_finding(self, finding: Finding) -> list[str]:
        mappings: list[str] = []
        if finding.severity in {Severity.HIGH, Severity.CRITICAL}:
            mappings += ["NIST AI RMF:MANAGE", "NIST AI RMF:MEASURE"]
        if "AI" in finding.title or "agent" in finding.description.lower():
            mappings += ["NIST AI RMF:MAP", "ISO/IEC 42001:AIMS", "OWASP:AI-SECURITY"]
        return sorted(set(mappings))
