from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Control:
    id: str
    framework: str
    title: str
    objective: str
    severity: str = "medium"


CATALOG = (
    Control("NIST-GOV-01", "NIST AI RMF", "Governance accountability", "Define accountable roles, authority and oversight for AI risk."),
    Control("NIST-MAP-01", "NIST AI RMF", "Context mapping", "Identify intended use, affected parties and system context."),
    Control("NIST-MEASURE-01", "NIST AI RMF", "Risk measurement", "Measure identified risks using repeatable evidence."),
    Control("NIST-MANAGE-01", "NIST AI RMF", "Risk treatment", "Prioritize and manage risks using documented actions."),
    Control("ISO42001-AIMS-01", "ISO/IEC 42001", "AIMS operation", "Maintain an auditable AI management system."),
    Control("EUAI-RISK-01", "EU AI Act", "Risk management", "Maintain a lifecycle risk-management process for applicable AI systems."),
    Control("OWASP-AI-SEC-01", "OWASP AI Security", "AI security assurance", "Identify and mitigate security risks across AI application boundaries."),
)


def controls_for(framework: str | None = None) -> tuple[Control, ...]:
    if not framework:
        return CATALOG
    text = framework.lower()
    return tuple(control for control in CATALOG if text in control.framework.lower())
