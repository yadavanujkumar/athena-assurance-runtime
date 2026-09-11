from __future__ import annotations

from dataclasses import dataclass, asdict

from .governance import GovernanceCatalog
from .lifecycle import FindingLifecycle
from .models import Finding
from .risk import RiskEngine


@dataclass(frozen=True, slots=True)
class AssuranceReasoning:
    """Deterministic, auditable reasoning context assembled from project evidence."""

    finding_id: str
    risk_score: float
    risk_band: str
    risk_rationale: str
    affected_components: list[dict]
    impact_path: list[dict]
    supporting_evidence: list[str]
    risk_factors: list[str]
    uncertainties: list[str]
    governance_mappings: list[str]
    lifecycle: dict | None
    prior_decisions: list[dict]
    recommended_investigations: list[str]
    why_now: list[str]
    confidence: float
    supply_chain_risk: int = 0
    affected_advisories: list[dict] | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ReasoningEngine:
    """Turns graph, risk, governance and memory signals into explainable assurance context."""

    def __init__(self, memory, risk: RiskEngine | None = None, governance: GovernanceCatalog | None = None) -> None:
        self.memory = memory
        self.risk = risk or RiskEngine()
        self.governance = governance or GovernanceCatalog()
        self.lifecycle = FindingLifecycle(memory)

    @staticmethod
    def _supply_chain_context(entities: list[dict], relationships: list[dict]) -> tuple[int, list[dict]]:
        """Return the strongest connected advisory risk and its advisory records."""
        dependency_ids = {e["id"] for e in entities if e.get("kind") == "dependency"}
        advisory_by_id = {e["id"]: e for e in entities if e.get("kind") == "advisory"}
        connected: list[dict] = []
        for edge in relationships:
            if edge.get("relation") != "affected_by" or edge.get("source") not in dependency_ids:
                continue
            advisory = advisory_by_id.get(edge.get("target"))
            if advisory:
                attrs = advisory.get("attributes") or {}
                connected.append({
                    "id": advisory["id"],
                    "name": advisory.get("name", "advisory"),
                    "package": attrs.get("package", ""),
                    "severity": attrs.get("severity", "unknown"),
                    "risk": int(attrs.get("risk", 0) or 0),
                    "identifiers": list(attrs.get("identifiers", []) or []),
                })
        connected.sort(key=lambda item: (-item["risk"], item["package"], item["name"]))
        return (max((item["risk"] for item in connected), default=0), connected)

    def reason(self, finding: Finding, graph, *, change_classes: set[str] | None = None) -> AssuranceReasoning:
        risk = self.risk.score(finding)
        context = graph.context_for_finding(finding.id, depth=2)
        entities = context.get("entities", [])
        relationships = context.get("relationships", [])
        entity_by_id = {e["id"]: e for e in entities}
        supply_risk, advisories = self._supply_chain_context(entities, relationships)
        adjusted_score = self.risk.with_supply_chain(risk, supply_risk)

        affected = [
            e for e in entities
            if e.get("kind") in {"file", "python_file", "dependency", "advisory", "ai_provider", "ai_model", "ai_prompt", "ai_tool", "ai_network_boundary", "ai_execution_boundary"}
        ]
        affected.sort(key=lambda e: (e.get("kind", ""), e.get("path") or "", e.get("name", "")))

        paths: list[dict] = []
        for edge in relationships:
            source = entity_by_id.get(edge["source"])
            target = entity_by_id.get(edge["target"])
            if source and target:
                paths.append({"source": source["name"], "source_kind": source["kind"], "relation": edge["relation"], "target": target["name"], "target_kind": target["kind"]})
        paths.sort(key=lambda p: (p["source_kind"], p["source"], p["relation"], p["target"]))

        supporting = list(dict.fromkeys(str(x) for x in finding.evidence))
        risk_factors = [f"Severity is {finding.severity.value}.", f"Detection confidence is {finding.confidence:.2f}."]
        if supporting:
            risk_factors.append("The finding has direct detector evidence.")
        else:
            risk_factors.append("The finding has no direct detector evidence; risk is discounted by the risk engine.")
        if supply_risk:
            risk_factors.append(f"Connected supply-chain advisory risk is {supply_risk}/100.")
        if any(e.get("kind", "").startswith("ai_") for e in affected):
            risk_factors.append("The finding is connected to an AI trust-boundary component.")
        if any(e.get("kind") == "dependency" for e in affected):
            risk_factors.append("The finding is connected to a declared dependency.")

        uncertainties: list[str] = []
        if not affected:
            uncertainties.append("No graph entity could be connected to this finding; impact scope is not yet established.")
        if not paths:
            uncertainties.append("No relationship path is available beyond the finding node.")
        if finding.confidence < 0.75:
            uncertainties.append("Detector confidence is below 0.75; targeted validation is recommended before remediation.")

        lifecycle_map = self.memory.fact("finding.lifecycle") or {}
        state = lifecycle_map.get(finding.id)
        if state is None:
            fingerprint = self.lifecycle.fingerprint(finding)
            state = lifecycle_map.get(fingerprint)

        decisions = [d for d in self.memory.decisions() if d.get("finding_id") == finding.id][:5]
        drift_events = self.memory.search_events("project_drift", limit=5)
        why_now: list[str] = []
        classes = sorted(change_classes or set())
        if classes:
            why_now.append("The current cycle detected change classes: " + ", ".join(classes) + ".")
        if drift_events:
            why_now.append("Recent project drift exists in durable memory.")
        if state and state.get("status") == "reopened":
            why_now.append("This finding was previously resolved and has reappeared.")
        if supply_risk:
            why_now.append("A connected dependency has active advisory exposure requiring supply-chain review.")
        if not why_now:
            why_now.append("The finding is part of the current assurance cycle.")

        recommendations: list[str] = []
        if not affected:
            recommendations.append("Investigate the finding source and establish a graph link to the affected component.")
        if any(e.get("kind") == "dependency" for e in affected) or supply_risk:
            recommendations.append("Inspect the dependency manifest and advisory evidence before changing versions.")
        if any(e.get("kind", "").startswith("ai_") for e in affected):
            recommendations.append("Trace the connected AI provider, model, prompt, tool and execution/network boundaries.")
        if finding.severity.value in {"high", "critical"} or supply_risk >= 80:
            recommendations.append("Run focused validation and preserve evidence before any write action.")
        if not recommendations:
            recommendations.append("Run targeted validation against the affected component and update the finding with new evidence.")

        return AssuranceReasoning(
            finding_id=finding.id,
            risk_score=adjusted_score.score,
            risk_band=adjusted_score.band,
            risk_rationale=adjusted_score.rationale,
            affected_components=affected,
            impact_path=paths,
            supporting_evidence=supporting,
            risk_factors=risk_factors,
            uncertainties=uncertainties,
            governance_mappings=self.governance.map_finding(finding),
            lifecycle=state,
            prior_decisions=decisions,
            recommended_investigations=list(dict.fromkeys(recommendations)),
            why_now=list(dict.fromkeys(why_now)),
            confidence=round(min(1.0, max(0.0, finding.confidence)), 2),
            supply_chain_risk=supply_risk,
            affected_advisories=advisories,
        )
