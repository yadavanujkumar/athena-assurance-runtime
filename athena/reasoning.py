from __future__ import annotations

import os
from dataclasses import dataclass, asdict

from .governance import GovernanceCatalog
from .llm import OptionalReasoning
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
    llm_advisory: str | None = None
    llm_provider: str = "none"
    llm_error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


class ReasoningEngine:
    """Turns graph, risk, governance and memory signals into explainable assurance context.

    Deterministic reasoning remains authoritative. Optional local LLM output is advisory only
    and is never parsed into an ATHENA action or policy decision.
    """

    def __init__(self, memory, risk: RiskEngine | None = None, governance: GovernanceCatalog | None = None, llm: OptionalReasoning | None = None) -> None:
        self.memory = memory
        self.risk = risk or RiskEngine()
        self.governance = governance or GovernanceCatalog()
        self.lifecycle = FindingLifecycle(memory)
        if llm is not None:
            self.llm = llm
        elif os.getenv("ATHENA_LLM", "").strip().lower() == "ollama":
            self.llm = OptionalReasoning.local_ollama(
                host=os.getenv("ATHENA_OLLAMA_HOST", "http://127.0.0.1:11434"),
                model=os.getenv("ATHENA_OLLAMA_MODEL", "llama3.2"),
            )
        else:
            self.llm = OptionalReasoning()

    @staticmethod
    def _supply_chain_context(entities: list[dict], relationships: list[dict]) -> tuple[int, list[dict]]:
        dependency_ids = {e["id"] for e in entities if e.get("kind") == "dependency"}
        advisory_by_id = {e["id"]: e for e in entities if e.get("kind") == "advisory"}
        connected: list[dict] = []
        for edge in relationships:
            if edge.get("relation") != "affected_by" or edge.get("source") not in dependency_ids:
                continue
            advisory = advisory_by_id.get(edge.get("target"))
            if advisory:
                attrs = advisory.get("attributes") or {}
                connected.append({"id": advisory["id"], "name": advisory.get("name", "advisory"), "package": attrs.get("package", ""), "severity": attrs.get("severity", "unknown"), "risk": int(attrs.get("risk", 0) or 0), "identifiers": list(attrs.get("identifiers", []) or [])})
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
        affected = [e for e in entities if e.get("kind") in {"file", "python_file", "dependency", "advisory", "ai_provider", "ai_model", "ai_prompt", "ai_tool", "ai_network_boundary", "ai_execution_boundary"}]
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
        risk_factors.append("The finding has direct detector evidence." if supporting else "The finding has no direct detector evidence; risk is discounted by the risk engine.")
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
            state = lifecycle_map.get(self.lifecycle.fingerprint(finding))
        lifecycle_state = str((state or {}).get("state", "new"))
        if state:
            risk_factors.append(f"Finding lifecycle state is {lifecycle_state}.")
            if lifecycle_state == "worsening": risk_factors.append("Severity or detector confidence increased since the prior observation.")
            elif lifecycle_state == "recurring": risk_factors.append("The same evidence has persisted across assurance cycles.")
            elif lifecycle_state == "reopened": risk_factors.append("The finding reappeared after being previously resolved.")
        decisions = [d for d in self.memory.decisions() if d.get("finding_id") == finding.id][:5]
        drift_events = self.memory.search_events("project_drift", limit=5)
        why_now: list[str] = []
        classes = sorted(change_classes or set())
        if classes: why_now.append("The current cycle detected change classes: " + ", ".join(classes) + ".")
        if drift_events: why_now.append("Recent project drift exists in durable memory.")
        if lifecycle_state == "new": why_now.append("This is a newly observed finding and has no prior lifecycle history.")
        elif lifecycle_state == "reopened": why_now.append("This finding was previously resolved and has reappeared, indicating regression.")
        elif lifecycle_state == "worsening": why_now.append("The finding is worsening relative to its previous observation and should be escalated.")
        elif lifecycle_state == "recurring": why_now.append("The finding is recurring; repeated evidence should be monitored without duplicating investigation unnecessarily.")
        elif lifecycle_state == "resolved": why_now.append("The finding is resolved; the current action should be limited to observation and closure evidence.")
        if supply_risk: why_now.append("A connected dependency has active advisory exposure requiring supply-chain review.")
        if not why_now: why_now.append("The finding is part of the current assurance cycle.")
        recommendations: list[str] = []
        if lifecycle_state == "resolved": recommendations.append("Preserve resolution evidence and observe for recurrence; do not propose remediation for a resolved finding.")
        elif lifecycle_state in {"new", "reopened", "worsening"}: recommendations.append("Investigate the finding and establish current evidence before any write action.")
        else: recommendations.append("Monitor the recurring finding and run targeted validation if its risk or evidence changes.")
        if not affected: recommendations.append("Investigate the finding source and establish a graph link to the affected component.")
        if any(e.get("kind") == "dependency" for e in affected) or supply_risk: recommendations.append("Inspect the dependency manifest and advisory evidence before changing versions.")
        if any(e.get("kind", "").startswith("ai_") for e in affected): recommendations.append("Trace the connected AI provider, model, prompt, tool and execution/network boundaries.")
        if finding.severity.value in {"high", "critical"} or supply_risk >= 80: recommendations.append("Run focused validation and preserve evidence before any write action.")

        llm_advisory = None
        llm_provider = "none"
        llm_error = None
        if self.llm.enabled:
            prompt = (
                "You are an assurance advisor. Analyze this finding using only the supplied facts. "
                "Return concise observations, uncertainties, and investigation suggestions. Never choose or authorize an action.\n"
                f"severity={finding.severity.value}; confidence={finding.confidence:.2f}; risk={adjusted_score.score:.1f}; "
                f"risk_band={adjusted_score.band}; lifecycle={lifecycle_state}; change_classes={classes}; "
                f"affected_components={[(e.get('kind'), e.get('name')) for e in affected[:20]]}; "
                f"evidence={supporting[:20]}"
            )
            result = self.llm.augment(prompt)
            llm_advisory, llm_provider, llm_error = (result.text or None), result.provider, result.error
            if llm_error:
                uncertainties.append("Optional LLM advisory was unavailable; deterministic reasoning remains authoritative.")

        return AssuranceReasoning(finding_id=finding.id, risk_score=adjusted_score.score, risk_band=adjusted_score.band, risk_rationale=adjusted_score.rationale, affected_components=affected, impact_path=paths, supporting_evidence=supporting, risk_factors=risk_factors, uncertainties=uncertainties, governance_mappings=self.governance.map_finding(finding), lifecycle=state, prior_decisions=decisions, recommended_investigations=list(dict.fromkeys(recommendations)), why_now=list(dict.fromkeys(why_now)), confidence=round(min(1.0, max(0.0, finding.confidence)), 2), supply_chain_risk=supply_risk, affected_advisories=advisories, llm_advisory=llm_advisory, llm_provider=llm_provider, llm_error=llm_error)
