from athena.assurance import AssuranceEngine
from athena.graph import KnowledgeGraph
from athena.memory import Memory
from athena.models import Action, Finding, Relationship, Severity
from athena.planner import Planner
from athena.policy import Authority, PolicyEngine
from athena.reasoning import ReasoningEngine


def _graph_with_advisory(tmp_path):
    graph = KnowledgeGraph()
    project = graph.upsert_entity("project", str(tmp_path), name="demo", path=str(tmp_path))
    dependency = graph.upsert_entity("dependency", "python:requests", name="requests", path="requirements.txt", attributes={"ecosystem": "python", "version": "2.32.0"})
    advisory = graph.upsert_entity("advisory", "python:requests:CVE-2026-0001:<2.32.4", name="CVE-2026-0001", attributes={"package": "requests", "severity": "critical", "risk": 100, "identifiers": ["CVE-2026-0001"]})
    graph.add_relationship(Relationship(project.id, "contains", dependency.id))
    graph.add_relationship(Relationship(dependency.id, "affected_by", advisory.id))
    return graph, dependency, advisory


def test_reasoning_blends_connected_advisory_risk(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    graph, dependency, _ = _graph_with_advisory(tmp_path)
    finding = Finding("F-SC", "Dependency exposure", "requests is used by the application", Severity.LOW, 0.8, ["requests"])
    finding_entity = graph.upsert_entity("finding", finding.id, name=finding.id)
    graph.add_relationship(Relationship(finding_entity.id, "affects", dependency.id))

    result = ReasoningEngine(memory).reason(finding, graph)
    assert result.supply_chain_risk == 100
    assert result.risk_score > 20
    assert result.affected_advisories[0]["name"] == "CVE-2026-0001"
    assert any("supply-chain" in item.lower() for item in result.risk_factors)
    memory.close()


def test_planner_prioritizes_active_advisories(tmp_path):
    graph, _, _ = _graph_with_advisory(tmp_path)
    tasks = Planner().plan(None, graph, [])
    dependency = next(task for task in tasks if task.kind == "dependency_review")
    assert dependency.priority == 125
    assert "advisories" in dependency.reason


def test_assurance_can_block_critical_supply_chain_context(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    policy = PolicyEngine(Authority(modify=True, block=True))
    finding = Finding("F-BLOCK", "Dependency exposure", "vulnerable dependency", Severity.LOW, 0.8, ["requests"])
    context = {"risk_band": "critical", "supply_chain_risk": 100, "affected_components": [], "uncertainties": []}
    decisions = AssuranceEngine(memory, policy).assess([finding], {finding.id: context})
    assert decisions[0].action is Action.BLOCK
    assert decisions[0].approved is False
    memory.close()
