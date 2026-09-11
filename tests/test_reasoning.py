from athena.graph import KnowledgeGraph
from athena.memory import Memory
from athena.models import Finding, Relationship, Severity
from athena.reasoning import ReasoningEngine


def test_reasoning_follows_connected_project_context(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    graph = KnowledgeGraph()
    project = graph.upsert_entity("project", str(tmp_path), name="demo", path=str(tmp_path))
    source = graph.upsert_entity("python_file", "app.py", name="app.py", path="app.py")
    dependency = graph.upsert_entity("dependency", "python:requests", name="requests", path="requirements.txt", attributes={"ecosystem": "python"})
    ai = graph.upsert_entity("ai_tool", "app.py:tool", name="tool", path="app.py", attributes={"signal_kind": "tool"})
    finding = Finding("F1", "AI tool security issue", "agent tool can reach a dependency", Severity.HIGH, 0.9, ["app.py:10", "requests"])
    finding_entity = graph.upsert_entity("finding", finding.id, name=finding.id, attributes={"finding_id": finding.id})
    graph.add_relationship(Relationship(project.id, "contains", source.id))
    graph.add_relationship(Relationship(source.id, "imports", dependency.id))
    graph.add_relationship(Relationship(source.id, "defines", ai.id))
    graph.add_relationship(Relationship(finding_entity.id, "detected_in", source.id))
    graph.add_relationship(Relationship(finding_entity.id, "affects", dependency.id))
    graph.add_relationship(Relationship(finding_entity.id, "targets", ai.id))

    result = ReasoningEngine(memory).reason(finding, graph)
    kinds = {item["kind"] for item in result.affected_components}
    relations = {item["relation"] for item in result.impact_path}
    assert "python_file" in kinds
    assert "dependency" in kinds
    assert "ai_tool" in kinds
    assert {"detected_in", "affects", "targets"}.issubset(relations)
    assert result.risk_band == "high"
    memory.close()


def test_reasoning_includes_governance_lifecycle_and_prior_decision(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    graph = KnowledgeGraph()
    finding = Finding("F2", "Agent prompt risk", "agent prompt can influence tool use", Severity.CRITICAL, 0.8, ["agent.py:20"])
    graph.upsert_entity("finding", finding.id, name=finding.id, attributes={"finding_id": finding.id})
    memory.fact("finding.lifecycle", {"F2": {"id": "F2", "fingerprint": "abc", "status": "reopened", "occurrences": 3}})
    memory.db.execute("INSERT INTO decisions(id,payload,updated_at) VALUES(?,?,?)", ("D2", '{"id":"D2","finding_id":"F2","action":"recommend","approved":false,"rationale":"needs validation","created_at":"now"}', "now"))
    memory.db.commit()

    result = ReasoningEngine(memory).reason(finding, graph, change_classes={"ai", "source"})
    assert "NIST AI RMF:MANAGE" in result.governance_mappings
    assert "NIST AI RMF:MAP" in result.governance_mappings
    assert result.lifecycle["status"] == "reopened"
    assert result.prior_decisions[0]["id"] == "D2"
    assert any("ai, source" in item for item in result.why_now)
    assert result.uncertainties
    memory.close()
