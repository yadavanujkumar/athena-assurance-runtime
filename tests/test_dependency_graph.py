from pathlib import Path

from athena.dependencies import Advisory
from athena.dependency_graph import DependencyGraphBuilder
from athena.graph import KnowledgeGraph


class StubAnalyzer:
    def inventory(self, root):
        return []

    def audit(self, root, ecosystem):
        return type("Audit", (), {"available": True, "tool": "stub", "findings": []})()

    @staticmethod
    def normalize_advisories(findings, ecosystem, source):
        return []

    @staticmethod
    def advisory_risk(advisory):
        return 80


def test_reconcile_advisories_removes_stale_nodes_and_edges(tmp_path: Path):
    graph = KnowledgeGraph()
    dependency = graph.upsert_entity("dependency", "python:requests", name="requests")
    advisory = graph.upsert_entity(
        "advisory",
        "python:requests:CVE-1:<2.0",
        name="CVE-1",
        attributes={"ecosystem": "python", "package": "requests"},
    )
    from athena.models import Relationship
    graph.add_relationship(Relationship(dependency.id, "affected_by", advisory.id))

    removed = DependencyGraphBuilder(StubAnalyzer()).reconcile_advisories(graph, "python", set())
    assert removed == [advisory.id]
    assert advisory.id not in graph.entities
    assert not graph.relationships


def test_reconcile_preserves_active_advisory(tmp_path: Path):
    graph = KnowledgeGraph()
    advisory = graph.upsert_entity(
        "advisory",
        "python:requests:CVE-1:<2.0",
        name="CVE-1",
        attributes={"ecosystem": "python", "package": "requests"},
    )
    removed = DependencyGraphBuilder(StubAnalyzer()).reconcile_advisories(graph, "python", {advisory.id})
    assert removed == []
    assert advisory.id in graph.entities
