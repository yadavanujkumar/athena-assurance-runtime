from __future__ import annotations

from .dependencies import DependencyAnalyzer
from .models import Relationship


class DependencyGraphBuilder:
    """Projects dependency inventory into the living assurance graph."""

    def __init__(self, analyzer: DependencyAnalyzer | None = None) -> None:
        self.analyzer = analyzer or DependencyAnalyzer()

    def build(self, graph, root) -> list[dict]:
        created: list[dict] = []
        for dependency in self.analyzer.inventory(root):
            entity = graph.upsert_entity(
                "dependency", f"{dependency.ecosystem}:{dependency.name}",
                name=dependency.name, path=dependency.source,
                attributes={"ecosystem": dependency.ecosystem, "version": dependency.version, "source": dependency.source},
            )
            manifests = graph.find_entities(path=dependency.source)
            if manifests:
                graph.add_relationship(Relationship(manifests[0].id, "declares", entity.id))
            else:
                project = next((e for e in graph.entities.values() if e.kind == "project"), None)
                if project:
                    graph.add_relationship(Relationship(project.id, "declares_dependency", entity.id))
            created.append({"id": entity.id, "kind": entity.kind, "name": entity.name, "ecosystem": dependency.ecosystem, "version": dependency.version, "source": dependency.source})
        return created
