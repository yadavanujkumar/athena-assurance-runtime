from __future__ import annotations

from .dependencies import DependencyAnalyzer
from .models import Relationship


class DependencyGraphBuilder:
    """Projects dependency inventory and advisory risk into the living assurance graph."""

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

    def add_advisories(self, graph, root, ecosystem: str) -> list[dict]:
        """Refresh normalized advisories and reconcile stale advisory graph nodes."""
        audit = self.analyzer.audit(root, ecosystem)
        if not audit.available:
            return []
        advisories = self.analyzer.normalize_advisories(audit.findings, ecosystem, audit.tool)
        results: list[dict] = []
        active_ids: set[str] = set()
        for advisory in advisories:
            dependency_id = f"{advisory.ecosystem}:{advisory.package}"
            entity_id = graph.entity_id("dependency", dependency_id)
            existing = graph.entities.get(entity_id)
            attributes = dict(existing.attributes) if existing else {}
            attributes.update({"ecosystem": advisory.ecosystem, "name": advisory.package})
            dependency = graph.upsert_entity(
                "dependency", dependency_id,
                name=existing.name if existing else advisory.package,
                path=existing.path if existing else None,
                attributes=attributes,
            )
            key = f"{advisory.ecosystem}:{advisory.package}:{','.join(advisory.identifiers)}:{advisory.vulnerable_range or ''}"
            entity = graph.upsert_entity(
                "advisory", key, name=advisory.identifiers[0] if advisory.identifiers else f"{advisory.package} advisory",
                attributes={**advisory.to_dict(), "risk": self.analyzer.advisory_risk(advisory)},
            )
            active_ids.add(entity.id)
            graph.add_relationship(Relationship(dependency.id, "affected_by", entity.id))
            results.append({"dependency_id": dependency.id, "advisory_id": entity.id, **advisory.to_dict(), "risk": self.analyzer.advisory_risk(advisory)})
        self.reconcile_advisories(graph, ecosystem, active_ids)
        return results

    @staticmethod
    def reconcile_advisories(graph, ecosystem: str, active_ids: set[str]) -> list[str]:
        """Remove advisory nodes no longer reported by a successful ecosystem audit."""
        stale = [
            entity.id for entity in graph.entities.values()
            if entity.kind == "advisory"
            and entity.attributes.get("ecosystem") == ecosystem
            and entity.id not in active_ids
        ]
        for entity_id in stale:
            graph.entities.pop(entity_id, None)
        if stale:
            stale_set = set(stale)
            graph.relationships = [r for r in graph.relationships if r.source not in stale_set and r.target not in stale_set]
        return sorted(stale)
