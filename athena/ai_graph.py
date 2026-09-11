from __future__ import annotations

from .ai_inventory import AIInventory
from .models import Entity, Relationship


class AIGraphBuilder:
    """Projects AI inventory signals into the living knowledge graph."""

    def build(self, graph, root) -> list[dict]:
        signals = AIInventory().scan(root)
        project = next((e for e in graph.entities.values() if e.kind == "project"), None)
        if project is None:
            return []
        created: list[dict] = []
        for signal in signals:
            entity_id = graph.entity_id(f"ai_{signal.kind}", f"{signal.source}:{signal.name}")
            entity = graph.add_entity(Entity(entity_id, f"ai_{signal.kind}", signal.name, signal.source))
            source_id = next((e.id for e in graph.entities.values() if e.path == signal.source), project.id)
            relation = "exposes" if signal.kind.endswith("_boundary") else "contains_ai_signal"
            graph.add_relationship(Relationship(source_id, relation, entity.id))
            created.append({"id": entity.id, "kind": entity.kind, "name": entity.name, "source": signal.source, "confidence": signal.confidence})
        return created
