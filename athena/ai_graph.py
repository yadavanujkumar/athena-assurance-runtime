from __future__ import annotations

from .ai_inventory import AIInventory
from .models import Relationship


class AIGraphBuilder:
    """Projects AI signals into explicit trust-boundary graph relationships."""

    RELATIONS = {
        "provider": "uses_provider",
        "model": "uses_model",
        "prompt": "defines_prompt",
        "tool": "registers_tool",
        "network_boundary": "exposes_network",
        "execution_boundary": "exposes_execution",
    }

    def build(self, graph, root) -> list[dict]:
        signals = AIInventory().scan(root)
        project = next((e for e in graph.entities.values() if e.kind == "project"), None)
        if project is None:
            return []
        created: list[dict] = []
        for signal in signals:
            entity = graph.upsert_entity(
                f"ai_{signal.kind}", f"{signal.source}:{signal.name}",
                name=signal.name, path=signal.source,
                attributes={"signal_kind": signal.kind, "confidence": signal.confidence, "detail": signal.detail},
            )
            source = next((e for e in graph.entities.values() if e.path == signal.source and e.kind in {"file", "python_file"}), project)
            graph.add_relationship(Relationship(source.id, self.RELATIONS.get(signal.kind, "contains_ai_signal"), entity.id))
            created.append({"id": entity.id, "kind": entity.kind, "name": entity.name, "source": signal.source, "confidence": signal.confidence})
        return created
