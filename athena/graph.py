from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import ast
import hashlib
import json

from .models import Entity, Relationship


class KnowledgeGraph:
    """Small dependency-free graph store for the initial runtime."""

    def __init__(self) -> None:
        self.entities: dict[str, Entity] = {}
        self.relationships: list[Relationship] = []

    @staticmethod
    def entity_id(kind: str, value: str) -> str:
        return hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:16]

    def add_entity(self, entity: Entity) -> Entity:
        self.entities[entity.id] = entity
        return entity

    def add_relationship(self, relationship: Relationship) -> None:
        if relationship not in self.relationships:
            self.relationships.append(relationship)

    def discover_project(self, root: Path) -> None:
        root = root.resolve()
        project = self.add_entity(Entity(self.entity_id("project", str(root)), "project", root.name, str(root)))
        ignored = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}
        for path in root.rglob("*"):
            if any(part in ignored for part in path.parts):
                continue
            if not path.is_file():
                continue
            kind = "python_file" if path.suffix == ".py" else "file"
            entity = self.add_entity(Entity(self.entity_id(kind, str(path)), kind, path.name, str(path.relative_to(root))))
            self.add_relationship(Relationship(project.id, "contains", entity.id))
            if path.suffix == ".py":
                self._discover_python(path, entity.id)

    def _discover_python(self, path: Path, file_id: str) -> None:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dep = self.add_entity(Entity(self.entity_id("module", alias.name), "module", alias.name))
                    self.add_relationship(Relationship(file_id, "imports", dep.id))
            elif isinstance(node, ast.ImportFrom) and node.module:
                dep = self.add_entity(Entity(self.entity_id("module", node.module), "module", node.module))
                self.add_relationship(Relationship(file_id, "imports", dep.id))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                symbol = self.add_entity(Entity(self.entity_id("symbol", f"{path}:{node.name}"), "symbol", node.name, str(path)))
                self.add_relationship(Relationship(file_id, "defines", symbol.id))

    def to_dict(self) -> dict:
        return {
            "entities": [asdict(e) for e in self.entities.values()],
            "relationships": [asdict(r) for r in self.relationships],
        }

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "KnowledgeGraph":
        graph = cls()
        if not path.exists():
            return graph
        data = json.loads(path.read_text(encoding="utf-8"))
        for item in data.get("entities", []):
            graph.add_entity(Entity(**item))
        for item in data.get("relationships", []):
            graph.add_relationship(Relationship(**item))
        return graph
