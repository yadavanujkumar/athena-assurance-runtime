from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from .models import Entity, Relationship


class KnowledgeGraph:
    """Dependency-free living project graph with bounded traversal/query primitives."""

    def __init__(self) -> None:
        self.entities: dict[str, Entity] = {}
        self.relationships: list[Relationship] = []

    @staticmethod
    def entity_id(kind: str, value: str) -> str:
        return hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:16]

    def add_entity(self, entity: Entity) -> Entity:
        self.entities[entity.id] = entity
        return entity

    def upsert_entity(self, kind: str, value: str, *, name: str | None = None, path: str | None = None, attributes: dict | None = None) -> Entity:
        return self.add_entity(Entity(self.entity_id(kind, value), kind, name or value, path, attributes or {}))

    def add_relationship(self, relationship: Relationship) -> None:
        if relationship not in self.relationships:
            self.relationships.append(relationship)

    def find_entities(self, *, kind: str | None = None, name: str | None = None, path: str | None = None) -> list[Entity]:
        return [e for e in self.entities.values() if (kind is None or e.kind == kind) and (name is None or e.name == name) and (path is None or e.path == path)]

    def neighbors(self, entity_id: str, relation: str | None = None, direction: str = "both") -> list[Entity]:
        if direction not in {"in", "out", "both"}:
            raise ValueError("direction must be 'in', 'out' or 'both'")
        ids: set[str] = set()
        for edge in self.relationships:
            if relation is not None and edge.relation != relation:
                continue
            if direction in {"out", "both"} and edge.source == entity_id:
                ids.add(edge.target)
            if direction in {"in", "both"} and edge.target == entity_id:
                ids.add(edge.source)
        return [self.entities[i] for i in ids if i in self.entities]

    def relationships_for(self, entity_id: str) -> list[Relationship]:
        return [r for r in self.relationships if r.source == entity_id or r.target == entity_id]

    def subgraph(self, seed_ids: list[str] | set[str], depth: int = 1) -> dict:
        if depth < 0:
            raise ValueError("depth must be >= 0")
        visited = {i for i in seed_ids if i in self.entities}
        frontier = set(visited)
        for _ in range(depth):
            next_frontier = {n.id for i in frontier for n in self.neighbors(i)} - visited
            visited.update(next_frontier)
            frontier = next_frontier
        edges = [r for r in self.relationships if r.source in visited and r.target in visited]
        return {"entities": [asdict(self.entities[i]) for i in visited], "relationships": [asdict(r) for r in edges]}

    def context_for_finding(self, finding_id: str, depth: int = 2) -> dict:
        seeds = [e.id for e in self.find_entities(kind="finding") if e.name == finding_id or e.attributes.get("finding_id") == finding_id]
        return self.subgraph(seeds, depth)

    def discover_project(self, root: Path) -> None:
        root = root.resolve()
        project = self.upsert_entity("project", str(root), name=root.name, path=str(root))
        ignored = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".athena"}
        current_files: set[str] = set()
        current_symbols: set[str] = set()
        for path in root.rglob("*"):
            if any(part in ignored for part in path.parts) or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            current_files.add(rel)
            kind = "python_file" if path.suffix == ".py" else "file"
            entity = self.upsert_entity(kind, str(path), name=path.name, path=rel)
            self.add_relationship(Relationship(project.id, "contains", entity.id))
            if path.suffix == ".py":
                current_symbols.update(self._discover_python(path, entity.id, root))
        self.reconcile_project(root, current_files=current_files, current_symbols=current_symbols)

    def reconcile_project(self, root: Path, *, current_files: set[str] | None = None, current_symbols: set[str] | None = None) -> list[str]:
        """Remove stale file/symbol nodes and every edge attached to them."""
        root = root.resolve()
        current_files = current_files if current_files is not None else self._current_files(root)
        current_symbols = current_symbols if current_symbols is not None else self._current_symbols(root)
        stale: set[str] = set()
        for entity in self.entities.values():
            if entity.kind not in {"file", "python_file", "symbol"}:
                continue
            if entity.kind in {"file", "python_file"}:
                if entity.path not in current_files:
                    stale.add(entity.id)
            elif entity.path:
                try:
                    rel = Path(entity.path).resolve().relative_to(root).as_posix()
                except ValueError:
                    continue
                if f"{rel}:{entity.name}" not in current_symbols:
                    stale.add(entity.id)
        for entity_id in stale:
            self.entities.pop(entity_id, None)
        self.relationships = [r for r in self.relationships if r.source not in stale and r.target not in stale]
        return sorted(stale)

    @staticmethod
    def _current_files(root: Path) -> set[str]:
        ignored = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".athena"}
        return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and not any(part in ignored for part in p.parts)}

    @staticmethod
    def _current_symbols(root: Path) -> set[str]:
        symbols: set[str] = set()
        ignored = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".athena"}
        for path in root.rglob("*.py"):
            if any(part in ignored for part in path.parts):
                continue
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue
            rel = path.relative_to(root).as_posix()
            symbols.update(f"{rel}:{node.name}" for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
        return symbols

    def _discover_python(self, path: Path, file_id: str, root: Path) -> set[str]:
        discovered: set[str] = set()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            return discovered
        rel = path.relative_to(root).as_posix()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    dep = self.upsert_entity("module", alias.name)
                    self.add_relationship(Relationship(file_id, "imports", dep.id))
            elif isinstance(node, ast.ImportFrom) and node.module:
                dep = self.upsert_entity("module", node.module)
                self.add_relationship(Relationship(file_id, "imports", dep.id))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                discovered.add(f"{rel}:{node.name}")
                symbol = self.upsert_entity("symbol", f"{path}:{node.name}", name=node.name, path=str(path))
                self.add_relationship(Relationship(file_id, "defines", symbol.id))
        return discovered

    def to_dict(self) -> dict:
        return {"entities": [asdict(e) for e in self.entities.values()], "relationships": [asdict(r) for r in self.relationships]}

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


# Backward-compatible name used by the runtime and existing integrations.
ProjectGraph = KnowledgeGraph
