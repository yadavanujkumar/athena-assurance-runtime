from pathlib import Path

from athena.graph import KnowledgeGraph


def test_reconcile_removes_deleted_files_and_symbols(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text("class Old:\n    pass\n\ndef keep():\n    pass\n", encoding="utf-8")
    stale = tmp_path / "stale.txt"
    stale.write_text("obsolete", encoding="utf-8")

    graph = KnowledgeGraph()
    graph.discover_project(tmp_path)
    old_symbol = graph.entity_id("symbol", f"{app}:Old")
    keep_symbol = graph.entity_id("symbol", f"{app}:keep")
    stale_file = graph.entity_id("file", str(stale))
    assert old_symbol in graph.entities
    assert keep_symbol in graph.entities
    assert stale_file in graph.entities

    app.write_text("def keep():\n    pass\n", encoding="utf-8")
    stale.unlink()
    removed = graph.reconcile_project(tmp_path)

    assert old_symbol in removed
    assert stale_file in removed
    assert old_symbol not in graph.entities
    assert stale_file not in graph.entities
    assert keep_symbol in graph.entities
    assert all(edge.source in graph.entities and edge.target in graph.entities for edge in graph.relationships)


def test_reconcile_keeps_current_files(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text("def run():\n    pass\n", encoding="utf-8")
    graph = KnowledgeGraph()
    graph.discover_project(tmp_path)
    assert graph.reconcile_project(tmp_path) == []
    assert graph.entity_id("python_file", str(app)) in graph.entities
