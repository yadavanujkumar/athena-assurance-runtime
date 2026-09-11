from pathlib import Path

from athena.graph import KnowledgeGraph
from athena.runtime import AthenaRuntime


def test_graph_discovers_python_symbols(tmp_path: Path):
    (tmp_path / "app.py").write_text("import json\n\nclass Demo:\n    def run(self):\n        return 1\n", encoding="utf-8")
    graph = KnowledgeGraph()
    graph.discover_project(tmp_path)
    assert any(e.kind == "python_file" for e in graph.entities.values())
    assert any(e.kind == "symbol" and e.name == "Demo" for e in graph.entities.values())
    assert any(r.relation == "imports" for r in graph.relationships)


def test_runtime_finds_eval(tmp_path: Path):
    (tmp_path / "bad.py").write_text("value = eval(user_input)\n", encoding="utf-8")
    runtime = AthenaRuntime(tmp_path)
    findings = runtime.inspect()
    runtime.close()
    assert any(f.title == "Dynamic eval usage" for f in findings)


def test_memory_survives_runtime_restart(tmp_path: Path):
    runtime = AthenaRuntime(tmp_path)
    objective = runtime.set_objective("check governance boundaries")
    runtime.close()

    restarted = AthenaRuntime(tmp_path)
    assert any(item["id"] == objective.id for item in restarted.memory.objectives())
    restarted.close()
