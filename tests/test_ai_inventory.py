from pathlib import Path

from athena.ai_inventory import AIInventory
from athena.ai_graph import AIGraphBuilder
from athena.graph import KnowledgeGraph


def test_ai_inventory_detects_model_prompt_tool_and_boundaries(tmp_path: Path):
    (tmp_path / "agent.py").write_text(
        "from openai import OpenAI\nmodel = 'gpt-test'\nprompt = 'hello'\ntools = [run_command]\nimport subprocess\nsubprocess.run(['echo','x'])\n",
        encoding="utf-8",
    )
    signals = AIInventory().scan(tmp_path)
    kinds = {s.kind for s in signals}
    assert {"provider", "model", "prompt", "tool", "execution_boundary"} <= kinds


def test_ai_graph_projects_signals(tmp_path: Path):
    (tmp_path / "agent.py").write_text("import langgraph\nprompt = 'x'\n", encoding="utf-8")
    graph = KnowledgeGraph()
    graph.discover_project(tmp_path)
    created = AIGraphBuilder().build(graph, tmp_path)
    assert created
    assert any(e.kind == "ai_provider" for e in graph.entities.values())
