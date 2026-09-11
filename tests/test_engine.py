from athena.engine import AssuranceEngine
from athena.runtime import AthenaRuntime


def test_engine_executes_bounded_cycle(tmp_path):
    (tmp_path / "app.py").write_text("value = eval(user_input)\n", encoding="utf-8")
    runtime = AthenaRuntime(tmp_path)
    results = AssuranceEngine(runtime).run(max_tasks=3)
    assert results
    assert any(item.get("task") == "security_review" for item in results)
    assert runtime.memory.recent_events()
    runtime.close()


def test_remediation_is_persisted_as_decision(tmp_path):
    (tmp_path / "bad.py").write_text("x = eval(input())\n", encoding="utf-8")
    runtime = AthenaRuntime(tmp_path)
    runtime.inspect()
    assert runtime.memory.findings()
    runtime.close()
