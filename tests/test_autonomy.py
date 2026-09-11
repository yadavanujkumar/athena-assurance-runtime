from pathlib import Path

from athena.runtime import AthenaRuntime
from athena.risk import RiskEngine
from athena.models import Finding, Severity


def test_autonomous_cycle_persists_events(tmp_path: Path):
    (tmp_path / "app.py").write_text("value = eval(user_input)\n", encoding="utf-8")
    runtime = AthenaRuntime(tmp_path)
    result = runtime.run_autonomous_cycle("security assurance")
    events = runtime.memory.recent_events(50)
    runtime.close()
    assert result["findings"]
    kinds = {event["kind"] for event in events}
    assert "investigation_completed" in kinds
    assert "decision" in kinds
    assert "remediation_plan" in kinds


def test_risk_engine_is_monotonic_for_severity():
    engine = RiskEngine()
    low = Finding("l", "low", "x", Severity.LOW, 1.0, ["x"])
    high = Finding("h", "high", "x", Severity.HIGH, 1.0, ["x"])
    assert engine.score(high).score > engine.score(low).score
