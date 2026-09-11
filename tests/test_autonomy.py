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


def test_advisory_work_is_durable_and_duplicate_safe(tmp_path: Path):
    runtime = AthenaRuntime(tmp_path)
    runtime.initialize()
    advisory = runtime.graph.upsert_entity(
        "advisory",
        "python:requests:CVE-1:<2.0",
        name="CVE-1",
        attributes={
            "ecosystem": "python",
            "package": "requests",
            "risk": 100,
            "identifiers": ["CVE-1"],
            "vulnerable_range": "<2.0",
            "fixed_version": "2.0",
        },
    )

    first = runtime._sync_advisory_work("security")
    second = runtime._sync_advisory_work("security")

    assert [item.id for item in first] == [item.id for item in second]
    assert first[0].kind == "dependency_advisory_review"
    assert first[0].context_key == "advisory:" + advisory.id
    assert first[0].priority == 130
    assert first[0].status == "queued"
    runtime.close()


def test_resolved_advisory_cancels_queued_work(tmp_path: Path):
    runtime = AthenaRuntime(tmp_path)
    runtime.initialize()
    advisory = runtime.graph.upsert_entity(
        "advisory",
        "python:requests:CVE-2:<2.0",
        name="CVE-2",
        attributes={"ecosystem": "python", "package": "requests", "risk": 80},
    )
    created = runtime._sync_advisory_work(None)
    assert created
    runtime.graph.entities.pop(advisory.id)
    runtime._sync_advisory_work(None)
    assert runtime.work.get(created[0].id).status == "cancelled"
    runtime.close()


def test_risk_engine_is_monotonic_for_severity():
    engine = RiskEngine()
    low = Finding("l", "low", "x", Severity.LOW, 1.0, ["x"])
    high = Finding("h", "high", "x", Severity.HIGH, 1.0, ["x"])
    assert engine.score(high).score > engine.score(low).score
