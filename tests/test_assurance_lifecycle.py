from athena.assurance import AssuranceEngine
from athena.memory import Memory
from athena.models import Action, Finding, Severity
from athena.policy import Authority, PolicyEngine


def _engine(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    return memory, AssuranceEngine(memory, PolicyEngine(Authority()))


def _finding():
    return Finding("F1", "Risk", "test", Severity.HIGH, 0.95, ["app.py:1"])


def test_new_high_risk_is_investigated(tmp_path):
    memory, engine = _engine(tmp_path)
    action = engine._action_for_context(_finding(), {"risk_band": "high", "lifecycle": {"state": "new"}})
    assert action is Action.INVESTIGATE
    memory.close()


def test_reopened_and_worsening_high_risk_are_escalated(tmp_path):
    memory, engine = _engine(tmp_path)
    finding = _finding()
    for state in ("reopened", "worsening"):
        action = engine._action_for_context(finding, {"risk_band": "high", "lifecycle": {"state": state}})
        assert action is Action.INVESTIGATE
    memory.close()


def test_recurring_high_risk_avoids_redundant_investigation(tmp_path):
    memory, engine = _engine(tmp_path)
    action = engine._action_for_context(_finding(), {"risk_band": "high", "lifecycle": {"state": "recurring"}})
    assert action is Action.RECOMMEND
    memory.close()


def test_resolved_finding_is_observed(tmp_path):
    memory, engine = _engine(tmp_path)
    action = engine._action_for_context(_finding(), {"risk_band": "high", "lifecycle": {"state": "resolved"}})
    assert action is Action.OBSERVE
    memory.close()


def test_rationale_explains_lifecycle_transition(tmp_path):
    memory, engine = _engine(tmp_path)
    finding = _finding()
    context = {"risk_band": "high", "affected_components": [], "lifecycle": {"state": "reopened"}}
    decisions = engine.assess([finding], {finding.id: context})
    assert decisions[0].action is Action.INVESTIGATE
    assert "regressed after resolution" in decisions[0].rationale
    memory.close()
