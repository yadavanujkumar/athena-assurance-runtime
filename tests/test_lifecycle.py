from athena.lifecycle import FindingLifecycle
from athena.memory import Memory
from athena.models import Finding, Severity


def test_finding_reopens_and_tracks_occurrences(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    lifecycle = FindingLifecycle(memory)
    finding = Finding("F1", "Unsafe eval", "eval detected", Severity.HIGH, 0.9, ["app.py:10"])

    first = lifecycle.reconcile([finding])
    second = lifecycle.reconcile([finding])

    assert first[0]["status"] == "open"
    assert first[0]["state"] == "new"
    assert second[0]["state"] == "recurring"
    assert second[0]["occurrences"] == 2
    memory.close()


def test_missing_finding_becomes_resolved(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    lifecycle = FindingLifecycle(memory)
    finding = Finding("F1", "Unsafe eval", "eval detected", Severity.HIGH, 0.9, ["app.py:10"])
    lifecycle.reconcile([finding])
    states = lifecycle.reconcile([])
    assert states[0]["status"] == "resolved"
    assert states[0]["state"] == "resolved"
    memory.close()


def test_resolved_finding_reopens_when_seen_again(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    lifecycle = FindingLifecycle(memory)
    finding = Finding("F1", "Unsafe eval", "eval detected", Severity.HIGH, 0.9, ["app.py:10"])
    lifecycle.reconcile([finding])
    lifecycle.reconcile([])
    states = lifecycle.reconcile([finding])
    assert states[0]["state"] == "reopened"
    assert states[0]["occurrences"] == 2
    memory.close()


def test_severity_or_confidence_increase_is_worsening(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    lifecycle = FindingLifecycle(memory)
    first = Finding("F1", "Unsafe eval", "eval detected", Severity.MEDIUM, 0.7, ["app.py:10"])
    worse = Finding("F1", "Unsafe eval", "eval detected", Severity.HIGH, 0.8, ["app.py:10"])
    lifecycle.reconcile([first])
    states = lifecycle.reconcile([worse])
    assert states[0]["state"] == "worsening"
    memory.close()


def test_lifecycle_transition_is_durable(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    lifecycle = FindingLifecycle(memory)
    finding = Finding("F1", "Unsafe eval", "eval detected", Severity.HIGH, 0.9, ["app.py:10"])
    lifecycle.reconcile([finding])
    lifecycle.reconcile([])
    events = memory.search_events("finding_lifecycle_transition", limit=5)
    assert any(event["payload"]["to"] == "resolved" for event in events)
    memory.close()
