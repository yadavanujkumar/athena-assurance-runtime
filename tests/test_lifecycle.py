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
    assert second[0]["occurrences"] == 2
    memory.close()


def test_missing_finding_becomes_resolved(tmp_path):
    memory = Memory(tmp_path / "memory.sqlite3")
    lifecycle = FindingLifecycle(memory)
    finding = Finding("F1", "Unsafe eval", "eval detected", Severity.HIGH, 0.9, ["app.py:10"])
    lifecycle.reconcile([finding])
    states = lifecycle.reconcile([])
    assert states[0]["status"] == "resolved"
    memory.close()
