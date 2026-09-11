from pathlib import Path

from athena.memory import Memory


def test_decision_request_requires_explicit_resolution(tmp_path: Path):
    memory = Memory(tmp_path / "athena.db")
    try:
        request = memory.create_decision_request("REQ-1", "F-1", "modify", "High risk requires human approval.")
        assert request["status"] == "pending"
        assert memory.approved_decision("F-1") is None

        resolved = memory.resolve_decision_request("REQ-1", approved=True, actor="anuj", rationale="Reviewed evidence.")
        assert resolved is not None
        assert resolved["status"] == "approved"
        assert resolved["actor"] == "anuj"
        assert memory.approved_decision("F-1")["id"] == "REQ-1"
    finally:
        memory.close()


def test_rejected_request_cannot_authorize_action(tmp_path: Path):
    memory = Memory(tmp_path / "athena.db")
    try:
        memory.create_decision_request("REQ-2", "F-2", "modify", "Write action requested.")
        resolved = memory.resolve_decision_request("REQ-2", approved=False, actor="reviewer")
        assert resolved["status"] == "rejected"
        assert memory.approved_decision("F-2") is None
        assert memory.decision_requests("pending") == []
    finally:
        memory.close()
