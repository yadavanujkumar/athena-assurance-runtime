import hashlib
from pathlib import Path

from athena.models import Finding, Severity
from athena.remediation import SafeRemediationEngine
from athena.remediation_loop import RemediationLoop


def test_requires_explicit_approval(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("value = eval(user_input)\n", encoding="utf-8")
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98, ["app.py:1"])
    proposal = SafeRemediationEngine().propose(tmp_path, finding)
    outcome = RemediationLoop(tmp_path).execute(proposal)
    assert outcome.status == "approval_required"
    assert path.read_text(encoding="utf-8") == "value = eval(user_input)\n"


def test_apply_verifies_final_content_hash(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("value = eval(user_input)\n", encoding="utf-8")
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98, ["app.py:1"])
    proposal = SafeRemediationEngine().propose(tmp_path, finding)
    engine = SafeRemediationEngine()
    applied = engine.apply(tmp_path, proposal, approved=True)
    content = applied.read_text(encoding="utf-8")
    assert content == proposal.after
    assert hashlib.sha256(content.encode("utf-8")).hexdigest() == engine.sha256(proposal.after)


def test_failed_validation_rolls_back_and_verifies_hash(tmp_path: Path):
    path = tmp_path / "app.py"
    original = "value = eval(user_input)\n"
    path.write_text(original, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_fail.py").write_text("def test_fail():\n    assert False\n", encoding="utf-8")
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98, ["app.py:1"])
    proposal = SafeRemediationEngine().propose(tmp_path, finding)
    outcome = RemediationLoop(tmp_path).execute(proposal, approved=True)
    assert outcome.status == "rolled_back"
    restored = path.read_text(encoding="utf-8")
    assert restored == original
    assert hashlib.sha256(restored.encode("utf-8")).hexdigest() == proposal.before_sha256


class _ConcurrentEditValidation:
    def __init__(self, path: Path):
        self.path = path

    def detect_commands(self, root):
        return ["fake validation"]

    def run(self, root, command):
        self.path.write_text("user changed this during validation\n", encoding="utf-8")
        return type("Result", (), {"to_dict": lambda self: {"command": command, "available": True, "passed": False}})()


def test_concurrent_change_blocks_rollback(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text("value = eval(user_input)\n", encoding="utf-8")
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98, ["app.py:1"])
    proposal = SafeRemediationEngine().propose(tmp_path, finding)
    validation = _ConcurrentEditValidation(path)
    outcome = RemediationLoop(tmp_path, validation=validation).execute(proposal, approved=True)
    assert outcome.status == "rollback_blocked"
    assert path.read_text(encoding="utf-8") == "user changed this during validation\n"
