from athena.remediation import SafeRemediationEngine
from athena.remediation_loop import RemediationLoop
from athena.models import Finding, Severity


def test_requires_explicit_approval(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("value = eval(user_input)\n", encoding="utf-8")
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98, ["app.py:1"])
    proposal = SafeRemediationEngine().propose(tmp_path, finding)
    outcome = RemediationLoop(tmp_path).execute(proposal)
    assert outcome.status == "approval_required"
    assert path.read_text(encoding="utf-8") == "value = eval(user_input)\n"


def test_failed_validation_rolls_back(tmp_path):
    path = tmp_path / "app.py"
    path.write_text("value = eval(user_input)\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_fail.py").write_text("def test_fail():\n    assert False\n", encoding="utf-8")
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98, ["app.py:1"])
    proposal = SafeRemediationEngine().propose(tmp_path, finding)
    outcome = RemediationLoop(tmp_path).execute(proposal, approved=True)
    assert outcome.status == "rolled_back"
    assert path.read_text(encoding="utf-8") == "value = eval(user_input)\n"
