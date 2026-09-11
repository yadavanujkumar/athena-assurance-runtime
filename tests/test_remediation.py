from pathlib import Path

import pytest

from athena.models import Finding, Severity
from athena.remediation import SafeRemediationEngine


def test_proposes_bounded_eval_patch(tmp_path: Path):
    source = "value = eval(user_input)\n"
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98, ["app.py:1"])

    proposal = SafeRemediationEngine().propose(tmp_path, finding)

    assert proposal is not None
    assert "ast.literal_eval(user_input)" in proposal.after
    assert proposal.before_sha256
    assert "+++" in proposal.diff


def test_patch_requires_approval_and_fresh_content(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text("value = eval(user_input)\n", encoding="utf-8")
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98, ["app.py:1"])
    engine = SafeRemediationEngine()
    proposal = engine.propose(tmp_path, finding)
    assert proposal is not None

    with pytest.raises(PermissionError):
        engine.apply(tmp_path, proposal)

    path.write_text("value = eval(other_input)\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="stale"):
        engine.apply(tmp_path, proposal, approved=True)


def test_approved_patch_applies_only_inside_root(tmp_path: Path):
    path = tmp_path / "app.py"
    path.write_text("value = eval(user_input)\n", encoding="utf-8")
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98, ["app.py:1"])
    engine = SafeRemediationEngine()
    proposal = engine.propose(tmp_path, finding)
    assert proposal is not None

    applied = engine.apply(tmp_path, proposal, approved=True)

    assert applied == path.resolve()
    assert path.read_text(encoding="utf-8") == "import ast\nvalue = ast.literal_eval(user_input)\n"
