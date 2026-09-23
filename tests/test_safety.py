"""Safety and authority enforcement tests for ATHENA."""

from __future__ import annotations

from pathlib import Path

import pytest

from athena.memory import Memory
from athena.models import Finding, Severity
from athena.policy import Authority, PolicyEngine
from athena.models import Action
from athena.remediation import SafeRemediationEngine
from athena.remediation_loop import RemediationLoop
from athena.security import SecurityBoundaryError, safe_project_path, has_safe_permissions
from athena.validation import ValidationEngine


# ---------------------------------------------------------------------------
# Authority enforcement
# ---------------------------------------------------------------------------

def test_modify_blocked_by_default():
    """MODIFY is blocked when authority.modify is False (the default)."""
    policy = PolicyEngine(Authority())  # default: modify=False
    finding = Finding("F1", "High risk", "test", Severity.HIGH, 0.99, ["app.py:1"])
    assert not policy.can_remediate(finding)


def test_block_blocked_by_default():
    """BLOCK is blocked when authority.block is False (the default)."""
    policy = PolicyEngine(Authority())
    assert not policy.can_execute(Action.BLOCK)


def test_modify_allowed_when_explicitly_enabled():
    """MODIFY is only allowed when authority.modify is explicitly True."""
    policy = PolicyEngine(Authority(modify=True))
    finding = Finding("F1", "High risk", "test", Severity.HIGH, 0.99, ["app.py:1"])
    assert policy.can_remediate(finding)


def test_remediate_denied_without_approved_decision(tmp_path: Path):
    """Remediation is denied when no approved decision exists in durable memory."""
    from athena.runtime import AthenaRuntime

    path = tmp_path / "app.py"
    path.write_text("value = eval(user_input)\n", encoding="utf-8")
    runtime = AthenaRuntime(tmp_path, authority=Authority(modify=True))
    runtime.initialize()
    findings = runtime.inspect()
    assert findings

    proposal = runtime.patch_engine.propose(tmp_path, findings[0])
    assert proposal is not None

    # No decision has been approved yet; should return approval_required
    result = runtime.remediate(proposal, approved=False)
    assert result["status"] == "approval_required"
    runtime.close()


def test_rejected_decision_cannot_authorize_remediation(tmp_path: Path):
    """A rejected decision request must not allow remediation."""
    memory = Memory(tmp_path / "athena.db")
    try:
        memory.create_decision_request("REQ-1", "F-1", "modify", "test")
        memory.resolve_decision_request("REQ-1", approved=False, actor="reviewer")
        # The finding has a rejected decision — approved_decision must be None
        assert memory.approved_decision("F-1") is None
        # And the request is still in durable history
        requests = memory.decision_requests()
        assert any(r["id"] == "REQ-1" and r["status"] == "rejected" for r in requests)
    finally:
        memory.close()


# ---------------------------------------------------------------------------
# Secret non-exposure
# ---------------------------------------------------------------------------

def test_detectors_do_not_expose_secret_value(tmp_path: Path):
    """Findings must not include the actual secret value, only location."""
    from athena.detectors import SecretDetector

    secret_file = tmp_path / "config.py"
    secret_file.write_text('api_key = "super-secret-value-abc123xyz"\n', encoding="utf-8")
    findings = SecretDetector().scan(tmp_path)
    assert findings, "Expected at least one finding for the secret"
    for f in findings:
        for ev in f.evidence:
            assert "super-secret-value-abc123xyz" not in str(ev), (
                "Secret value must not appear in finding evidence"
            )
        assert "super-secret-value-abc123xyz" not in f.description
        assert "super-secret-value-abc123xyz" not in f.title


# ---------------------------------------------------------------------------
# Command allowlist enforcement
# ---------------------------------------------------------------------------

def test_unsafe_command_is_rejected():
    """The validation engine must reject commands not on the allowlist."""
    engine = ValidationEngine()
    result = engine.run(None, "rm -rf /")
    assert not result.available
    assert "allowlist" in result.stderr.lower()


def test_safe_commands_pass_allowlist():
    """Well-known safe commands must be accepted by the allowlist check."""
    engine = ValidationEngine()
    for command in ("pytest", "python -m pytest", "npm test", "go test ./..."):
        assert engine._allowed(command), f"Expected {command!r} to be allowed"


def test_shell_injection_blocked():
    """Commands with shell metacharacters that expand beyond the allowed prefix must be rejected."""
    engine = ValidationEngine()
    malicious = "pytest; rm -rf /"
    result = engine.run(None, malicious)
    assert not result.available


# ---------------------------------------------------------------------------
# Path traversal protection
# ---------------------------------------------------------------------------

def test_remediation_path_escape_blocked(tmp_path: Path):
    """Remediation must refuse to write to files outside the project root."""
    engine = SafeRemediationEngine()
    from athena.remediation import PatchProposal
    import hashlib
    outside = tmp_path.parent / "outside.py"
    outside.write_text("pass\n", encoding="utf-8")
    sha = hashlib.sha256(b"pass\n").hexdigest()
    proposal = PatchProposal(
        finding_id="F-TEST",
        path="../outside.py",
        before_sha256=sha,
        before="pass\n",
        after="# patched\n",
        rationale="escape test",
    )
    with pytest.raises((ValueError, FileNotFoundError)):
        engine.apply(tmp_path, proposal, approved=True)


# ---------------------------------------------------------------------------
# Configuration safety clamping
# ---------------------------------------------------------------------------

def test_config_clamps_dangerous_values(tmp_path: Path):
    """RuntimeConfig must clamp unreasonably small values to safe minimums."""
    import json
    from athena.config import RuntimeConfig

    config_path = tmp_path / ".athena" / "config.json"
    config_path.parent.mkdir(exist_ok=True)
    config_path.write_text(json.dumps({
        "max_work_per_cycle": 0,
        "max_attempts": 0,
        "lease_ttl_seconds": 0,
        "watch_interval_seconds": 0.0,
    }), encoding="utf-8")
    config = RuntimeConfig.load(tmp_path)
    assert config.max_work_per_cycle >= 1
    assert config.max_attempts >= 1
    assert config.lease_ttl_seconds >= 1
    assert config.watch_interval_seconds >= 0.5


# ---------------------------------------------------------------------------
# Memory durability
# ---------------------------------------------------------------------------

def test_rejected_decision_persists_across_restarts(tmp_path: Path):
    """A rejected decision must remain visible after memory is reopened."""
    db_path = tmp_path / "athena.db"
    m1 = Memory(db_path)
    m1.create_decision_request("REQ-PERSIST", "F-P", "modify", "test")
    m1.resolve_decision_request("REQ-PERSIST", approved=False, actor="reviewer")
    m1.close()

    m2 = Memory(db_path)
    requests = m2.decision_requests()
    assert any(r["id"] == "REQ-PERSIST" and r["status"] == "rejected" for r in requests)
    m2.close()


def test_pending_request_not_overwritten_on_repeat_detection(tmp_path: Path):
    """Re-detecting the same finding must not create a new pending request that overwrites history."""
    db_path = tmp_path / "athena.db"
    memory = Memory(db_path)
    try:
        # Create a pending request
        memory.create_decision_request("REQ-DUP", "F-DUP", "modify", "test")
        assert memory.decision_requests("pending")[0]["id"] == "REQ-DUP"

        # Resolve it as rejected
        memory.resolve_decision_request("REQ-DUP", approved=False, actor="reviewer")
        assert memory.decision_requests("pending") == []

        # A re-detection scenario should not see a pending request for this finding
        assert memory.approved_decision("F-DUP") is None
        # The rejected request must still be there
        requests = memory.decision_requests("rejected")
        assert any(r["id"] == "REQ-DUP" for r in requests)
    finally:
        memory.close()
