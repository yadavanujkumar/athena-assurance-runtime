from athena.models import Finding, Severity
from athena.policy import Authority, PolicyEngine


def test_modify_requires_authority():
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98)
    assert not PolicyEngine().can_remediate(finding)
    assert PolicyEngine(Authority(modify=True)).can_remediate(finding)


def test_low_severity_cannot_be_modified():
    finding = Finding("F1", "Low risk", "test", Severity.LOW, 0.98)
    assert not PolicyEngine(Authority(modify=True)).can_remediate(finding)


def test_blocked_critical_cannot_be_modified():
    finding = Finding("F1", "Critical risk", "test", Severity.CRITICAL, 0.98)
    policy = PolicyEngine(Authority(modify=True, block=True))
    assert policy.next_action(finding).value == "block"
    assert not policy.can_remediate(finding)
    assert not policy.can_remediate_record({"id": "F1", "title": "Critical risk", "description": "test", "severity": "critical", "confidence": 0.98})


def test_invalid_persisted_finding_is_denied():
    assert not PolicyEngine(Authority(modify=True)).can_remediate_record({"id": "F1", "severity": "unknown"})
