from athena.models import Finding, Severity
from athena.policy import Authority, PolicyEngine


def test_modify_requires_authority():
    finding = Finding("F1", "Dynamic eval usage", "eval", Severity.HIGH, 0.98)
    assert not PolicyEngine().can_remediate(finding)
    assert PolicyEngine(Authority(modify=True)).can_remediate(finding)


def test_low_severity_cannot_be_modified():
    finding = Finding("F1", "Low risk", "test", Severity.LOW, 0.98)
    assert not PolicyEngine(Authority(modify=True)).can_remediate(finding)
