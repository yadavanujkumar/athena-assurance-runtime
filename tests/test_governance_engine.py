from athena.governance_engine import GovernanceEngine
from athena.models import Finding, Severity


def test_high_ai_finding_maps_to_actionable_controls():
    finding = Finding("F1", "AI tool exposure", "agent can invoke a tool", Severity.HIGH, 0.95, ["src/agent.py"])
    assessments = GovernanceEngine().assess(finding)
    keys = {(item.framework, item.control_id) for item in assessments}
    assert ("NIST AI RMF", "MANAGE") in keys
    assert ("NIST AI RMF", "MAP") in keys
    assert ("OWASP", "AI-SECURITY") in keys
    assert all(item.status == "attention" for item in assessments)


def test_resolved_finding_is_addressed_not_compliance_claim_without_mapping():
    finding = Finding("F2", "AI risk", "agent issue", Severity.HIGH, 0.9, ["evidence"], status="resolved")
    assessments = GovernanceEngine().assess(finding)
    assert assessments
    assert all(item.status == "addressed" for item in assessments)
