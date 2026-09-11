from athena.governance import GovernanceCatalog
from athena.models import Finding, Severity

def test_governance_catalog_and_mapping():
    catalog=GovernanceCatalog()
    assert len(catalog.controls()) >= 7
    finding=Finding('x','AI agent risk','agent can access tools',Severity.HIGH,0.9)
    mapped=catalog.map_finding(finding)
    assert 'NIST AI RMF:MANAGE' in mapped
    assert 'OWASP:AI-SECURITY' in mapped
