from pathlib import Path

from athena.dependencies import Advisory, DependencyAnalyzer


def test_inventory_reads_python_and_node_manifests(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\nfastapi>=0.1\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"^5.0.0"}}', encoding="utf-8")
    deps = DependencyAnalyzer().inventory(tmp_path)
    assert {(d.ecosystem, d.name) for d in deps} == {("python", "requests"), ("python", "fastapi"), ("node", "express")}


def test_unknown_auditor_is_safe(tmp_path: Path):
    result = DependencyAnalyzer().audit(tmp_path, "rust")
    assert result.available is False
    assert result.findings == []


def test_advisory_normalization_and_risk():
    findings = [{"package": "requests", "severity": "high", "vulnerable_versions": "<2.32.4", "fix_versions": [{"version": "2.32.4"}], "ids": ["CVE-2026-0001"]}]
    advisories = DependencyAnalyzer.normalize_advisories(findings, "python", "pip-audit")
    assert advisories == [Advisory("python", "requests", "high", "<2.32.4", "2.32.4", ("CVE-2026-0001",), "pip-audit")]
    assert DependencyAnalyzer.advisory_risk(advisories[0]) == 80


def test_advisory_normalization_skips_unidentified_records():
    assert DependencyAnalyzer.normalize_advisories([{"severity": "high"}], "node", "npm") == []
