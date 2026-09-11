from pathlib import Path

from athena.dependencies import DependencyAnalyzer


def test_inventory_reads_python_and_node_manifests(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\nfastapi>=0.1\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"^5.0.0"}}', encoding="utf-8")
    deps = DependencyAnalyzer().inventory(tmp_path)
    assert {(d.ecosystem, d.name) for d in deps} == {("python", "requests"), ("python", "fastapi"), ("node", "express")}


def test_unknown_auditor_is_safe(tmp_path: Path):
    result = DependencyAnalyzer().audit(tmp_path, "rust")
    assert result.available is False
    assert result.findings == []
