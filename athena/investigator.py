from __future__ import annotations

import subprocess
from pathlib import Path

from .detectors import default_detectors
from .evidence import Evidence, EvidenceLedger
from .governance import GovernanceCatalog
from .inspectors import ProjectInspector
from .models import Finding
from .risk import RiskEngine


class Investigator:
    """Executes bounded, read-only investigations and records their evidence."""

    def __init__(self, root: Path, graph, memory) -> None:
        self.root = root
        self.graph = graph
        self.memory = memory
        self.ledger = EvidenceLedger()
        self.risk = RiskEngine()
        self.governance = GovernanceCatalog()

    def run(self, task_kind: str) -> dict:
        if task_kind in {"architecture_review", "dependency_review", "ai_system_review"}:
            findings = ProjectInspector().inspect(self.root, self.graph)
            for finding in findings:
                self.ledger.add(Evidence(f"E-{finding.id}", "project_signal", "project_inspector", finding.description, finding.confidence))
                self.memory.add_finding(finding)
            result = {"task": task_kind, "findings": [f.id for f in findings], "evidence": self.ledger.to_dict()}
            self.memory.remember("evidence", result)
            return result

        if task_kind in {"security_review", "finding_triage"}:
            findings: list[Finding] = []
            for detector in default_detectors():
                findings.extend(detector.scan(self.root))
            output = []
            for finding in findings:
                risk = self.risk.score(finding)
                controls = self.governance.map_finding(finding)
                self.memory.add_finding(finding)
                output.append({"finding": finding.id, "risk": risk.score, "band": risk.band, "controls": controls})
                self.ledger.add(Evidence(f"E-{finding.id}", "finding", "detector", finding.description, finding.confidence))
            result = {"task": task_kind, "results": output, "evidence": self.ledger.to_dict()}
            self.memory.remember("investigation", result)
            return result

        if task_kind == "governance_review":
            controls = [c.to_dict() for c in self.governance.controls()]
            result = {"task": task_kind, "controls": controls}
            self.memory.remember("governance_catalog_review", result)
            return result

        if task_kind == "evidence_validation":
            result = {"task": task_kind, "git": self._git_context()}
            self.memory.remember("validation", result)
            return result

        if task_kind == "scope_objective":
            return {"task": task_kind, "status": "scoped"}
        return {"task": task_kind, "status": "unsupported"}

    def _git_context(self) -> dict:
        def git(*args: str) -> str:
            try:
                completed = subprocess.run(["git", *args], cwd=self.root, text=True, capture_output=True, timeout=10, check=False)
                return completed.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                return ""
        return {
            "branch": git("branch", "--show-current"),
            "head": git("rev-parse", "HEAD"),
            "status": git("status", "--short"),
            "recent_commits": git("log", "-5", "--oneline"),
        }
