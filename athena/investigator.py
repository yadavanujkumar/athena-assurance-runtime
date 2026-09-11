from __future__ import annotations

import subprocess
from pathlib import Path

from .detectors import default_detectors
from .evidence import Evidence, EvidenceLedger
from .governance import GovernanceCatalog
from .inspectors import ProjectInspector
from .models import Finding, Severity
from .risk import RiskEngine


class Investigator:
    """Executes bounded, read-only investigations and converts observations into evidence."""

    def __init__(self, root: Path, graph, memory) -> None:
        self.root = root
        self.graph = graph
        self.memory = memory
        self.ledger = EvidenceLedger()
        self.risk = RiskEngine()
        self.governance = GovernanceCatalog()

    def run(self, task_kind: str) -> dict:
        if task_kind in {"architecture_review", "dependency_review", "ai_system_review"}:
            inspection = ProjectInspector(self.root, self.graph).inspect()
            for item in inspection:
                self.ledger.add(Evidence(item["id"], "project_signal", "project_inspector", str(item), 0.9))
            self.memory.remember("evidence", {"task": task_kind, "items": self.ledger.to_dict()})
            return {"task": task_kind, "evidence": self.ledger.to_dict()}

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
                self.ledger.add(Evidence(f"E-{finding.id}", "finding", detector.name, finding.description, finding.confidence))
            self.memory.remember("investigation", {"task": task_kind, "results": output})
            return {"task": task_kind, "results": output, "evidence": self.ledger.to_dict()}

        if task_kind == "governance_review":
            controls = [c.__dict__ if hasattr(c, "__dict__") else {"framework": c.framework, "control_id": c.control_id, "title": c.title, "intent": c.intent} for c in self.governance.controls()]
            self.memory.remember("governance_catalog_review", {"controls": controls})
            return {"task": task_kind, "controls": controls}

        if task_kind == "evidence_validation":
            result = self._git_context()
            self.memory.remember("validation", result)
            return {"task": task_kind, "git": result}

        if task_kind == "scope_objective":
            return {"task": task_kind, "status": "scoped"}
        return {"task": task_kind, "status": "unsupported"}

    def _git_context(self) -> dict:
        def git(*args: str) -> str:
            try:
                return subprocess.run(["git", *args], cwd=self.root, text=True, capture_output=True, timeout=10, check=False).stdout.strip()
            except (OSError, subprocess.SubprocessError):
                return ""
        return {"branch": git("branch", "--show-current"), "head": git("rev-parse", "HEAD"), "status": git("status", "--short"), "recent_commits": git("log", "-5", "--oneline")}
