from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import hashlib
import re

from .dependencies import DependencyAnalyzer
from .detectors import default_detectors
from .lifecycle import FindingLifecycle
from .models import Finding, Severity, utc_now
from .validation import ValidationEngine


@dataclass(slots=True)
class Evidence:
    source: str
    kind: str
    detail: str
    collected_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class InvestigationResult:
    objective: str
    findings: list[Finding]
    evidence: list[Evidence]
    completed: bool = True


class InvestigationEngine:
    """Runs bounded investigations and produces an evidence ledger."""

    def __init__(self, root: Path, memory, governance=None) -> None:
        self.root = root
        self.memory = memory
        self.governance = governance
        self.dependencies = DependencyAnalyzer()
        self.validation = ValidationEngine()
        self.lifecycle = FindingLifecycle(memory)

    def run(self, objective: str, task_kind: str | None = None, reconcile_lifecycle: bool = True) -> InvestigationResult:
        evidence = [Evidence(str(self.root), "scope", objective)]
        findings: list[Finding] = []
        kind = task_kind or self._infer_task(objective)

        if kind in {"dependency_review", "dependency_advisory_review"}:
            deps = self.dependencies.inventory(self.root)
            evidence.extend(Evidence(d.source, "dependency", f"{d.ecosystem}:{d.name}@{d.version or 'unversioned'}") for d in deps)
            self.memory.fact("dependencies.inventory", [d.to_dict() for d in deps])
            target = self._advisory_target(objective) if kind == "dependency_advisory_review" else None
            ecosystems = [target[0]] if target else sorted({d.ecosystem for d in deps})
            for ecosystem in ecosystems:
                audit = self.dependencies.audit(self.root, ecosystem)
                evidence.append(Evidence(audit.tool, "audit", f"available={audit.available}; exit_code={audit.exit_code}; advisories={len(audit.findings)}"))
                self.memory.remember("dependency_audit", audit.to_dict())
                for advisory in audit.findings:
                    name = advisory.get("name") or advisory.get("package") or "dependency"
                    if target and name.lower() != target[1].lower():
                        continue
                    identifiers = advisory.get("identifiers") or advisory.get("id") or advisory.get("cve") or []
                    if isinstance(identifiers, str):
                        identifiers = [identifiers]
                    identifier_text = ",".join(str(item) for item in identifiers) or "unidentified"
                    severity = self._advisory_severity(advisory.get("severity"))
                    stable_key = f"{ecosystem}:{name}:{identifier_text}:{advisory.get('vulnerable_range') or advisory.get('range') or ''}"
                    stable_id = "DEP-" + hashlib.sha256(stable_key.encode()).hexdigest()[:14].upper()
                    vulnerable = advisory.get("vulnerable_range") or advisory.get("range") or "unknown"
                    fixed = advisory.get("fixed_version") or advisory.get("fixed") or "unknown"
                    finding = Finding(stable_id, f"Dependency vulnerability: {name}", f"An installed open-source dependency auditor reported a {severity.value.lower()} vulnerability or advisory for {name}.", severity, 0.9, [audit.tool, name, identifier_text, vulnerable], f"Upgrade {name} to {fixed} when available, or replace/constrain the affected dependency, then rerun the audit.")
                    findings.append(finding)
                    self.memory.add_finding(finding)
            if deps and not findings:
                self.memory.remember("dependency_inventory", {"count": len(deps), "ecosystems": sorted({d.ecosystem for d in deps})})
        elif kind in {"validation", "change_validation"}:
            for command in self.validation.detect_commands(self.root):
                result = self.validation.run(self.root, command)
                evidence.append(Evidence(command, "validation", f"passed={result.passed}; exit_code={result.exit_code}"))
                self.memory.remember("validation_result", result.to_dict())
                if result.available and not result.passed:
                    stable = hashlib.sha256(command.encode()).hexdigest()[:10]
                    findings.append(Finding("VALIDATION-FAILED-" + stable, "Project validation failed", f"Detected validation command failed: {command}", Severity.HIGH, 0.95, [command, result.stderr[-1000:]], "Investigate the failing test or validation command before accepting the project state."))
        else:
            for detector in default_detectors():
                for finding in detector.scan(self.root):
                    findings.append(finding)
                    self.memory.add_finding(finding)
                    evidence.extend(Evidence(item, "finding", finding.title) for item in finding.evidence)

        if reconcile_lifecycle:
            lifecycle = self.lifecycle.reconcile(findings)
            self.memory.remember("evidence_correlation", {"states": lifecycle, "evidence_count": len(evidence)})
        self.memory.remember("investigation_completed", {"objective": objective, "task_kind": kind, "finding_count": len(findings), "critical_count": sum(f.severity is Severity.CRITICAL for f in findings), "high_count": sum(f.severity is Severity.HIGH for f in findings), "evidence_count": len(evidence)})
        return InvestigationResult(objective, findings, evidence)

    @staticmethod
    def _advisory_target(objective: str) -> tuple[str, str] | None:
        match = re.search(r"active\s+(python|node)\s+advisory\s+for\s+([^;]+)", objective, re.IGNORECASE)
        if not match:
            return None
        return match.group(1).lower(), match.group(2).strip()

    @staticmethod
    def _advisory_severity(value) -> Severity:
        text = str(value or "").strip().lower()
        if text in {"critical", "crit", "cvss:critical"}:
            return Severity.CRITICAL
        if text in {"high", "important", "severe"}:
            return Severity.HIGH
        if text in {"medium", "moderate"}:
            return Severity.MEDIUM
        if text in {"low", "minor"}:
            return Severity.LOW
        return Severity.HIGH

    @staticmethod
    def _infer_task(objective: str) -> str:
        text = objective.lower()
        if "depend" in text or "supply chain" in text:
            return "dependency_review"
        if "test" in text or "validat" in text:
            return "validation"
        return "security_review"


# Compatibility facade retained for runtime integrations and older callers.
Investigator = InvestigationEngine
