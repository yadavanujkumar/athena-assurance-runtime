from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Dependency:
    ecosystem: str
    name: str
    version: str | None
    source: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class Advisory:
    ecosystem: str
    package: str
    severity: str
    vulnerable_range: str | None
    fixed_version: str | None
    identifiers: tuple[str, ...]
    source: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["identifiers"] = list(self.identifiers)
        return data


@dataclass(frozen=True, slots=True)
class AuditResult:
    tool: str
    available: bool
    exit_code: int | None
    findings: list[dict]
    output: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class DependencyAnalyzer:
    """Read manifests and normalize optional open-source supply-chain advisories."""

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root).resolve() if root is not None else None

    def inventory(self, root: str | Path | None = None) -> list[Dependency]:
        project_root = self._root(root)
        result: list[Dependency] = []
        result.extend(self._requirements(project_root / "requirements.txt"))
        result.extend(self._pyproject(project_root / "pyproject.toml"))
        result.extend(self._package_json(project_root / "package.json"))
        result.extend(self._go_mod(project_root / "go.mod"))
        return result

    def audit(self, root: str | Path | None, ecosystem: str) -> AuditResult:
        project_root = self._root(root)
        commands = {"python": ["python", "-m", "pip_audit", "-f", "json"], "node": ["npm", "audit", "--json"]}
        command = commands.get(ecosystem)
        if command is None:
            return AuditResult(ecosystem, False, None, [], "No built-in auditor for this ecosystem.")
        try:
            completed = subprocess.run(command, cwd=project_root, text=True, capture_output=True, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return AuditResult(command[0], False, None, [], str(exc))
        output = completed.stdout or completed.stderr
        findings = self._parse_audit(output, ecosystem)
        return AuditResult(command[0], True, completed.returncode, findings, output[:12000])

    def advisories(self, root: str | Path | None, ecosystem: str) -> list[Advisory]:
        """Run an installed auditor and convert results into stable advisory records."""
        result = self.audit(root, ecosystem)
        return self.normalize_advisories(result.findings, ecosystem, result.tool)

    def _root(self, root: str | Path | None) -> Path:
        selected = root if root is not None else self.root
        return Path(selected or ".").resolve()

    @staticmethod
    def normalize_advisories(findings: list[dict], ecosystem: str, source: str) -> list[Advisory]:
        advisories: list[Advisory] = []
        for item in findings:
            package = str(item.get("package") or item.get("name") or item.get("dependency", ""))
            if not package:
                continue
            ids = item.get("ids") or item.get("id") or item.get("identifiers") or item.get("via") or []
            if isinstance(ids, str):
                ids = [ids]
            if not isinstance(ids, (list, tuple)):
                ids = [str(ids)]
            severity = str(item.get("severity") or item.get("fix_versions") and "high" or "unknown").lower()
            vulnerable = item.get("vulnerable_versions") or item.get("vulnerable_range") or item.get("range")
            fixed = item.get("fixed_version")
            if fixed is None:
                fixes = item.get("fix_versions")
                if isinstance(fixes, list) and fixes:
                    first = fixes[0]
                    fixed = first.get("version") if isinstance(first, dict) else first
            advisories.append(Advisory(ecosystem, package, severity, str(vulnerable) if vulnerable else None, str(fixed) if fixed else None, tuple(sorted({str(i) for i in ids})), source))
        return advisories

    @staticmethod
    def advisory_risk(advisory: Advisory) -> int:
        """Transparent 0-100 supply-chain risk contribution; not a vulnerability score."""
        weights = {"critical": 100, "high": 80, "moderate": 55, "medium": 55, "low": 25, "unknown": 40}
        return weights.get(advisory.severity, 40)

    def _requirements(self, path: Path) -> list[Dependency]:
        if not path.exists():
            return []
        result = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            match = re.match(r"([A-Za-z0-9_.-]+)\s*(?:==|>=|<=|~=|>|<)\s*([^;\s]+)", line)
            if match:
                result.append(Dependency("python", match.group(1), match.group(2), path.name))
        return result

    def _pyproject(self, path: Path) -> list[Dependency]:
        if not path.exists():
            return []
        text = path.read_text(encoding="utf-8", errors="ignore")
        result = []
        in_deps = False
        for line in text.splitlines():
            if line.strip().startswith("dependencies") and "[" in line:
                in_deps = True
            if in_deps:
                match = re.search(r"[\"']([A-Za-z0-9_.-]+)(?:\s*[<>=~!].*)?[\"']", line)
                if match:
                    result.append(Dependency("python", match.group(1), None, path.name))
                if "]" in line:
                    in_deps = False
        return result

    def _package_json(self, path: Path) -> list[Dependency]:
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        result = []
        for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, version in data.get(section, {}).items():
                result.append(Dependency("node", name, str(version), path.name))
        return result

    def _go_mod(self, path: Path) -> list[Dependency]:
        if not path.exists():
            return []
        result = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            match = re.match(r"\s*([\w./-]+)\s+(v[\w.+-]+)", line)
            if match and not line.strip().startswith(("module ", "go ")):
                result.append(Dependency("go", match.group(1), match.group(2), path.name))
        return result

    @staticmethod
    def _parse_audit(output: str, ecosystem: str) -> list[dict]:
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []
        if ecosystem == "python":
            return data if isinstance(data, list) else data.get("dependencies", [])
        vulnerabilities = data.get("vulnerabilities", {}) if isinstance(data, dict) else {}
        return [dict(v, package=name) for name, v in vulnerabilities.items()]
