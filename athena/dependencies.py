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
class AuditResult:
    tool: str
    available: bool
    exit_code: int | None
    findings: list[dict]
    output: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class DependencyAnalyzer:
    """Read dependency manifests and optionally run installed open-source auditors."""

    def inventory(self, root: str | Path) -> list[Dependency]:
        root = Path(root).resolve()
        result: list[Dependency] = []
        result.extend(self._requirements(root / "requirements.txt"))
        result.extend(self._pyproject(root / "pyproject.toml"))
        result.extend(self._package_json(root / "package.json"))
        result.extend(self._go_mod(root / "go.mod"))
        return result

    def audit(self, root: str | Path, ecosystem: str) -> AuditResult:
        root = Path(root).resolve()
        commands = {
            "python": ["python", "-m", "pip_audit", "-f", "json"],
            "node": ["npm", "audit", "--json"],
        }
        command = commands.get(ecosystem)
        if command is None:
            return AuditResult(ecosystem, False, None, [], "No built-in auditor for this ecosystem.")
        try:
            completed = subprocess.run(command, cwd=root, text=True, capture_output=True, timeout=120, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return AuditResult(command[0], False, None, [], str(exc))
        output = completed.stdout or completed.stderr
        findings = self._parse_audit(output, ecosystem)
        return AuditResult(command[0], True, completed.returncode, findings, output[:12000])

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
