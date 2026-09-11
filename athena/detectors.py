from __future__ import annotations

from pathlib import Path
import ast
import hashlib
import re

from .models import Finding, Severity


class Detector:
    name = "base"

    def scan(self, root: Path) -> list[Finding]:
        raise NotImplementedError


def _id(title: str, evidence: str) -> str:
    return "F-" + hashlib.sha256(f"{title}:{evidence}".encode()).hexdigest()[:10].upper()


class PythonSafetyDetector(Detector):
    name = "python-safety"

    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in root.rglob("*.py"):
            if any(part in {".git", ".venv", "venv", "node_modules", "__pycache__"} for part in path.parts):
                continue
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (OSError, UnicodeDecodeError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
                    evidence = f"{path}:{node.lineno}"
                    findings.append(Finding(_id("dynamic eval", evidence), "Dynamic eval usage", "eval() executes dynamically supplied Python and can become code execution when input is attacker-controlled.", Severity.HIGH, 0.98, [evidence], "Replace eval with an explicit parser or constrained dispatch."))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "exec":
                    evidence = f"{path}:{node.lineno}"
                    findings.append(Finding(_id("dynamic exec", evidence), "Dynamic exec usage", "exec() executes dynamically supplied Python and creates a high-risk code execution boundary.", Severity.HIGH, 0.98, [evidence], "Remove exec or isolate it behind a tightly constrained execution boundary."))
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "system" and isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                    evidence = f"{path}:{node.lineno}"
                    findings.append(Finding(_id("os system", evidence), "Shell command execution", "os.system() creates a shell execution boundary and should be reviewed for untrusted input and least privilege.", Severity.MEDIUM, 0.95, [evidence], "Prefer subprocess with an argument list and explicit validation."))
        return findings


class SecretDetector(Detector):
    name = "secrets"
    patterns = [
        re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}['\"]"),
    ]

    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.stat().st_size > 1_000_000 or any(part in {".git", ".venv", "venv", "node_modules"} for part in path.parts):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for line_no, line in enumerate(text.splitlines(), 1):
                if any(pattern.search(line) for pattern in self.patterns):
                    evidence = f"{path}:{line_no}"
                    findings.append(Finding(_id("possible secret", evidence), "Possible hard-coded secret", "A credential-like value appears to be embedded in source or configuration.", Severity.HIGH, 0.82, [evidence], "Move the secret to a secure secret store or environment injection and rotate it if it is real."))
        return findings


class ConfigDetector(Detector):
    name = "configuration"

    def scan(self, root: Path) -> list[Finding]:
        findings: list[Finding] = []
        for name in (".env", ".env.local", ".env.production"):
            path = root / name
            if path.exists():
                evidence = str(path)
                findings.append(Finding(_id("environment file", evidence), "Environment file present", "A local environment file exists in the project tree. Confirm it is ignored and contains no committed credentials.", Severity.MEDIUM, 0.9, [evidence], "Add the file to ignore rules and use a non-secret example file for documented configuration."))
        return findings


def default_detectors() -> list[Detector]:
    return [PythonSafetyDetector(), SecretDetector(), ConfigDetector()]
