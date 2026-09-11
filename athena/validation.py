from __future__ import annotations

import shlex
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ValidationResult:
    command: str
    available: bool
    exit_code: int | None
    passed: bool
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class ValidationEngine:
    """Runs only detected, read-only validation commands with bounded execution."""

    ALLOWED_PREFIXES = (
        "pytest", "python -m pytest", "python -m unittest", "npm test", "npm run test",
        "go test", "cargo test", "mvn test", "gradle test",
    )

    def detect_commands(self, root: str | Path) -> list[str]:
        root = Path(root).resolve()
        commands: list[str] = []
        if (root / "pytest.ini").exists() or (root / "tests").is_dir() or (root / "pyproject.toml").exists():
            commands.append("python -m pytest")
        if (root / "package.json").exists():
            commands.append("npm test")
        if (root / "go.mod").exists():
            commands.append("go test ./...")
        if (root / "Cargo.toml").exists():
            commands.append("cargo test")
        if (root / "pom.xml").exists():
            commands.append("mvn test")
        if (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
            commands.append("gradle test")
        return list(dict.fromkeys(commands))

    def run(self, root: str | Path, command: str, timeout: int = 120) -> ValidationResult:
        if not self._allowed(command):
            return ValidationResult(command, False, None, False, stderr="Command is outside ATHENA's read-only validation allowlist.")
        try:
            parts = shlex.split(command)
            completed = subprocess.run(parts, cwd=Path(root).resolve(), text=True, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return ValidationResult(command, False, None, False, stderr=str(exc))
        return ValidationResult(command, True, completed.returncode, completed.returncode == 0, completed.stdout[-12000:], completed.stderr[-12000:])

    @classmethod
    def _allowed(cls, command: str) -> bool:
        normalized = " ".join(command.strip().split())
        return any(normalized == prefix or normalized.startswith(prefix + " ") for prefix in cls.ALLOWED_PREFIXES)
