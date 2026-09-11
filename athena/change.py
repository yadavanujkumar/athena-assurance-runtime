from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class FileChange:
    path: str
    kind: str
    previous: str | None = None
    current: str | None = None


@dataclass(frozen=True, slots=True)
class FileFingerprint:
    """Content identity plus metadata used to explain a detected change."""

    sha256: str
    size: int
    mtime_ns: int


class ChangeAnalyzer:
    """Compares content-addressed file inventories and classifies project drift."""

    IGNORED = {".git", ".athena", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}

    def inventory(self, root: str | Path) -> dict[str, FileFingerprint]:
        root = Path(root).resolve()
        result: dict[str, FileFingerprint] = {}
        for path in root.rglob("*"):
            if not path.is_file() or any(part in self.IGNORED for part in path.parts):
                continue
            try:
                stat = path.stat()
                digest = self._sha256(path)
            except OSError:
                continue
            result[path.relative_to(root).as_posix()] = FileFingerprint(digest, stat.st_size, stat.st_mtime_ns)
        return result

    def compare(self, previous: dict, current: dict) -> list[FileChange]:
        changes: list[FileChange] = []
        for path in sorted(set(previous) | set(current)):
            if path not in previous:
                changes.append(FileChange(path, "added", None, self._identity(current[path])))
            elif path not in current:
                changes.append(FileChange(path, "removed", self._identity(previous[path]), None))
            elif self._sha(previous[path]) != self._sha(current[path]):
                changes.append(FileChange(path, "modified", self._identity(previous[path]), self._identity(current[path])))
        return changes

    @staticmethod
    def classify(changes: list[FileChange]) -> set[str]:
        classes: set[str] = set()
        for change in changes:
            path = change.path.lower()
            if path.endswith((".py", ".js", ".ts", ".java", ".go", ".rs", ".cpp", ".c")):
                classes.add("source")
            if any(x in path for x in ("requirements", "pyproject", "package.json", "package-lock", "poetry.lock", "cargo.toml", "go.mod")):
                classes.add("dependency")
            if any(x in path for x in ("model", "agent", "prompt", "llm", "ai")):
                classes.add("ai")
            if any(x in path for x in ("docker", "k8s", "terraform", ".github", "deploy")):
                classes.add("deployment")
            if any(x in path for x in ("config", ".env", "secret", "auth", "permission", "policy")):
                classes.add("security")
        return classes

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _sha(value) -> str:
        return value.sha256 if isinstance(value, FileFingerprint) else str(value[0])

    @staticmethod
    def _identity(value) -> str:
        if isinstance(value, FileFingerprint):
            return value.sha256
        return str(value)
