from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class FileChange:
    path: str
    kind: str
    previous: str | None = None
    current: str | None = None


class ChangeAnalyzer:
    """Compares lightweight file inventories and classifies project drift."""

    IGNORED = {".git", ".athena", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}

    def inventory(self, root: str | Path) -> dict[str, tuple[int, int]]:
        root = Path(root).resolve()
        result: dict[str, tuple[int, int]] = {}
        for path in root.rglob("*"):
            if not path.is_file() or any(part in self.IGNORED for part in path.parts):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            result[path.relative_to(root).as_posix()] = (stat.st_size, stat.st_mtime_ns)
        return result

    def compare(self, previous: dict[str, tuple[int, int]], current: dict[str, tuple[int, int]]) -> list[FileChange]:
        changes: list[FileChange] = []
        for path in sorted(set(previous) | set(current)):
            if path not in previous:
                changes.append(FileChange(path, "added", None, str(current[path])))
            elif path not in current:
                changes.append(FileChange(path, "removed", str(previous[path]), None))
            elif previous[path] != current[path]:
                changes.append(FileChange(path, "modified", str(previous[path]), str(current[path])))
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
