from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ProjectSnapshot:
    fingerprint: str
    file_count: int
    git_head: str = ""
    git_status: str = ""


class Snapshotter:
    """Creates stable, read-only project snapshots for drift detection."""

    IGNORED = {".git", ".athena", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache"}

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    def capture(self) -> ProjectSnapshot:
        entries: list[str] = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or any(part in self.IGNORED for part in path.parts):
                continue
            try:
                stat = path.stat()
            except OSError:
                continue
            rel = path.relative_to(self.root).as_posix()
            entries.append(f"{rel}|{stat.st_size}|{stat.st_mtime_ns}")
        digest = hashlib.sha256("\n".join(entries).encode()).hexdigest()
        return ProjectSnapshot(digest, len(entries), self._git("rev-parse", "HEAD"), self._git("status", "--short"))

    def changed_since(self, previous: ProjectSnapshot | None) -> bool:
        return previous is None or self.capture().fingerprint != previous.fingerprint

    def _git(self, *args: str) -> str:
        try:
            result = subprocess.run(["git", *args], cwd=self.root, text=True, capture_output=True, timeout=10, check=False)
            return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
