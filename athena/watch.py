from __future__ import annotations
import hashlib
import time
from pathlib import Path
from collections.abc import Callable

class ProjectWatcher:
    """Dependency-free polling watcher that emits when project content changes."""
    def __init__(self, root: str | Path, interval: float = 5.0):
        self.root = Path(root).resolve()
        self.interval = interval

    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        ignored = {'.git', '.athena', '.venv', 'venv', 'node_modules', '__pycache__', '.pytest_cache'}
        for path in sorted(self.root.rglob('*')):
            if not path.is_file() or any(p in ignored for p in path.parts):
                continue
            try:
                stat = path.stat()
                digest.update(str(path.relative_to(self.root)).encode())
                digest.update(str(stat.st_size).encode())
                digest.update(str(stat.st_mtime_ns).encode())
            except OSError:
                continue
        return digest.hexdigest()

    def run(self, on_change: Callable[[str], None], once: bool = False) -> None:
        previous = self.fingerprint()
        if once:
            on_change(previous)
            return
        while True:
            time.sleep(self.interval)
            current = self.fingerprint()
            if current != previous:
                previous = current
                on_change(current)
