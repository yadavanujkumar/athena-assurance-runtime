from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .snapshot import ProjectSnapshot, Snapshotter


@dataclass(frozen=True, slots=True)
class WatchEvent:
    changed: bool
    previous: ProjectSnapshot | None
    current: ProjectSnapshot


class ContinuousWatch:
    """Dependency-free polling loop that emits bounded project drift events."""

    def __init__(self, root: str | Path, interval_seconds: float = 5.0) -> None:
        self.snapshotter = Snapshotter(root)
        self.interval_seconds = max(1.0, interval_seconds)
        self.previous: ProjectSnapshot | None = None

    def poll(self) -> WatchEvent:
        current = self.snapshotter.capture()
        event = WatchEvent(self.previous is not None and current.fingerprint != self.previous.fingerprint, self.previous, current)
        self.previous = current
        return event

    def run(self, callback, *, iterations: int | None = None) -> None:
        count = 0
        while iterations is None or count < iterations:
            event = self.poll()
            callback(event)
            count += 1
            if iterations is None or count < iterations:
                time.sleep(self.interval_seconds)
