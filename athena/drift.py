from __future__ import annotations

from dataclasses import dataclass
from .snapshot import ProjectSnapshot, Snapshotter


@dataclass(frozen=True, slots=True)
class Drift:
    changed: bool
    previous: str | None
    current: str
    git_changed: bool


class DriftDetector:
    """Turns project snapshots into an explicit change signal for the assurance loop."""

    def __init__(self, root) -> None:
        self.snapshotter = Snapshotter(root)

    def compare(self, previous: ProjectSnapshot | None) -> Drift:
        current = self.snapshotter.capture()
        return Drift(
            changed=previous is None or previous.fingerprint != current.fingerprint,
            previous=previous.fingerprint if previous else None,
            current=current.fingerprint,
            git_changed=bool(previous and previous.git_head and current.git_head != previous.git_head),
        )
