from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class WatchResult:
    cycles: int
    stopped: bool
    last_result: dict | None


class AutonomousWatcher:
    """Dependency-free continuous runner around AthenaRuntime.

    The watcher delegates all authority, policy and remediation decisions to the runtime;
    it only controls when another bounded autonomous cycle is requested.
    """

    def __init__(self, runtime, *, interval_seconds: float | None = None) -> None:
        self.runtime = runtime
        configured = runtime.config.watch_interval_seconds
        self.interval_seconds = max(0.5, float(interval_seconds if interval_seconds is not None else configured))
        self._stop = False

    def stop(self) -> None:
        self._stop = True

    def run(self, *, cycles: int | None = None, objective: str | None = None, max_work: int | None = None, sleep: bool = True) -> WatchResult:
        completed = 0
        last_result = None
        while not self._stop and (cycles is None or completed < max(1, cycles)):
            last_result = self.runtime.run_autonomous_cycle(objective=objective, max_work=max_work)
            completed += 1
            if self._stop or (cycles is not None and completed >= cycles):
                break
            if sleep:
                time.sleep(self.interval_seconds)
        return WatchResult(completed, self._stop, last_result)
