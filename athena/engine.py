from __future__ import annotations

from .investigator import Investigator


class AssuranceEngine:
    """Autonomous assurance loop with durable event boundaries and bounded actions."""

    def __init__(self, runtime) -> None:
        self.runtime = runtime
        self.investigator = Investigator(runtime.root, runtime.graph, runtime.memory)

    def run(self, max_tasks: int | None = None) -> list[dict]:
        tasks = self.runtime.autonomous_plan()
        results = []
        for task in tasks[:max_tasks]:
            self.runtime.memory.remember("task_started", {"kind": task.kind, "priority": task.priority, "reason": task.reason})
            try:
                result = self.investigator.run(task.kind)
                self.runtime.memory.remember("task_completed", {"kind": task.kind, "result": result})
                results.append(result)
            except Exception as exc:
                self.runtime.memory.remember("task_failed", {"kind": task.kind, "error": repr(exc)})
                results.append({"task": task.kind, "status": "failed", "error": str(exc)})
        self.runtime.memory.remember("assurance_cycle", {"tasks_planned": len(tasks), "tasks_executed": len(results)})
        return results
