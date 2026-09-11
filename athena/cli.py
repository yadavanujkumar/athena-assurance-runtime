from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from .runtime import AthenaRuntime
from .watch import ProjectWatcher


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="athena", description="ATHENA autonomous assurance runtime")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "inspect", "status", "findings", "plan"):
        cmd = sub.add_parser(name)
        cmd.add_argument("path", nargs="?", default=".")
    work = sub.add_parser("work")
    work.add_argument("path", nargs="?", default=".")
    work.add_argument("--all", action="store_true", help="Include completed work")
    resume = sub.add_parser("resume")
    resume.add_argument("path", nargs="?", default=".")
    resume.add_argument("--max-work", type=int, default=5)
    objective = sub.add_parser("objective")
    objective.add_argument("text")
    objective.add_argument("path", nargs="?", default=".")
    cycle = sub.add_parser("run")
    cycle.add_argument("path", nargs="?", default=".")
    cycle.add_argument("--objective", help="Explicit assurance objective")
    cycle.add_argument("--yes", action="store_true", help="Accept ATHENA's baseline objective without prompting")
    cycle.add_argument("--max-work", type=int, default=5)
    watch = sub.add_parser("watch")
    watch.add_argument("path", nargs="?", default=".")
    watch.add_argument("--interval", type=float, default=5.0)
    watch.add_argument("--once", action="store_true")
    return parser


def choose_objective(runtime: AthenaRuntime) -> str | None:
    """Ask for agreement when ATHENA has no explicit user objective."""
    runtime.initialize()
    tasks = runtime.autonomous_plan()
    proposals = [task for task in tasks if task.kind != "scope_objective"][:3]
    print("ATHENA inspected the project and proposes these assurance priorities:")
    for index, task in enumerate(proposals, 1):
        print(f"  {index}. {task.reason}")
    print("  r. Redefine the objective")
    print("  b. Continue with ATHENA's baseline")
    choice = input("Choose [1-3/r/b]: ").strip().lower()
    if choice == "r":
        text = input("Enter the assurance objective: ").strip()
        return text or None
    if choice in {"1", "2", "3"} and int(choice) <= len(proposals):
        return proposals[int(choice) - 1].reason
    return "Establish an autonomous assurance baseline across the project."


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    runtime = AthenaRuntime(Path(args.path))
    try:
        if args.command == "init":
            runtime.initialize()
            print(f"ATHENA initialized: {runtime.root}")
        elif args.command == "inspect":
            print(json.dumps([asdict(f) for f in runtime.inspect()], indent=2))
        elif args.command == "status":
            print(json.dumps(runtime.status(), indent=2))
        elif args.command == "findings":
            print(json.dumps(runtime.memory.findings(), indent=2))
        elif args.command == "work":
            print(json.dumps(runtime.work_status(args.all), indent=2))
        elif args.command == "resume":
            print(json.dumps(runtime.resume(args.max_work), indent=2))
        elif args.command == "objective":
            objective = runtime.set_objective(args.text)
            print(json.dumps({"id": objective.id, "text": objective.text}, indent=2))
        elif args.command == "plan":
            print(json.dumps([{"kind": t.kind, "reason": t.reason, "priority": t.priority} for t in runtime.autonomous_plan()], indent=2))
        elif args.command == "run":
            objective = args.objective
            if objective is None and not args.yes:
                objective = choose_objective(runtime)
            print(json.dumps(runtime.run_autonomous_cycle(objective, args.max_work), indent=2))
        elif args.command == "watch":
            def changed(fingerprint):
                runtime.memory.remember("project_changed", {"fingerprint": fingerprint})
                print(f"Change detected: {fingerprint}")
                print(json.dumps(runtime.run_autonomous_cycle(), indent=2))

            runtime.initialize()
            ProjectWatcher(runtime.root, args.interval).run(changed, args.once)
        return 0
    finally:
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
