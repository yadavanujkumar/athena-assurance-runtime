from __future__ import annotations

import argparse
import json
from pathlib import Path

from .runtime import AthenaRuntime
from .watch import ProjectWatcher


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="athena", description="ATHENA autonomous assurance runtime")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "inspect", "status", "findings", "plan"):
        cmd = sub.add_parser(name)
        cmd.add_argument("path", nargs="?", default=".")
    objective = sub.add_parser("objective")
    objective.add_argument("text")
    objective.add_argument("path", nargs="?", default=".")
    cycle = sub.add_parser("run")
    cycle.add_argument("path", nargs="?", default=".")
    cycle.add_argument("--objective", help="Explicit assurance objective")
    watch = sub.add_parser("watch")
    watch.add_argument("path", nargs="?", default=".")
    watch.add_argument("--interval", type=float, default=5.0)
    watch.add_argument("--once", action="store_true")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    runtime = AthenaRuntime(Path(args.path))
    try:
        if args.command == "init":
            runtime.initialize()
            print(f"ATHENA initialized: {runtime.root}")
        elif args.command == "inspect":
            print(json.dumps(runtime.inspect(), indent=2))
        elif args.command == "status":
            print(json.dumps(runtime.status(), indent=2))
        elif args.command == "findings":
            print(json.dumps(runtime.memory.findings(), indent=2))
        elif args.command == "objective":
            objective = runtime.set_objective(args.text)
            print(json.dumps({"id": objective.id, "text": objective.text}, indent=2))
        elif args.command == "plan":
            print(json.dumps([{"kind": t.kind, "reason": t.reason, "priority": t.priority} for t in runtime.autonomous_plan()], indent=2))
        elif args.command == "run":
            print(json.dumps(runtime.run_autonomous_cycle(args.objective), indent=2))
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
