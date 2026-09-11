from __future__ import annotations

import argparse
import json
from pathlib import Path

from .runtime import AthenaRuntime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="athena", description="ATHENA autonomous assurance runtime")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("init", "inspect", "status", "findings"):
        cmd = sub.add_parser(name)
        cmd.add_argument("path", nargs="?", default=".")

    objective = sub.add_parser("objective")
    objective.add_argument("text")
    objective.add_argument("path", nargs="?", default=".")
    return parser


def main(argv: list[str] | None = None) -> int:
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
        return 0
    finally:
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
