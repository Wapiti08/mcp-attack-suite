from __future__ import annotations

import argparse
import json
from pathlib import Path

from .run import env_root, run_once


def main(argv: list[str] | None = None) -> int:
    default_out = env_root() / "runs"
    parser = argparse.ArgumentParser(prog="arena.runner")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="Run a challenge with a submission manifest and validate the objective.")
    run.add_argument("--challenge", required=True, help="Challenge id (e.g. cryptosystem, emailsystem).")
    run.add_argument("--attack", required=True, help="Attack config name. Looks up environment/arena/challenges/<challenge>/attacks/<attack>.json.")
    run.add_argument("--submission", required=True, help="Path to submission artifact file (png/py/etc).")
    run.add_argument("--out", default=str(default_out), help="Output directory for run artifacts.")
    run.add_argument("--no-agent", action="store_true", help="Only start servers + run validator (skip LLM).")

    args = parser.parse_args(argv)

    if args.cmd == "run":
        try:
            result = run_once(
                challenge_id=str(args.challenge),
                submission_path=Path(args.submission),
                attack=str(args.attack),
                out_dir=Path(args.out),
                run_agent=not bool(args.no_agent),
            )
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0 if result.get("ok") else 2
        except Exception as e:
            print(json.dumps({"ok": False, "error": str(e), "error_type": type(e).__name__}, indent=2, ensure_ascii=False))
            return 2

    return 2
