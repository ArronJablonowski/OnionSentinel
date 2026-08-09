#!/usr/bin/env python3
"""Evaluate Onion Sentinel investigation-harness traces without changing them."""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

OPERATIONS_DIR = Path(__file__).resolve().parent
if str(OPERATIONS_DIR) not in sys.path:
    sys.path.insert(0, str(OPERATIONS_DIR))

from trace_evaluation_api import *  # noqa: F401,F403,E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--run-id", help="Evaluate exactly one harness run")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the complete machine-readable JSON report",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Write the complete JSON report to an owner-only file",
    )
    parser.add_argument(
        "--fail-on-invalid-chain",
        action="store_true",
        help="Exit 1 if any selected trace has a broken event chain",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = evaluate_database(args.db, args.run_id)
        if args.out:
            atomic_private_json(args.out, report)
        if args.json:
            print(json.dumps(report, indent=2, sort_keys=True))
        else:
            print(human_report(report))
            if args.out:
                print(f"JSON report: {args.out.expanduser()}")
        if args.fail_on_invalid_chain and not report["integrity"]["all_chains_valid"]:
            return 1
        return 0
    except (EvaluationError, sqlite3.Error, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
