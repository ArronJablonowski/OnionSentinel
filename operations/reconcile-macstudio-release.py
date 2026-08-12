#!/usr/bin/env python3
"""Compare an exact Git release with its live Mac Studio runtime, read-only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from runtime_release_reconciliation import (
    ReconciliationError,
    read_live_release_id,
    reconcile,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--stack-dir", type=Path, required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--expected-release-id", required=True)
    parser.add_argument("--health-url", default="http://127.0.0.1:8766/healthz")
    parser.add_argument("--live-release-id", help="test/offline override; skips health request")
    parser.add_argument("--summary-only", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        live_release_id = args.live_release_id or read_live_release_id(args.health_url)
        report = reconcile(
            repo_root=args.repo_root.resolve(),
            stack_dir=args.stack_dir.expanduser().absolute(),
            revision=args.source_revision,
            expected_release_id=args.expected_release_id,
            live_release_id=live_release_id,
        )
    except (OSError, ReconciliationError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    if args.summary_only:
        report = {key: value for key, value in report.items() if key != "entries"}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
