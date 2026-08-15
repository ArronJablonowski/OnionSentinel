#!/usr/bin/env python3
"""Apply or preview Onion Sentinel's bounded application-log policy."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from application_log_maintenance import (
    ApplicationLogMaintenanceError,
    maintain_logs,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stack-dir",
        type=Path,
        default=Path.home() / "n8n-local",
    )
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        report = maintain_logs(args.stack_dir, apply=args.apply)
    except ApplicationLogMaintenanceError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
