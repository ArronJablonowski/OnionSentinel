#!/usr/bin/env python3
"""Create the immutable retention seal for one completed evaluation run."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from evaluation_artifact_seal import write_seal


def _parse_timestamp(value: str | None) -> dt.datetime:
    if not value:
        return dt.datetime.now(dt.timezone.utc)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("--completed-at must include a timezone")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, action="append", required=True)
    parser.add_argument("--completed-at")
    args = parser.parse_args()
    try:
        path = write_seal(
            args.run_dir,
            outputs=tuple(args.output),
            completed_at=_parse_timestamp(args.completed_at),
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps({"ok": True, "seal": path.name}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
