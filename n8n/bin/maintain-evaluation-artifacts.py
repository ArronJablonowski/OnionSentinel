#!/usr/bin/env python3
"""Apply seal-gated retention and capacity policy to evaluation artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import tempfile

from evaluation_artifact_contract import REPORT_SCHEMA, default_policy
from evaluation_artifact_retention import maintain


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stack-dir", type=Path, default=Path.home() / "n8n-local")
    parser.add_argument("--encrypted-storage-root", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--apply", action="store_true")
    return parser


def _timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _atomic_report(path: Path, document: dict[str, object]) -> None:
    target = path.expanduser()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.is_symlink():
        raise ValueError("evaluation maintenance report must not be a symlink")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        os.chmod(target, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    args = _parser().parse_args()
    now = dt.datetime.now(dt.timezone.utc)
    report_path = args.report or (
        args.stack_dir / "logs/evaluation-artifact-maintenance.json"
    )
    try:
        lock_path = args.stack_dir / "run/evaluation-artifact-maintenance.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with lock_path.open("w", encoding="utf-8") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = maintain(
                args.stack_dir,
                now=now,
                policy=default_policy(),
                apply=args.apply,
                encrypted_storage_root=args.encrypted_storage_root,
            )
        report = {
            "schema": REPORT_SCHEMA,
            "generated_at": _timestamp(now),
            **result,
        }
    except (BlockingIOError, OSError, ValueError) as exc:
        report = {
            "schema": REPORT_SCHEMA,
            "generated_at": _timestamp(now),
            "status": "failure",
            "applied": False,
            "error": str(exc),
        }
    _atomic_report(report_path, report)
    print(json.dumps(report, sort_keys=True))
    return {"ok": 0, "warning": 1}.get(str(report.get("status")), 2)


if __name__ == "__main__":
    raise SystemExit(main())
