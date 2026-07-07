#!/usr/bin/env python3
"""Conservative retention cleanup for runtime-only PCAP evidence.

Raw PCAP broker artifacts are operational evidence, not repo content. This
script keeps that runtime area bounded while preserving derived Markdown/JSON
analysis longer for analyst review and AI prompt context. It defaults to
dry-run so operators can inspect the exact delete set before applying it.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any


HOME = Path.home()
DEFAULT_ARTIFACT_DIR = HOME / "n8n-local" / "pcap-evidence" / "artifacts"
DEFAULT_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_ARTIFACT_RETENTION_DAYS = 14
DEFAULT_ANALYSIS_RETENTION_DAYS = 30


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clean old Onion Sentinel PCAP runtime artifacts")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR)
    parser.add_argument("--artifact-retention-days", type=int, default=DEFAULT_ARTIFACT_RETENTION_DAYS)
    parser.add_argument("--analysis-retention-days", type=int, default=DEFAULT_ANALYSIS_RETENTION_DAYS)
    parser.add_argument("--apply", action="store_true", help="Delete matched files. Omit for dry-run.")
    return parser.parse_args()


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def validate_runtime_path(path: Path) -> Path:
    resolved = path.expanduser().resolve()
    allowed_root = (HOME / "n8n-local").resolve()
    if resolved in {HOME.resolve(), allowed_root, Path("/")}:
        raise ValueError(f"refusing unsafe cleanup path: {resolved}")
    if not resolved.is_relative_to(allowed_root):
        raise ValueError(f"cleanup path must be under {allowed_root}: {resolved}")
    return resolved


def cutoff_for(days: int, now: dt.datetime) -> float:
    if days < 1:
        raise ValueError("retention days must be at least 1")
    return (now - dt.timedelta(days=days)).timestamp()


def stale_files(root: Path, cutoff_timestamp: float) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*") if path.is_file() and path.stat().st_mtime < cutoff_timestamp)


def remove_empty_dirs(root: Path, apply: bool) -> list[str]:
    removed: list[str] = []
    if not root.exists():
        return removed
    for path in sorted((item for item in root.rglob("*") if item.is_dir()), reverse=True):
        try:
            next(path.iterdir())
        except StopIteration:
            removed.append(str(path))
            if apply:
                path.rmdir()
    return removed


def cleanup_tree(root: Path, retention_days: int, now: dt.datetime, apply: bool) -> dict[str, Any]:
    root = validate_runtime_path(root)
    cutoff = cutoff_for(retention_days, now)
    files = stale_files(root, cutoff)
    deleted_bytes = sum(path.stat().st_size for path in files)
    deleted = [str(path) for path in files]
    if apply:
        for path in files:
            path.unlink(missing_ok=True)
    empty_dirs = remove_empty_dirs(root, apply)
    return {
        "root": str(root),
        "retention_days": retention_days,
        "matched_files": len(files),
        "matched_bytes": deleted_bytes,
        "files": deleted,
        "empty_dirs": empty_dirs,
    }


def run(args: argparse.Namespace, now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or utc_now()
    artifact = cleanup_tree(args.artifact_dir, args.artifact_retention_days, now, args.apply)
    analysis = cleanup_tree(args.analysis_dir, args.analysis_retention_days, now, args.apply)
    return {
        "ok": True,
        "mode": "apply" if args.apply else "dry-run",
        "generated_at": project_now(),
        "artifact_cleanup": artifact,
        "analysis_cleanup": analysis,
    }


def main() -> int:
    args = parse_args()
    try:
        result = run(args)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
