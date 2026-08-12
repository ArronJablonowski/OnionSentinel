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
import sqlite3
import sys
from pathlib import Path
from typing import Any

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from pcap_lifecycle import analysis_completed, delete_request_artifacts


HOME = Path.home()
DEFAULT_ARTIFACT_DIR = HOME / "n8n-local" / "pcap-evidence" / "artifacts"
DEFAULT_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_ARTIFACT_RETENTION_DAYS = 14
DEFAULT_ANALYSIS_RETENTION_DAYS = 30


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Clean old Onion Sentinel PCAP runtime artifacts")
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--artifact-retention-days", type=int, default=DEFAULT_ARTIFACT_RETENTION_DAYS)
    parser.add_argument("--analysis-retention-days", type=int, default=DEFAULT_ANALYSIS_RETENTION_DAYS)
    parser.add_argument("--apply", action="store_true", help="Delete matched files. Omit for dry-run.")
    parser.add_argument("--analyzed-only", action="store_true", help="Only remove raw request directories with validated Zeek and TShark analysis")
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


def _completed_analysis_request_ids(analysis_root: Path):
    if not analysis_root.exists():
        return
    for path in sorted(analysis_root.glob("*-pcap-analysis.json")):
        try:
            analysis = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        request = analysis.get("request") if isinstance(analysis, dict) else None
        request_id = request.get("request_id") if isinstance(request, dict) else None
        if request_id and analysis_completed(analysis):
            yield request_id


def _request_artifact_match(
    artifact_root: Path, request_id: object, apply: bool,
) -> dict[str, Any] | None:
    target = (artifact_root / str(request_id)).resolve()
    if target.parent != artifact_root or not target.is_dir():
        return None
    files = [item for item in target.rglob("*") if item.is_file()]
    match = {
        "request_id": str(request_id),
        "bytes": sum(item.stat().st_size for item in files),
        "files": len(files),
    }
    if apply:
        match.update(delete_request_artifacts(artifact_root, request_id))
    return match


def _request_cleanup_projection(
    artifact_root: Path, request_ids, apply: bool,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for request_id in request_ids:
        try:
            match = _request_artifact_match(artifact_root, request_id, apply)
            if match is not None:
                matches.append(match)
        except (OSError, ValueError):
            continue
    return {
        "matched_requests": len(matches),
        "matched_bytes": sum(int(item.get("bytes") or 0) for item in matches),
        "requests": matches,
    }


def cleanup_analyzed_artifacts(artifact_dir: Path, analysis_dir: Path, apply: bool) -> dict[str, Any]:
    """Remove historical raw artifacts only when durable dual-parser evidence exists."""
    artifact_root = validate_runtime_path(artifact_dir)
    analysis_root = validate_runtime_path(analysis_dir)
    return _request_cleanup_projection(
        artifact_root,
        _completed_analysis_request_ids(analysis_root),
        apply,
    )


def cleanup_terminal_artifacts(artifact_dir: Path, db_path: Path, apply: bool) -> dict[str, Any]:
    """Remove artifacts that cannot participate in any future successful parse."""
    artifact_root = validate_runtime_path(artifact_dir)
    if not db_path.exists():
        return {"matched_requests": 0, "matched_bytes": 0, "requests": [], "reason": "database not found"}
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            """
            SELECT request_id
            FROM pcap_requests
            WHERE status IN ('failed', 'rejected')
              AND outcome IN ('no_packets_available', 'expired', 'oversize')
            """
        ).fetchall()
    finally:
        conn.close()
    return _request_cleanup_projection(
        artifact_root,
        (request_id for (request_id,) in rows),
        apply,
    )


def run(args: argparse.Namespace, now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or utc_now()
    analyzed = cleanup_analyzed_artifacts(args.artifact_dir, args.analysis_dir, args.apply)
    terminal = cleanup_terminal_artifacts(args.artifact_dir, getattr(args, "db", DEFAULT_DB), args.apply)
    if getattr(args, "analyzed_only", False):
        artifact = {"skipped": True, "reason": "analyzed-only mode"}
        analysis = {"skipped": True, "reason": "analyzed-only mode"}
    else:
        artifact = cleanup_tree(args.artifact_dir, args.artifact_retention_days, now, args.apply)
        analysis = cleanup_tree(args.analysis_dir, args.analysis_retention_days, now, args.apply)
    return {
        "ok": True,
        "mode": "apply" if args.apply else "dry-run",
        "generated_at": project_now(),
        "analyzed_artifact_cleanup": analyzed,
        "terminal_artifact_cleanup": terminal,
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
