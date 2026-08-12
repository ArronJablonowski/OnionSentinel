#!/usr/bin/env python3
"""Diagnose stale Onion Sentinel AI prompt and queue state.

The scheduler and dashboard both infer AI state from prompt packages, analysis
artifacts, PCAP evidence, and SQLite group state. This command gives operators a
single read-only view of that contract, with an optional cleanup mode for prompt
packages that are already superseded by newer group analysis.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from typing import Any


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
ALLOWED_FILTER_STATUSES = {"accepted", "acknowledged", "duplicate", "escalated", "suppressed", "unknown"}
__DELETE_ERROR_MAX_CHARS = 240


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check AI prompt, analysis, and grouped alert queue consistency")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to alert-store SQLite database")
    parser.add_argument("--prompt-dir", type=Path, default=DEFAULT_PROMPT_DIR, help="Directory containing *-ai-prompt.json")
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR, help="Directory containing local AI analysis JSON")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument("--fail-on-issue", action="store_true", help="Exit non-zero when stale/orphan/missing state is found")
    parser.add_argument(
        "--delete-resolved-prompts",
        action="store_true",
        help="Delete prompt packages that are older than current group analysis",
    )
    parser.add_argument(
        "--delete-orphan-prompts",
        action="store_true",
        help="Delete prompt packages whose primary/group alert IDs are no longer present in SQLite",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def iter_alert_ids(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        alert_id = value.get("alert_id")
        if alert_id:
            found.add(str(alert_id))
        for child in value.values():
            found.update(iter_alert_ids(child))
    elif isinstance(value, list):
        for child in value:
            found.update(iter_alert_ids(child))
    return found


def prompt_alert_ids(payload: dict[str, Any]) -> set[str]:
    """Return the primary/group alert IDs that determine queue freshness."""
    found: set[str] = set()
    alert = payload.get("alert")
    if isinstance(alert, dict) and alert.get("alert_id"):
        found.add(str(alert["alert_id"]))
    grouped = payload.get("grouped_alert_context")
    if isinstance(grouped, dict):
        timeline = grouped.get("timeline_sample")
        if isinstance(timeline, list):
            for item in timeline:
                if isinstance(item, dict) and item.get("alert_id"):
                    found.add(str(item["alert_id"]))
    return found or iter_alert_ids(payload)


def group_key(row: sqlite3.Row) -> str:
    suppression_key = str(row["suppression_key"] or "").strip()
    if suppression_key:
        return suppression_key
    return "|".join(
        [
            str(row["triage_level"] or ""),
            str(row["rule_name"] or ""),
            str(row["source_ip"] or ""),
            str(row["destination_ip"] or ""),
            str(row["filter_status"] or "accepted"),
        ]
    )


def db_state(conn: sqlite3.Connection) -> tuple[dict[str, Any], dict[str, str], dict[str, set[str]]]:
    conn.row_factory = sqlite3.Row
    quick_check = conn.execute("PRAGMA quick_check").fetchone()[0]
    alert_rows = conn.execute(
        """
        SELECT alert_id, triage_level, rule_name, source_ip, destination_ip,
               COALESCE(NULLIF(filter_status, ''), 'accepted') AS filter_status,
               suppression_key
        FROM alerts
        """
    ).fetchall()
    alert_to_group: dict[str, str] = {}
    group_members: dict[str, set[str]] = {}
    bad_alert_filters = 0
    for row in alert_rows:
        status = str(row["filter_status"] or "accepted")
        if status not in ALLOWED_FILTER_STATUSES:
            bad_alert_filters += 1
        key = group_key(row)
        alert_to_group[str(row["alert_id"])] = key
        group_members.setdefault(key, set()).add(str(row["alert_id"]))

    bad_summary_filters = conn.execute(
        """
        SELECT COUNT(*)
        FROM alert_group_summary
        WHERE COALESCE(NULLIF(filter_status, ''), 'accepted') NOT IN
          ('accepted', 'acknowledged', 'duplicate', 'escalated', 'suppressed', 'unknown')
        """
    ).fetchone()[0]
    summary_keys = {
        str(row[0])
        for row in conn.execute("SELECT group_key FROM alert_group_summary WHERE group_key IS NOT NULL").fetchall()
    }
    alert_keys = set(group_members)
    state = {
        "quick_check": quick_check,
        "alert_rows": len(alert_rows),
        "alert_groups": len(alert_keys),
        "summary_groups": len(summary_keys),
        "bad_alert_filters": bad_alert_filters,
        "bad_summary_filters": bad_summary_filters,
        "orphan_summaries": len(summary_keys - alert_keys),
        "missing_summaries": len(alert_keys - summary_keys),
    }
    return state, alert_to_group, group_members


def artifact_index(directory: Path, suffix: str, prompt_mode: bool = False) -> tuple[dict[str, float], dict[Path, set[str]]]:
    latest: dict[str, float] = {}
    path_ids: dict[Path, set[str]] = {}
    for path in sorted(directory.glob(f"*{suffix}")) if directory.exists() else []:
        payload = load_json(path)
        if not payload:
            continue
        ids = prompt_alert_ids(payload) if prompt_mode else iter_alert_ids(payload)
        if not ids:
            continue
        path_ids[path] = ids
        mtime = path.stat().st_mtime
        for alert_id in ids:
            latest[alert_id] = max(latest.get(alert_id, 0), mtime)
    return latest, path_ids


def __delete_prompt_paths(
    prompt_paths: list[str],
    stale_prompts: list[dict[str, Any]],
    deleted_prompts: list[str],
) -> None:
    for prompt_path in prompt_paths:
        path = Path(prompt_path)
        try:
            path.unlink()
            deleted_prompts.append(prompt_path)
        except OSError as exc:
            stale_prompts.append(
                {
                    "path": prompt_path,
                    "delete_error": str(exc)[:__DELETE_ERROR_MAX_CHARS],
                }
            )


def __print_stale_prompt(item: dict[str, Any]) -> None:
    if "delete_error" in item:
        print(
            f"DELETE_ERROR {item['path']} "
            f"error={item['delete_error']}"
        )
        return
    print(f"STALE {item['path']} alert_ids={','.join(item['alert_ids'])}")


def main() -> int:
    args = parse_args()
    if not args.db.exists():
        print(f"ERROR db not found: {args.db}", file=sys.stderr)
        return 2

    with closing(sqlite3.connect(args.db)) as conn:
        state, alert_to_group, group_members = db_state(conn)
    analysis_mtimes, _analysis_paths = artifact_index(args.analysis_dir, ".json")
    prompt_mtimes, prompt_paths = artifact_index(args.prompt_dir, "-ai-prompt.json", prompt_mode=True)

    stale_prompts: list[dict[str, Any]] = []
    resolved_prompts: list[str] = []
    orphan_prompts: list[str] = []
    for path, alert_ids in prompt_paths.items():
        prompt_mtime = path.stat().st_mtime
        known_ids = [alert_id for alert_id in alert_ids if alert_id in alert_to_group]
        if not known_ids:
            orphan_prompts.append(str(path))
            continue
        group_ids: set[str] = set()
        for alert_id in known_ids:
            group_ids.update(group_members.get(alert_to_group[alert_id], {alert_id}))
        latest_group_analysis = max((analysis_mtimes.get(alert_id, 0) for alert_id in group_ids), default=0)
        if prompt_mtime > latest_group_analysis:
            stale_prompts.append(
                {
                    "path": str(path),
                    "alert_ids": sorted(known_ids),
                    "group_size": len(group_ids),
                    "prompt_mtime": prompt_mtime,
                    "latest_group_analysis_mtime": latest_group_analysis,
                }
            )
        else:
            resolved_prompts.append(str(path))

    deleted_prompts: list[str] = []
    if args.delete_resolved_prompts:
        __delete_prompt_paths(
            resolved_prompts,
            stale_prompts,
            deleted_prompts,
        )
    if args.delete_orphan_prompts:
        __delete_prompt_paths(
            orphan_prompts,
            stale_prompts,
            deleted_prompts,
        )

    result = {
        "db": state,
        "artifacts": {
            "prompt_packages": len(prompt_paths),
            "analysis_alert_ids": len(analysis_mtimes),
            "stale_prompts": len(stale_prompts),
            "resolved_prompts": len(resolved_prompts),
            "orphan_prompts": len(orphan_prompts),
            "deleted_resolved_prompts": len(deleted_prompts),
        },
        "stale_prompts": stale_prompts,
        "orphan_prompts": orphan_prompts,
        "deleted_resolved_prompts": deleted_prompts,
    }
    issues = [
        state["quick_check"] != "ok",
        state["bad_alert_filters"],
        state["bad_summary_filters"],
        state["orphan_summaries"],
        state["missing_summaries"],
        stale_prompts,
        orphan_prompts,
    ]
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"quick_check: {state['quick_check']}")
        print(
            "groups: "
            f"alerts={state['alert_groups']} summary={state['summary_groups']} "
            f"missing={state['missing_summaries']} orphan={state['orphan_summaries']}"
        )
        print(
            "filters: "
            f"bad_alert_filters={state['bad_alert_filters']} "
            f"bad_summary_filters={state['bad_summary_filters']}"
        )
        print(
            "ai prompts: "
            f"prompt_packages={len(prompt_paths)} stale={len(stale_prompts)} "
            f"resolved={len(resolved_prompts)} orphan={len(orphan_prompts)}"
        )
        if deleted_prompts:
            print(f"deleted_resolved_prompts: {len(deleted_prompts)}")
        for item in stale_prompts[:20]:
            __print_stale_prompt(item)
        for path in orphan_prompts[:20]:
            print(f"ORPHAN {path}")
    return 1 if args.fail_on_issue and any(issues) else 0


if __name__ == "__main__":
    raise SystemExit(main())
