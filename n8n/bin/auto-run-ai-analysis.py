#!/usr/bin/env python3
"""Automatically analyze the next eligible SOC alert with local Ollama.

This wrapper is intended for launchd. It processes a small bounded batch per
run, holds a lock so two model jobs do not overlap, skips grouped detections
that already have analysis JSON, and reuses the existing prompt builder plus
local analysis runner.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_PCAP_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_LOCK = HOME / "n8n-local" / "run" / "ai-analysis.lock"
DEFAULT_PORTAL_BUILDER = HOME / ".hermes" / "scripts" / "build_soc_alerts_dashboard.py"
DEFAULT_PORTAL_SYNC = HOME / "n8n-local" / "bin" / "sync-soc-alerts-portal.py"
DEFAULT_SOC_WEB_DIR = HOME / "SOC Alerts Web"
DEFAULT_SOC_PORTAL_DIR = HOME / "report_portal" / "library" / "Cybersecurity" / "SOC Alerts"
DEFAULT_MODEL = os.environ.get("SOC_AI_MODEL", "")
DEFAULT_LEVELS = "critical,high,medium,low,informational"
SEVERITY_PRIORITY = ("critical", "high", "medium", "low", "informational")
ELIGIBLE_FILTER_STATUSES = ("accepted", "escalated", "unknown", "suppressed")
TEST_PREFIXES = ("phase%", "config-%", "internal-test-%", "sqlite-%", "policy-%", "codex-%")


def alert_time_sql() -> str:
    """Return the newest usable alert timestamp expression for queue priority."""
    return "COALESCE(NULLIF(last_seen, ''), NULLIF(timestamp, ''), NULLIF(first_seen, ''))"


def alert_group_key_sql() -> str:
    """Return SQL for the same duplicate-group key used by the dashboard."""
    return (
        "COALESCE(NULLIF(suppression_key, ''), "
        "COALESCE(triage_level, '') || '|' || "
        "COALESCE(rule_name, '') || '|' || "
        "COALESCE(source_ip, '') || '|' || "
        "COALESCE(destination_ip, '') || '|' || "
        "COALESCE(NULLIF(filter_status, ''), 'accepted'))"
    )


def severity_priority_sql(column: str = "triage_level") -> str:
    """Return SQL that drains each severity bucket before moving lower.

    Policy: no High alert is selected while any eligible Critical group remains;
    no Medium alert is selected while any eligible Critical or High group
    remains; and so on. Inside each severity bucket, newest alerts go first.
    """
    cases = "\n            ".join(
        f"WHEN '{level}' THEN {index}"
        for index, level in enumerate(SEVERITY_PRIORITY, start=1)
    )
    return f"CASE {column}\n            {cases}\n            ELSE {len(SEVERITY_PRIORITY) + 1}\n          END"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze the next eligible SOC alert using local AI")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to alert-store SQLite DB")
    parser.add_argument("--prompt-dir", type=Path, default=DEFAULT_PROMPT_DIR, help="Prompt package directory")
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_ANALYSIS_DIR, help="AI analysis output directory")
    parser.add_argument("--pcap-analysis-dir", type=Path, default=DEFAULT_PCAP_ANALYSIS_DIR, help="Parsed PCAP evidence directory")
    parser.add_argument("--lock-file", type=Path, default=DEFAULT_LOCK, help="Non-overlap lock file")
    parser.add_argument("--levels", default=DEFAULT_LEVELS, help="Comma-separated triage levels to analyze")
    parser.add_argument("--hours", type=int, default=87600, help="Lookback window for eligible alerts")
    parser.add_argument("--max-per-run", type=int, default=0, help="Maximum unique alert groups to analyze per scheduler run; 0 drains the queue until no eligible alerts remain")
    parser.add_argument("--related-limit", type=int, default=8, help="Related alert count passed to prompt builder")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Optional Ollama model override; defaults to Settings page AI model routing config")
    parser.add_argument("--timeout", type=int, default=240, help="Ollama request timeout in seconds")
    parser.add_argument("--portal-builder", type=Path, default=DEFAULT_PORTAL_BUILDER, help="Dashboard builder to run after successful analysis")
    parser.add_argument("--portal-sync", type=Path, default=DEFAULT_PORTAL_SYNC, help="Dashboard sync script to run after successful analysis")
    parser.add_argument("--no-portal-refresh", action="store_true", help="Do not rebuild/sync the SOC portal after analysis")
    parser.add_argument("--include-tests", action="store_true", help="Allow test/validation alert IDs")
    parser.add_argument("--dry-run", action="store_true", help="Print the selected alert without calling Ollama")
    args = parser.parse_args()
    if args.hours <= 0:
        parser.error("--hours must be positive")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.max_per_run < 0:
        parser.error("--max-per-run must be zero or positive")
    return args


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def test_filter_sql() -> tuple[str, list[object]]:
    clauses = []
    params: list[object] = []
    for pattern in TEST_PREFIXES:
        clauses.append("alert_id NOT LIKE ?")
        params.append(pattern)
    return " AND ".join(clauses), params


def latest_analysis_mtimes(analysis_dir: Path) -> dict[str, float]:
    latest: dict[str, float] = {}
    if not analysis_dir.exists():
        return latest
    for path in analysis_dir.glob("*-local-ai-analysis.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert_id = str(data.get("alert_id") or "").strip()
        if alert_id:
            latest[alert_id] = max(latest.get(alert_id, 0), path.stat().st_mtime)
    return latest


def latest_pcap_analysis_mtimes(pcap_analysis_dir: Path) -> dict[str, float]:
    latest: dict[str, float] = {}
    if not pcap_analysis_dir.exists():
        return latest
    for path in pcap_analysis_dir.glob("*-pcap-analysis.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        alert_id = str(request.get("alert_id") or data.get("alert_id") or "").strip()
        if alert_id:
            latest[alert_id] = max(latest.get(alert_id, 0), path.stat().st_mtime)
    return latest


def latest_pcap_group_mtimes(pcap_analysis_dir: Path) -> dict[str, float]:
    """Return newest parsed PCAP evidence time keyed by grouped detection id."""
    latest: dict[str, float] = {}
    if not pcap_analysis_dir.exists():
        return latest
    for path in pcap_analysis_dir.glob("*-pcap-analysis.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        group_id = str(request.get("group_id") or "").strip()
        if group_id:
            latest[group_id] = max(latest.get(group_id, 0), path.stat().st_mtime)
    return latest


def latest_prompt_mtimes(prompt_dir: Path) -> dict[str, float]:
    latest: dict[str, float] = {}
    if not prompt_dir.exists():
        return latest
    for path in prompt_dir.glob("*-ai-prompt.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
        alert_id = str(alert.get("alert_id") or data.get("alert_id") or "").strip()
        if alert_id:
            latest[alert_id] = max(latest.get(alert_id, 0), path.stat().st_mtime)
    return latest


def alert_group_key_from_mapping(alert: dict) -> str:
    """Return the scheduler duplicate-group key for prompt-package alert data."""
    suppression_key = str(alert.get("suppression_key") or "").strip()
    if suppression_key:
        return suppression_key
    return "|".join(
        [
            str(alert.get("triage_level") or ""),
            str(alert.get("rule_name") or ""),
            str(alert.get("source_ip") or ""),
            str(alert.get("destination_ip") or ""),
            str(alert.get("filter_status") or "accepted"),
        ]
    )


def latest_prompt_group_mtimes(conn: sqlite3.Connection, prompt_dir: Path) -> dict[str, float]:
    """Return newest AI prompt time keyed by the live DB duplicate group.

    Prompt packages are immutable queue artifacts, but duplicate-group fields can
    be repaired or normalized later in SQLite. Resolve prompt alert IDs through
    the current DB so manual reanalysis uses the same group key as selection.
    """
    prompt_mtimes = latest_prompt_mtimes(prompt_dir)
    latest: dict[str, float] = {}
    if not prompt_mtimes:
        return latest
    placeholders = ", ".join("?" for _ in prompt_mtimes)
    prompt_rows = rows(
        conn,
        f"""
        SELECT alert_id, suppression_key, triage_level, rule_name, source_ip,
               destination_ip, filter_status
        FROM alerts
        WHERE alert_id IN ({placeholders})
        """,
        sorted(prompt_mtimes),
    )
    db_prompt_ids: set[str] = set()
    for row in prompt_rows:
        alert_id = str(row["alert_id"] or "").strip()
        db_prompt_ids.add(alert_id)
        group_key = alert_group_key(row)
        latest[group_key] = max(latest.get(group_key, 0), prompt_mtimes.get(alert_id, 0))

    # Fallback for prompt packages whose source alert has been aged out of the
    # DB. These cannot make the scheduler select work, but retaining the mapping
    # keeps diagnostics deterministic.
    if not prompt_dir.exists():
        return latest
    for path in prompt_dir.glob("*-ai-prompt.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
        alert_id = str(alert.get("alert_id") or data.get("alert_id") or "").strip()
        if alert_id in db_prompt_ids:
            continue
        group_key = alert_group_key_from_mapping(alert)
        if group_key:
            latest[group_key] = max(latest.get(group_key, 0), path.stat().st_mtime)
    return latest


def analyzed_alert_ids(analysis_dir: Path, pcap_analysis_dir: Path | None = None, prompt_dir: Path | None = None) -> set[str]:
    """Return analyzed alert ids, excluding AI artifacts stale versus PCAP or manual requeue prompts."""
    ai_mtimes = latest_analysis_mtimes(analysis_dir)
    prompt_mtimes = latest_prompt_mtimes(prompt_dir) if prompt_dir else {}
    if not pcap_analysis_dir:
        return {alert_id for alert_id, ai_mtime in ai_mtimes.items() if prompt_mtimes.get(alert_id, 0) <= ai_mtime}
    pcap_mtimes = latest_pcap_analysis_mtimes(pcap_analysis_dir)
    return {
        alert_id
        for alert_id, ai_mtime in ai_mtimes.items()
        if pcap_mtimes.get(alert_id, 0) <= ai_mtime and prompt_mtimes.get(alert_id, 0) <= ai_mtime
    }


def alert_group_key(row: sqlite3.Row) -> str:
    """Return the same duplicate-group key used by the SOC dashboard."""
    suppression_key = str(row["suppression_key"] or "").strip() if "suppression_key" in row.keys() else ""
    if suppression_key:
        return suppression_key
    filter_status = str(row["filter_status"] or "accepted")
    return "|".join(
        [
            str(row["triage_level"] or ""),
            str(row["rule_name"] or ""),
            str(row["source_ip"] or ""),
            str(row["destination_ip"] or ""),
            filter_status,
        ]
    )


def alert_group_id(group_key: str) -> str:
    return hashlib.sha1(group_key.encode("utf-8")).hexdigest()[:12]


def analyzed_alert_groups(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path | None = None,
    pcap_analysis_dir: Path | None = None,
    prompt_dir: Path | None = None,
) -> set[str]:
    """Map analyzed alert IDs back to grouped detections.

    The dashboard displays grouped duplicate detections, not every raw alert row.
    A group is complete only when its newest AI analysis is newer than both its
    newest parsed PCAP evidence and newest prompt package. That keeps duplicate
    suppression efficient while still honoring manual reanalysis requests.
    """
    if not analyzed_ids:
        return set()
    ai_mtimes = latest_analysis_mtimes(analysis_dir) if analysis_dir else {}
    pcap_group_mtimes = latest_pcap_group_mtimes(pcap_analysis_dir) if pcap_analysis_dir else {}
    prompt_group_mtimes = latest_prompt_group_mtimes(conn, prompt_dir) if prompt_dir else {}
    placeholders = ", ".join("?" for _ in analyzed_ids)
    analyzed_rows = rows(
        conn,
        f"""
        SELECT alert_id, suppression_key, triage_level, rule_name, source_ip,
               destination_ip, filter_status
        FROM alerts
        WHERE alert_id IN ({placeholders})
        """,
        sorted(analyzed_ids),
    )
    group_ai_mtimes: dict[str, float] = {}
    for row in analyzed_rows:
        group_key = alert_group_key(row)
        ai_mtime = ai_mtimes.get(str(row["alert_id"] or "").strip(), 0)
        group_ai_mtimes[group_key] = max(group_ai_mtimes.get(group_key, 0), ai_mtime)

    analyzed_groups: set[str] = set()
    for group_key, ai_mtime in group_ai_mtimes.items():
        group_pcap_mtime = pcap_group_mtimes.get(alert_group_id(group_key), 0)
        group_prompt_mtime = prompt_group_mtimes.get(group_key, 0)
        if group_pcap_mtime and ai_mtime and group_pcap_mtime > ai_mtime:
            continue
        if group_prompt_mtime and ai_mtime and group_prompt_mtime > ai_mtime:
            continue
        analyzed_groups.add(group_key)
    return analyzed_groups


def select_next_alert(
    conn: sqlite3.Connection,
    args: argparse.Namespace,
    already_analyzed: set[str],
    already_selected_groups: set[str] | None = None,
) -> sqlite3.Row | None:
    levels = [level.strip().lower() for level in args.levels.split(",") if level.strip()]
    if not levels:
        raise SystemExit("--levels must contain at least one level")
    since = (dt.datetime.now().astimezone() - dt.timedelta(hours=args.hours)).replace(microsecond=0).isoformat().replace("T", "  ")
    newest_alert_time = alert_time_sql()
    group_key_expr = alert_group_key_sql()
    filter_sql = ""
    filter_params: list[object] = []
    if not args.include_tests:
        filter_sql, filter_params = test_filter_sql()
        filter_sql = f"AND {filter_sql}"
    placeholders = ", ".join("?" for _ in levels)
    prompt_mtimes = latest_prompt_mtimes(args.prompt_dir) if getattr(args, "prompt_dir", None) else {}
    ai_mtimes = latest_analysis_mtimes(args.analysis_dir) if getattr(args, "analysis_dir", None) else {}
    prompt_override_ids = sorted(
        alert_id
        for alert_id, prompt_mtime in prompt_mtimes.items()
        if prompt_mtime > ai_mtimes.get(alert_id, 0)
    )
    prompt_override_sql = ""
    prompt_override_params: list[object] = []
    if prompt_override_ids:
        prompt_override_sql = f" OR alert_id IN ({', '.join('?' for _ in prompt_override_ids)})"
        prompt_override_params.extend(prompt_override_ids)
    analyzed_groups = analyzed_alert_groups(
        conn,
        already_analyzed,
        getattr(args, "analysis_dir", None),
        getattr(args, "pcap_analysis_dir", None),
        getattr(args, "prompt_dir", None),
    )
    skipped_groups = set(already_selected_groups or set())
    candidates = rows(
        conn,
        f"""
        WITH eligible AS (
          SELECT alert_id, first_seen, last_seen, timestamp, rule_name,
                 source_ip, destination_ip, triage_level, triage_score,
                 COALESCE(NULLIF(filter_status, ''), 'accepted') AS filter_status,
                 routing, suppression_key,
                 {newest_alert_time} AS queue_time,
                 replace(replace({newest_alert_time}, 'T', ' '), 'Z', '') AS queue_time_sort,
                 {group_key_expr} AS queue_group_key,
                 {severity_priority_sql()} AS severity_rank
          FROM alerts
          WHERE replace(replace({newest_alert_time}, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')
            AND triage_level IN ({placeholders})
            AND (
              COALESCE(NULLIF(filter_status, ''), 'accepted') IN ({", ".join("?" for _ in ELIGIBLE_FILTER_STATUSES)})
              {prompt_override_sql}
            )
            {filter_sql}
        ),
        ranked_groups AS (
          SELECT *,
                 ROW_NUMBER() OVER (
                   PARTITION BY queue_group_key
                   ORDER BY queue_time_sort DESC, COALESCE(triage_score, 0) DESC, alert_id DESC
                 ) AS group_row_rank
          FROM eligible
        )
        SELECT alert_id, first_seen, last_seen, timestamp, rule_name,
               source_ip, destination_ip, triage_level, triage_score,
               filter_status, routing, suppression_key, queue_time,
               queue_group_key
        FROM ranked_groups
        WHERE group_row_rank = 1
        ORDER BY severity_rank ASC, queue_time_sort DESC,
                 COALESCE(triage_score, 0) DESC, alert_id DESC
        """,
        [since, *levels, *ELIGIBLE_FILTER_STATUSES, *prompt_override_params, *filter_params],
    )
    for candidate in candidates:
        # SQLite has already reduced the raw alert stream to the newest row per
        # duplicate group and sorted those groups by strict severity drain
        # order. Python only filters groups already analyzed or selected during
        # this same continuous-drain run.
        group_key = candidate["queue_group_key"] or alert_group_key(candidate)
        if candidate["alert_id"] not in already_analyzed and group_key not in analyzed_groups and group_key not in skipped_groups:
            return candidate
    return None


def latest_prompt_for_alert(prompt_dir: Path, alert_id: str) -> Path | None:
    if not prompt_dir.exists():
        return None
    matches: list[tuple[float, Path]] = []
    for path in prompt_dir.glob("*-ai-prompt.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        alert = data.get("alert") if isinstance(data.get("alert"), dict) else {}
        if alert.get("alert_id") == alert_id:
            matches.append((path.stat().st_mtime, path))
    if not matches:
        return None
    return sorted(matches)[-1][1]


def latest_pcap_evidence_mtime_for_alert(selected: sqlite3.Row, pcap_analysis_dir: Path) -> float:
    """Return newest parsed PCAP evidence mtime for the selected alert group."""
    if not pcap_analysis_dir.exists():
        return 0
    selected_alert_id = str(selected["alert_id"] or "").strip()
    selected_group_id = alert_group_id(str(selected["queue_group_key"] or alert_group_key(selected)))
    newest = 0.0
    for path in pcap_analysis_dir.glob("*-pcap-analysis.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        if str(request.get("alert_id") or "").strip() != selected_alert_id and str(request.get("group_id") or "").strip() != selected_group_id:
            continue
        newest = max(newest, path.stat().st_mtime)
    return newest


def reusable_prompt_for_alert(prompt_dir: Path, selected: sqlite3.Row, pcap_analysis_dir: Path) -> Path | None:
    """Return a prompt package only if it is current with parsed PCAP evidence."""
    prompt = latest_prompt_for_alert(prompt_dir, str(selected["alert_id"] or ""))
    if not prompt:
        return None
    pcap_mtime = latest_pcap_evidence_mtime_for_alert(selected, pcap_analysis_dir)
    if pcap_mtime and pcap_mtime > prompt.stat().st_mtime:
        return None
    return prompt


def run_command(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    print("running:", " ".join(cmd), flush=True)
    return subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def build_prompt(alert_id: str, args: argparse.Namespace) -> Path:
    builder = Path(__file__).with_name("build-ai-investigation-prompt.py")
    cmd = [
        sys.executable,
        str(builder),
        "--alert-id",
        alert_id,
        "--out-dir",
        str(args.prompt_dir),
        "--related-limit",
        str(args.related_limit),
    ]
    if args.include_tests:
        cmd.append("--include-tests")
    proc = run_command(cmd)
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        raise SystemExit(f"prompt builder failed rc={proc.returncode}")
    prompt_path = Path(proc.stdout.strip().splitlines()[-1])
    if not prompt_path.exists():
        raise SystemExit(f"prompt builder did not create a prompt package: {prompt_path}")
    return prompt_path


def analysis_command(prompt_path: Path, args: argparse.Namespace) -> list[str]:
    runner = Path(__file__).with_name("run-local-ai-analysis.py")
    cmd = [
        sys.executable,
        str(runner),
        "--prompt-package",
        str(prompt_path),
        "--out-dir",
        str(args.analysis_dir),
        "--timeout",
        str(args.timeout),
    ]
    if args.model:
        cmd.extend(["--model", args.model])
    return cmd


def run_analysis(prompt_path: Path, args: argparse.Namespace) -> subprocess.CompletedProcess[str]:
    cmd = analysis_command(prompt_path, args)
    return run_command(cmd)


def run_analysis_with_activity_refresh(prompt_path: Path, args: argparse.Namespace) -> subprocess.CompletedProcess[str]:
    cmd = analysis_command(prompt_path, args)
    print("running:", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Give the process table a moment to include run-local-ai-analysis.py with
    # its prompt package path, then rebuild the static dashboard while the job is
    # active so the SOC Alerts page can show its animated Analyzing metric.
    if not args.no_portal_refresh:
        time.sleep(1)
        refresh_portal(args)
    stdout, stderr = proc.communicate()
    return subprocess.CompletedProcess(cmd, proc.returncode, stdout, stderr)


def refresh_portal(args: argparse.Namespace) -> None:
    if args.no_portal_refresh:
        return
    for script in (args.portal_builder, args.portal_sync):
        if not script.exists():
            print(f"portal refresh skipped missing script: {script}", file=sys.stderr)
            return
    for script in (args.portal_builder, args.portal_sync):
        proc = run_command(["/usr/bin/python3", str(script)])
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        if proc.returncode != 0:
            print(f"portal refresh command failed rc={proc.returncode}: {script}", file=sys.stderr)
            if script == args.portal_sync:
                copy_soc_dashboard_fallback()
            return


def copy_soc_dashboard_fallback() -> None:
    """Keep the SOC dashboard fresh even if an unrelated portal builder fails."""
    if not DEFAULT_SOC_WEB_DIR.exists():
        print(f"SOC portal fallback skipped missing source: {DEFAULT_SOC_WEB_DIR}", file=sys.stderr)
        return
    DEFAULT_SOC_PORTAL_DIR.mkdir(parents=True, exist_ok=True)
    for item in DEFAULT_SOC_WEB_DIR.iterdir():
        destination = DEFAULT_SOC_PORTAL_DIR / item.name
        if item.is_dir():
            shutil.copytree(item, destination, dirs_exist_ok=True)
        elif item.is_file():
            shutil.copy2(item, destination)
    print(f"SOC portal fallback copied {DEFAULT_SOC_WEB_DIR} -> {DEFAULT_SOC_PORTAL_DIR}")


def main() -> int:
    args = parse_args()
    if not args.db.exists():
        print(f"{project_now()} SQLite DB not found: {args.db}", file=sys.stderr)
        return 2

    args.lock_file.parent.mkdir(parents=True, exist_ok=True)
    with args.lock_file.open("w") as lock_handle:
        try:
            fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"{project_now()} another AI analysis run is already active")
            return 0

        args.prompt_dir.mkdir(parents=True, exist_ok=True)
        args.analysis_dir.mkdir(parents=True, exist_ok=True)
        selected_groups: set[str] = set()
        analyzed_count = 0
        while args.max_per_run == 0 or analyzed_count < args.max_per_run:
            # Re-query before every selection so newly arrived higher-severity
            # alerts take priority over any lower-severity backlog.
            print(f"{project_now()} checking highest-priority unanalyzed alert queue", flush=True)
            conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                selected = select_next_alert(
                    conn,
                    args,
                    analyzed_alert_ids(args.analysis_dir, args.pcap_analysis_dir, args.prompt_dir),
                    selected_groups,
                )
            finally:
                conn.close()

            if not selected:
                if analyzed_count == 0:
                    print(f"{project_now()} no eligible unanalyzed alert found")
                break

            alert_id = selected["alert_id"]
            selected_groups.add(alert_group_key(selected))
            print(
                json.dumps(
                    {
                        "selected_alert_id": alert_id,
                        "rule_name": selected["rule_name"],
                        "triage_level": selected["triage_level"],
                        "triage_score": selected["triage_score"],
                        "last_seen": selected["last_seen"],
                        "queue_time": selected["queue_time"],
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            if args.dry_run:
                continue

            prompt_path = reusable_prompt_for_alert(args.prompt_dir, selected, args.pcap_analysis_dir) or build_prompt(alert_id, args)
            proc = run_analysis_with_activity_refresh(prompt_path, args)
            if proc.stdout:
                print(proc.stdout, end="")
            if proc.stderr:
                print(proc.stderr, file=sys.stderr, end="")
            if proc.returncode != 0:
                raise SystemExit(f"local AI analysis failed rc={proc.returncode}")
            analyzed_count += 1

        if analyzed_count:
            print(f"{project_now()} analyzed {analyzed_count} unique alert group(s)")
        refresh_portal(args)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
