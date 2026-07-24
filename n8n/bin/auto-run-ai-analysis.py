#!/usr/bin/env python3
"""Automatically analyze the next eligible SOC alert with its assigned model.

This wrapper is intended for launchd. Separate provider lanes allow hosted CLI
work to proceed while local Ollama inference is active. Each lane still holds
its own worker lock, while run-local-ai-analysis.py enforces a second host-wide
lock around every Ollama call so local models can never overlap.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import sqlite3
import urllib.error
import urllib.request
import sys
from pathlib import Path
from typing import Iterable

BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from disk_capacity import require_runtime_capacity
from bounded_http import BoundedHttpError, read_bounded_json
from bounded_process import BoundedProcessError, run_bounded_command


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_PROMPT_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_PCAP_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_INCIDENT_EVIDENCE_DIR = HOME / "n8n-local" / "soc-alerts" / "incident-evidence"
DEFAULT_INCIDENT_EVIDENCE_CONFIG = HOME / "n8n-local" / "config" / "incident-evidence.json"
DEFAULT_AI_SETTINGS = HOME / "n8n-local" / "config" / "ai_model_settings.json"
DEFAULT_LOCK = HOME / "n8n-local" / "run" / "ai-analysis.lock"
DEFAULT_WAKE = Path(os.environ.get(
    "AI_ANALYSIS_WAKE_PATH",
    HOME / "n8n-local" / "run" / "ai-analysis.wake",
))
DEFAULT_DASHBOARD_WAKE = Path(os.environ.get(
    "SOC_DASHBOARD_WAKE_PATH",
    HOME / "n8n-local" / "run" / "dashboard-refresh.wake",
))
DEFAULT_MODEL = os.environ.get("SOC_AI_MODEL", "")
DEFAULT_LEVELS = "critical,high,medium,low,informational"
SEVERITY_PRIORITY = ("critical", "high", "medium", "low", "informational")
ELIGIBLE_FILTER_STATUSES = ("accepted", "escalated", "unknown", "suppressed")
TEST_PREFIXES = ("phase%", "config-%", "internal-test-%", "sqlite-%", "policy-%", "codex-%")
DEFAULT_MAX_PROMPT_BYTES = max(256 * 1024, int(os.environ.get("SOC_AI_MAX_PROMPT_PACKAGE_BYTES", 4 * 1024 * 1024)))
DEFAULT_MAX_CHILD_STDOUT_BYTES = max(1024 * 1024, int(os.environ.get("SOC_AI_SCHEDULER_MAX_STDOUT_BYTES", 16 * 1024 * 1024)))
DEFAULT_MAX_CHILD_STDERR_BYTES = max(256 * 1024, int(os.environ.get("SOC_AI_SCHEDULER_MAX_STDERR_BYTES", 2 * 1024 * 1024)))
DEFAULT_MAX_CONTROL_RESPONSE_BYTES = 1024 * 1024
MAX_AI_SETTINGS_BYTES = 256 * 1024
CODEX_CLI_REASONING_EFFORTS = frozenset({"low", "medium", "high", "xhigh"})
CODEX_CLI_MODEL_CATALOG = frozenset({
    "gpt-5.5",
    "gpt-5.6-sol",
    "gpt-5.6-terra",
    "gpt-5.6-luna",
})
AGENT_ROLES = (
    "soc-analyst",
    "incident-responder",
    "siem-engineer",
    "cyber-threat-intel",
    "threat-hunter",
)


def alert_time_sql(alias: str = "") -> str:
    """Return the newest usable alert timestamp expression for queue priority."""
    prefix = f"{alias}." if alias else ""
    return (
        f"COALESCE(NULLIF({prefix}last_seen, ''), "
        f"NULLIF({prefix}timestamp, ''), NULLIF({prefix}first_seen, ''))"
    )


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
    parser.add_argument("--incident-evidence-dir", type=Path, default=DEFAULT_INCIDENT_EVIDENCE_DIR, help="Restricted Security Onion incident evidence directory")
    parser.add_argument("--incident-evidence-config", type=Path, default=DEFAULT_INCIDENT_EVIDENCE_CONFIG, help="Restricted relay evidence transport config")
    parser.add_argument("--ai-settings-file", type=Path, default=DEFAULT_AI_SETTINGS, help="AI model routing settings JSON")
    parser.add_argument(
        "--provider-lane",
        choices=("any", "ollama", "cli"),
        default="any",
        help="Only claim jobs assigned to this inference provider",
    )
    parser.add_argument("--lock-file", type=Path, default=DEFAULT_LOCK, help="Non-overlap lock file")
    parser.add_argument("--wake-file", type=Path, default=DEFAULT_WAKE, help="Consumable launchd wake marker")
    parser.add_argument("--levels", default=DEFAULT_LEVELS, help="Comma-separated triage levels to analyze")
    parser.add_argument("--hours", type=int, default=87600, help="Lookback window for eligible alerts")
    parser.add_argument("--max-per-run", type=int, default=0, help="Maximum unique alert groups to analyze per scheduler run; 0 drains the queue until no eligible alerts remain")
    parser.add_argument("--related-limit", type=int, default=8, help="Related alert count passed to prompt builder")
    parser.add_argument("--correlation-limit", type=int, default=8, help="Scored correlation candidates passed to prompt builder")
    parser.add_argument("--correlation-min-score", type=int, default=15, help="Minimum deterministic correlation score")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Optional Ollama model override; defaults to Settings page AI model routing config")
    parser.add_argument("--timeout", type=int, default=600, help="Ollama request timeout in seconds")
    parser.add_argument(
        "--max-prompt-bytes",
        type=int,
        default=DEFAULT_MAX_PROMPT_BYTES,
        help="Hard byte ceiling for each generated AI prompt package",
    )
    parser.add_argument("--portal-wake-file", type=Path, default=DEFAULT_DASHBOARD_WAKE, help="Wake file for the independent dashboard refresh worker")
    parser.add_argument("--no-portal-refresh", action="store_true", help="Do not signal the independent dashboard refresh worker")
    parser.add_argument("--alert-store-url", default=os.environ.get("ALERT_STORE_URL", "http://127.0.0.1:8787"), help="Alert-store URL for durable AI job status")
    parser.add_argument("--include-tests", action="store_true", help="Allow test/validation alert IDs")
    parser.add_argument("--dry-run", action="store_true", help="Print the selected alert without calling Ollama")
    args = parser.parse_args()
    if args.hours <= 0:
        parser.error("--hours must be positive")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if args.max_prompt_bytes < 256 * 1024:
        parser.error("--max-prompt-bytes must be at least 262144")
    if args.max_per_run < 0:
        parser.error("--max-per-run must be zero or positive")
    if args.correlation_limit <= 0:
        parser.error("--correlation-limit must be positive")
    if args.correlation_min_score < 0 or args.correlation_min_score > 100:
        parser.error("--correlation-min-score must be between 0 and 100")
    return args


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def cli_agent_roles(settings_path: Path) -> set[str]:
    """Return roles explicitly assigned to the hosted Codex/GPT CLI lane.

    Settings are treated as untrusted runtime input. A missing, oversized, or
    malformed file fails closed to the local lane so a configuration accident
    cannot unexpectedly send alert evidence to a hosted model.
    """
    try:
        if not settings_path.is_file() or settings_path.stat().st_size > MAX_AI_SETTINGS_BYTES:
            return set()
        raw = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return set()
    routes = raw.get("agent_models") if isinstance(raw, dict) else {}
    if not isinstance(routes, dict):
        return set()
    codex_models = raw.get("codex_cli_models", [])
    if not isinstance(codex_models, list):
        return set()
    enabled_codex_routes: set[str] = set()
    for entry in codex_models:
        if not isinstance(entry, dict) or entry.get("enabled") is not True:
            continue
        model = str(entry.get("model") or "").strip()
        effort = str(entry.get("reasoning_effort") or "").strip().lower()
        if (
            model in CODEX_CLI_MODEL_CATALOG
            and effort in CODEX_CLI_REASONING_EFFORTS
        ):
            enabled_codex_routes.add(f"codex-cli:{model}:{effort}")
    cli_roles: set[str] = set()
    for role in AGENT_ROLES:
        route = str(routes.get(role) or "").strip()
        if route.lower() in {"gpt-cli", "codex-cli"} or route in enabled_codex_routes:
            cli_roles.add(role)
    return cli_roles


def configured_analysis_levels(settings_path: Path, configured_levels: str) -> list[str]:
    """Return the launch allowlist constrained by the saved automatic AI floor.

    The scheduler argument remains a deployment-level ceiling. Settings can
    raise the floor at runtime without editing or reloading the launchd plist.
    Older settings files retain the historical all-severity analysis behavior
    until the operator explicitly saves the new control.
    """
    requested = [
        level.strip().lower()
        for level in str(configured_levels or "").split(",")
        if level.strip().lower() in SEVERITY_PRIORITY
    ]
    try:
        if not settings_path.is_file() or settings_path.stat().st_size > MAX_AI_SETTINGS_BYTES:
            raw = {}
        else:
            raw = json.loads(settings_path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raw = {}
    except (OSError, ValueError, TypeError):
        raw = {}
    threshold = str(
        raw.get("soc_analyst_analysis_min_severity", "informational") or ""
    ).strip().lower()
    if threshold == "info":
        threshold = "informational"
    if threshold == "disabled":
        return []
    if threshold not in SEVERITY_PRIORITY:
        threshold = "informational"
    highest_allowed_index = SEVERITY_PRIORITY.index(threshold)
    return [
        level
        for level in SEVERITY_PRIORITY[: highest_allowed_index + 1]
        if level in requested
    ]


def provider_lane_sql(args: argparse.Namespace) -> tuple[str, list[object]]:
    """Build an allowlisted SQL predicate for the selected provider lane."""
    provider_lane = str(getattr(args, "provider_lane", "any") or "any")
    if provider_lane == "any":
        return "", []
    cli_roles = sorted(cli_agent_roles(Path(getattr(args, "ai_settings_file", DEFAULT_AI_SETTINGS))))
    role_expr = """
      CASE
        WHEN p.id IS NULL THEN 'soc-analyst'
        WHEN json_valid(COALESCE(p.payload_json, '')) THEN
          COALESCE(
            NULLIF(TRIM(CAST(json_extract(p.payload_json, '$.agent_role') AS TEXT)), ''),
            CASE WHEN p.job_type = 'incident_response_analysis'
                 THEN 'incident-responder' ELSE 'soc-analyst' END
          )
        WHEN p.job_type = 'incident_response_analysis' THEN 'incident-responder'
        ELSE 'soc-analyst'
      END
    """
    if not cli_roles:
        return ("AND 0 = 1", []) if provider_lane == "cli" else ("", [])
    placeholders = ", ".join("?" for _ in cli_roles)
    operator = "IN" if provider_lane == "cli" else "NOT IN"
    return f"AND ({role_expr}) {operator} ({placeholders})", list(cli_roles)


def rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def report_ai_job_status(
    base_url: str,
    group_id: str,
    status: str,
    error: str = "",
    lease_token: str = "",
    job_type: str = "ai_analysis",
) -> bool | str:
    """Transition durable AI intent through a bounded local HTTP contract.

    Returning ``False`` only represents a rolling-deployment 404. Network,
    malformed-response, and oversized-response failures remain visible so the
    worker never performs expensive inference without a durable processing
    lease in the current indexed architecture.
    """
    payload = json.dumps({
        "job_type": job_type,
        "dedupe_key": group_id,
        "status": status,
        "error": error[:1000],
        "lease_token": lease_token,
    }).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/jobs/status",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status not in range(200, 300):
                raise RuntimeError(f"AI job status returned HTTP {response.status}")
            result = read_bounded_json(response, max_bytes=DEFAULT_MAX_CONTROL_RESPONSE_BYTES)
            if not result.get("ok", True):
                raise RuntimeError(str(result.get("reason") or "AI job status was rejected"))
            if status == "processing":
                claimed_token = str(result.get("lease_token") or "")
                if not claimed_token:
                    raise RuntimeError("AI job processing transition did not return a lease token")
                return claimed_token
            return True
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise RuntimeError(f"AI job status returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, BoundedHttpError) as exc:
        raise RuntimeError(f"AI job status request failed: {exc}") from exc


def reconcile_completed_ai_jobs(base_url: str, group_ids: set[str]) -> int:
    """Mark pending queue intent complete when current artifacts already satisfy it."""
    if not group_ids:
        return 0
    payload = json.dumps({
        "job_type": "ai_analysis",
        "dedupe_keys": sorted(group_ids),
    }).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/jobs/reconcile-completed",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            if response.status not in range(200, 300):
                raise RuntimeError(f"AI job reconciliation returned HTTP {response.status}")
            result = read_bounded_json(response, max_bytes=DEFAULT_MAX_CONTROL_RESPONSE_BYTES)
            return int(result.get("reconciled") or 0)
    except urllib.error.HTTPError as exc:
        # Older alert-store versions may not have the batch endpoint during a
        # rolling deployment. Analysis must continue and the next run retries.
        if exc.code == 404:
            return 0
        raise RuntimeError(f"AI job reconciliation returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, BoundedHttpError) as exc:
        raise RuntimeError(f"AI job reconciliation failed: {exc}") from exc


def test_filter_sql(column: str = "alert_id") -> tuple[str, list[object]]:
    clauses = []
    params: list[object] = []
    for pattern in TEST_PREFIXES:
        clauses.append(f"{column} NOT LIKE ?")
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


def completed_analysis_group_ids(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path,
    pcap_analysis_dir: Path,
    prompt_dir: Path,
) -> set[str]:
    """Return stable queue keys for groups whose analysis artifacts are current."""
    completed_keys = analyzed_alert_groups(
        conn,
        analyzed_ids,
        analysis_dir,
        pcap_analysis_dir,
        prompt_dir,
    )
    if not completed_keys or not analyzed_ids:
        return set()
    columns = {str(item[1]) for item in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    stable_select = "stable_group_id" if "stable_group_id" in columns else "NULL AS stable_group_id"
    placeholders = ", ".join("?" for _ in analyzed_ids)
    analyzed_rows = rows(
        conn,
        f"""
        SELECT alert_id, suppression_key, triage_level, rule_name, source_ip,
               destination_ip, filter_status, {stable_select}
        FROM alerts WHERE alert_id IN ({placeholders})
        """,
        sorted(analyzed_ids),
    )
    completed_ids: set[str] = set()
    for row in analyzed_rows:
        group_key = alert_group_key(row)
        if group_key not in completed_keys:
            continue
        stable_id = str(row["stable_group_id"] or "").strip()
        completed_ids.add(stable_id or alert_group_id(group_key))
    return completed_ids


def orphaned_pending_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Return pending AI queue keys that no longer map to an alert group.

    Stable group identities can be replaced when legacy rows are normalized or
    grouping policy changes. Those old durable intents are not actionable, but
    leaving them pending makes queue health report a worker stall forever.
    """
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "durable_jobs" not in tables:
        return set()
    pending_ids = {
        str(row[0] or "").strip()
        for row in conn.execute(
            "SELECT dedupe_key FROM durable_jobs WHERE job_type = 'ai_analysis' AND status = 'pending'"
        ).fetchall()
        if str(row[0] or "").strip()
    }
    if not pending_ids:
        return set()
    # alert_group_summary is the authoritative set of currently actionable
    # groups. Raw alert rows can retain superseded identities after a recovery
    # or grouping-policy migration, which otherwise leaves queue intents that
    # no scheduler selection can ever satisfy.
    active_ids = {
        str(row[0] or "").strip()
        for row in conn.execute("SELECT group_id FROM alert_group_summary").fetchall()
        if str(row[0] or "").strip()
    }
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "alert_group_alias" in tables:
        for legacy_id, stable_id in conn.execute(
            "SELECT legacy_group_id, stable_group_id FROM alert_group_alias"
        ).fetchall():
            # Summaries retain the legacy dashboard identifier while durable
            # AI jobs use the V2 stable identity. Follow the alias in that
            # direction so both forms remain actionable.
            if str(legacy_id or "").strip() in active_ids:
                active_ids.add(str(stable_id or "").strip())
    return pending_ids - active_ids


def pending_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Return coalesced durable AI intents that still require a model run."""
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "durable_jobs" not in tables:
        return set()
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            "SELECT dedupe_key FROM durable_jobs WHERE job_type = 'ai_analysis' AND status = 'pending'"
        ).fetchall()
        if str(row[0] or "").strip()
    }


def reconcilable_completed_ai_job_ids(conn: sqlite3.Connection, group_ids: set[str]) -> set[str]:
    """Keep artifact reconciliation from erasing newly queued evidence.

    A pending job is artifact-reconcilable only when a worker previously began
    processing it. Fresh alert, enrichment, and PCAP intents deliberately have
    no processing start and must reach the scheduler even when an older report
    artifact exists for the same duplicate group.
    """
    if not group_ids:
        return set()
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if "durable_jobs" not in tables:
        return set()
    columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(durable_jobs)").fetchall()}
    if "processing_started_at" not in columns or "rerun_requested" not in columns:
        return group_ids
    placeholders = ", ".join("?" for _ in group_ids)
    return {
        str(row[0] or "").strip()
        for row in conn.execute(
            f"""
            SELECT dedupe_key FROM durable_jobs
            WHERE job_type = 'ai_analysis' AND status = 'pending'
              AND COALESCE(rerun_requested, 0) = 0
              AND processing_started_at IS NOT NULL
              AND dedupe_key IN ({placeholders})
            """,
            sorted(group_ids),
        ).fetchall()
        if str(row[0] or "").strip()
    }


def reconcilable_ai_job_ids(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path,
    pcap_analysis_dir: Path,
    prompt_dir: Path,
) -> set[str]:
    """Combine artifact-complete and obsolete durable AI queue intents."""
    completed = completed_analysis_group_ids(
        conn,
        analyzed_ids,
        analysis_dir,
        pcap_analysis_dir,
        prompt_dir,
    )
    return reconcilable_completed_ai_job_ids(conn, completed) | orphaned_pending_ai_job_ids(conn)


def indexed_scheduler_available(conn: sqlite3.Connection) -> bool:
    """Return whether durable jobs and analysis results can drive scheduling."""
    tables = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    if not {"alerts", "durable_jobs", "ai_analysis_runs"}.issubset(tables):
        return False
    alert_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(alerts)")}
    job_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(durable_jobs)")}
    run_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(ai_analysis_runs)")}
    return {"stable_group_id", "stable_group_key"}.issubset(alert_columns) and {
        "id", "job_type", "dedupe_key", "status", "payload_json", "priority",
        "attempt_count", "max_attempts", "next_attempt_at", "processing_started_at",
        "rerun_requested", "requested_at",
    }.issubset(job_columns) and {"group_id", "generated_at"}.issubset(run_columns)


def indexed_reconcilable_ai_job_ids(conn: sqlite3.Connection) -> set[str]:
    """Find recovered jobs already satisfied by a committed analysis result.

    A job is never reconciled merely because an old analysis exists. The
    indexed run must be at least as new as the processing attempt that produced
    it, which preserves fresh alert, enrichment, PCAP, and manual rerun intent.
    """
    if not indexed_scheduler_available(conn):
        return set()
    completed = {
        str(row[0] or "").strip()
        for row in conn.execute(
            """
            SELECT j.dedupe_key
            FROM durable_jobs AS j
            WHERE j.job_type = 'ai_analysis' AND j.status = 'pending'
              AND COALESCE(j.rerun_requested, 0) = 0
              AND j.processing_started_at IS NOT NULL
              AND EXISTS (
                SELECT 1 FROM ai_analysis_runs AS r
                WHERE r.group_id = j.dedupe_key
                  AND julianday(replace(r.generated_at, '  ', 'T')) >=
                      julianday(replace(j.processing_started_at, '  ', 'T'))
              )
            """
        ).fetchall()
        if str(row[0] or "").strip()
    }
    orphaned = {
        str(row[0] or "").strip()
        for row in conn.execute(
            """
            SELECT j.dedupe_key
            FROM durable_jobs AS j
            WHERE j.job_type = 'ai_analysis' AND j.status = 'pending'
              AND NOT EXISTS (
                SELECT 1 FROM alerts AS a WHERE a.stable_group_id = j.dedupe_key
              )
            """
        ).fetchall()
        if str(row[0] or "").strip()
    }
    return completed | orphaned


def select_next_alert_indexed(
    conn: sqlite3.Connection,
    args: argparse.Namespace,
    already_selected_groups: set[str] | None = None,
) -> sqlite3.Row | None:
    """Select one group using only indexed SQLite state.

    Durable intent overrides age, suppression, test, and prior-analysis filters.
    Manual requests get their own priority bucket, then every bucket follows
    strict severity/newest ordering. Re-running this query before every model
    call preserves preemption when a more severe alert arrives mid-drain.
    """
    levels = [level.strip().lower() for level in args.levels.split(",") if level.strip()]
    if not levels:
        raise SystemExit("--levels must contain at least one level")
    since = (dt.datetime.now().astimezone() - dt.timedelta(hours=args.hours)).replace(
        microsecond=0,
    ).isoformat().replace("T", "  ")
    newest_alert_time = alert_time_sql("a")
    eligible_alert_time = alert_time_sql("eligible")
    level_placeholders = ", ".join("?" for _ in levels)
    test_sql = ""
    test_params: list[object] = []
    if not args.include_tests:
        clause, test_params = test_filter_sql("eligible.alert_id")
        test_sql = f"AND {clause}"
    run_columns = {
        str(row[1]) for row in conn.execute("PRAGMA table_info(ai_analysis_runs)")
    }
    run_role_sql = (
        "AND COALESCE(ar.agent_role, 'soc-analyst') = 'soc-analyst'"
        if "agent_role" in run_columns
        else ""
    )
    lane_sql, lane_params = provider_lane_sql(args)
    # Indexed groups are guarded by durable job state. Do not apply the legacy
    # per-process exclusion set: a request coalesced while inference is active
    # becomes a fresh pending job and should be eligible immediately.
    del already_selected_groups
    candidate = conn.execute(
        f"""
        WITH due_jobs_ranked AS (
          SELECT id, job_type, dedupe_key, payload_json, priority,
                 ROW_NUMBER() OVER (
                   PARTITION BY dedupe_key
                   ORDER BY CASE job_type WHEN 'incident_response_analysis' THEN 0 ELSE 1 END,
                            priority DESC, requested_at ASC, id ASC
                 ) AS job_rank
          FROM durable_jobs
          WHERE job_type IN ('incident_response_analysis', 'ai_analysis')
            AND status = 'pending'
            AND attempt_count < max_attempts
            AND julianday(replace(next_attempt_at, '  ', 'T')) <=
                julianday(replace(?, '  ', 'T'))
        ),
        due_jobs AS (
          SELECT id, job_type, dedupe_key, payload_json, priority
          FROM due_jobs_ranked WHERE job_rank = 1
        ),
        ranked AS (
          SELECT a.*,
                 {newest_alert_time} AS queue_time,
                 julianday(replace({newest_alert_time}, '  ', 'T')) AS queue_time_sort,
                 {severity_priority_sql('a.triage_level')} AS severity_rank,
                 ROW_NUMBER() OVER (
                   PARTITION BY a.stable_group_id
                   ORDER BY julianday(replace({newest_alert_time}, '  ', 'T')) DESC,
                            COALESCE(a.triage_score, 0) DESC, a.alert_id DESC
                 ) AS group_row_rank
          FROM alerts AS a
          WHERE a.stable_group_id IS NOT NULL AND a.stable_group_id != ''
        )
        SELECT r.alert_id, r.first_seen, r.last_seen, r.timestamp, r.rule_name,
               r.source_ip, r.destination_ip, r.triage_level, r.triage_score,
               COALESCE(NULLIF(r.filter_status, ''), 'accepted') AS filter_status,
               r.stable_group_id, r.routing, r.suppression_key, r.queue_time,
               COALESCE(NULLIF(r.stable_group_key, ''), r.stable_group_id) AS queue_group_key,
               p.payload_json AS durable_payload_json,
               p.job_type AS durable_job_type,
               CASE WHEN p.id IS NOT NULL THEN 1 ELSE 0 END AS has_durable_intent,
               CASE
                 WHEN p.job_type = 'incident_response_analysis' THEN 0
                 WHEN p.id IS NOT NULL
                   AND instr(replace(p.payload_json, ' ', ''), '"manual_reanalysis":true') > 0 THEN 0
                 WHEN p.id IS NOT NULL THEN 1
                 ELSE 2
               END AS request_bucket,
               r.severity_rank, r.queue_time_sort
        FROM ranked AS r
        LEFT JOIN due_jobs AS p ON p.dedupe_key = r.stable_group_id
        WHERE r.group_row_rank = 1
          AND (
            p.id IS NOT NULL
            OR (
              NOT EXISTS (
                SELECT 1 FROM durable_jobs AS existing
                WHERE existing.job_type = 'ai_analysis'
                  AND existing.dedupe_key = r.stable_group_id
                  AND existing.status != 'completed'
              )
              AND NOT EXISTS (
                SELECT 1 FROM ai_analysis_runs AS ar
                WHERE ar.group_id = r.stable_group_id
                  {run_role_sql}
              )
              AND EXISTS (
                SELECT 1 FROM alerts AS eligible
                WHERE eligible.stable_group_id = r.stable_group_id
                  AND julianday(replace({eligible_alert_time}, '  ', 'T')) >=
                      julianday(replace(?, '  ', 'T'))
                  AND eligible.triage_level IN ({level_placeholders})
                  AND COALESCE(NULLIF(eligible.filter_status, ''), 'accepted')
                      IN ({", ".join("?" for _ in ELIGIBLE_FILTER_STATUSES)})
                  {test_sql}
              )
            )
          )
          {lane_sql}
        ORDER BY request_bucket ASC, COALESCE(p.priority, 0) DESC,
                 severity_rank ASC, queue_time_sort DESC,
                 COALESCE(r.triage_score, 0) DESC, r.alert_id DESC
        LIMIT 1
        """,
        [project_now(), since, *levels, *ELIGIBLE_FILTER_STATUSES, *test_params, *lane_params],
    ).fetchone()
    return candidate


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
    pending_group_ids = pending_ai_job_ids(conn)
    skipped_groups = set(already_selected_groups or set())
    alert_columns = {str(item[1]) for item in conn.execute("PRAGMA table_info(alerts)").fetchall()}
    stable_group_select = "stable_group_id" if "stable_group_id" in alert_columns else "NULL AS stable_group_id"
    candidates = rows(
        conn,
        f"""
        WITH eligible AS (
          SELECT alert_id, first_seen, last_seen, timestamp, rule_name,
                 source_ip, destination_ip, triage_level, triage_score,
                 COALESCE(NULLIF(filter_status, ''), 'accepted') AS filter_status,
                 {stable_group_select},
                 routing, suppression_key,
                 {newest_alert_time} AS queue_time,
                 replace(replace({newest_alert_time}, 'T', ' '), 'Z', '') AS queue_time_sort,
                 {group_key_expr} AS queue_group_key,
                 {severity_priority_sql()} AS severity_rank
          FROM alerts
          WHERE (
              (
                replace(replace({newest_alert_time}, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')
                AND triage_level IN ({placeholders})
                AND COALESCE(NULLIF(filter_status, ''), 'accepted') IN ({", ".join("?" for _ in ELIGIBLE_FILTER_STATUSES)})
                {filter_sql}
              )
              {prompt_override_sql}
            )
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
               filter_status, stable_group_id, routing, suppression_key, queue_time,
               queue_group_key
        FROM ranked_groups
        WHERE group_row_rank = 1
        ORDER BY severity_rank ASC, queue_time_sort DESC,
                 COALESCE(triage_score, 0) DESC, alert_id DESC
        """,
        [since, *levels, *ELIGIBLE_FILTER_STATUSES, *filter_params, *prompt_override_params],
    )
    if prompt_override_ids:
        prompt_override_set = set(prompt_override_ids)
        # A manual Analyze click is an analyst-directed override. Keep the SQL
        # severity ordering inside manual/automatic buckets, but drain manual
        # prompts before unattended backlog so the UI action has immediate effect.
        candidates = sorted(
            candidates,
            key=lambda candidate: 0 if str(candidate["alert_id"] or "") in prompt_override_set else 1,
        )

    for candidate in candidates:
        # SQLite has already reduced the raw alert stream to the newest row per
        # duplicate group and sorted those groups by strict severity drain
        # order. Python only filters groups already analyzed or selected during
        # this same continuous-drain run.
        group_key = candidate["queue_group_key"] or alert_group_key(candidate)
        stable_id = str(candidate["stable_group_id"] or "").strip()
        queue_group_id = stable_id or alert_group_id(str(group_key))
        if group_key in skipped_groups:
            continue
        if queue_group_id in pending_group_ids:
            return candidate
        if candidate["alert_id"] not in already_analyzed and group_key not in analyzed_groups:
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


def durable_payload(selected: sqlite3.Row) -> dict[str, object]:
    """Decode trusted queue metadata without letting corruption alter limits."""
    if "durable_payload_json" not in selected.keys():
        return {}
    try:
        payload = json.loads(str(selected["durable_payload_json"] or "{}"))
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def bounded_int(value: object, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(maximum, parsed))


def run_command(
    cmd: list[str],
    *,
    timeout_seconds: float,
    max_stdout_bytes: int = DEFAULT_MAX_CHILD_STDOUT_BYTES,
    max_stderr_bytes: int = DEFAULT_MAX_CHILD_STDERR_BYTES,
    progress_callback=None,
    progress_interval_seconds: float = 30,
):
    """Run one trusted helper with bounded time, memory, and descendants."""
    print("running:", " ".join(cmd), flush=True)
    return run_bounded_command(
        cmd,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
        progress_callback=progress_callback,
        progress_interval_seconds=progress_interval_seconds,
    )


def collect_incident_evidence(alert_id: str, args: argparse.Namespace, *, progress_callback=None) -> Path:
    collector = Path(__file__).with_name("collect-incident-evidence.py")
    proc = run_command(
        [
            sys.executable,
            str(collector),
            "--alert-id",
            alert_id,
            "--db",
            str(args.db),
            "--config",
            str(args.incident_evidence_config),
            "--out-dir",
            str(args.incident_evidence_dir),
        ],
        timeout_seconds=360,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=DEFAULT_MAX_CHILD_STDERR_BYTES,
        progress_callback=progress_callback,
        progress_interval_seconds=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"incident evidence collector failed rc={proc.returncode}")
    output_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not output_lines:
        raise RuntimeError("incident evidence collector returned no artifact path")
    artifact = Path(output_lines[-1])
    try:
        artifact.resolve().relative_to(args.incident_evidence_dir.resolve())
    except ValueError as exc:
        raise RuntimeError("incident evidence collector returned a path outside its configured directory") from exc
    if not artifact.is_file():
        raise RuntimeError("incident evidence collector did not publish its artifact")
    return artifact


def build_prompt(
    alert_id: str,
    args: argparse.Namespace,
    job_payload: dict[str, object] | None = None,
    incident_evidence_path: Path | None = None,
) -> Path:
    builder = Path(__file__).with_name("build-ai-investigation-prompt.py")
    job_payload = job_payload or {}
    related_limit = bounded_int(job_payload.get("related_limit"), args.related_limit, 1, 500)
    pcap_analysis_limit = bounded_int(job_payload.get("pcap_analysis_limit"), 8, 1, 25)
    cmd = [
        sys.executable,
        str(builder),
        "--alert-id",
        alert_id,
        "--out-dir",
        str(args.prompt_dir),
        "--related-limit",
        str(related_limit),
        "--correlation-limit",
        str(args.correlation_limit),
        "--correlation-min-score",
        str(args.correlation_min_score),
        "--pcap-analysis-limit",
        str(pcap_analysis_limit),
        "--max-package-bytes",
        str(args.max_prompt_bytes),
        "--agent-role",
        str(job_payload.get("agent_role") or "soc-analyst"),
    ]
    if incident_evidence_path is not None:
        cmd.extend(["--incident-evidence-file", str(incident_evidence_path)])
    if args.include_tests:
        cmd.append("--include-tests")
    proc = run_command(
        cmd,
        timeout_seconds=180,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=DEFAULT_MAX_CHILD_STDERR_BYTES,
    )
    if proc.returncode != 0:
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, end="")
        raise RuntimeError(f"prompt builder failed rc={proc.returncode}")
    output_lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not output_lines:
        raise RuntimeError("prompt builder returned no output path")
    prompt_path = Path(output_lines[-1])
    if not prompt_path.exists():
        raise RuntimeError(f"prompt builder did not create a prompt package: {prompt_path}")
    try:
        prompt_path.resolve().relative_to(args.prompt_dir.resolve())
    except ValueError as exc:
        raise RuntimeError("prompt builder returned a path outside the configured prompt directory") from exc
    if prompt_path.stat().st_size > args.max_prompt_bytes:
        raise RuntimeError(f"prompt package exceeded the {args.max_prompt_bytes}-byte worker limit")
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
        "--alert-store-url",
        args.alert_store_url,
        "--ai-settings-file",
        str(args.ai_settings_file),
    ]
    if args.model:
        cmd.extend(["--model", args.model])
    return cmd


def run_analysis(prompt_path: Path, args: argparse.Namespace, *, progress_callback=None):
    cmd = analysis_command(prompt_path, args)
    return run_command(
        cmd,
        timeout_seconds=args.timeout + 120,
        max_stdout_bytes=DEFAULT_MAX_CHILD_STDOUT_BYTES,
        max_stderr_bytes=DEFAULT_MAX_CHILD_STDERR_BYTES,
        progress_callback=progress_callback,
        progress_interval_seconds=60,
    )


def flush_deferred_analysis_results(args: argparse.Namespace) -> None:
    """Publish locally spooled result indexes before scheduling new GPU work."""
    runner = Path(__file__).with_name("run-local-ai-analysis.py")
    proc = run_command(
        [
            sys.executable,
            str(runner),
            "--flush-index-only",
            "--alert-store-url",
            args.alert_store_url,
        ],
        timeout_seconds=60,
        max_stdout_bytes=1024 * 1024,
        max_stderr_bytes=1024 * 1024,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or f"rc={proc.returncode}"
        raise RuntimeError(f"deferred analysis index flush failed: {detail}")


def signal_dashboard_refresh(args: argparse.Namespace) -> None:
    """Wake the independent portal worker without delaying local inference.

    The Web UI polls fast-changing AI state from the API. Static dashboard
    generation is therefore eventual presentation work and must never sit on
    the alert-analysis critical path.
    """
    if args.no_portal_refresh:
        return
    try:
        args.portal_wake_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        args.portal_wake_file.write_text(f"{project_now()} ai-analysis-complete\n", encoding="utf-8")
        args.portal_wake_file.chmod(0o600)
    except OSError as error:
        # Durable AI completion remains authoritative even if presentation
        # refresh signaling is temporarily unavailable.
        print(f"dashboard refresh signal failed: {error}", file=sys.stderr)


def consume_wake_marker(path: Path) -> None:
    """Clear the event that launched this run so later work is not lost.

    If durable work arrives while the worker is active, alert-store recreates
    the marker. launchd then observes a pending path event and starts another
    pass after this process exits.
    """
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        print(f"AI wake marker could not be consumed: {error}", file=sys.stderr)


def reconcile_worker_state(args: argparse.Namespace, indexed_mode: bool) -> int:
    """Reconcile durable queue state without scanning artifacts in modern mode."""
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        if indexed_mode:
            completed_group_ids = indexed_reconcilable_ai_job_ids(conn)
        else:
            analyzed_ids = analyzed_alert_ids(args.analysis_dir, args.pcap_analysis_dir, args.prompt_dir)
            completed_group_ids = reconcilable_ai_job_ids(
                conn,
                analyzed_ids,
                args.analysis_dir,
                args.pcap_analysis_dir,
                args.prompt_dir,
            )
    finally:
        conn.close()
    return reconcile_completed_ai_jobs(args.alert_store_url, completed_group_ids)


def main() -> int:
    args = parse_args()
    launch_levels = args.levels
    require_runtime_capacity(args.analysis_dir, 0, label="AI analysis")
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

        consume_wake_marker(args.wake_file)
        args.prompt_dir.mkdir(parents=True, exist_ok=True)
        args.analysis_dir.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            indexed_mode = indexed_scheduler_available(conn)
        finally:
            conn.close()

        if not indexed_mode and args.provider_lane == "cli":
            # Legacy databases do not expose the durable job payload that owns
            # the agent role. A CLI worker therefore cannot prove that a job is
            # assigned to its privacy/cost boundary and must fail closed.
            print(
                f"{project_now()} CLI provider lane requires the indexed scheduler; no work claimed",
                flush=True,
            )
            return 0

        if indexed_mode:
            # A model result is first written atomically to local disk, then
            # indexed through alert-store. Publish any result left behind by a
            # transient callback failure before considering another inference.
            flush_deferred_analysis_results(args)
        reconciled = reconcile_worker_state(args, indexed_mode)
        if reconciled:
            print(f"{project_now()} reconciled {reconciled} completed durable AI job(s)", flush=True)
        selected_groups: set[str] = set()
        analyzed_count = 0
        attempted_count = 0
        while args.max_per_run == 0 or attempted_count < args.max_per_run:
            allowed_analysis_levels = configured_analysis_levels(
                args.ai_settings_file,
                launch_levels,
            )
            # A sentinel keeps the indexed query able to claim and retire
            # pre-upgrade automatic jobs while excluding every legacy
            # non-durable candidate when automation is disabled.
            args.levels = ",".join(allowed_analysis_levels or ["__disabled__"])
            # Re-query before every selection so newly arrived higher-severity
            # alerts take priority over any lower-severity backlog.
            print(f"{project_now()} checking highest-priority unanalyzed alert queue", flush=True)
            conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
            try:
                if indexed_mode:
                    selected = select_next_alert_indexed(conn, args, selected_groups)
                else:
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
            selected_group_id = str(selected["stable_group_id"] or "") if "stable_group_id" in selected.keys() else ""
            if not selected_group_id:
                selected_group_id = alert_group_id(str(selected["queue_group_key"] or alert_group_key(selected)))
            selected_groups.add(selected_group_id)
            selected_groups.add(str(selected["queue_group_key"] or alert_group_key(selected)))
            durable_job_type = (
                str(selected["durable_job_type"] or "ai_analysis")
                if "durable_job_type" in selected.keys()
                else "ai_analysis"
            )
            job_payload = durable_payload(selected)
            durable_intent = bool(
                selected["has_durable_intent"]
                if "has_durable_intent" in selected.keys()
                else False
            )
            automatic_analysis_below_floor = (
                indexed_mode
                and durable_intent
                and durable_job_type == "ai_analysis"
                and job_payload.get("manual_reanalysis") is not True
                and str(selected["triage_level"] or "").strip().lower()
                not in set(allowed_analysis_levels)
            )
            attempted_count += 1
            print(
                json.dumps(
                    {
                        "selected_alert_id": alert_id,
                        "rule_name": selected["rule_name"],
                        "triage_level": selected["triage_level"],
                        "triage_score": selected["triage_score"],
                        "last_seen": selected["last_seen"],
                        "queue_time": selected["queue_time"],
                        "job_type": durable_job_type,
                        "provider_lane": args.provider_lane,
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
            if args.dry_run:
                break

            processing_recorded = False
            processing_lease_token = ""
            try:
                processing_transition = report_ai_job_status(
                    args.alert_store_url,
                    selected_group_id,
                    "processing",
                    job_type=durable_job_type,
                )
                processing_recorded = bool(processing_transition)
                processing_lease_token = (
                    processing_transition if isinstance(processing_transition, str) else ""
                )
                if indexed_mode and durable_intent and not processing_recorded:
                    raise RuntimeError("durable AI job disappeared before its processing lease was recorded")
                if automatic_analysis_below_floor:
                    report_ai_job_status(
                        args.alert_store_url,
                        selected_group_id,
                        "completed",
                        lease_token=processing_lease_token,
                        job_type=durable_job_type,
                    )
                    print(
                        f"{project_now()} skipped automatic AI analysis for "
                        f"{selected['triage_level']} group below configured threshold",
                        flush=True,
                    )
                    continue
                def renew_processing_lease() -> None:
                    renewed = report_ai_job_status(
                        args.alert_store_url,
                        selected_group_id,
                        "processing",
                        lease_token=processing_lease_token,
                        job_type=durable_job_type,
                    )
                    if renewed != processing_lease_token:
                        raise RuntimeError("durable AI processing lease could not be renewed")

                incident_evidence_path = None
                if durable_job_type == "incident_response_analysis":
                    incident_evidence_path = collect_incident_evidence(
                        alert_id,
                        args,
                        progress_callback=renew_processing_lease if processing_recorded else None,
                    )
                # Indexed work always builds a fresh bounded package at claim
                # time. This guarantees manual reruns and newly coalesced alert,
                # enrichment, PCAP, note, and memory evidence cannot reuse an
                # obsolete prompt artifact.
                prompt_path = (
                    build_prompt(
                        alert_id,
                        args,
                        job_payload,
                        incident_evidence_path=incident_evidence_path,
                    )
                    if indexed_mode
                    else reusable_prompt_for_alert(args.prompt_dir, selected, args.pcap_analysis_dir)
                    or build_prompt(alert_id, args)
                )
                proc = run_analysis(
                    prompt_path,
                    args,
                    progress_callback=renew_processing_lease if processing_recorded else None,
                )
                if proc.stdout:
                    print(proc.stdout, end="")
                if proc.stderr:
                    print(proc.stderr, file=sys.stderr, end="")
                if proc.returncode != 0:
                    detail = proc.stderr or f"local AI analysis failed rc={proc.returncode}"
                    if processing_recorded:
                        report_ai_job_status(
                            args.alert_store_url,
                            selected_group_id,
                            "failed",
                            detail,
                            processing_lease_token,
                            job_type=durable_job_type,
                        )
                    print(detail.strip(), file=sys.stderr)
                    continue
                if processing_recorded:
                    report_ai_job_status(
                        args.alert_store_url,
                        selected_group_id,
                        "completed",
                        lease_token=processing_lease_token,
                        job_type=durable_job_type,
                    )
                analyzed_count += 1
            except (BoundedProcessError, RuntimeError, OSError) as error:
                if processing_recorded:
                    try:
                        report_ai_job_status(
                            args.alert_store_url,
                            selected_group_id,
                            "failed",
                            str(error),
                            processing_lease_token,
                            job_type=durable_job_type,
                        )
                    except RuntimeError as status_error:
                        print(f"AI failure callback also failed: {status_error}", file=sys.stderr)
                print(f"{project_now()} AI group {selected_group_id} failed: {error}", file=sys.stderr)
                continue

        if analyzed_count:
            print(f"{project_now()} analyzed {analyzed_count} unique alert group(s)")
            signal_dashboard_refresh(args)
        # Reconcile again before exit because alerts can enqueue durable intent
        # while a long-running inference is active. This prevents a completed
        # artifact from waiting for the next five-minute scheduler invocation
        # before queue/SLO state becomes accurate.
        reconciled = reconcile_worker_state(args, indexed_mode)
        if reconciled:
            print(f"{project_now()} reconciled {reconciled} completed durable AI job(s) before exit", flush=True)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
