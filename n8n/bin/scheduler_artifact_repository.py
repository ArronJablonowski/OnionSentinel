"""Read-only legacy scheduler artifact indexing and freshness policy."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


def _json_object(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def latest_analysis_mtimes(analysis_dir: Path) -> dict[str, float]:
    latest: dict[str, float] = {}
    if not analysis_dir.exists():
        return latest
    for path in analysis_dir.glob("*-local-ai-analysis.json"):
        data = _json_object(path)
        if data is None:
            continue
        alert_id = str(data.get("alert_id") or "").strip()
        if alert_id:
            try:
                latest[alert_id] = max(
                    latest.get(alert_id, 0), path.stat().st_mtime
                )
            except OSError:
                continue
    return latest


def latest_pcap_analysis_mtimes(
    pcap_analysis_dir: Path,
) -> dict[str, float]:
    latest: dict[str, float] = {}
    if not pcap_analysis_dir.exists():
        return latest
    for path in pcap_analysis_dir.glob("*-pcap-analysis.json"):
        data = _json_object(path)
        if data is None:
            continue
        request = data.get("request")
        request = request if isinstance(request, dict) else {}
        alert_id = str(
            request.get("alert_id") or data.get("alert_id") or ""
        ).strip()
        if alert_id:
            try:
                latest[alert_id] = max(
                    latest.get(alert_id, 0), path.stat().st_mtime
                )
            except OSError:
                continue
    return latest


def latest_pcap_group_mtimes(
    pcap_analysis_dir: Path,
) -> dict[str, float]:
    """Return newest parsed PCAP evidence time keyed by grouped detection id."""
    latest: dict[str, float] = {}
    if not pcap_analysis_dir.exists():
        return latest
    for path in pcap_analysis_dir.glob("*-pcap-analysis.json"):
        data = _json_object(path)
        if data is None:
            continue
        request = data.get("request")
        request = request if isinstance(request, dict) else {}
        group_id = str(request.get("group_id") or "").strip()
        if group_id:
            try:
                latest[group_id] = max(
                    latest.get(group_id, 0), path.stat().st_mtime
                )
            except OSError:
                continue
    return latest


def latest_prompt_mtimes(prompt_dir: Path) -> dict[str, float]:
    latest: dict[str, float] = {}
    if not prompt_dir.exists():
        return latest
    for path in prompt_dir.glob("*-ai-prompt.json"):
        data = _json_object(path)
        if data is None:
            continue
        alert = data.get("alert")
        alert = alert if isinstance(alert, dict) else {}
        alert_id = str(
            alert.get("alert_id") or data.get("alert_id") or ""
        ).strip()
        if alert_id:
            try:
                latest[alert_id] = max(
                    latest.get(alert_id, 0), path.stat().st_mtime
                )
            except OSError:
                continue
    return latest


def alert_group_key_from_mapping(alert: Any) -> str:
    """Return the scheduler duplicate-group key for an alert mapping."""
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


def alert_group_key(row: sqlite3.Row) -> str:
    """Return the same duplicate-group key used by the SOC dashboard."""
    suppression_key = (
        str(row["suppression_key"] or "").strip()
        if "suppression_key" in row.keys()
        else ""
    )
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


def _live_prompt_group_mtimes(
    conn: sqlite3.Connection,
    prompt_mtimes: dict[str, float],
) -> tuple[dict[str, float], set[str]]:
    placeholders = ", ".join("?" for _ in prompt_mtimes)
    prompt_rows = conn.execute(
        f"""
        SELECT alert_id, suppression_key, triage_level, rule_name, source_ip,
               destination_ip, filter_status
        FROM alerts
        WHERE alert_id IN ({placeholders})
        """,
        sorted(prompt_mtimes),
    ).fetchall()
    latest: dict[str, float] = {}
    db_prompt_ids: set[str] = set()
    for row in prompt_rows:
        alert_id = str(row["alert_id"] or "").strip()
        db_prompt_ids.add(alert_id)
        group_key = alert_group_key(row)
        latest[group_key] = max(
            latest.get(group_key, 0), prompt_mtimes.get(alert_id, 0)
        )
    return latest, db_prompt_ids


def _merge_aged_out_prompt_groups(
    prompt_dir: Path,
    latest: dict[str, float],
    db_prompt_ids: set[str],
) -> None:
    for path in prompt_dir.glob("*-ai-prompt.json"):
        data = _json_object(path)
        if data is None:
            continue
        alert = data.get("alert")
        alert = alert if isinstance(alert, dict) else {}
        alert_id = str(
            alert.get("alert_id") or data.get("alert_id") or ""
        ).strip()
        if alert_id in db_prompt_ids:
            continue
        group_key = alert_group_key_from_mapping(alert)
        if not group_key:
            continue
        try:
            latest[group_key] = max(
                latest.get(group_key, 0), path.stat().st_mtime
            )
        except OSError:
            continue


def latest_prompt_group_mtimes(
    conn: sqlite3.Connection,
    prompt_dir: Path,
) -> dict[str, float]:
    """Return newest prompt time keyed by the live duplicate group."""
    prompt_mtimes = latest_prompt_mtimes(prompt_dir)
    if not prompt_mtimes:
        return {}
    latest, db_prompt_ids = _live_prompt_group_mtimes(conn, prompt_mtimes)
    if not prompt_dir.exists():
        return latest
    _merge_aged_out_prompt_groups(prompt_dir, latest, db_prompt_ids)
    return latest


def analyzed_alert_ids(
    analysis_dir: Path,
    pcap_analysis_dir: Path | None = None,
    prompt_dir: Path | None = None,
) -> set[str]:
    """Return alert IDs whose analysis is newer than all relevant evidence."""
    ai_mtimes = latest_analysis_mtimes(analysis_dir)
    prompt_mtimes = latest_prompt_mtimes(prompt_dir) if prompt_dir else {}
    if not pcap_analysis_dir:
        return {
            alert_id
            for alert_id, ai_mtime in ai_mtimes.items()
            if prompt_mtimes.get(alert_id, 0) <= ai_mtime
        }
    pcap_mtimes = latest_pcap_analysis_mtimes(pcap_analysis_dir)
    return {
        alert_id
        for alert_id, ai_mtime in ai_mtimes.items()
        if pcap_mtimes.get(alert_id, 0) <= ai_mtime
        and prompt_mtimes.get(alert_id, 0) <= ai_mtime
    }


def analyzed_alert_groups(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path | None = None,
    pcap_analysis_dir: Path | None = None,
    prompt_dir: Path | None = None,
) -> set[str]:
    """Map current analysis artifacts to freshness-qualified groups."""
    if not analyzed_ids:
        return set()
    clocks = _group_artifact_clocks(
        conn, analysis_dir, pcap_analysis_dir, prompt_dir
    )
    placeholders = ", ".join("?" for _ in analyzed_ids)
    analyzed_rows = conn.execute(
        f"""
        SELECT alert_id, suppression_key, triage_level, rule_name, source_ip,
               destination_ip, filter_status
        FROM alerts
        WHERE alert_id IN ({placeholders})
        """,
        sorted(analyzed_ids),
    ).fetchall()
    group_ai_mtimes: dict[str, float] = {}
    for row in analyzed_rows:
        group_key = alert_group_key(row)
        ai_mtime = clocks[0].get(
            str(row["alert_id"] or "").strip(), 0
        )
        group_ai_mtimes[group_key] = max(
            group_ai_mtimes.get(group_key, 0), ai_mtime
        )
    return _fresh_group_keys(group_ai_mtimes, clocks[1], clocks[2])


def _group_artifact_clocks(
    conn: sqlite3.Connection,
    analysis_dir: Path | None,
    pcap_analysis_dir: Path | None,
    prompt_dir: Path | None,
) -> tuple[dict[str, float], dict[str, float], dict[str, float]]:
    return (
        latest_analysis_mtimes(analysis_dir) if analysis_dir else {},
        latest_pcap_group_mtimes(pcap_analysis_dir)
        if pcap_analysis_dir
        else {},
        latest_prompt_group_mtimes(conn, prompt_dir) if prompt_dir else {},
    )


def _fresh_group_keys(
    group_ai_mtimes: dict[str, float],
    pcap_group_mtimes: dict[str, float],
    prompt_group_mtimes: dict[str, float],
) -> set[str]:
    fresh: set[str] = set()
    for group_key, ai_mtime in group_ai_mtimes.items():
        pcap_mtime = pcap_group_mtimes.get(alert_group_id(group_key), 0)
        prompt_mtime = prompt_group_mtimes.get(group_key, 0)
        if pcap_mtime and ai_mtime and pcap_mtime > ai_mtime:
            continue
        if prompt_mtime and ai_mtime and prompt_mtime > ai_mtime:
            continue
        fresh.add(group_key)
    return fresh


def completed_analysis_group_ids(
    conn: sqlite3.Connection,
    analyzed_ids: set[str],
    analysis_dir: Path,
    pcap_analysis_dir: Path,
    prompt_dir: Path,
) -> set[str]:
    """Return stable queue keys for groups with current analysis artifacts."""
    completed_keys = analyzed_alert_groups(
        conn,
        analyzed_ids,
        analysis_dir,
        pcap_analysis_dir,
        prompt_dir,
    )
    if not completed_keys or not analyzed_ids:
        return set()
    columns = {
        str(item[1])
        for item in conn.execute("PRAGMA table_info(alerts)").fetchall()
    }
    stable_select = (
        "stable_group_id"
        if "stable_group_id" in columns
        else "NULL AS stable_group_id"
    )
    placeholders = ", ".join("?" for _ in analyzed_ids)
    analyzed_rows = conn.execute(
        f"""
        SELECT alert_id, suppression_key, triage_level, rule_name, source_ip,
               destination_ip, filter_status, {stable_select}
        FROM alerts WHERE alert_id IN ({placeholders})
        """,
        sorted(analyzed_ids),
    ).fetchall()
    completed_ids: set[str] = set()
    for row in analyzed_rows:
        group_key = alert_group_key(row)
        if group_key not in completed_keys:
            continue
        stable_id = str(row["stable_group_id"] or "").strip()
        completed_ids.add(stable_id or alert_group_id(group_key))
    return completed_ids


def latest_prompt_for_alert(
    prompt_dir: Path,
    alert_id: str,
) -> Path | None:
    if not prompt_dir.exists():
        return None
    matches: list[tuple[float, Path]] = []
    for path in prompt_dir.glob("*-ai-prompt.json"):
        data = _json_object(path)
        if data is None:
            continue
        alert = data.get("alert")
        alert = alert if isinstance(alert, dict) else {}
        if alert.get("alert_id") != alert_id:
            continue
        try:
            matches.append((path.stat().st_mtime, path))
        except OSError:
            continue
    return sorted(matches)[-1][1] if matches else None


def latest_pcap_evidence_mtime_for_alert(
    selected: sqlite3.Row,
    pcap_analysis_dir: Path,
) -> float:
    """Return newest PCAP evidence mtime for a selected alert group."""
    if not pcap_analysis_dir.exists():
        return 0
    selected_alert_id = str(selected["alert_id"] or "").strip()
    selected_group_id = alert_group_id(
        str(selected["queue_group_key"] or alert_group_key(selected))
    )
    newest = 0.0
    for path in pcap_analysis_dir.glob("*-pcap-analysis.json"):
        matched_mtime = _matching_pcap_mtime(
            path, selected_alert_id, selected_group_id
        )
        if matched_mtime is not None:
            newest = max(newest, matched_mtime)
    return newest


def _matching_pcap_mtime(
    path: Path,
    selected_alert_id: str,
    selected_group_id: str,
) -> float | None:
    data = _json_object(path)
    if data is None:
        return None
    request = data.get("request")
    request = request if isinstance(request, dict) else {}
    alert_id = str(request.get("alert_id") or "").strip()
    group_id = str(request.get("group_id") or "").strip()
    if alert_id != selected_alert_id and group_id != selected_group_id:
        return None
    try:
        return path.stat().st_mtime
    except OSError:
        return None


def reusable_prompt_for_alert(
    prompt_dir: Path,
    selected: sqlite3.Row,
    pcap_analysis_dir: Path,
) -> Path | None:
    """Return a prompt only if it is current with parsed PCAP evidence."""
    prompt = latest_prompt_for_alert(
        prompt_dir, str(selected["alert_id"] or "")
    )
    if not prompt:
        return None
    pcap_mtime = latest_pcap_evidence_mtime_for_alert(
        selected, pcap_analysis_dir
    )
    try:
        prompt_mtime = prompt.stat().st_mtime
    except OSError:
        return None
    if pcap_mtime and pcap_mtime > prompt_mtime:
        return None
    return prompt
