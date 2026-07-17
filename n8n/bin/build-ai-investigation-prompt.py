#!/usr/bin/env python3
"""Build a local-first AI investigation prompt package from alert-store SQLite.

The script does not call an LLM. It prepares a bounded evidence bundle and a
strict JSON response contract that can be sent to Hermes, Ollama, or a hosted
frontier model depending on the escalation policy.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Iterable


BIN_DIR = Path(__file__).resolve().parent
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))
from agent_memory import build_agent_memory_context


HOME = Path.home()
DEFAULT_DB = HOME / "n8n-local" / "alert_store_data" / "alerts.sqlite3"
DEFAULT_ROLLUPS = HOME / "n8n-local" / "soc-alerts" / "daily-rollups"
DEFAULT_OUT = HOME / "n8n-local" / "soc-alerts" / "ai-prompts"
DEFAULT_SYSTEM_PROMPT_FILE = HOME / "n8n-local" / "config" / "soc_analyst_system_prompt.md"
DEFAULT_AGENT_MEMORY_DIR = HOME / "n8n-local" / "soc-alerts" / "agent-memory"
DEFAULT_PCAP_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "pcap-analysis"
DEFAULT_AI_ANALYSIS_DIR = HOME / "n8n-local" / "soc-alerts" / "ai-analysis"
DEFAULT_SOC_ANALYST_MEMORY_FILE = DEFAULT_AGENT_MEMORY_DIR / "soc-analyst-memory.md"
DEFAULT_SHARED_AGENT_MEMORY_FILE = DEFAULT_AGENT_MEMORY_DIR / "shared-agent-memory.md"
DEFAULT_SYSTEM_PROMPT = "You are a careful SOC analyst assisting with Security Onion alerts."
TEST_PREFIXES = ("phase%", "config-%", "internal-test-%", "sqlite-%", "policy-%", "codex-%")
ESCALATE_LEVELS = {"critical", "high"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build an AI investigation prompt package")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="Path to alert-store SQLite DB")
    parser.add_argument("--rollup-dir", type=Path, default=DEFAULT_ROLLUPS, help="Daily rollup directory")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT, help="Output directory for prompt packages")
    parser.add_argument("--alert-id", help="Exact alert_id to package")
    parser.add_argument("--levels", default="critical,high,medium", help="Comma-separated levels when alert-id is omitted")
    parser.add_argument("--hours", type=int, default=24, help="Lookback when alert-id is omitted")
    parser.add_argument("--related-limit", type=int, default=15, help="Maximum related alerts to include")
    parser.add_argument("--correlation-limit", type=int, default=8, help="Maximum scored correlation candidates to include")
    parser.add_argument("--correlation-min-score", type=int, default=15, help="Minimum deterministic correlation score")
    parser.add_argument("--rollup-bytes", type=int, default=12000, help="Maximum bytes from latest daily rollup")
    parser.add_argument("--system-prompt-file", type=Path, default=DEFAULT_SYSTEM_PROMPT_FILE, help="Editable SOC Analyst system prompt file")
    parser.add_argument("--agent-memory-file", type=Path, default=DEFAULT_SOC_ANALYST_MEMORY_FILE, help="SOC Analyst Markdown memory file")
    parser.add_argument("--shared-memory-file", type=Path, default=DEFAULT_SHARED_AGENT_MEMORY_FILE, help="Shared Cyber Security Agent Markdown memory file")
    parser.add_argument("--pcap-analysis-dir", type=Path, default=DEFAULT_PCAP_ANALYSIS_DIR, help="Parsed Zeek/TShark PCAP evidence directory")
    parser.add_argument("--analysis-dir", type=Path, default=DEFAULT_AI_ANALYSIS_DIR, help="Prior local AI analysis directory")
    parser.add_argument("--memory-bytes", type=int, default=8000, help="Maximum bytes to include from each agent memory file")
    parser.add_argument("--pcap-analysis-limit", type=int, default=3, help="Maximum parsed PCAP evidence artifacts to include")
    parser.add_argument("--include-tests", action="store_true", help="Include validation/test alerts")
    parser.add_argument("--stdout", action="store_true", help="Print package JSON instead of writing a file")
    args = parser.parse_args()
    if args.hours <= 0:
        parser.error("--hours must be positive")
    if args.related_limit <= 0:
        parser.error("--related-limit must be positive")
    if args.correlation_limit <= 0:
        parser.error("--correlation-limit must be positive")
    if args.correlation_min_score < 0 or args.correlation_min_score > 100:
        parser.error("--correlation-min-score must be between 0 and 100")
    if args.rollup_bytes <= 0:
        parser.error("--rollup-bytes must be positive")
    if args.memory_bytes <= 0:
        parser.error("--memory-bytes must be positive")
    if args.pcap_analysis_limit <= 0:
        parser.error("--pcap-analysis-limit must be positive")
    return args


def project_now() -> str:
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


def filename_timestamp(value: str) -> str:
    match = re.match(r"^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(Z|[+-]\d{2}:\d{2})$", value)
    if match:
        year, month, day, hour, minute, second, zone = match.groups()
        return f"{year}{month}{day}-{hour}{minute}{second}{zone.replace(':', '')}"
    return safe_filename(value)


def safe_filename(value: str) -> str:
    return (
        str(value or "alert")
        .replace(":", "")
        .replace("/", "-")
        .replace("\\", "-")
        .replace("|", "-")
        .replace(" ", "-")
    )[:180]


def rows(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> list[sqlite3.Row]:
    return conn.execute(sql, tuple(params)).fetchall()


def row(conn: sqlite3.Connection, sql: str, params: Iterable[object] = ()) -> sqlite3.Row | None:
    return conn.execute(sql, tuple(params)).fetchone()


def test_filter_sql(prefix: str = "alert_id") -> tuple[str, list[object]]:
    clauses = []
    params: list[object] = []
    for pattern in TEST_PREFIXES:
        clauses.append(f"{prefix} NOT LIKE ?")
        params.append(pattern)
    return " AND ".join(clauses), params


def parse_alert_json(value: str | None) -> dict:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def parse_json_object(value: str | None) -> dict:
    try:
        parsed = json.loads(value or "{}")
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def safe_int(value: object, default: int = 0) -> int:
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def load_system_prompt(path: Path) -> str:
    """Load the analyst-editable system prompt used by the AI runner."""
    try:
        prompt = path.read_text(encoding="utf-8").strip()
        if prompt:
            return prompt
    except Exception:
        pass
    return DEFAULT_SYSTEM_PROMPT


def sqlite_value(row_value: sqlite3.Row, key: str, default: object = None) -> object:
    return row_value[key] if key in row_value.keys() else default


def alert_group_key(row_value: sqlite3.Row) -> str:
    """Return the same duplicate-group key used by the dashboard and AI scheduler."""
    suppression_key = str(sqlite_value(row_value, "suppression_key") or "").strip()
    if suppression_key:
        return suppression_key
    return "|".join(
        [
            str(sqlite_value(row_value, "triage_level") or "unscored"),
            str(sqlite_value(row_value, "rule_name") or "unknown-rule"),
            str(sqlite_value(row_value, "source_ip") or "unknown-source"),
            str(sqlite_value(row_value, "destination_ip") or "unknown-destination"),
            str(sqlite_value(row_value, "filter_status") or "accepted"),
        ]
    )


def alert_group_id(group_key: str) -> str:
    return hashlib.sha1(str(group_key or "").encode("utf-8")).hexdigest()[:12]


def analyst_state_context(conn: sqlite3.Connection, selected: sqlite3.Row) -> dict:
    group_key = alert_group_key(selected)
    group_id = alert_group_id(group_key)
    try:
        state = row(
            conn,
            """SELECT status, repeat_count, reason, updated_at, updated_by
               FROM analyst_alert_group_state WHERE group_id = ? OR group_key = ?
               ORDER BY updated_at DESC LIMIT 1""",
            [group_id, group_key],
        )
    except sqlite3.OperationalError:
        state = None
    return {
        "group_id": group_id,
        "group_key": group_key,
        "status": state["status"] if state else "open",
        "repeat_count_at_decision": state["repeat_count"] if state else 0,
        "reason": state["reason"] if state else None,
        "updated_at": state["updated_at"] if state else None,
        "updated_by": state["updated_by"] if state else None,
    }


def prior_analysis_context(analysis_dir: Path, selected: sqlite3.Row, limit: int = 3) -> list[dict]:
    alert_id = str(selected["alert_id"] or "")
    found: list[dict] = []
    if not analysis_dir.exists():
        return found
    for path in sorted(analysis_dir.glob("*-local-ai-analysis.json"), reverse=True):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        text = json.dumps(payload, sort_keys=True)
        if alert_id not in text:
            continue
        result = payload.get("analysis") if isinstance(payload.get("analysis"), dict) else payload
        found.append({
            "artifact": str(path),
            "generated_at": payload.get("generated_at") or result.get("generated_at"),
            "model": payload.get("analysis_model") or payload.get("model"),
            "detection_outcome": result.get("detection_outcome"),
            "bluf": result.get("bluf"),
            "summary": result.get("summary"),
            "confidence": result.get("confidence"),
            "tuning_recommendation": result.get("tuning_recommendation"),
        })
        if len(found) >= limit:
            break
    return found


def latest_rollup(rollup_dir: Path, limit_bytes: int) -> dict:
    files = sorted(rollup_dir.glob("*-soc-daily-rollup.md"))
    if not files:
        return {"path": None, "content": ""}
    latest = files[-1]
    data = latest.read_bytes()[:limit_bytes]
    return {"path": str(latest), "content": data.decode("utf-8", errors="replace")}


def compact_pcap_analysis(record: dict) -> dict:
    """Keep PCAP evidence prompt-safe by including summaries, not packet bodies."""
    zeek = record.get("zeek") if isinstance(record.get("zeek"), dict) else {}
    tshark = record.get("tshark") if isinstance(record.get("tshark"), dict) else {}
    request = record.get("request") if isinstance(record.get("request"), dict) else {}
    return {
        "analysis_artifact": record.get("_analysis_path"),
        "generated_at": record.get("generated_at"),
        "request_id": request.get("request_id"),
        "alert_id": request.get("alert_id"),
        "group_id": request.get("group_id"),
        "artifact_state": record.get("artifact_state"),
        "pcap_files": [
            {
                "name": item.get("name"),
                "size_bytes": item.get("size_bytes"),
                "sha256": item.get("sha256"),
            }
            for item in (record.get("pcap_files") if isinstance(record.get("pcap_files"), list) else [])[:5]
            if isinstance(item, dict)
        ],
        "tool_paths": record.get("tool_paths") if isinstance(record.get("tool_paths"), dict) else {},
        "zeek": {
            "available": bool(zeek.get("available")),
            "reason": zeek.get("reason"),
            "record_counts": zeek.get("record_counts") if isinstance(zeek.get("record_counts"), dict) else {},
            "top_connections": zeek.get("top_connections") if isinstance(zeek.get("top_connections"), list) else [],
            "dns_queries": zeek.get("dns_queries") if isinstance(zeek.get("dns_queries"), list) else [],
            "tls_sni": zeek.get("tls_sni") if isinstance(zeek.get("tls_sni"), list) else [],
            "http_hosts": zeek.get("http_hosts") if isinstance(zeek.get("http_hosts"), list) else [],
            "notices": zeek.get("notices") if isinstance(zeek.get("notices"), list) else [],
            "weird": zeek.get("weird") if isinstance(zeek.get("weird"), list) else [],
        },
        "tshark": {
            "available": bool(tshark.get("available")),
            "reason": tshark.get("reason"),
            "samples": [
                {
                    "pcap": Path(str(sample.get("pcap") or "capture")).name,
                    "protocol_hierarchy": str(sample.get("protocol_hierarchy") or "")[:4000],
                    "conversations": str(sample.get("conversations") or "")[:4000],
                    "field_sample_tsv": str(sample.get("field_sample_tsv") or "")[:4000],
                }
                for sample in (tshark.get("samples") if isinstance(tshark.get("samples"), list) else [])[:2]
                if isinstance(sample, dict)
            ],
        },
    }


def compact_public_enrichment_record(record: dict) -> dict:
    """Keep public enrichment useful for the model without raw provider payloads."""
    return {
        "source": record.get("source"),
        "indicator": record.get("indicator"),
        "indicator_type": record.get("indicator_type"),
        "verdict": record.get("verdict"),
        "confidence": record.get("confidence"),
        "tags": record.get("tags") if isinstance(record.get("tags"), list) else [],
        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),
        "cached_at": record.get("cached_at"),
    }


def public_enrichment_context(conn: sqlite3.Connection, selected: sqlite3.Row, limit: int, include_tests: bool) -> dict:
    """Collect normalized public enrichment for the selected duplicate group."""
    filter_sql = ""
    filter_params: list[object] = []
    if not include_tests:
        test_sql, filter_params = test_filter_sql("alert_id")
        filter_sql = f"AND {test_sql}"
    try:
        candidates = rows(
            conn,
            f"""
            SELECT alert_id, first_seen, last_seen, seen_count, rule_name, source_ip,
                   destination_ip, destination_port, triage_level, triage_score,
                   filter_status, suppression_key, enrichment_json
            FROM alerts
            WHERE COALESCE(filter_status, 'accepted') IN ('accepted', 'escalated', 'unknown', 'suppressed')
              {filter_sql}
            ORDER BY last_seen DESC, alert_id DESC
            """,
            filter_params,
        )
    except sqlite3.Error:
        candidates = [selected]

    selected_group_key = alert_group_key(selected)
    group_rows = [item for item in candidates if alert_group_key(item) == selected_group_key] or [selected]
    records: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    indicators: dict[str, list[str]] = {}
    seen_records: set[tuple[str, str, str]] = set()

    for item in group_rows:
        bundle = parse_json_object(str(sqlite_value(item, "enrichment_json") or ""))
        external = bundle.get("external_intel") if isinstance(bundle.get("external_intel"), dict) else bundle
        for record in external.get("records", []) if isinstance(external.get("records"), list) else []:
            if not isinstance(record, dict):
                continue
            compact = compact_public_enrichment_record(record)
            key = (
                str(compact.get("source") or ""),
                str(compact.get("indicator_type") or ""),
                str(compact.get("indicator") or ""),
            )
            if key in seen_records:
                continue
            seen_records.add(key)
            records.append(compact)
            if len(records) >= limit:
                break
        for item_list, target in ((external.get("skipped"), skipped), (external.get("errors"), errors)):
            if isinstance(item_list, list):
                for entry in item_list[:limit]:
                    if isinstance(entry, dict):
                        target.append({key: entry.get(key) for key in ("source", "reason", "indicator", "indicator_type") if key in entry})
                    else:
                        target.append({"reason": str(entry)})
        raw_indicators = external.get("indicators") if isinstance(external.get("indicators"), dict) else {}
        for key, value in raw_indicators.items():
            if isinstance(value, list):
                indicators[str(key)] = [str(item) for item in value[:limit]]
        if len(records) >= limit:
            break

    verdict_counts: dict[str, int] = {}
    for record in records:
        verdict = str(record.get("verdict") or "unknown").lower()
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

    return {
        "records": records,
        "record_limit": limit,
        "verdict_counts": verdict_counts,
        "indicators": indicators,
        "skipped": skipped[:limit],
        "errors": errors[:limit],
        "usage_guidance": (
            "Use public enrichment records as reputation/context evidence, not as sole proof of compromise. "
            "Mention malicious, suspicious, benign, scanner/noise, and unknown verdicts when they affect assessment, "
            "false-positive reasoning, escalation, or SIEM tuning."
        ),
    }


def pcap_request_context(conn: sqlite3.Connection, selected: sqlite3.Row) -> list[dict]:
    try:
        found = rows(
            conn,
            """
            SELECT *
            FROM pcap_requests
            WHERE alert_id = ?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            [selected["alert_id"]],
        )
    except sqlite3.Error:
        return []
    return [dict(item) for item in found]


def pcap_evidence_context(conn: sqlite3.Connection, selected: sqlite3.Row, analysis_dir: Path, limit: int) -> dict:
    requests = pcap_request_context(conn, selected)
    request_ids = {str(item.get("request_id") or "") for item in requests}
    alert_id = str(selected["alert_id"])
    evidence = []
    if analysis_dir.exists():
        for path in sorted(analysis_dir.glob("*-pcap-analysis.json"), key=lambda item: item.stat().st_mtime, reverse=True):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(record, dict):
                continue
            request = record.get("request") if isinstance(record.get("request"), dict) else {}
            if request.get("alert_id") != alert_id and request.get("request_id") not in request_ids:
                continue
            record["_analysis_path"] = str(path)
            evidence.append(compact_pcap_analysis(record))
            if len(evidence) >= limit:
                break
    return {
        "pcap_requests": requests,
        "parsed_evidence": evidence,
        "analysis_dir": str(analysis_dir),
        "usage_guidance": (
            "Use parsed_evidence when present. Zeek is the primary structured network evidence; "
            "TShark corroborates packet-level conversations and protocol hierarchy. If parsed_evidence is empty, "
            "treat PCAP as unavailable and list it as an evidence gap instead of inferring packet contents."
        ),
    }


def select_alert(conn: sqlite3.Connection, args: argparse.Namespace) -> sqlite3.Row:
    if args.alert_id:
        selected = row(conn, "SELECT * FROM alerts WHERE alert_id = ?", [args.alert_id])
        if not selected:
            raise SystemExit(f"alert_id not found: {args.alert_id}")
        return selected

    levels = [level.strip().lower() for level in args.levels.split(",") if level.strip()]
    if not levels:
        raise SystemExit("--levels must contain at least one level")
    since = (dt.datetime.now().astimezone() - dt.timedelta(hours=args.hours)).replace(microsecond=0).isoformat().replace("T", "  ")
    filter_sql = ""
    filter_params: list[object] = []
    if not args.include_tests:
        test_sql, filter_params = test_filter_sql()
        filter_sql = f"AND {test_sql}"
    placeholders = ", ".join("?" for _ in levels)
    selected = row(
        conn,
        f"""
        SELECT *
        FROM alerts
        WHERE replace(replace(last_seen, 'T', ' '), 'Z', '') >= replace(replace(?, 'T', ' '), 'Z', '')
          AND triage_level IN ({placeholders})
          AND COALESCE(filter_status, 'accepted') IN ('accepted', 'escalated', 'unknown')
          {filter_sql}
        ORDER BY
          CASE triage_level WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
          triage_score DESC,
          replace(replace(last_seen, 'T', ' '), 'Z', '') DESC
        LIMIT 1
        """,
        [since, *levels, *filter_params],
    )
    if not selected:
        raise SystemExit("no matching alert found")
    return selected


def related_alerts(conn: sqlite3.Connection, selected: sqlite3.Row, limit: int, include_tests: bool) -> list[dict]:
    filter_sql = ""
    filter_params: list[object] = []
    if not include_tests:
        test_sql, filter_params = test_filter_sql("alert_id")
        filter_sql = f"AND {test_sql}"
    found = rows(
        conn,
        f"""
        SELECT alert_id, last_seen, rule_name, source_ip, destination_ip,
               triage_level, triage_score, filter_status, routing, seen_count
        FROM alerts
        WHERE alert_id != ?
          AND (
            rule_name = ?
            OR source_ip = ?
            OR destination_ip = ?
            OR (source_ip = ? AND destination_ip = ?)
          )
          {filter_sql}
        ORDER BY last_seen DESC
        LIMIT ?
        """,
        [
            selected["alert_id"],
            selected["rule_name"],
            selected["source_ip"],
            selected["destination_ip"],
            selected["source_ip"],
            selected["destination_ip"],
            *filter_params,
            limit,
        ],
    )
    return [dict(item) for item in found]


CORRELATION_WEIGHTS = {
    "hash": 50,
    "url": 45,
    "domain": 35,
    "host": 35,
    "user": 35,
    "cve": 25,
    "rule": 12,
    "dataset": 4,
    "port": 4,
    "protocol": 3,
}


def parse_project_datetime(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T", 1)
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def correlation_observable_weight(observable_type: str, value: str) -> int:
    if observable_type != "ip":
        return CORRELATION_WEIGHTS.get(observable_type, 0)
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return 0
    return 35 if address.is_private else 25


def correlation_time_bonus(selected_last_seen: object, related_last_seen: object) -> tuple[int, str | None]:
    selected_time = parse_project_datetime(selected_last_seen)
    related_time = parse_project_datetime(related_last_seen)
    if not selected_time or not related_time:
        return 0, None
    seconds = abs((selected_time - related_time).total_seconds())
    if seconds <= 3600:
        return 20, "detections occurred within one hour"
    if seconds <= 86400:
        return 10, "detections occurred within 24 hours"
    if seconds <= 604800:
        return 5, "detections occurred within seven days"
    return 0, None


def correlated_alert_context(
    conn: sqlite3.Connection,
    selected: sqlite3.Row,
    limit: int,
    min_score: int,
) -> dict:
    """Return bounded, deterministic cross-alert context with provenance.

    SQLite observables generate candidates; prior model conclusions only
    annotate those candidates and never create evidence on their own.
    """
    selected_group_id = str(sqlite_value(selected, "stable_group_id") or "").strip().lower()
    if not selected_group_id:
        return {
            "selected_group_id": None,
            "candidates": [],
            "candidate_limit": limit,
            "minimum_score": min_score,
            "status": "stable group identity unavailable",
        }
    try:
        matches = rows(
            conn,
            """
            SELECT related.group_id,
                   selected.observable_type,
                   selected.observable_value,
                   selected.role AS selected_role,
                   related.role AS related_role
            FROM alert_observables AS selected
            JOIN alert_observables AS related
              ON related.observable_type = selected.observable_type
             AND related.observable_value = selected.observable_value
             AND related.group_id != selected.group_id
            WHERE selected.group_id = ?
            LIMIT 4000
            """,
            [selected_group_id],
        )
        persisted = rows(
            conn,
            """
            SELECT source_group_id, related_group_id, correlation_score,
                   reasons_json, shared_observables_json, model_status,
                   model_confidence, model_hypothesis, updated_at
            FROM alert_correlations
            WHERE source_group_id = ? OR related_group_id = ?
            ORDER BY correlation_score DESC, updated_at DESC
            LIMIT 100
            """,
            [selected_group_id, selected_group_id],
        )
    except sqlite3.Error:
        return {
            "selected_group_id": selected_group_id,
            "candidates": [],
            "candidate_limit": limit,
            "minimum_score": min_score,
            "status": "correlation index unavailable",
        }

    candidate_data: dict[str, dict] = {}
    for match in matches:
        group_id = str(match["group_id"] or "")
        observable_type = str(match["observable_type"] or "")
        observable_value = str(match["observable_value"] or "")
        key = (
            observable_type,
            observable_value,
            str(match["selected_role"] or ""),
            str(match["related_role"] or ""),
        )
        candidate = candidate_data.setdefault(group_id, {"matches": {}, "persisted": None})
        candidate["matches"][key] = correlation_observable_weight(observable_type, observable_value)

    for item in persisted:
        source_id = str(item["source_group_id"] or "")
        related_id = str(item["related_group_id"] or "")
        group_id = related_id if source_id == selected_group_id else source_id
        if not group_id or group_id == selected_group_id:
            continue
        candidate = candidate_data.setdefault(group_id, {"matches": {}, "persisted": None})
        candidate["persisted"] = dict(item)

    ranked_ids = sorted(
        candidate_data,
        key=lambda group_id: max(
            sum(candidate_data[group_id]["matches"].values()),
            int(float((candidate_data[group_id]["persisted"] or {}).get("correlation_score") or 0)),
        ),
        reverse=True,
    )[:100]
    if not ranked_ids:
        return {
            "selected_group_id": selected_group_id,
            "candidates": [],
            "candidate_limit": limit,
            "minimum_score": min_score,
            "status": "no indexed correlation candidates",
        }

    placeholders = ",".join("?" for _ in ranked_ids)
    candidate_rows = rows(
        conn,
        f"""
        SELECT alert_id, stable_group_id, last_seen, first_seen, rule_name,
               source_ip, destination_ip, destination_port, transport_protocol,
               triage_level, triage_score, filter_status, seen_count
        FROM alerts
        WHERE stable_group_id IN ({placeholders})
        ORDER BY replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC,
                 alert_id DESC
        """,
        ranked_ids,
    )
    representative: dict[str, dict] = {}
    for item in candidate_rows:
        representative.setdefault(str(item["stable_group_id"] or ""), dict(item))

    analysis_rows = rows(
        conn,
        f"""
        SELECT analysis_id, group_id, generated_at, model, detection_outcome,
               bluf, summary, confidence
        FROM ai_analysis_runs
        WHERE group_id IN ({placeholders})
        ORDER BY generated_at DESC, analysis_id DESC
        """,
        ranked_ids,
    )
    prior_analysis: dict[str, dict] = {}
    for item in analysis_rows:
        prior_analysis.setdefault(str(item["group_id"] or ""), dict(item))

    candidates = []
    for group_id in ranked_ids:
        item = representative.get(group_id)
        if not item:
            continue
        data = candidate_data[group_id]
        shared = [
            {
                "type": key[0],
                "value": key[1],
                "selected_role": key[2],
                "related_role": key[3],
                "weight": weight,
            }
            for key, weight in sorted(data["matches"].items(), key=lambda pair: (-pair[1], pair[0]))
        ]
        evidence_score = min(80, sum(match["weight"] for match in shared))
        time_score, time_reason = correlation_time_bonus(sqlite_value(selected, "last_seen"), item.get("last_seen"))
        persisted_item = data["persisted"] or {}
        persisted_score = int(float(persisted_item.get("correlation_score") or 0))
        score = min(100, max(evidence_score + time_score, persisted_score))
        if score < min_score:
            continue
        reasons = [f"shared {match['type']}: {match['value']}" for match in shared[:8]]
        if time_reason:
            reasons.append(time_reason)
        if persisted_item:
            reasons.append("previous correlation record exists")
        candidates.append({
            "group_id": group_id,
            "score": score,
            "correlation_reasons": reasons,
            "shared_observables": shared[:12],
            "alert": item,
            "prior_analysis": prior_analysis.get(group_id),
            "previous_correlation": {
                "model_status": persisted_item.get("model_status"),
                "model_confidence": persisted_item.get("model_confidence"),
                "model_hypothesis": persisted_item.get("model_hypothesis"),
                "updated_at": persisted_item.get("updated_at"),
            } if persisted_item else None,
        })

    candidates.sort(key=lambda item: (item["score"], str(item["alert"].get("last_seen") or "")), reverse=True)
    return {
        "selected_group_id": selected_group_id,
        "candidates": candidates[:limit],
        "candidate_count_before_limit": len(candidates),
        "candidate_limit": limit,
        "minimum_score": min_score,
        "usage_guidance": (
            "Treat candidates as correlation leads, not confirmed incidents. Shared observables and timestamps are facts; "
            "prior_analysis and previous_correlation are earlier hypotheses. Require current evidence before asserting a relationship."
        ),
    }


def grouped_alert_context(conn: sqlite3.Connection, selected: sqlite3.Row, limit: int, include_tests: bool) -> dict:
    """Summarize the dashboard duplicate group so AI weighs alert frequency."""
    filter_sql = ""
    filter_params: list[object] = []
    if not include_tests:
        test_sql, filter_params = test_filter_sql("alert_id")
        filter_sql = f"AND {test_sql}"
    candidates = rows(
        conn,
        f"""
        SELECT alert_id, first_seen, last_seen, seen_count, rule_name, source_ip,
               destination_ip, destination_port, triage_level, triage_score,
               filter_status, suppression_key
        FROM alerts
        WHERE COALESCE(filter_status, 'accepted') IN ('accepted', 'escalated', 'unknown', 'suppressed')
          {filter_sql}
        ORDER BY last_seen DESC, alert_id DESC
        """,
        filter_params,
    )
    selected_group_key = alert_group_key(selected)
    group_rows = [item for item in candidates if alert_group_key(item) == selected_group_key]
    if not group_rows:
        group_rows = [selected]
    total_observations = sum(max(1, safe_int(sqlite_value(item, "seen_count"))) for item in group_rows)
    first_seen_values = [str(sqlite_value(item, "first_seen") or "") for item in group_rows if sqlite_value(item, "first_seen")]
    last_seen_values = [str(sqlite_value(item, "last_seen") or "") for item in group_rows if sqlite_value(item, "last_seen")]
    timeline = [
        {
            "alert_id": item["alert_id"],
            "first_seen": sqlite_value(item, "first_seen"),
            "last_seen": sqlite_value(item, "last_seen"),
            "seen_count": max(1, safe_int(sqlite_value(item, "seen_count"))),
            "source_ip": sqlite_value(item, "source_ip"),
            "destination_ip": sqlite_value(item, "destination_ip"),
            "destination_port": sqlite_value(item, "destination_port"),
            "triage_level": sqlite_value(item, "triage_level"),
            "triage_score": sqlite_value(item, "triage_score"),
            "filter_status": sqlite_value(item, "filter_status"),
        }
        for item in group_rows[:limit]
    ]
    return {
        "group_key": selected_group_key,
        "raw_alert_rows": len(group_rows),
        "total_observations": total_observations,
        "first_seen": min(first_seen_values) if first_seen_values else sqlite_value(selected, "first_seen"),
        "last_seen": max(last_seen_values) if last_seen_values else sqlite_value(selected, "last_seen"),
        "timeline_sample": timeline,
        "timeline_sample_limit": limit,
        "frequency_guidance": (
            "Use total_observations and raw_alert_rows to judge urgency, recurrence, and tuning. "
            "A high count may indicate active behavior, noisy expected software, or a rule that needs suppression/drop/tuning."
        ),
    }


def notification_context(conn: sqlite3.Connection, selected: sqlite3.Row) -> list[dict]:
    found = rows(
        conn,
        """
        SELECT channel, triage_level, rule_name, source_ip, destination_ip,
               sent_count, last_sent
        FROM notification_log
        WHERE rule_name = ?
           OR source_ip = ?
           OR destination_ip = ?
        ORDER BY last_sent DESC
        LIMIT 10
        """,
        [selected["rule_name"], selected["source_ip"], selected["destination_ip"]],
    )
    return [dict(item) for item in found]


def compact_alert(row_value: sqlite3.Row) -> dict:
    alert = parse_alert_json(row_value["alert_json"])
    triage = alert.get("triage") if isinstance(alert.get("triage"), dict) else {}
    return {
        "alert_id": row_value["alert_id"],
        "timestamp": row_value["timestamp"],
        "first_seen": row_value["first_seen"],
        "last_seen": row_value["last_seen"],
        "seen_count": row_value["seen_count"],
        "total_seen_count": sqlite_value(row_value, "total_seen_count"),
        "rule_name": row_value["rule_name"],
        "event_dataset": row_value["event_dataset"],
        "severity": row_value["severity"],
        "severity_label": row_value["severity_label"],
        "source_ip": row_value["source_ip"],
        "destination_ip": row_value["destination_ip"],
        "traffic_direction": row_value["traffic_direction"],
        "triage_score": row_value["triage_score"],
        "triage_level": row_value["triage_level"],
        "routing": row_value["routing"],
        "filter_status": row_value["filter_status"],
        "filter_reason": row_value["filter_reason"],
        "suppression_key": row_value["suppression_key"],
        "triage_reasons": triage.get("reasons", []),
        "raw_alert_subset": {
            "source": alert.get("source"),
            "destination": alert.get("destination"),
            "network": alert.get("network"),
            "event": alert.get("event"),
            "observer": alert.get("observer"),
            "message": alert.get("message"),
            "rule_category": alert.get("rule_category"),
            "rule_ruleset": alert.get("rule_ruleset"),
            "signature_id": alert.get("signature_id"),
        },
    }


def model_policy(level: str | None) -> dict:
    normalized = str(level or "").lower()
    return {
        "default_model_path": "local_llm",
        "hosted_second_opinion_allowed": normalized in ESCALATE_LEVELS,
        "hosted_second_opinion_rule": "Only use hosted GPT-class analysis for critical/high alerts or when local analysis requests escalation.",
        "privacy_rule": "Do not send raw packet payloads, credentials, tokens, or unnecessary internal notes to hosted models.",
    }


def build_package(conn: sqlite3.Connection, selected: sqlite3.Row, args: argparse.Namespace) -> dict:
    rollup = latest_rollup(args.rollup_dir, args.rollup_bytes)
    group_context = grouped_alert_context(conn, selected, args.related_limit, args.include_tests)
    pcap_context = pcap_evidence_context(conn, selected, args.pcap_analysis_dir, args.pcap_analysis_limit)
    enrichment_context = public_enrichment_context(conn, selected, args.related_limit, args.include_tests)
    analyst_state = analyst_state_context(conn, selected)
    correlation_context = correlated_alert_context(
        conn,
        selected,
        args.correlation_limit,
        args.correlation_min_score,
    )
    compact_selected = compact_alert(selected)
    memory_context = build_agent_memory_context(
        agent_role="soc-analyst",
        role_memory_file=args.agent_memory_file,
        shared_memory_file=args.shared_memory_file,
        evidence={
            "alert": compact_selected,
            "grouped_alert_context": group_context,
            "public_enrichment": enrichment_context,
            "pcap_evidence": pcap_context,
            "analyst_state": analyst_state,
            "correlated_alert_context": correlation_context,
        },
        limit_bytes=args.memory_bytes,
    )
    return {
        "package_type": "soc-ai-investigation-prompt",
        "generated_at": project_now(),
        "analysis_policy": model_policy(selected["triage_level"]),
        "system_prompt_file": str(args.system_prompt_file),
        "agent_memory_file": str(args.agent_memory_file),
        "shared_memory_file": str(args.shared_memory_file),
        "instructions": {
            "role": load_system_prompt(args.system_prompt_file),
            "grounding": [
                "Use only the provided evidence.",
                "Use agent_memory.role_memory and agent_memory.shared_memory as analyst memory context when relevant.",
                "Use public_enrichment records when present; weigh verdicts, confidence, tags, and skipped/error notes in the overall assessment.",
                "Use pcap_evidence.parsed_evidence when present; prefer Zeek summaries for flows/protocols and TShark summaries for packet-level corroboration.",
                "If memory conflicts with current alert evidence, prefer the current alert evidence and mention the conflict.",
                "Propose memory_candidates only for reusable lessons that are likely to help a later investigation. Do not use memory as a transcript or repeat the current alert summary.",
                "A shared memory candidate must be high-confidence, useful to multiple agent roles, grounded in supplied evidence, and contain no secrets, raw payloads, or live alert IDs.",
                "Return an empty memory_candidates array when no durable reusable lesson was established.",
                "Use grouped_alert_context.total_observations and raw_alert_rows when judging urgency, repeat behavior, and tuning.",
                "Use analyst_state and prior_analyses as context; do not treat an earlier conclusion as stronger than current evidence.",
                "Evaluate correlated_alert_context candidates using only their shared observables, timing, current evidence, and provenance. Prior analysis is a hypothesis, not a fact.",
                "Do not claim correlation from a common port, protocol, ASN, CDN, public resolver, or rule name alone. State evidence for and against every proposed relationship.",
                "Start the assessment with a BLUF classification. Classify whether the detection outcome is true-positive malicious, true-positive suspicious, true-positive authorized/benign, false positive, duplicate, informational/no-action, or inconclusive based on whether the rule correctly identified the intended behavior and whether the behavior appears malicious, suspicious, authorized, benign, or unknown.",
                "Do not invent packet contents, hostnames, users, process names, files, commands, or malware family names.",
                "If evidence is missing, say what is missing.",
                "Separate facts from hypotheses.",
                "Return valid JSON only using the response_schema.",
            ],
            "task": "Explain likely meaning, repeat frequency, false positive possibilities, urgency, next investigative steps, tuning actions, and whether a hosted second opinion is warranted.",
        },
        "response_schema": {
            "detection_outcome": "true_positive_malicious|true_positive_suspicious|true_positive_authorized_benign|false_positive_logic_rule|false_positive_data_parser|false_positive_bad_intel_ioc|duplicate|informational_no_action|inconclusive",
            "bluf": "Bottom-line sentence that starts with the classification and briefly states why.",
            "summary": "string",
            "likely_meaning": "string",
            "severity_reasoning": "string",
            "alert_frequency_assessment": "string",
            "public_enrichment_findings": ["string"],
            "pcap_analysis_findings": ["string"],
            "false_positive_possibilities": ["string"],
            "recommended_next_steps": ["string"],
            "evidence_used": ["string"],
            "evidence_gaps": ["string"],
            "confidence": "low|medium|high",
            "escalation_needed": "boolean",
            "hosted_second_opinion_recommended": "boolean",
            "tuning_recommendation": "none|suppress|drop|raise_score|lower_score|needs_more_data",
            "tuning_reason": "string",
            "recommended_tuning_actions": ["string"],
            "correlation_assessment": {
                "correlation_found": "boolean",
                "confidence": "low|medium|high",
                "related_groups": [{"group_id": "string", "reason": "string"}],
                "shared_evidence": ["string"],
                "contradicting_evidence": ["string"],
                "attack_chain_hypothesis": "string",
                "recommended_pivots": ["string"],
            },
            "memory_candidates": [
                {
                    "scope": "agent|shared",
                    "category": "benign_pattern|detection_pattern|environment_context|evidence_gap|investigation_pivot|response_lesson|threat_intel_lesson|tooling_lesson|tuning_decision",
                    "finding": "Reusable lesson, not a copy of the current alert summary.",
                    "use_when": "Conditions under which a later agent should retrieve this lesson.",
                    "evidence_basis": ["Current supplied evidence that supports the lesson."],
                    "confidence": "medium|high",
                    "tags": ["short retrieval tag"],
                    "ttl_days": "integer from 7 through 365",
                }
            ],
        },
        "alert": compact_selected,
        "grouped_alert_context": group_context,
        "public_enrichment": enrichment_context,
        "pcap_evidence": pcap_context,
        "analyst_state": analyst_state,
        "prior_analyses": prior_analysis_context(args.analysis_dir, selected),
        "related_alerts": related_alerts(conn, selected, args.related_limit, args.include_tests),
        "correlated_alert_context": correlation_context,
        "recent_notifications": notification_context(conn, selected),
        "agent_memory": memory_context,
        "latest_daily_rollup": rollup,
    }


def main() -> int:
    args = parse_args()
    if not args.db.exists():
        raise SystemExit(f"SQLite DB not found: {args.db}")
    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        selected = select_alert(conn, args)
        package = build_package(conn, selected, args)
    finally:
        conn.close()

    output = json.dumps(package, indent=2, sort_keys=True)
    if args.stdout:
        print(output)
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stamp = filename_timestamp(project_now())
    alert_id = safe_filename(str(package["alert"]["alert_id"]))
    out_path = args.out_dir / f"{stamp}-{alert_id}-ai-prompt.json"
    out_path.write_text(output + "\n", encoding="utf-8")
    print(out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
