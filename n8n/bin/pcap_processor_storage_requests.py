"""Read-only PCAP request selection and exact rule/playbook resolution."""
from __future__ import annotations

from pathlib import Path
from typing import Any


def request_from_row(row: Any) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def table_columns(conn: Any, table: str, rows: Any) -> set[str]:
    return {str(item["name"]) for item in rows(conn, f"PRAGMA table_info({table})")}


def pending_requests(
    db_path: Path,
    request_id: str | None,
    limit: int,
    out_dir: Path,
    overwrite: bool,
    dependencies: dict[str, Any],
) -> list[dict[str, Any]]:
    """Select fulfilled requests without starving older unanalyzed captures."""
    if not db_path.exists():
        return []
    sqlite3 = dependencies["sqlite3"]
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = dependencies["table_columns"](conn, "pcap_requests")
        order_column = "completed_at" if "completed_at" in columns else "updated_at"
        if request_id:
            candidates = dependencies["rows"](
                conn,
                "SELECT * FROM pcap_requests WHERE request_id = ? AND status = 'fulfilled'",
                [request_id],
            )
        else:
            candidates = conn.execute(
                f"""
                SELECT *
                FROM pcap_requests
                WHERE status = 'fulfilled'
                ORDER BY {order_column} DESC, created_at DESC
                """
            )
        found = _eligible_requests(
            candidates,
            columns,
            limit,
            out_dir,
            overwrite,
            dependencies["analysis_json_path"],
        )
    finally:
        conn.close()
    return [request_from_row(item) for item in found]


def _eligible_requests(
    candidates: Any,
    columns: set[str],
    limit: int,
    out_dir: Path,
    overwrite: bool,
    analysis_json_path: Any,
) -> list[Any]:
    found = []
    for item in candidates:
        request_id = str(item["request_id"] or "")
        durable_incomplete = (
            "analysis_status" in columns
            and str(item["analysis_status"] or "") != "completed"
        )
        if overwrite or durable_incomplete or not analysis_json_path(out_dir, request_id).exists():
            found.append(item)
            if len(found) >= limit:
                break
    return found


def _policy(status: str, evidence_gap: str, **extra: Any) -> dict[str, Any]:
    return {
        "playbook_policy": {
            "status": status,
            "fail_closed": status != "exact_playbook_matched",
            **extra,
            "evidence_gap": evidence_gap,
        }
    }


def _load_alert_row(
    db_path: Path,
    alert_id: str,
    dependencies: dict[str, Any],
) -> tuple[dict[str, Any] | None, Any | None]:
    sqlite3 = dependencies["sqlite3"]
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        columns = dependencies["table_columns"](conn, "alerts")
        if "alert_id" not in columns:
            return _policy(
                "alert_schema_unsupported",
                "The alert database lacks the alert_id column required for exact rule resolution.",
            ), None
        projection = ", ".join(
            column if column in columns else f"NULL AS {column}"
            for column in ("alert_json", "raw_event_json", "rule_id")
        )
        row = conn.execute(
            f"SELECT {projection} FROM alerts WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()
    finally:
        conn.close()
    return None, row


def _registry_failure(context: dict[str, Any], status: str) -> tuple[dict[str, Any], None]:
    messages = {
        "registry_missing": "The detection-playbook registry is missing; playbook-specific conclusions are unavailable.",
        "registry_unreadable": "The detection-playbook registry could not be read; playbook-specific conclusions are unavailable.",
        "registry_invalid": "The detection-playbook registry failed validation; playbook-specific conclusions are unavailable.",
    }
    context.update(_policy(status, messages[status]))
    return context, None


def _resolved_playbook(
    context: dict[str, Any],
    playbook_path: Path,
    dependencies: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    try:
        playbook_path.stat()
    except FileNotFoundError:
        return _registry_failure(context, "registry_missing")
    except OSError:
        return _registry_failure(context, "registry_unreadable")
    try:
        registry = dependencies["load_detection_playbooks"](playbook_path)
        playbook = dependencies["resolve_detection_playbook"](registry, context)
    except OSError:
        return _registry_failure(context, "registry_unreadable")
    except (UnicodeError, ValueError):
        return _registry_failure(context, "registry_invalid")
    if registry.get("version") == 0:
        return _registry_failure(context, "registry_missing")
    if not isinstance(playbook, dict):
        context.update(
            _policy(
                "no_exact_playbook",
                "No exact detection playbook matched the selected rule identity.",
                registry_version=registry.get("version"),
            )
        )
        return context, None
    context.update(
        _policy(
            "exact_playbook_matched",
            "",
            registry_version=registry.get("version"),
        )
    )
    return context, playbook


def signature_context_for_request(
    db_path: Path,
    request: dict[str, Any],
    playbook_path: Path,
    dependencies: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Load exact alert rule and exact-ID playbook without database writes."""
    alert_id = str(request.get("alert_id") or "").strip()
    if not alert_id:
        return _policy(
            "not_evaluated",
            "No selected alert id was supplied for exact detection-playbook resolution.",
        ), None
    if not db_path.exists():
        return _policy(
            "alert_database_missing",
            "The alert database was unavailable for exact detection-playbook resolution.",
        ), None
    failure, row = _load_alert_row(db_path, alert_id, dependencies)
    if failure is not None:
        return failure, None
    if row is None:
        return _policy(
            "alert_not_found",
            "The selected alert was not found for exact detection-playbook resolution.",
        ), None
    context = dependencies["extract_rule_context"](
        row["alert_json"], row["raw_event_json"], row["rule_id"]
    )
    return _resolved_playbook(context, playbook_path, dependencies)
