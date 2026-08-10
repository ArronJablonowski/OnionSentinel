"""Core SOC status-write, SQLite connection, and query-policy runtime wiring."""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any


def soc_alert_suppression_review_state(r: Any, alert_id: str) -> dict:
    try:
        with r.soc_alert_db_connect() as conn:
            return r.soc_alert_review_state_for_group(conn, alert_id)
    except (FileNotFoundError, r.sqlite3.Error):
        return r._soc_review_defaults()


def soc_alert_status_write_sources(r: Any) -> Any:
    return r.SocAlertStatusWriteSources(
        now_iso=r.now_iso_utc,
        validate_store_id=r.valid_soc_alert_store_id,
        status_response=r.soc_alert_status_response,
        current_repeat_count=r.current_soc_alert_group_repeat_count,
        suppression_review_state=r.soc_alert_suppression_review_state,
        write_offline_status=r.write_soc_alert_status,
        post_alert_store=r.alert_store_post_json,
        alert_store_error=r.AlertStoreRequestError,
        alert_store_configured=bool(r.SOC_ALERT_STORE_API_URL),
        direct_write_allowed=r.SOC_ALERT_STORE_DIRECT_WRITE_ALLOWED,
    )


def update_soc_alert_status(r: Any, payload: dict) -> tuple[bool, dict]:
    return r.apply_soc_alert_status_update(r.soc_alert_status_write_sources(), payload)


def valid_soc_alert_store_id(r: Any, value: object) -> str:
    alert_id = str(value or "").strip()
    if 1 <= len(alert_id) <= 256 and r.re.fullmatch(r"[A-Za-z0-9._:@=-]+", alert_id):
        return alert_id
    return ""


def soc_alert_api_error(r: Any, message: str, status: int = 400) -> tuple[int, dict]:
    return status, {"ok": False, "error": message}


@contextmanager
def soc_alert_db_connect(r: Any):
    if not r.SOC_ALERT_STORE_DB.exists():
        raise FileNotFoundError(f"SOC alert store DB not found: {r.SOC_ALERT_STORE_DB}")
    conn = r.sqlite3.connect(
        f"file:{r.SOC_ALERT_STORE_DB}?mode=ro", uri=True,
        timeout=r.SOC_ALERT_DB_BUSY_TIMEOUT_SECONDS,
    )
    conn.row_factory = r.sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {r.SOC_ALERT_DB_BUSY_TIMEOUT_MS}")
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def soc_alert_db_write_connect(r: Any):
    if not r.SOC_ALERT_STORE_DB.exists():
        raise FileNotFoundError(f"SOC alert store DB not found: {r.SOC_ALERT_STORE_DB}")
    with r.SOC_ALERT_DB_WRITE_LOCK:
        conn = r.sqlite3.connect(
            r.SOC_ALERT_STORE_DB, timeout=r.SOC_ALERT_DB_BUSY_TIMEOUT_SECONDS
        )
        conn.row_factory = r.sqlite3.Row
        conn.execute(f"PRAGMA busy_timeout = {r.SOC_ALERT_DB_BUSY_TIMEOUT_MS}")
        conn.execute("PRAGMA synchronous = FULL")
        conn.execute("PRAGMA wal_autocheckpoint = 1000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def parse_soc_alert_since(r: Any, value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""
    match = r.re.fullmatch(r"(\d{1,4})([mhdw])", raw)
    if match:
        amount = int(match.group(1))
        delta = {
            "m": r.dt.timedelta(minutes=amount), "h": r.dt.timedelta(hours=amount),
            "d": r.dt.timedelta(days=amount), "w": r.dt.timedelta(weeks=amount),
        }[match.group(2)]
        return r.format_iso_timestamp(
            r.dt.datetime.now(r.dt.timezone.utc) - delta, utc_z=True
        )
    if r.re.fullmatch(r"\d{4}-\d{2}-\d{2}t\d{2}:\d{2}(:\d{2})?z?", raw):
        value = raw.upper() if raw.endswith("z") else raw.upper() + "Z"
        return r.ISO_DATE_TIME_SEPARATOR_RE.sub(r"\1  ", value)
    if r.re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
        return raw + "  00:00:00Z"
    return ""


def soc_alert_level_names(r: Any, raw: str) -> list[str]:
    levels = []
    for part in str(raw or "").split(","):
        level = part.strip().lower()
        if level in r.SOC_ALERT_LEVEL_RANK:
            levels.append("informational" if level == "info" else level)
    return sorted(set(levels), key=lambda value: r.SOC_ALERT_LEVEL_RANK.get(value, 0), reverse=True)


def soc_alert_row_level(r: Any, row: Any) -> str:
    level = str(row["triage_level"] or row["severity_label"] or "informational").strip().lower()
    if level == "info":
        level = "informational"
    if level in r.SOC_ALERT_LEVEL_RANK:
        return level
    severity = row["severity"] if "severity" in row.keys() else None
    return {1: "high", 2: "medium", 3: "low"}.get(severity, "informational")


def soc_alert_visible_severity_summary(r: Any, rows: list[Any]) -> dict:
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "informational")}
    highest, highest_rank = "none", 0
    for row in rows:
        level = r.soc_alert_row_level(row)
        counts[level] = counts.get(level, 0) + 1
        rank = r.SOC_ALERT_LEVEL_RANK.get(level, 0)
        if rank > highest_rank:
            highest, highest_rank = level, rank
    return {"counts": counts, "highest": highest}


def soc_alert_limit(r: Any, raw: object, default: int = 100) -> int:
    try:
        value = int(str(raw or default))
    except ValueError:
        value = default
    return max(1, min(r.SOC_ALERT_API_MAX_LIMIT, value))


def soc_alert_page(r: Any, raw: object) -> int:
    try:
        value = int(str(raw or 1))
    except ValueError:
        value = 1
    return max(1, value)


def soc_alert_sort_clause(r: Any, query: dict[str, list[str]], *, fallback: bool = False) -> tuple[str, str, str]:
    raw_sort = str((query.get("sort") or ["last_seen"])[0]).strip().lower().replace("-", "_")
    direction = str((query.get("direction") or query.get("dir") or ["desc"])[0]).strip().lower()
    if direction not in {"asc", "desc"}:
        direction = "desc"
    if raw_sort not in r.SOC_ALERT_SORT_SQL:
        raw_sort = "last_seen"
    expression = r.SOC_ALERT_SORT_SQL[raw_sort]
    if fallback and raw_sort == "size":
        expression = "COALESCE(payload_size_bytes, LENGTH(COALESCE(alert_json, '')), 0)"
    tie = "ASC" if direction == "asc" else "DESC"
    id_column = "group_key" if fallback else "group_id"
    clause = f"{expression} {direction.upper()}, replace(replace(COALESCE(last_seen, timestamp, first_seen), 'T', ' '), 'Z', '') DESC, {id_column} {tie}"
    return raw_sort, direction, clause


def soc_alert_cursor_parts(r: Any, raw: str) -> tuple[str, str]:
    cursor = str(raw or "")
    if "|" not in cursor:
        return "", ""
    last_seen, alert_id = cursor.split("|", 1)
    return last_seen.strip(), r.valid_soc_alert_store_id(alert_id)
