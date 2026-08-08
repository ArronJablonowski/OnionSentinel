"""Durable persistence orchestration for SOC analyst alert status."""
from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import ContextManager


@dataclass(frozen=True)
class SocAlertStatusPersistenceSources:
    db_path: Path
    mirror_path: Path
    connect_read: Callable[[], AbstractContextManager]
    connect_write: Callable[[], AbstractContextManager]
    ensure_schema: Callable[[object], None]
    load_db: Callable[[object], dict]
    write_one: Callable[[object, str, object], None]
    write_many: Callable[[object, object], None]
    normalize: Callable[[object], dict | None]
    now_iso: Callable[[], str]
    uuid_hex: Callable[[], str]
    lock: ContextManager
    sleep: Callable[[float], None]
    retry_attempts: int = 5
    retry_base_seconds: float = 0.02


def retryable_soc_alert_status_error(exc: BaseException) -> bool:
    if not isinstance(exc, sqlite3.OperationalError):
        return False
    message = str(exc).lower()
    return any(marker in message for marker in (
        "database is busy",
        "database is locked",
        "disk i/o error",
    ))


def write_soc_alert_status_json_snapshot(
    sources: SocAlertStatusPersistenceSources,
    statuses: dict,
) -> None:
    sources.mirror_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ok": True,
        "updated_at": sources.now_iso(),
        "statuses": statuses,
    }
    tmp = sources.mirror_path.with_suffix(
        sources.mirror_path.suffix + f".{sources.uuid_hex()}.tmp"
    )
    tmp.write_text(
        json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
    )
    os.replace(tmp, sources.mirror_path)
    try:
        sources.mirror_path.chmod(0o600)
    except Exception:
        pass


def load_soc_alert_statuses_from_db(
    sources: SocAlertStatusPersistenceSources,
) -> dict:
    if not sources.db_path.exists():
        return {}
    try:
        with sources.connect_read() as conn:
            return sources.load_db(conn)
    except Exception:
        return {}


def load_soc_alert_statuses(
    sources: SocAlertStatusPersistenceSources,
) -> dict:
    """Use the SQLite authority whenever it exists; JSON is absence-only DR."""
    if sources.db_path.exists():
        return load_soc_alert_statuses_from_db(sources)
    try:
        data = json.loads(sources.mirror_path.read_text(encoding="utf-8"))
        statuses = data.get("statuses", {}) if isinstance(data, dict) else {}
        return statuses if isinstance(statuses, dict) else {}
    except Exception:
        return {}


def save_soc_alert_statuses_to_db(
    sources: SocAlertStatusPersistenceSources,
    statuses: object,
) -> None:
    """Merge an offline DR status batch without deleting unspecified groups."""
    if not sources.db_path.parent.exists():
        return
    with sources.connect_write() as conn:
        conn.execute("BEGIN IMMEDIATE")
        sources.ensure_schema(conn)
        sources.write_many(conn, statuses)


def save_soc_alert_statuses(
    sources: SocAlertStatusPersistenceSources,
    statuses: object,
) -> None:
    current = statuses if isinstance(statuses, dict) else {}
    normalized_statuses = {}
    for alert_id, raw_meta in current.items():
        meta = sources.normalize(raw_meta)
        if meta and meta["status"] != "open":
            normalized_statuses[str(alert_id)] = meta
    save_soc_alert_statuses_to_db(sources, normalized_statuses)
    write_soc_alert_status_json_snapshot(sources, normalized_statuses)


def _repository_meta(raw_meta: object, normalized: dict | None) -> object:
    if not normalized:
        return raw_meta
    current = raw_meta if isinstance(raw_meta, dict) else {}
    return {
        **normalized,
        "group_key": str(current.get("group_key") or ""),
        "updated_by": str(current.get("updated_by") or "")[:80],
    }


def write_soc_alert_status(
    sources: SocAlertStatusPersistenceSources,
    alert_id: str,
    raw_meta: object,
) -> None:
    """Commit one status and refresh its atomic mirror in one lock scope."""
    if not sources.db_path.parent.exists():
        return
    normalized = sources.normalize(raw_meta)
    repository_meta = _repository_meta(raw_meta, normalized)
    with sources.lock:
        for attempt in range(1, sources.retry_attempts + 1):
            try:
                with sources.connect_write() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    sources.ensure_schema(conn)
                    sources.write_one(conn, alert_id, repository_meta)
                break
            except sqlite3.OperationalError as exc:
                if (
                    not retryable_soc_alert_status_error(exc)
                    or attempt >= sources.retry_attempts
                ):
                    raise
                sources.sleep(sources.retry_base_seconds * attempt)
        write_soc_alert_status_json_snapshot(
            sources, load_soc_alert_statuses_from_db(sources)
        )
