"""Runtime wiring for SOC grouped-alert status persistence and projections."""
from __future__ import annotations

from typing import Any


def soc_alert_group_summary_available(runtime: Any, conn: Any) -> bool:
    """Return true when alert-store has populated the fast grouped summary."""
    return runtime.group_summary_available(runtime.soc_alert_status_store_sources(), conn)


def soc_alert_group_counts(runtime: Any, conn: Any) -> dict[str, int]:
    """Return current grouped repeat counts, keyed by group_id."""
    return runtime.load_soc_alert_group_counts(runtime.soc_alert_status_store_sources(), conn)


def soc_alert_manually_escalated_group_ids(runtime: Any, conn: Any) -> set[str]:
    """Return every dashboard alias moved manually to Incident Responder."""
    return runtime.load_manually_escalated_group_ids(
        runtime.soc_alert_status_store_sources(), conn
    )


def soc_alert_active_group_ids(
    runtime: Any,
    conn: Any,
    statuses: dict,
    manually_escalated_group_ids: set[str] | None = None,
) -> set[str]:
    """Return grouped detections currently visible in the default active view."""
    return runtime.load_active_soc_group_ids(
        runtime.soc_alert_status_store_sources(),
        conn,
        statuses,
        manually_escalated_group_ids,
    )


def soc_alert_status_store_sources(runtime: Any) -> Any:
    return runtime.SocAlertStatusStoreSources(
        table_exists=runtime.sqlite_table_exists,
        group_key_sql=runtime.soc_alert_group_key_sql,
        group_id=runtime.soc_alert_group_id,
        now_iso=runtime.now_iso_utc,
    )


def normalize_soc_group_statuses(runtime: Any, conn: Any) -> dict:
    """Load current group state and hide stale acknowledgements.

    Acknowledged detections should reappear when the matching grouped detection
    count increases. Suppressed detections remain hidden until explicitly
    exposed. Production deletion is owned by alert-store; portal reads must not
    become a second SQLite writer.
    """
    return runtime.load_soc_group_statuses(runtime.soc_alert_status_store_sources(), conn)


def soc_alert_status_persistence_sources(runtime: Any) -> Any:
    store = runtime.soc_alert_status_store_sources()
    return runtime.SocAlertStatusPersistenceSources(
        db_path=runtime.SOC_ALERT_STORE_DB,
        mirror_path=runtime.SOC_ALERT_STATUS_FILE,
        connect_read=runtime.soc_alert_db_connect,
        connect_write=runtime.soc_alert_db_write_connect,
        ensure_schema=runtime.ensure_soc_alert_status_table,
        load_db=runtime.normalize_soc_group_statuses,
        write_one=lambda conn, alert_id, meta: runtime.write_soc_group_status(
            store, conn, alert_id, meta
        ),
        write_many=lambda conn, statuses: runtime.write_soc_group_statuses(
            store, conn, statuses
        ),
        normalize=runtime.normalize_soc_alert_status_meta,
        now_iso=runtime.now_iso_utc,
        uuid_hex=lambda: runtime.uuid.uuid4().hex,
        lock=runtime.SOC_ALERT_DB_WRITE_LOCK,
        sleep=runtime.time.sleep,
        retry_attempts=runtime.SOC_ALERT_DB_WRITE_RETRY_ATTEMPTS,
        retry_base_seconds=runtime.SOC_ALERT_DB_WRITE_RETRY_BASE_SECONDS,
    )


def load_soc_alert_statuses_from_db(runtime: Any) -> dict:
    return runtime.load_persisted_soc_alert_statuses_from_db(
        runtime.soc_alert_status_persistence_sources()
    )


def write_soc_alert_status_json_snapshot(runtime: Any, statuses: dict) -> None:
    runtime.write_persisted_soc_alert_status_snapshot(
        runtime.soc_alert_status_persistence_sources(), statuses
    )


def save_soc_alert_statuses_to_db(runtime: Any, statuses: dict) -> None:
    """Persist offline DR-test state; production writes through alert-store."""
    runtime.save_persisted_soc_alert_statuses_to_db(
        runtime.soc_alert_status_persistence_sources(), statuses
    )


def load_soc_alert_statuses(runtime: Any) -> dict:
    """Load shared SOC alert status state, using JSON only if SQLite is absent."""
    return runtime.load_persisted_soc_alert_statuses(
        runtime.soc_alert_status_persistence_sources()
    )


def save_soc_alert_statuses(runtime: Any, statuses: dict) -> None:
    runtime.save_persisted_soc_alert_statuses(
        runtime.soc_alert_status_persistence_sources(), statuses
    )


def current_soc_alert_group_repeat_count(runtime: Any, alert_id: str) -> int:
    if not runtime.SOC_ALERT_STORE_DB.exists():
        return 0
    try:
        with runtime.soc_alert_db_connect() as conn:
            return int(runtime.soc_alert_group_counts(conn).get(alert_id, 0) or 0)
    except Exception:
        return 0


def write_soc_alert_status(runtime: Any, alert_id: str, meta: dict) -> None:
    """Atomically persist one analyst state change, then refresh the JSON mirror."""
    runtime.persist_soc_alert_status(
        runtime.soc_alert_status_persistence_sources(), alert_id, meta
    )


def soc_alert_status_response(runtime: Any) -> dict:
    statuses = runtime.load_soc_alert_statuses()
    try:
        with runtime.soc_alert_db_connect() as conn:
            group_counts = runtime.soc_alert_group_counts(conn)
            escalated_group_ids = runtime.soc_alert_manually_escalated_group_ids(conn)
            active_group_ids = runtime.soc_alert_active_group_ids(
                conn, statuses, escalated_group_ids
            )
    except Exception:
        return runtime.compose_status_payload(statuses)
    return runtime.compose_status_payload(
        statuses,
        group_counts=group_counts,
        escalated_group_ids=escalated_group_ids,
        active_group_ids=active_group_ids,
    )
