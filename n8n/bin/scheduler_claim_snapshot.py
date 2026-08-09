"""Read-only verification of server-authoritative durable claim snapshots."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClaimSnapshotPolicy:
    severity_priority: tuple[str, ...]
    stable_group_key_valid: Callable[[object], bool]


def _transition_snapshot(
    processing_transition: object,
    *,
    expected_job_type: str,
    expected_group_id: str,
    expected_job_id: int,
) -> tuple[dict[str, object], str, str]:
    payload = getattr(processing_transition, "job_payload", None)
    if not isinstance(payload, dict) or not payload:
        raise RuntimeError(
            "durable AI claim did not return its server-authoritative job identity"
        )
    _require_job_identity(
        processing_transition, expected_job_type, expected_job_id
    )
    resolved_group_id = _resolved_group_identity(
        processing_transition, payload, expected_group_id
    )
    return dict(payload), _claimed_alert_id(payload), resolved_group_id


def _require_job_identity(
    processing_transition: object,
    expected_job_type: str,
    expected_job_id: int,
) -> None:
    claimed_job_type = str(
        getattr(processing_transition, "job_type", "") or ""
    ).strip()
    try:
        claimed_job_id = int(
            getattr(processing_transition, "job_id", 0) or 0
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeError("durable AI claim job identity is invalid") from exc
    if claimed_job_type != expected_job_type or (
        expected_job_id and claimed_job_id != expected_job_id
    ):
        raise RuntimeError("durable AI claim job identity is invalid")


def _resolved_group_identity(
    processing_transition: object,
    payload: dict[str, object],
    expected_group_id: str,
) -> str:
    resolved_group_id = str(
        getattr(processing_transition, "resolved_key", "") or ""
    ).strip().lower()
    payload_group_id = str(payload.get("group_id") or "").strip().lower()
    if (
        not resolved_group_id
        or resolved_group_id != expected_group_id.strip().lower()
        or payload_group_id != resolved_group_id
    ):
        raise RuntimeError("durable AI claim group identity is invalid")
    return resolved_group_id


def _claimed_alert_id(payload: dict[str, object]) -> str:
    alert_ids = {
        str(payload.get(field) or "").strip()
        for field in ("alert_id", "representative_alert_id")
        if str(payload.get(field) or "").strip()
    }
    if len(alert_ids) != 1:
        raise RuntimeError("durable AI claim alert identity is invalid")
    return next(iter(alert_ids))


def _load_alert_snapshot(
    database_path: Path,
    alert_id: str,
) -> sqlite3.Row | None:
    try:
        connection = sqlite3.connect(
            f"file:{database_path}?mode=ro",
            uri=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            return connection.execute(
                """
                SELECT stable_group_id, stable_group_key, triage_level
                FROM alerts
                WHERE alert_id = ?
                LIMIT 1
                """,
                (alert_id,),
            ).fetchone()
        finally:
            connection.close()
    except sqlite3.Error as exc:
        raise RuntimeError(
            "durable AI claim identity verification failed"
        ) from exc


def _verified_triage_level(
    policy: ClaimSnapshotPolicy,
    payload: dict[str, object],
    alert: sqlite3.Row | None,
    resolved_group_id: str,
) -> str:
    if (
        not alert
        or str(alert["stable_group_id"] or "").strip().lower()
        != resolved_group_id
    ):
        raise RuntimeError("durable AI claim alert identity is invalid")
    if not _stable_group_key_matches(policy, payload, alert):
        raise RuntimeError("durable AI claim stable group key is invalid")
    triage_level = str(alert["triage_level"] or "").strip().lower()
    if triage_level not in policy.severity_priority:
        raise RuntimeError("durable AI claim alert identity is invalid")
    return triage_level


def _stable_group_key_matches(
    policy: ClaimSnapshotPolicy,
    payload: dict[str, object],
    alert: sqlite3.Row,
) -> bool:
    claimed_key = payload.get("stable_group_key")
    if claimed_key is None:
        return True
    return bool(
        policy.stable_group_key_valid(claimed_key)
        and policy.stable_group_key_valid(alert["stable_group_key"])
        and str(alert["stable_group_key"] or "") == claimed_key
    )


def claimed_durable_ai_job(
    policy: ClaimSnapshotPolicy,
    processing_transition: object,
    database_path: Path,
    *,
    expected_job_type: str,
    expected_group_id: str,
    expected_job_id: int = 0,
) -> tuple[dict[str, object], str, str, str]:
    """Validate and return the exact durable snapshot bound to a lease."""
    payload, alert_id, resolved_group_id = _transition_snapshot(
        processing_transition,
        expected_job_type=expected_job_type,
        expected_group_id=expected_group_id,
        expected_job_id=expected_job_id,
    )
    alert = _load_alert_snapshot(database_path, alert_id)
    triage_level = _verified_triage_level(
        policy, payload, alert, resolved_group_id
    )
    return payload, alert_id, resolved_group_id, triage_level
