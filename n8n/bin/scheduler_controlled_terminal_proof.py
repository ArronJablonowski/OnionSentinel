"""Read-only terminal database proof for controlled result recovery."""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ControlledTerminalProofSources:
    open_readonly_database: Callable[[Any], Any]
    accepted_fields_match: Callable[[Any, dict[str, Any]], bool]
    storage_canonical_digest: Callable[[object], str]
    valid_digest: Callable[[str], bool]


def _load_terminal_records(
    connection: Any,
    recovery: dict[str, Any],
) -> tuple[Any, Any, Any]:
    connection.execute("BEGIN")
    job = connection.execute(
        """
        SELECT id, status, lease_token, lease_expires_at,
               rerun_requested, payload_json
        FROM durable_jobs
        WHERE job_type = ? AND dedupe_key = ?
        """,
        (recovery["job_type"], recovery["stable_group_id"]),
    ).fetchone()
    accepted = connection.execute(
        """
        SELECT group_id, alert_id, agent_role, generated_at, model,
               model_path, detection_outcome, bluf, summary,
               confidence, artifact_path, evidence_hash, response_json
        FROM ai_analysis_runs WHERE analysis_id = ?
        """,
        (recovery["analysis_id"],),
    ).fetchone()
    incident_attempt = connection.execute(
        """
        SELECT attempt_id, run_id, case_id, group_id, status, analysis_id
        FROM incident_reanalysis_attempts WHERE analysis_id = ?
        """,
        (recovery["analysis_id"],),
    ).fetchone()
    return job, accepted, incident_attempt


def _job_matches(
    job: Any,
    payload: dict[str, Any],
    identity: dict[str, Any],
    recovery: dict[str, Any],
) -> bool:
    if not job:
        return False
    return all(
        (
            int(job["id"] or 0) == int(recovery["job_id"]),
            job["status"] == "completed",
            not job["lease_token"],
            not job["lease_expires_at"],
            int(job["rerun_requested"] or 0) == 0,
            payload.get("cohort_id") == identity["cohort_id"],
            payload.get("dispatch_id") == identity["dispatch_id"],
            payload.get("release_id") == identity["release_id"],
            payload.get("alert_id") == identity["representative_alert_id"],
            payload.get("representative_alert_id")
            == identity["representative_alert_id"],
            payload.get("group_id") == identity["stable_group_id"],
            payload.get("stable_group_id") == identity["stable_group_id"],
            payload.get("stable_group_key") == identity["stable_group_key"],
        )
    )


def _analysis_matches(
    sources: ControlledTerminalProofSources,
    accepted: Any,
    response: object,
    identity: dict[str, Any],
    recovery: dict[str, Any],
    expected_digest: str,
) -> bool:
    if not accepted or not isinstance(response, dict):
        return False
    return all(
        (
            accepted["group_id"] == identity["stable_group_id"],
            accepted["alert_id"] == identity["representative_alert_id"],
            accepted["agent_role"] == identity["agent_role"],
            sources.accepted_fields_match(
                accepted, recovery["accepted_fields"]
            ),
            response.get("_analysis_controlled_claim_sha256")
            == recovery["claim_digest"],
            sources.valid_digest(expected_digest),
            sources.storage_canonical_digest(response) == expected_digest,
        )
    )


def _attempt_matches(
    attempt: Any,
    job_payload: dict[str, Any],
    identity: dict[str, Any],
    recovery: dict[str, Any],
) -> bool:
    if recovery["job_type"] == "ai_analysis":
        return attempt is None
    if recovery["job_type"] != "incident_response_analysis" or attempt is None:
        return False
    return all(
        (
            attempt["attempt_id"] == identity["reanalysis_attempt_id"],
            attempt["run_id"] == job_payload.get("reanalysis_run_id"),
            attempt["case_id"] == job_payload.get("case_id"),
            attempt["group_id"] == identity["stable_group_id"],
            attempt["status"] == "completed",
            attempt["analysis_id"] == recovery["analysis_id"],
        )
    )


def prove_controlled_terminal_success(
    sources: ControlledTerminalProofSources,
    database_path: Any,
    recovery: dict[str, Any],
) -> bool:
    """Prove a lost completion response from immutable read-only DB state."""
    try:
        connection = sources.open_readonly_database(database_path)
        try:
            job, accepted, attempt = _load_terminal_records(
                connection, recovery
            )
        finally:
            connection.close()
        job_payload = json.loads(str(job["payload_json"])) if job else {}
        response = (
            json.loads(str(accepted["response_json"])) if accepted else {}
        )
    except (
        OSError,
        sqlite3.Error,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        return False
    identity = recovery["identity"]
    expected_digest = str(
        recovery.get("stored_response_digest")
        or recovery.get("stored_response_fallback_digest")
        or recovery["response_digest"]
    ).lower()
    return all(
        (
            _job_matches(job, job_payload, identity, recovery),
            _analysis_matches(
                sources,
                accepted,
                response,
                identity,
                recovery,
                expected_digest,
            ),
            _attempt_matches(attempt, job_payload, identity, recovery),
        )
    )
