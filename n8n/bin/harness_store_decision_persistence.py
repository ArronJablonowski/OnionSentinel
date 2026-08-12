"""Atomic bounded decision-ledger projection and persistence."""
from __future__ import annotations

from typing import Any, Callable, Mapping

from harness_contracts import bounded_metadata
from harness_policy import (
    HarnessIntegrityError,
    HarnessPolicyError,
    MAX_DECISION_EVIDENCE_REFS,
    Stage,
    _valid_identifier,
    canonical_json,
    digest_json,
    utc_now,
)


def record_decision(
    repository: Any,
    run_id: str,
    *,
    decision_id: str,
    decision_type: str,
    response: Mapping[str, Any],
    stage: str,
    connect: Callable[[Any], Any],
) -> None:
    """Persist one bounded immutable decision and event atomically."""
    _validate_stage(stage)
    projection = _decision_projection(response)
    decision_id = _valid_identifier(decision_id, "decision_id", 128)
    with connect(repository.path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _persist_decision(
            connection,
            run_id=run_id,
            decision_id=decision_id,
            decision_type=decision_type,
            response=response,
            projection=projection,
        )
        event = _append_decision_event(
            repository,
            connection,
            run_id=run_id,
            decision_id=decision_id,
            decision_type=decision_type,
            response=response,
            stage=stage,
            projection=projection,
        )
        repository._update_run_stage_tx(
            connection,
            run_id=run_id,
            stage=stage,
            updated_at=event["created_at"],
        )
        connection.commit()
    repository._audit_event(event)


def _validate_stage(stage: str) -> None:
    try:
        Stage(stage)
    except ValueError as exc:
        raise HarnessPolicyError("invalid decision stage") from exc


def _decision_projection(response: Mapping[str, Any]) -> dict[str, Any]:
    evidence_refs = [
        str(item)[:512]
        for item in (
            response.get("evidence_used")
            if isinstance(response.get("evidence_used"), list)
            else []
        )[:MAX_DECISION_EVIDENCE_REFS]
    ]
    rationale = " ".join(
        str(response.get(key) or "")
        for key in (
            "executive_summary",
            "detection_outcome_reasoning",
            "tuning_reason",
        )
    )[:12_000]
    confidence_score = _confidence_score(response)
    payload = bounded_metadata(
        {
            **{
                key: response.get(key)
                for key in (
                    "event_status",
                    "detection_validity",
                    "activity_disposition",
                    "handling",
                    "duplicate_of",
                    "detection_outcome",
                    "confidence",
                    "confidence_score",
                    "escalation_needed",
                    "final_disposition_status",
                    "tuning_recommendation",
                )
            },
            "response_digest": digest_json(response),
        }
    )
    values = (
        canonical_json(payload),
        canonical_json(evidence_refs),
        digest_json(rationale),
    )
    return {
        "evidence_refs": evidence_refs,
        "confidence_score": confidence_score,
        "payload": payload,
        "values": values,
    }


def _confidence_score(response: Mapping[str, Any]) -> float | None:
    try:
        confidence_score = float(response.get("confidence_score"))
        if not 0.0 <= confidence_score <= 1.0:
            return None
        return confidence_score
    except (TypeError, ValueError, OverflowError):
        return None


def _persist_decision(
    connection: Any,
    *,
    run_id: str,
    decision_id: str,
    decision_type: str,
    response: Mapping[str, Any],
    projection: Mapping[str, Any],
) -> None:
    existing = connection.execute(
        """
        SELECT payload_json, evidence_refs_json, rationale_digest
        FROM harness_decisions
        WHERE run_id = ? AND decision_id = ?
        """,
        (run_id, decision_id),
    ).fetchone()
    values = projection["values"]
    if existing is not None:
        if tuple(existing) != values:
            raise HarnessIntegrityError(
                "decision_id collides with different decision content"
            )
        return
    connection.execute(
        """
        INSERT INTO harness_decisions(
            run_id, decision_id, decision_type, status, outcome,
            confidence_score, evidence_refs_json, rationale_digest,
            payload_json, created_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            decision_id,
            str(decision_type or "")[:80],
            str(response.get("final_disposition_status") or "")[:80],
            str(response.get("detection_outcome") or "")[:80],
            projection["confidence_score"],
            values[1],
            values[2],
            values[0],
            utc_now(),
        ),
    )


def _append_decision_event(
    repository: Any,
    connection: Any,
    *,
    run_id: str,
    decision_id: str,
    decision_type: str,
    response: Mapping[str, Any],
    stage: str,
    projection: Mapping[str, Any],
) -> dict[str, Any]:
    values = projection["values"]
    return repository._append_event_tx(
        connection,
        run_id=run_id,
        event_type="decision.recorded",
        stage=stage,
        payload={
            "decision_id": decision_id,
            "decision_type": decision_type,
            "outcome": response.get("detection_outcome"),
            "confidence_score": projection["confidence_score"],
            "evidence_ref_count": len(projection["evidence_refs"]),
            "rationale_digest": values[2],
            "response_digest": projection["payload"]["response_digest"],
        },
        idempotency_key=f"decision:{decision_id}",
    )
