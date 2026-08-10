"""Hypothesis and decision write repository for the harness."""
from __future__ import annotations

import re
from typing import Any, Mapping

from harness_contracts import (
    _redacted_string,
    bounded_metadata,
    hypothesis_manifest_digest,
)
from harness_policy import (
    HarnessIntegrityError,
    HarnessPolicyError,
    MAX_DECISION_EVIDENCE_REFS,
    MAX_HYPOTHESES,
    Stage,
    _valid_identifier,
    canonical_json,
    digest_json,
    utc_now,
)
from harness_store_foundation import _connect


class HarnessStoreDecisionRepository:
    """Atomic, evidence-bound hypothesis and decision writes."""

    def record_hypotheses(
        self,
        run_id: str,
        hypotheses: Any,
        *,
        revision: int,
    ) -> dict[str, int]:
        if not isinstance(hypotheses, list):
            return {"accepted": 0, "rejected": 0}
        accepted = 0
        rejected = 0
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            known_refs = {
                str(row["evidence_ref"])
                for row in connection.execute(
                    "SELECT evidence_ref FROM harness_evidence WHERE run_id = ?",
                    (run_id,),
                ).fetchall()
            }
            for index, item in enumerate(hypotheses[:MAX_HYPOTHESES], 1):
                if not isinstance(item, dict):
                    rejected += 1
                    continue
                hypothesis_id = re.sub(
                    r"[^A-Za-z0-9._-]+",
                    "-",
                    str(item.get("id") or f"hypothesis-{index}"),
                ).strip("-")[:64]
                statement = _redacted_string(
                    str(item.get("statement") or "").strip(),
                    4_000,
                )
                status = str(item.get("status") or "unresolved").strip().lower()
                if (
                    not hypothesis_id
                    or not statement
                    or status not in {"supported", "contradicted", "unresolved"}
                ):
                    rejected += 1
                    continue
                supporting = [
                    str(ref)[:512]
                    for ref in (
                        item.get("supporting_evidence")
                        if isinstance(item.get("supporting_evidence"), list)
                        else []
                    )[:MAX_DECISION_EVIDENCE_REFS]
                    if str(ref) in known_refs
                ]
                contradicting = [
                    str(ref)[:512]
                    for ref in (
                        item.get("contradicting_evidence")
                        if isinstance(item.get("contradicting_evidence"), list)
                        else []
                    )[:MAX_DECISION_EVIDENCE_REFS]
                    if str(ref) in known_refs
                ]
                # A model may leave a hypothesis unresolved without citations,
                # but supported/contradicted states require matching provenance.
                if (
                    status == "supported"
                    and not supporting
                    or status == "contradicted"
                    and not contradicting
                ):
                    status = "unresolved"
                supporting_json = canonical_json(supporting)
                contradicting_json = canonical_json(contradicting)
                next_discriminator = _redacted_string(
                    item.get("next_discriminator"),
                    2_000,
                )
                statement_digest = digest_json(statement)
                normalized_revision = max(0, int(revision))
                existing = connection.execute(
                    """
                    SELECT statement_digest, status, supporting_refs_json,
                           contradicting_refs_json, next_discriminator, revision
                    FROM harness_hypotheses
                    WHERE run_id = ? AND hypothesis_id = ?
                    """,
                    (run_id, hypothesis_id),
                ).fetchone()
                content = (
                    statement_digest,
                    status,
                    supporting_json,
                    contradicting_json,
                    next_discriminator,
                )
                if existing is not None:
                    existing_content = tuple(existing)[:5]
                    existing_revision = int(existing["revision"])
                    if normalized_revision < existing_revision:
                        raise HarnessIntegrityError(
                            "hypothesis revision cannot move backwards"
                        )
                    if (
                        normalized_revision == existing_revision
                        and content != existing_content
                    ):
                        raise HarnessIntegrityError(
                            "hypothesis revision collides with different content"
                        )
                connection.execute(
                    """
                    INSERT INTO harness_hypotheses(
                        run_id, hypothesis_id, statement, statement_digest,
                        status, supporting_refs_json, contradicting_refs_json,
                        next_discriminator, revision, updated_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(run_id, hypothesis_id) DO UPDATE SET
                        statement = excluded.statement,
                        statement_digest = excluded.statement_digest,
                        status = excluded.status,
                        supporting_refs_json = excluded.supporting_refs_json,
                        contradicting_refs_json = excluded.contradicting_refs_json,
                        next_discriminator = excluded.next_discriminator,
                        revision = excluded.revision,
                        updated_at = excluded.updated_at
                    WHERE excluded.revision > harness_hypotheses.revision
                    """,
                    (
                        run_id,
                        hypothesis_id,
                        statement,
                        statement_digest,
                        status,
                        supporting_json,
                        contradicting_json,
                        next_discriminator,
                        normalized_revision,
                        utc_now(),
                    ),
                )
                accepted += 1
            manifest_digest = hypothesis_manifest_digest(
                connection.execute(
                    """
                    SELECT hypothesis_id, statement_digest, status,
                           supporting_refs_json, contradicting_refs_json,
                           next_discriminator, revision
                    FROM harness_hypotheses
                    WHERE run_id = ?
                    ORDER BY hypothesis_id
                    """,
                    (run_id,),
                ).fetchall()
            )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="hypotheses.updated",
                stage=Stage.EVIDENCE_SYNTHESIS.value,
                payload={
                    "accepted": accepted,
                    "rejected": rejected,
                    "revision": revision,
                    "manifest_digest": manifest_digest,
                },
                idempotency_key=f"hypotheses:{revision}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=Stage.EVIDENCE_SYNTHESIS.value,
                updated_at=event["created_at"],
            )
            connection.commit()
        self._audit_event(event)
        return {"accepted": accepted, "rejected": rejected}

    def record_decision(
        self,
        run_id: str,
        *,
        decision_id: str,
        decision_type: str,
        response: Mapping[str, Any],
        stage: str = Stage.EVIDENCE_SYNTHESIS.value,
    ) -> None:
        try:
            Stage(stage)
        except ValueError as exc:
            raise HarnessPolicyError("invalid decision stage") from exc
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
        try:
            confidence_score = float(response.get("confidence_score"))
            if not 0.0 <= confidence_score <= 1.0:
                confidence_score = None
        except (TypeError, ValueError, OverflowError):
            confidence_score = None
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
                # Keep the selected fields queryable while binding this ledger
                # row to the exact canonical response supplied at this stage.
                "response_digest": digest_json(response),
            }
        )
        decision_id = _valid_identifier(decision_id, "decision_id", 128)
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT payload_json, evidence_refs_json, rationale_digest
                FROM harness_decisions
                WHERE run_id = ? AND decision_id = ?
                """,
                (run_id, decision_id),
            ).fetchone()
            values = (
                canonical_json(payload),
                canonical_json(evidence_refs),
                digest_json(rationale),
            )
            if existing is not None:
                if tuple(existing) != values:
                    raise HarnessIntegrityError(
                        "decision_id collides with different decision content"
                    )
            else:
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
                        confidence_score,
                        values[1],
                        values[2],
                        values[0],
                        utc_now(),
                    ),
                )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="decision.recorded",
                stage=stage,
                payload={
                    "decision_id": decision_id,
                    "decision_type": decision_type,
                    "outcome": response.get("detection_outcome"),
                    "confidence_score": confidence_score,
                    "evidence_ref_count": len(evidence_refs),
                    "rationale_digest": values[2],
                    "response_digest": payload["response_digest"],
                },
                idempotency_key=f"decision:{decision_id}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=stage,
                updated_at=event["created_at"],
            )
            connection.commit()
        self._audit_event(event)
