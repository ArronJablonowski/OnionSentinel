"""Terminal state, snapshot, chain verification, and trace export repository."""
from __future__ import annotations

import json
from typing import Any, Mapping

from harness_contracts import (
    bounded_metadata,
    ledger_manifest,
)
from harness_policy import (
    HARNESS_SCHEMA,
    TRACE_SCHEMA,
    HarnessIntegrityError,
    HarnessPolicyError,
    RunStatus,
    Stage,
    canonical_json,
    digest_json,
    utc_now,
)
from harness_store_foundation import _connect
from harness_store_trace_verification import verify_trace_chain


class HarnessStoreTraceRepository:
    """Atomic terminal state plus read-only snapshot and trace integrity."""

    def finish(
        self,
        run_id: str,
        *,
        status: str,
        reason: str = "",
        summary: Mapping[str, Any] | None = None,
    ) -> None:
        if status not in {
            RunStatus.SUCCEEDED.value,
            RunStatus.FAILED.value,
            RunStatus.CANCELLED.value,
            RunStatus.WAITING_FOR_REVIEW.value,
        }:
            raise HarnessPolicyError("invalid terminal run status")
        stage = (
            Stage.COMPLETE.value
            if status == RunStatus.SUCCEEDED.value
            else Stage.HUMAN_REVIEW.value
            if status == RunStatus.WAITING_FOR_REVIEW.value
            else Stage.FAILED.value
        )
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT status FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if current is None:
                raise HarnessIntegrityError("unknown harness run")
            if current["status"] not in {
                RunStatus.RUNNING.value,
                RunStatus.WAITING_FOR_REVIEW.value,
                status,
            }:
                raise HarnessIntegrityError("run already has a different terminal status")
            reason_digest = digest_json(str(reason or ""))
            terminal_reason = (
                f"sha256:{reason_digest}" if str(reason or "") else ""
            )
            terminal_ledger_manifest = (
                ledger_manifest(connection, run_id)
                if status
                in {
                    RunStatus.SUCCEEDED.value,
                    RunStatus.FAILED.value,
                    RunStatus.CANCELLED.value,
                }
                else None
            )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type=f"run.{status}",
                stage=stage,
                payload={
                    "reason_present": bool(str(reason or "")),
                    "reason_digest": reason_digest,
                    "summary": summary or {},
                    **(
                        {"ledger_manifest": terminal_ledger_manifest}
                        if terminal_ledger_manifest is not None
                        else {}
                    ),
                },
                idempotency_key=f"run.terminal:{status}",
            )
            connection.execute(
                """
                UPDATE harness_runs
                SET status = ?, stage = ?, completed_at = ?, updated_at = ?,
                    terminal_reason = ?, summary_json = ?,
                    revision = revision + 1
                WHERE run_id = ?
                """,
                (
                    status,
                    stage,
                    event["created_at"],
                    event["created_at"],
                    terminal_reason,
                    canonical_json(bounded_metadata(summary or {})),
                    run_id,
                ),
            )
            connection.commit()
        self._audit_event(event)

    def snapshot(self, run_id: str) -> dict[str, Any]:
        with _connect(self.path) as connection:
            run = connection.execute(
                "SELECT * FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise HarnessIntegrityError("unknown harness run")
            counts = connection.execute(
                """
                SELECT
                  (SELECT COUNT(*) FROM harness_events WHERE run_id = ?) events,
                  (SELECT COUNT(*) FROM harness_evidence WHERE run_id = ?) evidence,
                  (SELECT COUNT(*) FROM harness_hypotheses WHERE run_id = ?) hypotheses,
                  (SELECT COUNT(*) FROM harness_decisions WHERE run_id = ?) decisions,
                  (SELECT COUNT(*) FROM harness_model_calls WHERE run_id = ?) model_calls,
                  (SELECT COUNT(*) FROM harness_tool_calls WHERE run_id = ?) tool_calls
                """,
                (run_id, run_id, run_id, run_id, run_id, run_id),
            ).fetchone()
            return {
                **dict(run),
                "counts": dict(counts),
            }

    def verify_chain(self, run_id: str) -> dict[str, Any]:
        return verify_trace_chain(
            self.path,
            run_id,
            connection_factory=_connect,
        )

    def export_trace(self, run_id: str) -> dict[str, Any]:
        with _connect(self.path) as connection:
            run = connection.execute(
                "SELECT * FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise HarnessIntegrityError("unknown harness run")
            events = [
                {
                    **dict(row),
                    "payload": json.loads(row["payload_json"]),
                }
                for row in connection.execute(
                    """
                    SELECT * FROM harness_events
                    WHERE run_id = ? ORDER BY sequence
                    """,
                    (run_id,),
                ).fetchall()
            ]
            evidence = [
                {
                    **dict(row),
                    "metadata": json.loads(row["metadata_json"]),
                }
                for row in connection.execute(
                    """
                    SELECT * FROM harness_evidence
                    WHERE run_id = ? ORDER BY evidence_ref
                    """,
                    (run_id,),
                ).fetchall()
            ]
            hypotheses = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_hypotheses
                    WHERE run_id = ? ORDER BY hypothesis_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            decisions = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_decisions
                    WHERE run_id = ? ORDER BY created_at, decision_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            model_calls = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_model_calls
                    WHERE run_id = ? ORDER BY created_at, call_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            tool_calls = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_tool_calls
                    WHERE run_id = ? ORDER BY round_number, call_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
            budget_reservations = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM harness_budget_reservations
                    WHERE run_id = ?
                    ORDER BY reservation_type, reservation_id
                    """,
                    (run_id,),
                ).fetchall()
            ]
        return {
            "schema": TRACE_SCHEMA,
            "exported_at": utc_now(),
            "run": dict(run),
            "events": events,
            "evidence": evidence,
            "hypotheses": hypotheses,
            "decisions": decisions,
            "model_calls": model_calls,
            "tool_calls": tool_calls,
            "budget_reservations": budget_reservations,
            "integrity": self.verify_chain(run_id),
        }
