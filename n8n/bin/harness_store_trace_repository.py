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
        stage = _terminal_stage(status)
        with _connect(self.path) as connection:
            _admit_terminal_run(connection, run_id, status)
            reason_digest, terminal_reason = _terminal_reason(reason)
            terminal_ledger_manifest = _terminal_ledger_manifest(
                connection,
                run_id,
                status,
            )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type=f"run.{status}",
                stage=stage,
                payload=_terminal_event_payload(
                    reason,
                    reason_digest,
                    summary,
                    terminal_ledger_manifest,
                ),
                idempotency_key=f"run.terminal:{status}",
            )
            _update_terminal_run(
                connection,
                run_id=run_id,
                status=status,
                stage=stage,
                event=event,
                terminal_reason=terminal_reason,
                summary=summary,
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
            trace = _collect_trace(connection, run_id)
        return _trace_export(run_id, trace, self.verify_chain)


def _terminal_stage(status: str) -> str:
    if status not in {
        RunStatus.SUCCEEDED.value,
        RunStatus.FAILED.value,
        RunStatus.CANCELLED.value,
        RunStatus.WAITING_FOR_REVIEW.value,
    }:
        raise HarnessPolicyError("invalid terminal run status")
    if status == RunStatus.SUCCEEDED.value:
        return Stage.COMPLETE.value
    if status == RunStatus.WAITING_FOR_REVIEW.value:
        return Stage.HUMAN_REVIEW.value
    return Stage.FAILED.value


def _admit_terminal_run(connection: Any, run_id: str, status: str) -> None:
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


def _terminal_reason(reason: str) -> tuple[str, str]:
    reason_digest = digest_json(str(reason or ""))
    terminal_reason = f"sha256:{reason_digest}" if str(reason or "") else ""
    return reason_digest, terminal_reason


def _terminal_ledger_manifest(
    connection: Any,
    run_id: str,
    status: str,
) -> dict[str, Any] | None:
    if status in {
        RunStatus.SUCCEEDED.value,
        RunStatus.FAILED.value,
        RunStatus.CANCELLED.value,
    }:
        return ledger_manifest(connection, run_id)
    return None


def _terminal_event_payload(
    reason: str,
    reason_digest: str,
    summary: Mapping[str, Any] | None,
    terminal_ledger_manifest: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "reason_present": bool(str(reason or "")),
        "reason_digest": reason_digest,
        "summary": summary or {},
        **(
            {"ledger_manifest": terminal_ledger_manifest}
            if terminal_ledger_manifest is not None
            else {}
        ),
    }


def _update_terminal_run(
    connection: Any,
    *,
    run_id: str,
    status: str,
    stage: str,
    event: Mapping[str, Any],
    terminal_reason: str,
    summary: Mapping[str, Any] | None,
) -> None:
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


def _required_run(connection: Any, run_id: str) -> Any:
    run = connection.execute(
        "SELECT * FROM harness_runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    if run is None:
        raise HarnessIntegrityError("unknown harness run")
    return run


def _json_rows(
    connection: Any,
    run_id: str,
    query: str,
    source_key: str,
    projection_key: str,
) -> list[dict[str, Any]]:
    return [
        {
            **dict(row),
            projection_key: json.loads(row[source_key]),
        }
        for row in connection.execute(query, (run_id,)).fetchall()
    ]


def _rows(connection: Any, run_id: str, query: str) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, (run_id,)).fetchall()]


def _collect_trace(connection: Any, run_id: str) -> dict[str, Any]:
    return {
        "run": _required_run(connection, run_id),
        "events": _json_rows(
            connection,
            run_id,
            """SELECT * FROM harness_events
               WHERE run_id = ? ORDER BY sequence""",
            "payload_json",
            "payload",
        ),
        "evidence": _json_rows(
            connection,
            run_id,
            """SELECT * FROM harness_evidence
               WHERE run_id = ? ORDER BY evidence_ref""",
            "metadata_json",
            "metadata",
        ),
        "hypotheses": _rows(
            connection,
            run_id,
            """SELECT * FROM harness_hypotheses
               WHERE run_id = ? ORDER BY hypothesis_id""",
        ),
        "decisions": _rows(
            connection,
            run_id,
            """SELECT * FROM harness_decisions
               WHERE run_id = ? ORDER BY created_at, decision_id""",
        ),
        "model_calls": _rows(
            connection,
            run_id,
            """SELECT * FROM harness_model_calls
               WHERE run_id = ? ORDER BY created_at, call_id""",
        ),
        "tool_calls": _rows(
            connection,
            run_id,
            """SELECT * FROM harness_tool_calls
               WHERE run_id = ? ORDER BY round_number, call_id""",
        ),
        "budget_reservations": _rows(
            connection,
            run_id,
            """SELECT * FROM harness_budget_reservations
               WHERE run_id = ? ORDER BY reservation_type, reservation_id""",
        ),
    }


def _trace_export(
    run_id: str,
    trace: Mapping[str, Any],
    verify_chain: Any,
) -> dict[str, Any]:
    return {
        "schema": TRACE_SCHEMA,
        "exported_at": utc_now(),
        "run": dict(trace["run"]),
        "events": trace["events"],
        "evidence": trace["evidence"],
        "hypotheses": trace["hypotheses"],
        "decisions": trace["decisions"],
        "model_calls": trace["model_calls"],
        "tool_calls": trace["tool_calls"],
        "budget_reservations": trace["budget_reservations"],
        "integrity": verify_chain(run_id),
    }
