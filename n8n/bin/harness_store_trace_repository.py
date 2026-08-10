"""Terminal state, snapshot, chain verification, and trace export repository."""
from __future__ import annotations

import hmac
import hashlib
import json
from typing import Any, Mapping

from harness_contracts import (
    SUPPORTED_LEDGER_MANIFEST_SCHEMAS,
    bounded_metadata,
    hypothesis_manifest_digest,
    ledger_manifest,
)
from harness_policy import (
    HARNESS_SCHEMA,
    LEDGER_MANIFEST_SCHEMA_V1,
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
        with _connect(self.path) as connection:
            run = connection.execute(
                "SELECT status FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise HarnessIntegrityError("unknown harness run")
            rows = connection.execute(
                """
                SELECT * FROM harness_events
                WHERE run_id = ?
                ORDER BY sequence
                """,
                (run_id,),
            ).fetchall()
            actual_ledger_manifests = {
                schema: ledger_manifest(
                    connection,
                    run_id,
                    schema=schema,
                )
                for schema in SUPPORTED_LEDGER_MANIFEST_SCHEMAS
            }
            hypothesis_rows = connection.execute(
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
        previous = "0" * 64
        errors: list[str] = []
        expected_sequence = 1
        for row in rows:
            payload_hash = hashlib.sha256(
                str(row["payload_json"]).encode("utf-8")
            ).hexdigest()
            body = {
                "run_id": run_id,
                "sequence": int(row["sequence"]),
                "idempotency_key": row["idempotency_key"],
                "event_type": row["event_type"],
                "stage": row["stage"],
                "created_at": row["created_at"],
                "payload_sha256": row["payload_sha256"],
                "previous_event_sha256": row["previous_event_sha256"],
            }
            expected_hash = digest_json(body)
            if int(row["sequence"]) != expected_sequence:
                errors.append(f"sequence gap at {row['sequence']}")
            if row["payload_sha256"] != payload_hash:
                errors.append(f"payload digest mismatch at {row['sequence']}")
            if row["previous_event_sha256"] != previous:
                errors.append(f"previous hash mismatch at {row['sequence']}")
            if row["event_sha256"] != expected_hash:
                errors.append(f"event hash mismatch at {row['sequence']}")
            if row["event_id"] != f"evt-{expected_hash[:32]}":
                errors.append(f"event id mismatch at {row['sequence']}")
            previous = str(row["event_sha256"])
            expected_sequence += 1
        latest_hypothesis_event = next(
            (
                row
                for row in reversed(rows)
                if row["event_type"] == "hypotheses.updated"
            ),
            None,
        )
        if latest_hypothesis_event is not None:
            try:
                payload = json.loads(latest_hypothesis_event["payload_json"])
            except (TypeError, json.JSONDecodeError):
                payload = {}
            expected_manifest = str(payload.get("manifest_digest") or "")
            actual_manifest = hypothesis_manifest_digest(hypothesis_rows)
            if not expected_manifest:
                errors.append("latest hypothesis event has no manifest digest")
            elif expected_manifest != actual_manifest:
                errors.append("hypothesis ledger manifest mismatch")
        ledger_manifest_bound = False
        ledger_manifest_schema = ""
        started_event = next(
            (
                row
                for row in rows
                if row["event_type"] == "run.started"
            ),
            None,
        )
        try:
            started_payload = (
                json.loads(started_event["payload_json"])
                if started_event is not None
                else {}
            )
        except (TypeError, json.JSONDecodeError):
            started_payload = {}
        legacy_manifest_eligible = (
            started_event is not None
            and isinstance(started_payload, dict)
            and "assigned_reviewer_route" not in started_payload
        )
        if run["status"] in {
            RunStatus.SUCCEEDED.value,
            RunStatus.FAILED.value,
            RunStatus.CANCELLED.value,
        }:
            terminal_event = next(
                (
                    row
                    for row in reversed(rows)
                    if row["event_type"] == f"run.{run['status']}"
                ),
                None,
            )
            if terminal_event is None:
                errors.append("terminal run has no matching terminal event")
            else:
                try:
                    terminal_payload = json.loads(
                        terminal_event["payload_json"]
                    )
                except (TypeError, json.JSONDecodeError):
                    terminal_payload = {}
                expected_ledger_manifest = terminal_payload.get(
                    "ledger_manifest"
                )
                if not isinstance(expected_ledger_manifest, dict):
                    errors.append(
                        "terminal ledger manifest is missing or malformed"
                    )
                else:
                    ledger_manifest_schema = str(
                        expected_ledger_manifest.get("schema") or ""
                    )
                    actual_ledger_manifest = actual_ledger_manifests.get(
                        ledger_manifest_schema
                    )
                    if (
                        ledger_manifest_schema
                        == LEDGER_MANIFEST_SCHEMA_V1
                        and not legacy_manifest_eligible
                    ):
                        errors.append(
                            "terminal ledger manifest schema downgrade"
                        )
                    elif actual_ledger_manifest is None:
                        errors.append(
                            "unsupported terminal ledger manifest schema"
                        )
                    else:
                        ledger_manifest_bound = True
                if ledger_manifest_bound:
                    if digest_json(expected_ledger_manifest) != digest_json(
                        actual_ledger_manifest
                    ):
                        errors.append("terminal ledger manifest mismatch")
        return {
            "run_id": run_id,
            "valid": not errors and bool(rows),
            "event_count": len(rows),
            "head_sha256": previous if rows else "",
            "ledger_manifest_bound": ledger_manifest_bound,
            "ledger_manifest_schema": ledger_manifest_schema,
            "errors": errors,
        }

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
