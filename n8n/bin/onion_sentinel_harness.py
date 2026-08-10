#!/usr/bin/env python3
"""Durable, model-neutral investigation harness for Onion Sentinel.

The harness is deliberately a trusted control-plane component. Models may
propose queries, hypotheses, memory candidates, and actions, but this module
owns policy decisions, durable run state, provenance, and audit integrity.

Version 1 is a shadow-capable runtime around the existing production runner.
It does not give a model direct shell, database, Security Onion, or credential
access. Existing typed brokers remain the only query execution boundary.
"""
from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import enum
import hashlib
import hmac
import importlib.util
import json
import os
import re
import sqlite3
import stat
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

HARNESS_SOURCE_DIR = Path(__file__).resolve().parent
if str(HARNESS_SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(HARNESS_SOURCE_DIR))

try:
    from security_jsonl_log import SecurityJsonlLogger
except ModuleNotFoundError:
    _logging_spec = importlib.util.spec_from_file_location(
        "security_jsonl_log",
        Path(__file__).with_name("security_jsonl_log.py"),
    )
    if _logging_spec is None or _logging_spec.loader is None:
        raise
    _logging_module = importlib.util.module_from_spec(_logging_spec)
    sys.modules.setdefault("security_jsonl_log", _logging_module)
    _logging_spec.loader.exec_module(_logging_module)
    SecurityJsonlLogger = _logging_module.SecurityJsonlLogger


from harness_policy import (
    HARNESS_SCHEMA,
    POLICY_SCHEMA,
    TRACE_SCHEMA,
    LEDGER_MANIFEST_SCHEMA_V1,
    LEDGER_MANIFEST_SCHEMA,
    SQL_SCHEMA_VERSION,
    DEFAULT_POLICY_PATH,
    DEFAULT_DB_PATH,
    DEFAULT_HARNESS_LOG_PATH,
    MAX_POLICY_BYTES,
    MAX_EVENT_PAYLOAD_BYTES,
    MAX_EVENT_STRING,
    MAX_EVENT_ITEMS,
    MAX_EVIDENCE_REFS,
    MAX_HYPOTHESES,
    MAX_DECISION_EVIDENCE_REFS,
    IDENTIFIER_RE,
    DIGEST_RE,
    INVESTIGATION_SKILL_ADVISORY_MODE,
    INVESTIGATION_SKILL_UNAVAILABLE_MODE,
    MAX_ATTESTED_INVESTIGATION_SKILLS,
    INVESTIGATION_SKILL_ATTESTATION_KEYS,
    EXTERNAL_AGENT_HARNESS_PROVIDERS,
    external_agent_harness_provider,
    should_start_onion_sentinel_harness,
    HarnessError,
    HarnessPolicyError,
    HarnessIntegrityError,
    AgentRole,
    TaskKind,
    RunStatus,
    Stage,
    TrustTier,
    READ_ONLY_CAPABILITIES,
    MUTATING_CAPABILITIES,
    SENSITIVE_ACTIVE_CAPABILITIES,
    APPROVAL_GATED_CAPABILITIES,
    ALL_CAPABILITIES,
    QUERY_BACKEND_CAPABILITIES,
    query_backend_capability,
    query_backend_is_approval_gated,
    DEFAULT_ROLE_CAPABILITIES,
    DEFAULT_BUDGETS,
    MIN_BUDGETS,
    MAX_BUDGETS,
    REQUIRED_POLICY_FIELDS,
    REQUIRED_MEMORY_FIELDS,
    SECRET_KEY_RE,
    SECRET_VALUE_PATTERNS,
    utc_now,
    canonical_json,
    digest_json,
    _valid_identifier,
    _model_route,
    _digest_or_hash,
    _nonnegative_int,
    PolicyDecision,
    policy_decision_is_effective,
    HarnessPolicy,
    load_policy,
    task_kind_for_role,
)


from harness_query_contract import (
    RETURNED_COUNT_KEYS,
    observed_returned_count,
    observed_truncation,
    QUERY_SUCCESS_STATUSES,
    SECURITY_ONION_QUERY_STATUSES,
    resolve_query_binding,
)

from harness_contracts import (
    sanitize_metadata,
    bounded_metadata,
    investigation_skill_selection_attestation,
    hypothesis_manifest_digest,
    LEDGER_TABLE_ORDERS,
    RUN_IDENTITY_COLUMNS,
    LEGACY_RUN_IDENTITY_COLUMNS_V1,
    SUPPORTED_LEDGER_MANIFEST_SCHEMAS,
    ledger_manifest,
    approximate_evidence_rows,
    JobEnvelope,
    _redacted_string,
)


from harness_store_foundation import (
    HarnessStoreFoundation,
    _connect,
    _probe_existing_schema_version,
    _secure_sqlite_files,
)


class HarnessStore(HarnessStoreFoundation):
    """Owner-only SQLite event store with per-run hash chains."""

    def start_run(
        self,
        envelope: JobEnvelope,
        policy: HarnessPolicy,
    ) -> dict[str, Any]:
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM harness_runs WHERE run_id = ?",
                (envelope.run_id,),
            ).fetchone()
            if existing is not None:
                if (
                    existing["job_digest"] != envelope.job_digest
                    or existing["policy_digest"] != policy.digest
                ):
                    raise HarnessIntegrityError(
                        "run_id collides with a different job or policy"
                    )
                connection.commit()
                return dict(existing)
            connection.execute(
                """
                INSERT INTO harness_runs(
                    run_id, trace_id, correlation_id, case_id, alert_id, role,
                    task_kind, status, stage, assigned_route,
                    assigned_reviewer_route, prompt_digest,
                    evidence_manifest_digest, configuration_digest,
                    policy_version, policy_digest, policy_mode, parent_run_id,
                    job_digest, started_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    envelope.run_id,
                    envelope.trace_id,
                    envelope.correlation_id,
                    envelope.case_id,
                    envelope.alert_id,
                    envelope.role,
                    envelope.task_kind,
                    RunStatus.RUNNING.value,
                    Stage.INTAKE.value,
                    envelope.assigned_route,
                    envelope.assigned_reviewer_route,
                    envelope.prompt_digest,
                    envelope.evidence_manifest_digest,
                    envelope.configuration_digest,
                    policy.version,
                    policy.digest,
                    policy.mode,
                    envelope.parent_run_id,
                    envelope.job_digest,
                    envelope.created_at,
                    envelope.created_at,
                ),
            )
            event = self._append_event_tx(
                connection,
                run_id=envelope.run_id,
                event_type="run.started",
                stage=Stage.INTAKE.value,
                payload={
                    "schema": HARNESS_SCHEMA,
                    "trace_id": envelope.trace_id,
                    "correlation_id": envelope.correlation_id,
                    "case_id": envelope.case_id,
                    "alert_id": envelope.alert_id,
                    "role": envelope.role,
                    "task_kind": envelope.task_kind,
                    "assigned_route": envelope.assigned_route,
                    "assigned_reviewer_route": (
                        envelope.assigned_reviewer_route
                    ),
                    "prompt_digest": envelope.prompt_digest,
                    "evidence_manifest_digest": envelope.evidence_manifest_digest,
                    "configuration_digest": envelope.configuration_digest,
                    "skill_selection_attestation": (
                        envelope.skill_selection_attestation
                    ),
                    "job_digest": envelope.job_digest,
                    "policy_version": policy.version,
                    "policy_digest": policy.digest,
                    "policy_mode": policy.mode,
                },
                idempotency_key="run.started",
                created_at=envelope.created_at,
            )
            connection.commit()
        self._audit_event(event)
        return self.snapshot(envelope.run_id)

    def append_event(
        self,
        run_id: str,
        event_type: str,
        stage: str,
        payload: Mapping[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        try:
            Stage(stage)
        except ValueError as exc:
            raise HarnessPolicyError(f"unknown harness stage: {stage}") from exc
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_mutable_run_tx(connection, run_id)
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type=event_type,
                stage=stage,
                payload=payload,
                idempotency_key=idempotency_key,
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=stage,
                updated_at=event["created_at"],
            )
            connection.commit()
        self._audit_event(event)
        return event

    def reserve_budget_operation(
        self,
        run_id: str,
        *,
        reservation_type: str,
        reservation_id: str,
        amount: int,
        max_total: int,
        max_operations: int,
        enforce: bool,
        preexisting_violations: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Atomically reserve bounded work before a model or broker executes."""
        if reservation_type not in {"model-call", "query-round"}:
            raise HarnessPolicyError("unknown budget reservation type")
        reservation_id = _valid_identifier(
            reservation_id,
            "budget reservation_id",
            128,
        )
        amount = max(0, int(amount))
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_mutable_run_tx(connection, run_id)
            existing = connection.execute(
                """
                SELECT amount
                FROM harness_budget_reservations
                WHERE run_id = ? AND reservation_type = ?
                  AND reservation_id = ?
                """,
                (run_id, reservation_type, reservation_id),
            ).fetchone()
            totals = connection.execute(
                """
                SELECT COUNT(*) operation_count, COALESCE(SUM(amount), 0) total
                FROM harness_budget_reservations
                WHERE run_id = ? AND reservation_type = ?
                """,
                (run_id, reservation_type),
            ).fetchone()
            if existing is not None:
                if int(existing["amount"]) != amount:
                    raise HarnessIntegrityError(
                        "budget reservation collides with different amount"
                    )
                connection.commit()
                return {
                    "reserved": True,
                    "existing": True,
                    "operation_count": int(totals["operation_count"]),
                    "total": int(totals["total"]),
                    "violations": sorted(set(preexisting_violations)),
                }
            proposed_operations = int(totals["operation_count"]) + 1
            proposed_total = int(totals["total"]) + amount
            violations = list(preexisting_violations)
            if proposed_operations > int(max_operations):
                violations.append(
                    "max_model_calls"
                    if reservation_type == "model-call"
                    else "max_query_rounds"
                )
            if proposed_total > int(max_total):
                violations.append(
                    "max_model_calls"
                    if reservation_type == "model-call"
                    else "max_queries_total"
                )
            reserved = not violations or not enforce
            if reserved:
                connection.execute(
                    """
                    INSERT INTO harness_budget_reservations(
                        run_id, reservation_type, reservation_id,
                        amount, created_at
                    ) VALUES(?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        reservation_type,
                        reservation_id,
                        amount,
                        utc_now(),
                    ),
                )
            connection.commit()
        return {
            "reserved": reserved,
            "existing": False,
            "operation_count": proposed_operations,
            "total": proposed_total,
            "violations": sorted(set(violations)),
        }

    def transition(
        self,
        run_id: str,
        stage: str,
        *,
        route: str = "",
        reason: str = "",
        ordinal: int = 0,
    ) -> dict[str, Any]:
        try:
            Stage(stage)
        except ValueError as exc:
            raise HarnessPolicyError(f"unknown harness stage: {stage}") from exc
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = connection.execute(
                "SELECT status, active_route FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if run is None:
                raise HarnessIntegrityError("unknown harness run")
            if run["status"] not in {
                RunStatus.RUNNING.value,
                RunStatus.WAITING_FOR_REVIEW.value,
            }:
                raise HarnessIntegrityError(
                    "cannot transition a terminal harness run"
                )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="run.stage",
                stage=stage,
                payload={
                    "active_route": route[:256],
                    "reason": reason[:500],
                },
                idempotency_key=f"stage:{stage}:{ordinal}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=stage,
                updated_at=event["created_at"],
                active_route=(
                    route[:256] if route else str(run["active_route"])
                ),
            )
            connection.commit()
        self._audit_event(event)
        return event

    def register_evidence(
        self,
        run_id: str,
        *,
        evidence_ref: str,
        source: str,
        source_class: str,
        trust_tier: str,
        corroborating: bool,
        status: str = "",
        evidence_digest: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        evidence_ref = str(evidence_ref or "").strip()[:512]
        if not evidence_ref:
            raise HarnessIntegrityError("evidence reference is required")
        try:
            TrustTier(trust_tier)
        except ValueError as exc:
            raise HarnessIntegrityError("unknown evidence trust tier") from exc
        digest = _digest_or_hash(evidence_digest or {
            "ref": evidence_ref,
            "source": source,
            "source_class": source_class,
            "status": status,
            "metadata": metadata or {},
        })
        metadata_json = canonical_json(bounded_metadata(metadata or {}))
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_mutable_run_tx(connection, run_id)
            existing = connection.execute(
                """
                SELECT evidence_digest FROM harness_evidence
                WHERE run_id = ? AND evidence_ref = ?
                """,
                (run_id, evidence_ref),
            ).fetchone()
            if existing is not None:
                if existing["evidence_digest"] != digest:
                    raise HarnessIntegrityError(
                        "immutable evidence reference collides with different content"
                    )
                connection.commit()
                return
            connection.execute(
                """
                INSERT INTO harness_evidence(
                    run_id, evidence_ref, source, source_class, trust_tier,
                    corroborating, status, evidence_digest, observed_at,
                    metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    evidence_ref,
                    str(source or "")[:160],
                    str(source_class or "unknown")[:160],
                    trust_tier,
                    1 if corroborating else 0,
                    str(status or "")[:64],
                    digest,
                    utc_now(),
                    metadata_json,
                ),
            )
            connection.commit()

    def register_evidence_contract(
        self,
        run_id: str,
        contract: Mapping[str, Any] | None,
    ) -> int:
        references = (
            contract.get("references")
            if isinstance(contract, Mapping)
            else None
        )
        if not isinstance(references, list):
            return 0
        count = 0
        for item in references[:MAX_EVIDENCE_REFS]:
            if not isinstance(item, dict) or not item.get("ref"):
                continue
            source = str(item.get("source") or "unknown")
            source_class = str(item.get("source_class") or source)
            trust = (
                TrustTier.MEMORY_LEAD.value
                if source_class in {"agent_memory", "shared_memory", "memory"}
                else TrustTier.EXTERNAL_INTELLIGENCE.value
                if source_class == "public_enrichment"
                else TrustTier.TRUSTED_COLLECTOR.value
            )
            self.register_evidence(
                run_id,
                evidence_ref=str(item["ref"]),
                source=source,
                source_class=source_class,
                trust_tier=trust,
                corroborating=item.get("corroborating") is True,
                status=str(item.get("status") or ""),
                evidence_digest=str(item.get("evidence_digest") or ""),
                metadata={"returned": item.get("returned")},
            )
            count += 1
        manifest_digest = digest_json(contract or {})
        self.append_event(
            run_id,
            "evidence.catalogued",
            Stage.CONTEXT_ASSEMBLY.value,
            {
                "contract_schema": str(
                    (contract or {}).get("schema") if isinstance(contract, Mapping) else ""
                ),
                "references_registered": count,
                "manifest_digest": manifest_digest,
            },
            idempotency_key=f"evidence.catalogued:{manifest_digest[:24]}",
        )
        return count

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

    def record_model_call(
        self,
        run_id: str,
        *,
        call_id: str,
        purpose: str,
        requested_route: str,
        response: Mapping[str, Any],
        independent_review: bool,
        input_digest: str,
        duration_ms: int,
        status: str = "completed",
    ) -> None:
        call_id = _valid_identifier(call_id, "model call_id", 128)
        output_digest = digest_json(response)
        values = (
            _redacted_string(purpose, 160),
            str(requested_route or "")[:256],
            str(response.get("_analysis_model") or "")[:256],
            str(response.get("_analysis_model_path") or "")[:80],
            str(response.get("_analysis_provider") or "")[:80],
            str(response.get("_analysis_harness") or "")[:80],
            1 if independent_review else 0,
            str(status or "")[:80],
            _digest_or_hash(input_digest),
            output_digest,
            max(0, int(duration_ms)),
            utc_now(),
        )
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT purpose, requested_route, observed_model,
                       observed_model_path, observed_provider,
                       observed_harness, independent_review, status,
                       input_digest, output_digest, duration_ms, created_at
                FROM harness_model_calls
                WHERE run_id = ? AND call_id = ?
                """,
                (run_id, call_id),
            ).fetchone()
            if existing is not None:
                # Wall-clock duration and creation time are observational. The
                # immutable input/output identities are the collision boundary.
                if tuple(existing)[:10] != values[:10]:
                    raise HarnessIntegrityError(
                        "model call_id collides with different call content"
                    )
                event_duration_ms = int(existing["duration_ms"])
            else:
                connection.execute(
                    """
                    INSERT INTO harness_model_calls(
                        run_id, call_id, purpose, requested_route,
                        observed_model, observed_model_path, observed_provider,
                        observed_harness, independent_review, status,
                        input_digest, output_digest, duration_ms, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (run_id, call_id, *values),
                )
                event_duration_ms = values[10]
            model_stage = (
                Stage.INDEPENDENT_REVIEW.value
                if independent_review
                else Stage.PRIMARY_ANALYSIS.value
            )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="model.completed",
                stage=model_stage,
                payload={
                    "call_id": call_id,
                    "purpose": purpose,
                    "requested_route": requested_route,
                    "observed_model": response.get("_analysis_model"),
                    "observed_model_path": response.get(
                        "_analysis_model_path"
                    ),
                    "observed_provider": response.get("_analysis_provider"),
                    "observed_harness": response.get("_analysis_harness"),
                    "independent_review": independent_review,
                    "input_digest": values[8],
                    "output_digest": output_digest,
                    "duration_ms": event_duration_ms,
                    "status": status,
                },
                idempotency_key=f"model.completed:{call_id}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=model_stage,
                updated_at=event["created_at"],
                active_route=str(requested_route or ""),
            )
            connection.commit()
        self._audit_event(event)

    def record_tool_call(
        self,
        run_id: str,
        *,
        call_id: str,
        round_number: int,
        backend: str,
        capability: str,
        purpose: str,
        request_digest: str,
        result_digest: str,
        status: str,
        read_only: bool,
        coverage: str,
        truncated: bool,
    ) -> None:
        call_id = _valid_identifier(call_id, "tool call_id", 128)
        values = (
            max(0, int(round_number)),
            str(backend or "")[:80],
            str(capability or "")[:120],
            _redacted_string(purpose, 500),
            _digest_or_hash(request_digest),
            _digest_or_hash(result_digest),
            str(status or "")[:80],
            1 if read_only else 0,
            str(coverage or "unknown")[:80],
            1 if truncated else 0,
            utc_now(),
        )
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT round_number, backend, capability, purpose,
                       request_digest, result_digest, status, read_only,
                       coverage, truncated, created_at
                FROM harness_tool_calls
                WHERE run_id = ? AND call_id = ?
                """,
                (run_id, call_id),
            ).fetchone()
            if existing is not None:
                if tuple(existing)[:10] != values[:10]:
                    raise HarnessIntegrityError(
                        "tool call_id collides with different call content"
                    )
            else:
                connection.execute(
                    """
                    INSERT INTO harness_tool_calls(
                        run_id, call_id, round_number, backend, capability,
                        purpose, request_digest, result_digest, status,
                        read_only, coverage, truncated, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (run_id, call_id, *values),
                )
            event = self._append_event_tx(
                connection,
                run_id=run_id,
                event_type="tool.completed",
                stage=Stage.QUERY_EXECUTION.value,
                payload={
                    "call_id": call_id,
                    "round": values[0],
                    "backend": values[1],
                    "capability": values[2],
                    "request_digest": values[4],
                    "result_digest": values[5],
                    "status": values[6],
                    "read_only": bool(values[7]),
                    "coverage": values[8],
                    "truncated": bool(values[9]),
                },
                idempotency_key=f"tool.completed:{call_id}",
            )
            self._update_run_stage_tx(
                connection,
                run_id=run_id,
                stage=Stage.QUERY_EXECUTION.value,
                updated_at=event["created_at"],
            )
            connection.commit()
        self._audit_event(event)

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


PHASE_STAGE_MAP = {
    "preparing": Stage.CONTEXT_ASSEMBLY.value,
    "primary_analysis": Stage.PRIMARY_ANALYSIS.value,
    "investigation_query_planning": Stage.QUERY_PLANNING.value,
    "investigation_query_execution": Stage.QUERY_EXECUTION.value,
    "evidence_synthesis": Stage.EVIDENCE_SYNTHESIS.value,
    "second_opinion": Stage.INDEPENDENT_REVIEW.value,
    "post_processing": Stage.POST_PROCESSING.value,
    "persistence": Stage.PERSISTENCE.value,
}


class HarnessRun:
    """Small integration surface used by the existing model runner."""

    def __init__(
        self,
        store: HarnessStore,
        envelope: JobEnvelope,
        policy: HarnessPolicy,
    ):
        self.store = store
        self.envelope = envelope
        self.policy = policy
        self.store.start_run(envelope, policy)
        with _connect(self.store.path) as connection:
            usage = connection.execute(
                """
                SELECT
                  (
                    SELECT COUNT(*)
                    FROM harness_budget_reservations
                    WHERE run_id = ? AND reservation_type = 'query-round'
                  ) query_rounds,
                  (
                    SELECT COALESCE(SUM(amount), 0)
                    FROM harness_budget_reservations
                    WHERE run_id = ? AND reservation_type = 'query-round'
                  ) queries_total,
                  (
                    SELECT COUNT(*)
                    FROM harness_budget_reservations
                    WHERE run_id = ? AND reservation_type = 'model-call'
                  ) model_calls
                """,
                (self.run_id, self.run_id, self.run_id),
            ).fetchone()
            phase_rows = connection.execute(
                """
                SELECT stage, COUNT(*) phase_count
                FROM harness_events
                WHERE run_id = ? AND event_type = 'run.stage'
                GROUP BY stage
                """,
                (self.run_id,),
            ).fetchall()
        self._phase_counts = {
            str(row["stage"]): int(row["phase_count"])
            for row in phase_rows
        }
        self._query_rounds = int(usage["query_rounds"])
        self._queries_total = int(usage["queries_total"])
        self._model_calls = int(usage["model_calls"])

    @property
    def run_id(self) -> str:
        return self.envelope.run_id

    def remaining_model_calls(self) -> int:
        """Return the hard remaining call budget for bounded orchestration."""
        return max(
            0,
            int(self.policy.budgets["max_model_calls"])
            - int(self._model_calls),
        )

    def query_rounds_used(self) -> int:
        """Return the highest globally reserved query-round ordinal."""
        return max(0, int(self._query_rounds))

    def remaining_query_rounds(self) -> int:
        """Return the hard remaining global query-round budget."""
        return max(
            0,
            int(self.policy.budgets["max_query_rounds"])
            - self.query_rounds_used(),
        )

    def remaining_queries(self) -> int:
        """Return the hard remaining admitted-query budget."""
        return max(
            0,
            int(self.policy.budgets["max_queries_total"])
            - int(self._queries_total),
        )

    def trace_context(self) -> dict[str, Any]:
        return {
            "schema": HARNESS_SCHEMA,
            "run_id": self.envelope.run_id,
            "trace_id": self.envelope.trace_id,
            "correlation_id": self.envelope.correlation_id,
            "policy_version": self.policy.version,
            "policy_mode": self.policy.mode,
        }

    def catalogue_prompt_evidence(self, prompt_package: Mapping[str, Any]) -> int:
        contract = prompt_package.get("evidence_reference_contract")
        return self.store.register_evidence_contract(
            self.run_id,
            contract if isinstance(contract, Mapping) else {},
        )

    def _elapsed_seconds(self) -> float:
        snapshot = self.store.snapshot(self.run_id)
        raw = str(snapshot.get("started_at") or "")
        try:
            started = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return 0.0
        if started.tzinfo is None:
            started = started.replace(tzinfo=dt.timezone.utc)
        return max(
            0.0,
            (dt.datetime.now(dt.timezone.utc) - started).total_seconds(),
        )

    def _enforce_budget(
        self,
        *,
        operation_id: str,
        operation: str,
        stage: str,
        observed: Mapping[str, Any],
        violations: Sequence[str],
    ) -> None:
        payload = {
            "operation_id": operation_id,
            "operation": operation,
            "observed": dict(observed),
            "limits": dict(self.policy.budgets),
            "violations": sorted(set(violations)),
            "policy_mode": self.policy.mode,
        }
        decision_digest = digest_json(payload)[:24]
        self.store.append_event(
            self.run_id,
            "policy.budget",
            stage,
            payload,
            idempotency_key=(
                f"policy.budget:{operation_id}:{decision_digest}"
            ),
        )
        if violations and self.policy.mode == "enforce":
            raise HarnessPolicyError(
                f"{operation} exceeds harness budget: "
                + ", ".join(sorted(set(violations)))
            )

    def preflight_model_call(
        self,
        *,
        call_id: str,
        input_value: Any,
        requested_route: str,
        purpose: str,
        independent_review: bool = False,
    ) -> None:
        call_id = _valid_identifier(call_id, "model call_id", 128)
        requested_route = _model_route(
            requested_route,
            "requested model route",
        )
        expected_route = (
            self.envelope.assigned_reviewer_route
            if independent_review
            else self.envelope.assigned_route
        )
        route_allowed = (
            bool(expected_route) and requested_route == expected_route
        )
        route_reason = (
            "requested route matches the immutable reviewer assignment"
            if route_allowed and independent_review
            else "requested route matches the immutable primary assignment"
            if route_allowed
            else "no reviewer route was assigned to this run"
            if independent_review and not expected_route
            else "no primary route was assigned to this run"
            if not expected_route
            else "requested route does not match the immutable run assignment"
        )
        model_stage = (
            Stage.INDEPENDENT_REVIEW.value
            if independent_review
            else Stage.PRIMARY_ANALYSIS.value
        )
        self.store.append_event(
            self.run_id,
            "policy.model-route",
            model_stage,
            {
                "call_id": call_id,
                "purpose": _redacted_string(purpose, 160),
                "requested_route": requested_route,
                "expected_route": expected_route,
                "independent_review": independent_review,
                "allowed": route_allowed,
                "reason": route_reason,
                "policy_mode": self.policy.mode,
            },
            idempotency_key=f"policy.model-route:{call_id}",
        )
        if not route_allowed and self.policy.mode == "enforce":
            raise HarnessPolicyError(route_reason)
        prompt_bytes = len(canonical_json(input_value).encode("utf-8"))
        evidence_rows = approximate_evidence_rows(input_value)
        elapsed_seconds = self._elapsed_seconds()
        violations: list[str] = []
        if prompt_bytes > self.policy.budgets["max_prompt_evidence_bytes"]:
            violations.append("max_prompt_evidence_bytes")
        if evidence_rows > self.policy.budgets["max_prompt_evidence_rows"]:
            violations.append("max_prompt_evidence_rows")
        if elapsed_seconds > self.policy.budgets["max_run_seconds"]:
            violations.append("max_run_seconds")
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="model-call",
            reservation_id=call_id,
            amount=1,
            max_total=self.policy.budgets["max_model_calls"],
            max_operations=self.policy.budgets["max_model_calls"],
            enforce=self.policy.mode == "enforce",
            preexisting_violations=violations,
        )
        violations = list(reservation["violations"])
        if reservation["reserved"]:
            self._model_calls = max(
                self._model_calls,
                int(reservation["total"]),
            )
        next_model_call = int(reservation["operation_count"])
        self._enforce_budget(
            operation_id=f"model:{call_id}",
            operation="model call",
            stage=model_stage,
            observed={
                "call_id": call_id,
                "purpose": _redacted_string(purpose, 160),
                "requested_route": requested_route,
                "expected_route": expected_route,
                "route_allowed": route_allowed,
                "independent_review": independent_review,
                "next_model_call": next_model_call,
                "prompt_bytes": prompt_bytes,
                "approximate_evidence_rows": evidence_rows,
                "reserved": bool(
                    reservation["reserved"]
                ),
            },
            violations=violations,
        )

    def authorize_tool(
        self,
        *,
        round_number: int,
        query_id: str,
        backend: str,
        approved: bool = False,
    ) -> PolicyDecision:
        capability = query_backend_capability(backend)
        decision = self.policy.authorize(
            self.envelope.role,
            capability,
            approved=approved,
        )
        event_key = digest_json(
            {
                "round": round_number,
                "query_id": str(query_id),
                "backend": str(backend),
                "capability": capability,
                "approved": approved,
            }
        )[:24]
        self.store.append_event(
            self.run_id,
            "policy.tool-authorization",
            Stage.QUERY_PLANNING.value,
            {
                "round": max(0, int(round_number)),
                "query_id": str(query_id)[:128],
                "backend": str(backend)[:80],
                "capability": capability,
                "allowed": decision.allowed,
                "approved": approved,
                "effective_in_shadow": policy_decision_is_effective(
                    "shadow",
                    decision,
                ),
                "requires_approval": decision.requires_approval,
                "reason": decision.reason,
            },
            idempotency_key=f"policy.tool:{event_key}",
        )
        return decision

    def preflight_query_batch(
        self,
        *,
        round_number: int,
        request_count: int,
    ) -> None:
        round_number = int(round_number)
        if round_number < 1:
            raise HarnessPolicyError("query round_number must be positive")
        request_count = max(0, int(request_count))
        elapsed_seconds = self._elapsed_seconds()
        violations: list[str] = []
        if round_number > self.policy.budgets["max_query_rounds"]:
            violations.append("max_query_rounds")
        if request_count > self.policy.budgets["max_queries_per_round"]:
            violations.append("max_queries_per_round")
        if elapsed_seconds > self.policy.budgets["max_run_seconds"]:
            violations.append("max_run_seconds")
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="query-round",
            reservation_id=str(round_number),
            amount=request_count,
            max_total=self.policy.budgets["max_queries_total"],
            max_operations=self.policy.budgets["max_query_rounds"],
            enforce=self.policy.mode == "enforce",
            preexisting_violations=violations,
        )
        violations = list(reservation["violations"])
        if reservation["reserved"]:
            self._query_rounds = max(self._query_rounds, round_number)
            self._queries_total = max(
                self._queries_total,
                int(reservation["total"]),
            )
        queries_after_batch = int(reservation["total"])
        self._enforce_budget(
            operation_id=f"query-round:{round_number}",
            operation="query batch",
            stage=Stage.QUERY_PLANNING.value,
            observed={
                "round": round_number,
                "request_count": request_count,
                "queries_after_batch": queries_after_batch,
                "reserved": bool(
                    reservation["reserved"]
                ),
            },
            violations=violations,
        )

    def phase(
        self,
        phase: str,
        route: str = "",
        reason: str = "",
    ) -> None:
        stage = PHASE_STAGE_MAP.get(phase, Stage.POST_PROCESSING.value)
        ordinal = self._phase_counts.get(stage, 0) + 1
        self._phase_counts[stage] = ordinal
        self.store.transition(
            self.run_id,
            stage,
            route=route,
            reason=reason,
            ordinal=ordinal,
        )

    def model_call(
        self,
        *,
        call_id: str,
        purpose: str,
        requested_route: str,
        response: Mapping[str, Any],
        input_value: Any,
        duration_seconds: float,
        independent_review: bool = False,
        status: str = "completed",
    ) -> None:
        call_id = _valid_identifier(call_id, "model call_id", 128)
        requested_route = _model_route(
            requested_route,
            "completed model route",
        )
        with _connect(self.store.path) as connection:
            authorization_row = connection.execute(
                """
                SELECT payload_json
                FROM harness_events
                WHERE run_id = ? AND idempotency_key = ?
                """,
                (
                    self.run_id,
                    f"policy.model-route:{call_id}",
                ),
            ).fetchone()
        authorization = (
            json.loads(str(authorization_row["payload_json"]))
            if authorization_row is not None
            else {}
        )
        observed_route = str(
            response.get("_analysis_model_route") or ""
        ).strip()
        route_authorized = bool(
            authorization.get("allowed") is True
            and authorization.get("requested_route") == requested_route
            and bool(authorization.get("independent_review"))
            is bool(independent_review)
        )
        observed_matches = (
            not response
            or (
                bool(observed_route)
                and observed_route == requested_route
            )
        )
        observation_allowed = route_authorized and observed_matches
        observation_reason = (
            "authorized route and collector-observed route agree"
            if observation_allowed and response
            else "authorized failed invocation has no model response"
            if observation_allowed
            else "model call has no matching allowed preflight"
            if not route_authorized
            else "collector-observed route differs from the authorized route"
        )
        observation_stage = (
            Stage.INDEPENDENT_REVIEW.value
            if independent_review
            else Stage.PRIMARY_ANALYSIS.value
        )
        self.store.append_event(
            self.run_id,
            "policy.model-observation",
            observation_stage,
            {
                "call_id": call_id,
                "requested_route": requested_route,
                "observed_route": observed_route,
                "independent_review": independent_review,
                "response_present": bool(response),
                "allowed": observation_allowed,
                "reason": observation_reason,
                "policy_mode": self.policy.mode,
            },
            idempotency_key=f"policy.model-observation:{call_id}",
        )
        if not observation_allowed and self.policy.mode == "enforce":
            raise HarnessPolicyError(observation_reason)
        # The runner performs the full prompt/runtime preflight before invoking
        # a model. This idempotent reservation is a final hard-count backstop
        # for callers using the record API directly.
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="model-call",
            reservation_id=call_id,
            amount=1,
            max_total=self.policy.budgets["max_model_calls"],
            max_operations=self.policy.budgets["max_model_calls"],
            enforce=self.policy.mode == "enforce",
        )
        if reservation["violations"] and self.policy.mode == "enforce":
            self._enforce_budget(
                operation_id=f"model:{call_id}",
                operation="model call",
                stage=(
                    Stage.INDEPENDENT_REVIEW.value
                    if independent_review
                    else Stage.PRIMARY_ANALYSIS.value
                ),
                observed={
                    "call_id": call_id,
                    "next_model_call": reservation["operation_count"],
                    "reserved": False,
                },
                violations=reservation["violations"],
            )
        self.store.record_model_call(
            self.run_id,
            call_id=call_id,
            purpose=purpose,
            requested_route=requested_route,
            response=response,
            independent_review=independent_review,
            input_digest=digest_json(input_value),
            duration_ms=max(0, round(float(duration_seconds) * 1_000)),
            status=status,
        )
        self._model_calls = max(self._model_calls, int(reservation["total"]))

    def query_round(
        self,
        round_result: Mapping[str, Any],
    ) -> None:
        round_number = int(round_result.get("round") or self._query_rounds + 1)
        if round_number < 1:
            raise HarnessPolicyError("query round_number must be positive")
        requests = (
            round_result.get("requests")
            if isinstance(round_result.get("requests"), list)
            else []
        )
        results = (
            round_result.get("results")
            if isinstance(round_result.get("results"), list)
            else []
        )
        # The typed query broker is expected to call the full preflight before
        # execution. Reserve again idempotently so direct record-API users
        # cannot exceed hard count/round limits without a durable denial.
        direct_violations: list[str] = []
        if len(requests) > self.policy.budgets["max_queries_per_round"]:
            direct_violations.append("max_queries_per_round")
        if round_number > self.policy.budgets["max_query_rounds"]:
            direct_violations.append("max_query_rounds")
        reservation = self.store.reserve_budget_operation(
            self.run_id,
            reservation_type="query-round",
            reservation_id=str(round_number),
            amount=len(requests),
            max_total=self.policy.budgets["max_queries_total"],
            max_operations=self.policy.budgets["max_query_rounds"],
            enforce=self.policy.mode == "enforce",
            preexisting_violations=direct_violations,
        )
        direct_violations = list(reservation["violations"])
        if direct_violations and self.policy.mode == "enforce":
            self._enforce_budget(
                operation_id=f"query-round:{round_number}",
                operation="query batch",
                stage=Stage.QUERY_PLANNING.value,
                observed={
                    "round": round_number,
                    "request_count": len(requests),
                    "queries_after_batch": (
                        reservation["total"]
                    ),
                    "reserved": bool(
                        reservation["reserved"]
                    ),
                },
                violations=direct_violations,
            )
        if reservation["reserved"]:
            self._queries_total = max(
                self._queries_total,
                int(reservation["total"]),
            )
        self._query_rounds = max(self._query_rounds, round_number)
        status_counts: dict[str, int] = {}
        backend_counts: dict[str, int] = {}
        trusted_query_digests: list[str] = []
        request_by_id = {
            str(item.get("query_id")): item
            for item in requests
            if isinstance(item, dict) and item.get("query_id")
        }
        result_by_id: dict[str, dict[str, Any]] = {}
        for item in results:
            if not isinstance(item, dict):
                continue
            status = str(item.get("status") or "unknown")[:40]
            backend = str(item.get("backend") or "unknown")[:40]
            status_counts[status] = status_counts.get(status, 0) + 1
            backend_counts[backend] = backend_counts.get(backend, 0) + 1
            item_ids = (
                [str(value) for value in item.get("query_ids", [])]
                if isinstance(item.get("query_ids"), list)
                else [str(item.get("query_id"))]
                if item.get("query_id")
                else []
            )
            for item_id in item_ids:
                result_by_id[item_id] = item
            audits = (
                item.get("trusted_query_audit")
                if isinstance(item.get("trusted_query_audit"), list)
                else []
            )
            for audit in audits:
                if not isinstance(audit, dict):
                    continue
                digest = str(audit.get("query_digest") or "")
                if DIGEST_RE.fullmatch(digest):
                    trusted_query_digests.append(digest)
                    returned_count = observed_returned_count(audit)
                    result_digest = str(
                        audit.get("result_digest") or ""
                    ).lower()
                    if not DIGEST_RE.fullmatch(result_digest):
                        result_digest = ""
                    supplied_ref = str(
                        audit.get("evidence_ref")
                        or f"query:{digest}"
                    ).strip()
                    if not supplied_ref or supplied_ref.startswith("query:"):
                        ref = f"query:{digest}"
                        if DIGEST_RE.fullmatch(result_digest):
                            ref += f":{result_digest}"
                    else:
                        ref = supplied_ref[:512]
                    self.store.register_evidence(
                        self.run_id,
                        evidence_ref=ref,
                        source=backend,
                        source_class=(
                            "live_endpoint_osquery"
                            if backend == "osquery"
                            else "packet_evidence"
                            if backend == "pcap_zeek"
                            else "security_onion_investigation_query"
                        ),
                        trust_tier=TrustTier.READ_ONLY_BACKEND.value,
                        corroborating=(
                            str(audit.get("status") or status)
                            in {"ok", "completed", "success"}
                            and returned_count is not None
                            and returned_count > 0
                        ),
                        status=str(audit.get("status") or status),
                        evidence_digest=str(
                            result_digest or digest
                        ),
                        metadata={
                            "query_id": audit.get("query_id"),
                            "query_digest": digest,
                            "returned": returned_count,
                            "truncated": audit.get("truncated"),
                        },
                    )
        # Policy/schema/backend rejections may never have entered the admitted
        # request list. They still need a durable tool ledger row so denial and
        # evidence-gap metrics reflect the actual investigation trajectory.
        for query_id, result in result_by_id.items():
            if query_id not in request_by_id:
                request_by_id[query_id] = {
                    "query_id": query_id,
                    "backend": result.get("backend"),
                    "purpose": result.get("purpose")
                    or "proposal rejected before execution",
                    "rejected_before_execution": True,
                }
        for query_id, request in request_by_id.items():
            result = result_by_id.get(query_id, {})
            backend = str(request.get("backend") or result.get("backend") or "")
            evidence = (
                result.get("evidence")
                if isinstance(result.get("evidence"), dict)
                else {}
            )
            result_status, result_observation = resolve_query_binding(
                result,
                query_id,
            )
            returned_count = observed_returned_count(result_observation)
            coverage = str(
                evidence.get("coverage")
                or evidence.get("coverage_semantics")
                or (
                    "exact-zero"
                    if result_status == "ok"
                    and returned_count == 0
                    else "bounded-result"
                    if result_status == "ok"
                    and returned_count is not None
                    and returned_count > 0
                    else "unknown"
                    if result_status == "ok"
                    else "evidence-gap"
                )
            )
            self.store.record_tool_call(
                self.run_id,
                call_id=f"round-{round_number}-{query_id}"[:128],
                round_number=round_number,
                backend=backend,
                capability=query_backend_capability(backend),
                purpose=str(request.get("purpose") or ""),
                request_digest=digest_json(request),
                result_digest=digest_json(result),
                status=result_status,
                read_only=result.get("read_only") is True,
                coverage=coverage,
                truncated=observed_truncation(result_observation),
            )
        with _connect(self.store.path) as connection:
            usage = connection.execute(
                """
                SELECT COUNT(*) executed_queries
                FROM harness_tool_calls
                WHERE run_id = ?
                  AND lower(status) NOT IN (
                    'rejected', 'denied', 'blocked',
                    'unauthorized', 'forbidden'
                  )
                """,
                (self.run_id,),
            ).fetchone()
        self._queries_total = max(
            self._queries_total,
            int(usage["executed_queries"]),
        )
        budget_violations = list(direct_violations)
        if self._query_rounds > self.policy.budgets["max_query_rounds"]:
            budget_violations.append("max_query_rounds")
        # Rejected proposals are audit rows but did not consume an execution
        # budget. The preflight reservation is authoritative when present;
        # this post-execution fallback counts admitted requests for callers that
        # use the harness API directly.
        admitted_total = max(self._queries_total, len(requests))
        if admitted_total > self.policy.budgets["max_queries_total"]:
            budget_violations.append("max_queries_total")
        if len(requests) > self.policy.budgets["max_queries_per_round"]:
            budget_violations.append("max_queries_per_round")
        self.store.append_event(
            self.run_id,
            "queries.completed",
            Stage.QUERY_EXECUTION.value,
            {
                "round": round_number,
                "request_count": len(requests),
                "result_count": len(results),
                "rejected_proposal_count": sum(
                    1
                    for request in request_by_id.values()
                    if request.get("rejected_before_execution") is True
                ),
                "status_counts": status_counts,
                "backend_counts": backend_counts,
                "trusted_query_digests": sorted(set(trusted_query_digests)),
                "budget_violations": budget_violations,
            },
            idempotency_key=f"queries.completed:{round_number}",
        )
        if budget_violations and self.policy.mode == "enforce":
            raise HarnessPolicyError(
                "investigation exceeded harness budget: "
                + ", ".join(budget_violations)
            )

    def record_response(
        self,
        response: Mapping[str, Any],
        *,
        decision_id: str,
        decision_type: str,
        hypothesis_revision: int,
    ) -> None:
        decision_stage = (
            Stage.INDEPENDENT_REVIEW.value
            if decision_type == "independent-review"
            else Stage.POST_PROCESSING.value
            if decision_type == "post-review-analysis"
            else Stage.EVIDENCE_SYNTHESIS.value
        )
        self.store.record_hypotheses(
            self.run_id,
            response.get("hypotheses"),
            revision=hypothesis_revision,
        )
        self.store.record_decision(
            self.run_id,
            decision_id=decision_id,
            decision_type=decision_type,
            response=response,
            stage=decision_stage,
        )

    def memory_promotion_decision(
        self,
        response: Mapping[str, Any],
        *,
        has_shared_candidates: bool,
        human_approved: bool = False,
    ) -> PolicyDecision:
        return memory_promotion_decision(
            self.policy,
            response,
            role=self.envelope.role,
            has_shared_candidates=has_shared_candidates,
            human_approved=human_approved,
        )

    def preflight_completion(
        self,
        *,
        operation_id: str = "run-complete",
    ) -> None:
        operation_id = _valid_identifier(
            operation_id,
            "completion operation_id",
            128,
        )
        elapsed_seconds = self._elapsed_seconds()
        self._enforce_budget(
            operation_id=operation_id,
            operation="run completion",
            stage=Stage.PERSISTENCE.value,
            observed={"elapsed_seconds": round(elapsed_seconds, 3)},
            violations=(
                ["max_run_seconds"]
                if elapsed_seconds > self.policy.budgets["max_run_seconds"]
                else []
            ),
        )

    def record_memory_writeback(
        self,
        receipt: Mapping[str, Any],
    ) -> None:
        """Record bounded post-commit results without storing memory content."""
        self.store.append_event(
            self.run_id,
            "memory.writeback",
            Stage.PERSISTENCE.value,
            receipt,
            idempotency_key="memory.writeback:post-commit",
        )

    def observe_postcommit_runtime(self) -> dict[str, Any]:
        """Audit an SLO breach after commit without invalidating durable work."""
        elapsed_seconds = self._elapsed_seconds()
        exceeded = elapsed_seconds > self.policy.budgets["max_run_seconds"]
        payload = {
            "elapsed_seconds": round(elapsed_seconds, 3),
            "max_run_seconds": self.policy.budgets["max_run_seconds"],
            "exceeded": exceeded,
            "enforcement_boundary": "post-commit-observation",
        }
        self.store.append_event(
            self.run_id,
            "slo.runtime",
            Stage.PERSISTENCE.value,
            payload,
            idempotency_key="slo.runtime:post-commit",
        )
        return payload

    def complete(
        self,
        summary: Mapping[str, Any] | None = None,
        *,
        check_budget: bool = True,
    ) -> None:
        if check_budget:
            self.preflight_completion()
        self.store.finish(
            self.run_id,
            status=RunStatus.SUCCEEDED.value,
            summary=summary,
        )

    def fail(self, reason: str) -> None:
        self.store.finish(
            self.run_id,
            status=RunStatus.FAILED.value,
            reason=reason,
        )


def memory_promotion_decision(
    policy: HarnessPolicy,
    response: Mapping[str, Any],
    *,
    role: str,
    has_shared_candidates: bool,
    human_approved: bool = False,
) -> PolicyDecision:
    """Gate durable model memory against review, evidence, and poisoning risks."""
    controls = (
        response.get("_automation_controls")
        if isinstance(response.get("_automation_controls"), dict)
        else {}
    )
    if controls.get("memory_writeback_blocked"):
        return PolicyDecision(
            False,
            "memory.promote",
            str(controls.get("reason") or "automation guardrail blocked memory"),
        )
    validation = (
        response.get("_evidence_reference_validation")
        if isinstance(response.get("_evidence_reference_validation"), dict)
        else {}
    )
    source_classes = {
        str(item)
        for item in validation.get("corroborating_source_classes", [])
        if str(item)
    } if isinstance(validation.get("corroborating_source_classes"), list) else set()
    invalid_refs = (
        validation.get("invalid_refs")
        if isinstance(validation.get("invalid_refs"), list)
        else []
    )
    if invalid_refs:
        return PolicyDecision(
            False,
            "memory.promote",
            "memory candidate depends on unresolved evidence references",
        )
    if len(source_classes) < 2:
        return PolicyDecision(
            False,
            "memory.promote",
            "fewer than two corroborating evidence source classes",
        )
    try:
        confidence_score = float(response.get("confidence_score"))
    except (TypeError, ValueError, OverflowError):
        confidence_score = 0.0
    if (
        str(response.get("confidence") or "").lower() != "high"
        or confidence_score < 0.8
    ):
        return PolicyDecision(
            False,
            "memory.promote",
            "analysis confidence is below the memory promotion threshold",
        )
    if policy.memory_require_independent_agreement:
        review = (
            response.get("_second_opinion")
            if isinstance(response.get("_second_opinion"), dict)
            else {}
        )
        comparison = (
            review.get("comparison")
            if isinstance(review.get("comparison"), dict)
            else {}
        )
        if (
            review.get("status") != "completed"
            or comparison.get("agreement") != "agreement"
            or comparison.get("material_disagreement") is True
        ):
            return PolicyDecision(
                False,
                "memory.promote",
                "independent reviewer did not fully corroborate the analysis",
            )
    if (
        has_shared_candidates
        and policy.shared_memory_requires_human_approval
        and not human_approved
    ):
        return PolicyDecision(
            False,
            "memory.promote",
            "shared memory requires explicit human approval",
            requires_approval=True,
        )
    return policy.authorize(
        role,
        "memory.promote",
        approved=human_approved,
    )


def start_harness_run(
    *,
    run_id: str,
    prompt_package: Mapping[str, Any],
    role: str,
    assigned_route: str,
    configuration: Mapping[str, Any],
    reanalysis_attempt_id: str = "",
    policy_path: Path = DEFAULT_POLICY_PATH,
    db_path: Path = DEFAULT_DB_PATH,
    policy: HarnessPolicy | None = None,
) -> HarnessRun | None:
    effective_policy = policy or load_policy(policy_path)
    start_allowed, _ = should_start_onion_sentinel_harness(
        policy_enabled=effective_policy.enabled,
        assigned_route=assigned_route,
        reviewer_route=configuration.get("reviewer_route"),
    )
    if not start_allowed:
        return None
    envelope = JobEnvelope.from_prompt(
        run_id=run_id,
        prompt_package=prompt_package,
        role=role,
        assigned_route=assigned_route,
        configuration=configuration,
        reanalysis_attempt_id=reanalysis_attempt_id,
    )
    run = HarnessRun(HarnessStore(db_path), envelope, effective_policy)
    run.catalogue_prompt_evidence(prompt_package)
    return run


def main() -> int:
    print(
        "onion_sentinel_harness.py is a runtime module; use the read-only "
        "evaluate-harness-traces.py utility for inspection",
        file=os.sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
