"""Run lifecycle and evidence write repository for the harness."""
from __future__ import annotations

from typing import Any, Mapping

from harness_contracts import JobEnvelope, bounded_metadata
from harness_policy import (
    HARNESS_SCHEMA,
    HarnessIntegrityError,
    HarnessPolicy,
    HarnessPolicyError,
    MAX_EVIDENCE_REFS,
    RunStatus,
    Stage,
    TrustTier,
    _digest_or_hash,
    canonical_json,
    digest_json,
    utc_now,
)
from harness_store_foundation import _connect


class HarnessStoreRunRepository:
    """Atomic run lifecycle, stage, event, and evidence writes."""

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
