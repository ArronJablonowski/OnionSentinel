"""Run lifecycle and evidence write repository for the harness."""
from __future__ import annotations

from typing import Any, Mapping

from harness_contracts import (
    JobEnvelope,
    bounded_metadata,
    execution_contract_digest,
    parse_execution_contract,
)
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


_SELECT_RUN_SQL = "SELECT * FROM harness_runs WHERE run_id = ?"
_INSERT_RUN_SQL = """
    INSERT INTO harness_runs(
        run_id, trace_id, correlation_id, case_id, alert_id, role,
        task_kind, status, stage, assigned_route,
        assigned_reviewer_route, prompt_digest,
        evidence_manifest_digest, configuration_digest,
        execution_contract_json, execution_contract_digest,
        policy_version, policy_digest, policy_mode, parent_run_id,
        job_digest, started_at, updated_at
    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
_SELECT_EVIDENCE_SQL = """
    SELECT evidence_digest FROM harness_evidence
    WHERE run_id = ? AND evidence_ref = ?
"""
_INSERT_EVIDENCE_SQL = """
    INSERT INTO harness_evidence(
        run_id, evidence_ref, source, source_class, trust_tier,
        corroborating, status, evidence_digest, observed_at,
        metadata_json
    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _validate_existing_run(
    existing: Mapping[str, Any],
    envelope: JobEnvelope,
    policy: HarnessPolicy,
) -> None:
    if (
        existing["job_digest"] != envelope.job_digest
        or existing["policy_digest"] != policy.digest
    ):
        raise HarnessIntegrityError(
            "run_id collides with a different job or policy"
        )


def _validate_execution_contract_binding(
    envelope: JobEnvelope,
    policy: HarnessPolicy,
) -> None:
    try:
        contract = parse_execution_contract(envelope.execution_contract_json)
        digest = execution_contract_digest(contract)
    except ValueError as exc:
        raise HarnessIntegrityError("job execution contract is invalid") from exc
    reviewer = contract["reviewer"]
    reviewer_route = reviewer["route"] if reviewer is not None else ""
    if (
        digest != envelope.execution_contract_digest
        or contract["policy_version"] != policy.version
        or contract["primary"]["route"] != envelope.assigned_route
        or reviewer_route != envelope.assigned_reviewer_route
    ):
        raise HarnessIntegrityError(
            "job execution contract does not match the durable run identity"
        )


def _run_insert_values(
    envelope: JobEnvelope,
    policy: HarnessPolicy,
) -> tuple[Any, ...]:
    return (
        envelope.run_id, envelope.trace_id, envelope.correlation_id,
        envelope.case_id, envelope.alert_id, envelope.role,
        envelope.task_kind, RunStatus.RUNNING.value, Stage.INTAKE.value,
        envelope.assigned_route, envelope.assigned_reviewer_route,
        envelope.prompt_digest, envelope.evidence_manifest_digest,
        envelope.configuration_digest, envelope.execution_contract_json,
        envelope.execution_contract_digest, policy.version, policy.digest,
        policy.mode, envelope.parent_run_id, envelope.job_digest,
        envelope.created_at, envelope.created_at,
    )


def _run_started_payload(
    envelope: JobEnvelope,
    policy: HarnessPolicy,
) -> dict[str, Any]:
    return {
        "schema": HARNESS_SCHEMA,
        "trace_id": envelope.trace_id,
        "correlation_id": envelope.correlation_id,
        "case_id": envelope.case_id,
        "alert_id": envelope.alert_id,
        "role": envelope.role,
        "task_kind": envelope.task_kind,
        "assigned_route": envelope.assigned_route,
        "assigned_reviewer_route": envelope.assigned_reviewer_route,
        "prompt_digest": envelope.prompt_digest,
        "evidence_manifest_digest": envelope.evidence_manifest_digest,
        "configuration_digest": envelope.configuration_digest,
        "execution_contract": parse_execution_contract(
            envelope.execution_contract_json
        ),
        "execution_contract_digest": envelope.execution_contract_digest,
        "skill_selection_attestation": envelope.skill_selection_attestation,
        "job_digest": envelope.job_digest,
        "policy_version": policy.version,
        "policy_digest": policy.digest,
        "policy_mode": policy.mode,
    }


def _append_run_started(
    repository: Any,
    connection: Any,
    envelope: JobEnvelope,
    policy: HarnessPolicy,
) -> dict[str, Any]:
    return repository._append_event_tx(
        connection,
        run_id=envelope.run_id,
        event_type="run.started",
        stage=Stage.INTAKE.value,
        payload=_run_started_payload(envelope, policy),
        idempotency_key="run.started",
        created_at=envelope.created_at,
    )


def _validated_stage(stage: str) -> None:
    try:
        Stage(stage)
    except ValueError as exc:
        raise HarnessPolicyError(f"unknown harness stage: {stage}") from exc


def _require_transitionable_run(run: Mapping[str, Any] | None) -> None:
    if run is None:
        raise HarnessIntegrityError("unknown harness run")
    if run["status"] not in {
        RunStatus.RUNNING.value,
        RunStatus.WAITING_FOR_REVIEW.value,
    }:
        raise HarnessIntegrityError("cannot transition a terminal harness run")


def _append_transition_event(
    repository: Any,
    connection: Any,
    run_id: str,
    stage: str,
    route: str,
    reason: str,
    ordinal: int,
) -> dict[str, Any]:
    return repository._append_event_tx(
        connection,
        run_id=run_id,
        event_type="run.stage",
        stage=stage,
        payload={"active_route": route[:256], "reason": reason[:500]},
        idempotency_key=f"stage:{stage}:{ordinal}",
    )


def _update_transition_stage(
    repository: Any,
    connection: Any,
    run: Mapping[str, Any],
    run_id: str,
    stage: str,
    route: str,
    event: Mapping[str, Any],
) -> None:
    repository._update_run_stage_tx(
        connection,
        run_id=run_id,
        stage=stage,
        updated_at=event["created_at"],
        active_route=route[:256] if route else str(run["active_route"]),
    )


def _evidence_identity(
    evidence_ref: str,
    source: str,
    source_class: str,
    trust_tier: str,
    status: str,
    evidence_digest: str,
    metadata: Mapping[str, Any] | None,
) -> tuple[str, str, str]:
    normalized_ref = str(evidence_ref or "").strip()[:512]
    if not normalized_ref:
        raise HarnessIntegrityError("evidence reference is required")
    try:
        TrustTier(trust_tier)
    except ValueError as exc:
        raise HarnessIntegrityError("unknown evidence trust tier") from exc
    digest = _digest_or_hash(evidence_digest or {
        "ref": normalized_ref,
        "source": source,
        "source_class": source_class,
        "status": status,
        "metadata": metadata or {},
    })
    return normalized_ref, digest, canonical_json(bounded_metadata(metadata or {}))


def _validate_evidence_replay(
    existing: Mapping[str, Any],
    digest: str,
) -> None:
    if existing["evidence_digest"] != digest:
        raise HarnessIntegrityError(
            "immutable evidence reference collides with different content"
        )


def _evidence_insert_values(
    run_id: str,
    evidence_ref: str,
    source: str,
    source_class: str,
    trust_tier: str,
    corroborating: bool,
    status: str,
    digest: str,
    metadata_json: str,
) -> tuple[Any, ...]:
    return (
        run_id, evidence_ref, str(source or "")[:160],
        str(source_class or "unknown")[:160], trust_tier,
        1 if corroborating else 0, str(status or "")[:64], digest,
        utc_now(), metadata_json,
    )


def _contract_references(
    contract: Mapping[str, Any] | None,
) -> list[Any] | None:
    references = contract.get("references") if isinstance(contract, Mapping) else None
    return references if isinstance(references, list) else None


def _contract_trust_tier(source_class: str) -> str:
    if source_class in {"agent_memory", "shared_memory", "memory"}:
        return TrustTier.MEMORY_LEAD.value
    if source_class == "public_enrichment":
        return TrustTier.EXTERNAL_INTELLIGENCE.value
    return TrustTier.TRUSTED_COLLECTOR.value


def _register_contract_reference(
    repository: Any,
    run_id: str,
    item: Any,
) -> bool:
    if not isinstance(item, dict) or not item.get("ref"):
        return False
    source = str(item.get("source") or "unknown")
    source_class = str(item.get("source_class") or source)
    repository.register_evidence(
        run_id,
        evidence_ref=str(item["ref"]),
        source=source,
        source_class=source_class,
        trust_tier=_contract_trust_tier(source_class),
        corroborating=item.get("corroborating") is True,
        status=str(item.get("status") or ""),
        evidence_digest=str(item.get("evidence_digest") or ""),
        metadata={"returned": item.get("returned")},
    )
    return True


def _append_evidence_catalogue(
    repository: Any,
    run_id: str,
    contract: Mapping[str, Any] | None,
    count: int,
) -> None:
    manifest_digest = digest_json(contract or {})
    schema = (
        (contract or {}).get("schema")
        if isinstance(contract, Mapping)
        else ""
    )
    repository.append_event(
        run_id,
        "evidence.catalogued",
        Stage.CONTEXT_ASSEMBLY.value,
        {
            "contract_schema": str(schema),
            "references_registered": count,
            "manifest_digest": manifest_digest,
        },
        idempotency_key=f"evidence.catalogued:{manifest_digest[:24]}",
    )


class HarnessStoreRunRepository:
    """Atomic run lifecycle, stage, event, and evidence writes."""

    def start_run(
        self,
        envelope: JobEnvelope,
        policy: HarnessPolicy,
    ) -> dict[str, Any]:
        _validate_execution_contract_binding(envelope, policy)
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                _SELECT_RUN_SQL,
                (envelope.run_id,),
            ).fetchone()
            if existing is not None:
                _validate_existing_run(existing, envelope, policy)
                connection.commit()
                return dict(existing)
            connection.execute(
                _INSERT_RUN_SQL,
                _run_insert_values(envelope, policy),
            )
            event = _append_run_started(self, connection, envelope, policy)
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
        _validated_stage(stage)
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            run = connection.execute(
                "SELECT status, active_route FROM harness_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            _require_transitionable_run(run)
            event = _append_transition_event(
                self, connection, run_id, stage, route, reason, ordinal,
            )
            _update_transition_stage(
                self, connection, run, run_id, stage, route, event,
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
        evidence_ref, digest, metadata_json = _evidence_identity(
            evidence_ref, source, source_class, trust_tier, status,
            evidence_digest, metadata,
        )
        with _connect(self.path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_mutable_run_tx(connection, run_id)
            existing = connection.execute(
                _SELECT_EVIDENCE_SQL,
                (run_id, evidence_ref),
            ).fetchone()
            if existing is not None:
                _validate_evidence_replay(existing, digest)
                connection.commit()
                return
            connection.execute(
                _INSERT_EVIDENCE_SQL,
                _evidence_insert_values(
                    run_id, evidence_ref, source, source_class, trust_tier,
                    corroborating, status, digest, metadata_json,
                ),
            )
            connection.commit()

    def register_evidence_contract(
        self,
        run_id: str,
        contract: Mapping[str, Any] | None,
    ) -> int:
        references = _contract_references(contract)
        if references is None:
            return 0
        count = 0
        for item in references[:MAX_EVIDENCE_REFS]:
            count += int(_register_contract_reference(self, run_id, item))
        _append_evidence_catalogue(self, run_id, contract, count)
        return count
