#!/usr/bin/env python3
"""Ordered evidence collection and prompt-package orchestration."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from prompt_detection_context import DetectionContextRequest, prepare_detection_context
from prompt_evidence_admission import (
    PromptEvidenceAdmissionRequest,
    PromptEvidenceAdmissionSources,
    prepare_prompt_evidence_admission,
)
from prompt_evidence_snapshot import (
    CoreEvidenceSnapshotRequest,
    CoreEvidenceSnapshotSources,
    HistoricalEvidenceSnapshotRequest,
    HistoricalEvidenceSnapshotSources,
    collect_core_evidence_snapshot,
    collect_historical_evidence_snapshot,
)
from prompt_package_view_model import (
    PreparedPromptPackageView,
    assemble_prepared_prompt_package,
)
from prompt_response_contract import PromptContractRequest, build_prompt_contract


@dataclass(frozen=True)
class PromptPackageWorkflowPolicy:
    """Stable bounds and defaults supplied by the composition root."""

    default_investigation_skills_path: Path
    default_detection_playbooks_path: Path
    default_asset_inventory_path: Path
    maximum_detection_group_rows: int
    maximum_incident_evidence_bytes: int
    query_packs: tuple[str, ...]
    query_v2: bool


@dataclass(frozen=True)
class PromptPackageWorkflowSources:
    """Runtime ports used by the ordered package workflow."""

    grouped_alert_context: Callable[..., Any]
    pcap_evidence_context: Callable[..., Any]
    public_enrichment_context: Callable[..., Any]
    authorized_activity_context: Callable[..., Any]
    analyst_state_context: Callable[..., Any]
    correlated_alert_context: Callable[..., Any]
    compact_alert: Callable[..., Any]
    detection_context_sources: Callable[[], Any]
    investigation_query_context: Callable[..., Any]
    build_agent_memory_context: Callable[..., Any]
    blind_model_authored_context: Callable[..., Any]
    load_json_bounded: Callable[..., Any]
    validate_incident_evidence: Callable[..., Any]
    reject_preprojected_incident_evidence: Callable[..., Any]
    project_incident_evidence_hits: Callable[..., Any]
    load_system_prompt: Callable[..., str]
    agent_task: Callable[..., str]
    prior_analysis_context: Callable[..., Any]
    related_alerts: Callable[..., Any]
    query_rows: Callable[..., Any]
    execution_lineage: Callable[..., dict]
    project_now: Callable[[], str]
    model_policy: Callable[[str | None], dict]


def _collect_core_snapshot(sources, connection, selected, args):
    return collect_core_evidence_snapshot(
        CoreEvidenceSnapshotSources(
            grouped_alert_context=sources.grouped_alert_context,
            pcap_evidence_context=sources.pcap_evidence_context,
            public_enrichment_context=sources.public_enrichment_context,
            authorized_activity_context=sources.authorized_activity_context,
            analyst_state_context=sources.analyst_state_context,
            correlated_alert_context=sources.correlated_alert_context,
            compact_alert=sources.compact_alert,
        ),
        CoreEvidenceSnapshotRequest(
            connection=connection,
            selected=selected,
            rollup_dir=args.rollup_dir,
            rollup_bytes=args.rollup_bytes,
            related_limit=args.related_limit,
            include_tests=bool(args.include_tests),
            pcap_analysis_dir=args.pcap_analysis_dir,
            pcap_analysis_limit=args.pcap_analysis_limit,
            correlation_limit=args.correlation_limit,
            correlation_min_score=args.correlation_min_score,
        ),
    )


def _collect_detection_context(sources, policy, connection, selected, args):
    return prepare_detection_context(
        sources.detection_context_sources(),
        DetectionContextRequest(
            connection=connection,
            selected=selected,
            include_tests=bool(args.include_tests),
            agent_role=str(args.agent_role),
            investigation_skills_path=Path(
                getattr(
                    args,
                    "investigation_skills",
                    policy.default_investigation_skills_path,
                )
            ),
            detection_playbooks_path=Path(
                getattr(
                    args,
                    "detection_playbooks",
                    policy.default_detection_playbooks_path,
                )
            ),
            asset_inventory_path=Path(
                getattr(
                    args,
                    "asset_inventory_file",
                    policy.default_asset_inventory_path,
                )
            ),
            maximum_group_rows=policy.maximum_detection_group_rows,
        ),
    )


def _admit_evidence(sources, policy, selected, args, snapshot, detection_context):
    return prepare_prompt_evidence_admission(
        PromptEvidenceAdmissionSources(
            investigation_query_context=sources.investigation_query_context,
            build_agent_memory_context=sources.build_agent_memory_context,
            blind_model_authored_context=sources.blind_model_authored_context,
            load_json_bounded=sources.load_json_bounded,
            validate_incident_evidence=sources.validate_incident_evidence,
            reject_preprojected_incident_evidence=(
                sources.reject_preprojected_incident_evidence
            ),
            project_incident_evidence_hits=sources.project_incident_evidence_hits,
        ),
        PromptEvidenceAdmissionRequest(
            selected=selected,
            agent_role=str(args.agent_role),
            group_id=str(snapshot.analyst_state.get("group_id") or ""),
            exact_validation_rows=detection_context.exact_validation_rows,
            pcap_context=snapshot.pcap_evidence,
            enrichment_context=snapshot.public_enrichment,
            compact_alert=snapshot.alert,
            grouped_alert_context=snapshot.grouped_alert_context,
            detection_validation=detection_context.detection_validation,
            asset_context=detection_context.asset_context,
            authorization_evidence=snapshot.authorization_evidence,
            analyst_state=snapshot.analyst_state,
            correlation_context=snapshot.correlated_alert_context,
            role_memory_file=args.agent_memory_file,
            shared_memory_file=args.shared_memory_file,
            memory_bytes=args.memory_bytes,
            blind_reanalysis=bool(args.blind_reanalysis),
            incident_evidence_file=args.incident_evidence_file,
            maximum_incident_evidence_bytes=(
                policy.maximum_incident_evidence_bytes
            ),
        ),
    )


def _create_prompt_contract(sources, policy, args) -> dict:
    return build_prompt_contract(
        PromptContractRequest(
            agent_role=str(args.agent_role),
            blind_reanalysis=bool(args.blind_reanalysis),
            role_prompt=sources.load_system_prompt(args.system_prompt_file),
            task=sources.agent_task(
                args.agent_role,
                blind_reanalysis=args.blind_reanalysis,
            ),
            query_packs=policy.query_packs,
            query_v2=policy.query_v2,
        )
    )


def _collect_history(sources, connection, selected, args):
    return collect_historical_evidence_snapshot(
        HistoricalEvidenceSnapshotSources(
            prior_analysis_context=sources.prior_analysis_context,
            related_alerts=sources.related_alerts,
            query_rows=sources.query_rows,
        ),
        HistoricalEvidenceSnapshotRequest(
            connection=connection,
            selected=selected,
            analysis_dir=args.analysis_dir,
            related_limit=args.related_limit,
            include_tests=bool(args.include_tests),
            blind_reanalysis=bool(args.blind_reanalysis),
        ),
    )


def _assemble_package(
    sources,
    selected,
    args,
    snapshot,
    detection_context,
    admitted_evidence,
    prompt_contract,
    history,
) -> dict:
    return assemble_prepared_prompt_package(
        PreparedPromptPackageView(
            agent_role=str(args.agent_role),
            blind_reanalysis=bool(args.blind_reanalysis),
            lineage=sources.execution_lineage(
                selected,
                blind_reanalysis=args.blind_reanalysis,
            ),
            generated_at=sources.project_now(),
            analysis_policy=sources.model_policy(selected["triage_level"]),
            runtime_files={
                "system_prompt_file": str(args.system_prompt_file),
                "second_opinion_system_prompt_file": str(
                    args.second_opinion_prompt_file
                ),
                "agent_memory_file": str(args.agent_memory_file),
                "shared_memory_file": str(args.shared_memory_file),
            },
            prompt_contract=prompt_contract,
            core_snapshot=snapshot,
            detection_context=detection_context,
            admitted_evidence=admitted_evidence,
            history=history,
        )
    )


def build_prepared_prompt_package(
    sources: PromptPackageWorkflowSources,
    policy: PromptPackageWorkflowPolicy,
    connection: Any,
    selected: Any,
    args: Any,
) -> dict:
    """Run collection, admission, contract, history, and assembly in order."""
    snapshot = _collect_core_snapshot(sources, connection, selected, args)
    detection_context = _collect_detection_context(
        sources,
        policy,
        connection,
        selected,
        args,
    )
    admitted_evidence = _admit_evidence(
        sources,
        policy,
        selected,
        args,
        snapshot,
        detection_context,
    )
    prompt_contract = _create_prompt_contract(sources, policy, args)
    history = _collect_history(sources, connection, selected, args)
    return _assemble_package(
        sources,
        selected,
        args,
        snapshot,
        detection_context,
        admitted_evidence,
        prompt_contract,
        history,
    )
