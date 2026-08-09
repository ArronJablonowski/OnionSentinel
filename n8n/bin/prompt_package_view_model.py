#!/usr/bin/env python3
"""Assemble prepared investigation evidence into one prompt package view."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class PromptPackageView:
    """Prepared values admitted to model-facing package assembly."""

    agent_role: str
    blind_reanalysis: bool
    lineage: Mapping[str, Any]
    generated_at: str
    analysis_policy: Mapping[str, Any]
    runtime_files: Mapping[str, str]
    prompt_contract: Mapping[str, Any]
    evidence_sections: Mapping[str, Any]
    incident_evidence: dict | None


@dataclass(frozen=True)
class PreparedPromptPackageView:
    """Prepared subsystem outputs ready for final evidence-section mapping."""

    agent_role: str
    blind_reanalysis: bool
    lineage: Mapping[str, Any]
    generated_at: str
    analysis_policy: Mapping[str, Any]
    runtime_files: Mapping[str, str]
    prompt_contract: Mapping[str, Any]
    core_snapshot: Any
    detection_context: Any
    admitted_evidence: Any
    history: Any


BLIND_EXCLUDED_CONTEXT = (
    "prior AI analyses",
    "prior model-authored correlation hypotheses",
    "unconfirmed model-observed memory",
)
MISSING_INCIDENT_EVIDENCE_ERROR = (
    "incident-responder analysis requires validated restricted Security Onion evidence"
)


def _reanalysis_context(view: PromptPackageView) -> dict:
    return {
        "blind": view.blind_reanalysis,
        "excluded_context": (
            list(BLIND_EXCLUDED_CONTEXT) if view.blind_reanalysis else []
        ),
    }


def _base_package(view: PromptPackageView) -> dict:
    return {
        "package_type": "soc-ai-investigation-prompt",
        "agent_role": view.agent_role,
        **view.lineage,
        "generated_at": view.generated_at,
        "analysis_policy": dict(view.analysis_policy),
        **view.runtime_files,
        **view.prompt_contract,
        **view.evidence_sections,
        "reanalysis_context": _reanalysis_context(view),
    }


def assemble_prompt_package(view: PromptPackageView) -> dict:
    """Return a complete package or fail closed for missing IR evidence."""
    package = _base_package(view)
    if view.agent_role != "incident-responder":
        return package
    if view.incident_evidence is None:
        raise RuntimeError(MISSING_INCIDENT_EVIDENCE_ERROR)
    package["incident_response_evidence"] = view.incident_evidence
    return package


def _prepared_evidence_sections(prepared: PreparedPromptPackageView) -> dict:
    snapshot = prepared.core_snapshot
    detection = prepared.detection_context
    admitted = prepared.admitted_evidence
    history = prepared.history
    return {
        "alert": snapshot.alert,
        "grouped_alert_context": snapshot.grouped_alert_context,
        "public_enrichment": snapshot.public_enrichment,
        "pcap_evidence": snapshot.pcap_evidence,
        "investigation_query_capability": admitted.investigation_capability,
        "_local_investigation_query_context": (
            admitted.local_investigation_query_context
        ),
        "investigation_skills": detection.investigation_skills,
        "detection_validation": detection.detection_validation,
        "asset_context": detection.asset_context,
        "authorization_evidence": snapshot.authorization_evidence,
        "analyst_state": snapshot.analyst_state,
        "prior_analyses": history.prior_analyses,
        "related_alerts": history.related_alerts,
        "correlated_alert_context": admitted.correlation_context,
        "recent_notifications": history.recent_notifications,
        "agent_memory": admitted.memory_context,
        "latest_daily_rollup": snapshot.latest_daily_rollup,
    }


def assemble_prepared_prompt_package(prepared: PreparedPromptPackageView) -> dict:
    """Map prepared subsystem outputs and apply final package invariants."""
    return assemble_prompt_package(
        PromptPackageView(
            agent_role=prepared.agent_role,
            blind_reanalysis=prepared.blind_reanalysis,
            lineage=prepared.lineage,
            generated_at=prepared.generated_at,
            analysis_policy=prepared.analysis_policy,
            runtime_files=prepared.runtime_files,
            prompt_contract=prepared.prompt_contract,
            evidence_sections=_prepared_evidence_sections(prepared),
            incident_evidence=prepared.admitted_evidence.incident_evidence,
        )
    )
