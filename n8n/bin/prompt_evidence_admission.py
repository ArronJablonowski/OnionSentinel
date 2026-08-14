#!/usr/bin/env python3
"""Admit governed query, memory, and incident evidence to prompt assembly."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Callable

from agent_memory_context_contract import refresh_selected_memory_snapshot


@dataclass(frozen=True)
class PromptEvidenceAdmissionRequest:
    """Prepared evidence and bounded runtime inputs for admission."""

    selected: Any
    agent_role: str
    group_id: str
    exact_validation_rows: list[Any]
    pcap_context: dict
    enrichment_context: dict
    compact_alert: dict
    grouped_alert_context: dict
    detection_validation: dict
    asset_context: dict
    authorization_evidence: dict
    analyst_state: dict
    correlation_context: dict
    role_memory_file: Path
    shared_memory_file: Path
    memory_bytes: int
    blind_reanalysis: bool
    incident_evidence_file: Path | None
    maximum_incident_evidence_bytes: int


@dataclass(frozen=True)
class PromptEvidenceAdmissionSources:
    """I/O and policy operations injected by the legacy composition root."""

    investigation_query_context: Callable[..., tuple[dict, dict]]
    build_agent_memory_context: Callable[..., dict]
    blind_model_authored_context: Callable[[dict, dict], tuple[dict, dict]]
    load_json_bounded: Callable[[Path, int], dict]
    validate_incident_evidence: Callable[[dict], Any]
    reject_preprojected_incident_evidence: Callable[[dict], Any]
    project_incident_evidence_hits: Callable[..., Any]


@dataclass(frozen=True)
class AdmittedPromptEvidence:
    """Evidence views approved for final model-facing package assembly."""

    investigation_capability: dict
    local_investigation_query_context: dict
    memory_context: dict
    correlation_context: dict
    incident_evidence: dict | None


def permitted_enrichment_indicators(enrichment_context: dict) -> dict:
    """Project only explicit public-enrichment indicators by exact kind."""
    indicators = enrichment_context.get("indicators", {})
    return {
        "ip": list(indicators.get("public_ips", [])),
        "domain": list(indicators.get("domains", [])),
        "url": list(indicators.get("urls", [])),
        "hash": [
            item.get("value") if isinstance(item, dict) else item
            for item in indicators.get("hashes", [])
        ],
        "cve": list(indicators.get("cves", [])),
    }


def _retain_confirmed_memory(memory: dict) -> None:
    for key in ("role_memory", "shared_memory"):
        section = memory.get(key)
        if not isinstance(section, dict):
            continue
        records = section.get("records")
        if isinstance(records, list):
            section["records"] = [
                record
                for record in records
                if (
                    isinstance(record, dict)
                    and str(record.get("status") or "") == "operator-confirmed"
                )
            ]
            refresh_selected_memory_snapshot(section)
    memory["usage_guidance"] = (
        "This is a blind reanalysis. Use only operator-authored notes and "
        "operator-confirmed memory; do not infer any previous model conclusion."
    )


def _remove_prior_correlations(correlation: dict) -> None:
    candidates = correlation.get("candidates")
    if not isinstance(candidates, list):
        return
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        candidate.pop("prior_analysis", None)
        candidate.pop("previous_correlation", None)
        reasons = candidate.get("correlation_reasons")
        if isinstance(reasons, list):
            candidate["correlation_reasons"] = [
                reason
                for reason in reasons
                if str(reason).strip().lower()
                != "previous correlation record exists"
            ]


def blind_model_authored_context(
    memory_context: dict,
    correlation_context: dict,
) -> tuple[dict, dict]:
    """Remove prior model conclusions while retaining confirmed context."""
    memory = json.loads(json.dumps(memory_context))
    correlation = json.loads(json.dumps(correlation_context))
    _retain_confirmed_memory(memory)
    _remove_prior_correlations(correlation)
    return memory, correlation


def _query_context(
    sources: PromptEvidenceAdmissionSources,
    request: PromptEvidenceAdmissionRequest,
) -> tuple[dict, dict]:
    parsed_pcap = request.pcap_context.get("parsed_evidence")
    capability, local_context = sources.investigation_query_context(
        request.selected,
        request.exact_validation_rows,
        request.group_id,
        request.agent_role,
        bool(isinstance(parsed_pcap, list) and parsed_pcap),
    )
    local_context["permitted_enrichment_indicators"] = (
        permitted_enrichment_indicators(request.enrichment_context)
    )
    return capability, local_context


def _memory_context(
    sources: PromptEvidenceAdmissionSources,
    request: PromptEvidenceAdmissionRequest,
) -> tuple[dict, dict]:
    memory = sources.build_agent_memory_context(
        agent_role=request.agent_role,
        role_memory_file=request.role_memory_file,
        shared_memory_file=request.shared_memory_file,
        evidence={
            "alert": request.compact_alert,
            "grouped_alert_context": request.grouped_alert_context,
            "public_enrichment": request.enrichment_context,
            "pcap_evidence": request.pcap_context,
            "detection_validation": request.detection_validation,
            "asset_context": request.asset_context,
            "authorization_evidence": request.authorization_evidence,
            "analyst_state": request.analyst_state,
            "correlated_alert_context": request.correlation_context,
        },
        limit_bytes=request.memory_bytes,
    )
    if not request.blind_reanalysis:
        return memory, request.correlation_context
    return sources.blind_model_authored_context(
        memory,
        request.correlation_context,
    )


def _incident_evidence(
    sources: PromptEvidenceAdmissionSources,
    request: PromptEvidenceAdmissionRequest,
) -> dict | None:
    if request.incident_evidence_file is None:
        return None
    evidence = sources.load_json_bounded(
        request.incident_evidence_file,
        request.maximum_incident_evidence_bytes,
    )
    sources.validate_incident_evidence(evidence)
    sources.reject_preprojected_incident_evidence(evidence)
    sources.project_incident_evidence_hits(
        evidence,
        limit=20,
        reason="initial_prompt_projection",
    )
    sources.validate_incident_evidence(evidence)
    return evidence


def prepare_prompt_evidence_admission(
    sources: PromptEvidenceAdmissionSources,
    request: PromptEvidenceAdmissionRequest,
) -> AdmittedPromptEvidence:
    """Return only query, memory, correlation, and IR evidence admitted by policy."""
    capability, local_context = _query_context(sources, request)
    memory, correlation = _memory_context(sources, request)
    return AdmittedPromptEvidence(
        investigation_capability=capability,
        local_investigation_query_context=local_context,
        memory_context=memory,
        correlation_context=correlation,
        incident_evidence=_incident_evidence(sources, request),
    )
