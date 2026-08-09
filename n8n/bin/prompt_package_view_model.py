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
