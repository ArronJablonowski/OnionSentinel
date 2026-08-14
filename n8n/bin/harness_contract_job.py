"""Pure immutable job-envelope field projection."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from harness_policy import AgentRole, HARNESS_SCHEMA, HarnessPolicyError


@dataclass(frozen=True)
class JobEnvelopeProjectionServices:
    valid_identifier: Callable[..., str]
    model_route: Callable[..., str]
    digest_value: Callable[[Any], str]
    task_kind_value: Callable[..., str]
    skill_attestation: Callable[[Mapping[str, Any]], dict[str, Any]]
    execution_contract_builder: Callable[..., dict[str, Any]]
    execution_contract_json_value: Callable[[Any], str]
    execution_contract_digest_value: Callable[[Any], str]
    now_value: Callable[[], str]


def _validate_role(role: str) -> None:
    try:
        AgentRole(role)
    except ValueError as exc:
        raise HarnessPolicyError(f"unsupported agent role: {role}") from exc


def _prompt_identity_values(
    prompt_package: Mapping[str, Any],
    run_id: str,
) -> tuple[str, str, str, dict[str, Any]]:
    alert = _mapping_value(prompt_package, "alert")
    incident = _mapping_value(prompt_package, "incident_response_evidence")
    alert_id = str(alert.get("alert_id") or prompt_package.get("alert_id") or "")
    case_id = str(
        incident.get("case_id")
        or prompt_package.get("case_id")
        or alert_id
        or run_id
    )
    return (
        alert_id,
        case_id,
        _correlation_id(prompt_package, case_id),
        _mapping_value(prompt_package, "evidence_reference_contract"),
    )


def _identity_fields(
    *,
    run_id: str,
    correlation_id: str,
    case_id: str,
    alert_id: str,
    valid_identifier: Callable[..., str],
) -> dict[str, str]:
    run_id = valid_identifier(run_id, "run_id", 128)
    return {
        "run_id": run_id,
        "trace_id": hashlib.sha256(
            f"{HARNESS_SCHEMA}:{run_id}".encode("utf-8")
        ).hexdigest()[:32],
        "correlation_id": valid_identifier(
            correlation_id or run_id,
            "correlation_id",
        ),
        "case_id": valid_identifier(case_id or run_id, "case_id"),
        "alert_id": valid_identifier(alert_id, "alert_id") if alert_id else "",
    }


def _execution_contract_fields(
    *,
    prompt_package: Mapping[str, Any],
    contract: Mapping[str, Any],
    assigned_route: str,
    configuration: Mapping[str, Any],
    source_revision: str,
    policy_version: str,
    services: JobEnvelopeProjectionServices,
) -> dict[str, Any]:
    primary_route = services.model_route(assigned_route, "assigned primary route")
    reviewer_route = services.model_route(
        configuration.get("reviewer_route"),
        "assigned reviewer route",
        allow_empty=True,
    )
    skills = services.skill_attestation(prompt_package)
    execution_contract = services.execution_contract_builder(
        source_revision=source_revision,
        assigned_route=primary_route,
        reviewer_route=reviewer_route,
        policy_version=policy_version,
        skill_attestation=skills,
    )
    return {
        "assigned_route": primary_route,
        "assigned_reviewer_route": reviewer_route,
        "prompt_digest": services.digest_value(prompt_package),
        "evidence_manifest_digest": services.digest_value(contract),
        "configuration_digest": services.digest_value(configuration),
        "execution_contract_json": services.execution_contract_json_value(
            execution_contract
        ),
        "execution_contract_digest": services.execution_contract_digest_value(
            execution_contract
        ),
        "skill_selection_attestation": skills,
    }


def _parent_run_id(prompt_package: Mapping[str, Any]) -> str:
    return str(
        prompt_package.get("parent_analysis_id")
        or prompt_package.get("prior_analysis_id")
        or ""
    )[:128]


def job_envelope_values(
    *,
    run_id: str,
    prompt_package: Mapping[str, Any],
    role: str,
    assigned_route: str,
    configuration: Mapping[str, Any],
    source_revision: str,
    policy_version: str,
    reanalysis_attempt_id: str,
    services: JobEnvelopeProjectionServices,
) -> dict[str, Any]:
    """Validate a prompt and return the exact immutable envelope fields."""
    _validate_role(role)
    alert_id, case_id, correlation_id, contract = _prompt_identity_values(
        prompt_package,
        run_id,
    )
    task_kind = services.task_kind_value(
        role,
        reanalysis_attempt_id=reanalysis_attempt_id,
        manual_reanalysis=bool(prompt_package.get("manual_reanalysis")),
    )
    return {
        **_identity_fields(
            run_id=run_id,
            correlation_id=correlation_id,
            case_id=case_id,
            alert_id=alert_id,
            valid_identifier=services.valid_identifier,
        ),
        "role": role,
        "task_kind": task_kind,
        **_execution_contract_fields(
            prompt_package=prompt_package,
            contract=contract,
            assigned_route=assigned_route,
            configuration=configuration,
            source_revision=source_revision,
            policy_version=policy_version,
            services=services,
        ),
        "parent_run_id": _parent_run_id(prompt_package),
        "created_at": services.now_value(),
    }


def _mapping_value(
    prompt_package: Mapping[str, Any],
    key: str,
) -> dict[str, Any]:
    value = prompt_package.get(key)
    return value if isinstance(value, dict) else {}


def _correlation_id(
    prompt_package: Mapping[str, Any],
    case_id: str,
) -> str:
    grouped_context = _mapping_value(prompt_package, "grouped_alert_context")
    return str(
        prompt_package.get("group_id")
        or grouped_context.get("group_id")
        or case_id
    )
