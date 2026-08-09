"""Fail-closed reviewer precommit admission for controlled evaluations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    attestation_schema: str
    maximum_reason_length: int = 1000


@dataclass(frozen=True)
class Dependencies:
    route_identity: Callable[[str, dict[str, Any]], str]
    route_is_hosted: Callable[[str, dict[str, Any]], bool]
    build_review_package: Callable[..., dict[str, Any]]
    validate_reviewer: Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
    validate_response: Callable[[dict[str, Any], dict[str, Any]], Any]
    validation_errors: tuple[type[BaseException], ...]
    gate_error: type[Exception]


def enforce(
    prompt_package: dict[str, Any], response: dict[str, Any],
    settings: dict[str, Any], agent_role: str, *, trigger_reason: str,
    freeze_enabled: bool, policy: Policy, dependencies: Dependencies,
) -> dict[str, Any] | None:
    """Require one case-bound reviewer decision before frozen persistence."""
    second_opinion = _second_opinion(response)
    reviewer_response = _reviewer_response(second_opinion)
    reviewer_route = _configured_route(
        settings, "agent_second_opinion_models", agent_role,
    )
    if not _required(
        freeze_enabled, trigger_reason, reviewer_route, settings, agent_role,
        dependencies,
    ):
        return reviewer_response
    if second_opinion is None or reviewer_response is None:
        _reject(_missing_reason(second_opinion), policy, dependencies)
    _validate_history(second_opinion, policy, dependencies)
    review_package = dependencies.build_review_package(
        prompt_package,
        hosted=dependencies.route_is_hosted(reviewer_route, settings),
    )
    try:
        validated = dependencies.validate_reviewer(reviewer_response, review_package)
        dependencies.validate_response(validated, review_package)
    except dependencies.validation_errors as exc:
        _reject(f"retained reviewer response is not recordable: {exc}", policy, dependencies)
    _validate_attestation(reviewer_response, review_package, policy, dependencies)
    return reviewer_response


def _second_opinion(response: dict[str, Any]) -> dict[str, Any] | None:
    value = response.get("_second_opinion")
    return value if isinstance(value, dict) else None


def _reviewer_response(second_opinion: Any) -> dict[str, Any] | None:
    value = second_opinion.get("response") if isinstance(second_opinion, dict) else None
    return value if isinstance(value, dict) else None


def _configured_route(
    settings: dict[str, Any], key: str, agent_role: str,
) -> str:
    routes = settings.get(key) or {}
    return str(routes.get(agent_role) or "").strip()


def _required(
    freeze_enabled: bool, trigger_reason: str, reviewer_route: str,
    settings: dict[str, Any], agent_role: str, dependencies: Dependencies,
) -> bool:
    if not freeze_enabled or not str(trigger_reason or "").strip() or not reviewer_route:
        return False
    primary = _configured_route(settings, "agent_models", agent_role)
    return dependencies.route_identity(primary, settings) != dependencies.route_identity(
        reviewer_route, settings,
    )


def _missing_reason(second_opinion: dict[str, Any] | None) -> str:
    status = str(second_opinion.get("status") or "missing") if second_opinion else "missing"
    error = str(second_opinion.get("error") or "").strip() if second_opinion else ""
    suffix = f"; error={error}" if error else ""
    return (
        "the triggered independent reviewer produced no validated response "
        f"(status={status}{suffix})"
    )


def _reject(reason: str, policy: Policy, dependencies: Dependencies) -> None:
    raise dependencies.gate_error(
        "controlled evaluation reviewer precommit gate failed: "
        f"{reason[:policy.maximum_reason_length]}"
    )


def _validate_history(
    second_opinion: dict[str, Any], policy: Policy, dependencies: Dependencies,
) -> None:
    status = str(second_opinion.get("status") or "").strip().lower()
    if status not in {"completed", "invalid"}:
        _reject(f"reviewer response has non-recordable status {status or 'missing'}", policy, dependencies)
    attempts, failures = second_opinion.get("attempts"), second_opinion.get("validation_failures")
    valid = (
        not isinstance(attempts, bool) and attempts in {1, 2}
        and isinstance(failures, list) and len(failures) == attempts - 1
    )
    if not valid:
        _reject("reviewer attempt history exceeds or violates the one-repair contract", policy, dependencies)


def _validate_attestation(
    reviewer_response: dict[str, Any], review_package: dict[str, Any],
    policy: Policy, dependencies: Dependencies,
) -> None:
    attestation = reviewer_response.get("_review_contract_validation")
    expected = review_package["review_contract"]
    valid = (
        isinstance(attestation, dict)
        and attestation.get("schema") == policy.attestation_schema
        and attestation.get("valid") is True
        and str(attestation.get("case_id") or "") == str(expected.get("case_id") or "")
        and str(attestation.get("evidence_hash") or "") == str(expected.get("evidence_hash") or "")
    )
    if not valid:
        _reject("reviewer validation attestation is missing or does not bind this case", policy, dependencies)
