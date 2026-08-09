"""Capability advertisement and bounded follow-up for live endpoint OSQuery."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class Policy:
    schema: str
    supported_roles: frozenset[str]
    default_allowed_roles: tuple[str, ...] = ("incident-responder",)
    model_route_role: str = "incident-responder"


@dataclass(frozen=True)
class Dependencies:
    capability_descriptor: Callable[[dict[str, Any]], dict[str, Any]]
    collect: Callable[[str, list[dict[str, Any]], dict[str, Any]], dict[str, Any]]
    now: Callable[[], str]
    canonical_model_route: Callable[[Any], str]
    analyze_model_route: Callable[
        [str, dict[str, Any], Any, dict[str, Any]], dict[str, Any]
    ]
    collection_errors: tuple[type[BaseException], ...]
    client_error: type[Exception]


def _role_scoped_config(
    config: dict[str, Any],
    agent_role: str,
    policy: Policy,
) -> dict[str, Any]:
    allowed = config.get("allowed_agent_roles")
    if not isinstance(allowed, list):
        allowed = list(policy.default_allowed_roles)
    if agent_role in allowed:
        return config
    return {**config, "enabled": False, "allowed_target_aliases": []}


def _backend_descriptor(descriptor: dict[str, Any]) -> dict[str, Any]:
    return {
        "enabled": bool(descriptor.get("enabled")),
        "target_aliases": list(descriptor.get("target_aliases") or []),
        "allowed_tables": list(descriptor.get("allowed_tables") or []),
        "target_platform": descriptor.get("target_platform") or "",
        "osquery_version": descriptor.get("osquery_version") or "",
        "table_schemas": dict(descriptor.get("table_schemas") or {}),
        "max_queries": descriptor.get("max_queries"),
        "max_rows_per_query": descriptor.get("max_rows_per_query"),
        "restrictions": list(descriptor.get("restrictions") or []),
    }


def prepare_capability(
    prompt_package: dict[str, Any],
    agent_role: str,
    config: dict[str, Any],
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any] | None:
    """Advertise a role-scoped, model-safe live endpoint capability."""
    if agent_role not in policy.supported_roles:
        return None
    scoped = _role_scoped_config(config, agent_role, policy)
    descriptor = dependencies.capability_descriptor(scoped)
    prompt_package["live_osquery_capability"] = descriptor
    capability = prompt_package.get("investigation_query_capability")
    if isinstance(capability, dict):
        if descriptor.get("enabled") is True:
            capability["enabled"] = True
        backends = capability.get("backends")
        if isinstance(backends, dict):
            backends["osquery"] = _backend_descriptor(descriptor)
    return scoped


def case_id(prompt_package: dict[str, Any]) -> str:
    """Derive a non-sensitive stable case token for cross-node correlation."""
    analyst_state = prompt_package.get("analyst_state")
    alert = prompt_package.get("alert")
    raw = ""
    if isinstance(analyst_state, dict):
        raw = str(analyst_state.get("group_id") or "")
    if not raw and isinstance(alert, dict):
        raw = str(alert.get("alert_id") or alert.get("rule_name") or "")
    return "ir-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _collect_evidence(
    case_token: str,
    requests: list[dict[str, Any]],
    config: dict[str, Any] | None,
    policy: Policy,
    dependencies: Dependencies,
) -> tuple[dict[str, Any], str]:
    try:
        if not config or not config.get("enabled"):
            raise dependencies.client_error(
                "live-host OSQuery is not enabled for this deployment"
            )
        return dependencies.collect(case_token, requests, config), ""
    except dependencies.collection_errors as exc:
        error = str(exc)[:1000]
        return {
            "schema": policy.schema,
            "case_id": case_token,
            "generated_at": dependencies.now(),
            "complete": False,
            "read_only": True,
            "results": [],
            "collection_error": error,
        }, error


def _attach_follow_up_context(
    prompt_package: dict[str, Any],
    evidence: dict[str, Any],
) -> None:
    prompt_package["live_osquery_evidence"] = evidence
    prompt_package["live_osquery_follow_up"] = {
        "final_pass": True,
        "instruction": (
            "Use the collected endpoint evidence and return the final report. "
            "Do not request another live OSQuery batch."
        ),
    }


def follow_up(
    prompt_package: dict[str, Any],
    primary_response: dict[str, Any],
    args: Any,
    settings: dict[str, Any],
    config: dict[str, Any] | None,
    *,
    policy: Policy,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Execute one validated endpoint batch and one final model pass."""
    requests = primary_response.pop("live_osquery_requests", [])
    if not requests:
        return primary_response
    evidence, collection_error = _collect_evidence(
        case_id(prompt_package), requests, config, policy, dependencies
    )
    _attach_follow_up_context(prompt_package, evidence)
    models = settings.get("agent_models") or {}
    route = dependencies.canonical_model_route(
        models.get(policy.model_route_role)
    )
    final = dependencies.analyze_model_route(
        route, prompt_package, args, settings
    )
    repeated = final.pop("live_osquery_requests", [])
    final["_live_osquery_follow_up"] = {
        "requested": len(requests) if isinstance(requests, list) else 0,
        "collected": len(evidence.get("results") or []),
        "complete": bool(evidence.get("complete")),
        "collection_error": collection_error,
        "repeated_requests_ignored": (
            len(repeated) if isinstance(repeated, list) else 0
        ),
    }
    return final
