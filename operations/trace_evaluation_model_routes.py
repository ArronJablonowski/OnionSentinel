#!/usr/bin/env python3
"""Prove assigned model-route authorization and observed runtime identity."""
from __future__ import annotations

import collections
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence


@dataclass(frozen=True)
class ModelRoutePolicy:
    success_statuses: frozenset[str]
    validation_failed_status: str
    maximum_reported: int
    normalize_status: Callable[[object], str]
    safe_json: Callable[..., Any]


@dataclass
class _EventIndex:
    authorizations: dict[str, list[dict[str, Any]]]
    observations: dict[str, list[dict[str, Any]]]
    denied_authorizations: list[str]
    denied_observations: list[str]
    malformed_authorizations: int = 0
    malformed_observations: int = 0


@dataclass
class _CallResults:
    authorized: int = 0
    authorization_failures: list[dict[str, Any]] | None = None
    authorization_unverified: list[str] | None = None
    identity_verified: int = 0
    identity_failures: list[dict[str, Any]] | None = None
    identity_unverified: list[str] | None = None
    identity_not_applicable: int = 0

    def __post_init__(self) -> None:
        self.authorization_failures = self.authorization_failures or []
        self.authorization_unverified = self.authorization_unverified or []
        self.identity_failures = self.identity_failures or []
        self.identity_unverified = self.identity_unverified or []


def expected_route_identity(route: object) -> dict[str, str] | None:
    """Project a supported assigned route into collector-owned metadata."""
    normalized = str(route or "").strip()
    if normalized.startswith("codex-cli:"):
        return _codex_identity(normalized.removeprefix("codex-cli:"))
    if normalized.startswith("ollama:"):
        return _ollama_identity(normalized.removeprefix("ollama:"))
    return _agent_identity(normalized)


def _codex_identity(value: str) -> dict[str, str] | None:
    model, separator, _effort = value.rpartition(":")
    if not separator or not model:
        return None
    return {
        "model": model,
        "provider": "codex-cli",
        "path": "frontier-codex-cli",
        "harness": "",
    }


def _ollama_identity(model: str) -> dict[str, str] | None:
    if not model:
        return None
    return {
        "model": model,
        "provider": "ollama",
        "path": "ollama",
        "harness": "",
    }


def _agent_identity(route: str) -> dict[str, str] | None:
    for agent in ("hermes-agent", "openclaw"):
        prefix = f"{agent}:"
        if route.startswith(prefix):
            return _parsed_agent_identity(agent, route.removeprefix(prefix))
    return None


def _parsed_agent_identity(agent: str, value: str) -> dict[str, str] | None:
    model, separator, _effort = value.rpartition(":")
    if not separator or not model:
        return None
    provider = "openai-codex" if agent == "hermes-agent" else _openclaw_provider(model)
    return {"model": model, "provider": provider, "path": agent, "harness": agent}


def _openclaw_provider(model: str) -> str:
    return model.split("/", 1)[0] if "/" in model else "openclaw"


def _empty_index() -> _EventIndex:
    return _EventIndex({}, {}, [], [])


def _event_index(
    events: Sequence[Mapping[str, Any]],
    malformed: collections.Counter[str],
    policy: ModelRoutePolicy,
) -> _EventIndex:
    index = _empty_index()
    for event in events:
        event_type = str(event.get("event_type") or "")
        if event_type not in {"policy.model-route", "policy.model-observation"}:
            continue
        payload = _event_payload(event, event_type, malformed, policy)
        call_id = str(payload.get("call_id") or "")
        if not call_id:
            _record_malformed(index, event_type)
            continue
        _record_event(index, event_type, call_id, payload)
    return index


def _event_payload(
    event: Mapping[str, Any],
    event_type: str,
    malformed: collections.Counter[str],
    policy: ModelRoutePolicy,
) -> dict[str, Any]:
    label = (
        "event.policy_model_route.payload_json"
        if event_type == "policy.model-route"
        else "event.policy_model_observation.payload_json"
    )
    return policy.safe_json(event.get("payload_json"), {}, malformed, label)


def _record_malformed(index: _EventIndex, event_type: str) -> None:
    if event_type == "policy.model-route":
        index.malformed_authorizations += 1
    else:
        index.malformed_observations += 1


def _record_event(
    index: _EventIndex,
    event_type: str,
    call_id: str,
    payload: dict[str, Any],
) -> None:
    if event_type == "policy.model-route":
        index.authorizations.setdefault(call_id, []).append(payload)
        if not bool(payload.get("allowed")):
            index.denied_authorizations.append(call_id)
        return
    index.observations.setdefault(call_id, []).append(payload)
    if not bool(payload.get("allowed")):
        index.denied_observations.append(call_id)


def _expected_route(run: Mapping[str, Any], independent: bool) -> str:
    key = "assigned_reviewer_route" if independent else "assigned_route"
    return str(run.get(key) or "")


def _authorization_reasons(
    independent: bool,
    requested: str,
    expected: str,
    authorizations: Sequence[Mapping[str, Any]],
    observations: Sequence[Mapping[str, Any]],
) -> list[str]:
    reasons: list[str] = []
    if not expected:
        reasons.append("assigned-route-missing")
    if requested != expected:
        reasons.append("model-ledger-requested-route-mismatch")
    reasons.extend(_authorization_event_reasons(independent, requested, expected, authorizations))
    reasons.extend(_observation_event_reasons(independent, requested, observations))
    return sorted(set(reasons))


def _authorization_event_reasons(
    independent: bool,
    requested: str,
    expected: str,
    events: Sequence[Mapping[str, Any]],
) -> list[str]:
    if not events:
        return ["authorization-event-missing"]
    if len(events) != 1:
        return ["authorization-event-count-mismatch"]
    event = events[0]
    reasons: list[str] = []
    if not bool(event.get("allowed")):
        reasons.append("authorization-denied-but-model-recorded")
    if str(event.get("requested_route") or "") != requested:
        reasons.append("authorization-requested-route-mismatch")
    if str(event.get("expected_route") or "") != expected:
        reasons.append("authorization-assignment-mismatch")
    if bool(event.get("independent_review")) != independent:
        reasons.append("authorization-role-mismatch")
    return reasons


def _observation_event_reasons(
    independent: bool,
    requested: str,
    events: Sequence[Mapping[str, Any]],
) -> list[str]:
    if not events:
        return ["model-observation-event-missing"]
    if len(events) != 1:
        return ["model-observation-event-count-mismatch"]
    event = events[0]
    reasons: list[str] = []
    if str(event.get("requested_route") or "") != requested:
        reasons.append("model-observation-requested-route-mismatch")
    if bool(event.get("independent_review")) != independent:
        reasons.append("model-observation-role-mismatch")
    return reasons


def _identity_reasons(
    requested: str,
    expected: Mapping[str, str],
    observed: Mapping[str, str],
    observations: Sequence[Mapping[str, Any]],
) -> list[str]:
    reasons: list[str] = []
    if len(observations) == 1:
        observed_route = str(observations[0].get("observed_route") or "")
        if observed_route != requested:
            reasons.append("observed-route-mismatch")
    for field in ("model", "path", "harness"):
        if expected[field] and observed[field] != expected[field]:
            reasons.append(f"observed-{field}-mismatch")
    if expected["provider"] and observed["provider"] != expected["provider"]:
        reasons.append("observed-provider-mismatch")
    return sorted(set(reasons))


def _observed_identity(row: Mapping[str, Any]) -> dict[str, str]:
    return {
        "model": str(row.get("observed_model") or ""),
        "provider": str(row.get("observed_provider") or ""),
        "path": str(row.get("observed_model_path") or ""),
        "harness": str(row.get("observed_harness") or ""),
    }


def _evaluate_authorization(
    call_id: str,
    independent: bool,
    requested: str,
    expected: str,
    index: _EventIndex,
    current_contract: bool,
    results: _CallResults,
) -> None:
    if not current_contract:
        results.authorization_unverified.append(call_id)
        return
    reasons = _authorization_reasons(
        independent,
        requested,
        expected,
        index.authorizations.get(call_id, []),
        index.observations.get(call_id, []),
    )
    if reasons:
        results.authorization_failures.append({"call_id": call_id, "reasons": reasons})
    else:
        results.authorized += 1


def _evaluate_identity(
    row: Mapping[str, Any],
    call_id: str,
    requested: str,
    index: _EventIndex,
    results: _CallResults,
    policy: ModelRoutePolicy,
) -> None:
    valid_statuses = policy.success_statuses | {policy.validation_failed_status}
    if policy.normalize_status(row.get("status")) not in valid_statuses:
        results.identity_not_applicable += 1
        return
    expected = expected_route_identity(requested)
    if expected is None:
        results.identity_unverified.append(call_id)
        return
    observed = _observed_identity(row)
    reasons = _identity_reasons(
        requested, expected, observed, index.observations.get(call_id, [])
    )
    if not reasons:
        results.identity_verified += 1
        return
    results.identity_failures.append(
        {
            "call_id": call_id,
            "requested_route": requested,
            "observed_model": observed["model"],
            "observed_model_path": observed["path"],
            "observed_provider": observed["provider"],
            "observed_harness": observed["harness"],
            "reasons": reasons,
        }
    )


def _evaluate_calls(
    run: Mapping[str, Any],
    model_calls: Sequence[Mapping[str, Any]],
    index: _EventIndex,
    current_contract: bool,
    policy: ModelRoutePolicy,
) -> _CallResults:
    results = _CallResults()
    for row in model_calls:
        call_id = str(row.get("call_id") or "")
        independent = int(row.get("independent_review") or 0) == 1
        requested = str(row.get("requested_route") or "")
        _evaluate_authorization(
            call_id, independent, requested, _expected_route(run, independent),
            index, current_contract, results,
        )
        _evaluate_identity(row, call_id, requested, index, results, policy)
    return results


def _bounded_ids(values: Sequence[str], maximum: int) -> list[str]:
    return sorted(set(values))[:maximum]


def _event_summary(
    index: _EventIndex,
    model_call_ids: set[str],
    maximum: int,
) -> dict[str, Any]:
    orphan_authorizations = sorted(set(index.authorizations) - model_call_ids)
    orphan_observations = sorted(set(index.observations) - model_call_ids)
    return {
        "authorization_event_count": sum(map(len, index.authorizations.values())),
        "authorization_allowed_event_count": sum(
            bool(item.get("allowed"))
            for items in index.authorizations.values()
            for item in items
        ),
        "authorization_denied_event_count": len(index.denied_authorizations),
        "authorization_denied_call_ids": _bounded_ids(index.denied_authorizations, maximum),
        "authorization_malformed_event_count": index.malformed_authorizations,
        "authorization_orphan_event_count": len(orphan_authorizations),
        "authorization_orphan_call_ids": orphan_authorizations[:maximum],
        "observation_event_count": sum(map(len, index.observations.values())),
        "observation_denied_event_count": len(index.denied_observations),
        "observation_denied_call_ids": _bounded_ids(index.denied_observations, maximum),
        "observation_malformed_event_count": index.malformed_observations,
        "observation_orphan_event_count": len(orphan_observations),
        "observation_orphan_call_ids": orphan_observations[:maximum],
    }


def _call_summary(
    results: _CallResults,
    maximum: int,
) -> dict[str, Any]:
    return {
        "authorized_call_count": results.authorized,
        "authorization_failure_count": len(results.authorization_failures),
        "authorization_failures": results.authorization_failures[:maximum],
        "authorization_unverified_call_count": len(results.authorization_unverified),
        "authorization_unverified_call_ids": _bounded_ids(
            results.authorization_unverified, maximum
        ),
        "identity_verified_call_count": results.identity_verified,
        "identity_mismatch_count": len(results.identity_failures),
        "identity_failures": results.identity_failures[:maximum],
        "identity_unverified_call_count": len(results.identity_unverified),
        "identity_unverified_call_ids": _bounded_ids(results.identity_unverified, maximum),
        "identity_not_applicable_count": results.identity_not_applicable,
    }


def model_route_consistency(
    run: Mapping[str, Any],
    events: Sequence[Mapping[str, Any]],
    model_calls: Sequence[Mapping[str, Any]],
    malformed: collections.Counter[str],
    policy: ModelRoutePolicy,
) -> dict[str, Any]:
    """Evaluate requested-route authorization and observed runtime identity."""
    index = _event_index(events, malformed, policy)
    current_contract = all(
        key in run for key in ("assigned_route", "assigned_reviewer_route")
    )
    model_call_ids = {
        str(row.get("call_id") or "")
        for row in model_calls
        if str(row.get("call_id") or "")
    }
    results = _evaluate_calls(run, model_calls, index, current_contract, policy)
    return {
        "contract_available": current_contract,
        **_event_summary(index, model_call_ids, policy.maximum_reported),
        **_call_summary(results, policy.maximum_reported),
    }
