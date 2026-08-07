"""Pure normalization and authorization for one investigation-query round."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence


@dataclass(frozen=True)
class Authorization:
    allowed: bool
    capability: str = ""
    reason: str = ""


@dataclass(frozen=True)
class Dependencies:
    normalize: Callable[..., dict[str, Any]]
    validate_repair: Callable[[dict[str, Any], dict[str, Any]], None]
    backend_available: Callable[[str], bool]
    semantic_digest: Callable[[dict[str, Any]], str]
    ignore_semantic_repeat: Callable[[Any], Any]
    authorize: Callable[[dict[str, Any]], Authorization]
    repair_scope: Callable[..., dict[str, Any] | None]
    query_text: Callable[[Any, int], str]
    valid_query_id: Callable[[str], bool]


@dataclass(frozen=True)
class Result:
    state: Any
    normalized: tuple[dict[str, Any], ...]
    rejected: tuple[dict[str, Any], ...]
    repair_scopes: dict[str, dict[str, Any]]
    seen_semantic_digests: frozenset[str]


@dataclass(frozen=True)
class _OneResult:
    state: Any
    admitted: dict[str, Any] | None = None
    rejected: dict[str, Any] | None = None
    repair_candidate: tuple[str, dict[str, Any]] | None = None


def resolve_authorization(
    *,
    runtime_present: bool,
    approval_gated: bool,
    policy_mode: str,
    decision: Any,
    decision_effective: Callable[[str, Any], bool],
    fallback_capability: str,
) -> Authorization:
    """Resolve an injected harness decision without granting query authority."""
    if not runtime_present:
        return Authorization(True)
    if decision is None:
        return (
            Authorization(
                False,
                fallback_capability,
                "approval authorization was unavailable",
            )
            if approval_gated
            else Authorization(True)
        )
    if decision_effective(policy_mode, decision):
        return Authorization(True)
    return Authorization(False, decision.capability, decision.reason)


def _rejection(
    query_id: str,
    backend: str,
    error: str,
    *,
    semantic_digest: str = "",
) -> dict[str, Any]:
    result = {
        "query_id": query_id,
        "backend": backend,
        "status": "rejected",
        "read_only": True,
        "error": error,
    }
    if semantic_digest:
        result["request_semantic_digest"] = semantic_digest
    return result


def _contract_query_id(
    raw: Any,
    round_number: int,
    position: int,
    dependencies: Dependencies,
) -> str:
    candidate = (
        dependencies.query_text(raw.get("query_id"), 64)
        if isinstance(raw, dict)
        else ""
    )
    return (
        candidate
        if dependencies.valid_query_id(candidate)
        else f"round-{round_number}-query-{position}"
    )


def _normalize(
    raw: Any,
    *,
    round_number: int,
    position: int,
    repair_round: bool,
    repair_scopes: Mapping[str, dict[str, Any]],
    time_envelope: Any,
    authorization_context: Any,
    dependencies: Dependencies,
    error_type: type[Exception],
) -> dict[str, Any]:
    if repair_round:
        query_id = (
            dependencies.query_text(raw.get("query_id"), 64)
            if isinstance(raw, dict)
            else ""
        )
        if query_id not in repair_scopes:
            raise error_type("query repair emitted an unrequested query_id")
    request = dependencies.normalize(
        raw,
        round_number=round_number,
        position=position,
        time_envelope=time_envelope,
        authorization_context=authorization_context,
    )
    if repair_round:
        dependencies.validate_repair(request, repair_scopes[request["query_id"]])
    return request


def _repair_candidate(
    raw: Any,
    reason: str,
    *,
    round_number: int,
    position: int,
    time_envelope: Any,
    authorization_context: Any,
    dependencies: Dependencies,
) -> tuple[str, dict[str, Any]] | None:
    scope = dependencies.repair_scope(
        raw,
        round_number=round_number,
        position=position,
        time_envelope=time_envelope,
        authorization_context=authorization_context,
    )
    if scope is None:
        return None
    return scope["query_id"], {
        "scope": scope,
        "reason": reason[:1000],
        "trigger": "contract_rejection",
    }


def _admit_normalized(
    request: dict[str, Any],
    *,
    state: Any,
    round_number: int,
    position: int,
    repair_round: bool,
    seen_ids: set[str],
    semantic_history: set[str],
    dependencies: Dependencies,
    error_type: type[Exception],
) -> tuple[Any, dict[str, Any] | None, dict[str, Any] | None]:
    if request["query_id"] in seen_ids:
        if repair_round:
            raise error_type("query repair repeated a rejected query_id")
        request["query_id"] = f"round-{round_number}-query-{position}"
    seen_ids.add(request["query_id"])
    if not dependencies.backend_available(request["backend"]):
        return state, None, _rejection(
            request["query_id"],
            request["backend"],
            f"{request['backend']} investigation backend is disabled, "
            "unadvertised, or lacks trusted local evidence",
        )
    digest = dependencies.semantic_digest(request)
    if digest in semantic_history and not repair_round:
        return dependencies.ignore_semantic_repeat(state), None, _rejection(
            request["query_id"],
            request["backend"],
            "equivalent investigation query was already executed in an earlier round",
            semantic_digest=digest,
        )
    authorization = dependencies.authorize(request)
    if not authorization.allowed:
        return state, None, _rejection(
            request["query_id"],
            request["backend"],
            "Onion Sentinel harness denied capability "
            f"{authorization.capability}: {authorization.reason}",
        )
    semantic_history.add(digest)
    return state, request, None


def _contract_failure(
    raw: Any,
    exc: Exception,
    *,
    round_number: int,
    position: int,
    repair_round: bool,
    time_envelope: Any,
    authorization_context: Any,
    dependencies: Dependencies,
) -> tuple[dict[str, Any], tuple[str, dict[str, Any]] | None]:
    reason = str(exc)[:1000]
    query_id = _contract_query_id(raw, round_number, position, dependencies)
    candidate = None if repair_round else _repair_candidate(
        raw,
        reason,
        round_number=round_number,
        position=position,
        time_envelope=time_envelope,
        authorization_context=authorization_context,
        dependencies=dependencies,
    )
    return _rejection(query_id, "contract", reason), candidate


def _process_one(
    raw: Any,
    *,
    state: Any, round_number: int, position: int, repair_round: bool,
    pending_repair_scopes: Mapping[str, dict[str, Any]],
    time_envelope: Any, authorization_context: Any,
    seen_ids: set[str], semantic_history: set[str],
    dependencies: Dependencies, error_type: type[Exception],
) -> _OneResult:
    try:
        request = _normalize(
            raw,
            round_number=round_number,
            position=position,
            repair_round=repair_round,
            repair_scopes=pending_repair_scopes,
            time_envelope=time_envelope,
            authorization_context=authorization_context,
            dependencies=dependencies,
            error_type=error_type,
        )
        updated, admitted, denied = _admit_normalized(
            request,
            state=state,
            round_number=round_number,
            position=position,
            repair_round=repair_round,
            seen_ids=seen_ids,
            semantic_history=semantic_history,
            dependencies=dependencies,
            error_type=error_type,
        )
        return _OneResult(state=updated, admitted=admitted, rejected=denied)
    except error_type as exc:
        rejection, candidate = _contract_failure(
            raw,
            exc,
            round_number=round_number,
            position=position,
            repair_round=repair_round,
            time_envelope=time_envelope,
            authorization_context=authorization_context,
            dependencies=dependencies,
        )
        return _OneResult(
            state=state, rejected=rejection, repair_candidate=candidate
        )


def run(
    raw_requests: Sequence[Any],
    *,
    state: Any,
    round_number: int,
    repair_round: bool,
    pending_repair_scopes: Mapping[str, dict[str, Any]],
    seen_semantic_digests: set[str] | frozenset[str],
    time_envelope: Any,
    authorization_context: Any,
    dependencies: Dependencies,
    error_type: type[Exception],
) -> Result:
    """Normalize and authorize a bounded round without executing any query."""
    normalized: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    repair_candidates: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    semantic_history = set(seen_semantic_digests)
    updated_state = state
    for position, raw in enumerate(raw_requests, 1):
        item = _process_one(
            raw, state=updated_state, round_number=round_number,
            position=position, repair_round=repair_round,
            pending_repair_scopes=pending_repair_scopes,
            time_envelope=time_envelope,
            authorization_context=authorization_context,
            seen_ids=seen_ids, semantic_history=semantic_history,
            dependencies=dependencies, error_type=error_type,
        )
        updated_state = item.state
        if item.admitted is not None:
            normalized.append(item.admitted)
        if item.rejected is not None:
            rejected.append(item.rejected)
        if item.repair_candidate is not None:
            repair_candidates[item.repair_candidate[0]] = item.repair_candidate[1]
    return Result(
        state=updated_state,
        normalized=tuple(normalized),
        rejected=tuple(rejected),
        repair_scopes=repair_candidates,
        seen_semantic_digests=frozenset(semantic_history),
    )
