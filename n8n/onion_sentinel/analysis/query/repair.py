"""Fail-closed repair contracts for rejected investigation queries."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Type

from . import primitives, repair_catalog


OBSERVABLE_KINDS = repair_catalog.OBSERVABLE_KINDS
REPAIRABLE_STATUSES = frozenset(
    {"rejected", "invalid", "invalid_request", "invalid_response", "contract_error"}
)


@dataclass(frozen=True)
class Dependencies:
    normalize_request: Callable[..., dict[str, Any]]
    normalize_event_tuple: Callable[[dict[str, Any]], dict[str, Any]]
    pack_event_tuple_fields: Callable[[str], set[str] | frozenset[str]]
    prompt_error_category: Callable[[Any], str]
    prompt_error_digest: Callable[[Any], str]
    canonical_digest: Callable[[Any], str]


def recover_observables(
    value: Any, authorization_context: Any,
) -> dict[str, list[str]] | None:
    return repair_catalog.recover(value, authorization_context)


def _valid_observables(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and not set(value).difference(OBSERVABLE_KINDS)
        and all(
            isinstance(value.get(kind, []), list)
            and len(value.get(kind, [])) <= 8
            for kind in OBSERVABLE_KINDS
        )
        and 1 <= sum(len(value.get(kind, [])) for kind in OBSERVABLE_KINDS) <= 8
    )


def _tuple_ips(
    parameters: dict[str, Any], dependencies: Dependencies,
    error_type: Type[Exception],
) -> set[str]:
    if not isinstance(parameters.get("event_tuple"), dict):
        return set()
    try:
        normalized = dependencies.normalize_event_tuple(parameters["event_tuple"])
    except error_type:
        return set()
    return {
        value
        for value in (normalized.get("source_ip"), normalized.get("destination_ip"))
        if isinstance(value, str) and value
    }


def _repair_observables(
    parameters: dict[str, Any], authorization_context: Any,
    dependencies: Dependencies, error_type: Type[Exception],
) -> tuple[dict[str, list[str]] | None, str] | None:
    raw = parameters.get("observables")
    if _valid_observables(raw):
        return None, "original_valid_scope"
    recovered = recover_observables(raw, authorization_context)
    if recovered is not None:
        return recovered, "trusted_catalog_intersection"
    tuple_ips = _tuple_ips(parameters, dependencies, error_type)
    recovered = (
        recover_observables(sorted(tuple_ips), authorization_context)
        if tuple_ips
        else None
    )
    if recovered is None or not tuple_ips.issubset(set(recovered.get("ips") or [])):
        return None
    return recovered, "trusted_event_tuple_intersection"


def _bounded_request(
    raw: dict[str, Any], backend: str, parameters: dict[str, Any],
    recovered: dict[str, list[str]] | None,
) -> dict[str, Any]:
    bounded = {
        "query_id": raw.get("query_id"),
        "backend": backend,
        "purpose": raw.get("purpose"),
        "parameters": {
            key: parameters.get(key)
            for key in ("pack", "window", "observables", "size", "aggregation")
            if key in parameters
        },
    }
    if recovered is not None:
        bounded["parameters"]["observables"] = recovered
    if isinstance(parameters.get("event_tuple"), dict):
        bounded["parameters"]["event_tuple"] = copy.deepcopy(parameters["event_tuple"])
    return bounded


def _scope_from_normalized(
    normalized: dict[str, Any], source: str,
) -> dict[str, Any]:
    parameters = normalized["parameters"]
    result = {
        "query_id": normalized["query_id"],
        "backend": normalized["backend"],
        "purpose": normalized["purpose"],
        "pack": parameters["pack"],
        "window": dict(parameters["window"]),
        "observables": {
            kind: list(values) for kind, values in parameters["observables"].items()
        },
        "size": parameters["size"],
        "aggregation": parameters["aggregation"],
        "observable_scope_source": source,
    }
    if isinstance(parameters.get("event_tuple"), dict):
        result["event_tuple"] = copy.deepcopy(parameters["event_tuple"])
    return result


def scope(
    raw: Any, *, round_number: int, position: int, time_envelope: Any = None,
    authorization_context: Any = None, dependencies: Dependencies,
    error_type: Type[Exception] = ValueError,
) -> dict[str, Any] | None:
    """Recover a normalized scope that a later repair cannot widen."""
    if not isinstance(raw, dict):
        return None
    backend = primitives.text(raw.get("backend"), 32).lower()
    parameters = raw.get("parameters")
    if backend not in {"elastic", "oql"} or not isinstance(parameters, dict):
        return None
    observable_scope = _repair_observables(
        parameters, authorization_context, dependencies, error_type
    )
    if observable_scope is None:
        return None
    recovered, source = observable_scope
    try:
        normalized = dependencies.normalize_request(
            _bounded_request(raw, backend, parameters, recovered),
            round_number=round_number,
            position=position,
            time_envelope=time_envelope,
            authorization_context=authorization_context,
        )
    except error_type:
        return None
    return _scope_from_normalized(normalized, source)


def _validate_fixed(
    request: dict[str, Any], parameters: dict[str, Any],
    original: dict[str, Any], error_type: Type[Exception],
) -> None:
    exact_pairs = (
        ("query_id", request.get("query_id"), original.get("query_id")),
        ("backend", request.get("backend"), original.get("backend")),
        ("purpose", request.get("purpose"), original.get("purpose")),
        ("pack", parameters.get("pack"), original.get("pack")),
        ("aggregation", parameters.get("aggregation"), original.get("aggregation")),
    )
    widened = [label for label, repaired, prior in exact_pairs if repaired != prior]
    if widened:
        raise error_type(
            "query repair changed fixed scope field(s): " + ", ".join(widened)
        )


def _validate_window(
    repaired: Any, original: Any, error_type: Type[Exception],
) -> None:
    if not isinstance(repaired, dict) or not isinstance(original, dict):
        raise error_type("query repair window is invalid")
    repaired_start = primitives.utc(
        repaired.get("start"), "query repair window start", error_type=error_type
    )
    original_start = primitives.utc(
        original.get("start"), "original query window start", error_type=error_type
    )
    repaired_end = primitives.utc(
        repaired.get("end"), "query repair window end", error_type=error_type
    )
    original_end = primitives.utc(
        original.get("end"), "original query window end", error_type=error_type
    )
    if repaired_start < original_start or repaired_end > original_end:
        raise error_type("query repair widened the rejected request time window")


def _validate_observables(
    repaired: Any, original: Any, error_type: Type[Exception],
) -> None:
    if not isinstance(repaired, dict) or not isinstance(original, dict):
        raise error_type("query repair observables are invalid")
    widened = any(
        not set(repaired.get(kind) or []).issubset(set(original.get(kind) or []))
        for kind in OBSERVABLE_KINDS
    )
    if widened:
        raise error_type("query repair widened the rejected request observables")


def validate(
    request: dict[str, Any], original: dict[str, Any], *,
    error_type: Type[Exception] = ValueError,
) -> None:
    """Reject a proposed repair that widens any original query dimension."""
    parameters = request.get("parameters")
    if not isinstance(parameters, dict):
        raise error_type("query repair parameters are invalid")
    _validate_fixed(request, parameters, original, error_type)
    _validate_window(parameters.get("window"), original.get("window"), error_type)
    _validate_observables(
        parameters.get("observables"), original.get("observables"), error_type
    )
    if int(parameters.get("size") or 0) > int(original.get("size") or 0):
        raise error_type("query repair increased the rejected request row budget")
    if parameters.get("event_tuple") != original.get("event_tuple"):
        raise error_type("query repair widened or changed the rejected event tuple")


def request_from_scope(original: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct the exact normalized request authorized by a repair scope."""
    request = {
        "query_id": original["query_id"],
        "backend": original["backend"],
        "purpose": original["purpose"],
        "parameters": {
            "pack": original["pack"],
            "window": copy.deepcopy(original["window"]),
            "observables": copy.deepcopy(original["observables"]),
            "size": original["size"],
            "aggregation": original["aggregation"],
        },
    }
    if isinstance(original.get("event_tuple"), dict):
        request["parameters"]["event_tuple"] = copy.deepcopy(original["event_tuple"])
    return request


def failures(round_result: Any) -> dict[str, str]:
    """Return broker contract/invalid-response failures by exact query ID."""
    if not isinstance(round_result, dict):
        return {}
    found: dict[str, str] = {}

    def record(value: Any, *, fallback: str = "") -> None:
        if not isinstance(value, dict):
            return
        status = primitives.text(value.get("status"), 40).lower()
        query_id = primitives.text(value.get("query_id"), 64)
        if query_id and status in REPAIRABLE_STATUSES:
            found.setdefault(
                query_id,
                primitives.text(value.get("error"), 500)
                or fallback
                or f"broker returned {status}",
            )

    for result in round_result.get("results") if isinstance(round_result.get("results"), list) else []:
        if not isinstance(result, dict):
            continue
        record(result)
        for item in result.get("trusted_query_audit") if isinstance(result.get("trusted_query_audit"), list) else []:
            record(item, fallback="broker query audit reported an invalid response")
        evidence = result.get("evidence")
        if isinstance(evidence, dict):
            for item in evidence.get("results") if isinstance(evidence.get("results"), list) else []:
                record(item, fallback="broker returned invalid model evidence")
    return found


def prompt_entry(
    original: dict[str, Any], *, reason: str, trigger: str,
    dependencies: Dependencies,
) -> dict[str, Any]:
    """Expose only rejected scope and value-free tuple guidance."""
    event_tuple = original.get("event_tuple") if isinstance(original.get("event_tuple"), dict) else {}
    return {
        "query_id": original["query_id"],
        "backend": original["backend"],
        "purpose": original["purpose"],
        "pack": original["pack"],
        "window": original["window"],
        "observables": original["observables"],
        "maximum_size": original["size"],
        "aggregation": original["aggregation"],
        "observable_scope_source": original.get(
            "observable_scope_source", "original_valid_scope"
        ),
        "original_event_tuple_fields": sorted(event_tuple),
        "pack_event_tuple_fields": sorted(
            dependencies.pack_event_tuple_fields(original["pack"])
        ),
        "trigger": trigger,
        "error": dependencies.prompt_error_category(reason),
        "error_sha256": dependencies.prompt_error_digest(reason),
        "scope_digest": dependencies.canonical_digest(original),
    }
