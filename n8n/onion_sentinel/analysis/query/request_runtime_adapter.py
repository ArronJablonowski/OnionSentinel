"""Concrete compatibility binding for governed query request normalization."""
from __future__ import annotations

from typing import Any, Mapping


def normalize_backend_parameters(
    b: Mapping[str, Any], backend: str, parameters: dict[str, Any],
    purpose: str, time_envelope: Any, authorization_context: Any,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if backend in {"elastic", "oql"}:
        return b["_query_security_onion"]().normalize(
            parameters, purpose=purpose, backend=backend,
            time_envelope=time_envelope,
            authorization_context=authorization_context,
            policy=b["_query_security_onion_policy"](),
            dependencies=b["_query_security_onion_dependencies"](),
            error_type=b["InvestigationQueryError"],
        )
    if backend == "osquery":
        module = b["_query_endpoint"]()
        normalized = module.normalize(
            parameters,
            dependencies=module.Dependencies(
                normalize_query=b["normalize_live_osquery_query"],
                query_error=b["LiveOsqueryContractError"],
            ),
            error_type=b["InvestigationQueryError"],
        )
        return normalized, {}
    if backend == "enrichment":
        normalized = b["_query_enrichment"]().normalize(
            parameters, authorization_context=authorization_context,
            error_type=b["InvestigationQueryError"],
        )
        return normalized, {}
    normalized = b["_query_derived"]().normalize(
        parameters, policy=b["_query_derived_policy"](),
        dependencies=b["_query_derived_dependencies"](),
        error_type=b["InvestigationQueryError"],
    )
    return normalized, {}


def normalize_request(
    b: Mapping[str, Any], raw: Any, *, round_number: int, position: int,
    time_envelope: Any = None, authorization_context: Any = None,
) -> dict[str, Any]:
    module = b["_query_request"]()
    return module.normalize(
        raw, round_number=round_number, position=position,
        time_envelope=time_envelope,
        authorization_context=authorization_context,
        policy=b["_query_request_policy"](),
        dependencies=module.Dependencies(
            normalize_parameters=b["_normalize_investigation_backend_parameters"]),
        error_type=b["InvestigationQueryError"],
    )


def pop_requests(
    b: Mapping[str, Any], response: dict[str, Any],
) -> list[Any]:
    """Consume unified requests and translate both legacy request fields."""
    unified = response.pop("investigation_query_requests", [])
    requests = list(unified) if isinstance(unified, list) else [unified]
    legacy_pcap = response.pop("pcap_query_requests", [])
    if isinstance(legacy_pcap, list):
        for index, item in enumerate(legacy_pcap, 1):
            if not isinstance(item, dict):
                requests.append(item)
                continue
            requests.append({
                "query_id": f"legacy-pcap-{index}",
                "backend": "pcap_zeek",
                "purpose": "Resolve the model's requested bounded PCAP evidence gap.",
                "parameters": item,
            })
    legacy_osquery = response.pop("live_osquery_requests", [])
    if isinstance(legacy_osquery, list):
        for index, item in enumerate(legacy_osquery, 1):
            if not isinstance(item, dict):
                requests.append(item)
                continue
            requests.append({
                "query_id": f"legacy-osquery-{index}",
                "backend": "osquery",
                "purpose": b["_query_text"](item.get("purpose"), 500)
                or "Resolve the model's requested endpoint evidence gap.",
                "parameters": {
                    "target_alias": item.get("target_alias"),
                    "query": item.get("query"),
                },
            })
    return requests
