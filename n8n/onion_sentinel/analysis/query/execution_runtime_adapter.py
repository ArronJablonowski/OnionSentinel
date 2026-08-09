"""Concrete runtime bindings for governed, read-only query execution.

The execution package owns backend transition policy.  This adapter projects
the legacy runner's live callables and constants into those transitions without
importing the executable or expanding model authority.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping


def safe_audit_summary(b: Mapping[str, Any], value: Any) -> dict[str, Any]:
    encoded = json.dumps(
        value if isinstance(value, (dict, list)) else {},
        sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")
    source = value if isinstance(value, dict) else {}
    text = b["_query_text"]
    return {
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "query_contract": text(source.get("query_contract") or source.get("schema"), 128),
        "authorized_request_digest": text(
            source.get("authorized_request_digest") or source.get("request_digest"), 128),
        "authorization_context_digest": text(
            source.get("authorization_context_digest")
            or source.get("authorization_digest"), 128),
        "security_onion_response_digest": text(
            source.get("security_onion_response_digest"), 128),
        "complete": bool(source.get("complete")),
    }


def bounded_trusted_query_audit(
    b: Mapping[str, Any], raw: Any, fields: frozenset[str],
) -> list[dict[str, Any]]:
    """Retain exact broker-rendered queries without carrying full result hits."""
    if not isinstance(raw, list):
        return []
    output: list[dict[str, Any]] = []
    for item in raw[: b["MAX_INVESTIGATION_QUERIES_PER_ROUND"]]:
        if not isinstance(item, dict):
            continue
        selected = {
            str(key): b["model_safe_copy"](value)
            for key, value in item.items() if str(key) in fields
        }
        encoded = json.dumps(
            selected, sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")
        if len(encoded) > 64 * 1024:
            selected = {
                key: value for key, value in selected.items()
                if key not in {
                    "query_dsl", "observables", "observable_provenance", "shards",
                }
            }
            selected["audit_truncated"] = True
        output.append(selected)
    return output


def runtime_env_value(b: Mapping[str, Any], name: str) -> str:
    environment = b["os"].environ
    if str(environment.get(b["CONTROLLED_EVALUATION_MODE_ENV"]) or "").strip() == "1":
        return ""
    direct = str(environment.get(name) or "").strip()
    if direct:
        return direct
    env_file = Path.home() / "n8n-local" / ".env"
    try:
        for line in env_file.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == name:
                return value.strip().strip('"').strip("'")
    except OSError:
        pass
    return ""


def prepare_enrichment_context(
    b: Mapping[str, Any], prompt_package: dict[str, Any], agent_role: str,
    alert_store_url: str,
) -> dict[str, Any]:
    token = b["_runtime_env_value"]("N8N_POST_COMMIT_TOKEN")
    enabled = agent_role in {"soc-analyst", "incident-responder"} and len(token) >= 32
    config = {
        "enabled": enabled,
        "token": token,
        "alert_store_url": alert_store_url.rstrip("/"),
        "n8n_url": str(
            b["os"].environ.get("N8N_INVESTIGATION_ENRICHMENT_URL")
            or "http://127.0.0.1:5678/webhook/onion-sentinel-investigation-enrichment"
        ).rstrip("/"),
        "timeout": 120,
    }
    capability = prompt_package.get("investigation_query_capability")
    if isinstance(capability, dict):
        backends = capability.get("backends")
        if isinstance(backends, dict) and isinstance(backends.get("enrichment"), dict):
            backends["enrichment"]["enabled"] = enabled
        if enabled:
            capability["enabled"] = True
    return config


def post_enrichment_json(
    b: Mapping[str, Any], url: str, payload: dict[str, Any],
    headers: dict[str, str], timeout: int,
) -> dict[str, Any]:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = b["urllib"].request.Request(
        url, data=body, headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with b["urllib"].request.urlopen(request, timeout=timeout) as response:
        result = b["read_bounded_json"](response, max_bytes=8 * 1024 * 1024)
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise b["InvestigationQueryError"](
            "enrichment service returned an unsuccessful response")
    return result


def project_enrichment_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        return {}
    raw = record.get("raw_response")
    raw_bytes = json.dumps(
        raw, sort_keys=True, separators=(",", ":"), default=str,
    ).encode("utf-8")
    digest = str(record.get("raw_response_sha256") or "") or hashlib.sha256(raw_bytes).hexdigest()
    projected = {
        key: record.get(key) for key in (
            "source", "indicator", "indicator_type", "verdict", "confidence",
            "tags", "first_seen", "last_seen", "cached_at", "expires_at", "cache_state",
        )
    }
    projected["provider_evidence"] = {
        "response_sha256": digest,
        "response_size_bytes": int(record.get("raw_response_size_bytes") or len(raw_bytes)),
        "cache_response_complete": record.get("raw_response_complete", True) is True,
        "prompt_projection_complete": len(raw_bytes) <= 32 * 1024,
        **(
            {"response": raw} if len(raw_bytes) <= 32 * 1024
            else {"response_json_prefix": raw_bytes[: 32 * 1024].decode("utf-8", "ignore")}
        ),
    }
    return projected


def collect_enrichment(
    b: Mapping[str, Any], request: dict[str, Any], config: dict[str, Any],
) -> dict[str, Any]:
    module = b["_query_execution_enrichment"]()
    return module.collect(
        request, config,
        dependencies=module.CollectionDependencies(
            post_json=b["_post_investigation_enrichment_json"],
            project_record=b["_project_investigation_enrichment_record"],
        ),
    )


def security_onion_authorization_context(
    b: Mapping[str, Any], value: Any,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    forwarded = b["INVESTIGATION_SECURITY_ONION_AUTHORIZATION_CONTEXT_FIELDS"]
    local_only = b["INVESTIGATION_LOCAL_ONLY_AUTHORIZATION_CONTEXT_FIELDS"]
    unsupported = set(value).difference(forwarded, local_only)
    if unsupported:
        raise b["InvestigationQueryContractError"](
            "local authorization context contains unsupported fields: "
            + ", ".join(sorted(str(item) for item in unsupported)))
    return {key: copy.deepcopy(value[key]) for key in forwarded if key in value}


def execute_security_backend(
    b: Mapping[str, Any], requests: list[dict[str, Any]], context: dict[str, Any],
    round_number: int, executor: Callable[..., dict[str, Any]],
) -> Any:
    module = b["_query_execution_security_onion"]()
    return module.execute(
        requests, context, round_number=round_number,
        policy=module.Policy(
            query_contract=b["INVESTIGATION_QUERY_CONTRACT"],
            require_anchor_time=b["INVESTIGATION_QUERY_V2"],
        ),
        dependencies=module.Dependencies(
            project_context=b["security_onion_authorization_context"],
            authorize=b["authorize_investigation_query_request"], executor=executor,
            text=b["_query_text"], random_hex=lambda size: b["os"].urandom(size).hex(),
            bounded_audit=b["_bounded_trusted_query_audit"],
            safe_audit_summary=b["_safe_audit_summary"],
            contract_error=b["InvestigationQueryContractError"],
            query_error=b["InvestigationQueryError"],
        ),
    )


def execute_endpoint_backend(
    b: Mapping[str, Any], requests: list[dict[str, Any]],
    prompt_package: dict[str, Any], config: dict[str, Any] | None,
    executor: Callable[..., dict[str, Any]],
) -> Any:
    module = b["_query_execution_endpoint"]()
    return module.execute(
        requests, prompt_package, config,
        dependencies=module.Dependencies(
            executor=executor, validate_artifact=b["validate_live_osquery_result_artifact"],
            case_id=b["live_osquery_case_id"], target_bound=b["_live_osquery_target_bound_to_case"],
            support_bindings=b["_live_osquery_support_bindings"],
            accumulate_evidence=b["accumulate_live_osquery_evidence"],
            accumulate_failure=b["accumulate_live_osquery_failure"],
            normalize_query=b["normalize_live_osquery_query"], text=b["_query_text"],
            bounded_audit=b["_bounded_trusted_query_audit"],
            safe_audit_summary=b["_safe_audit_summary"],
            client_error=b["LiveOsqueryClientError"],
            handled_errors=(
                b["LiveOsqueryClientError"], b["LiveOsqueryContractError"], OSError,
            ),
        ),
    )


def execute_derived_backend(
    b: Mapping[str, Any], requests: list[dict[str, Any]],
    prompt_package: dict[str, Any], executor: Callable[..., dict[str, Any]],
) -> Any:
    module = b["_query_execution_derived"]()
    context = prompt_package.get("pcap_evidence")
    return module.execute(
        requests, context if isinstance(context, dict) else {},
        dependencies=module.Dependencies(
            executor=executor, validate_evidence=b["validate_derived_query_evidence"],
            source_digest=b["_derived_evidence_source_digest"],
            bounded_audit=b["_bounded_trusted_query_audit"],
            safe_audit_summary=b["_safe_audit_summary"],
            handled_errors=(
                b["InvestigationQueryError"], b["PcapEvidenceQueryError"], OSError,
            ),
        ),
    )


def execute_enrichment_backend(
    b: Mapping[str, Any], requests: list[dict[str, Any]],
    config: dict[str, Any] | None, executor: Callable[..., dict[str, Any]],
) -> Any:
    module = b["_query_execution_enrichment"]()
    return module.execute(
        requests, config,
        dependencies=module.Dependencies(
            executor=executor, error_type=b["InvestigationQueryError"],
            handled_errors=(
                b["InvestigationQueryError"], OSError, b["urllib"].error.URLError,
            ),
        ),
    )


def execute_batch(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
    requests: list[dict[str, Any]], *, round_number: int,
    live_osquery_config: dict[str, Any] | None = None,
    security_onion_executor: Callable[..., dict[str, Any]] | None = None,
    osquery_executor: Callable[..., dict[str, Any]] | None = None,
    derived_executor: Callable[..., dict[str, Any]] | None = None,
    enrichment_executor: Callable[..., dict[str, Any]] | None = None,
    enrichment_config: dict[str, Any] | None = None,
    security_onion_config_path: Any = None, investigation_pivot_dir: Any = None,
) -> dict[str, Any]:
    if security_onion_executor is None:
        security_onion_executor = lambda proposal, authorization: b["collect_security_onion_pivots"](
            proposal, authorization, config_path=security_onion_config_path,
            out_dir=investigation_pivot_dir)
    osquery_executor = osquery_executor or b["collect_live_osquery"]
    derived_executor = derived_executor or b["query_derived_pcap_evidence"]
    enrichment_executor = enrichment_executor or b["collect_investigation_enrichment"]
    local_context = prompt_package.get("_local_investigation_query_context")
    authorization_context = local_context if isinstance(local_context, dict) else {}
    module = b["_query_execution_batch"]()
    return module.execute(
        requests, round_number=round_number,
        policy=module.Policy(result_schema=b["INVESTIGATION_QUERY_RESULT_SCHEMA"]),
        dependencies=module.Dependencies(
            security_onion=lambda selected: b["_execute_security_query_backend"](
                selected, authorization_context, round_number, security_onion_executor),
            endpoint=lambda selected: b["_execute_endpoint_query_backend"](
                selected, prompt_package, live_osquery_config, osquery_executor),
            derived=lambda selected: b["_execute_derived_query_backend"](
                selected, prompt_package, derived_executor),
            enrichment=lambda selected: b["_execute_enrichment_query_backend"](
                selected, enrichment_config, enrichment_executor),
            now=b["project_now"],
        ),
    )
