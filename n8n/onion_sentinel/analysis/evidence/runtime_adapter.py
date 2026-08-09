"""Concrete runtime bindings for model-visible evidence and provenance."""
from __future__ import annotations

from typing import Any, Mapping


def reference_policy(b: Mapping[str, Any]) -> Any:
    return b["_evidence_references"]().Policy(
        maximum_text_length=b["EVIDENCE_REFERENCE_TEXT_MAX"])


def registry_instance(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_registry"]()
    return module.Registry(
        maximum_references=b["EVIDENCE_REFERENCE_MAX"],
        deps=module.Dependencies(
            bounded_reference=b["_bounded_reference"],
            source_class=b["evidence_source_class"],
            canonical_count=b["_canonical_investigation_count"],
        ),
    )


def columnar_policy(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_columnar"]()
    return module.Policy(
        result_schema=b["INVESTIGATION_QUERY_RESULT_SCHEMA"],
        provenance_schema=b["INVESTIGATION_COLUMNAR_PROVENANCE_SCHEMA"],
        columns=tuple(b["INVESTIGATION_COLUMNAR_PROVENANCE_COLUMNS"]),
        empty_ref_instruction=b["INVESTIGATION_COLUMNAR_EMPTY_REF_INSTRUCTION"],
        success_statuses=frozenset(b["INVESTIGATION_QUERY_SUCCESS_STATUSES"]),
        maximum_queries=b["MAX_INVESTIGATION_QUERIES_TOTAL"],
        maximum_rounds=b["MAX_INVESTIGATION_QUERY_ROUNDS"],
    )


def columnar_dependencies(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_columnar"]()
    return module.Dependencies(
        prompt_json_bytes=b["_investigation_prompt_json_bytes"],
        canonical_count=b["_canonical_investigation_count"],
        result_bound_reference=b["result_bound_query_reference"],
    )


def hosted_projection_policy(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_hosted_projection"]()
    return module.Policy(
        provenance_schema=b["INVESTIGATION_COLUMNAR_PROVENANCE_SCHEMA"],
        columns=tuple(b["INVESTIGATION_COLUMNAR_PROVENANCE_COLUMNS"]),
        maximum_queries=b["MAX_INVESTIGATION_QUERIES_TOTAL"],
        list_path_sentinel=b["_MODEL_LIST_PATH_SENTINEL"],
    )


def hosted_projection_dependencies(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_hosted_projection"]()
    return module.Dependencies(
        exact_columnar_envelope=b["_exact_hosted_columnar_envelope"],
        prompt_json_bytes=b["_investigation_prompt_json_bytes"],
    )


def transport_policy(b: Mapping[str, Any]) -> Any:
    return b["_evidence_transport"]().Policy(
        internal_keys=frozenset(b["MODEL_INTERNAL_KEYS"]),
        hosted_forbidden_keys=frozenset(b["HOSTED_FORBIDDEN_KEYS"]),
        list_path_sentinel=b["_MODEL_LIST_PATH_SENTINEL"],
        fixed_point_max_passes=b["HOSTED_TRANSPORT_FIXED_POINT_MAX_PASSES"],
    )


def transport_dependencies(b: Mapping[str, Any]) -> Any:
    return b["_evidence_transport"]().Dependencies(
        redact_asset_owners=b["_redact_unshared_asset_owners"],
        reviewed_sha256_path=b["_reviewed_hosted_sha256_evidence_path"],
        exact_columnar_envelope=b["_exact_hosted_columnar_envelope"],
        sanitize_hosted_evidence=b["_sanitize_hosted_investigation_evidence"],
        refinalize_columnar_envelope=b["_refinalize_hosted_columnar_envelope"],
        evidence_reference_contract=b["evidence_reference_contract"],
    )


def endpoint_policy(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_endpoint"]()
    return module.Policy(
        live_schema=b["LIVE_OSQUERY_SCHEMA"],
        support_schema="onion-sentinel-live-osquery-support-v1",
        success_statuses=frozenset(b["INVESTIGATION_QUERY_SUCCESS_STATUSES"]),
    )


def endpoint_dependencies(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_endpoint"]()
    return module.Dependencies(
        normalize_live_query=b["normalize_live_osquery_query"],
        normalization_error=b["LiveOsqueryContractError"],
    )


def traversal_policy(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_traversal"]()
    return module.Policy(
        success_statuses=frozenset(b["INVESTIGATION_QUERY_SUCCESS_STATUSES"]),
        columnar_schema=b["INVESTIGATION_COLUMNAR_PROVENANCE_SCHEMA"],
    )


def traversal_dependencies(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_traversal"]()
    return module.Dependencies(
        bounded_reference=b["_bounded_reference"],
        result_bound_reference=b["result_bound_query_reference"],
    )


def contract_dependencies(b: Mapping[str, Any]) -> Any:
    module = b["_evidence_contract"]()
    return module.Dependencies(
        registry_factory=b["_evidence_registry_instance"],
        traverse=lambda value, path, sink: b["_evidence_traversal"]().visit(
            value, path, sink, b["_evidence_traversal_policy"](),
            b["_evidence_traversal_dependencies"]()),
        process_columnar=lambda value, sink: b["_evidence_columnar"]().process(
            value, sink, b["_evidence_columnar_policy"](),
            b["_evidence_columnar_dependencies"]()),
        has_structured_authorization=b["_has_structured_authorization_evidence"],
    )


def redact_unshared_asset_owners(asset_context: Any) -> Any:
    if not isinstance(asset_context, dict):
        return asset_context
    sanitized = dict(asset_context)
    matched_assets = sanitized.get("matched_assets")
    if not isinstance(matched_assets, list):
        return sanitized
    sanitized_assets: list[Any] = []
    for raw_asset in matched_assets:
        if not isinstance(raw_asset, dict):
            sanitized_assets.append(raw_asset)
            continue
        asset = dict(raw_asset)
        if asset.get("share_with_hosted_models") is not True:
            asset.pop("owner_ref", None)
        sanitized_assets.append(asset)
    sanitized["matched_assets"] = sanitized_assets
    return sanitized


def reviewed_sha256_path(b: Mapping[str, Any], path: tuple[object, ...]) -> bool:
    return b["_evidence_hosted_projection"]().reviewed_sha256_path(
        path, b["_evidence_hosted_projection_policy"]())


def exact_hosted_columnar_envelope(
    b: Mapping[str, Any], value: Any, *, require_encoded_accounting: bool,
) -> bool:
    return b["_evidence_columnar"]().exact_hosted_envelope(
        value, require_encoded_accounting=require_encoded_accounting,
        policy=b["_evidence_columnar_policy"](),
        deps=b["_evidence_columnar_dependencies"](),
    )


def refinalize_hosted_columnar_envelope(b: Mapping[str, Any], value: Any) -> Any:
    return b["_evidence_hosted_projection"]().refinalize_columnar(
        value, maximum_passes=b["HOSTED_TRANSPORT_FIXED_POINT_MAX_PASSES"],
        dependencies=b["_evidence_hosted_projection_dependencies"]())


def sanitize_hosted_evidence(
    b: Mapping[str, Any], value: Any, path: tuple[str, ...] = (), *,
    preserve_columnar_rows: bool = False,
) -> Any:
    return b["_evidence_hosted_projection"]().sanitize(
        value, path=path, preserve_columnar_rows=preserve_columnar_rows,
        policy=b["_evidence_hosted_projection_policy"]())


def model_safe_copy(
    b: Mapping[str, Any], value: Any, *, hosted: bool = False,
    reviewer_safe: bool = False, path: tuple[object, ...] = (),
) -> Any:
    return b["_evidence_transport"]().model_safe_copy(
        value, hosted=hosted, reviewer_safe=reviewer_safe, path=path,
        policy=b["_evidence_transport_policy"](),
        dependencies=b["_evidence_transport_dependencies"]())


def synchronize_hosted_contract(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> dict[str, Any]:
    module = b["_evidence_transport"]()
    return module.synchronize_hosted_contract(
        prompt_package,
        maximum_passes=b["HOSTED_TRANSPORT_FIXED_POINT_MAX_PASSES"],
        dependencies=module.SynchronizationDependencies(
            model_safe_copy=lambda value: b["model_safe_copy"](value, hosted=True),
            prompt_json_bytes=b["_investigation_prompt_json_bytes"],
            validation_error=b["InvestigationQueryError"],
        ),
    )


def bounded_reference(b: Mapping[str, Any], value: Any) -> str:
    return b["_evidence_references"]().bounded(
        value, b["_evidence_reference_policy"]())


def source_class(b: Mapping[str, Any], source: Any) -> str:
    return b["_evidence_references"]().source_class(source)


def result_bound_reference(
    b: Mapping[str, Any], query_digest: Any, result_digest: Any = "", *,
    namespace: str = "query", label: Any = "",
) -> tuple[str, str]:
    return b["_evidence_references"]().result_bound(
        query_digest, result_digest, namespace=namespace, label=label,
        policy=b["_evidence_reference_policy"]())


def reference_contract(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> dict[str, Any]:
    return b["_evidence_contract"]().build(
        prompt_package, b["_evidence_contract_dependencies"]())


def attach_reference_contract(
    b: Mapping[str, Any], prompt_package: dict[str, Any],
) -> dict[str, Any]:
    return b["_evidence_contract"]().attach(
        prompt_package, b["_evidence_contract_dependencies"]())


def validate_references(
    b: Mapping[str, Any], response: dict[str, Any],
    prompt_package: dict[str, Any] | None,
) -> dict[str, Any]:
    module = b["_evidence_validation"]()
    return module.apply(
        response, prompt_package,
        module.Dependencies(bounded_reference=b["_bounded_reference"]),
    )
