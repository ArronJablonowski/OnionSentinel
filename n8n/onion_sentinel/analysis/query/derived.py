"""Governed normalization for derived PCAP and Zeek evidence requests."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Callable, Mapping, Type

from . import primitives


@dataclass(frozen=True)
class Policy:
    operations: frozenset[str]
    filters_by_operation: Mapping[str, frozenset[str] | set[str]]
    maximum_filters: int = 16
    default_limit: int = 10
    maximum_limit: int = 20


@dataclass(frozen=True)
class Dependencies:
    normalize_filters: Callable[[str, dict[str, Any]], dict[str, Any]]
    filter_error: Type[Exception]
    positive_integer: Callable[[Any, int, int, str], int]


@dataclass(frozen=True)
class IntegrityPolicy:
    contract: str
    maximum_source_records: int = 20
    maximum_artifacts_per_record: int = 20


@dataclass(frozen=True)
class IntegrityDependencies:
    text: Callable[[Any, int], str]
    error_type: Type[Exception]


def _filters(
    operation: str, value: Any, *, policy: Policy,
    dependencies: Dependencies, error_type: Type[Exception],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise error_type("derived-evidence filters must be an object")
    unsupported = set(value).difference(
        policy.filters_by_operation.get(operation, set())
    )
    if unsupported:
        raise error_type(
            f"unsupported {operation} filters: "
            + ", ".join(sorted(str(item) for item in unsupported))
        )
    if len(value) > policy.maximum_filters or any(
        isinstance(item, (dict, list)) for item in value.values()
    ):
        raise error_type(
            "derived-evidence filters must contain at most "
            f"{policy.maximum_filters} scalar exact values"
        )
    try:
        return dependencies.normalize_filters(operation, value)
    except dependencies.filter_error as exc:
        raise error_type(str(exc)) from exc


def normalize(
    parameters: dict[str, Any], *, policy: Policy, dependencies: Dependencies,
    error_type: Type[Exception] = ValueError,
) -> dict[str, Any]:
    """Admit one bounded derived-evidence operation and exact filter set."""
    operation = primitives.text(parameters.get("operation"), 64).lower()
    if operation not in policy.operations:
        raise error_type(
            f"unsupported derived-evidence operation: {operation or 'missing'}"
        )
    return {
        "operation": operation,
        "filters": _filters(
            operation, parameters.get("filters", {}), policy=policy,
            dependencies=dependencies, error_type=error_type,
        ),
        "indicator": primitives.text(parameters.get("indicator"), 253),
        "limit": dependencies.positive_integer(
            parameters.get("limit"), policy.default_limit,
            policy.maximum_limit, "derived-evidence query limit",
        ),
    }


def validate_evidence(
    value: Any, expected_requests: list[dict[str, Any]], *,
    policy: IntegrityPolicy, dependencies: IntegrityDependencies,
) -> dict[str, Any]:
    """Bind every derived result to its normalized request and result rows."""
    if not isinstance(value, dict) or value.get("schema") != policy.contract:
        raise dependencies.error_type("derived PCAP/Zeek result schema is invalid")
    executed, results = value.get("executed"), value.get("results")
    if not _matching_counts(executed, results, expected_requests):
        raise dependencies.error_type(
            "derived PCAP/Zeek result count does not match the request"
        )
    for index, expected in enumerate(expected_requests):
        _validate_result(executed[index], results[index], expected, policy, dependencies)
    return value


def _matching_counts(executed: Any, results: Any, expected: list[Any]) -> bool:
    return (
        isinstance(executed, list) and isinstance(results, list)
        and len(executed) == len(expected) and len(results) == len(expected)
    )


def _validate_result(
    executed: Any, result: Any, expected: dict[str, Any],
    policy: IntegrityPolicy, dependencies: IntegrityDependencies,
) -> None:
    if executed != expected:
        raise dependencies.error_type(
            "derived PCAP/Zeek executed query does not match the normalized request"
        )
    if not isinstance(result, dict) or result.get("query") != expected:
        raise dependencies.error_type(
            "derived PCAP/Zeek result query does not match the normalized request"
        )
    records = result.get("records")
    if not isinstance(records, list):
        raise dependencies.error_type("derived PCAP/Zeek records must be an array")
    if not _valid_digests(result, records, expected, policy.contract):
        raise dependencies.error_type("derived PCAP/Zeek query or result digest is invalid")
    if not isinstance(result.get("audit"), dict):
        raise dependencies.error_type("derived PCAP/Zeek audit is missing")


def _valid_digests(
    result: dict[str, Any], records: list[Any], request: dict[str, Any], contract: str,
) -> bool:
    query_digest = _digest({"contract": contract, "request": request})
    result_digest = _digest(records)
    return (
        result.get("query_digest") == query_digest
        and result.get("result_digest") == result_digest
    )


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def source_digest(
    pcap_context: dict[str, Any], *, policy: IntegrityPolicy,
    dependencies: IntegrityDependencies,
) -> str:
    """Bind a derived pivot to capture artifacts represented by the local index."""
    parsed = pcap_context.get("parsed_evidence")
    records = parsed if isinstance(parsed, list) else []
    identities = [
        identity for record in records[:policy.maximum_source_records]
        if isinstance(record, dict)
        and (identity := _record_identity(record, policy, dependencies)) is not None
    ]
    if not identities:
        raise dependencies.error_type(
            "derived PCAP/Zeek evidence has no capture-bound artifact identity"
        )
    identities.sort(key=lambda item: json.dumps(
        item, sort_keys=True, separators=(",", ":"), default=str,
    ))
    encoded = json.dumps(
        identities, sort_keys=True, separators=(",", ":"), default=str,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _record_identity(
    record: dict[str, Any], policy: IntegrityPolicy,
    dependencies: IntegrityDependencies,
) -> dict[str, Any] | None:
    raw_files = record.get("pcap_files")
    files = raw_files if isinstance(raw_files, list) else []
    artifacts = [
        artifact for item in files[:policy.maximum_artifacts_per_record]
        if isinstance(item, dict)
        and (artifact := _artifact_identity(item, dependencies)) is not None
    ]
    if not artifacts:
        return None
    artifacts.sort(key=lambda item: (item["sha256"], item["name"], str(item["size_bytes"])))
    return {
        "artifacts": artifacts,
        "request_id": dependencies.text(record.get("request_id"), 160),
        "group_id": dependencies.text(record.get("group_id"), 160),
        "generated_at": dependencies.text(record.get("generated_at"), 100),
    }


def _artifact_identity(
    item: dict[str, Any], dependencies: IntegrityDependencies,
) -> dict[str, Any] | None:
    digest = dependencies.text(item.get("sha256"), 64)
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        return None
    return {
        "name": dependencies.text(item.get("name"), 255),
        "sha256": digest,
        "size_bytes": item.get("size_bytes"),
    }
