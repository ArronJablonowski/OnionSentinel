"""Versioned, content-free identity for all investigation memory layers."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from agent_memory_validation import (
    DEFAULT_ROLE_RECORD_LIMIT,
    DEFAULT_SHARED_RECORD_LIMIT,
    MEMORY_SNAPSHOT_SCHEMA,
    MEMORY_ROLES,
)


MEMORY_CONTEXT_CONTRACT_SCHEMA = "onion-sentinel-memory-context-contract-v1"
SUMMARY_REQUIREMENTS = (
    "citations",
    "uncertainty",
    "contradictions",
    "telemetry_gaps",
)
WORKING_MEMORY_SECTIONS = (
    "alert",
    "grouped_alert_context",
    "analyst_state",
    "prior_analyses",
    "correlated_alert_context",
    "investigation_query_results",
)
DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _optional_mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _case_id(package: Mapping[str, Any]) -> str:
    local = package.get("_local_investigation_query_context")
    local = _optional_mapping(local)
    incident = package.get("incident_response_evidence")
    incident = _optional_mapping(incident)
    current_contract = package.get("memory_context_contract")
    current_contract = _optional_mapping(current_contract)
    value = str(
        local.get("case_id")
        or incident.get("case_id")
        or package.get("case_id")
        or current_contract.get("case_id")
        or ""
    ).strip()
    if not value or len(value) > 160 or not re.fullmatch(r"[A-Za-z0-9._:-]+", value):
        raise ValueError("memory contract requires a valid case identity")
    return value


def _evidence_layer(package: Mapping[str, Any]) -> dict[str, Any]:
    contract = _mapping(
        package.get("evidence_reference_contract"),
        "immutable evidence contract",
    )
    references = contract.get("references")
    if not isinstance(references, list):
        references = contract.get("refs")
    if not isinstance(references, list):
        raise ValueError("immutable evidence contract references must be an array")
    return {
        "contract_schema": str(contract.get("schema") or ""),
        "manifest_digest": _digest(contract),
        "reference_count": len(references),
        "retention": "immutable-run-ledger",
    }


def _working_memory_layer(
    package: Mapping[str, Any],
    *,
    case_id: str,
) -> dict[str, Any]:
    sections = [
        {
            "name": name,
            "digest": _digest(package[name]),
            "serialized_bytes": len(_canonical_json(package[name]).encode("utf-8")),
        }
        for name in WORKING_MEMORY_SECTIONS
        if name in package
    ]
    manifest = {
        "case_id": case_id,
        "sections": sections,
        "summary_requirements": list(SUMMARY_REQUIREMENTS),
    }
    return {
        "scope": "case",
        "case_id": case_id,
        "manifest_digest": _digest(manifest),
        "sections": sections,
        "section_count": len(sections),
        "compaction": "ordered-package-budget-policy",
        "retention": "run-and-case-history-bounded",
        "cleanup": "prompt-artifact-and-harness-retention-policy",
    }


def _nonnegative_integer(value: object) -> int:
    return max(0, int(value or 0))


def _selected_versions(
    snapshot: Mapping[str, Any],
    layer: str,
) -> list[dict[str, Any]]:
    versions = snapshot.get("selected_record_versions")
    if not isinstance(versions, list):
        raise ValueError(f"{layer} snapshot versions must be an array")
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in versions:
        if not isinstance(item, Mapping):
            raise ValueError(f"{layer} snapshot version entry must be an object")
        record_id = str(item.get("id") or "")
        try:
            version = int(item.get("version"))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{layer} snapshot version must be an integer") from exc
        if (
            not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", record_id)
            or version < 1
            or record_id in seen
        ):
            raise ValueError(f"{layer} snapshot version entry is invalid")
        normalized.append({"id": record_id, "version": version})
        seen.add(record_id)
    return normalized


def _memory_snapshot_layer(
    memory: Mapping[str, Any],
    *,
    section: str,
    layer: str,
    record_limit: int,
) -> dict[str, Any]:
    context = _mapping(memory.get(section), f"{layer} context")
    snapshot = _mapping(context.get("snapshot"), f"{layer} snapshot")
    if snapshot.get("schema") != MEMORY_SNAPSHOT_SCHEMA:
        raise ValueError(f"{layer} snapshot schema is unsupported")
    source_digest = str(snapshot.get("source_digest") or "")
    selected_digest = str(snapshot.get("selected_records_digest") or "")
    if not DIGEST_RE.fullmatch(source_digest) or not DIGEST_RE.fullmatch(
        selected_digest
    ):
        raise ValueError(f"{layer} snapshot has an invalid digest")
    versions = _selected_versions(snapshot, layer)
    return {
        "snapshot_schema": str(snapshot.get("schema") or ""),
        "source_digest": source_digest,
        "selected_records_digest": selected_digest,
        "selected_record_versions": versions,
        "source_bytes": _nonnegative_integer(snapshot.get("source_bytes")),
        "selected_records_bytes": _nonnegative_integer(
            snapshot.get("selected_records_bytes")
        ),
        "manual_notes_bytes": _nonnegative_integer(
            snapshot.get("manual_notes_bytes")
        ),
        "selected_records": _nonnegative_integer(
            snapshot.get("selected_managed_records", len(versions))
        ),
        "truncated": bool(snapshot.get("truncated")),
        "record_limit": record_limit,
        "retention": "expiry-then-deterministic-record-limit",
        "cleanup": "atomic-write-under-exclusive-lock",
    }


def refresh_selected_memory_snapshot(context: dict[str, Any]) -> None:
    """Rebind selected-record identity after deterministic context filtering."""
    snapshot = context.get("snapshot")
    records = context.get("records")
    if not isinstance(snapshot, dict) or not isinstance(records, list):
        return
    selected = [record for record in records if isinstance(record, dict)]
    encoded = _canonical_json(selected).encode("utf-8")
    snapshot["selected_records_digest"] = hashlib.sha256(encoded).hexdigest()
    snapshot["selected_record_versions"] = [
        {
            "id": str(record.get("id") or ""),
            "version": max(1, int(record.get("version") or 1)),
        }
        for record in selected
    ]
    snapshot["selected_records_bytes"] = len(encoded)
    snapshot["selected_managed_records"] = len(selected)
    snapshot["selection_filtered"] = True


def build_agent_memory_context_contract(
    package: Mapping[str, Any],
    *,
    evaluation_frozen: bool,
) -> dict[str, Any]:
    """Build one provider-neutral manifest without copying memory content."""
    role = str(package.get("agent_role") or "").strip().lower()
    if role not in MEMORY_ROLES:
        raise ValueError(f"unsupported memory contract agent role: {role}")
    case_id = _case_id(package)
    memory = _mapping(package.get("agent_memory"), "agent memory")
    contract: dict[str, Any] = {
        "schema": MEMORY_CONTEXT_CONTRACT_SCHEMA,
        "provider_contract": "provider-neutral",
        "case_id": case_id,
        "agent_role": role,
        "evaluation_frozen": bool(evaluation_frozen),
        "summary_requirements": list(SUMMARY_REQUIREMENTS),
        "layers": {
            "immutable_evidence": _evidence_layer(package),
            "case_local_working_memory": _working_memory_layer(
                package,
                case_id=case_id,
            ),
            "durable_analyst_memory": _memory_snapshot_layer(
                memory,
                section="role_memory",
                layer="durable analyst memory",
                record_limit=DEFAULT_ROLE_RECORD_LIMIT,
            ),
            "shared_cross_agent_knowledge": _memory_snapshot_layer(
                memory,
                section="shared_memory",
                layer="shared cross-agent knowledge",
                record_limit=DEFAULT_SHARED_RECORD_LIMIT,
            ),
        },
    }
    contract["contract_digest"] = _digest(contract)
    return contract


def attach_agent_memory_context_contract(
    package: dict[str, Any],
    *,
    evaluation_frozen: bool,
) -> dict[str, Any]:
    """Attach or deterministically replace the exact memory manifest."""
    package["memory_context_contract"] = build_agent_memory_context_contract(
        package,
        evaluation_frozen=evaluation_frozen,
    )
    return package


def rebind_agent_memory_context_contract(package: dict[str, Any]) -> None:
    """Rebuild all layer identities after reviewer package filtering."""
    existing = package.get("memory_context_contract")
    if not isinstance(existing, dict):
        return
    package["memory_context_contract"] = build_agent_memory_context_contract(
        package,
        evaluation_frozen=bool(existing.get("evaluation_frozen")),
    )


__all__ = [
    "MEMORY_CONTEXT_CONTRACT_SCHEMA",
    "SUMMARY_REQUIREMENTS",
    "WORKING_MEMORY_SECTIONS",
    "attach_agent_memory_context_contract",
    "build_agent_memory_context_contract",
    "rebind_agent_memory_context_contract",
    "refresh_selected_memory_snapshot",
]
