#!/usr/bin/env python3
"""Signed, content-bounded lifecycle registry for v2 investigation skills."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import re
from typing import Any, Callable, Iterable, Mapping

import investigation_skills_v2 as skills


SCHEMA = "onion-sentinel-investigation-skill-registry-v2"
SELECTION_SCHEMA = "onion-sentinel-investigation-skill-selection-v2"
PROVIDER_SCOPE = "native-harness-only"
MAX_RECORDS = 64
MAX_RELATIONS = 16
MAX_REVOCATIONS = 256
_DIGEST = re.compile(r"[a-f0-9]{64}")
_SIGNATURE = re.compile(r"[a-f0-9]{128}")
_KEY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}")
_STATES = frozenset({"candidate", "shadow", "active", "deprecated", "revoked"})
_NATIVE_PROVIDERS = frozenset({"codex-cli", "ollama"})
_BUDGET_FIELDS = (
    "max_queries", "max_rows", "max_bytes", "timeout_seconds",
)
_UNSEALED_FIELDS = frozenset({
    "schema", "revision", "mode", "provider_scope",
    "previous_registry_digest", "revoked_artifact_digests", "records",
})
_SEALED_FIELDS = _UNSEALED_FIELDS | {"signature", "registry_digest"}
_RECORD_FIELDS = frozenset({"state", "manifest", "dependencies", "conflicts"})
_RECORD_FIELDS = _RECORD_FIELDS | {"evaluation"}
_SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "value"})
_EVALUATION_SCHEMA = "onion-sentinel-investigation-skill-evaluation-v1"
_EVALUATION_FIELDS = frozenset({
    "schema", "manifest_digest", "evaluation_digest", "source_revision",
    "reviewer", "approver", "evaluated_at", "unit_test_count",
    "replay_case_count", "independent_query_review", "adversarial_tests",
    "human_approved", "outcome",
})
_PERSON = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{2,127}")


Signer = Callable[[bytes], Mapping[str, str]]
Verifier = Callable[[bytes, dict[str, str]], bool]


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def signing_bytes(value: Mapping[str, Any]) -> bytes:
    projected = copy.deepcopy(dict(value))
    projected["signature"] = {"algorithm": "", "key_id": "", "value": ""}
    projected["registry_digest"] = "0" * 64
    return _canonical_bytes(projected)


def registry_digest(value: Mapping[str, Any]) -> str:
    projected = copy.deepcopy(dict(value))
    projected["registry_digest"] = "0" * 64
    return _digest(projected)


def _bounded_digests(value: Any, field: str, maximum: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"registry {field} is invalid")
    if any(not isinstance(item, str) or not _DIGEST.fullmatch(item) for item in value):
        raise ValueError(f"registry {field} is invalid")
    if len(value) != len(set(value)):
        raise ValueError(f"registry {field} is invalid")
    return list(value)


def _validate_header(value: Mapping[str, Any], fields: frozenset[str]) -> None:
    if frozenset(value) != fields or value.get("schema") != SCHEMA:
        raise ValueError("registry field set or schema is invalid")
    _validate_revision(value.get("revision"))
    _validate_predecessor(value.get("previous_registry_digest"))
    if value.get("mode") not in {"shadow", "active"}:
        raise ValueError("registry mode is invalid")
    if value.get("provider_scope") != PROVIDER_SCOPE:
        raise ValueError("registry provider scope is invalid")


def _validate_revision(revision: Any) -> None:
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise ValueError("registry revision is invalid")


def _validate_predecessor(previous: Any) -> None:
    if previous != "" and (
        not isinstance(previous, str) or not _DIGEST.fullmatch(previous)
    ):
        raise ValueError("registry predecessor digest is invalid")


def _validate_signature(value: Any, *, required: bool) -> dict[str, str]:
    if not isinstance(value, Mapping) or frozenset(value) != _SIGNATURE_FIELDS:
        raise ValueError("registry signature is invalid")
    signature = {key: str(value.get(key) or "") for key in _SIGNATURE_FIELDS}
    if not required and signature == {"algorithm": "none", "key_id": "", "value": ""}:
        return signature
    if (
        signature["algorithm"] != "external-ed25519"
        or not _KEY_ID.fullmatch(signature["key_id"])
        or not _SIGNATURE.fullmatch(signature["value"])
    ):
        raise ValueError("registry signature is invalid")
    return signature


def _validate_record(raw: Any, *, mode: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or frozenset(raw) != _RECORD_FIELDS:
        raise ValueError("registry record is invalid")
    state = _record_state(raw.get("state"), mode)
    manifest = skills.validate_manifest(raw.get("manifest"))
    dependencies = _bounded_digests(
        raw.get("dependencies"), "record dependencies", MAX_RELATIONS,
    )
    conflicts = _bounded_digests(
        raw.get("conflicts"), "record conflicts", MAX_RELATIONS,
    )
    _validate_record_relations(dependencies, conflicts)
    _validate_record_promotion(manifest, state)
    evaluation = _validate_evaluation(raw.get("evaluation"), manifest, state)
    return {
        "state": state,
        "manifest": manifest,
        "dependencies": dependencies,
        "conflicts": conflicts,
        "evaluation": evaluation,
    }


def _evaluated_at(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 40:
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _evaluation_identity(
    raw: Mapping[str, Any], manifest: Mapping[str, Any], state: str,
) -> None:
    maintainer = manifest["maintainer"]
    lineage = manifest["lineage"]
    reviewer = raw.get("reviewer")
    approver = raw.get("approver")
    checks = (
        raw.get("manifest_digest") == manifest["artifact_digest"],
        raw.get("source_revision") == lineage["source_revision"],
        reviewer == maintainer["reviewer"],
        _valid_person(reviewer, required=True),
        _valid_person(approver, required=state == "active"),
        not approver or approver != reviewer,
    )
    if not all(checks):
        raise ValueError("registry evaluation attestation identity is invalid")


def _valid_person(value: Any, *, required: bool) -> bool:
    if not isinstance(value, str):
        return False
    return bool(_PERSON.fullmatch(value)) if required or value else True


def _evaluation_results(
    raw: Mapping[str, Any], manifest: Mapping[str, Any], state: str,
) -> None:
    verification = manifest["verification"]
    unit_count = raw.get("unit_test_count")
    replay_count = raw.get("replay_case_count")
    checks = (
        isinstance(unit_count, int) and not isinstance(unit_count, bool),
        isinstance(unit_count, int) and 1 <= unit_count <= 1_000_000,
        isinstance(replay_count, int) and not isinstance(replay_count, bool),
        replay_count == verification["replay_cases"],
        raw.get("independent_query_review")
        is verification["independent_query_review"],
        raw.get("adversarial_tests") is verification["adversarial_tests"],
        raw.get("human_approved") is verification["human_approved"],
        state != "active" or raw.get("human_approved") is True,
        raw.get("outcome") == "pass",
    )
    if not all(checks):
        raise ValueError("registry evaluation attestation results are invalid")


def _validate_evaluation(
    value: Any, manifest: Mapping[str, Any], state: str,
) -> dict[str, Any] | None:
    required = state in {"shadow", "active"}
    if value is None and not required:
        return None
    if (
        not isinstance(value, Mapping)
        or frozenset(value) != _EVALUATION_FIELDS
        or value.get("schema") != _EVALUATION_SCHEMA
        or not isinstance(value.get("evaluation_digest"), str)
        or not _DIGEST.fullmatch(value["evaluation_digest"])
        or value["evaluation_digest"] == manifest["artifact_digest"]
        or not _evaluated_at(value.get("evaluated_at"))
    ):
        raise ValueError("registry evaluation attestation is invalid")
    _evaluation_identity(value, manifest, state)
    _evaluation_results(value, manifest, state)
    return copy.deepcopy(dict(value))


def _record_state(value: Any, mode: str) -> str:
    state = str(value or "")
    if state not in _STATES or (state == "active" and mode != "active"):
        raise ValueError("registry record lifecycle state is invalid")
    return state


def _validate_record_relations(
    dependencies: list[str], conflicts: list[str],
) -> None:
    if set(dependencies) & set(conflicts):
        raise ValueError("registry record dependency conflicts with itself")


def _validate_record_promotion(manifest: dict[str, Any], state: str) -> None:
    target = state if state in {"shadow", "active"} else None
    if target is not None and not skills.promotion_eligible(manifest, target)[0]:
        raise ValueError("registry record promotion gates are incomplete")


def _validate_record_set(
    raw: Any, *, mode: str, revoked: set[str],
) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw or len(raw) > MAX_RECORDS:
        raise ValueError("registry records are invalid")
    records = [_validate_record(item, mode=mode) for item in raw]
    _validate_unique_records(records)
    _validate_resolved_relations(records)
    _validate_revocations(records, revoked)
    return records


def _validate_unique_records(records: list[dict[str, Any]]) -> None:
    identities = [
        (item["manifest"]["id"], item["manifest"]["version"])
        for item in records
    ]
    digests = [item["manifest"]["artifact_digest"] for item in records]
    if len(identities) != len(set(identities)) or len(digests) != len(set(digests)):
        raise ValueError("registry record identities must be unique")


def _validate_resolved_relations(records: list[dict[str, Any]]) -> None:
    available = {item["manifest"]["artifact_digest"] for item in records}
    unresolved = any(
        not set(item["dependencies"] + item["conflicts"]).issubset(available)
        for item in records
    )
    if unresolved:
        raise ValueError("registry record relation is unresolved")


def _validate_revocations(
    records: list[dict[str, Any]], revoked: set[str],
) -> None:
    for item in records:
        digest = item["manifest"]["artifact_digest"]
        if (digest in revoked) != (item["state"] == "revoked"):
            raise ValueError("registry revocation state is inconsistent")


def _validated_content(value: Mapping[str, Any]) -> dict[str, Any]:
    revoked = _bounded_digests(
        value.get("revoked_artifact_digests"),
        "revoked artifact digests",
        MAX_REVOCATIONS,
    )
    records = _validate_record_set(
        value.get("records"), mode=str(value["mode"]), revoked=set(revoked),
    )
    return {
        **{key: copy.deepcopy(value[key]) for key in _UNSEALED_FIELDS},
        "revoked_artifact_digests": revoked,
        "records": records,
    }


def seal_registry(raw: Mapping[str, Any], *, signer: Signer | None) -> dict[str, Any]:
    """Validate and content-address one immutable registry snapshot."""
    if not isinstance(raw, Mapping):
        raise ValueError("registry must be an object")
    _validate_header(raw, _UNSEALED_FIELDS)
    value = _validated_content(raw)
    value["signature"] = {"algorithm": "none", "key_id": "", "value": ""}
    value["registry_digest"] = "0" * 64
    if value["mode"] == "active":
        if signer is None:
            raise ValueError("active registry requires an external signer")
        value["signature"] = _validate_signature(
            signer(signing_bytes(value)), required=True,
        )
    elif signer is not None:
        value["signature"] = _validate_signature(
            signer(signing_bytes(value)), required=False,
        )
    value["registry_digest"] = registry_digest(value)
    return value


def validate_registry(
    raw: Any, *, verifier: Verifier | None = None,
) -> dict[str, Any]:
    """Validate digest, lifecycle, and operator signature without mutation."""
    if not isinstance(raw, Mapping):
        raise ValueError("registry must be an object")
    _validate_header(raw, _SEALED_FIELDS)
    claimed = raw.get("registry_digest")
    if not isinstance(claimed, str) or registry_digest(raw) != claimed:
        raise ValueError("registry digest mismatch")
    value = _validated_content(raw)
    required = value["mode"] == "active"
    signature = _validate_signature(raw.get("signature"), required=required)
    if required and verifier is None:
        raise ValueError("active registry requires signature verifier")
    if required and not verifier(signing_bytes(raw), signature):
        raise ValueError("registry signature verification failed")
    return {**value, "signature": signature, "registry_digest": claimed}


def _budget(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping) or frozenset(value) != frozenset(_BUDGET_FIELDS):
        raise ValueError("job skill budget is invalid")
    projected: dict[str, int] = {}
    for field in _BUDGET_FIELDS:
        item = value.get(field)
        if isinstance(item, bool) or not isinstance(item, int) or item < 1:
            raise ValueError("job skill budget is invalid")
        projected[field] = item
    return projected


def _active_records(registry: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [item for item in registry["records"] if item["state"] == "active"]


def _lifecycle_rejections(registry: Mapping[str, Any]) -> list[dict[str, str]]:
    rejected: list[dict[str, str]] = []
    for item in registry["records"]:
        if item["state"] == "active":
            continue
        reason = (
            "artifact_revoked" if item["state"] == "revoked"
            else "lifecycle_state_unavailable"
        )
        rejected.append({"id": item["manifest"]["id"], "reason": reason})
    return rejected


def _rejections_for_provider(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    return [
        {"id": item["manifest"]["id"], "reason": "unsupported_provider"}
        for item in records
    ]


def _selection_records(
    records: list[dict[str, Any]], selection: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    by_digest = {
        item["manifest"]["artifact_digest"]: item for item in records
    }
    selected = [by_digest[item["artifact_digest"]] for item in selection["selected"]]
    rejected = list(selection.get("rejected") or [])
    return selected, rejected


def _relation_rejections(
    records: list[dict[str, Any]], selected: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    selected_digests = {
        item["manifest"]["artifact_digest"] for item in selected
    }
    conflicted_digests = _conflicted_digests(selected, selected_digests)
    rejected: list[dict[str, str]] = []
    admitted: list[dict[str, Any]] = []
    for item in selected:
        digest = item["manifest"]["artifact_digest"]
        reason = ""
        if not set(item["dependencies"]).issubset(selected_digests):
            reason = "dependency_unavailable"
        elif digest in conflicted_digests:
            reason = "skill_conflict"
        if reason:
            rejected.append({"id": item["manifest"]["id"], "reason": reason})
        else:
            admitted.append(item)
    return admitted, rejected


def _conflicted_digests(
    selected: list[dict[str, Any]], selected_digests: set[str],
) -> set[str]:
    conflicted: set[str] = set()
    for item in selected:
        peers = set(item["conflicts"]) & selected_digests
        if peers:
            conflicted.add(item["manifest"]["artifact_digest"])
            conflicted.update(peers)
    return conflicted


def _aggregate_budget(records: list[dict[str, Any]]) -> dict[str, int]:
    return {
        field: sum(item["manifest"]["budgets"][field] for item in records)
        for field in _BUDGET_FIELDS
    }


def _budget_admission(
    records: list[dict[str, Any]], limit: dict[str, int],
) -> tuple[list[dict[str, Any]], list[dict[str, str]], dict[str, int]]:
    aggregate = _aggregate_budget(records)
    if all(aggregate[field] <= limit[field] for field in _BUDGET_FIELDS):
        return records, [], aggregate
    rejected = [
        {"id": item["manifest"]["id"], "reason": "aggregate_budget_exceeded"}
        for item in records
    ]
    return [], rejected, aggregate


def _identity(item: dict[str, Any]) -> dict[str, str]:
    manifest = item["manifest"]
    return {
        "id": manifest["id"],
        "version": manifest["version"],
        "artifact_digest": manifest["artifact_digest"],
        "selection_reason": "exact_match_capability_and_promotion_gates_satisfied",
    }


def _deduplicated_rejections(
    values: Iterable[Mapping[str, Any]],
) -> list[dict[str, str]]:
    unique = {
        (str(item.get("id") or "unknown"), str(item.get("reason") or "unknown"))
        for item in values
    }
    return [{"id": item[0], "reason": item[1]} for item in sorted(unique)]


def _selection_result(
    registry: Mapping[str, Any], provider: str, compatible: bool,
    selected: list[dict[str, Any]], rejected: list[dict[str, str]],
    aggregate: dict[str, int], truncated: bool,
) -> dict[str, Any]:
    identities = sorted((_identity(item) for item in selected), key=lambda item: item["id"])
    return {
        "schema": SELECTION_SCHEMA,
        "mode": registry["mode"],
        "registry_version": registry["revision"],
        "registry_digest": registry["registry_digest"],
        "provider": provider,
        "provider_compatible": compatible,
        "selected": identities,
        "selected_count": len(identities),
        "truncated": truncated,
        "rejected": _deduplicated_rejections(rejected),
        "aggregate_budget": aggregate,
        "enforcement": "identity_only_no_execution",
    }


def select_registry(
    raw: Any, context: Mapping[str, Any], role: str,
    permitted_capabilities: Iterable[str], *, provider: str,
    budget: Mapping[str, Any], verifier: Verifier | None = None,
) -> dict[str, Any]:
    """Select one provider-compatible, relation-complete, budgeted skill set."""
    validated = validate_registry(raw, verifier=verifier)
    limits = _budget(budget)
    records = _active_records(validated)
    lifecycle_rejected = _lifecycle_rejections(validated)
    normalized_provider = str(provider or "").strip().lower()
    if normalized_provider not in _NATIVE_PROVIDERS:
        return _selection_result(
            validated, normalized_provider, False, [],
            _rejections_for_provider(records), _aggregate_budget([]), False,
        )
    selection = skills.resolve_manifests(
        records, context, role, permitted_capabilities,
    )
    selected, rejected = _selection_records(records, selection)
    selected, relation_rejected = _relation_rejections(records, selected)
    selected, budget_rejected, aggregate = _budget_admission(selected, limits)
    return _selection_result(
        validated, normalized_provider, True, selected,
        lifecycle_rejected + rejected + relation_rejected + budget_rejected,
        aggregate, bool(selection.get("truncated")),
    )


def rollback_snapshot(
    history: Iterable[Any], current_digest: str, *,
    verifier: Verifier | None = None,
) -> dict[str, Any]:
    """Return the exact signed predecessor snapshot for controlled restoration."""
    validated = [validate_registry(item, verifier=verifier) for item in history]
    by_digest = {item["registry_digest"]: item for item in validated}
    if len(by_digest) != len(validated):
        raise ValueError("registry history contains duplicate snapshots")
    current = by_digest.get(current_digest)
    if current is None:
        raise ValueError("current registry snapshot is unavailable")
    previous_digest = current["previous_registry_digest"]
    previous = by_digest.get(previous_digest)
    if previous is None or previous["revision"] >= current["revision"]:
        raise ValueError("registry rollback predecessor is unavailable")
    return copy.deepcopy(previous)
