#!/usr/bin/env python3
"""Validate governed v2 investigation-skill candidates without activating them.

This module is deliberately disconnected from the production v1 selector.  It
provides the fail-closed contract needed to replay and review v2 manifests
before a separately approved registry can make them available to the harness.
It never executes a query or grants a capability.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit


SCHEMA = "onion-sentinel-investigation-skill-manifest-v2"
RESULT_SCHEMA = "onion-sentinel-skill-result-v1"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SELECTED = 4
DIGEST_RE = re.compile(r"[a-f0-9]{64}")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?")
IDENTIFIER_RE = re.compile(r"[a-z][a-z0-9.-]{2,127}")
SAFE_ROLES = {
    "soc-analyst", "incident-responder", "siem-engineer",
    "cyber-threat-intel", "threat-hunter",
}
SAFE_STATES = {"candidate", "shadow", "active", "deprecated", "revoked"}
SAFE_BACKENDS = {
    "elastic", "oql", "suricata", "zeek", "pcap-derived",
    "osquery-historical", "osquery-live", "threat-intel", "ac-hunter",
}
SAFE_LANGUAGES = {"query-dsl", "kql", "oql", "broker-parameters", "osquery-sql"}
REQUIRED_FIELDS = {
    "schema", "id", "version", "artifact_digest", "lineage",
    "compatibility", "maintainer", "roles", "match", "objective",
    "capabilities", "safety", "budgets", "preconditions",
    "required_evidence", "query_templates", "output_contract",
    "alternative_hypotheses", "stop_conditions", "confidence_limiters",
    "known_false_positive_patterns", "verification", "references",
}
RUNTIME_COMPATIBILITY = {
    "harness_contract": "onion-sentinel-harness-job-envelope-v1",
    "policy_schema": "onion-sentinel-investigation-harness-policy-v1",
    "evidence_contract": "onion-sentinel-evidence-reference-contract-v1",
}
_COMPATIBILITY_VALUE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def artifact_digest(manifest: Mapping[str, Any]) -> str:
    value = dict(manifest)
    value["artifact_digest"] = "0" * 64
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _bounded_strings(value: Any, field: str, *, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise ValueError(f"{field} must be a non-empty bounded list")
    if any(not isinstance(item, str) or not item.strip() or len(item) > 500 for item in value):
        raise ValueError(f"{field} contains an invalid value")
    if len(value) != len(set(value)):
        raise ValueError(f"{field} must contain unique values")
    return list(value)


def _validate_manifest_contract(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != REQUIRED_FIELDS:
        raise ValueError("manifest fields do not match the v2 contract")
    if raw.get("schema") != SCHEMA:
        raise ValueError("unsupported manifest schema")
    return raw


def _validate_manifest_identity(raw: dict[str, Any]) -> None:
    if not IDENTIFIER_RE.fullmatch(str(raw.get("id") or "")):
        raise ValueError("manifest id is invalid")
    if not VERSION_RE.fullmatch(str(raw.get("version") or "")):
        raise ValueError("manifest version is invalid")
    claimed = str(raw.get("artifact_digest") or "")
    if not DIGEST_RE.fullmatch(claimed) or artifact_digest(raw) != claimed:
        raise ValueError("manifest artifact digest mismatch")


def _timestamp(value: Any) -> bool:
    if not isinstance(value, str) or len(value) > 40:
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _validate_manifest_lineage(raw: dict[str, Any]) -> None:
    lineage = raw.get("lineage")
    if not isinstance(lineage, dict) or set(lineage) != {
        "source_revision", "predecessor_digest",
    }:
        raise ValueError("manifest lineage is invalid")
    revision = lineage.get("source_revision")
    predecessor = lineage.get("predecessor_digest")
    if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{7,64}", revision):
        raise ValueError("manifest lineage is invalid")
    if predecessor != "" and (
        not isinstance(predecessor, str) or not DIGEST_RE.fullmatch(predecessor)
    ):
        raise ValueError("manifest lineage is invalid")


def _validate_manifest_compatibility(raw: dict[str, Any]) -> None:
    compatibility = raw.get("compatibility")
    if not isinstance(compatibility, dict) or set(compatibility) != set(
        RUNTIME_COMPATIBILITY
    ):
        raise ValueError("manifest compatibility is invalid")
    if any(
        not isinstance(value, str) or not _COMPATIBILITY_VALUE_RE.fullmatch(value)
        for value in compatibility.values()
    ):
        raise ValueError("manifest compatibility is invalid")


def _validate_manifest_maintainer(raw: dict[str, Any]) -> None:
    maintainer = raw.get("maintainer")
    if not isinstance(maintainer, dict) or set(maintainer) != {
        "owner", "reviewed_at", "reviewer",
    }:
        raise ValueError("manifest maintainer is invalid")
    if any(
        not isinstance(maintainer.get(key), str)
        or not str(maintainer[key]).strip()
        or len(str(maintainer[key])) > 100
        for key in ("owner", "reviewer")
    ) or not _timestamp(maintainer.get("reviewed_at")):
        raise ValueError("manifest maintainer is invalid")


def _validate_manifest_verification(raw: dict[str, Any]) -> None:
    verification = raw.get("verification")
    flags = {
        "unit_tests", "independent_query_review", "adversarial_tests",
        "human_approved",
    }
    if not isinstance(verification, dict) or set(verification) != flags | {
        "replay_cases",
    }:
        raise ValueError("manifest verification is invalid")
    replay_cases = verification.get("replay_cases")
    if any(not isinstance(verification.get(key), bool) for key in flags) or (
        not isinstance(replay_cases, int)
        or isinstance(replay_cases, bool)
        or replay_cases < 0
    ):
        raise ValueError("manifest verification is invalid")


def _bounded_reference_text(value: Any, maximum: int) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= maximum


def _https_reference_url(value: Any) -> bool:
    parsed = urlsplit(value) if isinstance(value, str) else None
    return bool(parsed and parsed.scheme == "https" and parsed.hostname)


def _validate_reference(reference: Any) -> None:
    fields = {"title", "url", "product_version", "retrieved_at"}
    if not isinstance(reference, dict) or set(reference) != fields:
        raise ValueError("manifest references are invalid")
    valid = (
        _bounded_reference_text(reference.get("title"), 200)
        and _bounded_reference_text(reference.get("product_version"), 80)
        and _https_reference_url(reference.get("url"))
        and _timestamp(reference.get("retrieved_at"))
    )
    if not valid:
        raise ValueError("manifest references are invalid")


def _validate_manifest_references(raw: dict[str, Any]) -> None:
    references = raw.get("references")
    if not isinstance(references, list) or not references or len(references) > 64:
        raise ValueError("manifest references are invalid")
    for reference in references:
        _validate_reference(reference)


def _validate_manifest_access(raw: dict[str, Any]) -> None:
    roles = _bounded_strings(raw.get("roles"), "roles", maximum=5)
    if not set(roles).issubset(SAFE_ROLES):
        raise ValueError("manifest role is unsupported")
    capabilities = _bounded_strings(raw.get("capabilities"), "capabilities")
    if any(not IDENTIFIER_RE.fullmatch(item) for item in capabilities):
        raise ValueError("manifest capability is invalid")


def _validate_manifest_safety(raw: dict[str, Any]) -> None:
    safety = raw.get("safety")
    if not isinstance(safety, dict) or set(safety) != {
        "read_only", "active_operation", "sensitivity", "requires_approval",
    }:
        raise ValueError("manifest safety contract is invalid")
    if safety.get("read_only") is not True:
        raise ValueError("v2 skills cannot grant mutation authority")
    if safety.get("active_operation") is True and safety.get("requires_approval") is not True:
        raise ValueError("active operation must require approval")


def _validate_manifest_budgets(raw: dict[str, Any]) -> None:
    budgets = raw.get("budgets")
    bounds = {
        "max_queries": (1, 12), "max_rows": (1, 5000),
        "max_bytes": (1024, 8 * 1024 * 1024), "timeout_seconds": (1, 300),
    }
    if not isinstance(budgets, dict) or set(budgets) != set(bounds):
        raise ValueError("manifest budgets are invalid")
    for name, (lower, upper) in bounds.items():
        if not isinstance(budgets[name], int) or not lower <= budgets[name] <= upper:
            raise ValueError(f"manifest {name} is outside its bound")


def _validate_manifest_match(raw: dict[str, Any]) -> None:
    match = raw.get("match")
    if not isinstance(match, dict) or set(match) != {
        "tasks", "protocols", "alert_families", "data_sources",
    }:
        raise ValueError("manifest match contract is invalid")
    for name, values in match.items():
        _bounded_strings(values, f"match.{name}")


def _validate_query_template(template: Any, template_ids: set[str]) -> None:
    if not isinstance(template, dict) or set(template) != {
        "id", "backend", "language", "purpose", "parameters", "expected_fields",
    }:
        raise ValueError("query template contract is invalid")
    template_id = str(template.get("id") or "")
    if template_id in template_ids or not template_id:
        raise ValueError("query template id is invalid or duplicated")
    template_ids.add(template_id)
    if template.get("backend") not in SAFE_BACKENDS or template.get("language") not in SAFE_LANGUAGES:
        raise ValueError("query template backend or language is unsupported")
    _bounded_strings(template.get("parameters"), f"{template_id}.parameters")
    _bounded_strings(template.get("expected_fields"), f"{template_id}.expected_fields")


def _validate_manifest_templates(raw: dict[str, Any]) -> None:
    templates = raw.get("query_templates")
    if not isinstance(templates, list) or not templates or len(templates) > 12:
        raise ValueError("query_templates must contain 1-12 templates")
    template_ids: set[str] = set()
    for template in templates:
        _validate_query_template(template, template_ids)


def _validate_manifest_output(raw: dict[str, Any]) -> None:
    output = raw.get("output_contract")
    if output != {
        "schema": RESULT_SCHEMA,
        "coverage_required": True,
        "truncation_required": True,
        "evidence_refs_required": True,
    }:
        raise ValueError("skill output contract is unsafe")
    for name in (
        "preconditions", "required_evidence", "alternative_hypotheses",
        "stop_conditions", "confidence_limiters", "known_false_positive_patterns",
    ):
        _bounded_strings(raw.get(name), name)


def validate_manifest(raw: Any) -> dict[str, Any]:
    manifest = _validate_manifest_contract(raw)
    _validate_manifest_identity(manifest)
    _validate_manifest_lineage(manifest)
    _validate_manifest_compatibility(manifest)
    _validate_manifest_maintainer(manifest)
    _validate_manifest_access(manifest)
    _validate_manifest_safety(manifest)
    _validate_manifest_budgets(manifest)
    _validate_manifest_match(manifest)
    _validate_manifest_templates(manifest)
    _validate_manifest_output(manifest)
    _validate_manifest_verification(manifest)
    _validate_manifest_references(manifest)
    return json.loads(json.dumps(raw))


def load_manifest(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds its byte limit")
    return validate_manifest(json.loads(raw.decode("utf-8")))


def _verification_failures(verification: Mapping[str, Any]) -> list[str]:
    failures: list[str] = []
    for field in ("unit_tests", "independent_query_review", "adversarial_tests"):
        if verification.get(field) is not True:
            failures.append(field)
    if not isinstance(verification.get("replay_cases"), int) or verification.get("replay_cases", 0) < 1:
        failures.append("replay_cases")
    return failures


def _promotion_failures(
    manifest: Mapping[str, Any], target_state: str,
) -> list[str] | None:
    verification = manifest.get("verification")
    if not isinstance(verification, dict):
        return None
    failures = _verification_failures(verification)
    maintainer = manifest.get("maintainer")
    if not isinstance(maintainer, dict) or str(maintainer.get("reviewer") or "").strip().lower() in {"", "pending"}:
        failures.append("independent_reviewer")
    if target_state == "active" and verification.get("human_approved") is not True:
        failures.append("human_approved")
    return failures


def promotion_eligible(manifest: Mapping[str, Any], target_state: str) -> tuple[bool, list[str]]:
    if target_state not in {"shadow", "active"}:
        raise ValueError("promotion target must be shadow or active")
    failures = _promotion_failures(manifest, target_state)
    if failures is None:
        return False, ["verification_missing"]
    try:
        validate_manifest(dict(manifest))
    except (TypeError, ValueError):
        failures.append("manifest_validation")
    return not failures, sorted(set(failures))


def _record_identity(record: Mapping[str, Any]) -> tuple[str, Any, str]:
    state = str(record.get("state") or "")
    manifest = record.get("manifest")
    identity = str(manifest.get("id") or "unknown") if isinstance(manifest, dict) else "unknown"
    return state, manifest, identity


def _context_dimensions(context: Mapping[str, Any]) -> dict[str, str]:
    return {
        "tasks": str(context.get("task") or ""),
        "protocols": str(context.get("protocol") or ""),
        "alert_families": str(context.get("alert_family") or ""),
        "data_sources": str(context.get("data_source") or ""),
    }


def _validated_record(
    record: Mapping[str, Any], selectable_states: set[str],
) -> tuple[dict[str, Any] | None, str, dict[str, str] | None]:
    state, manifest, identity = _record_identity(record)
    if state not in SAFE_STATES or state not in selectable_states:
        rejection = {"id": identity, "reason": "lifecycle_state_unavailable"}
        return None, state, rejection
    try:
        validated = validate_manifest(manifest)
    except (TypeError, ValueError):
        rejection = {"id": identity, "reason": "manifest_validation_failed"}
        return None, state, rejection
    return validated, state, None


def _admission_rejection(
    validated: dict[str, Any], state: str, context: Mapping[str, Any],
    normalized_role: str, permitted: set[str], identity: str,
) -> dict[str, str] | None:
    eligible, _ = promotion_eligible(validated, state)
    if not eligible:
        return {"id": identity, "reason": "promotion_gates_incomplete"}
    if validated["compatibility"] != RUNTIME_COMPATIBILITY:
        return {"id": identity, "reason": "compatibility_mismatch"}
    if normalized_role not in validated["roles"]:
        return {"id": identity, "reason": "role_mismatch"}
    dimensions = _context_dimensions(context)
    if any(value and value not in validated["match"][name] for name, value in dimensions.items()):
        return {"id": identity, "reason": "exact_match_failed"}
    if not set(validated["capabilities"]).issubset(permitted):
        return {"id": identity, "reason": "capability_not_permitted"}
    return None


def _resolve_record(
    record: Mapping[str, Any], context: Mapping[str, Any],
    normalized_role: str, permitted: set[str], selectable_states: set[str],
) -> tuple[dict[str, str] | None, dict[str, str] | None]:
    validated, state, rejection = _validated_record(record, selectable_states)
    if rejection is not None or validated is None:
        return None, rejection
    identity = str(validated["id"])
    rejection = _admission_rejection(
        validated, state, context, normalized_role, permitted, identity,
    )
    if rejection is not None:
        return None, rejection
    selected = {
        **{key: validated[key] for key in ("id", "version", "artifact_digest")},
        "selection_reason": "exact_match_capability_and_promotion_gates_satisfied",
    }
    return selected, None


def resolve_manifests(
    records: Iterable[Mapping[str, Any]],
    context: Mapping[str, Any],
    role: str,
    permitted_capabilities: Iterable[str],
    *,
    allow_shadow: bool = False,
) -> dict[str, Any]:
    """Return digest-bound identities only; never return guidance or templates."""
    permitted = set(permitted_capabilities)
    selectable_states = {"active", "shadow"} if allow_shadow else {"active"}
    selected: list[dict[str, str]] = []
    rejected: list[dict[str, str]] = []
    normalized_role = str(role or "").strip().lower()
    for record in records:
        selection, rejection = _resolve_record(
            record, context, normalized_role, permitted, selectable_states,
        )
        if rejection is not None:
            rejected.append(rejection)
        elif selection is not None:
            selected.append(selection)
    selected.sort(key=lambda item: (item["id"], item["version"], item["artifact_digest"]))
    rejected.sort(key=lambda item: (item["id"], item["reason"]))
    return {
        "schema": "onion-sentinel-investigation-skill-selection-v2-candidate",
        "selected": selected[:MAX_SELECTED],
        "selected_count": min(len(selected), MAX_SELECTED),
        "truncated": len(selected) > MAX_SELECTED,
        "rejected": rejected,
        "enforcement": "identity_only_no_execution",
    }
