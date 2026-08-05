#!/usr/bin/env python3
"""Validate governed v2 investigation-skill candidates without activating them.

This module is deliberately disconnected from the production v1 selector.  It
provides the fail-closed contract needed to replay and review v2 manifests
before a separately approved registry can make them available to the harness.
It never executes a query or grants a capability.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


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


def validate_manifest(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != REQUIRED_FIELDS:
        raise ValueError("manifest fields do not match the v2 contract")
    if raw.get("schema") != SCHEMA:
        raise ValueError("unsupported manifest schema")
    if not IDENTIFIER_RE.fullmatch(str(raw.get("id") or "")):
        raise ValueError("manifest id is invalid")
    if not VERSION_RE.fullmatch(str(raw.get("version") or "")):
        raise ValueError("manifest version is invalid")
    claimed = str(raw.get("artifact_digest") or "")
    if not DIGEST_RE.fullmatch(claimed) or artifact_digest(raw) != claimed:
        raise ValueError("manifest artifact digest mismatch")

    roles = _bounded_strings(raw.get("roles"), "roles", maximum=5)
    if not set(roles).issubset(SAFE_ROLES):
        raise ValueError("manifest role is unsupported")
    capabilities = _bounded_strings(raw.get("capabilities"), "capabilities")
    if any(not IDENTIFIER_RE.fullmatch(item) for item in capabilities):
        raise ValueError("manifest capability is invalid")

    safety = raw.get("safety")
    if not isinstance(safety, dict) or set(safety) != {
        "read_only", "active_operation", "sensitivity", "requires_approval",
    }:
        raise ValueError("manifest safety contract is invalid")
    if safety.get("read_only") is not True:
        raise ValueError("v2 skills cannot grant mutation authority")
    if safety.get("active_operation") is True and safety.get("requires_approval") is not True:
        raise ValueError("active operation must require approval")

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

    match = raw.get("match")
    if not isinstance(match, dict) or set(match) != {
        "tasks", "protocols", "alert_families", "data_sources",
    }:
        raise ValueError("manifest match contract is invalid")
    for name, values in match.items():
        _bounded_strings(values, f"match.{name}")

    templates = raw.get("query_templates")
    if not isinstance(templates, list) or not templates or len(templates) > 12:
        raise ValueError("query_templates must contain 1-12 templates")
    template_ids: set[str] = set()
    for template in templates:
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
    return json.loads(json.dumps(raw))


def load_manifest(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds its byte limit")
    return validate_manifest(json.loads(raw.decode("utf-8")))


def promotion_eligible(manifest: Mapping[str, Any], target_state: str) -> tuple[bool, list[str]]:
    if target_state not in {"shadow", "active"}:
        raise ValueError("promotion target must be shadow or active")
    failures: list[str] = []
    verification = manifest.get("verification")
    if not isinstance(verification, dict):
        return False, ["verification_missing"]
    for field in ("unit_tests", "independent_query_review", "adversarial_tests"):
        if verification.get(field) is not True:
            failures.append(field)
    if not isinstance(verification.get("replay_cases"), int) or verification.get("replay_cases", 0) < 1:
        failures.append("replay_cases")
    maintainer = manifest.get("maintainer")
    if not isinstance(maintainer, dict) or str(maintainer.get("reviewer") or "").strip().lower() in {"", "pending"}:
        failures.append("independent_reviewer")
    if target_state == "active" and verification.get("human_approved") is not True:
        failures.append("human_approved")
    try:
        validate_manifest(dict(manifest))
    except (TypeError, ValueError):
        failures.append("manifest_validation")
    return not failures, sorted(set(failures))


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
        state = str(record.get("state") or "")
        manifest = record.get("manifest")
        identity = str(manifest.get("id") or "unknown") if isinstance(manifest, dict) else "unknown"
        if state not in SAFE_STATES or state not in selectable_states:
            rejected.append({"id": identity, "reason": "lifecycle_state_unavailable"})
            continue
        try:
            validated = validate_manifest(manifest)
        except (TypeError, ValueError):
            rejected.append({"id": identity, "reason": "manifest_validation_failed"})
            continue
        eligible, _ = promotion_eligible(validated, state)
        if not eligible:
            rejected.append({"id": identity, "reason": "promotion_gates_incomplete"})
            continue
        if normalized_role not in validated["roles"]:
            rejected.append({"id": identity, "reason": "role_mismatch"})
            continue
        match = validated["match"]
        dimensions = {
            "tasks": str(context.get("task") or ""),
            "protocols": str(context.get("protocol") or ""),
            "alert_families": str(context.get("alert_family") or ""),
            "data_sources": str(context.get("data_source") or ""),
        }
        if any(value and value not in match[name] for name, value in dimensions.items()):
            rejected.append({"id": identity, "reason": "exact_match_failed"})
            continue
        requested = set(validated["capabilities"])
        if not requested.issubset(permitted):
            rejected.append({"id": identity, "reason": "capability_not_permitted"})
            continue
        selected.append({
            "id": validated["id"],
            "version": validated["version"],
            "artifact_digest": validated["artifact_digest"],
        })
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
