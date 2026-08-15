#!/usr/bin/env python3
"""Validate and select bounded Onion Sentinel investigation skills.

Skills are code-owned procedural guidance.  This module never executes a query,
changes a case, or promotes a candidate skill.  It only returns a deterministic,
digest-bound projection for the trusted prompt builder and harness trace.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping


REGISTRY_SCHEMA = "onion-sentinel-investigation-skills-v1"
SELECTION_SCHEMA = "onion-sentinel-investigation-skill-selection-v1"
MAX_REGISTRY_BYTES = 1024 * 1024
MAX_SKILLS = 250
MAX_SELECTED_SKILLS = 4
MAX_LIST_ITEMS = 24
MAX_TEXT = 1000
IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}")
SAFE_ROLES = {
    "soc-analyst",
    "incident-responder",
    "siem-engineer",
    "cyber-threat-intel",
    "threat-hunter",
}
SAFE_STATUSES = {"candidate", "shadow", "active", "deprecated"}
SAFE_BACKENDS = {
    "elastic", "oql", "osquery", "pcap_zeek", "enrichment", "ac_hunter",
}
SAFE_EVIDENCE = {
    "alert",
    "asset_context",
    "cached_enrichment",
    "elastic_events",
    "endpoint_osquery",
    "network_flow",
    "pcap",
    "suricata",
    "zeek_conn",
    "zeek_dns",
    "zeek_files",
    "zeek_http",
    "zeek_ssh",
    "zeek_tls",
    "ac_hunter_behavioral_context",
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _bounded_text(value: Any, field: str, *, required: bool = True) -> str:
    text = str(value or "").strip()
    if (required and not text) or len(text) > MAX_TEXT:
        raise ValueError(f"{field} must be a non-empty bounded string")
    return text


def _identifier(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not IDENTIFIER_RE.fullmatch(text):
        raise ValueError(f"{field} is invalid")
    return text


def _string_list(
    value: Any,
    field: str,
    *,
    allowed: set[str] | None = None,
    required: bool = False,
) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_LIST_ITEMS:
        raise ValueError(f"{field} must be a bounded list")
    result: list[str] = []
    for index, item in enumerate(value):
        text = _bounded_text(item, f"{field}[{index}]").lower()
        if allowed is not None and text not in allowed:
            raise ValueError(f"{field}[{index}] is unsupported")
        if text not in result:
            result.append(text)
    if required and not result:
        raise ValueError(f"{field} must not be empty")
    return result


def _match_mapping(value: Any, skill_id: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{skill_id}.match must be an object")
    allowed_keys = {
        "event_datasets",
        "protocols",
        "destination_ports",
        "rule_name_contains",
        "evidence_sources",
    }
    unknown = set(value) - allowed_keys
    if unknown:
        raise ValueError(f"{skill_id}.match has unsupported keys: {sorted(unknown)}")
    return value


def _normalized_match_lists(
    value: dict[str, Any], skill_id: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in (
        "event_datasets", "protocols", "rule_name_contains",
        "evidence_sources",
    ):
        if key in value:
            result[key] = _string_list(
                value[key],
                f"{skill_id}.match.{key}",
                allowed=SAFE_EVIDENCE if key == "evidence_sources" else None,
            )
    return result


def _normalized_destination_ports(
    value: dict[str, Any], skill_id: str,
) -> list[int] | None:
    if "destination_ports" not in value:
        return None
    ports = value["destination_ports"]
    if (
        not isinstance(ports, list)
        or len(ports) > MAX_LIST_ITEMS
        or any(not isinstance(port, int) or port < 1 or port > 65535 for port in ports)
    ):
        raise ValueError(f"{skill_id}.match.destination_ports is invalid")
    return list(dict.fromkeys(ports))


def _validate_match(value: Any, skill_id: str) -> dict[str, Any]:
    mapping = _match_mapping(value, skill_id)
    result = _normalized_match_lists(mapping, skill_id)
    ports = _normalized_destination_ports(mapping, skill_id)
    if ports is not None:
        result["destination_ports"] = ports
    if not any(result.values()):
        raise ValueError(f"{skill_id}.match must define a bounded deterministic trigger")
    return result


def _validate_pivots(value: Any, skill_id: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value or len(value) > 12:
        raise ValueError(f"{skill_id}.pivot_plan must contain 1-12 steps")
    result: list[dict[str, Any]] = []
    step_ids: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"{skill_id}.pivot_plan[{index}] must be an object")
        step = _identifier(raw.get("step"), f"{skill_id}.pivot_plan[{index}].step")
        if step in step_ids:
            raise ValueError(f"{skill_id}.pivot_plan has duplicate step {step}")
        step_ids.add(step)
        backend = _identifier(raw.get("backend"), f"{skill_id}.{step}.backend")
        if backend not in SAFE_BACKENDS:
            raise ValueError(f"{skill_id}.{step}.backend is unsupported")
        result.append(
            {
                "step": step,
                "backend": backend,
                "pack": _identifier(raw.get("pack"), f"{skill_id}.{step}.pack"),
                "purpose": _identifier(raw.get("purpose"), f"{skill_id}.{step}.purpose"),
                "discriminator": _bounded_text(
                    raw.get("discriminator"),
                    f"{skill_id}.{step}.discriminator",
                ),
                "required": raw.get("required") is True,
            }
        )
    return result


def _skill_identity(
    raw: dict[str, Any], index: int,
) -> tuple[str, int, str, list[str]]:
    skill_id = _identifier(raw.get("id"), f"skills[{index}].id")
    version = raw.get("version")
    if not isinstance(version, int) or version < 1:
        raise ValueError(f"{skill_id}.version must be a positive integer")
    status = _identifier(raw.get("status"), f"{skill_id}.status")
    if status not in SAFE_STATUSES:
        raise ValueError(f"{skill_id}.status is unsupported")
    roles = _string_list(raw.get("roles"), f"{skill_id}.roles", allowed=SAFE_ROLES, required=True)
    return skill_id, version, status, roles


def _skill_projection(
    raw: dict[str, Any], skill_id: str, version: int,
    status: str, roles: list[str],
) -> dict[str, Any]:
    return {
        "id": skill_id,
        "version": version,
        "status": status,
        "roles": roles,
        "match": _validate_match(raw.get("match"), skill_id),
        "objective": _bounded_text(raw.get("objective"), f"{skill_id}.objective"),
        "required_evidence": _string_list(
            raw.get("required_evidence"),
            f"{skill_id}.required_evidence",
            allowed=SAFE_EVIDENCE,
            required=True,
        ),
        "pivot_plan": _validate_pivots(raw.get("pivot_plan"), skill_id),
        "alternative_hypotheses": _string_list(
            raw.get("alternative_hypotheses"),
            f"{skill_id}.alternative_hypotheses",
            required=True,
        ),
        "stop_conditions": _string_list(
            raw.get("stop_conditions"),
            f"{skill_id}.stop_conditions",
            required=True,
        ),
        "confidence_limiters": _string_list(
            raw.get("confidence_limiters"),
            f"{skill_id}.confidence_limiters",
            required=True,
        ),
        "known_false_positive_patterns": _string_list(
            raw.get("known_false_positive_patterns", []),
            f"{skill_id}.known_false_positive_patterns",
        ),
        "verification": _string_list(
            raw.get("verification"),
            f"{skill_id}.verification",
            required=True,
        ),
    }


def _validate_skill(raw: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"skills[{index}] must be an object")
    skill_id, version, status, roles = _skill_identity(raw, index)
    skill = _skill_projection(raw, skill_id, version, status, roles)
    skill["skill_sha256"] = _sha256(skill)
    return skill


def _read_registry_bytes(path: Path) -> bytes | None:
    try:
        if path.stat().st_size > MAX_REGISTRY_BYTES:
            raise ValueError("investigation skill registry exceeds its byte limit")
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    if len(raw) > MAX_REGISTRY_BYTES:
        raise ValueError("investigation skill registry exceeds its byte limit")
    return raw


def _empty_registry() -> dict[str, Any]:
    empty = {"schema": REGISTRY_SCHEMA, "version": 0, "mode": "shadow", "skills": []}
    return {**empty, "registry_sha256": _sha256(empty)}


def _registry_payload(raw: bytes) -> tuple[dict[str, Any], list[Any]]:
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != REGISTRY_SCHEMA:
        raise ValueError("unsupported investigation skill registry")
    if payload.get("version") != 1 or payload.get("mode") != "shadow":
        raise ValueError("investigation skill registry must be version 1 in shadow mode")
    raw_skills = payload.get("skills")
    if not isinstance(raw_skills, list) or len(raw_skills) > MAX_SKILLS:
        raise ValueError("investigation skills must be a bounded list")
    return payload, raw_skills


def _validated_skills(raw_skills: list[Any]) -> list[dict[str, Any]]:
    skills = [_validate_skill(raw_skill, index) for index, raw_skill in enumerate(raw_skills)]
    identities = [(skill["id"], skill["version"]) for skill in skills]
    if len(identities) != len(set(identities)):
        raise ValueError("investigation skill id/version pairs must be unique")
    return skills


def _learning_policy(payload: dict[str, Any]) -> dict[str, bool]:
    learning = payload.get("learning_policy")
    if not isinstance(learning, dict):
        raise ValueError("investigation skill learning_policy must be an object")
    required_learning = {
        "agent_may_propose": True,
        "agent_may_activate": False,
        "require_replay_evaluation": True,
        "require_independent_review": True,
        "require_human_approval": True,
    }
    if any(learning.get(key) is not expected for key, expected in required_learning.items()):
        raise ValueError("investigation skill learning policy weakens required promotion gates")
    return required_learning


def load_investigation_skills(path: Path) -> dict[str, Any]:
    """Load a strict bounded registry, returning an empty shadow registry if absent."""
    raw = _read_registry_bytes(path)
    if raw is None:
        return _empty_registry()
    payload, raw_skills = _registry_payload(raw)
    normalized_skills = _validated_skills(raw_skills)
    required_learning = _learning_policy(payload)
    normalized = {
        "schema": REGISTRY_SCHEMA,
        "version": 1,
        "mode": "shadow",
        "learning_policy": required_learning,
        "skills": normalized_skills,
    }
    return {**normalized, "registry_sha256": _sha256(normalized)}


def _context_match_values(
    context: Mapping[str, Any],
) -> tuple[str, str, str, int, set[str]]:
    dataset = str(context.get("event_dataset") or "").strip().lower()
    protocol = str(
        context.get("transport_protocol") or context.get("network_protocol") or ""
    ).strip().lower()
    rule_name = str(context.get("rule_name") or "").strip().lower()
    try:
        destination_port = int(context.get("destination_port"))
    except (TypeError, ValueError):
        destination_port = 0
    raw_sources = context.get("evidence_sources")
    evidence_sources = {
        str(item or "").strip().lower()
        for item in raw_sources
    } if isinstance(raw_sources, list) else set()
    return dataset, protocol, rule_name, destination_port, evidence_sources


def _trigger_checks(
    match: Mapping[str, Any], dataset: str, protocol: str,
    rule_name: str, destination_port: int, evidence_sources: set[str],
) -> list[bool]:
    checks: list[bool] = []
    if match.get("event_datasets"):
        checks.append(dataset in set(match["event_datasets"]))
    if match.get("protocols"):
        checks.append(protocol in set(match["protocols"]))
    if match.get("destination_ports"):
        checks.append(destination_port in set(match["destination_ports"]))
    if match.get("rule_name_contains"):
        checks.append(any(fragment in rule_name for fragment in match["rule_name_contains"]))
    if match.get("evidence_sources"):
        checks.append(set(match["evidence_sources"]).issubset(evidence_sources))
    return checks


def _matches(skill: Mapping[str, Any], context: Mapping[str, Any]) -> bool:
    match = skill.get("match") if isinstance(skill.get("match"), dict) else {}
    dataset, protocol, rule_name, destination_port, evidence_sources = (
        _context_match_values(context)
    )
    checks = _trigger_checks(
        match, dataset, protocol, rule_name, destination_port, evidence_sources,
    )
    return bool(checks) and all(checks)


def resolve_investigation_skills(
    registry: Mapping[str, Any],
    context: Mapping[str, Any],
    role: str,
) -> dict[str, Any]:
    """Return a stable, bounded shadow selection for one investigation."""
    normalized_role = str(role or "").strip().lower()
    selected = [
        skill
        for skill in registry.get("skills", [])
        if isinstance(skill, dict)
        and skill.get("status") in {"shadow", "active"}
        and normalized_role in skill.get("roles", [])
        and _matches(skill, context)
    ]
    selected.sort(key=lambda skill: (str(skill["id"]), int(skill["version"])))
    truncated = len(selected) > MAX_SELECTED_SKILLS
    projected = selected[:MAX_SELECTED_SKILLS]
    return {
        "schema": SELECTION_SCHEMA,
        "mode": "shadow",
        "registry_version": int(registry.get("version") or 0),
        "registry_sha256": str(registry.get("registry_sha256") or ""),
        "selected": projected,
        "selected_count": len(projected),
        "truncated": truncated,
        "enforcement": "advisory_only",
    }
