"""Agent-memory registries, schema normalization, and provenance records.

This module is the policy foundation for the memory subsystem.  It performs no
filesystem writes and depends only on the standard library.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import re
from pathlib import Path
from typing import Any, Iterable


AGENT_MEMORY_FILES = {
    "soc-analyst": "soc-analyst-memory.md",
    "incident-responder": "incident-responder-memory.md",
    "siem-engineer": "siem-engineer-memory.md",
    "cyber-threat-intel": "cyber-threat-intel-memory.md",
    "threat-hunter": "threat-hunter-memory.md",
}
AGENT_PROMPT_FILES = {
    "soc-analyst": "soc_analyst_system_prompt.md",
    "incident-responder": "incident_responder_system_prompt.md",
    "siem-engineer": "siem_engineer_system_prompt.md",
    "cyber-threat-intel": "cyber_threat_intel_system_prompt.md",
    "threat-hunter": "threat_hunter_system_prompt.md",
}
AGENT_SECOND_OPINION_PROMPT_FILES = {
    "soc-analyst": "soc_analyst_second_opinion_prompt.md",
    "incident-responder": "incident_responder_second_opinion_prompt.md",
    "siem-engineer": "siem_engineer_second_opinion_prompt.md",
    "cyber-threat-intel": "cyber_threat_intel_second_opinion_prompt.md",
    "threat-hunter": "threat_hunter_second_opinion_prompt.md",
}
MEMORY_ROLES = frozenset(AGENT_MEMORY_FILES)
MEMORY_CATEGORIES = {
    "benign_pattern",
    "detection_pattern",
    "environment_context",
    "evidence_gap",
    "investigation_pivot",
    "response_lesson",
    "threat_intel_lesson",
    "tooling_lesson",
    "tuning_decision",
}
TOKEN_RE = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9._:/-]{2,}[a-z0-9])|[a-z0-9]{4,})",
    re.IGNORECASE,
)
STOP_WORDS = {
    "about", "after", "alert", "alerts", "analysis", "before", "current",
    "detection", "evidence", "finding", "group", "memory", "observed",
    "onion", "sentinel", "should", "source", "shared", "their", "there",
    "these", "this", "using", "when", "where", "which", "with",
}
SECRET_PATTERNS = (
    re.compile(r"BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY", re.IGNORECASE),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    re.compile(r"\b[0-9]{8,12}:AA[A-Za-z0-9_-]{30,}\b"),
    re.compile(
        r"\b(?:authorization|api[_ -]?key|secret|password)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"(?:\.ds-logs|\balert[_ -]?id\s*[:=])", re.IGNORECASE),
)
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
ACTIVE_MEMORY_STATUSES = frozenset({"model-observed", "operator-confirmed"})
DEFAULT_ROLE_RECORD_LIMIT = 200
DEFAULT_SHARED_RECORD_LIMIT = 300
MEMORY_SNAPSHOT_SCHEMA = "onion-sentinel-agent-memory-snapshot-v1"


def role_memory_file(memory_dir: Path, agent_role: str) -> Path:
    """Return the canonical role-memory path from the shared role registry."""
    try:
        filename = AGENT_MEMORY_FILES[agent_role]
    except KeyError as exc:
        raise ValueError(f"unsupported agent role: {agent_role}") from exc
    return memory_dir / filename


def role_prompt_file(config_dir: Path, agent_role: str) -> Path:
    """Return the canonical system-prompt path from the shared role registry."""
    try:
        filename = AGENT_PROMPT_FILES[agent_role]
    except KeyError as exc:
        raise ValueError(f"unsupported agent role: {agent_role}") from exc
    return config_dir / filename


def role_second_opinion_prompt_file(config_dir: Path, agent_role: str) -> Path:
    """Return the canonical independent-review prompt path for an agent role."""
    try:
        filename = AGENT_SECOND_OPINION_PROMPT_FILES[agent_role]
    except KeyError as exc:
        raise ValueError(f"unsupported agent role: {agent_role}") from exc
    return config_dir / filename


def project_now() -> str:
    return (
        dt.datetime.now()
        .astimezone()
        .replace(microsecond=0)
        .isoformat()
        .replace("T", "  ")
    )


def _parse_time(value: object) -> dt.datetime | None:
    text = str(value or "").strip().replace("  ", "T", 1)
    if not text:
        return None
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _clean_text(value: object, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    text = text.replace("<!--", "").replace("-->", "")
    return text[:limit].strip()


def _contains_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def _tokens(value: object) -> set[str]:
    if isinstance(value, dict):
        parts: Iterable[object] = value.values()
    elif isinstance(value, (list, tuple, set)):
        parts = value
    else:
        parts = (value,)
    found: set[str] = set()
    for part in parts:
        if isinstance(part, (dict, list, tuple, set)):
            found.update(_tokens(part))
            continue
        for token in TOKEN_RE.findall(str(part or "").lower()):
            if len(token) >= 3 and token not in STOP_WORDS:
                found.add(token[:160])
    return found


def _candidate_evidence_basis(value: dict[str, Any]) -> list[str]:
    raw = value.get("evidence_basis")
    if not isinstance(raw, list):
        return []
    cleaned = [_clean_text(item, 300) for item in raw]
    return [item for item in cleaned if item]


def _candidate_shape_is_allowed(
    *,
    scope: str,
    category: str,
    confidence: str,
) -> bool:
    if scope not in {"agent", "shared"} or category not in MEMORY_CATEGORIES:
        return False
    if confidence not in CONFIDENCE_RANK or confidence == "low":
        return False
    if scope == "shared" and confidence != "high":
        return False
    return True


def _candidate_ttl_days(value: dict[str, Any], *, scope: str) -> int:
    fallback = 180 if scope == "shared" else 90
    try:
        ttl_days = int(value.get("ttl_days") or fallback)
    except (TypeError, ValueError):
        ttl_days = fallback
    return min(365, max(7, ttl_days))


def normalize_memory_candidate(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    scope = str(value.get("scope") or "agent").strip().lower()
    category = str(value.get("category") or "").strip().lower()
    confidence = str(value.get("confidence") or "low").strip().lower()
    if not _candidate_shape_is_allowed(
        scope=scope,
        category=category,
        confidence=confidence,
    ):
        return None
    finding = _clean_text(value.get("finding"), 800)
    use_when = _clean_text(value.get("use_when"), 500)
    evidence_basis = _candidate_evidence_basis(value)
    if len(finding) < 20 or len(use_when) < 10 or not evidence_basis:
        return None
    tags = sorted(_tokens(value.get("tags", [])))[:12]
    combined = " ".join([finding, use_when, *evidence_basis, *tags])
    if _contains_secret(combined):
        return None
    return {
        "scope": scope,
        "category": category,
        "confidence": confidence,
        "finding": finding,
        "use_when": use_when,
        "evidence_basis": evidence_basis[:6],
        "tags": tags,
        "ttl_days": _candidate_ttl_days(value, scope=scope),
    }


def normalize_memory_candidates(
    value: object,
    limit: int = 5,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    normalized: list[dict[str, Any]] = []
    for item in value:
        candidate = normalize_memory_candidate(item)
        if candidate:
            normalized.append(candidate)
        if len(normalized) >= limit:
            break
    return normalized


def _candidate_id(agent_role: str, candidate: dict[str, Any]) -> str:
    stable = "|".join(
        [
            agent_role,
            candidate["scope"],
            candidate["category"],
            re.sub(r"[^a-z0-9]+", " ", candidate["finding"].lower()).strip(),
            re.sub(r"[^a-z0-9]+", " ", candidate["use_when"].lower()).strip(),
        ]
    )
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()[:20]


def _new_record(
    agent_role: str,
    candidate: dict[str, Any],
    *,
    analysis_id: str,
    source_artifact: str,
    now: dt.datetime,
) -> dict[str, Any]:
    created_at = now.replace(microsecond=0).isoformat().replace("T", "  ")
    expires_at = (
        (now + dt.timedelta(days=candidate["ttl_days"]))
        .replace(microsecond=0)
        .isoformat()
        .replace("T", "  ")
    )
    return {
        "id": _candidate_id(agent_role, candidate),
        "version": 1,
        "scope": candidate["scope"],
        "category": candidate["category"],
        "status": "model-observed",
        "confidence": candidate["confidence"],
        "finding": candidate["finding"],
        "use_when": candidate["use_when"],
        "evidence_basis": candidate["evidence_basis"],
        "tags": candidate["tags"],
        "created_at": created_at,
        "last_reinforced_at": created_at,
        "expires_at": expires_at,
        "reinforced_count": 1,
        "source_agent": agent_role,
        "source_analysis_id": _clean_text(analysis_id, 96),
        "source_artifact_hash": (
            hashlib.sha256(Path(source_artifact).name.encode("utf-8")).hexdigest()[:16]
            if source_artifact
            else ""
        ),
    }
