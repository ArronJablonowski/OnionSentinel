#!/usr/bin/env python3
"""Bounded, role-aware Markdown memory for Onion Sentinel agents.

The report corpus and SQLite analysis history remain the authoritative record of
individual investigations. Agent memory stores only reusable lessons that can
improve later work. Managed records are kept in a delimited Markdown section so
operators can maintain notes outside that section without the automation
rewriting them.
"""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import tempfile
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
MANAGED_START = "<!-- ONION_SENTINEL_MANAGED_MEMORY_START -->"
MANAGED_END = "<!-- ONION_SENTINEL_MANAGED_MEMORY_END -->"
RECORD_RE = re.compile(
    r"<!-- onion-sentinel-memory:v1\s*\n(?P<metadata>\{.*?\})\s*\n-->",
    re.DOTALL,
)
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
    re.compile(r"\b(?:authorization|api[_ -]?key|secret|password)\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"(?:\.ds-logs|\balert[_ -]?id\s*[:=])", re.IGNORECASE),
)
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}
DEFAULT_ROLE_RECORD_LIMIT = 200
DEFAULT_SHARED_RECORD_LIMIT = 300


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
    return dt.datetime.now().astimezone().replace(microsecond=0).isoformat().replace("T", "  ")


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


def _split_managed(text: str) -> tuple[str, str, str]:
    if MANAGED_START not in text or MANAGED_END not in text:
        return text.rstrip(), "", ""
    before, remainder = text.split(MANAGED_START, 1)
    managed, after = remainder.split(MANAGED_END, 1)
    return before.rstrip(), managed.strip(), after.strip()


def _load_text_locked(path: Path) -> str:
    if not path.exists():
        return ""
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_SH)
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _records_from_managed(managed: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for match in RECORD_RE.finditer(managed):
        try:
            record = json.loads(match.group("metadata"))
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict) and record.get("id"):
            records.append(record)
    return records


def read_memory_file(path: Path) -> tuple[str, list[dict[str, Any]]]:
    """Return operator-maintained Markdown and parsed managed records."""
    text = _load_text_locked(path)
    before, managed, after = _split_managed(text)
    manual = "\n\n".join(part for part in (before, after) if part).strip()
    return manual, _records_from_managed(managed)


def _record_is_expired(record: dict[str, Any], now: dt.datetime) -> bool:
    if record.get("status") == "operator-confirmed":
        return False
    expires = _parse_time(record.get("expires_at"))
    return bool(expires and expires < now)


def _relevance_score(record: dict[str, Any], query_tokens: set[str]) -> int:
    record_tokens = _tokens(
        {
            "finding": record.get("finding"),
            "use_when": record.get("use_when"),
            "evidence_basis": record.get("evidence_basis"),
        }
    )
    tag_tokens = _tokens(record.get("tags", []))
    score = len(query_tokens.intersection(record_tokens)) * 2
    score += len(query_tokens.intersection(tag_tokens)) * 6
    if record.get("status") == "operator-confirmed":
        score += 3
    score += min(3, int(record.get("reinforced_count") or 1) - 1)
    return score


def _bounded_utf8(text: str, limit_bytes: int) -> str:
    encoded = text.encode("utf-8")[: max(0, limit_bytes)]
    return encoded.decode("utf-8", errors="ignore")


def load_memory_context(
    path: Path,
    *,
    agent_role: str,
    evidence: object,
    limit_bytes: int = 8000,
    max_records: int = 8,
) -> dict[str, Any]:
    """Select relevant records instead of blindly injecting a file prefix."""
    manual, records = read_memory_file(path)
    now = dt.datetime.now().astimezone()
    active = [record for record in records if not _record_is_expired(record, now)]
    query_tokens = _tokens(evidence)
    scored = [(_relevance_score(record, query_tokens), record) for record in active]
    scored.sort(
        key=lambda item: (
            item[0],
            CONFIDENCE_RANK.get(str(item[1].get("confidence") or "low"), 0),
            str(item[1].get("last_reinforced_at") or item[1].get("created_at") or ""),
        ),
        reverse=True,
    )
    selected = [record for score, record in scored if score > 0][:max_records]
    if not selected:
        selected = [record for _, record in scored[: min(2, max_records)]]

    manual_budget = min(2000, max(0, limit_bytes // 4))
    manual_notes = _bounded_utf8(manual, manual_budget)
    record_budget = max(0, limit_bytes - len(manual_notes.encode("utf-8")))
    bounded_records: list[dict[str, Any]] = []
    used = 0
    visible_fields = (
        "id", "category", "status", "confidence", "finding", "use_when",
        "evidence_basis", "tags", "created_at", "last_reinforced_at",
        "expires_at", "reinforced_count", "source_agent", "source_analysis_id",
    )
    for record in selected:
        compact = {key: record.get(key) for key in visible_fields if record.get(key) not in (None, "", [])}
        size = len(json.dumps(compact, sort_keys=True).encode("utf-8"))
        if bounded_records and used + size > record_budget:
            break
        if size <= record_budget:
            bounded_records.append(compact)
            used += size
    return {
        "path": str(path),
        "exists": path.exists(),
        "agent_role": agent_role,
        "manual_notes": manual_notes,
        "records": bounded_records,
        "total_managed_records": len(records),
        "active_managed_records": len(active),
        "selection_policy": (
            "Relevant managed records are selected by current evidence, tags, confidence, reinforcement, and recency. "
            "Memory is context and must be corroborated by current evidence."
        ),
        "max_bytes": limit_bytes,
    }


def build_agent_memory_context(
    *,
    agent_role: str,
    role_memory_file: Path,
    shared_memory_file: Path,
    evidence: object,
    limit_bytes: int = 8000,
) -> dict[str, Any]:
    if agent_role not in MEMORY_ROLES:
        raise ValueError(f"unsupported agent role: {agent_role}")
    return {
        "role_memory": load_memory_context(
            role_memory_file,
            agent_role=agent_role,
            evidence=evidence,
            limit_bytes=limit_bytes,
        ),
        "shared_memory": load_memory_context(
            shared_memory_file,
            agent_role="shared",
            evidence=evidence,
            limit_bytes=limit_bytes,
        ),
        "usage_guidance": (
            "Use memory only as a lead or reusable lesson. Corroborate it with current evidence, preserve its confidence/status, "
            "and explicitly note conflicts. Never treat model-observed memory as proof."
        ),
    }


def build_agent_execution_context(
    *,
    agent_role: str,
    config_dir: Path,
    memory_dir: Path,
    evidence: object,
    limit_bytes: int = 8000,
) -> dict[str, Any]:
    """Package one agent prompt with the only supported memory context shape."""
    prompt_file = role_prompt_file(config_dir, agent_role)
    if not prompt_file.is_file():
        raise FileNotFoundError(f"agent system prompt not found: {prompt_file}")
    reviewer_prompt_file = role_second_opinion_prompt_file(config_dir, agent_role)
    if not reviewer_prompt_file.is_file():
        raise FileNotFoundError(f"agent second-opinion prompt not found: {reviewer_prompt_file}")
    memory_file = role_memory_file(memory_dir, agent_role)
    shared_file = memory_dir / "shared-agent-memory.md"
    return {
        "agent_role": agent_role,
        "system_prompt_file": str(prompt_file),
        "system_prompt": prompt_file.read_text(encoding="utf-8", errors="replace").strip(),
        # The reviewer reads this file in a separate model call. Its contents are
        # intentionally excluded from the primary package to preserve isolation.
        "second_opinion_system_prompt_file": str(reviewer_prompt_file),
        "agent_memory_file": str(memory_file),
        "shared_memory_file": str(shared_file),
        "agent_memory": build_agent_memory_context(
            agent_role=agent_role,
            role_memory_file=memory_file,
            shared_memory_file=shared_file,
            evidence=evidence,
            limit_bytes=limit_bytes,
        ),
        "memory_writeback_contract": {
            "response_field": "memory_candidates",
            "adapter": "manage-agent-memory.py writeback",
            "rule": "Only deterministic validation may update role or shared memory.",
        },
    }


def normalize_memory_candidate(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    scope = str(value.get("scope") or "agent").strip().lower()
    category = str(value.get("category") or "").strip().lower()
    confidence = str(value.get("confidence") or "low").strip().lower()
    finding = _clean_text(value.get("finding"), 800)
    use_when = _clean_text(value.get("use_when"), 500)
    evidence_basis = [
        _clean_text(item, 300)
        for item in value.get("evidence_basis", [])
        if _clean_text(item, 300)
    ] if isinstance(value.get("evidence_basis"), list) else []
    tags = sorted(_tokens(value.get("tags", [])))[:12]
    if scope not in {"agent", "shared"} or category not in MEMORY_CATEGORIES:
        return None
    if confidence not in CONFIDENCE_RANK or confidence == "low":
        return None
    if scope == "shared" and confidence != "high":
        return None
    if len(finding) < 20 or len(use_when) < 10 or not evidence_basis:
        return None
    combined = " ".join([finding, use_when, *evidence_basis, *tags])
    if _contains_secret(combined):
        return None
    try:
        ttl_days = int(value.get("ttl_days") or (180 if scope == "shared" else 90))
    except (TypeError, ValueError):
        ttl_days = 180 if scope == "shared" else 90
    return {
        "scope": scope,
        "category": category,
        "confidence": confidence,
        "finding": finding,
        "use_when": use_when,
        "evidence_basis": evidence_basis[:6],
        "tags": tags,
        "ttl_days": min(365, max(7, ttl_days)),
    }


def normalize_memory_candidates(value: object, limit: int = 5) -> list[dict[str, Any]]:
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
    expires_at = (now + dt.timedelta(days=candidate["ttl_days"])).replace(microsecond=0).isoformat().replace("T", "  ")
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
            if source_artifact else ""
        ),
    }


def _merge_record(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    merged["last_reinforced_at"] = incoming["last_reinforced_at"]
    merged["expires_at"] = incoming["expires_at"]
    merged["reinforced_count"] = int(existing.get("reinforced_count") or 1) + 1
    if CONFIDENCE_RANK.get(incoming["confidence"], 0) > CONFIDENCE_RANK.get(str(existing.get("confidence")), 0):
        merged["confidence"] = incoming["confidence"]
    merged["evidence_basis"] = list(dict.fromkeys([
        *[str(item) for item in existing.get("evidence_basis", [])],
        *incoming["evidence_basis"],
    ]))[-6:]
    merged["tags"] = sorted(set(existing.get("tags", [])).union(incoming["tags"]))[:12]
    merged["source_analysis_id"] = incoming["source_analysis_id"]
    merged["source_artifact_hash"] = incoming["source_artifact_hash"]
    return merged


def _record_markdown(record: dict[str, Any]) -> str:
    title = str(record.get("category") or "lesson").replace("_", " ").title()
    metadata = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    evidence = "; ".join(str(item) for item in record.get("evidence_basis", [])) or "n/a"
    tags = ", ".join(str(item) for item in record.get("tags", [])) or "none"
    return "\n".join(
        [
            f"### {title}",
            f"<!-- onion-sentinel-memory:v1\n{metadata}\n-->",
            f"- **Finding:** {record.get('finding', '')}",
            f"- **Use when:** {record.get('use_when', '')}",
            f"- **Evidence basis:** {evidence}",
            f"- **Confidence / status:** {record.get('confidence', 'low')} / {record.get('status', 'model-observed')}",
            f"- **Tags:** {tags}",
            f"- **Last reinforced:** {record.get('last_reinforced_at', '')} ({record.get('reinforced_count', 1)} observation(s))",
            f"- **Review or expiry:** {record.get('expires_at', '')}",
        ]
    )


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    current_mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, current_mode)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def initialize_memory_file(path: Path, title: str) -> dict[str, Any]:
    """Add the managed section without changing operator-authored Markdown."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
            start_count = text.count(MANAGED_START)
            end_count = text.count(MANAGED_END)
            if start_count == 1 and end_count == 1:
                return {"changed": False, "created": False, "path": str(path)}
            if start_count or end_count:
                raise ValueError(f"refusing to repair malformed managed section in {path}")
            created = not path.exists()
            operator_text = text.rstrip() or f"# {title}\n\n## Operator Notes"
            initialized = f"{operator_text}\n\n{MANAGED_START}\n\n{MANAGED_END}\n"
            _atomic_write_text(path, initialized)
            return {"changed": True, "created": created, "path": str(path)}
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _write_records(
    path: Path,
    incoming: list[dict[str, Any]],
    *,
    record_limit: int,
) -> dict[str, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    now = dt.datetime.now().astimezone()
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
            before, managed, after = _split_managed(text)
            existing_records = _records_from_managed(managed)
            active = [record for record in existing_records if not _record_is_expired(record, now)]
            by_id = {str(record.get("id")): record for record in active}
            added = 0
            reinforced = 0
            for record in incoming:
                record_id = str(record["id"])
                if record_id in by_id:
                    by_id[record_id] = _merge_record(by_id[record_id], record)
                    reinforced += 1
                else:
                    by_id[record_id] = record
                    added += 1
            records = list(by_id.values())
            records.sort(
                key=lambda item: (
                    item.get("status") == "operator-confirmed",
                    str(item.get("last_reinforced_at") or item.get("created_at") or ""),
                ),
                reverse=True,
            )
            records = records[:record_limit]
            managed_body = "\n\n".join(_record_markdown(record) for record in records)
            sections = [before.rstrip(), MANAGED_START, managed_body, MANAGED_END, after.strip()]
            output = "\n\n".join(section for section in sections if section).rstrip() + "\n"
            _atomic_write_text(path, output)
            return {
                "added": added,
                "reinforced": reinforced,
                "expired_removed": max(0, len(existing_records) - len(active)),
                "retained": len(records),
            }
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def persist_memory_candidates(
    *,
    agent_role: str,
    role_memory_file: Path,
    shared_memory_file: Path,
    candidates: object,
    analysis_id: str,
    source_artifact: str = "",
) -> dict[str, Any]:
    """Validate and persist reusable model observations without blocking analysis."""
    if agent_role not in MEMORY_ROLES:
        raise ValueError(f"unsupported agent role: {agent_role}")
    submitted = len(candidates) if isinstance(candidates, list) else 0
    normalized = normalize_memory_candidates(candidates)
    now = dt.datetime.now().astimezone()
    role_records: list[dict[str, Any]] = []
    shared_records: list[dict[str, Any]] = []
    for candidate in normalized:
        record = _new_record(
            agent_role,
            candidate,
            analysis_id=analysis_id,
            source_artifact=source_artifact,
            now=now,
        )
        (shared_records if candidate["scope"] == "shared" else role_records).append(record)
    result: dict[str, Any] = {
        "submitted": submitted,
        "accepted": len(normalized),
        "rejected": max(0, submitted - len(normalized)),
        "role": {"added": 0, "reinforced": 0, "expired_removed": 0, "retained": 0},
        "shared": {"added": 0, "reinforced": 0, "expired_removed": 0, "retained": 0},
    }
    if role_records:
        result["role"] = _write_records(
            role_memory_file,
            role_records,
            record_limit=DEFAULT_ROLE_RECORD_LIMIT,
        )
    if shared_records:
        result["shared"] = _write_records(
            shared_memory_file,
            shared_records,
            record_limit=DEFAULT_SHARED_RECORD_LIMIT,
        )
    return result
