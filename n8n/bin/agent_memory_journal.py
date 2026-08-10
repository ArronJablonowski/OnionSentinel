"""Bounded agent-memory Markdown journal and retrieval primitives."""
from __future__ import annotations

import datetime as dt
import fcntl
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from agent_memory_validation import (
    ACTIVE_MEMORY_STATUSES,
    CONFIDENCE_RANK,
    MEMORY_ROLES,
    _parse_time,
    _tokens,
    role_memory_file,
    role_prompt_file,
    role_second_opinion_prompt_file,
)


MANAGED_START = "<!-- ONION_SENTINEL_MANAGED_MEMORY_START -->"
MANAGED_END = "<!-- ONION_SENTINEL_MANAGED_MEMORY_END -->"
RECORD_RE = re.compile(
    r"<!-- onion-sentinel-memory:v1\s*\n(?P<metadata>\{.*?\})\s*\n-->",
    re.DOTALL,
)


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


def _active_memory_records(
    records: list[dict[str, Any]],
    *,
    now: dt.datetime,
) -> list[dict[str, Any]]:
    return [
        record
        for record in records
        if (
            not _record_is_expired(record, now)
            and str(record.get("status") or "model-observed")
            in ACTIVE_MEMORY_STATUSES
        )
    ]


def _selected_memory_records(
    active: list[dict[str, Any]],
    *,
    evidence: object,
    max_records: int,
) -> list[dict[str, Any]]:
    query_tokens = _tokens(evidence)
    scored = [(_relevance_score(record, query_tokens), record) for record in active]
    scored.sort(
        key=lambda item: (
            item[0],
            CONFIDENCE_RANK.get(str(item[1].get("confidence") or "low"), 0),
            str(
                item[1].get("last_reinforced_at")
                or item[1].get("created_at")
                or ""
            ),
        ),
        reverse=True,
    )
    selected = [record for score, record in scored if score > 0][:max_records]
    return selected or [record for _, record in scored[: min(2, max_records)]]


def _compact_visible_record(record: dict[str, Any]) -> dict[str, Any]:
    visible_fields = (
        "id", "category", "status", "confidence", "finding", "use_when",
        "evidence_basis", "tags", "created_at", "last_reinforced_at",
        "expires_at", "reinforced_count", "source_agent", "source_analysis_id",
    )
    return {
        key: record.get(key)
        for key in visible_fields
        if record.get(key) not in (None, "", [])
    }


def _bounded_selected_records(
    selected: list[dict[str, Any]],
    *,
    record_budget: int,
) -> list[dict[str, Any]]:
    bounded_records: list[dict[str, Any]] = []
    used = 0
    for record in selected:
        compact = _compact_visible_record(record)
        size = len(json.dumps(compact, sort_keys=True).encode("utf-8"))
        if bounded_records and used + size > record_budget:
            break
        if size <= record_budget:
            bounded_records.append(compact)
            used += size
    return bounded_records


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
    active = _active_memory_records(records, now=dt.datetime.now().astimezone())
    selected = _selected_memory_records(
        active,
        evidence=evidence,
        max_records=max_records,
    )
    manual_budget = min(2000, max(0, limit_bytes // 4))
    manual_notes = _bounded_utf8(manual, manual_budget)
    record_budget = max(0, limit_bytes - len(manual_notes.encode("utf-8")))
    bounded_records = _bounded_selected_records(
        selected,
        record_budget=record_budget,
    )
    return {
        "path": str(path),
        "exists": path.exists(),
        "agent_role": agent_role,
        "manual_notes": manual_notes,
        "records": bounded_records,
        "total_managed_records": len(records),
        "active_managed_records": len(active),
        "selection_policy": (
            "Relevant managed records are selected by current evidence, tags, "
            "confidence, reinforcement, and recency. Memory is context and must "
            "be corroborated by current evidence."
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
            "Use memory only as a lead or reusable lesson. Corroborate it with "
            "current evidence, preserve its confidence/status, and explicitly "
            "note conflicts. Never treat model-observed memory as proof."
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
        raise FileNotFoundError(
            f"agent second-opinion prompt not found: {reviewer_prompt_file}"
        )
    memory_file = role_memory_file(memory_dir, agent_role)
    shared_file = memory_dir / "shared-agent-memory.md"
    return {
        "agent_role": agent_role,
        "system_prompt_file": str(prompt_file),
        "system_prompt": prompt_file.read_text(
            encoding="utf-8",
            errors="replace",
        ).strip(),
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


def _record_markdown(record: dict[str, Any]) -> str:
    title = str(record.get("category") or "lesson").replace("_", " ").title()
    metadata = json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    evidence = "; ".join(
        str(item) for item in record.get("evidence_basis", [])
    ) or "n/a"
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
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=str(path.parent),
        text=True,
    )
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
            text = (
                path.read_text(encoding="utf-8", errors="replace")
                if path.exists()
                else ""
            )
            start_count = text.count(MANAGED_START)
            end_count = text.count(MANAGED_END)
            if start_count == 1 and end_count == 1:
                return {"changed": False, "created": False, "path": str(path)}
            if start_count or end_count:
                raise ValueError(
                    f"refusing to repair malformed managed section in {path}"
                )
            created = not path.exists()
            operator_text = text.rstrip() or f"# {title}\n\n## Operator Notes"
            initialized = (
                f"{operator_text}\n\n{MANAGED_START}\n\n{MANAGED_END}\n"
            )
            _atomic_write_text(path, initialized)
            return {"changed": True, "created": created, "path": str(path)}
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
