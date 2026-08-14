"""Agent-memory quarantine and deterministic promotion policy."""
from __future__ import annotations

import datetime as dt
import fcntl
import re
from pathlib import Path
from typing import Any, Iterable

from agent_memory_journal import (
    MANAGED_END,
    MANAGED_START,
    _atomic_write_text,
    _record_is_expired,
    _record_markdown,
    _records_from_managed,
    _split_managed,
    read_memory_file,
)
from agent_memory_validation import (
    CONFIDENCE_RANK,
    DEFAULT_ROLE_RECORD_LIMIT,
    DEFAULT_SHARED_RECORD_LIMIT,
    MEMORY_ROLES,
    _clean_text,
    _new_record,
    normalize_memory_candidates,
    project_now,
)


def _merge_record(
    existing: dict[str, Any],
    incoming: dict[str, Any],
) -> dict[str, Any]:
    merged = dict(existing)
    merged["version"] = max(1, int(existing.get("version") or 1)) + 1
    merged["last_reinforced_at"] = incoming["last_reinforced_at"]
    merged["expires_at"] = incoming["expires_at"]
    merged["reinforced_count"] = int(existing.get("reinforced_count") or 1) + 1
    if CONFIDENCE_RANK.get(
        incoming["confidence"],
        0,
    ) > CONFIDENCE_RANK.get(str(existing.get("confidence")), 0):
        merged["confidence"] = incoming["confidence"]
    merged["evidence_basis"] = list(
        dict.fromkeys(
            [
                *[str(item) for item in existing.get("evidence_basis", [])],
                *incoming["evidence_basis"],
            ]
        )
    )[-6:]
    merged["tags"] = sorted(
        set(existing.get("tags", [])).union(incoming["tags"])
    )[:12]
    merged["source_analysis_id"] = incoming["source_analysis_id"]
    merged["source_artifact_hash"] = incoming["source_artifact_hash"]
    return merged


def _is_poisoned_bpfdoor_code_zero_record(record: dict[str, Any]) -> bool:
    """Match the narrow model-only BPFDoor/code-zero claim identified by audit."""
    if str(record.get("status") or "") != "model-observed":
        return False
    combined = " ".join(
        str(value or "")
        for value in (
            record.get("finding"),
            record.get("use_when"),
            " ".join(str(item) for item in record.get("evidence_basis", [])),
            " ".join(str(item) for item in record.get("tags", [])),
        )
    ).lower()
    if "bpfdoor" not in combined:
        return False
    code_zero = bool(
        re.search(r"\b(?:icmp\s+)?code\s*(?:=|:|is|of)?\s*0\b", combined)
    )
    false_positive_claim = bool(
        re.search(
            r"\b(?:false\s*positive|logic\s*(?:error|mismatch)|"
            r"rules?\s+out|does\s+not\s+match|required\s+code)\b",
            combined,
        )
    )
    return code_zero and false_positive_claim


def _bpfdoor_text(record: dict[str, Any]) -> str:
    return " ".join(
        str(value or "")
        for value in (
            record.get("finding"),
            record.get("use_when"),
            " ".join(str(item) for item in record.get("evidence_basis", [])),
            " ".join(str(item) for item in record.get("tags", [])),
        )
    ).lower()


def _quarantine_selector(
    explicit_ids: set[str],
):
    def selected(record: dict[str, Any]) -> bool:
        if str(record.get("status") or "") != "model-observed":
            return False
        if _is_poisoned_bpfdoor_code_zero_record(record):
            return True
        return (
            str(record.get("id") or "") in explicit_ids
            and "bpfdoor" in _bpfdoor_text(record)
        )

    return selected


def _quarantine_result(
    path: Path,
    *,
    apply: bool,
    predicate_matches: list[dict[str, Any]],
    explicit_matches: list[dict[str, Any]],
) -> dict[str, Any]:
    matches = [*predicate_matches, *explicit_matches]
    return {
        "path": str(path),
        "dry_run": not apply,
        "matched": len(matches),
        "record_ids": [str(record.get("id") or "") for record in matches],
        "predicate_match_ids": [
            str(record.get("id") or "") for record in predicate_matches
        ],
        "explicit_id_match_ids": [
            str(record.get("id") or "") for record in explicit_matches
        ],
        "applied": 0,
    }


def _apply_quarantine(
    path: Path,
    *,
    selected,
    selected_ids: set[str],
    reason: str,
) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    before, managed, after = _split_managed(text)
    current_records = _records_from_managed(managed)
    now = project_now()
    applied = 0
    updated: list[dict[str, Any]] = []
    for record in current_records:
        current = dict(record)
        if str(current.get("id") or "") in selected_ids and selected(current):
            current["version"] = max(1, int(current.get("version") or 1)) + 1
            current["status"] = "quarantined"
            current["quarantined_at"] = now
            current["quarantine_reason"] = _clean_text(reason, 500)
            applied += 1
        updated.append(current)
    managed_body = "\n\n".join(_record_markdown(record) for record in updated)
    sections = [
        before.rstrip(),
        MANAGED_START,
        managed_body,
        MANAGED_END,
        after.strip(),
    ]
    output = "\n\n".join(section for section in sections if section).rstrip() + "\n"
    _atomic_write_text(path, output)
    return applied


def _quarantine_matches(
    records: list[dict[str, Any]],
    *,
    explicit_ids: set[str],
):
    selected = _quarantine_selector(explicit_ids)
    predicate_matches = [
        record
        for record in records
        if _is_poisoned_bpfdoor_code_zero_record(record)
    ]
    predicate_ids = {
        str(record.get("id") or "") for record in predicate_matches
    }
    explicit_matches = [
        record
        for record in records
        if selected(record) and str(record.get("id") or "") not in predicate_ids
    ]
    return selected, predicate_matches, explicit_matches


def _commit_quarantine(
    path: Path,
    *,
    selected,
    matches: list[dict[str, Any]],
    reason: str,
) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_suffix(path.suffix + ".lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            return _apply_quarantine(
                path,
                selected=selected,
                selected_ids={str(record.get("id") or "") for record in matches},
                reason=reason,
            )
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def quarantine_bpfdoor_code_zero_memory(
    path: Path,
    *,
    apply: bool = False,
    record_ids: Iterable[str] = (),
    reason: str = (
        "Quarantined by the BPFDoor predicate correction: ICMP code 0 alone "
        "does not invalidate deployed SID 2069174 without the xbit-setting event."
    ),
) -> dict[str, Any]:
    """Preview or quarantine only poisoned, model-observed BPFDoor memories."""
    _, records = read_memory_file(path)
    explicit_ids = {
        str(value or "").strip()
        for value in record_ids
        if str(value or "").strip()
    }
    selected, predicate_matches, explicit_matches = _quarantine_matches(
        records,
        explicit_ids=explicit_ids,
    )
    result = _quarantine_result(
        path,
        apply=apply,
        predicate_matches=predicate_matches,
        explicit_matches=explicit_matches,
    )
    matches = [*predicate_matches, *explicit_matches]
    if not apply or not matches:
        return result

    result["applied"] = _commit_quarantine(
        path,
        selected=selected,
        matches=matches,
        reason=reason,
    )
    result["dry_run"] = False
    return result


def __accumulate_record(
    by_id: dict[str, dict[str, Any]],
    record: dict[str, Any],
) -> str:
    record_id = str(record["id"])
    if record_id not in by_id:
        by_id[record_id] = record
        return "added"
    existing = by_id[record_id]
    if str(existing.get("source_analysis_id") or "") == str(
        record.get("source_analysis_id") or ""
    ):
        return "replayed"
    by_id[record_id] = _merge_record(existing, record)
    return "reinforced"


def _ordered_records(
    existing_records: list[dict[str, Any]],
    incoming: list[dict[str, Any]],
    *,
    now: dt.datetime,
    record_limit: int,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    active = [record for record in existing_records if not _record_is_expired(record, now)]
    by_id = {str(record.get("id")): record for record in active}
    counts = {"added": 0, "reinforced": 0, "replayed": 0}
    for record in incoming:
        counts[__accumulate_record(by_id, record)] += 1
    records = list(by_id.values())
    records.sort(
        key=lambda item: (
            item.get("status") == "operator-confirmed",
            str(item.get("last_reinforced_at") or item.get("created_at") or ""),
        ),
        reverse=True,
    )
    records = records[:record_limit]
    return records, {
        **counts,
        "expired_removed": max(0, len(existing_records) - len(active)),
        "retained": len(records),
    }


def _write_records(
    path: Path,
    incoming: list[dict[str, Any]],
    *,
    record_limit: int,
) -> dict[str, int]:
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
            before, managed, after = _split_managed(text)
            records, stats = _ordered_records(
                _records_from_managed(managed),
                incoming,
                now=dt.datetime.now().astimezone(),
                record_limit=record_limit,
            )
            managed_body = "\n\n".join(
                _record_markdown(record) for record in records
            )
            sections = [
                before.rstrip(),
                MANAGED_START,
                managed_body,
                MANAGED_END,
                after.strip(),
            ]
            output = (
                "\n\n".join(section for section in sections if section).rstrip()
                + "\n"
            )
            _atomic_write_text(path, output)
            return stats
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _empty_persist_stats() -> dict[str, int]:
    return {
        "added": 0,
        "reinforced": 0,
        "replayed": 0,
        "expired_removed": 0,
        "retained": 0,
    }


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
        target = shared_records if candidate["scope"] == "shared" else role_records
        target.append(record)
    result: dict[str, Any] = {
        "submitted": submitted,
        "accepted": len(normalized),
        "rejected": max(0, submitted - len(normalized)),
        "role": _empty_persist_stats(),
        "shared": _empty_persist_stats(),
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
