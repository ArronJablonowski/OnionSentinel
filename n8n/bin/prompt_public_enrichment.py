#!/usr/bin/env python3
"""Project cached public enrichment into bounded prompt context."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Callable


MAX_PROVIDER_PROMPT_BYTES = 16 * 1024
STATUS_FIELDS = ("source", "reason", "indicator", "indicator_type")


@dataclass(frozen=True)
class PublicEnrichmentSources:
    """Group-row and JSON operations supplied by the builder facade."""

    row_value: Callable[[Any, str], Any]
    alert_group_rows: Callable[..., list[Any]]
    parse_json_object: Callable[[str], dict]


@dataclass(frozen=True)
class PublicEnrichmentRequest:
    """Selected alert and explicit group projection bounds."""

    connection: Any
    selected: Any
    record_limit: int
    include_tests: bool


def _provider_evidence(record: dict) -> dict:
    raw = record.get("raw_response")
    serialized = json.dumps(
        raw,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    raw_bytes = serialized.encode("utf-8")
    complete = len(raw_bytes) <= MAX_PROVIDER_PROMPT_BYTES
    projection = (
        {"response": raw}
        if complete
        else {
            "response_json_prefix": raw_bytes[:MAX_PROVIDER_PROMPT_BYTES].decode(
                "utf-8", "ignore"
            )
        }
    )
    return {
        "response_sha256": record.get("raw_response_sha256")
        or hashlib.sha256(raw_bytes).hexdigest(),
        "response_size_bytes": record.get("raw_response_size_bytes")
        or len(raw_bytes),
        "cache_response_complete": record.get("raw_response_complete", True),
        "prompt_projection_complete": complete,
        **projection,
    }


def compact_public_enrichment_record(record: dict) -> dict:
    """Return metadata plus a digest-bound bounded provider projection."""
    return {
        "source": record.get("source"),
        "indicator": record.get("indicator"),
        "indicator_type": record.get("indicator_type"),
        "verdict": record.get("verdict"),
        "confidence": record.get("confidence"),
        "tags": record.get("tags") if isinstance(record.get("tags"), list) else [],
        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),
        "cached_at": record.get("cached_at"),
        "raw_response_sha256": record.get("raw_response_sha256"),
        "raw_response_size_bytes": record.get("raw_response_size_bytes"),
        "raw_response_complete": record.get("raw_response_complete"),
        "provider_evidence": _provider_evidence(record),
    }


def _external_bundle(bundle: dict) -> dict:
    external = bundle.get("external_intel")
    return external if isinstance(external, dict) else bundle


def _record_key(record: dict) -> tuple[str, str, str]:
    return (
        str(record.get("source") or ""),
        str(record.get("indicator_type") or ""),
        str(record.get("indicator") or ""),
    )


def _append_records(
    external: dict,
    records: list[dict],
    seen: set[tuple[str, str, str]],
    limit: int,
) -> None:
    candidates = external.get("records")
    if not isinstance(candidates, list):
        return
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        compact = compact_public_enrichment_record(candidate)
        key = _record_key(compact)
        if key in seen:
            continue
        seen.add(key)
        records.append(compact)
        if len(records) >= limit:
            return


def _normalized_status_entry(entry: Any) -> dict:
    if not isinstance(entry, dict):
        return {"reason": str(entry)}
    return {key: entry.get(key) for key in STATUS_FIELDS if key in entry}


def _append_status_entries(external: dict, key: str, target: list, limit: int) -> None:
    entries = external.get(key)
    if not isinstance(entries, list):
        return
    target.extend(_normalized_status_entry(entry) for entry in entries[:limit])


def _merge_indicators(external: dict, indicators: dict[str, list[str]], limit: int) -> None:
    raw = external.get("indicators")
    if not isinstance(raw, dict):
        return
    for key, value in raw.items():
        if isinstance(value, list):
            indicators[str(key)] = [str(item) for item in value[:limit]]


def _verdict_counts(records: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        verdict = str(record.get("verdict") or "unknown").lower()
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def build_public_enrichment_context(
    sources: PublicEnrichmentSources,
    request: PublicEnrichmentRequest,
) -> dict:
    """Collect deduplicated enrichment from the selected alert group."""
    group_rows = sources.alert_group_rows(
        request.connection,
        request.selected,
        include_tests=request.include_tests,
        extra_columns=("enrichment_json",),
    )
    records: list[dict] = []
    skipped: list[dict] = []
    errors: list[dict] = []
    indicators: dict[str, list[str]] = {}
    seen: set[tuple[str, str, str]] = set()
    for row in group_rows:
        bundle = sources.parse_json_object(
            str(sources.row_value(row, "enrichment_json") or "")
        )
        external = _external_bundle(bundle)
        _append_records(external, records, seen, request.record_limit)
        _append_status_entries(external, "skipped", skipped, request.record_limit)
        _append_status_entries(external, "errors", errors, request.record_limit)
        _merge_indicators(external, indicators, request.record_limit)
        if len(records) >= request.record_limit:
            break
    return {
        "records": records,
        "record_limit": request.record_limit,
        "verdict_counts": _verdict_counts(records),
        "indicators": indicators,
        "skipped": skipped[: request.record_limit],
        "errors": errors[: request.record_limit],
        "usage_guidance": (
            "Use public enrichment records as reputation/context evidence, not as sole proof of compromise. "
            "Mention malicious, suspicious, benign, scanner/noise, and unknown verdicts when they affect assessment, "
            "false-positive reasoning, escalation, or SIEM tuning."
        ),
    }
