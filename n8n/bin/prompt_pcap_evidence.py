#!/usr/bin/env python3
"""Project bounded PCAP artifacts into prompt-safe network evidence."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import sqlite3
from typing import Any, Callable


@dataclass(frozen=True)
class PcapEvidenceSources:
    """Trusted alert-store and bounded-file operations supplied by the builder."""

    row_value: Callable[[Any, str], Any]
    query_rows: Callable[[Any, str, list[Any]], list[Any]]
    load_json_bounded: Callable[[Path], Any]


@dataclass(frozen=True)
class PcapEvidenceRequest:
    """Selected alert and explicit PCAP evidence bounds."""

    connection: Any
    selected: Any
    analysis_dir: Path
    evidence_limit: int
    legacy_scan_limit: int


def _dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list:
    return value if isinstance(value, list) else []


def _bounded_dict_list(value: Any, limit: int) -> list[dict]:
    return [item for item in _list(value)[:limit] if isinstance(item, dict)]


def _local_query_index(zeek: dict, tshark: dict) -> dict[str, list]:
    result: dict[str, list] = {}
    for parser in (zeek, tshark):
        for operation, values in _dict(parser.get("_local_query_index")).items():
            if not isinstance(values, list):
                continue
            current = result.setdefault(str(operation), [])
            current.extend(item for item in values if isinstance(item, dict))
            del current[192:]
    return result


def _pcap_files(record: dict) -> list[dict]:
    return [
        {
            "name": item.get("name"),
            "size_bytes": item.get("size_bytes"),
            "sha256": item.get("sha256"),
        }
        for item in _bounded_dict_list(record.get("pcap_files"), 5)
    ]


def _zeek_projection(zeek: dict) -> dict:
    return {
        "available": bool(zeek.get("available")),
        "reason": zeek.get("reason"),
        "record_counts": _dict(zeek.get("record_counts")),
        "coverage": _dict(zeek.get("coverage")),
        "sampling": _dict(zeek.get("sampling")),
        "top_connections": _list(zeek.get("top_connections")),
        "dns_queries": _list(zeek.get("dns_queries")),
        "tls_sni": _list(zeek.get("tls_sni")),
        "http_hosts": _list(zeek.get("http_hosts")),
        "files": _list(zeek.get("files")),
        "notices": _list(zeek.get("notices")),
        "weird": _list(zeek.get("weird")),
    }


def _tshark_samples(tshark: dict) -> list[dict]:
    return [
        {
            "pcap": Path(str(sample.get("pcap") or "capture")).name,
            "protocol_hierarchy": str(sample.get("protocol_hierarchy") or "")[:4000],
            "conversations": str(sample.get("conversations") or "")[:4000],
            "field_sample_tsv": str(sample.get("field_sample_tsv") or "")[:4000],
        }
        for sample in _bounded_dict_list(tshark.get("samples"), 2)
    ]


def _tshark_projection(tshark: dict) -> dict:
    return {
        "available": bool(tshark.get("available")),
        "reason": tshark.get("reason"),
        "coverage": _dict(tshark.get("coverage")),
        "sampling": _dict(tshark.get("sampling")),
        "protocol_counts": _list(tshark.get("protocol_counts"))[:20],
        "top_conversations": _list(tshark.get("top_conversations"))[:20],
        "icmp_size_review": _dict(tshark.get("icmp_size_review")),
        "icmp_semantics": _dict(tshark.get("icmp_semantics")),
        "dns_activity": _dict(tshark.get("dns_activity")),
        "http_user_agents": _dict(tshark.get("http_user_agents")),
        "tls_versions": _dict(tshark.get("tls_versions")),
        "geoip": _dict(tshark.get("geoip")),
        "packet_samples": _list(tshark.get("packet_samples"))[:20],
        "samples": _tshark_samples(tshark),
    }


def compact_pcap_analysis(record: dict) -> dict:
    """Keep summaries and bounded capability indexes, never packet bodies."""
    zeek = _dict(record.get("zeek"))
    tshark = _dict(record.get("tshark"))
    request = _dict(record.get("request"))
    return {
        "analysis_artifact": record.get("_analysis_path"),
        "evidence_relationship": record.get("_evidence_relationship"),
        "generated_at": record.get("generated_at"),
        "request_id": request.get("request_id"),
        "alert_id": request.get("alert_id"),
        "group_id": request.get("group_id"),
        "artifact_state": record.get("artifact_state"),
        "coverage": _dict(record.get("coverage")),
        "evidence_security": _dict(record.get("evidence_security")),
        "pcap_files": _pcap_files(record),
        "tool_paths": _dict(record.get("tool_paths")),
        "zeek": _zeek_projection(zeek),
        "tshark": _tshark_projection(tshark),
        "detection_context": _dict(record.get("detection_context")),
        "_local_query_index": _local_query_index(zeek, tshark),
    }


def pcap_request_context(
    sources: PcapEvidenceSources,
    connection: Any,
    selected: Any,
) -> list[dict]:
    """Return exact and stable-group-related requests with exact fallback."""
    alert_id = str(selected["alert_id"] or "")
    stable_group_id = str(sources.row_value(selected, "stable_group_id") or "").strip()
    try:
        found = sources.query_rows(
            connection,
            """
            SELECT p.*,
                   CASE WHEN p.alert_id = ? THEN 'exact_alert'
                        ELSE 'stable_group_related' END AS evidence_relationship
            FROM pcap_requests p
            LEFT JOIN alert_group_alias a ON a.legacy_group_id = p.group_id
            WHERE p.alert_id = ?
               OR (? <> '' AND COALESCE(a.stable_group_id, p.group_id) = ?)
            ORDER BY created_at DESC
            LIMIT 10
            """,
            [alert_id, alert_id, stable_group_id, stable_group_id],
        )
    except sqlite3.Error:
        try:
            found = sources.query_rows(
                connection,
                """
                SELECT p.*, 'exact_alert' AS evidence_relationship
                FROM pcap_requests p
                WHERE p.alert_id = ?
                ORDER BY created_at DESC
                LIMIT 10
                """,
                [alert_id],
            )
        except sqlite3.Error:
            return []
    return [dict(item) for item in found]


def _request_ids(requests: list[dict]) -> list[str]:
    return [
        str(item.get("request_id") or "")
        for item in requests
        if str(item.get("request_id") or "")
    ]


def _request_relationships(requests: list[dict]) -> dict[str, str]:
    return {
        str(item.get("request_id") or ""): str(
            item.get("evidence_relationship") or "exact_alert"
        )
        for item in requests
        if str(item.get("request_id") or "")
    }


def _request_indexes(requests: list[dict]) -> tuple[list[str], dict, dict]:
    request_ids = _request_ids(requests)
    order = {request_id: position for position, request_id in enumerate(request_ids)}
    return request_ids, order, _request_relationships(requests)


def _safe_request_path(analysis_dir: Path, request_id: str) -> Path:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", request_id).strip("-")[:140]
    return analysis_dir / f"{name}-pcap-analysis.json"


def _candidate_paths(
    analysis_dir: Path,
    request_ids: list[str],
    evidence_limit: int,
    legacy_scan_limit: int,
) -> list[Path]:
    direct = [_safe_request_path(analysis_dir, request_id) for request_id in request_ids]
    candidates = [path for path in direct if path.exists()]
    if len(candidates) >= evidence_limit:
        return candidates
    try:
        legacy = sorted(
            analysis_dir.glob("*-pcap-analysis.json"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )[:legacy_scan_limit]
    except OSError:
        legacy = []
    candidates.extend(path for path in legacy if path not in candidates)
    return candidates


def _load_evidence(
    sources: PcapEvidenceSources,
    candidates: list[Path],
    alert_id: str,
    request_ids: set[str],
    relationships: dict,
    limit: int,
) -> list[dict]:
    evidence: list[dict] = []
    loaded: set[Path] = set()
    for path in candidates:
        if path in loaded:
            continue
        loaded.add(path)
        try:
            record = sources.load_json_bounded(path)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(record, dict):
            continue
        request = _dict(record.get("request"))
        request_id = str(request.get("request_id") or "")
        if request.get("alert_id") != alert_id and request_id not in request_ids:
            continue
        record["_analysis_path"] = str(path)
        record["_evidence_relationship"] = relationships.get(request_id, "exact_alert")
        evidence.append(compact_pcap_analysis(record))
        if len(evidence) >= limit:
            break
    return evidence


def _sort_evidence(evidence: list[dict], request_order: dict) -> None:
    evidence.sort(
        key=lambda item: (
            0 if item.get("evidence_relationship") == "exact_alert" else 1,
            request_order.get(str(item.get("request_id") or ""), len(request_order)),
        )
    )


def build_pcap_evidence_context(
    sources: PcapEvidenceSources,
    request: PcapEvidenceRequest,
) -> dict:
    """Collect bounded artifacts and prioritize exact selected-alert evidence."""
    requests = pcap_request_context(sources, request.connection, request.selected)
    request_ids, request_order, relationships = _request_indexes(requests)
    evidence: list[dict] = []
    if request.analysis_dir.exists():
        candidates = _candidate_paths(
            request.analysis_dir,
            request_ids,
            request.evidence_limit,
            request.legacy_scan_limit,
        )
        evidence = _load_evidence(
            sources,
            candidates,
            str(request.selected["alert_id"]),
            set(request_ids),
            relationships,
            request.evidence_limit,
        )
    _sort_evidence(evidence, request_order)
    return {
        "pcap_requests": requests,
        "parsed_evidence": evidence,
        "exact_alert_evidence_count": sum(
            item.get("evidence_relationship") == "exact_alert" for item in evidence
        ),
        "stable_group_related_evidence_count": sum(
            item.get("evidence_relationship") == "stable_group_related"
            for item in evidence
        ),
        "analysis_dir": str(request.analysis_dir),
        "usage_guidance": (
            "Use parsed_evidence when present. Zeek is the primary structured network evidence; "
            "TShark corroborates packet-level conversations and protocol hierarchy. If parsed_evidence is empty, "
            "treat PCAP as unavailable and list it as an evidence gap instead of inferring packet contents. "
            "Evidence marked exact_alert can support the selected event. Evidence marked stable_group_related "
            "is historical context for a related group event and must not be represented as packet proof for "
            "the selected alert."
        ),
    }
