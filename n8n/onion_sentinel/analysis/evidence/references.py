"""Bounded, result-bound evidence reference primitives."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


@dataclass(frozen=True)
class Policy:
    maximum_text_length: int


SOURCE_CLASSES = {
    "alert": "security_onion_detection",
    "grouped_alert_context": "security_onion_detection",
    "detection_validation": "security_onion_detection",
    "public_enrichment": "public_enrichment",
    "asset_context": "asset_inventory_context",
    "analyst_state": "analyst_state",
    "pcap_evidence": "packet_evidence",
    "incident_response_evidence": "security_onion_incident_export",
    "investigation_query_results": "security_onion_investigation_query",
    "live_osquery_evidence": "live_endpoint_osquery",
    "ac_hunter_evidence": "behavioral_context",
}


def bounded(value: Any, policy: Policy) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[
        :policy.maximum_text_length
    ]


def source_class(source: Any) -> str:
    """Group multiple citations from one underlying source into one signal."""
    root = str(source or "").strip().lower().split(".", 1)[0]
    return SOURCE_CLASSES.get(root, root or "unknown")


def result_bound(
    query_digest: Any,
    result_digest: Any = "",
    *,
    namespace: str = "query",
    label: Any = "",
    policy: Policy,
) -> tuple[str, str]:
    """Return an immutable query reference and its strongest safe digest."""
    query_text = bounded(query_digest, policy)[:64].lower()
    if not re.fullmatch(r"[a-f0-9]{64}", query_text):
        return "", ""
    result_text = bounded(result_digest, policy)[:64].lower()
    if not re.fullmatch(r"[a-f0-9]{64}", result_text):
        result_text = ""
    normalized_namespace = str(namespace or "").strip().lower()
    if normalized_namespace not in {"query", "pack", "query-id"}:
        return "", ""
    suffix = f":{query_text}" + (f":{result_text}" if result_text else "")
    if normalized_namespace == "query":
        reference = f"query{suffix}"
    else:
        maximum_label = (
            policy.maximum_text_length
            - len(normalized_namespace)
            - 1
            - len(suffix)
        )
        bounded_label = bounded(label, policy)[:maximum_label]
        if not bounded_label:
            return "", ""
        reference = f"{normalized_namespace}:{bounded_label}{suffix}"
    return reference, result_text or query_text
