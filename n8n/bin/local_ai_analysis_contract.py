"""Package-free model, evidence, reviewer, and query policy tables."""
from __future__ import annotations

import re

from investigation_query_contract import (
    PACKS as INVESTIGATION_QUERY_PACK_DEFINITIONS,
)
from local_ai_runtime_contract import (
    ACTIVITY_DISPOSITION_VALUES,
    CONFIDENCE_VALUES,
    DETECTION_OUTCOME_VALUES,
    DETECTION_VALIDITY_VALUES,
    EVENT_STATUS_VALUES,
    HANDLING_VALUES,
    TUNING_VALUES,
)

MODEL_INTERNAL_KEYS = {
    "analysis_artifact",
    "analysis_dir",
    "tool_paths",
    "system_prompt_file",
    "second_opinion_system_prompt_file",
    "agent_memory_file",
    "shared_memory_file",
    "sha256",
    "_live_osquery_evidence_accumulator",
}
HOSTED_TRANSPORT_FIXED_POINT_MAX_PASSES = 8
_MODEL_LIST_PATH_SENTINEL = object()
HOSTED_FORBIDDEN_KEYS = {
    "packet_samples",
    "field_sample_tsv",
    "pcap_follow_up_results",
    "pcap_query_requests",
    "raw_packet_payload",
    "raw_packet_payloads",
    "raw_payload",
    "payload",
    "live_osquery_requests",
    "hex",
    "printable",
    "raw_rule",
    "rule_text",
}

EVIDENCE_REFERENCE_MAX = 400
EVIDENCE_REFERENCE_TEXT_MAX = 256
REVIEW_OBSERVABLE_MAX = 256
REVIEW_EVIDENCE_USED_MAX = 100
REVIEW_HYPOTHESES_MAX = 20
REVIEW_VALIDATION_MESSAGE_MAX = 1000
REVIEW_VALIDATION_FAILURE_SCHEMA = (
    "onion-sentinel-reviewer-validation-failure-v1"
)
REVIEW_IPV4_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![A-Za-z0-9])"
)
REVIEW_DOMAIN_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}(?![A-Za-z0-9_-])"
)
REVIEW_COMMUNITY_ID_RE = re.compile(
    # Community ID v1 is the literal version prefix plus a base64-encoded
    # SHA-1 digest: 27 data characters and one padding character. Requiring
    # that exact shape prevents Elasticsearch document-ID suffixes such as
    # ``000535:XuBJm58BIwAfe8Cpckf6`` from becoming foreign observables.
    # Twenty input bytes leave four significant bits in the final base64
    # character, so its two pad bits must be zero for the canonical encoding.
    r"(?<![A-Za-z0-9_])1:[A-Za-z0-9+/]{26}[AEIMQUYcgkosw048]="
    r"(?![A-Za-z0-9_+/=])"
)
REVIEW_OBSERVABLE_KINDS = frozenset(
    {"ip", "domain", "host", "user", "community_id"}
)
REVIEW_NON_DOMAIN_SUFFIXES = frozenset(
    {
        "csv", "html", "json", "log", "md", "pcap", "pcapng", "py", "toml",
        "txt", "yaml", "yml",
    }
)


def _review_known_field_paths() -> frozenset[str]:
    """Return reviewed dotted field paths and their non-domain prefixes."""
    paths = {
        "dns.question.name", "event.dataset", "event.module", "host.name",
        "network.community_id", "process.name", "rule.id", "rule.name",
        "rule.uuid", "suricata.flags", "source.ip", "destination.ip", "user.name",
    }
    for pack in INVESTIGATION_QUERY_PACK_DEFINITIONS.values():
        for field in pack.get("fields", []):
            parts = str(field).lower().split(".")
            paths.update(
                ".".join(parts[:length])
                for length in range(2, len(parts) + 1)
            )
    return frozenset(paths)


REVIEW_KNOWN_FIELD_PATHS = _review_known_field_paths()
REVIEW_TAXONOMY_FIELD_PATHS = frozenset(
    {
        "data_stream_dataset",
        "data_stream_type",
        "event_dataset",
        "event_module",
    }
)
REVIEW_ARTIFACT_FIELD_PATHS = frozenset(
    {
        "command",
        "executable",
        "path",
        "process_command_line",
        "process_executable",
        "process_path",
        "script",
    }
)
REVIEW_ARTIFACT_SUFFIXES = frozenset({"sh"})
REVIEW_RULE_LABEL_FIELD_PATHS = frozenset(
    {
        "alert_signature",
        "rule_name",
        "signature",
    }
)

INVESTIGATION_PARAMETER_KEYS = {
    "elastic": frozenset({
        "pack", "window", "observables", "event_tuple", "size", "aggregation",
    }),
    "oql": frozenset({
        "pack", "window", "observables", "event_tuple", "size", "aggregation",
    }),
    "osquery": frozenset({"target_alias", "query"}),
    "pcap_zeek": frozenset({"operation", "filters", "indicator", "limit"}),
    "enrichment": frozenset({"indicator_type", "indicator"}),
}

TRUSTED_QUERY_AUDIT_FIELDS = frozenset(
    {
        "query_id", "dialect", "backend", "pack", "purpose", "aggregation",
        "window", "observables", "observable_provenance", "event_tuple",
        "event_tuple_provenance", "requested_size", "match_semantics",
        "anchor_time", "result_coverage", "execution_backend", "semantics",
        "index_scope", "query_endpoint", "endpoint", "query_dsl", "query",
        "query_digest", "result_digest", "execution_digest", "request_digest",
        "item_digest", "kql_equivalent", "kql_digest", "oql_equivalent",
        "oql_digest", "target_alias", "operation", "filters", "indicator",
        "limit", "status", "semantic_valid", "total_hits", "returned_hits",
        "total_rows", "returned_rows", "candidate_records_scanned",
        "unique_records_matched", "records_returned", "truncated",
        "result_truncated", "index_scan_truncated", "derived_views_considered",
        "duration_ms", "timed_out", "took_ms", "shards", "error",
        "evidence_summary", "evidence_ref",
    }
)

INVESTIGATION_QUERY_NONEXECUTION_STATUSES = frozenset(
    {"rejected", "denied", "blocked", "unauthorized", "forbidden"}
)

STRUCTURED_ENUMS: dict[str, list[str]] = {
    "event_status": sorted(EVENT_STATUS_VALUES),
    "detection_validity": sorted(DETECTION_VALIDITY_VALUES),
    "activity_disposition": sorted(ACTIVITY_DISPOSITION_VALUES),
    "handling": sorted(HANDLING_VALUES),
    "detection_outcome": sorted(DETECTION_OUTCOME_VALUES),
    "confidence": sorted(CONFIDENCE_VALUES),
    "tuning_recommendation": sorted(TUNING_VALUES),
    "scope": ["agent", "shared"],
    "status": ["supported", "contradicted", "unresolved"],
    "kind": sorted(REVIEW_OBSERVABLE_KINDS),
}
STRUCTURED_BOOLEAN_KEYS = frozenset(
    {
        "escalation_needed",
        "hosted_second_opinion_recommended",
        "second_opinion_recommended",
        "correlation_found",
    }
)

__all__ = tuple(name for name in globals() if name.isupper())
