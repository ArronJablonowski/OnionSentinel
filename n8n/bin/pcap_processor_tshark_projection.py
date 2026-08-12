"""Provenance-safe public TShark evidence projection."""
from __future__ import annotations

from typing import Any

from pcap_processor_tshark_state import TsharkState


def _association(state: TsharkState) -> str:
    if state.endpoint_pair_complete and state.time_filter_applied:
        return "selected-alert-endpoints-and-request-window"
    if state.endpoint_filter_applied or state.time_filter_applied:
        return "partially-filtered-selected-alert-candidate"
    return "capture-wide-not-attributed-to-selected-alert"


def _icmp_provenance(
    state: TsharkState,
    sanitize: Any,
) -> dict[str, Any]:
    filtered = state.endpoint_filter_applied or state.time_filter_applied
    return {
        "association": _association(state),
        "association_is_proof": False,
        "caution": (
            "Endpoint/time filtering produces candidate evidence for the selected alert, not proof that every retained packet caused it."
            if filtered
            else "No selected endpoint/time filters were available; ICMP findings describe the entire capture and must not be attributed to one alert."
        ),
        "selected_alert_id": sanitize(state.scope.get("selected_alert_id"), 256),
        "endpoint_filter": {
            "applied": state.endpoint_filter_applied,
            "pair_complete": state.endpoint_pair_complete,
            "direction": "bidirectional",
            "source_ip": (
                state.scope.get("source_ip") if state.endpoint_filter_applied else ""
            ),
            "destination_ip": (
                state.scope.get("destination_ip") if state.endpoint_filter_applied else ""
            ),
        },
        "time_filter": {
            "applied": state.time_filter_applied,
            "basis": str(state.scope.get("window_basis") or "unavailable")[:80],
            "window_start_epoch": (
                state.scope.get("window_start_epoch") if state.time_filter_applied else None
            ),
            "window_end_epoch": (
                state.scope.get("window_end_epoch") if state.time_filter_applied else None
            ),
        },
        "capture_icmp_packets_observed": state.capture_icmp_packet_count,
        "retained_icmp_packets": state.icmp_packet_count,
        "excluded_by_endpoint": state.icmp_excluded_endpoint,
        "excluded_by_time": state.icmp_excluded_time,
        "excluded_missing_timestamp": state.icmp_excluded_missing_timestamp,
    }


def _marker_offset(marker: dict[str, Any]) -> int | None:
    raw = marker.get("expected_offset")
    try:
        return int(raw) if raw not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _printable_marker(decoded: bytes, sanitize: Any) -> str:
    value = "".join(chr(item) if 32 <= item <= 126 else "." for item in decoded)
    return sanitize(value, 80)


def _marker_summary(
    marker: dict[str, Any],
    decoded: bytes,
    state: TsharkState,
    dependencies: dict[str, Any],
) -> dict[str, Any]:
    marker_id = str(marker["id"])
    expected_offset = _marker_offset(marker)
    offsets = state.marker_offsets[marker_id].most_common(("offset",), 128)
    expected_count = (
        sum(
            int(item.get("count") or 0)
            for item in offsets
            if item.get("offset") is not None and int(item["offset"]) == expected_offset
        )
        if expected_offset is not None
        else None
    )
    return {
        "id": marker_id,
        "source": marker.get("source"),
        "sha256": dependencies["hashlib"].sha256(decoded).hexdigest(),
        "length": len(decoded),
        "printable": _printable_marker(decoded, dependencies["sanitize_evidence_text"]),
        "expected_offset": expected_offset,
        "packets_with_marker": int(state.marker_packet_counts[marker_id]),
        "observations": sum(int(item.get("count") or 0) for item in offsets),
        "expected_offset_observations": expected_count,
        "offsets": offsets,
    }


def _icmp_semantics(
    state: TsharkState,
    provenance: dict[str, Any],
    marker_summaries: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "raw_payloads_included": False,
        "provenance": provenance,
        "type_code_counts": state.icmp_type_codes.most_common(
            ("family", "type", "code"), 128
        ),
        "identifiers": state.icmp_identifiers.most_common(
            ("identifier",), state.summary_limit
        ),
        "sequences": state.icmp_sequences.most_common(
            ("sequence",), state.summary_limit
        ),
        "payload_lengths": state.icmp_payload_lengths.most_common(
            ("payload_bytes",), state.summary_limit
        ),
        "request_reply_pairs": sum(
            int(item.get("count") or 0)
            for item in state.icmp_pair_latencies.most_common(
                ("latency_ms",), state.heavy_hitter_capacity
            )
        ),
        "reply_latency_ms": state.icmp_pair_latencies.most_common(
            ("latency_ms",), state.summary_limit
        ),
        "unmatched_requests_retained": len(state.pending_icmp_requests),
        "markers": marker_summaries,
    }


def _icmp_size_review(
    state: TsharkState,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    return {
        "classification": "suspicious-size-review-signal-not-a-c2-verdict",
        "provenance": provenance,
        "abnormal_frame_threshold_bytes": state.icmp_abnormal_min_frame_bytes,
        "icmp_packets_observed": state.icmp_packet_count,
        "abnormal_packets_observed": state.icmp_abnormal_count,
        "maximum_frame_bytes": state.icmp_max_frame_bytes,
        "top_abnormal_flows": state.icmp_anomalies.most_common(
            ("family", "type", "code", "source_ip", "destination_ip", "frame_bytes"),
            state.summary_limit,
        ),
        "representative_samples": state.icmp_anomaly_samples.records(),
    }


def _field_sample_tsv(
    packet_samples: list[dict[str, Any]],
    sanitize: Any,
) -> str:
    header = "\t".join(
        (
            "frame_number", "timestamp_epoch", "source_ip", "destination_ip",
            "source_port", "destination_port", "transport", "protocol",
            "frame_length", "dns_query", "tls_sni", "http_host", "http_uri",
        )
    )
    rows = [
        "\t".join(sanitize(record.get(key), 256) for key in header.split("\t"))
        for record in packet_samples
    ]
    return "\n".join([header] + rows)


def _activity_summaries(state: TsharkState) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    dns = {
        "packets_observed": state.dns_packet_count,
        "query_observations": state.dns_query_count,
        "answer_observations": state.dns_answer_count,
        "query_names": state.dns_queries.most_common(("query",), state.summary_limit),
        "query_types": state.dns_query_types.most_common(("type",), state.summary_limit),
        "response_codes": state.dns_rcodes.most_common(("rcode",), state.summary_limit),
        "answers": state.dns_answers.most_common(
            ("answer_type", "answer"), state.summary_limit
        ),
    }
    agents = {
        "observations": state.user_agent_count,
        "values": state.user_agents.most_common(
            ("http_version", "user_agent"), state.summary_limit
        ),
    }
    tls = {
        "observations": state.tls_version_observation_count,
        "versions": state.tls_versions.most_common(
            ("source", "raw_version", "version"), state.summary_limit
        ),
    }
    return dns, agents, tls


def _local_query_index(
    state: TsharkState,
    packet_samples: list[dict[str, Any]],
    icmp_semantics: dict[str, Any],
    geoip: dict[str, Any],
) -> dict[str, Any]:
    limit = state.query_index_limit
    return {
        "connections": state.conversations.most_common(
            ("source_ip", "destination_ip", "source_port", "destination_port", "transport", "protocol"),
            limit,
        ),
        "protocols": state.protocols.most_common(("protocol",), limit),
        "packet_samples": packet_samples,
        "packet_facts": packet_samples,
        "dns": state.dns_queries.most_common(("query",), limit),
        "dns_records": state.dns_record_samples.records(),
        "tls_records": state.tls_record_samples.records(),
        "http_records": state.http_record_samples.records(),
        "user_agents": state.user_agents.most_common(("http_version", "user_agent"), limit),
        "tls_versions": state.tls_versions.most_common(
            ("source", "raw_version", "version"), limit
        ),
        "icmp_anomalies": state.icmp_anomalies.most_common(
            ("family", "type", "code", "source_ip", "destination_ip", "frame_bytes"),
            limit,
        ),
        "icmp_facts": state.icmp_fact_samples.records(),
        "icmp_semantics": icmp_semantics,
        "geoip": geoip.get("records", [])[:limit],
    }


def project_tshark_result(
    pcap_files: list[Any],
    maxmind_db_paths: object,
    state: TsharkState,
    dependencies: dict[str, Any],
) -> dict[str, Any]:
    """Build the exact bounded public and local-query evidence projection."""
    packet_samples = state.reservoir.records()
    top_protocols = state.protocols.most_common(("protocol",), state.summary_limit)
    top_conversations = state.conversations.most_common(
        ("source_ip", "destination_ip", "source_port", "destination_port", "transport", "protocol"),
        state.summary_limit,
    )
    dns_activity, http_user_agents, tls_versions = _activity_summaries(state)
    provenance = _icmp_provenance(state, dependencies["sanitize_evidence_text"])
    marker_summaries = [
        _marker_summary(marker, decoded, state, dependencies)
        for marker, decoded in state.marker_values
    ]
    icmp_semantics = _icmp_semantics(state, provenance, marker_summaries)
    icmp_size_review = _icmp_size_review(state, provenance)
    paths = maxmind_db_paths or dependencies["configured_maxmind_db_paths"]()
    geoip = dependencies["maxmind_geoip_summary"](state.geoip_candidates, paths)
    field_sample_tsv = _field_sample_tsv(
        packet_samples, dependencies["sanitize_evidence_text"]
    )
    return {
        "available": True,
        "commands": state.commands,
        "coverage": _coverage_projection(pcap_files, state),
        "sampling": _sampling_projection(packet_samples, state),
        "protocol_counts": top_protocols,
        "top_conversations": top_conversations,
        "dns_activity": dns_activity,
        "http_user_agents": http_user_agents,
        "tls_versions": tls_versions,
        "icmp_size_review": icmp_size_review,
        "icmp_semantics": icmp_semantics,
        "geoip": geoip,
        "packet_samples": packet_samples,
        "_local_query_index": _local_query_index(
            state, packet_samples, icmp_semantics, geoip
        ),
        "samples": _sample_projection(
            top_protocols,
            top_conversations,
            field_sample_tsv,
            dependencies["json"],
        ),
    }


def _coverage_projection(pcap_files: list[Any], state: TsharkState) -> dict[str, Any]:
    return {
        **state.coverage.as_dict(),
        "pcap_files_total": len(pcap_files),
        "pcap_files_processed": state.files_processed,
        "complete": (
            state.files_processed == len(pcap_files)
            and all(item.get("ok") for item in state.commands)
        ),
        "per_file": state.per_file,
    }


def _sampling_projection(
    packet_samples: list[dict[str, Any]],
    state: TsharkState,
) -> dict[str, Any]:
    return {
        "strategy": "deterministic-reservoir-over-full-stream",
        "sample_limit": state.sample_limit,
        "packets_seen": state.reservoir.seen,
        "packets_sampled": len(packet_samples),
        "query_index_strategy": "deterministic-protocol-reservoirs",
        "query_index_limit_per_protocol": state.query_index_limit,
        "query_index_records": {
            "dns": len(state.dns_record_samples.records()),
            "tls": len(state.tls_record_samples.records()),
            "http": len(state.http_record_samples.records()),
            "icmp": len(state.icmp_fact_samples.records()),
        },
    }


def _sample_projection(
    protocols: list[dict[str, Any]],
    conversations: list[dict[str, Any]],
    field_sample_tsv: str,
    json_module: Any,
) -> list[dict[str, Any]]:
    return [
        {
            "pcap": "all-capture-files",
            "protocol_hierarchy": json_module.dumps(protocols, indent=2, sort_keys=True),
            "conversations": json_module.dumps(conversations, indent=2, sort_keys=True),
            "field_sample_tsv": field_sample_tsv[:12000],
        }
    ]
