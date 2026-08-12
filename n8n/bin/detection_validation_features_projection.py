"""Raw-payload-free public projection for detection packet features."""
from __future__ import annotations

from typing import Any

from detection_validation_packet import _bounded_counter, _bounded_text_counter
from detection_validation_features_markers import marker_results
from detection_validation_features_state import FeatureState


def _entropy_projection(entropies: list[float]) -> dict[str, float | None]:
    return {
        "minimum": round(min(entropies), 4) if entropies else None,
        "maximum": round(max(entropies), 4) if entropies else None,
        "average": round(sum(entropies) / len(entropies), 4) if entropies else None,
    }


def project_features(
    marker_values: list[tuple[dict[str, Any], bytes]],
    state: FeatureState,
) -> dict[str, Any]:
    """Return the stable bounded result contract."""
    stun_packets = int(sum(state.stun_kinds.values()))
    return {
        "source": "stored-security-onion-alert-packet-copies",
        "application_evidence_source": (
            "stored-security-onion-suricata-application-projection"
        ),
        "raw_payloads_included": False,
        "candidate_packets": state.candidate_count,
        "packets_parsed": state.parsed_packet_count,
        "content_packets_parsed": state.content_packet_count,
        "packet_protocols": _bounded_text_counter(state.protocol_counts),
        "unsupported_protocol_packets": state.unsupported_protocol_packets,
        "icmp_packets_parsed": state.icmp_packet_count,
        "udp_packets_parsed": state.udp_packet_count,
        "udp_payload_lengths": _bounded_counter(state.udp_payload_lengths),
        "stun": {
            "packets_parsed": stun_packets,
            "message_types": _bounded_text_counter(state.stun_kinds),
            "declared_body_lengths": _bounded_counter(state.stun_body_lengths),
            "magic_cookie_valid_packets": stun_packets,
            "transaction_ids_included": False,
            "raw_payloads_included": False,
        },
        "parse_errors": state.parse_errors,
        "truncated": state.truncated,
        "icmp_types": _bounded_counter(state.type_counts),
        "icmp_codes": _bounded_counter(state.code_counts),
        "icmp_identifiers": _bounded_counter(state.identifiers),
        "icmp_sequences": _bounded_counter(state.sequences),
        "payload_lengths": _bounded_counter(state.payload_lengths),
        "frame_lengths": _bounded_counter(state.frame_lengths),
        "payload_entropy": _entropy_projection(state.entropies),
        "markers": marker_results(marker_values, state),
    }
