"""Bounded group packet feature aggregation and evidence projection."""
from __future__ import annotations

from detection_validation_rule import *  # noqa: F401,F403
from detection_validation_rule import (  # noqa: F401
    _icmp_from_packet,
    _json_object,
    _nested,
    _row_value,
)
from detection_validation_packet import *  # noqa: F401,F403
from detection_validation_packet import (  # noqa: F401
    _bounded_application_buffers,
    _bounded_counter,
    _bounded_text_counter,
    _content_constraint,
    _content_evaluation_supported,
    _entropy,
    _network_packet_envelope,
    _ordered_deployed_content_constraints,
    _stun_binding_semantics,
    _udp_from_packet,
)
def extract_group_packet_features(
    grouped_rows: Iterable[object],
    markers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Decode stored packet copies and return bounded, raw-payload-free semantics."""
    marker_values: list[tuple[dict[str, Any], bytes]] = []
    for item in markers or []:
        try:
            decoded = bytes.fromhex(str(item.get("hex") or ""))
        except ValueError:
            continue
        if decoded:
            marker_values.append((item, decoded))
    type_counts: collections.Counter[int] = collections.Counter()
    code_counts: collections.Counter[int] = collections.Counter()
    identifiers: collections.Counter[int] = collections.Counter()
    sequences: collections.Counter[int] = collections.Counter()
    payload_lengths: collections.Counter[int] = collections.Counter()
    frame_lengths: collections.Counter[int] = collections.Counter()
    marker_offsets: dict[str, collections.Counter[int]] = {
        str(item["id"]): collections.Counter() for item, _ in marker_values
    }
    marker_packets: collections.Counter[str] = collections.Counter()
    marker_constraint_evaluated: collections.Counter[str] = collections.Counter()
    marker_constraint_satisfied: collections.Counter[str] = collections.Counter()
    marker_constraint_violated: collections.Counter[str] = collections.Counter()
    marker_constraint_unsupported: set[str] = set()
    entropies: list[float] = []
    parsed_packet_count = 0
    content_packet_count = 0
    icmp_packet_count = 0
    udp_packet_count = 0
    unsupported_protocol_packets = 0
    protocol_counts: collections.Counter[str] = collections.Counter()
    udp_payload_lengths: collections.Counter[int] = collections.Counter()
    stun_kinds: collections.Counter[str] = collections.Counter()
    stun_body_lengths: collections.Counter[int] = collections.Counter()
    candidate_count = 0
    parse_errors = 0
    truncated = False

    def observe_content(
        payload: bytes,
        selected_markers: list[tuple[dict[str, Any], bytes]],
        *,
        application_buffer: str | None = None,
    ) -> bool:
        if not selected_markers:
            return False
        ordered_constraints = _ordered_deployed_content_constraints(
            payload,
            selected_markers,
            application_buffer=application_buffer,
        )
        for spec, marker in selected_markers:
            marker_id = str(spec["id"])
            if spec.get("source") == "deployed_rule":
                constraint = ordered_constraints.get(marker_id)
            else:
                constraint = _content_constraint(payload, marker, spec)
            if constraint is None:
                marker_constraint_unsupported.add(marker_id)
            else:
                marker_constraint_evaluated[marker_id] += 1
                if constraint:
                    marker_constraint_satisfied[marker_id] += 1
                else:
                    marker_constraint_violated[marker_id] += 1
            if not _content_evaluation_supported(
                spec,
                application_buffer=application_buffer,
            ):
                continue
            modifiers = (
                spec.get("modifiers")
                if isinstance(spec.get("modifiers"), dict)
                else {}
            )
            haystack = payload.lower() if "nocase" in modifiers else payload
            needle = marker.lower() if "nocase" in modifiers else marker
            start = 0
            matches = 0
            while matches < MAX_MARKER_MATCHES_PER_PACKET:
                position = haystack.find(needle, start)
                if position < 0:
                    break
                marker_offsets[marker_id][position] += 1
                matches += 1
                start = position + 1
            if matches:
                marker_packets[marker_id] += 1
        return True

    for row in grouped_rows:
        if candidate_count >= MAX_GROUP_PACKETS:
            truncated = True
            break
        raw = _json_object(_row_value(row, "raw_event_json"))
        alert = _json_object(_row_value(row, "alert_json"))
        if not raw:
            raw = _json_object(_nested(alert, "security_onion.raw_event"))
        message = _json_object(raw.get("message"))
        application_buffers = _bounded_application_buffers(
            raw,
            message,
            alert,
            marker_values,
        )
        packet_text = str(message.get("packet") or "").strip()
        if not packet_text:
            continue
        candidate_count += 1
        if len(packet_text) > MAX_PACKET_BASE64_CHARS:
            parse_errors += 1
            continue
        try:
            packet = base64.b64decode(packet_text, validate=True)
        except (ValueError, TypeError):
            parse_errors += 1
            continue
        try:
            linktype = int(_nested(message, "packet_info.linktype") or 1)
        except (TypeError, ValueError):
            linktype = 1
        envelope = _network_packet_envelope(packet, linktype)
        if not envelope:
            parse_errors += 1
            continue
        protocol_number = int(envelope.get("protocol_number", -1))
        protocol_name = {
            1: "icmp",
            6: "tcp",
            17: "udp",
            58: "icmpv6",
        }.get(protocol_number, f"ip_protocol_{protocol_number}")
        protocol_counts[protocol_name] += 1
        row_has_content = False
        for buffer_name, buffer_payload in application_buffers.items():
            selected = [
                (spec, marker)
                for spec, marker in marker_values
                if str(spec.get("buffer") or "").strip().lower()
                == buffer_name
            ]
            row_has_content = (
                observe_content(
                    buffer_payload,
                    selected,
                    application_buffer=buffer_name,
                )
                or row_has_content
            )
        if protocol_number in {1, 58}:
            parsed = _icmp_from_packet(packet, linktype)
            if not parsed:
                parse_errors += 1
                continue
            parsed_packet_count += 1
            icmp_packet_count += 1
            payload = parsed.pop("_payload")
            type_counts[parsed["type"]] += 1
            code_counts[parsed["code"]] += 1
            identifiers[parsed["identifier"]] += 1
            sequences[parsed["sequence"]] += 1
            payload_lengths[len(payload)] += 1
            frame_lengths[parsed["frame_bytes"]] += 1
            entropies.append(_entropy(payload))
        elif protocol_number == 17:
            parsed = _udp_from_packet(packet, envelope)
            if not parsed:
                parse_errors += 1
                continue
            parsed_packet_count += 1
            udp_packet_count += 1
            payload = parsed.pop("_payload")
            udp_payload_lengths[len(payload)] += 1
            stun = _stun_binding_semantics(payload)
            if stun:
                stun_kinds[str(stun["kind"])] += 1
                stun_body_lengths[int(stun["declared_body_bytes"])] += 1
        else:
            # A valid, currently unsupported transport is not a parse error.
            parsed_packet_count += 1
            unsupported_protocol_packets += 1
            if row_has_content:
                content_packet_count += 1
            continue
        raw_markers = [
            (spec, marker)
            for spec, marker in marker_values
            if str(spec.get("buffer") or "").strip().lower()
            in {"", "pkt_data"}
        ]
        row_has_content = observe_content(payload, raw_markers) or row_has_content
        if row_has_content:
            content_packet_count += 1
    marker_results = []
    for spec, marker in marker_values:
        marker_id = str(spec["id"])
        expected_raw = spec.get("expected_offset")
        try:
            expected_offset = int(expected_raw) if expected_raw not in (None, "") else None
        except (TypeError, ValueError):
            expected_offset = None
        offset_counts = marker_offsets[marker_id]
        marker_results.append({
            "id": marker_id,
            "source": spec.get("source"),
            "sha256": hashlib.sha256(marker).hexdigest(),
            "length": len(marker),
            "packets_with_marker": int(marker_packets[marker_id]),
            "observations": int(sum(offset_counts.values())),
            "expected_offset": expected_offset,
            "expected_offset_observations": int(offset_counts.get(expected_offset, 0)) if expected_offset is not None else None,
            "offsets": _bounded_counter(offset_counts),
            "constraint_supported": (
                marker_id not in marker_constraint_unsupported
                and _content_evaluation_supported(
                    spec,
                    application_buffer=(
                        str(spec.get("buffer") or "").strip().lower()
                        or None
                    ),
                )
            ),
            "packets_evaluated_for_constraint": int(marker_constraint_evaluated[marker_id]),
            "packets_satisfying_constraint": int(marker_constraint_satisfied[marker_id]),
            "packets_violating_constraint": int(marker_constraint_violated[marker_id]),
        })
    return {
        "source": "stored-security-onion-alert-packet-copies",
        "application_evidence_source": (
            "stored-security-onion-suricata-application-projection"
        ),
        "raw_payloads_included": False,
        "candidate_packets": candidate_count,
        "packets_parsed": parsed_packet_count,
        "content_packets_parsed": content_packet_count,
        "packet_protocols": _bounded_text_counter(protocol_counts),
        "unsupported_protocol_packets": unsupported_protocol_packets,
        "icmp_packets_parsed": icmp_packet_count,
        "udp_packets_parsed": udp_packet_count,
        "udp_payload_lengths": _bounded_counter(udp_payload_lengths),
        "stun": {
            "packets_parsed": int(sum(stun_kinds.values())),
            "message_types": _bounded_text_counter(stun_kinds),
            "declared_body_lengths": _bounded_counter(stun_body_lengths),
            "magic_cookie_valid_packets": int(sum(stun_kinds.values())),
            "transaction_ids_included": False,
            "raw_payloads_included": False,
        },
        "parse_errors": parse_errors,
        "truncated": truncated,
        "icmp_types": _bounded_counter(type_counts),
        "icmp_codes": _bounded_counter(code_counts),
        "icmp_identifiers": _bounded_counter(identifiers),
        "icmp_sequences": _bounded_counter(sequences),
        "payload_lengths": _bounded_counter(payload_lengths),
        "frame_lengths": _bounded_counter(frame_lengths),
        "payload_entropy": {
            "minimum": round(min(entropies), 4) if entropies else None,
            "maximum": round(max(entropies), 4) if entropies else None,
            "average": round(sum(entropies) / len(entropies), 4) if entropies else None,
        },
        "markers": marker_results,
    }
