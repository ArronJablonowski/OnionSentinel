"""Per-line TShark evidence classification and bounded aggregation."""
from __future__ import annotations

from typing import Any

from pcap_processor_tshark_contract import FIELD_NAMES
from pcap_processor_tshark_state import TsharkState


def _parse_row(
    line: str,
    state: TsharkState,
    file_coverage: Any,
    dependencies: dict[str, Any],
) -> dict[str, str] | None:
    try:
        values = next(dependencies["csv"].reader([line], delimiter="\t", quotechar='"'))
    except (dependencies["csv"].Error, StopIteration):
        file_coverage.malformed_records += 1
        state.coverage.malformed_records += 1
        return None
    values.extend([""] * max(0, len(FIELD_NAMES) - len(values)))
    return dict(zip(FIELD_NAMES, values[: len(FIELD_NAMES)]))


def _transport_fields(row: dict[str, str]) -> tuple[str, str, str, str, str]:
    source = row["ipv4_src"] or row["ipv6_src"]
    destination = row["ipv4_dst"] or row["ipv6_dst"]
    source_port = row["tcp_srcport"] or row["udp_srcport"]
    destination_port = row["tcp_dstport"] or row["udp_dstport"]
    if row["tcp_srcport"] or row["tcp_dstport"]:
        transport = "tcp"
    elif row["udp_srcport"] or row["udp_dstport"]:
        transport = "udp"
    else:
        transport = ""
    return source, destination, source_port, destination_port, transport


def _observe_base(
    row: dict[str, str],
    state: TsharkState,
    file_coverage: Any,
    dependencies: dict[str, Any],
) -> tuple[str, str, str, str, str]:
    values = _transport_fields(row)
    source, destination, source_port, destination_port, transport = values
    decoded = bool(row["protocol"])
    file_coverage.observe(
        timestamp=row["timestamp_epoch"],
        length=row["frame_length"],
        decoded=decoded,
    )
    state.coverage.observe(
        timestamp=row["timestamp_epoch"],
        length=row["frame_length"],
        decoded=decoded,
    )
    state.protocols.add((row["protocol"],))
    state.conversations.add(
        (source, destination, source_port, destination_port, transport, row["protocol"])
    )
    source_public = dependencies["public_ip"](source)
    destination_public = dependencies["public_ip"](destination)
    if source_public:
        state.geoip_candidates.add((source_public, "source"))
    if destination_public:
        state.geoip_candidates.add((destination_public, "destination"))
    return values


def _observe_dns(
    row: dict[str, str],
    state: TsharkState,
    dependencies: dict[str, Any],
) -> tuple[list[str], list[str], list[str], list[tuple[str, str]]]:
    query_values, query_types, rcodes, answers = _dns_values(row, dependencies)
    protocol_is_dns = row["protocol"].upper() in {"DNS", "MDNS", "LLMNR", "NBNS"}
    if query_values or answers or row["dns_query_type"] or row["dns_rcode"] or protocol_is_dns:
        state.dns_packet_count += 1
    for value in query_values:
        state.dns_query_count += 1
        state.dns_queries.add((value,))
    for value in query_types:
        state.dns_query_types.add((value,))
    for value in rcodes:
        state.dns_rcodes.add((value,))
    for answer_type, value in answers:
        _observe_dns_answer(answer_type, value, state, dependencies)
    return query_values, query_types, rcodes, answers


def _dns_values(
    row: dict[str, str],
    dependencies: dict[str, Any],
) -> tuple[list[str], list[str], list[str], list[tuple[str, str]]]:
    occurrences = dependencies["tshark_occurrences"]
    return (
        occurrences(row["dns_query"]),
        occurrences(row["dns_query_type"]),
        occurrences(row["dns_rcode"]),
        [("A", value) for value in occurrences(row["dns_answer_ipv4"])]
        + [("AAAA", value) for value in occurrences(row["dns_answer_ipv6"])]
        + [("CNAME", value) for value in occurrences(row["dns_cname"])],
    )


def _observe_dns_answer(
    answer_type: str,
    value: str,
    state: TsharkState,
    dependencies: dict[str, Any],
) -> None:
    state.dns_answer_count += 1
    state.dns_answers.add((answer_type, value))
    address = dependencies["public_ip"](value)
    if address:
        state.geoip_candidates.add((address, "dns_answer"))


def _observe_user_agents(
    row: dict[str, str],
    state: TsharkState,
    occurrences: Any,
) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    sources = (("http/1", row["http_user_agent"]), ("http/2", row["http2_user_agent"]))
    for source_field, raw_values in sources:
        for value in occurrences(raw_values):
            state.user_agent_count += 1
            state.user_agents.add((source_field, value))
            facts.append({"http_version": source_field, "user_agent": value})
    return facts


def _observe_tls_versions(
    row: dict[str, str],
    state: TsharkState,
    dependencies: dict[str, Any],
) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    sources = (
        ("handshake", row["tls_handshake_version"]),
        ("supported", row["tls_supported_version"]),
        ("record", row["tls_record_version"]),
    )
    for version_source, raw_versions in sources:
        for value in dependencies["tshark_occurrences"](raw_versions):
            raw_version, version_name = dependencies["tls_version_name"](value)
            if not raw_version:
                continue
            state.tls_version_observation_count += 1
            state.tls_versions.add((version_source, raw_version, version_name))
            facts.append(
                {
                    "version_source": version_source,
                    "raw_version": raw_version,
                    "version": version_name,
                }
            )
    return facts


def _icmp_identity(row: dict[str, str]) -> tuple[str, str, str, str, str]:
    if row["icmpv6_type"] or row["icmpv6_code"]:
        family = "icmpv6"
    elif row["icmp_type"] or row["icmp_code"]:
        family = "icmp"
    else:
        return "", "", "", "", ""
    packet_type = row["icmpv6_type"] if family == "icmpv6" else row["icmp_type"]
    code = row["icmpv6_code"] if family == "icmpv6" else row["icmp_code"]
    return family, packet_type, code, row["icmp_identifier"], row["icmp_sequence"]


def _float_or_none(value: object) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _nonnegative_int(value: object, fallback: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return fallback


def _payload_bytes(row: dict[str, str], dependencies: dict[str, Any]) -> bytes:
    occurrences = dependencies["tshark_occurrences"]
    value = next(iter(occurrences(row["data_payload"])), str(row["data_payload"] or ""))
    payload_hex = dependencies["re"].sub(r"[^0-9A-Fa-f]", "", value)
    try:
        return bytes.fromhex(payload_hex) if payload_hex and len(payload_hex) % 2 == 0 else b""
    except ValueError:
        return b""


def _payload_length(
    row: dict[str, str],
    payload: bytes,
    dependencies: dict[str, Any],
) -> int:
    value = next(
        iter(dependencies["tshark_occurrences"](row["data_length"])),
        str(row["data_length"] or ""),
    )
    return _nonnegative_int(value or len(payload), len(payload))


def _observe_markers(payload: bytes, state: TsharkState) -> None:
    for marker, decoded_marker in state.marker_values:
        marker_id = str(marker["id"])
        found = False
        start = 0
        for _ in range(16):
            position = payload.find(decoded_marker, start)
            if position < 0:
                break
            state.marker_offsets[marker_id].add((position,))
            found = True
            start = position + 1
        if found:
            state.marker_packet_counts[marker_id] += 1


def _observe_pair(
    family: str,
    packet_type: str,
    identifier: str,
    sequence: str,
    source: str,
    destination: str,
    timestamp: float | None,
    state: TsharkState,
) -> None:
    if family == "icmp" and packet_type == "8" and identifier and sequence and timestamp is not None:
        _retain_request(identifier, sequence, source, destination, timestamp, state)
    elif family == "icmp" and packet_type == "0" and timestamp is not None:
        _complete_reply(identifier, sequence, source, destination, timestamp, state)


def _retain_request(
    identifier: str,
    sequence: str,
    source: str,
    destination: str,
    timestamp: float,
    state: TsharkState,
) -> None:
    if len(state.pending_icmp_requests) >= state.icmp_pair_state_limit:
        state.pending_icmp_requests.pop(next(iter(state.pending_icmp_requests)))
    state.pending_icmp_requests[(identifier, sequence, source, destination)] = timestamp


def _complete_reply(
    identifier: str,
    sequence: str,
    source: str,
    destination: str,
    timestamp: float,
    state: TsharkState,
) -> None:
    reverse_key = (identifier, sequence, destination, source)
    if reverse_key not in state.pending_icmp_requests:
        return
    latency_ms = max(
        0.0,
        (timestamp - state.pending_icmp_requests.pop(reverse_key)) * 1000.0,
    )
    state.icmp_pair_latencies.add((round(latency_ms, 3),))


def _observe_abnormal(
    row: dict[str, str],
    family: str,
    packet_type: str,
    code: str,
    source: str,
    destination: str,
    frame_bytes: int,
    state: TsharkState,
) -> None:
    if frame_bytes < state.icmp_abnormal_min_frame_bytes:
        return
    state.icmp_abnormal_count += 1
    state.icmp_anomalies.add((family, packet_type, code, source, destination, frame_bytes))
    state.icmp_anomaly_samples.add(
        {
            "frame_number": row["frame_number"],
            "timestamp_epoch": row["timestamp_epoch"],
            "family": family,
            "type": packet_type,
            "code": code,
            "source_ip": source,
            "destination_ip": destination,
            "frame_bytes": frame_bytes,
        }
    )


def _record_exclusion(exclusion: str, state: TsharkState) -> None:
    if exclusion == "endpoint":
        state.icmp_excluded_endpoint += 1
    elif exclusion == "time":
        state.icmp_excluded_time += 1
    elif exclusion == "missing_timestamp":
        state.icmp_excluded_missing_timestamp += 1


def _observe_selected_icmp(
    row: dict[str, str],
    identity: tuple[str, str, str, str, str],
    source: str,
    destination: str,
    timestamp: float | None,
    fact: dict[str, Any],
    state: TsharkState,
    dependencies: dict[str, Any],
) -> None:
    family, packet_type, code, identifier, sequence = identity
    state.icmp_packet_count += 1
    frame_bytes = _nonnegative_int(_float_or_none(row["frame_length"] or 0))
    state.icmp_max_frame_bytes = max(state.icmp_max_frame_bytes, frame_bytes)
    state.icmp_type_codes.add((family, packet_type, code))
    if identifier:
        state.icmp_identifiers.add((identifier,))
    if sequence:
        state.icmp_sequences.add((sequence,))
    payload = _payload_bytes(row, dependencies)
    payload_length = _payload_length(row, payload, dependencies)
    fact["icmp_payload_length"] = payload_length
    if payload_length:
        state.icmp_payload_lengths.add((payload_length,))
    _observe_markers(payload, state)
    _observe_pair(
        family, packet_type, identifier, sequence, source, destination, timestamp, state
    )
    _observe_abnormal(
        row, family, packet_type, code, source, destination, frame_bytes, state
    )


def _observe_icmp(
    row: dict[str, str],
    source: str,
    destination: str,
    state: TsharkState,
    dependencies: dict[str, Any],
) -> dict[str, Any]:
    identity = _icmp_identity(row)
    family, packet_type, code, identifier, sequence = identity
    if not family:
        return {}
    timestamp = _float_or_none(row["timestamp_epoch"])
    raw_length = next(
        iter(dependencies["tshark_occurrences"](row["data_length"])), "0"
    ) or 0
    safe_payload_length = _nonnegative_int(raw_length)
    state.capture_icmp_packet_count += 1
    selected, exclusion = dependencies["icmp_scope_match"](
        source, destination, timestamp, state.scope
    )
    fact = {
        "icmp_family": family,
        "icmp_type": packet_type,
        "icmp_code": code,
        "icmp_identifier": identifier,
        "icmp_sequence": sequence,
        "icmp_payload_length": safe_payload_length,
        "selected_scope_match": selected,
        "scope_exclusion_reason": exclusion,
    }
    if not selected:
        _record_exclusion(exclusion, state)
    else:
        _observe_selected_icmp(
            row, identity, source, destination, timestamp, fact, state, dependencies
        )
    return fact


def _packet_fact(
    row: dict[str, str],
    transport: tuple[str, str, str, str, str],
    dns: tuple[list[str], list[str], list[str], list[tuple[str, str]]],
    tls_sni: list[str],
    tls_versions: list[dict[str, str]],
    http_host: list[str],
    http_uri: list[str],
    user_agents: list[dict[str, str]],
    icmp_fact: dict[str, Any],
) -> dict[str, Any]:
    source, destination, source_port, destination_port, transport_name = transport
    queries, query_types, rcodes, answers = dns
    return {
        "source": "tshark",
        "record_type": "packet",
        "frame_number": row["frame_number"],
        "timestamp_epoch": row["timestamp_epoch"],
        "frame_length": row["frame_length"],
        "protocol": row["protocol"],
        "source_ip": source,
        "destination_ip": destination,
        "source_port": source_port,
        "destination_port": destination_port,
        "transport": transport_name,
        "dns_query": queries[0] if queries else "",
        "dns_queries": queries,
        "dns_qtypes": query_types,
        "dns_rcodes": rcodes,
        "dns_answers": [
            {"answer_type": answer_type, "answer": value}
            for answer_type, value in answers
        ],
        "tls_sni": tls_sni[0] if tls_sni else "",
        "tls_versions": tls_versions,
        "http_host": http_host[0] if http_host else "",
        "http_uri": http_uri[0] if http_uri else "",
        "http_user_agents": user_agents,
        **icmp_fact,
    }


def _index_protocol_facts(
    row: dict[str, str],
    fact: dict[str, Any],
    dns: tuple[list[str], list[str], list[str], list[tuple[str, str]]],
    tls_sni: list[str],
    tls_versions: list[dict[str, str]],
    http_host: list[str],
    http_uri: list[str],
    user_agents: list[dict[str, str]],
    icmp_fact: dict[str, Any],
    state: TsharkState,
) -> None:
    _index_dns_fact(dns, fact, state)
    _index_tls_fact(row, tls_sni, tls_versions, fact, state)
    _index_http_fact(row, http_host, http_uri, user_agents, fact, state)
    if icmp_fact:
        state.icmp_fact_samples.add({**fact, "record_type": "icmp"})


def _index_dns_fact(
    dns: tuple[list[str], list[str], list[str], list[tuple[str, str]]],
    fact: dict[str, Any],
    state: TsharkState,
) -> None:
    queries, query_types, rcodes, answers = dns
    if queries or answers or query_types or rcodes:
        state.dns_record_samples.add({**fact, "record_type": "dns"})


def _index_tls_fact(
    row: dict[str, str],
    tls_sni: list[str],
    tls_versions: list[dict[str, str]],
    fact: dict[str, Any],
    state: TsharkState,
) -> None:
    if tls_sni or tls_versions or row["protocol"].upper().startswith(("TLS", "SSL")):
        state.tls_record_samples.add({**fact, "record_type": "tls"})


def _index_http_fact(
    row: dict[str, str],
    http_host: list[str],
    http_uri: list[str],
    user_agents: list[dict[str, str]],
    fact: dict[str, Any],
    state: TsharkState,
) -> None:
    if http_host or http_uri or user_agents or row["protocol"].upper().startswith("HTTP"):
        state.http_record_samples.add({**fact, "record_type": "http"})


def parse_tshark_line(
    line: str,
    file_coverage: Any,
    state: TsharkState,
    dependencies: dict[str, Any],
) -> None:
    """Classify one bounded field-stream line and retain only safe facts."""
    row = _parse_row(line, state, file_coverage, dependencies)
    if row is None:
        return
    transport = _observe_base(row, state, file_coverage, dependencies)
    dns = _observe_dns(row, state, dependencies)
    occurrences = dependencies["tshark_occurrences"]
    user_agents = _observe_user_agents(row, state, occurrences)
    tls_versions = _observe_tls_versions(row, state, dependencies)
    tls_sni = occurrences(row["tls_sni"])
    http_host = occurrences(row["http_host"])
    http_uri = occurrences(row["http_uri"])
    icmp_fact = _observe_icmp(row, transport[0], transport[1], state, dependencies)
    fact = _packet_fact(
        row,
        transport,
        dns,
        tls_sni,
        tls_versions,
        http_host,
        http_uri,
        user_agents,
        icmp_fact,
    )
    state.reservoir.add(fact)
    _index_protocol_facts(
        row,
        fact,
        dns,
        tls_sni,
        tls_versions,
        http_host,
        http_uri,
        user_agents,
        icmp_fact,
        state,
    )
