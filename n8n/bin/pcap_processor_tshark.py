"""Bounded TShark packet, protocol, GeoIP, and ICMP analysis."""
from __future__ import annotations

from pcap_processor_contract import *  # noqa: F401,F403
from pcap_processor_storage import *  # noqa: F401,F403
from pcap_processor_storage import _icmp_scope_match, _timestamp_epoch  # noqa: F401
from pcap_processor_zeek import *  # noqa: F401,F403

def run_tshark(
    pcap_files: list[Path],
    maxmind_db_paths: dict[str, Path] | Path | None = None,
    markers: list[dict[str, Any]] | None = None,
    selected_scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tshark = tool_path("TSHARK_BIN", "tshark")
    if not tshark:
        return {"available": False, "reason": "tshark executable not found on PATH or TSHARK_BIN"}
    field_names = (
        "frame_number", "timestamp_epoch", "frame_length", "protocol",
        "ipv4_src", "ipv6_src", "ipv4_dst", "ipv6_dst",
        "tcp_srcport", "tcp_dstport", "udp_srcport", "udp_dstport",
        "dns_query", "dns_query_type", "dns_rcode", "dns_answer_ipv4", "dns_answer_ipv6", "dns_cname",
        "tls_sni", "tls_handshake_version", "tls_supported_version", "tls_record_version",
        "http_host", "http_uri", "http_user_agent", "http2_user_agent",
        "icmp_type", "icmp_code", "icmpv6_type", "icmpv6_code",
        "icmp_identifier", "icmp_sequence", "data_length", "data_payload",
    )
    tshark_fields = (
        "frame.number", "frame.time_epoch", "frame.len", "_ws.col.Protocol",
        "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
        "dns.qry.name", "dns.qry.type", "dns.flags.rcode", "dns.a", "dns.aaaa", "dns.cname",
        "tls.handshake.extensions_server_name", "tls.handshake.version", "tls.handshake.extensions.supported_version", "tls.record.version",
        "http.host", "http.request.uri", "http.user_agent", "http2.headers.user_agent",
        "icmp.type", "icmp.code", "icmpv6.type", "icmpv6.code",
        "icmp.ident", "icmp.seq", "data.len", "data.data",
    )
    commands: list[dict[str, Any]] = []
    coverage = CoverageTracker()
    per_file: list[dict[str, Any]] = []
    reservoir = DeterministicReservoir(TSHARK_SAMPLE_LIMIT)
    dns_record_samples = DeterministicReservoir(QUERY_INDEX_LIMIT)
    tls_record_samples = DeterministicReservoir(QUERY_INDEX_LIMIT)
    http_record_samples = DeterministicReservoir(QUERY_INDEX_LIMIT)
    icmp_fact_samples = DeterministicReservoir(QUERY_INDEX_LIMIT)
    protocols = BoundedTopCounter(128)
    conversations = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    dns_queries = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    dns_answers = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    dns_query_types = BoundedTopCounter(128)
    dns_rcodes = BoundedTopCounter(128)
    user_agents = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    tls_versions = BoundedTopCounter(128)
    icmp_anomalies = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    icmp_anomaly_samples = DeterministicReservoir(min(TSHARK_SAMPLE_LIMIT, 100))
    icmp_type_codes = BoundedTopCounter(128)
    icmp_identifiers = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    icmp_sequences = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    icmp_payload_lengths = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    icmp_pair_latencies = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    pending_icmp_requests: dict[tuple[str, str, str, str], float] = {}
    marker_values: list[tuple[dict[str, Any], bytes]] = []
    marker_offsets: dict[str, BoundedTopCounter] = {}
    marker_packet_counts: Counter[str] = Counter()
    for marker in markers or []:
        if not isinstance(marker, dict):
            continue
        try:
            decoded_marker = bytes.fromhex(str(marker.get("hex") or ""))
        except ValueError:
            continue
        marker_id = str(marker.get("id") or "")[:100]
        if not marker_id or not decoded_marker:
            continue
        marker_values.append((marker, decoded_marker))
        marker_offsets[marker_id] = BoundedTopCounter(128)
    geoip_candidates = BoundedTopCounter(HEAVY_HITTER_CAPACITY)
    dns_packet_count = 0
    dns_query_count = 0
    dns_answer_count = 0
    user_agent_count = 0
    tls_version_observation_count = 0
    icmp_packet_count = 0
    capture_icmp_packet_count = 0
    icmp_excluded_endpoint = 0
    icmp_excluded_time = 0
    icmp_excluded_missing_timestamp = 0
    icmp_abnormal_count = 0
    icmp_max_frame_bytes = 0
    scope = selected_scope if isinstance(selected_scope, dict) else {}
    endpoint_filter_applied = bool(scope.get("source_ip") or scope.get("destination_ip"))
    endpoint_pair_complete = bool(scope.get("source_ip") and scope.get("destination_ip"))
    time_filter_applied = isinstance(scope.get("window_start_epoch"), (int, float)) and isinstance(
        scope.get("window_end_epoch"),
        (int, float),
    )
    files_processed = 0
    for pcap in pcap_files:
        file_coverage = CoverageTracker()

        def on_line(line: str) -> None:
            nonlocal dns_packet_count, dns_query_count, dns_answer_count, user_agent_count
            nonlocal tls_version_observation_count, icmp_packet_count, icmp_abnormal_count, icmp_max_frame_bytes
            nonlocal capture_icmp_packet_count, icmp_excluded_endpoint, icmp_excluded_time
            nonlocal icmp_excluded_missing_timestamp
            try:
                values = next(csv.reader([line], delimiter="\t", quotechar='"'))
            except (csv.Error, StopIteration):
                file_coverage.malformed_records += 1
                coverage.malformed_records += 1
                return
            values.extend([""] * max(0, len(field_names) - len(values)))
            row = dict(zip(field_names, values[: len(field_names)]))
            source = row["ipv4_src"] or row["ipv6_src"]
            destination = row["ipv4_dst"] or row["ipv6_dst"]
            source_port = row["tcp_srcport"] or row["udp_srcport"]
            destination_port = row["tcp_dstport"] or row["udp_dstport"]
            transport = "tcp" if row["tcp_srcport"] or row["tcp_dstport"] else "udp" if row["udp_srcport"] or row["udp_dstport"] else ""
            decoded = bool(row["protocol"])
            file_coverage.observe(timestamp=row["timestamp_epoch"], length=row["frame_length"], decoded=decoded)
            coverage.observe(timestamp=row["timestamp_epoch"], length=row["frame_length"], decoded=decoded)
            protocols.add((row["protocol"],))
            conversations.add((source, destination, source_port, destination_port, transport, row["protocol"]))
            source_public = public_ip(source)
            destination_public = public_ip(destination)
            if source_public:
                geoip_candidates.add((source_public, "source"))
            if destination_public:
                geoip_candidates.add((destination_public, "destination"))
            query_values = tshark_occurrences(row["dns_query"])
            query_type_values = tshark_occurrences(row["dns_query_type"])
            rcode_values = tshark_occurrences(row["dns_rcode"])
            answer_values = (
                [("A", value) for value in tshark_occurrences(row["dns_answer_ipv4"])]
                + [("AAAA", value) for value in tshark_occurrences(row["dns_answer_ipv6"])]
                + [("CNAME", value) for value in tshark_occurrences(row["dns_cname"])]
            )
            if query_values or answer_values or row["dns_query_type"] or row["dns_rcode"] or row["protocol"].upper() in {"DNS", "MDNS", "LLMNR", "NBNS"}:
                dns_packet_count += 1
            for value in query_values:
                dns_query_count += 1
                dns_queries.add((value,))
            for value in query_type_values:
                dns_query_types.add((value,))
            for value in rcode_values:
                dns_rcodes.add((value,))
            for answer_type, value in answer_values:
                dns_answer_count += 1
                dns_answers.add((answer_type, value))
                address = public_ip(value)
                if address:
                    geoip_candidates.add((address, "dns_answer"))
            user_agent_facts: list[dict[str, str]] = []
            for source_field, raw_user_agents in (("http/1", row["http_user_agent"]), ("http/2", row["http2_user_agent"])):
                for raw_user_agent in tshark_occurrences(raw_user_agents):
                    user_agent_count += 1
                    user_agents.add((source_field, raw_user_agent))
                    user_agent_facts.append({
                        "http_version": source_field,
                        "user_agent": raw_user_agent,
                    })
            tls_version_facts: list[dict[str, str]] = []
            for version_source, raw_versions in (
                ("handshake", row["tls_handshake_version"]),
                ("supported", row["tls_supported_version"]),
                ("record", row["tls_record_version"]),
            ):
                for value in tshark_occurrences(raw_versions):
                    raw_version, version_name = tls_version_name(value)
                    if raw_version:
                        tls_version_observation_count += 1
                        tls_versions.add((version_source, raw_version, version_name))
                        tls_version_facts.append({
                            "version_source": version_source,
                            "raw_version": raw_version,
                            "version": version_name,
                        })
            tls_sni_values = tshark_occurrences(row["tls_sni"])
            http_host_values = tshark_occurrences(row["http_host"])
            http_uri_values = tshark_occurrences(row["http_uri"])
            icmp_family = "icmpv6" if row["icmpv6_type"] or row["icmpv6_code"] else "icmp" if row["icmp_type"] or row["icmp_code"] else ""
            icmp_fact: dict[str, Any] = {}
            if icmp_family:
                try:
                    packet_timestamp = float(row["timestamp_epoch"])
                except (TypeError, ValueError):
                    packet_timestamp = None
                icmp_type = row["icmpv6_type"] if icmp_family == "icmpv6" else row["icmp_type"]
                icmp_code = row["icmpv6_code"] if icmp_family == "icmpv6" else row["icmp_code"]
                identifier = row["icmp_identifier"]
                sequence = row["icmp_sequence"]
                try:
                    safe_payload_length = max(
                        0,
                        int(next(iter(tshark_occurrences(row["data_length"])), "0") or 0),
                    )
                except (TypeError, ValueError):
                    safe_payload_length = 0
                capture_icmp_packet_count += 1
                selected, exclusion = _icmp_scope_match(
                    source,
                    destination,
                    packet_timestamp,
                    scope,
                )
                icmp_fact = {
                    "icmp_family": icmp_family,
                    "icmp_type": icmp_type,
                    "icmp_code": icmp_code,
                    "icmp_identifier": identifier,
                    "icmp_sequence": sequence,
                    "icmp_payload_length": safe_payload_length,
                    "selected_scope_match": selected,
                    "scope_exclusion_reason": exclusion,
                }
                if not selected:
                    if exclusion == "endpoint":
                        icmp_excluded_endpoint += 1
                    elif exclusion == "time":
                        icmp_excluded_time += 1
                    elif exclusion == "missing_timestamp":
                        icmp_excluded_missing_timestamp += 1
                else:
                    icmp_packet_count += 1
                    try:
                        frame_bytes = max(0, int(float(row["frame_length"] or 0)))
                    except (TypeError, ValueError):
                        frame_bytes = 0
                    icmp_max_frame_bytes = max(icmp_max_frame_bytes, frame_bytes)
                    icmp_type_codes.add((icmp_family, icmp_type, icmp_code))
                    if identifier:
                        icmp_identifiers.add((identifier,))
                    if sequence:
                        icmp_sequences.add((sequence,))
                    payload_value = next(
                        iter(tshark_occurrences(row["data_payload"])),
                        str(row["data_payload"] or ""),
                    )
                    payload_hex = re.sub(r"[^0-9A-Fa-f]", "", payload_value)
                    try:
                        payload = bytes.fromhex(payload_hex) if payload_hex and len(payload_hex) % 2 == 0 else b""
                    except ValueError:
                        payload = b""
                    try:
                        data_length_value = next(
                            iter(tshark_occurrences(row["data_length"])),
                            str(row["data_length"] or ""),
                        )
                        payload_length = max(0, int(data_length_value or len(payload)))
                    except (TypeError, ValueError):
                        payload_length = len(payload)
                    icmp_fact["icmp_payload_length"] = payload_length
                    if payload_length:
                        icmp_payload_lengths.add((payload_length,))
                    for marker, decoded_marker in marker_values:
                        marker_id = str(marker["id"])
                        found = False
                        start = 0
                        for _ in range(16):
                            position = payload.find(decoded_marker, start)
                            if position < 0:
                                break
                            marker_offsets[marker_id].add((position,))
                            found = True
                            start = position + 1
                        if found:
                            marker_packet_counts[marker_id] += 1
                    pair_key = (identifier, sequence, source, destination)
                    reverse_key = (identifier, sequence, destination, source)
                    if (
                        icmp_family == "icmp"
                        and icmp_type == "8"
                        and identifier
                        and sequence
                        and packet_timestamp is not None
                    ):
                        if len(pending_icmp_requests) >= ICMP_PAIR_STATE_LIMIT:
                            pending_icmp_requests.pop(next(iter(pending_icmp_requests)))
                        pending_icmp_requests[pair_key] = packet_timestamp
                    elif (
                        icmp_family == "icmp"
                        and icmp_type == "0"
                        and reverse_key in pending_icmp_requests
                        and packet_timestamp is not None
                    ):
                        latency_ms = max(
                            0.0,
                            (packet_timestamp - pending_icmp_requests.pop(reverse_key)) * 1000.0,
                        )
                        icmp_pair_latencies.add((round(latency_ms, 3),))
                    if frame_bytes >= ICMP_ABNORMAL_MIN_FRAME_BYTES:
                        icmp_abnormal_count += 1
                        icmp_anomalies.add((icmp_family, icmp_type, icmp_code, source, destination, frame_bytes))
                        icmp_anomaly_samples.add({
                            "frame_number": row["frame_number"],
                            "timestamp_epoch": row["timestamp_epoch"],
                            "family": icmp_family,
                            "type": icmp_type,
                            "code": icmp_code,
                            "source_ip": source,
                            "destination_ip": destination,
                            "frame_bytes": frame_bytes,
                        })
            packet_fact = {
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
                "transport": transport,
                "dns_query": query_values[0] if query_values else "",
                "dns_queries": query_values,
                "dns_qtypes": query_type_values,
                "dns_rcodes": rcode_values,
                "dns_answers": [
                    {"answer_type": answer_type, "answer": value}
                    for answer_type, value in answer_values
                ],
                "tls_sni": tls_sni_values[0] if tls_sni_values else "",
                "tls_versions": tls_version_facts,
                "http_host": http_host_values[0] if http_host_values else "",
                "http_uri": http_uri_values[0] if http_uri_values else "",
                "http_user_agents": user_agent_facts,
                **icmp_fact,
            }
            reservoir.add(packet_fact)
            if query_values or answer_values or query_type_values or rcode_values:
                dns_record_samples.add({**packet_fact, "record_type": "dns"})
            if tls_sni_values or tls_version_facts or row["protocol"].upper().startswith(("TLS", "SSL")):
                tls_record_samples.add({**packet_fact, "record_type": "tls"})
            if http_host_values or http_uri_values or user_agent_facts or row["protocol"].upper().startswith("HTTP"):
                http_record_samples.add({**packet_fact, "record_type": "http"})
            if icmp_fact:
                icmp_fact_samples.add({**packet_fact, "record_type": "icmp"})

        command = [
            tshark, "-n", "-r", str(pcap), "-T", "fields",
            # TShark uses /t for a literal tab. A backslash-t value is treated
            # as ordinary text by current Wireshark releases and concatenates
            # quoted fields, which silently corrupts coverage telemetry.
            "-E", "header=n", "-E", "separator=/t", "-E", "quote=d", "-E", "occurrence=a",
            "-E", f"aggregator={TSHARK_OCCURRENCE_SEPARATOR}",
        ]
        for field_name in tshark_fields:
            command.extend(["-e", field_name])
        try:
            result = stream_isolated_lines(command, on_line, timeout_seconds=PARSER_TIMEOUT_SECONDS)
        except (BoundedProcessError, OSError) as exc:
            result = {"ok": False, "returncode": 124, "stderr": str(exc), "command": command, "line_count": 0, "stream_bytes": 0}
        commands.append({"type": "full_field_stream", **result})
        if result.get("ok"):
            files_processed += 1
        per_file.append({"pcap": pcap.name, **file_coverage.as_dict(), "ok": bool(result.get("ok"))})
    packet_samples = reservoir.records()
    top_protocols = protocols.most_common(("protocol",), SUMMARY_LIMIT)
    top_conversations = conversations.most_common(
        ("source_ip", "destination_ip", "source_port", "destination_port", "transport", "protocol"),
        SUMMARY_LIMIT,
    )
    dns_activity = {
        "packets_observed": dns_packet_count,
        "query_observations": dns_query_count,
        "answer_observations": dns_answer_count,
        "query_names": dns_queries.most_common(("query",), SUMMARY_LIMIT),
        "query_types": dns_query_types.most_common(("type",), SUMMARY_LIMIT),
        "response_codes": dns_rcodes.most_common(("rcode",), SUMMARY_LIMIT),
        "answers": dns_answers.most_common(("answer_type", "answer"), SUMMARY_LIMIT),
    }
    http_user_agents = {
        "observations": user_agent_count,
        "values": user_agents.most_common(("http_version", "user_agent"), SUMMARY_LIMIT),
    }
    tls_version_summary = {
        "observations": tls_version_observation_count,
        "versions": tls_versions.most_common(("source", "raw_version", "version"), SUMMARY_LIMIT),
    }
    if endpoint_pair_complete and time_filter_applied:
        association = "selected-alert-endpoints-and-request-window"
    elif endpoint_filter_applied or time_filter_applied:
        association = "partially-filtered-selected-alert-candidate"
    else:
        association = "capture-wide-not-attributed-to-selected-alert"
    icmp_provenance = {
        "association": association,
        "association_is_proof": False,
        "caution": (
            "Endpoint/time filtering produces candidate evidence for the selected alert, not proof that every retained packet caused it."
            if endpoint_filter_applied or time_filter_applied
            else "No selected endpoint/time filters were available; ICMP findings describe the entire capture and must not be attributed to one alert."
        ),
        "selected_alert_id": sanitize_evidence_text(scope.get("selected_alert_id"), 256),
        "endpoint_filter": {
            "applied": endpoint_filter_applied,
            "pair_complete": endpoint_pair_complete,
            "direction": "bidirectional",
            "source_ip": scope.get("source_ip") if endpoint_filter_applied else "",
            "destination_ip": scope.get("destination_ip") if endpoint_filter_applied else "",
        },
        "time_filter": {
            "applied": time_filter_applied,
            "basis": str(scope.get("window_basis") or "unavailable")[:80],
            "window_start_epoch": scope.get("window_start_epoch") if time_filter_applied else None,
            "window_end_epoch": scope.get("window_end_epoch") if time_filter_applied else None,
        },
        "capture_icmp_packets_observed": capture_icmp_packet_count,
        "retained_icmp_packets": icmp_packet_count,
        "excluded_by_endpoint": icmp_excluded_endpoint,
        "excluded_by_time": icmp_excluded_time,
        "excluded_missing_timestamp": icmp_excluded_missing_timestamp,
    }
    icmp_size_review = {
        "classification": "suspicious-size-review-signal-not-a-c2-verdict",
        "provenance": icmp_provenance,
        "abnormal_frame_threshold_bytes": ICMP_ABNORMAL_MIN_FRAME_BYTES,
        "icmp_packets_observed": icmp_packet_count,
        "abnormal_packets_observed": icmp_abnormal_count,
        "maximum_frame_bytes": icmp_max_frame_bytes,
        "top_abnormal_flows": icmp_anomalies.most_common(
            ("family", "type", "code", "source_ip", "destination_ip", "frame_bytes"),
            SUMMARY_LIMIT,
        ),
        "representative_samples": icmp_anomaly_samples.records(),
    }
    marker_summaries = []
    for marker, decoded_marker in marker_values:
        marker_id = str(marker["id"])
        expected_raw = marker.get("expected_offset")
        try:
            expected_offset = int(expected_raw) if expected_raw not in (None, "") else None
        except (TypeError, ValueError):
            expected_offset = None
        offsets = marker_offsets[marker_id].most_common(("offset",), 128)
        marker_summaries.append({
            "id": marker_id,
            "source": marker.get("source"),
            "sha256": hashlib.sha256(decoded_marker).hexdigest(),
            "length": len(decoded_marker),
            "printable": sanitize_evidence_text(
                "".join(chr(value) if 32 <= value <= 126 else "." for value in decoded_marker),
                80,
            ),
            "expected_offset": expected_offset,
            "packets_with_marker": int(marker_packet_counts[marker_id]),
            "observations": sum(int(item.get("count") or 0) for item in offsets),
            "expected_offset_observations": sum(
                int(item.get("count") or 0)
                for item in offsets
                if (
                    expected_offset is not None
                    and item.get("offset") is not None
                    and int(item["offset"]) == expected_offset
                )
            ) if expected_offset is not None else None,
            "offsets": offsets,
        })
    icmp_semantics = {
        "raw_payloads_included": False,
        "provenance": icmp_provenance,
        "type_code_counts": icmp_type_codes.most_common(("family", "type", "code"), 128),
        "identifiers": icmp_identifiers.most_common(("identifier",), SUMMARY_LIMIT),
        "sequences": icmp_sequences.most_common(("sequence",), SUMMARY_LIMIT),
        "payload_lengths": icmp_payload_lengths.most_common(("payload_bytes",), SUMMARY_LIMIT),
        "request_reply_pairs": sum(
            int(item.get("count") or 0)
            for item in icmp_pair_latencies.most_common(("latency_ms",), HEAVY_HITTER_CAPACITY)
        ),
        "reply_latency_ms": icmp_pair_latencies.most_common(("latency_ms",), SUMMARY_LIMIT),
        "unmatched_requests_retained": len(pending_icmp_requests),
        "markers": marker_summaries,
    }
    geoip = maxmind_geoip_summary(
        geoip_candidates,
        maxmind_db_paths or configured_maxmind_db_paths(),
    )
    field_sample_header = "\t".join((
        "frame_number", "timestamp_epoch", "source_ip", "destination_ip", "source_port",
        "destination_port", "transport", "protocol", "frame_length", "dns_query", "tls_sni", "http_host", "http_uri",
    ))
    field_sample_tsv = "\n".join(
        [field_sample_header]
        + ["\t".join(sanitize_evidence_text(record.get(key), 256) for key in field_sample_header.split("\t")) for record in packet_samples]
    )
    return {
        "available": True,
        "commands": commands,
        "coverage": {
            **coverage.as_dict(),
            "pcap_files_total": len(pcap_files),
            "pcap_files_processed": files_processed,
            "complete": files_processed == len(pcap_files) and all(item.get("ok") for item in commands),
            "per_file": per_file,
        },
        "sampling": {
            "strategy": "deterministic-reservoir-over-full-stream",
            "sample_limit": TSHARK_SAMPLE_LIMIT,
            "packets_seen": reservoir.seen,
            "packets_sampled": len(packet_samples),
            "query_index_strategy": "deterministic-protocol-reservoirs",
            "query_index_limit_per_protocol": QUERY_INDEX_LIMIT,
            "query_index_records": {
                "dns": len(dns_record_samples.records()),
                "tls": len(tls_record_samples.records()),
                "http": len(http_record_samples.records()),
                "icmp": len(icmp_fact_samples.records()),
            },
        },
        "protocol_counts": top_protocols,
        "top_conversations": top_conversations,
        "dns_activity": dns_activity,
        "http_user_agents": http_user_agents,
        "tls_versions": tls_version_summary,
        "icmp_size_review": icmp_size_review,
        "icmp_semantics": icmp_semantics,
        "geoip": geoip,
        "packet_samples": packet_samples,
        "_local_query_index": {
            "connections": conversations.most_common(
                ("source_ip", "destination_ip", "source_port", "destination_port", "transport", "protocol"),
                QUERY_INDEX_LIMIT,
            ),
            "protocols": protocols.most_common(("protocol",), QUERY_INDEX_LIMIT),
            "packet_samples": packet_samples,
            "packet_facts": packet_samples,
            "dns": dns_queries.most_common(("query",), QUERY_INDEX_LIMIT),
            "dns_records": dns_record_samples.records(),
            "tls_records": tls_record_samples.records(),
            "http_records": http_record_samples.records(),
            "user_agents": user_agents.most_common(("http_version", "user_agent"), QUERY_INDEX_LIMIT),
            "tls_versions": tls_versions.most_common(("source", "raw_version", "version"), QUERY_INDEX_LIMIT),
            "icmp_anomalies": icmp_anomalies.most_common(
                ("family", "type", "code", "source_ip", "destination_ip", "frame_bytes"),
                QUERY_INDEX_LIMIT,
            ),
            "icmp_facts": icmp_fact_samples.records(),
            "icmp_semantics": icmp_semantics,
            "geoip": geoip.get("records", [])[:QUERY_INDEX_LIMIT],
        },
        "samples": [{
            "pcap": "all-capture-files",
            "protocol_hierarchy": json.dumps(top_protocols, indent=2, sort_keys=True),
            "conversations": json.dumps(top_conversations, indent=2, sort_keys=True),
            "field_sample_tsv": field_sample_tsv[:12000],
        }],
    }

