"""Bounded Zeek projection, aggregation, and query-index analysis."""
from __future__ import annotations

from pcap_processor_contract import *  # noqa: F401,F403
from pcap_processor_storage import *  # noqa: F401,F403
from pcap_processor_storage import _timestamp_epoch  # noqa: F401

ZEEK_SUMMARY_FIELDS = {
    "conn": ("id.orig_h", "id.resp_h", "id.resp_p", "proto", "service"),
    "dns": ("query", "qtype_name", "rcode_name"),
    "tls": ("server_name", "id.orig_h", "id.resp_h"),
    "http": ("host", "uri", "method", "status_code"),
    "files": ("mime_type", "filename", "seen_bytes"),
    "notice": ("note", "msg"),
    "weird": ("name", "addl"),
}

# The private query index keeps a bounded, deterministic sample of
# protocol-specific records so a follow-up pivot can combine endpoints,
# timestamps, and protocol facts. Only these fields are projected; headers,
# payloads, credentials, file paths, arbitrary Zeek fields, and scripts never
# enter the index.
ZEEK_QUERY_FIELDS = {
    "conn": {
        "ts": "timestamp_epoch",
        "uid": "uid",
        "id.orig_h": "source_ip",
        "id.resp_h": "destination_ip",
        "id.orig_p": "source_port",
        "id.resp_p": "destination_port",
        "proto": "transport",
        "service": "service",
        "duration": "duration",
        "orig_bytes": "orig_bytes",
        "resp_bytes": "resp_bytes",
        "conn_state": "connection_state",
        "history": "history",
        "missed_bytes": "missed_bytes",
    },
    "dns": {
        "ts": "timestamp_epoch",
        "uid": "uid",
        "id.orig_h": "source_ip",
        "id.resp_h": "destination_ip",
        "id.orig_p": "source_port",
        "id.resp_p": "destination_port",
        "proto": "transport",
        "query": "query",
        "qtype": "qtype",
        "qtype_name": "qtype_name",
        "rcode": "rcode",
        "rcode_name": "rcode_name",
        "answers": "dns_answers",
        "rejected": "rejected",
    },
    "tls": {
        "ts": "timestamp_epoch",
        "uid": "uid",
        "id.orig_h": "source_ip",
        "id.resp_h": "destination_ip",
        "id.orig_p": "source_port",
        "id.resp_p": "destination_port",
        "version": "version",
        "cipher": "cipher",
        "curve": "curve",
        "server_name": "sni",
        "resumed": "resumed",
        "established": "established",
        "next_protocol": "next_protocol",
        "ja3": "ja3",
        "ja3s": "ja3s",
    },
    "http": {
        "ts": "timestamp_epoch",
        "uid": "uid",
        "id.orig_h": "source_ip",
        "id.resp_h": "destination_ip",
        "id.orig_p": "source_port",
        "id.resp_p": "destination_port",
        "method": "method",
        "host": "host",
        "uri": "uri",
        "referrer": "referrer",
        "version": "version",
        "user_agent": "user_agent",
        "request_body_len": "request_body_len",
        "response_body_len": "response_body_len",
        "status_code": "status_code",
        "status_msg": "status_message",
    },
    "files": {
        "ts": "timestamp_epoch",
        "fuid": "fuid",
        "conn_uids": "uid",
        "tx_hosts": "source_ip",
        "rx_hosts": "destination_ip",
        "source": "source_name",
        "mime_type": "mime_type",
        "filename": "filename",
        "seen_bytes": "seen_bytes",
        "total_bytes": "total_bytes",
        "missing_bytes": "missing_bytes",
        "overflow_bytes": "overflow_bytes",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
    },
    "notice": {
        "ts": "timestamp_epoch",
        "uid": "uid",
        "id.orig_h": "source_ip",
        "id.resp_h": "destination_ip",
        "id.orig_p": "source_port",
        "id.resp_p": "destination_port",
        "note": "note",
        "msg": "message",
        "sub": "sub",
        "src": "source_ip",
        "dst": "destination_ip",
        "p": "destination_port",
        "dropped": "dropped",
    },
    "weird": {
        "ts": "timestamp_epoch",
        "uid": "uid",
        "id.orig_h": "source_ip",
        "id.resp_h": "destination_ip",
        "id.orig_p": "source_port",
        "id.resp_p": "destination_port",
        "name": "name",
        "addl": "additional",
        "notice": "notice",
    },
}


def project_zeek_query_record(record: dict[str, Any], log_type: str) -> dict[str, Any]:
    """Project one Zeek JSON row into payload-free, queryable facts."""
    projected: dict[str, Any] = {"source": "zeek", "record_type": log_type}
    for source_field, output_field in ZEEK_QUERY_FIELDS.get(log_type, {}).items():
        value = record.get(source_field)
        if value not in (None, "", [], {}):
            projected[output_field] = value
    return projected


def aggregate_zeek_log(
    path: Path,
    fields: tuple[str, ...],
    counter: BoundedTopCounter,
    coverage: CoverageTracker,
    query_sample: DeterministicReservoir | None = None,
    log_type: str = "",
) -> None:
    """Read every Zeek record while keeping only bounded heavy-hitter state."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                coverage.malformed_records += 1
                continue
            if not isinstance(parsed, dict):
                coverage.malformed_records += 1
                continue
            packet_bytes = 0
            for key in ("orig_bytes", "resp_bytes", "seen_bytes"):
                try:
                    packet_bytes += max(0, int(parsed.get(key) or 0))
                except (TypeError, ValueError):
                    continue
            coverage.observe(timestamp=parsed.get("ts"), length=packet_bytes, decoded=True)
            counter.add(parsed.get(field) for field in fields)
            if query_sample is not None and log_type in ZEEK_QUERY_FIELDS:
                query_sample.add(project_zeek_query_record(parsed, log_type))


def run_zeek(pcap_files: list[Path], work_dir: Path) -> dict[str, Any]:
    zeek = tool_path("ZEEK_BIN", "zeek")
    if not zeek:
        return {"available": False, "reason": "zeek executable not found on PATH or ZEEK_BIN"}
    zeek_dir = work_dir / "zeek"
    zeek_dir.mkdir(parents=True, exist_ok=True)
    commands: list[dict[str, Any]] = []
    log_names = {
        "conn": ("conn.log",),
        "dns": ("dns.log",),
        "tls": ("ssl.log", "tls.log"),
        "http": ("http.log",),
        "files": ("files.log",),
        "notice": ("notice.log",),
        "weird": ("weird.log",),
    }
    counters = {key: BoundedTopCounter(HEAVY_HITTER_CAPACITY) for key in log_names}
    coverage = {key: CoverageTracker() for key in log_names}
    query_samples = {key: DeterministicReservoir(QUERY_INDEX_LIMIT) for key in log_names}
    files_processed = 0

    for index, pcap in enumerate(pcap_files):
        # Zeek uses fixed output names. A distinct workspace per capture keeps
        # one run from overwriting or silently mixing another capture's logs.
        capture_dir = zeek_dir / f"{index:04d}-{safe_filename(pcap.stem)}"
        capture_dir.mkdir(parents=True, exist_ok=False)
        try:
            result = run_command(
                [zeek, "-C", "LogAscii::use_json=T", "-r", str(pcap)],
                cwd=capture_dir,
                timeout=PARSER_TIMEOUT_SECONDS,
            )
            commands.append({key: result[key] for key in ("ok", "returncode", "stderr", "command")})
            for log_key, candidates in log_names.items():
                path = next((capture_dir / name for name in candidates if (capture_dir / name).exists()), None)
                if path is not None:
                    aggregate_zeek_log(
                        path,
                        ZEEK_SUMMARY_FIELDS[log_key],
                        counters[log_key],
                        coverage[log_key],
                        query_samples[log_key],
                        log_key,
                    )
            if result["ok"]:
                files_processed += 1
        finally:
            shutil.rmtree(capture_dir, ignore_errors=True)
    record_counts = {key: coverage[key].total_records for key in log_names}
    valid_timestamps = [item for item in coverage.values() if item.first_timestamp is not None]
    return {
        "available": True,
        "commands": commands,
        "record_counts": record_counts,
        "coverage": {
            "pcap_files_total": len(pcap_files),
            "pcap_files_processed": files_processed,
            "records_aggregated": sum(record_counts.values()),
            "first_timestamp_epoch": min((item.first_timestamp for item in valid_timestamps), default=None),
            "last_timestamp_epoch": max((item.last_timestamp for item in valid_timestamps), default=None),
            "per_log": {key: coverage[key].as_dict() for key in log_names},
            "complete": files_processed == len(pcap_files) and all(item.get("ok") for item in commands),
        },
        "sampling": {
            "strategy": "full-stream-bounded-heavy-hitters",
            "heavy_hitter_capacity_per_log": HEAVY_HITTER_CAPACITY,
            "query_index_strategy": "deterministic-reservoir-per-log",
            "query_index_limit_per_log": QUERY_INDEX_LIMIT,
            "query_index_records": {
                key: len(query_samples[key].records())
                for key in log_names
            },
            "records_truncated_before_aggregation": {key: False for key in log_names},
            "invalid_json_lines": {key: coverage[key].malformed_records for key in log_names},
        },
        "top_connections": counters["conn"].most_common(ZEEK_SUMMARY_FIELDS["conn"], SUMMARY_LIMIT),
        "dns_queries": counters["dns"].most_common(ZEEK_SUMMARY_FIELDS["dns"], SUMMARY_LIMIT),
        "tls_sni": counters["tls"].most_common(ZEEK_SUMMARY_FIELDS["tls"], SUMMARY_LIMIT),
        "http_hosts": counters["http"].most_common(ZEEK_SUMMARY_FIELDS["http"], SUMMARY_LIMIT),
        "files": counters["files"].most_common(ZEEK_SUMMARY_FIELDS["files"], SUMMARY_LIMIT),
        "notices": counters["notice"].most_common(ZEEK_SUMMARY_FIELDS["notice"], SUMMARY_LIMIT),
        "weird": counters["weird"].most_common(ZEEK_SUMMARY_FIELDS["weird"], SUMMARY_LIMIT),
        # This bounded index is retained only for local, allowlisted follow-up
        # queries. It is stripped before either the initial local prompt or any
        # hosted-model request is assembled.
        "_local_query_index": {
            "connections": query_samples["conn"].records(),
            "dns": query_samples["dns"].records(),
            "tls": query_samples["tls"].records(),
            "http": query_samples["http"].records(),
            "files": query_samples["files"].records(),
            "notices": query_samples["notice"].records(),
            "weird": query_samples["weird"].records(),
        },
    }
