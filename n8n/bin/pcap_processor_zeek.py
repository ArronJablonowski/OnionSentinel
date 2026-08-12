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
    workflow = __import__("pcap_zeek_workflow")
    return workflow.run_zeek(
        pcap_files,
        work_dir,
        policy=workflow.ZeekPolicy(
            summary_fields=ZEEK_SUMMARY_FIELDS,
            heavy_hitter_capacity=HEAVY_HITTER_CAPACITY,
            query_index_limit=QUERY_INDEX_LIMIT,
            summary_limit=SUMMARY_LIMIT,
            parser_timeout_seconds=PARSER_TIMEOUT_SECONDS,
        ),
        dependencies=workflow.ZeekDependencies(
            tool_path=tool_path,
            safe_filename=safe_filename,
            run_command=run_command,
            aggregate_log=aggregate_zeek_log,
            counter_factory=BoundedTopCounter,
            coverage_factory=CoverageTracker,
            reservoir_factory=DeterministicReservoir,
            remove_tree=shutil.rmtree,
        ),
    )
