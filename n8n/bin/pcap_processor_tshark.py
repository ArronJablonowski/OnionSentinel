"""Compatibility facade for bounded TShark evidence aggregation."""
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
    """Return bounded packet, protocol, GeoIP, and ICMP evidence."""
    from pcap_processor_tshark_workflow import run_tshark as run

    dependencies = {
        "BoundedProcessError": BoundedProcessError,
        "BoundedTopCounter": BoundedTopCounter,
        "CoverageTracker": CoverageTracker,
        "DeterministicReservoir": DeterministicReservoir,
        "configured_maxmind_db_paths": configured_maxmind_db_paths,
        "csv": csv,
        "hashlib": hashlib,
        "icmp_scope_match": _icmp_scope_match,
        "json": json,
        "maxmind_geoip_summary": maxmind_geoip_summary,
        "public_ip": public_ip,
        "re": re,
        "sanitize_evidence_text": sanitize_evidence_text,
        "stream_isolated_lines": stream_isolated_lines,
        "tshark_occurrences": tshark_occurrences,
        "tls_version_name": tls_version_name,
        "tool_path": tool_path,
    }
    configuration = {
        "heavy_hitter_capacity": HEAVY_HITTER_CAPACITY,
        "icmp_abnormal_min_frame_bytes": ICMP_ABNORMAL_MIN_FRAME_BYTES,
        "icmp_pair_state_limit": ICMP_PAIR_STATE_LIMIT,
        "occurrence_separator": TSHARK_OCCURRENCE_SEPARATOR,
        "query_index_limit": QUERY_INDEX_LIMIT,
        "sample_limit": TSHARK_SAMPLE_LIMIT,
        "summary_limit": SUMMARY_LIMIT,
        "timeout_seconds": PARSER_TIMEOUT_SECONDS,
    }
    return run(
        pcap_files,
        maxmind_db_paths,
        markers,
        selected_scope,
        dependencies,
        configuration,
    )
