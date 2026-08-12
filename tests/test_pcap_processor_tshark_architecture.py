"""Characterize bounded TShark aggregation before owner extraction."""

from __future__ import annotations

import importlib
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))
TSHARK = importlib.import_module("pcap_processor_tshark")

FIELD_NAMES = (
    "frame_number", "timestamp_epoch", "frame_length", "protocol",
    "ipv4_src", "ipv6_src", "ipv4_dst", "ipv6_dst",
    "tcp_srcport", "tcp_dstport", "udp_srcport", "udp_dstport",
    "dns_query", "dns_query_type", "dns_rcode", "dns_answer_ipv4", "dns_answer_ipv6", "dns_cname",
    "tls_sni", "tls_handshake_version", "tls_supported_version", "tls_record_version",
    "http_host", "http_uri", "http_user_agent", "http2_user_agent",
    "icmp_type", "icmp_code", "icmpv6_type", "icmpv6_code",
    "icmp_identifier", "icmp_sequence", "data_length", "data_payload",
)


def packet_line(**values: object) -> str:
    return "\t".join(str(values.get(name, "")) for name in FIELD_NAMES)


class PcapProcessorTsharkCharacterizationTests(unittest.TestCase):
    def test_legacy_namespace_and_signature_are_frozen(self):
        self.assertEqual(
            sorted(name for name in vars(TSHARK) if not name.startswith("__")),
            [
                "Any", "BIN_DIR", "BoundedHttpError", "BoundedProcessError",
                "BoundedTopCounter", "Counter", "CoverageTracker", "DEFAULT_AI_SETTINGS",
                "DEFAULT_ARTIFACT_DIR", "DEFAULT_DB", "DEFAULT_DETECTION_PLAYBOOKS",
                "DEFAULT_MAXMIND_DB", "DEFAULT_MAXMIND_DBS", "DEFAULT_OUT_DIR",
                "DEFAULT_WAKE", "DeterministicReservoir", "HEAVY_HITTER_CAPACITY", "HOME",
                "ICMP_ABNORMAL_MIN_FRAME_BYTES", "ICMP_PAIR_STATE_LIMIT", "Iterable", "LOG_LIMIT",
                "MAXMIND_GEOIP_MAX_LOOKUPS", "MAX_ARCHIVE_MEMBERS", "MAX_CONTROL_RESPONSE_BYTES",
                "MAX_EXTRACTED_BYTES", "MAX_PCAP_FILES", "MAX_REMOTE_ARTIFACT_BYTES",
                "MAX_SELECTION_WINDOW_SECONDS", "MAX_TOOL_STDERR_BYTES", "MAX_TOOL_STDOUT_BYTES",
                "PARSER_TIMEOUT_SECONDS", "PCAP_SUFFIXES", "Path", "QUERY_INDEX_LIMIT",
                "REMOTE_FETCH_TIMEOUT_SECONDS", "RUNTIME_PYTHON_DIR", "SUMMARY_LIMIT",
                "TLS_VERSION_NAMES", "TSHARK_OCCURRENCE_SEPARATOR", "TSHARK_SAMPLE_LIMIT",
                "ZEEK_QUERY_FIELDS", "ZEEK_SUMMARY_FIELDS", "_icmp_scope_match", "_timestamp_epoch",
                "aggregate_zeek_log", "analysis_completed", "analysis_json_path", "annotations",
                "argparse", "candidate_artifact_paths", "compact_maxmind_record",
                "configured_maxmind_db_path", "configured_maxmind_db_paths", "consume_wake_marker",
                "csv", "delete_request_artifacts", "detection_marker_specs", "dt",
                "extract_rule_context", "fetch_remote_artifact", "hashlib", "icmp_evidence_scope",
                "ipaddress", "json", "load_detection_playbooks", "load_json_lines",
                "local_artifact_path", "materialize_pcap_files", "maxmind_geoip_summary", "os",
                "parse_args", "pending_requests", "project_now", "project_zeek_query_record",
                "public_ip", "re", "read_bounded_json", "request_from_row", "require_runtime_capacity",
                "resolve_detection_playbook", "rows", "run_bounded_command",
                "run_bounded_command_to_file", "run_command", "run_isolated_command", "run_tshark",
                "run_zeek", "safe_extract_tar", "safe_filename", "sanitize_evidence_text",
                "scan_json_lines", "sha256_file", "shutil", "signal_follow_up",
                "signature_context_for_request", "sqlite3", "stream_isolated_lines", "sys",
                "table_columns", "tarfile", "tempfile", "tls_version_name", "tool_path", "top_values",
                "tshark_occurrences", "urllib",
            ],
        )
        self.assertEqual(
            str(inspect.signature(TSHARK.run_tshark)),
            "(pcap_files: 'list[Path]', maxmind_db_paths: 'dict[str, Path] | Path | None' = None, markers: 'list[dict[str, Any]] | None' = None, selected_scope: 'dict[str, Any] | None' = None) -> 'dict[str, Any]'",
        )

    def test_missing_tool_result_is_frozen(self):
        with mock.patch.object(TSHARK, "tool_path", return_value=None):
            self.assertEqual(
                TSHARK.run_tshark([]),
                {
                    "available": False,
                    "reason": "tshark executable not found on PATH or TSHARK_BIN",
                },
            )

    def test_one_pass_projection_and_raw_payload_exclusion_are_frozen(self):
        line = packet_line(
            frame_number=1,
            timestamp_epoch="2.5",
            frame_length=512,
            protocol="ICMP",
            ipv4_src="192.0.2.1",
            ipv4_dst="198.51.100.2",
            icmp_type=8,
            icmp_code=0,
            icmp_identifier=99,
            icmp_sequence=7,
            data_length=6,
            data_payload="41414141583a",
        )

        def stream(command, on_line, **kwargs):
            self.assertEqual(kwargs, {"timeout_seconds": TSHARK.PARSER_TIMEOUT_SECONDS})
            self.assertIn("separator=/t", command)
            self.assertIn(f"aggregator={TSHARK.TSHARK_OCCURRENCE_SEPARATOR}", command)
            on_line(line)
            return {
                "ok": True,
                "returncode": 0,
                "stderr": "",
                "command": command,
                "line_count": 1,
                "stream_bytes": len(line),
            }

        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "unit.pcap"
            capture.write_bytes(b"fixture")
            with (
                mock.patch.object(TSHARK, "tool_path", return_value="/usr/bin/tshark"),
                mock.patch.object(TSHARK, "stream_isolated_lines", side_effect=stream),
            ):
                result = TSHARK.run_tshark(
                    [capture],
                    Path(directory) / "missing.mmdb",
                    [{"id": "marker", "hex": "583a", "expected_offset": 4, "source": "unit"}],
                )

        self.assertEqual(result["coverage"]["pcap_files_processed"], 1)
        self.assertTrue(result["coverage"]["complete"])
        self.assertEqual(result["protocol_counts"], [{"protocol": "ICMP", "count": 1}])
        self.assertEqual(result["icmp_semantics"]["markers"][0]["expected_offset_observations"], 1)
        self.assertEqual(result["icmp_semantics"]["sequences"], [{"sequence": "7", "count": 1}])
        self.assertFalse(result["icmp_semantics"]["raw_payloads_included"])
        self.assertNotIn("41414141583a", json.dumps(result))
        self.assertNotIn("data_payload", json.dumps(result))

    def test_bounded_process_error_remains_per_file_incomplete_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "failed.pcap"
            capture.write_bytes(b"fixture")
            with (
                mock.patch.object(TSHARK, "tool_path", return_value="/usr/bin/tshark"),
                mock.patch.object(
                    TSHARK,
                    "stream_isolated_lines",
                    side_effect=TSHARK.BoundedProcessError("bounded timeout"),
                ),
            ):
                result = TSHARK.run_tshark([capture], Path(directory) / "missing.mmdb")

        self.assertTrue(result["available"])
        self.assertFalse(result["coverage"]["complete"])
        self.assertEqual(result["coverage"]["pcap_files_processed"], 0)
        self.assertEqual(result["commands"][0]["returncode"], 124)
        self.assertEqual(result["commands"][0]["stderr"], "bounded timeout")
        self.assertEqual(result["coverage"]["per_file"][0]["pcap"], "failed.pcap")


if __name__ == "__main__":
    unittest.main()
