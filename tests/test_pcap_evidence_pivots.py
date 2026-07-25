#!/usr/bin/env python3
"""Typed PCAP/Zeek pivot contract and derived-index regressions."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, BIN_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


queries = load_module("pcap_evidence_query_pivots", "pcap_evidence_query.py")
worker = load_module("process_pcap_evidence_pivots", "process-pcap-evidence.py")


class PcapEvidencePivotTest(unittest.TestCase):
    def setUp(self) -> None:
        self.context = {
            "parsed_evidence": [
                {
                    "zeek": {
                        "_local_query_index": {
                            "connections": [
                                {
                                    "source": "zeek",
                                    "record_type": "conn",
                                    "timestamp_epoch": 150.0,
                                    "source_ip": "192.0.2.10",
                                    "destination_ip": "198.51.100.20",
                                    "source_port": 51000,
                                    "destination_port": 80,
                                    "transport": "tcp",
                                    "service": "http",
                                },
                                {
                                    "source": "zeek",
                                    "record_type": "conn",
                                    "timestamp_epoch": 250.0,
                                    "source_ip": "192.0.2.10",
                                    "destination_ip": "198.51.100.30",
                                    "source_port": 52000,
                                    "destination_port": 443,
                                    "transport": "tcp",
                                    "service": "ssl",
                                },
                            ],
                            "dns": [
                                {
                                    "source": "zeek",
                                    "record_type": "dns",
                                    "timestamp_epoch": 260.0,
                                    "source_ip": "192.0.2.10",
                                    "destination_ip": "192.0.2.53",
                                    "query": "service.example",
                                    "qtype_name": "A",
                                    "rcode_name": "NOERROR",
                                    "dns_answers": [
                                        {
                                            "answer_type": "A",
                                            "answer": "198.51.100.30",
                                            "data_payload": "nested-secret-must-not-appear",
                                        }
                                    ],
                                }
                            ],
                            "tls": [
                                {
                                    "source": "zeek",
                                    "record_type": "tls",
                                    "timestamp_epoch": 270.0,
                                    "source_ip": "192.0.2.10",
                                    "destination_ip": "198.51.100.30",
                                    "destination_port": 443,
                                    "sni": "service.example",
                                    "version": "TLSv13",
                                    "established": True,
                                }
                            ],
                            "http": [
                                {
                                    "source": "zeek",
                                    "record_type": "http",
                                    "timestamp_epoch": 280.0,
                                    "source_ip": "192.0.2.10",
                                    "destination_ip": "198.51.100.30",
                                    "host": "service.example",
                                    "uri": "/api/v1/session",
                                    "method": "POST",
                                    "status_code": 201,
                                    "user_agent": "fixture-agent/1",
                                }
                            ],
                        },
                        # A timeless aggregate must not satisfy a time-bounded
                        # query merely because its endpoints match.
                        "top_connections": [
                            {
                                "count": 999,
                                "id.orig_h": "192.0.2.10",
                                "id.resp_h": "198.51.100.30",
                                "id.resp_p": "443",
                                "proto": "tcp",
                            }
                        ],
                    },
                    "tshark": {
                        "_local_query_index": {
                            "icmp_facts": [
                                {
                                    "source": "tshark",
                                    "record_type": "icmp",
                                    "timestamp_epoch": 290.0,
                                    "frame_number": 44,
                                    "frame_length": 512,
                                    "source_ip": "192.0.2.10",
                                    "destination_ip": "198.51.100.30",
                                    "protocol": "ICMP",
                                    "icmp_family": "icmp",
                                    "icmp_type": 8,
                                    "icmp_code": 0,
                                    "icmp_identifier": 99,
                                    "icmp_sequence": 7,
                                    "icmp_payload_length": 470,
                                    "selected_scope_match": True,
                                    # These fields simulate a corrupted private
                                    # index and must never reach query output.
                                    "data_payload": "41414141-secret",
                                    "command": "cat /etc/passwd",
                                    "path": "/private/capture.pcap",
                                }
                            ]
                        }
                    },
                }
            ]
        }

    def test_multi_field_flow_and_time_filters_exclude_timeless_aggregates(self) -> None:
        result = queries.query_derived_pcap_evidence(
            self.context,
            [
                {
                    "operation": "connections",
                    "filters": {
                        "source_ip": "192.0.2.10",
                        "destination_port": 443,
                        "transport": "tcp",
                        "start_epoch": 200,
                        "end_epoch": 300,
                    },
                    "limit": 10,
                }
            ],
        )

        records = result["results"][0]["records"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["destination_ip"], "198.51.100.30")
        self.assertEqual(records[0]["timestamp_epoch"], 250.0)
        self.assertTrue(result["results"][0]["audit"]["time_filter_requires_timestamped_record"])
        self.assertEqual(len(result["results"][0]["query_digest"]), 64)
        self.assertEqual(len(result["results"][0]["result_digest"]), 64)
        self.assertTrue(result["results"][0]["evidence_ref"].startswith("derived-pcap-zeek:"))

    def test_dns_tls_and_http_protocol_pivots_use_exact_typed_fields(self) -> None:
        result = queries.query_derived_pcap_evidence(
            self.context,
            [
                {
                    "operation": "dns",
                    "filters": {
                        "query": "service.example",
                        "answer": "198.51.100.30",
                        "qtype": "A",
                        "rcode": "NOERROR",
                    },
                },
                {
                    "operation": "tls",
                    "filters": {
                        "sni": "service.example",
                        "version": "TLSv13",
                        "established": True,
                    },
                },
                {
                    "operation": "http",
                    "filters": {
                        "host": "service.example",
                        "uri_prefix": "/api/",
                        "method": "POST",
                        "status_code": 201,
                        "user_agent": "fixture-agent/1",
                    },
                },
            ],
        )

        self.assertEqual([len(item["records"]) for item in result["results"]], [1, 1, 1])
        self.assertEqual(result["results"][0]["records"][0]["rcode_name"], "NOERROR")
        self.assertNotIn("nested-secret-must-not-appear", json.dumps(result))
        self.assertEqual(result["results"][1]["records"][0]["sni"], "service.example")
        self.assertEqual(result["results"][2]["records"][0]["uri"], "/api/v1/session")

    def test_icmp_fact_pivot_returns_lengths_but_never_payload_or_parser_metadata(self) -> None:
        result = queries.query_derived_pcap_evidence(
            self.context,
            [
                {
                    "operation": "icmp_facts",
                    "filters": {
                        "endpoint_ip": "198.51.100.30",
                        "icmp_type": 8,
                        "icmp_code": 0,
                        "frame_length_min": 500,
                        "payload_length_min": 400,
                        "selected_scope_match": True,
                    },
                }
            ],
        )

        record = result["results"][0]["records"][0]
        self.assertEqual(record["icmp_payload_length"], 470)
        encoded = json.dumps(result)
        self.assertNotIn("41414141-secret", encoded)
        self.assertNotIn("cat /etc/passwd", encoded)
        self.assertNotIn("/private/capture.pcap", encoded)
        self.assertFalse(result["provenance"]["raw_payloads_included"])
        self.assertFalse(result["provenance"]["parser_or_shell_invocation"])

    def test_contract_rejects_executable_or_untyped_request_surfaces(self) -> None:
        forbidden = [
            {"operation": "dns", "display_filter": "dns.qry.name contains x"},
            {"operation": "dns", "filters": {"regex": ".*"}},
            {"operation": "http", "filters": {"path": "/tmp/capture.pcap"}},
            {"operation": "tls", "filters": {"script": "load local"}},
            {"operation": "packet_facts", "filters": {"parser_args": ["-Y", "tcp"]}},
            {"operation": "coverage", "filters": {"start_epoch": 1}},
        ]

        for request in forbidden:
            with self.subTest(request=request):
                with self.assertRaises(queries.PcapEvidenceQueryError):
                    queries.query_derived_pcap_evidence(self.context, [request])

    def test_contract_rejects_bad_types_ranges_and_time_windows(self) -> None:
        invalid = [
            {"operation": "connections", "filters": {"source_ip": "not-an-ip"}},
            {"operation": "connections", "filters": {"destination_port": 70000}},
            {"operation": "http", "filters": {"status_code": True}},
            {"operation": "packet_facts", "filters": {"start_epoch": 300, "end_epoch": 200}},
            {"operation": "icmp_facts", "filters": {"frame_length_min": 600, "frame_length_max": 500}},
            {"operation": "dns", "filters": []},
            {"operation": "dns", "limit": 1.5},
        ]

        for request in invalid:
            with self.subTest(request=request):
                with self.assertRaises(queries.PcapEvidenceQueryError):
                    queries.query_derived_pcap_evidence(self.context, [request])

    def test_zeek_private_index_projects_only_allowlisted_record_facts(self) -> None:
        record = {
            "ts": 100.5,
            "uid": "C1",
            "id.orig_h": "192.0.2.10",
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 80,
            "method": "GET",
            "host": "service.example",
            "uri": "/health",
            "user_agent": "fixture-agent/1",
            "status_code": 200,
            "password": "must-not-appear",
            "cookie": "must-not-appear",
            "data_payload": "must-not-appear",
            "local_path": "/must/not/appear",
        }
        with tempfile.TemporaryDirectory() as temp_name:
            path = Path(temp_name) / "http.log"
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            counter = worker.BoundedTopCounter(16)
            coverage = worker.CoverageTracker()
            sample = worker.DeterministicReservoir(8)

            worker.aggregate_zeek_log(
                path,
                worker.ZEEK_SUMMARY_FIELDS["http"],
                counter,
                coverage,
                sample,
                "http",
            )

        projected = sample.records()[0]
        self.assertEqual(projected["timestamp_epoch"], 100.5)
        self.assertEqual(projected["host"], "service.example")
        self.assertEqual(projected["user_agent"], "fixture-agent/1")
        encoded = json.dumps(projected)
        self.assertNotIn("must-not-appear", encoded)
        self.assertNotIn("password", encoded)
        self.assertNotIn("cookie", encoded)
        self.assertNotIn("data_payload", encoded)

    def test_tshark_private_indexes_keep_dns_tls_http_icmp_facts_without_payload(self) -> None:
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

        def packet(**values):
            return "\t".join(str(values.get(name, "")) for name in field_names)

        with tempfile.TemporaryDirectory() as temp_name:
            capture = Path(temp_name) / "facts.pcap"
            capture.write_bytes(b"fixture")
            missing_mmdb = Path(temp_name) / "missing.mmdb"

            def stream(_command, on_line, **_kwargs):
                on_line(packet(
                    frame_number=1,
                    timestamp_epoch=100.0,
                    frame_length=512,
                    protocol="ICMP",
                    ipv4_src="192.0.2.10",
                    ipv4_dst="198.51.100.20",
                    dns_query="service.example",
                    dns_query_type=1,
                    dns_rcode=0,
                    dns_answer_ipv4="198.51.100.20",
                    tls_sni="service.example",
                    tls_supported_version="0x0304",
                    http_host="service.example",
                    http_uri="/api/v1",
                    http_user_agent="fixture-agent/1",
                    icmp_type=8,
                    icmp_code=0,
                    icmp_identifier=99,
                    icmp_sequence=7,
                    data_length=470,
                    data_payload="4141414142424242",
                ))
                return {
                    "ok": True,
                    "returncode": 0,
                    "stderr": "",
                    "command": _command,
                    "line_count": 1,
                    "stream_bytes": 1,
                }

            with (
                mock.patch.object(worker, "tool_path", return_value="/usr/bin/tshark"),
                mock.patch.object(worker, "stream_isolated_lines", side_effect=stream),
            ):
                result = worker.run_tshark([capture], missing_mmdb)

        index = result["_local_query_index"]
        self.assertEqual(index["dns_records"][0]["dns_answers"][0]["answer"], "198.51.100.20")
        self.assertEqual(index["tls_records"][0]["tls_versions"][0]["version"], "TLS 1.3")
        self.assertEqual(index["http_records"][0]["http_uri"], "/api/v1")
        self.assertEqual(index["icmp_facts"][0]["icmp_payload_length"], 470)
        encoded = json.dumps(index)
        self.assertNotIn("4141414142424242", encoded)
        self.assertNotIn("data_payload", encoded)


if __name__ == "__main__":
    unittest.main()
