#!/usr/bin/env python3
"""Direct contracts for bounded prompt-facing PCAP evidence."""
from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_pcap_evidence import (  # noqa: E402
    PcapEvidenceRequest,
    PcapEvidenceSources,
    build_pcap_evidence_context,
    compact_pcap_analysis,
    pcap_request_context,
)


def sources(**changes) -> PcapEvidenceSources:
    values = {
        "row_value": lambda row, key: row.get(key),
        "query_rows": mock.Mock(return_value=[]),
        "load_json_bounded": lambda path: json.loads(path.read_text(encoding="utf-8")),
    }
    values.update(changes)
    return PcapEvidenceSources(**values)


def selected():
    return {"alert_id": "alert-1", "stable_group_id": "group-stable"}


class PromptPcapEvidenceTests(unittest.TestCase):
    def test_compactor_bounds_summaries_and_never_projects_packet_bodies(self):
        connections = [{"id": index} for index in range(250)]
        record = {
            "packet": "must-not-project",
            "message": "must-not-project",
            "request": {
                "request_id": "request-1",
                "alert_id": "alert-1",
                "group_id": "group-1",
            },
            "pcap_files": [
                {"name": str(index), "size_bytes": index, "sha256": "a" * 64}
                for index in range(8)
            ],
            "zeek": {
                "available": True,
                "_local_query_index": {"connections": connections[:150]},
            },
            "tshark": {
                "available": True,
                "protocol_counts": list(range(30)),
                "packet_samples": list(range(30)),
                "_local_query_index": {"connections": connections[150:]},
                "samples": [
                    {
                        "pcap": f"/private/capture-{index}.pcap",
                        "protocol_hierarchy": "x" * 5000,
                        "conversations": "y" * 5000,
                        "field_sample_tsv": "z" * 5000,
                    }
                    for index in range(3)
                ],
            },
        }

        compact = compact_pcap_analysis(record)
        serialized = json.dumps(compact)

        self.assertNotIn("must-not-project", serialized)
        self.assertEqual(len(compact["pcap_files"]), 5)
        self.assertEqual(len(compact["tshark"]["protocol_counts"]), 20)
        self.assertEqual(len(compact["tshark"]["packet_samples"]), 20)
        self.assertEqual(len(compact["tshark"]["samples"]), 2)
        self.assertEqual(compact["tshark"]["samples"][0]["pcap"], "capture-0.pcap")
        self.assertEqual(
            len(compact["tshark"]["samples"][0]["protocol_hierarchy"]),
            4000,
        )
        self.assertEqual(len(compact["_local_query_index"]["connections"]), 192)

    def test_request_context_falls_back_to_exact_alert_for_legacy_schema(self):
        query = mock.Mock(
            side_effect=[
                sqlite3.OperationalError("missing alias table"),
                [{"request_id": "request-1", "evidence_relationship": "exact_alert"}],
            ]
        )

        result = pcap_request_context(sources(query_rows=query), "connection", selected())

        self.assertEqual(result[0]["request_id"], "request-1")
        self.assertEqual(query.call_count, 2)
        self.assertIn("LEFT JOIN alert_group_alias", query.call_args_list[0].args[1])
        self.assertNotIn("alert_group_alias", query.call_args_list[1].args[1])
        self.assertEqual(query.call_args_list[1].args[2], ["alert-1"])

    def test_request_context_returns_empty_when_both_schemas_are_unavailable(self):
        query = mock.Mock(side_effect=sqlite3.OperationalError("missing table"))

        result = pcap_request_context(sources(query_rows=query), "connection", selected())

        self.assertEqual(result, [])
        self.assertEqual(query.call_count, 2)

    def test_context_prefers_exact_artifact_and_rejects_unrelated_legacy_file(self):
        requests = [
            {
                "request_id": "related-request",
                "evidence_relationship": "stable_group_related",
            },
            {"request_id": "exact-request", "evidence_relationship": "exact_alert"},
        ]
        query = mock.Mock(return_value=requests)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "related-request-pcap-analysis.json").write_text(
                json.dumps(
                    {
                        "request": {
                            "request_id": "related-request",
                            "alert_id": "older-alert",
                        },
                        "zeek": {"available": True},
                    }
                ),
                encoding="utf-8",
            )
            (root / "exact-request-pcap-analysis.json").write_text(
                json.dumps(
                    {
                        "request": {
                            "request_id": "exact-request",
                            "alert_id": "alert-1",
                        },
                        "tshark": {"available": True},
                    }
                ),
                encoding="utf-8",
            )
            (root / "unrelated-pcap-analysis.json").write_text(
                json.dumps(
                    {
                        "request": {
                            "request_id": "unrelated",
                            "alert_id": "unrelated-alert",
                        },
                        "packet": "must-not-load",
                    }
                ),
                encoding="utf-8",
            )

            context = build_pcap_evidence_context(
                sources(query_rows=query),
                PcapEvidenceRequest(
                    connection="connection",
                    selected=selected(),
                    analysis_dir=root,
                    evidence_limit=5,
                    legacy_scan_limit=10,
                ),
            )

        self.assertEqual(
            [item["request_id"] for item in context["parsed_evidence"]],
            ["exact-request", "related-request"],
        )
        self.assertEqual(context["exact_alert_evidence_count"], 1)
        self.assertEqual(context["stable_group_related_evidence_count"], 1)

    def test_evidence_limit_stops_loading_after_first_admitted_artifact(self):
        query = mock.Mock(
            return_value=[
                {"request_id": "first", "evidence_relationship": "exact_alert"},
                {"request_id": "second", "evidence_relationship": "exact_alert"},
            ]
        )
        loader = mock.Mock(side_effect=lambda path: json.loads(path.read_text()))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for request_id in ("first", "second"):
                (root / f"{request_id}-pcap-analysis.json").write_text(
                    json.dumps(
                        {
                            "request": {
                                "request_id": request_id,
                                "alert_id": "alert-1",
                            }
                        }
                    ),
                    encoding="utf-8",
                )
            context = build_pcap_evidence_context(
                sources(query_rows=query, load_json_bounded=loader),
                PcapEvidenceRequest(
                    connection="connection",
                    selected=selected(),
                    analysis_dir=root,
                    evidence_limit=1,
                    legacy_scan_limit=10,
                ),
            )

        self.assertEqual(len(context["parsed_evidence"]), 1)
        self.assertEqual(loader.call_count, 1)


if __name__ == "__main__":
    unittest.main()
