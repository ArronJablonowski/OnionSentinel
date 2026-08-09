#!/usr/bin/env python3
"""Direct contracts for prompt query-capability projection."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))
SPEC = importlib.util.spec_from_file_location(
    "query_context_builder_fixture",
    BIN / "build-ai-investigation-prompt.py",
)
builder = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(builder)

from prompt_investigation_query_context import (  # noqa: E402
    build_investigation_query_context,
)


class PromptInvestigationQueryContextTests(unittest.TestCase):
    def row(self, **changes):
        value = {
            "alert_id": (
                ".ds-logs-suricata.alerts-so-2026.07.24-000001:alert-1"
            ),
            "alert_json": json.dumps(
                {
                    "elastic_index": (
                        ".ds-logs-suricata.alerts-so-2026.07.24-000001"
                    ),
                    "elastic_id": "alert-1",
                    "event": {"dataset": "suricata.alert"},
                    "source": {"ip": "192.0.2.10", "port": 49152},
                    "destination": {"ip": "198.51.100.20", "port": 443},
                    "network": {"transport": "tcp", "protocol": "tls"},
                    "dns": {"question": {"name": "example.test"}},
                }
            ),
            "raw_event_json": "{}",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "source_port": 49152,
            "destination_port": 443,
            "transport_protocol": "tcp",
            "network_protocol": "tls",
            "rule_id": "2016150",
            "timestamp": "2026-07-24T18:30:00Z",
            "first_seen": "2026-07-24T18:29:00Z",
            "last_seen": "2026-07-24T18:31:00Z",
        }
        value.update(changes)
        return value

    def project(self, row, *, role="incident-responder", pcap=False):
        return build_investigation_query_context(
            builder.investigation_query_context_policy(),
            builder.investigation_query_context_sources(),
            row,
            [row],
            "group-1",
            role,
            pcap,
        )

    def test_projects_exact_anchor_observables_tuple_and_time_window(self):
        capability, local = self.project(self.row())

        self.assertEqual(local["anchor"]["id"], "alert-1")
        self.assertEqual(local["actor_role"], "incident_responder")
        self.assertIn("192.0.2.10", local["permitted_observables"]["ips"])
        self.assertIn("example.test", local["permitted_observables"]["domains"])
        self.assertEqual(
            local["time_envelope"],
            {
                "start": "2026-07-23T18:30:00.000Z",
                "end": "2026-07-25T18:30:00.000Z",
            },
        )
        self.assertTrue(capability["backends"]["elastic"]["enabled"])
        self.assertEqual(
            local["permitted_event_tuples"][0]["role_semantics"],
            "packet_direction",
        )

    def test_missing_anchor_disables_security_queries_but_not_pcap(self):
        row = self.row(alert_id="invalid", alert_json="{}")
        capability, local = self.project(row, pcap=True)

        self.assertIsNone(local["anchor"])
        self.assertFalse(capability["backends"]["elastic"]["enabled"])
        self.assertFalse(capability["backends"]["oql"]["enabled"])
        self.assertTrue(capability["backends"]["pcap_zeek"]["enabled"])
        self.assertTrue(capability["enabled"])

    def test_unknown_actor_role_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "unsupported.*actor role"):
            self.project(self.row(), role="untrusted-role")

    def test_observable_and_tuple_sets_are_bounded_and_deduplicated(self):
        rows = []
        for index in range(40):
            row = self.row(
                source_ip=f"192.0.2.{index + 1}",
                source_port=40000 + index,
            )
            rows.append(row)

        _capability, local = build_investigation_query_context(
            builder.investigation_query_context_policy(),
            builder.investigation_query_context_sources(),
            rows[0],
            rows,
            "bounded-group",
            "soc-analyst",
            False,
        )

        self.assertEqual(len(local["permitted_observables"]["ips"]), 16)
        self.assertEqual(len(local["permitted_event_tuples"]), 32)


if __name__ == "__main__":
    unittest.main()
