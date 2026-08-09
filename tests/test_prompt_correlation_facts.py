#!/usr/bin/env python3
"""Direct contracts for trusted correlation facts and relationships."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_correlation_facts import (  # noqa: E402
    CORRELATION_MAX_RAW_JSON_BYTES,
    CorrelationFactSources,
    correlation_observable_weight,
    correlation_relationships,
    correlation_row_facts,
    correlation_time_bonus,
)


def row_value(row, key, default=None):
    return row.get(key, default)


class PromptCorrelationFactsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sources = CorrelationFactSources(
            row_value=row_value,
            parse_json_object=lambda value: json.loads(value or "{}"),
        )

    def test_collector_projection_normalizes_nested_flow_and_dns_answers(self):
        community_id = "1:gVOca2cr2eIKwoIKZ8QnLwW2gqU="
        facts = correlation_row_facts(
            self.sources,
            {
                "last_seen": "2026-07-15  10:00:00Z",
                "alert_json": json.dumps({
                    "source": {"ip": "10.0.0.10", "port": "51000"},
                    "destination": {"ip": "203.0.113.30", "port": 443},
                    "network": {
                        "community_id": community_id,
                        "transport": "TCP",
                        "protocol": "TLS",
                    },
                    "dns": {"answers": [{"data": "203.0.113.30"}]},
                }),
            },
        )

        self.assertEqual(facts["community_id"], community_id)
        self.assertEqual(facts["source_port"], 51000)
        self.assertEqual(facts["transport"], "tcp")
        self.assertEqual(facts["dns_answers"], ["203.0.113.30"])
        self.assertEqual(facts["timestamp_text"], "2026-07-15T10:00:00+00:00")

    def test_oversized_raw_json_cannot_supply_relationship_facts(self):
        facts = correlation_row_facts(
            self.sources,
            {
                "alert_json": "{" + "x" * CORRELATION_MAX_RAW_JSON_BYTES + "}",
                "source_ip": "10.0.0.10",
            },
        )

        self.assertEqual(facts["source_ip"], "10.0.0.10")
        self.assertEqual(facts["community_id"], "")
        self.assertEqual(facts["dns_answers"], [])

    def test_exact_relationships_are_bounded_and_explicit(self):
        timestamp = dt.datetime(2026, 7, 15, 10, 0, tzinfo=dt.timezone.utc)
        community_id = "1:gVOca2cr2eIKwoIKZ8QnLwW2gqU="
        selected = {
            "source_ip": "10.0.0.10",
            "destination_ip": "198.51.100.20",
            "source_port": 51000,
            "destination_port": 443,
            "transport": "tcp",
            "community_id": community_id,
            "dns_answers": [],
            "timestamp": timestamp,
            "timestamp_text": timestamp.isoformat(),
        }
        related = {
            **selected,
            "source_ip": "198.51.100.20",
            "destination_ip": "10.0.0.10",
            "source_port": 443,
            "destination_port": 51000,
            "timestamp": timestamp + dt.timedelta(seconds=2),
            "timestamp_text": (timestamp + dt.timedelta(seconds=2)).isoformat(),
        }

        relationships = correlation_relationships(selected, related)

        self.assertEqual(
            {item["kind"] for item in relationships},
            {"same_community_id", "reversed_five_tuple"},
        )
        self.assertTrue(
            all("correlation lead" in item["interpretation_limit"] for item in relationships)
        )

    def test_dns_relationship_requires_same_client_then_encrypted_destination(self):
        timestamp = dt.datetime(2026, 7, 15, 10, 0, tzinfo=dt.timezone.utc)
        dns = {
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.1",
            "destination_port": 53,
            "protocol": "dns",
            "dns_answers": ["203.0.113.30"],
            "timestamp": timestamp,
            "timestamp_text": timestamp.isoformat(),
        }
        tls = {
            "source_ip": "10.0.0.10",
            "destination_ip": "203.0.113.30",
            "destination_port": 443,
            "protocol": "tls",
            "dns_answers": [],
            "timestamp": timestamp + dt.timedelta(seconds=3),
            "timestamp_text": (timestamp + dt.timedelta(seconds=3)).isoformat(),
        }

        relationships = correlation_relationships(dns, tls)

        relationship = next(
            item for item in relationships if item["kind"] == "dns_answer_to_destination"
        )
        self.assertEqual(relationship["facts"]["elapsed_seconds"], 3.0)
        self.assertEqual(relationship["facts"]["resolved_ip"], "203.0.113.30")

    def test_weights_and_time_bonuses_are_deterministic(self):
        self.assertEqual(correlation_observable_weight("hash", "a" * 64), 50)
        self.assertEqual(correlation_observable_weight("ip", "not-an-ip"), 0)
        score, reason = correlation_time_bonus(
            "2026-07-15T10:00:00Z",
            "2026-07-15T10:30:00Z",
        )
        self.assertEqual((score, reason), (20, "detections occurred within one hour"))


if __name__ == "__main__":
    unittest.main()
