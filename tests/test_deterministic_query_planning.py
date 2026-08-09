#!/usr/bin/env python3
"""Direct contracts for protocol-first deterministic query planning."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "n8n"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from onion_sentinel.analysis.query import deterministic_planning  # noqa: E402


class QueryError(ValueError):
    pass


def parse_utc(value, _label):
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise QueryError(str(exc)) from exc
    if parsed.tzinfo is None:
        raise QueryError("timezone required")
    return parsed.astimezone(dt.timezone.utc)


def utc_text(value):
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


class DeterministicQueryPlanningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = deterministic_planning.Policy(
            pack_role_modes={
                "zeek_http": "zeek_originator_responder",
                "zeek_files": "zeek_originator_responder",
                "network_flow": "cross_sensor",
                "alert_context": "packet_direction",
            }
        )
        self.dependencies = deterministic_planning.Dependencies(
            is_incident_responder=lambda package: (
                package.get("agent_role") == "incident-responder"
            ),
            canonical_digest=lambda value: hashlib.sha256(
                json.dumps(value, sort_keys=True).encode()
            ).hexdigest(),
            parse_utc=parse_utc,
            utc_text=utc_text,
            pack_event_tuple_fields=lambda _pack: {
                "source_ip", "destination_ip", "source_port",
                "destination_port", "transport", "community_id",
            },
            query_error=QueryError,
        )

    @staticmethod
    def package() -> dict:
        return {
            "agent_role": "incident-responder",
            "alert": {
                "timestamp": "2026-07-24T18:30:00Z",
                "rule_name": "Synthetic HTTP detection",
                "network": {"protocol": "http"},
            },
            "investigation_query_capability": {
                "enabled": True,
                "backends": {
                    "elastic": {"packs": ["zeek_http", "zeek_files"]}
                },
            },
            "_local_investigation_query_context": {
                "anchor_time": "2026-07-24T18:30:00Z",
                "permitted_event_tuples": [{
                    "event_tuple": {
                        "source_ip": "192.0.2.10",
                        "destination_ip": "198.51.100.20",
                        "source_port": 49152,
                        "destination_port": 80,
                        "transport": "tcp",
                        "community_id": "1:direct-contract=",
                    },
                    "role_semantics": "zeek_originator_responder",
                }],
            },
        }

    def test_nested_protocol_fallback_builds_formatted_fixed_pack_plan(self) -> None:
        result = deterministic_planning.plan(
            self.package(), policy=self.policy, dependencies=self.dependencies
        )

        self.assertEqual(
            [request["query_id"] for request in result],
            ["deterministic-zeek_http", "deterministic-zeek_files"],
        )
        self.assertEqual(
            result[0]["parameters"]["window"],
            {
                "start": "2026-07-24T18:25:00.000Z",
                "end": "2026-07-24T18:35:00.000Z",
            },
        )
        self.assertEqual(
            result[0]["parameters"]["event_tuple"]["community_id"],
            "1:direct-contract=",
        )

    def test_invalid_or_untrusted_context_fails_closed(self) -> None:
        package = self.package()
        package["agent_role"] = "soc-analyst"
        self.assertEqual(
            deterministic_planning.plan(
                package, policy=self.policy, dependencies=self.dependencies
            ),
            [],
        )
        package["agent_role"] = "incident-responder"
        package["_local_investigation_query_context"][
            "permitted_event_tuples"
        ] = []
        self.assertEqual(
            deterministic_planning.plan(
                package, policy=self.policy, dependencies=self.dependencies
            ),
            [],
        )

    def test_cross_sensor_pack_omits_directional_tuple_without_join_key(self) -> None:
        package = self.package()
        package["alert"]["network"]["protocol"] = "unknown"
        package["investigation_query_capability"]["backends"]["elastic"][
            "packs"
        ] = ["network_flow", "alert_context"]
        entry = package["_local_investigation_query_context"][
            "permitted_event_tuples"
        ][0]
        entry["event_tuple"].pop("community_id")
        entry["role_semantics"] = "packet_direction"

        result = deterministic_planning.plan(
            package, policy=self.policy, dependencies=self.dependencies
        )

        self.assertNotIn("event_tuple", result[0]["parameters"])
        self.assertIn("event_tuple", result[1]["parameters"])


if __name__ == "__main__":
    unittest.main()
