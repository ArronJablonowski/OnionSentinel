#!/usr/bin/env python3
"""ARR-25 contract tests for stored, read-only OSQuery evidence."""
from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from investigation_query_contract import (  # noqa: E402
    HISTORICAL_OSQUERY_SCHEMA_CONTRACT,
    HISTORICAL_OSQUERY_SCHEMA_PROFILES,
    PACKS,
    InvestigationQueryContractError,
    compile_historical_osquery_schema_discovery,
    historical_osquery_field_caps_body,
    historical_osquery_field_caps_endpoint,
    validate_historical_osquery_schema_discovery,
)


def field_caps(*fields: str) -> dict:
    return {
        "fields": {
            field: {
                "keyword": {
                    "type": "keyword",
                    "searchable": True,
                    "aggregatable": True,
                }
            }
            for field in fields
        }
    }


class HistoricalOsquerySchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pack = PACKS["osquery_history"]
        self.observable_fields = ["host.name", "host.hostname", "agent.id"]

    def test_reviewed_profiles_cover_deployed_results_and_action_responses(self) -> None:
        self.assertEqual(
            HISTORICAL_OSQUERY_SCHEMA_CONTRACT,
            "onion-sentinel-historical-osquery-schema-v1",
        )
        self.assertEqual(
            set(HISTORICAL_OSQUERY_SCHEMA_PROFILES),
            {
                "ecs-endpoint-events-v1",
                "elastic-osquery-manager-flat-v1",
                "elastic-osquery-manager-action-responses-v1",
            },
        )
        fields = set(self.pack["fields"])
        required = {
            "host.hostname",
            "agent.id",
            "agent.name",
            "osquery.hostname",
            "osquery.uuid",
            "osquery.name",
            "osquery.path",
            "osquery.pid",
            "osquery.parent",
            "osquery.bundle_identifier",
            "osquery.bundle_name",
            "osquery.bundle_short_version",
            "osquery.category",
            "action_id",
            "schedule_id",
            "pack_id",
            "pack_name",
            "query_name",
            "response_id",
            "started_at",
            "completed_at",
            "action_response.osquery.count",
        }
        self.assertTrue(required.issubset(fields), sorted(required - fields))
        self.assertFalse(any("*" in field for field in fields))
        self.assertNotIn("action_data.query", fields)
        self.assertNotIn("osquery.query", fields)
        self.assertNotIn("osquery.sql", fields)

    def test_field_caps_request_is_exact_and_read_only(self) -> None:
        endpoint = historical_osquery_field_caps_endpoint(self.pack["indices"])
        self.assertEqual(
            endpoint,
            ",".join(self.pack["indices"])
            + "/_field_caps?ignore_unavailable=true&expand_wildcards=open",
        )
        self.assertEqual(
            historical_osquery_field_caps_body(self.pack["fields"]),
            {"fields": self.pack["fields"]},
        )
        self.assertNotIn("_search", endpoint)
        self.assertNotIn("query", historical_osquery_field_caps_body(
            self.pack["fields"]
        ))

    def test_deployed_flat_mapping_is_compatible_and_digest_bound(self) -> None:
        raw = field_caps(
            "@timestamp",
            "event.dataset",
            "host.name",
            "agent.id",
            "osquery.name",
            "osquery.path",
            "osquery.bundle_identifier",
        )
        discovery = compile_historical_osquery_schema_discovery(
            raw,
            index_scope=self.pack["indices"],
            projection_fields=self.pack["fields"],
            observable_fields=self.observable_fields,
        )

        self.assertTrue(discovery["mapping_compatible"])
        self.assertEqual(
            discovery["compatible_profiles"],
            ["elastic-osquery-manager-flat-v1"],
        )
        self.assertEqual(discovery["mapped_identity_fields"], [
            "agent.id", "host.name",
        ])
        self.assertEqual(
            validate_historical_osquery_schema_discovery(
                discovery,
                index_scope=self.pack["indices"],
                projection_fields=self.pack["fields"],
                observable_fields=self.observable_fields,
            ),
            discovery,
        )
        tampered = copy.deepcopy(discovery)
        tampered["mapped_fields"].append("action_data.query")
        with self.assertRaisesRegex(
            InvestigationQueryContractError,
            "schema discovery",
        ):
            validate_historical_osquery_schema_discovery(
                tampered,
                index_scope=self.pack["indices"],
                projection_fields=self.pack["fields"],
                observable_fields=self.observable_fields,
            )

    def test_mapping_drift_cannot_be_reported_as_a_trustworthy_zero(self) -> None:
        discovery = compile_historical_osquery_schema_discovery(
            field_caps("@timestamp", "event.dataset", "unreviewed.host"),
            index_scope=self.pack["indices"],
            projection_fields=self.pack["fields"],
            observable_fields=self.observable_fields,
        )

        self.assertFalse(discovery["mapping_compatible"])
        self.assertEqual(discovery["compatible_profiles"], [])
        self.assertEqual(discovery["mapped_observable_fields"], [])


if __name__ == "__main__":
    unittest.main()
