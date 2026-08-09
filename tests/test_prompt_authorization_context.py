#!/usr/bin/env python3
"""Direct contracts for exact operator-authorization projection."""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_authorization_context import (  # noqa: E402
    AuthorizationContextSources,
    authorized_activity_context,
    canonical_authorized_activity_entry,
)


def parse_datetime(value):
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def selected(**changes):
    value = {
        "alert_id": "alert-1",
        "alert_json": "{}",
        "timestamp": "2026-08-08T12:05:00Z",
        "last_seen": "2026-08-08T12:05:00Z",
        "first_seen": "2026-08-08T12:05:00Z",
        "source_ip": "10.77.7.222",
        "destination_ip": "192.0.2.20",
        "source_port": 41000,
        "destination_port": 22,
        "rule_id": "2003068",
        "transport_protocol": "tcp",
    }
    value.update(changes)
    return value


def authorization(**changes):
    value = {
        "status": "operator_authorized",
        "policy_id": "authorized-ssh-scan",
        "source_ips": ["10.77.7.222"],
        "destination_ips": ["192.0.2.20"],
        "rule_ids": ["2003068"],
        "source_ports": [41000],
        "destination_ports": [22],
        "destination_port_ranges": [],
        "transport_protocols": ["tcp"],
        "authorization_start": "2026-08-08T12:00:00Z",
        "authorization_end": "2026-08-08T12:10:00Z",
        "authorized_by": "must not enter model evidence",
        "scope": "free-form prose must not enter model evidence",
    }
    value.update(changes)
    return value


def sources(**changes):
    values = {
        "row_value": lambda row, key: row.get(key),
        "parse_alert_json": lambda raw: json.loads(raw),
        "parse_datetime": parse_datetime,
        "query_row": mock.Mock(return_value=None),
        "query_rows": mock.Mock(return_value=[]),
    }
    values.update(changes)
    return AuthorizationContextSources(**values)


class PromptAuthorizationContextTests(unittest.TestCase):
    def test_canonical_entry_binds_exact_tuple_and_excludes_free_form_fields(self):
        entry = canonical_authorized_activity_entry(
            sources(),
            selected(),
            authorization(),
            policy_id="authorized-ssh-scan",
        )

        self.assertIsNotNone(entry)
        self.assertRegex(
            entry["evidence_ref"],
            r"^authorized-activity:sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(entry["coverage"]["destination_ports"], [22])
        self.assertNotIn("authorized_by", entry)
        self.assertNotIn("scope", entry)

    def test_each_tuple_or_time_mismatch_fails_closed(self):
        variants = (
            {"source_ip": "10.77.7.223"},
            {"destination_ip": "192.0.2.21"},
            {"source_port": 41001},
            {"destination_port": 23},
            {"rule_id": "2003069"},
            {"transport_protocol": "udp"},
            {"timestamp": "2026-08-08T11:59:59Z"},
            {"timestamp": "2026-08-08T12:10:01Z"},
        )
        for changes in variants:
            with self.subTest(changes=changes):
                self.assertIsNone(
                    canonical_authorized_activity_entry(
                        sources(),
                        selected(**changes),
                        authorization(),
                        policy_id="authorized-ssh-scan",
                    )
                )

    def test_bounded_destination_range_is_accepted_but_malformed_range_is_not(self):
        ranged = authorization(
            destination_ports=[],
            destination_port_ranges=[[20, 25]],
        )
        entry = canonical_authorized_activity_entry(
            sources(), selected(), ranged, policy_id="authorized-ssh-scan"
        )

        self.assertEqual(entry["coverage"]["destination_port_ranges"], [[20, 25]])
        self.assertIsNone(
            canonical_authorized_activity_entry(
                sources(),
                selected(),
                authorization(
                    destination_ports=[],
                    destination_port_ranges=[[25, 20]],
                ),
                policy_id="authorized-ssh-scan",
            )
        )

    def test_campaign_projection_revalidates_policy_and_bounds_observations(self):
        campaign = {
            "campaign_id": "campaign-1",
            "policy_id": "authorized-ssh-scan",
            "representative_alert_id": "alert-1",
            "representative_group_id": "group-1",
            "bucket_start": "2026-08-08T12:00:00Z",
            "bucket_end": "2026-08-08T12:10:00Z",
            "first_seen": "2026-08-08T12:05:00Z",
            "last_seen": "2026-08-08T12:05:00Z",
            "member_count": 2,
            "distinct_target_count": 1,
            "authorization_json": json.dumps(authorization()),
        }
        observation = {
            "alert_id": "alert-1",
            "stable_group_id": "group-1",
            "destination_ip": "192.0.2.20",
            "destination_port": 22,
            "observed_at": "2026-08-08T12:05:00Z",
        }
        dependencies = sources(
            query_row=mock.Mock(return_value=campaign),
            query_rows=mock.Mock(return_value=[observation]),
        )

        context = authorized_activity_context(
            dependencies,
            "connection",
            selected(),
            limit=900,
        )

        self.assertEqual(context["status"], "operator_authorized")
        self.assertEqual(context["observations"], [observation])
        self.assertIs(context["observations_truncated"], True)
        self.assertNotIn("authorized_by", context["authorization"])
        query_args = dependencies.query_rows.call_args.args
        self.assertIn("FROM authorized_activity_campaign_members", query_args[1])
        self.assertEqual(query_args[2], ["campaign-1", 500])

    def test_missing_schema_and_invalid_campaign_membership_fail_closed(self):
        missing_schema = mock.Mock(side_effect=sqlite3.OperationalError("no table"))
        self.assertIsNone(
            authorized_activity_context(
                sources(query_row=missing_schema),
                "connection",
                selected(),
            )
        )
        campaign = {
            "campaign_id": "campaign-1",
            "policy_id": "authorized-ssh-scan",
            "authorization_json": json.dumps(authorization()),
        }
        self.assertIsNone(
            authorized_activity_context(
                sources(query_row=mock.Mock(return_value=campaign)),
                "connection",
                selected(source_ip="10.77.7.223"),
            )
        )


if __name__ == "__main__":
    unittest.main()
