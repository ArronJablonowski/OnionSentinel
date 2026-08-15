#!/usr/bin/env python3
"""Contracts for bounded, local-only AC Hunter prompt evidence."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_ac_hunter_context import (  # noqa: E402
    CONTEXT_SCHEMA,
    MAX_FINDINGS,
    build_ac_hunter_context,
)


DIGEST = "a" * 64


def snapshot(*, stale: bool = False, complete: bool = True) -> dict:
    statuses = {
        "beacons": {"status": "ok", "http_status": 200, "error": ""},
        "beacons_sni": {"status": "ok", "http_status": 200, "error": ""},
    }
    if not complete:
        statuses["beacons_sni"] = {
            "status": "failed",
            "http_status": 0,
            "error": "bounded failure",
        }
    findings = [
        {
            "id": "finding-related",
            "module": "beacons",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
            "fqdn": "updates.example.invalid",
            "port": 443,
            "protocol": "tcp",
            "score": 81,
            "priority_score": 4,
            "verdict": "needs_review",
            "reason": "Rare service; approved updater remains plausible.",
            "evidence": ["timing variance", "review the exact flow"],
            "watch_match": False,
            "count": 8,
        },
        {
            "id": "finding-unrelated",
            "module": "beacons",
            "source_ip": "203.0.113.55",
            "destination_ip": "203.0.113.56",
            "score": 99,
            "verdict": "high_concern",
            "reason": "must not enter this alert package",
        },
        {
            "id": "finding-shared-destination-only",
            "module": "beacons",
            "source_ip": "203.0.113.57",
            "destination_ip": "198.51.100.20",
            "score": 92,
            "verdict": "high_concern",
            "reason": "a shared destination is not an exact-host join",
        },
    ]
    return {
        "schema": "onion-sentinel-ac-hunter-review-v1",
        "version": 1,
        "ok": True,
        "last_pulled_at": "2026-08-14T20:00:00Z",
        "metadata": {
            "complete": complete,
            "dataset": "security-onion-rolling",
            "source": "ac-hunter",
            "source_statuses": statuses,
            "stale": stale,
            "storage_backend": "postgresql",
            "transport_path": "mac->relay->ac-hunter",
        },
        "dataset": {"name": "security-onion-rolling"},
        "time_range": {
            "start": "2026-08-13T20:00:00Z",
            "end": "2026-08-14T20:00:00Z",
        },
        "cache": {
            "status": "stale" if stale else "fresh",
            "stale": stale,
            "age_seconds": 120 if not stale else 9000,
            "ttl_seconds": 86400,
            "dataset_digest": DIGEST,
            "storage_backend": "postgresql",
        },
        "modules": {
            "beacons": {
                "status": "ok",
                "count": len(findings),
                "error": "",
                "findings": findings,
            },
            "beacons_sni": {
                "status": "ok" if complete else "failed",
                "count": 0,
                "error": "" if complete else "bounded failure",
                "findings": [],
            },
        },
        "correlated_hosts": [
            {
                "host": "192.0.2.10",
                "source_ip": "192.0.2.10",
                "modules": ["beacons", "beacons_sni"],
                "module_count": 2,
                "finding_count": 3,
                "priority_score": 4,
                "verdict": "needs_review",
                "reason": "Cross-module context; software update remains plausible.",
            },
            {
                "host": "203.0.113.55",
                "source_ip": "203.0.113.55",
                "modules": ["beacons"],
                "module_count": 1,
                "finding_count": 1,
                "priority_score": 5,
                "verdict": "high_concern",
                "reason": "unrelated",
            },
        ],
        "analyst_notes": [
            "Scores prioritize review and do not establish malware.",
            "Consider authorized software updates and shared infrastructure.",
        ],
        "disclaimer": "Behavioral context is not proof of malicious intent.",
        "counts": {"beacons": len(findings)},
    }


def response(value: dict, status: int = 200):
    encoded = json.dumps(value).encode("utf-8")
    return lambda: (status, encoded)


class PromptAcHunterContextTests(unittest.TestCase):
    def selected(self) -> dict:
        return {
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
        }

    def test_fresh_snapshot_projects_only_exact_alert_hosts_and_citation(self):
        context = build_ac_hunter_context(
            self.selected(), fetch_snapshot=response(snapshot())
        )

        self.assertEqual(context["schema"], CONTEXT_SCHEMA)
        self.assertEqual(context["status"], "fresh")
        self.assertTrue(context["available"])
        self.assertTrue(context["complete"])
        self.assertFalse(context["stale"])
        self.assertEqual(context["evidence_ref"], f"ac-hunter:{DIGEST}")
        self.assertEqual(context["evidence_digest"], DIGEST)
        self.assertEqual(context["matched_observables"], [
            "192.0.2.10", "198.51.100.20",
        ])
        self.assertEqual(
            [item["id"] for item in context["findings"]],
            ["finding-related"],
        )
        self.assertEqual(
            [item["source_ip"] for item in context["correlated_hosts"]],
            ["192.0.2.10"],
        )
        self.assertEqual(context["trust"], "untrusted_behavioral_context")
        self.assertFalse(context["malware_verdict_authority"])
        self.assertFalse(context["collection_triggered"])
        self.assertNotIn("203.0.113.55", json.dumps(context))
        self.assertNotIn("203.0.113.57", json.dumps(context))

    def test_fresh_complete_empty_scope_is_explicit_negative_context(self):
        value = snapshot()
        value["modules"]["beacons"]["findings"] = []
        value["counts"]["beacons"] = 0
        value["correlated_hosts"] = []

        context = build_ac_hunter_context(
            self.selected(), fetch_snapshot=response(value)
        )

        self.assertEqual(context["status"], "empty")
        self.assertEqual(context["returned"], 0)
        self.assertTrue(context["negative_evidence_allowed"])
        self.assertTrue(context["available"])
        self.assertEqual(context["evidence_ref"], f"ac-hunter:{DIGEST}")

    def test_stale_and_partial_states_cannot_be_negative_evidence(self):
        for value, expected in (
            (snapshot(stale=True), "stale"),
            (snapshot(complete=False), "partial"),
        ):
            with self.subTest(expected=expected):
                context = build_ac_hunter_context(
                    self.selected(), fetch_snapshot=response(value)
                )
                self.assertEqual(context["status"], expected)
                self.assertFalse(context["negative_evidence_allowed"])
                self.assertEqual(context["evidence_ref"], f"ac-hunter:{DIGEST}")

    def test_bounded_upstream_page_is_partial_even_when_requests_succeeded(self):
        value = snapshot()
        base = value["modules"]["beacons"]["findings"][0]
        value["modules"]["beacons"]["findings"] = [
            {
                **base,
                "id": f"unrelated-{index}",
                "source_ip": "203.0.113.99",
                "destination_ip": "203.0.113.100",
            }
            for index in range(100)
        ]
        value["counts"]["beacons"] = 342

        context = build_ac_hunter_context(
            self.selected(), fetch_snapshot=response(value)
        )

        self.assertEqual(context["status"], "partial")
        self.assertTrue(context["truncated"])
        self.assertFalse(context["negative_evidence_allowed"])
        beacons = next(
            item for item in context["module_statuses"]
            if item["module"] == "beacons"
        )
        self.assertTrue(beacons["source_truncated"])

    def test_not_collected_and_auth_failures_are_explicit_and_unciteable(self):
        for code, expected in ((404, "not_collected"), (401, "auth_failure"), (403, "auth_failure")):
            with self.subTest(code=code):
                context = build_ac_hunter_context(
                    self.selected(), fetch_snapshot=lambda code=code: (code, b"{}")
                )
                self.assertEqual(context["status"], expected)
                self.assertFalse(context["available"])
                self.assertEqual(context["evidence_ref"], "")
                self.assertEqual(context["findings"], [])

    def test_missing_alert_host_identity_is_unciteable(self):
        context = build_ac_hunter_context(
            {"source_ip": "", "destination_ip": ""},
            fetch_snapshot=response(snapshot()),
        )

        self.assertEqual(context["status"], "unavailable")
        self.assertFalse(context["available"])
        self.assertEqual(context["evidence_ref"], "")

    def test_malformed_or_oversized_snapshots_fail_closed_without_secret_echo(self):
        malformed = snapshot()
        malformed["cache"]["dataset_digest"] = "not-a-digest"
        malformed["password"] = "must-not-leak"
        contexts = [
            build_ac_hunter_context(
                self.selected(), fetch_snapshot=response(malformed)
            ),
            build_ac_hunter_context(
                self.selected(), fetch_snapshot=lambda: (200, b"x" * (1024 * 1024 + 1))
            ),
        ]
        for context in contexts:
            self.assertEqual(context["status"], "invalid")
            self.assertFalse(context["available"])
            self.assertNotIn("must-not-leak", json.dumps(context))

    def test_projection_bounds_findings_and_text(self):
        value = snapshot()
        value["modules"]["beacons"]["findings"] = [
            {
                **value["modules"]["beacons"]["findings"][0],
                "id": f"finding-{index:03d}",
                "reason": "r" * 5000,
            }
            for index in range(MAX_FINDINGS + 20)
        ]

        context = build_ac_hunter_context(
            self.selected(), fetch_snapshot=response(value)
        )

        self.assertEqual(len(context["findings"]), MAX_FINDINGS)
        self.assertEqual(context["status"], "partial")
        self.assertFalse(context["complete"])
        self.assertTrue(context["truncated"])
        self.assertFalse(context["negative_evidence_allowed"])
        self.assertLessEqual(len(context["findings"][0]["reason"]), 500)

    def test_composite_credential_keys_fail_closed(self):
        for key in ("api_token", "relay-password", "sessionCookie"):
            with self.subTest(key=key):
                value = snapshot()
                value[key] = "must-not-enter-the-prompt"

                context = build_ac_hunter_context(
                    self.selected(), fetch_snapshot=response(value)
                )

                self.assertEqual(context["status"], "invalid")
                self.assertFalse(context["available"])
                self.assertNotIn("must-not-enter-the-prompt", json.dumps(context))

    def test_sqlite_alert_rows_are_supported_without_mapping_get(self):
        connection = sqlite3.connect(":memory:")
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT '192.0.2.10' AS source_ip, "
            "'198.51.100.20' AS destination_ip"
        ).fetchone()
        self.addCleanup(connection.close)

        context = build_ac_hunter_context(
            row, fetch_snapshot=response(snapshot())
        )

        self.assertEqual(context["status"], "fresh")
        self.assertEqual(context["returned"], 2)


if __name__ == "__main__":
    unittest.main()
