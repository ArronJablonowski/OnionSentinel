#!/usr/bin/env python3
"""Contracts for System Health beacon-history projection."""
from __future__ import annotations

import datetime as dt
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_beacon_history import _entry, project_beacon_history  # noqa: E402


UTC = dt.timezone.utc


def parse_timestamp(value: object) -> dt.datetime:
    return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def format_timestamp(value: dt.datetime, *, timespec="seconds", utc_z=False) -> str:
    rendered = value.isoformat(timespec=timespec)
    return rendered.replace("+00:00", "Z") if utc_z else rendered


class BeaconHistoryTests(unittest.TestCase):
    def project(self, history, query=None, now=None):
        now = now or dt.datetime(2026, 8, 7, 12, 0, tzinfo=UTC)
        return project_beacon_history(
            query or {"hours": ["24"]}, history,
            now=now, generated_at="generated", history_source="history.json",
            pcap={"healthy": True}, pipeline={"available": True},
            parse_timestamp=parse_timestamp, format_timestamp=format_timestamp,
        )

    def test_window_is_defaulted_and_bounded(self) -> None:
        self.assertEqual(self.project([], {"hours": ["invalid"]})["window_hours"], 24)
        self.assertEqual(self.project([], {"hours": ["0"]})["window_hours"], 1)
        self.assertEqual(self.project([], {"hours": ["1000"]})["window_hours"], 168)

    def test_invalid_old_and_non_object_records_are_removed(self) -> None:
        payload = self.project([
            "invalid",
            {"generated_at": "invalid"},
            {"generated_at": "2026-08-05T00:00:00Z"},
            {"generated_at": "2026-08-07T11:00:00Z", "status": "ok"},
        ])
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["summary"]["successful"], 1)

    def test_previous_relay_failure_marks_recovery_record_unsuccessful(self) -> None:
        payload = self.project([{
            "generated_at": "2026-08-07T11:50:00Z",
            "status": "ok",
            "relay_previous_failure": {"http_status": 503, "summary": "relay failed"},
        }])
        entry = payload["entries"][0]
        self.assertFalse(entry["successful"])
        self.assertEqual(entry["http_status"], 503)
        self.assertEqual(entry["error"], "relay failed")

    def test_closed_and_open_gaps_are_derived_from_successes(self) -> None:
        payload = self.project([
            {"generated_at": "2026-08-07T10:00:00Z", "status": "ok"},
            {"generated_at": "2026-08-07T10:05:00Z", "status": "failed"},
            {"generated_at": "2026-08-07T10:30:00Z", "status": "ok"},
        ], now=dt.datetime(2026, 8, 7, 11, 0, tzinfo=UTC))
        self.assertEqual([gap["status"] for gap in payload["gaps"]], ["closed", "open"])
        self.assertEqual([gap["minutes"] for gap in payload["gaps"]], [30.0, 30.0])
        self.assertEqual(payload["summary"]["unsuccessful"], 1)

    def test_entries_sort_by_utc_and_summary_preserves_supplied_health(self) -> None:
        payload = self.project([
            {"generated_at": "2026-08-07T11:45:00Z", "status": 204},
            {"generated_at": "2026-08-07T11:30:00Z", "status": "200"},
        ])
        self.assertEqual(payload["entries"][0]["http_status"], 200)
        self.assertEqual(payload["entries"][1]["http_status"], 204)
        self.assertEqual(payload["pcap"], {"healthy": True})
        self.assertEqual(payload["pipeline"], {"available": True})

    def test_entry_preserves_exact_fallbacks_and_format_calls(self) -> None:
        calls = []

        def formatter(value, **kwargs):
            calls.append((value, kwargs))
            return f"formatted-{len(calls)}"

        timestamp = dt.datetime(2026, 8, 7, 11, 0, tzinfo=UTC)
        raw = {
            "status": "200",
            "first_rule": "fallback rule",
            "alert_count": 0,
            "posted_webhook_alerts": None,
        }

        entry = _entry(raw, timestamp, formatter)

        self.assertEqual(entry, {
            "timestamp": "formatted-1",
            "timestamp_utc": "formatted-2",
            "successful": True,
            "stage": "unknown",
            "status": "200",
            "message_type": "",
            "relay_host": "",
            "alert_count": 0,
            "posted_webhook_alerts": None,
            "rule_name": "fallback rule",
            "http_status": 200,
            "error": "",
            "previous_failure": None,
        })
        self.assertEqual(calls[0][1], {"timespec": "milliseconds"})
        self.assertEqual(
            calls[1],
            (timestamp, {"timespec": "milliseconds", "utc_z": True}),
        )

    def test_entry_non_mapping_previous_failure_does_not_override_error_or_success(self) -> None:
        entry = _entry(
            {
                "ok": True,
                "status": "ok",
                "error": "current failure text",
                "relay_previous_failure": ["not", "a", "mapping"],
            },
            dt.datetime(2026, 8, 7, 11, 0, tzinfo=UTC),
            format_timestamp,
        )
        self.assertFalse(entry["successful"])
        self.assertEqual(entry["error"], "current failure text")
        self.assertIsNone(entry["previous_failure"])


if __name__ == "__main__":
    unittest.main()
