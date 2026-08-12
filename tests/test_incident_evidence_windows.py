"""Characterization for bounded incident-evidence window projection."""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "n8n" / "bin"
SCRIPT = BIN_DIR / "collect-incident-evidence.py"


def load_module():
    if str(BIN_DIR) not in sys.path:
        sys.path.insert(0, str(BIN_DIR))
    spec = importlib.util.spec_from_file_location("incident_evidence_windows", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


collector = load_module()


class IncidentEvidenceWindowCharacterization(unittest.TestCase):
    def test_public_surface_and_signature_are_exact(self) -> None:
        names = sorted(name for name in dir(collector) if not name.startswith("__"))
        encoded = json.dumps(names, separators=(",", ":"), sort_keys=True).encode()
        self.assertEqual(
            (len(names), hashlib.sha256(encoded).hexdigest()),
            (53, "2f885f63c1abbdea61adfc088b452bb5c4cb24e72135d23f3e741039f2c20ecc"),
        )
        self.assertEqual(
            str(inspect.signature(collector.evidence_windows)),
            "(grouped: 'list[sqlite3.Row]') -> 'tuple[list[dict[str, str]], str]'",
        )

    def test_missing_timestamps_use_one_exact_captured_utc_hour(self) -> None:
        frozen = dt.datetime(2026, 1, 2, 12, 0, tzinfo=dt.timezone.utc)
        datetime_proxy = mock.Mock(wraps=dt.datetime)
        datetime_proxy.now.return_value = frozen
        with mock.patch.object(collector.dt, "datetime", datetime_proxy):
            value = collector.evidence_windows([{"other": "ignored"}])
        self.assertEqual(
            value,
            (
                [{
                    "start": "2026-01-02T11:00:00.000Z",
                    "end": "2026-01-02T12:00:00.000Z",
                }],
                "fallback one-hour window",
            ),
        )
        datetime_proxy.now.assert_called_once_with(dt.timezone.utc)

    def test_complete_coverage_uses_sorted_extent_padding_and_day_chunks(self) -> None:
        grouped = [
            {
                "first_seen": "2026-01-02T03:00:00Z",
                "last_seen": "invalid",
                "timestamp": "2026-01-01T01:00:00-05:00",
            },
            {
                "first_seen": "2026-01-01T01:00:00Z",
                "last_seen": "2026-01-02T03:00:00Z",
            },
        ]
        self.assertEqual(
            collector.evidence_windows(grouped),
            (
                [
                    {
                        "start": "2026-01-01T00:55:00.000Z",
                        "end": "2026-01-02T00:55:00.000Z",
                    },
                    {
                        "start": "2026-01-02T00:55:00.000Z",
                        "end": "2026-01-02T03:05:00.000Z",
                    },
                ],
                "complete alert firing window",
            ),
        )

    def test_naive_and_empty_values_are_ignored_in_column_order(self) -> None:
        seen: list[object] = []
        original = collector.parse_time

        def observe(value: object):
            seen.append(value)
            return original(value)

        grouped = [{
            "timestamp": "2026-01-01T01:00:00Z",
            "first_seen": "2026-01-01T00:00:00",
            "last_seen": "",
        }]
        with mock.patch.object(collector, "parse_time", side_effect=observe):
            windows, note = collector.evidence_windows(grouped)
        self.assertEqual(
            seen,
            ["2026-01-01T00:00:00", "", "2026-01-01T01:00:00Z"],
        )
        self.assertEqual(note, "complete alert firing window")
        self.assertEqual(
            windows,
            [{
                "start": "2026-01-01T00:55:00.000Z",
                "end": "2026-01-01T01:05:00.000Z",
            }],
        )

    def test_equal_extent_guard_projects_exact_ten_minutes(self) -> None:
        with mock.patch.object(collector, "WINDOW_PADDING", dt.timedelta(0)):
            self.assertEqual(
                collector.evidence_windows(
                    [{"timestamp": "2026-01-01T01:00:00Z"}]
                ),
                (
                    [{
                        "start": "2026-01-01T01:00:00.000Z",
                        "end": "2026-01-01T01:10:00.000Z",
                    }],
                    "complete alert firing window",
                ),
            )

    def test_long_coverage_keeps_first_day_and_exact_latest_three_days(self) -> None:
        self.assertEqual(
            collector.evidence_windows(
                [{
                    "first_seen": "2026-01-01T00:00:00Z",
                    "last_seen": "2026-01-10T00:00:00Z",
                }]
            ),
            (
                [
                    {
                        "start": "2025-12-31T23:55:00.000Z",
                        "end": "2026-01-01T23:55:00.000Z",
                    },
                    {
                        "start": "2026-01-07T00:05:00.000Z",
                        "end": "2026-01-08T00:05:00.000Z",
                    },
                    {
                        "start": "2026-01-08T00:05:00.000Z",
                        "end": "2026-01-09T00:05:00.000Z",
                    },
                    {
                        "start": "2026-01-09T00:05:00.000Z",
                        "end": "2026-01-10T00:05:00.000Z",
                    },
                ],
                "bounded first-day and latest-three-day coverage; middle interval is an explicit evidence gap",
            ),
        )


if __name__ == "__main__":
    unittest.main()
