"""Direct contracts for governed query scalar and time-window normalization."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "n8n"))
from onion_sentinel.analysis.query import primitives, window  # noqa: E402


class QueryContractError(ValueError):
    pass


class QueryWindowPackageTests(unittest.TestCase):
    def test_positive_integer_rejects_bool_and_out_of_range_values(self) -> None:
        for value in (True, 0, 101, "invalid"):
            with self.subTest(value=value), self.assertRaises(QueryContractError):
                primitives.positive_integer(
                    value, 25, 100, "query size", error_type=QueryContractError
                )
        self.assertEqual(
            primitives.positive_integer(None, 25, 100, "query size", error_type=QueryContractError),
            25,
        )

    def test_utc_requires_timezone_and_canonicalizes_to_utc(self) -> None:
        with self.assertRaisesRegex(QueryContractError, "UTC offset"):
            primitives.utc(
                "2026-07-24T12:00:00", "window start",
                error_type=QueryContractError,
            )
        parsed = primitives.utc(
            "2026-07-24T12:00:00-06:00", "window start",
            error_type=QueryContractError,
        )
        self.assertEqual(parsed, dt.datetime(2026, 7, 24, 18, tzinfo=dt.timezone.utc))

    def test_window_clips_to_trusted_envelope_with_explicit_audit(self) -> None:
        normalized, audit = window.normalize(
            {"start": "2026-07-24T00:00:00Z", "end": "2026-07-24T12:00:00Z"},
            time_envelope={
                "start": "2026-07-24T02:00:00Z",
                "end": "2026-07-24T10:00:00Z",
            }, error_type=QueryContractError,
        )
        self.assertEqual(normalized["start"], "2026-07-24T02:00:00.000Z")
        self.assertEqual(audit["reasons"], ["clipped_to_trusted_time_envelope"])

    def test_long_window_is_clamped_to_24_hours_nearest_alert(self) -> None:
        normalized, audit = window.normalize(
            {"start": "2026-07-23T00:00:00Z", "end": "2026-07-26T00:00:00Z"},
            time_envelope={
                "start": "2026-07-23T00:00:00Z",
                "end": "2026-07-26T00:00:00Z",
            }, error_type=QueryContractError,
        )
        start = primitives.utc(normalized["start"], "start", error_type=QueryContractError)
        end = primitives.utc(normalized["end"], "end", error_type=QueryContractError)
        self.assertEqual(end - start, dt.timedelta(hours=24))
        self.assertIn("clamped_to_24_hours_nearest_alert", audit["reasons"])

    def test_nonoverlapping_window_fails_closed(self) -> None:
        with self.assertRaisesRegex(QueryContractError, "does not overlap"):
            window.normalize(
                {"start": "2026-07-20T00:00:00Z", "end": "2026-07-20T01:00:00Z"},
                time_envelope={
                    "start": "2026-07-24T00:00:00Z",
                    "end": "2026-07-24T01:00:00Z",
                }, error_type=QueryContractError,
            )


if __name__ == "__main__":
    unittest.main()
