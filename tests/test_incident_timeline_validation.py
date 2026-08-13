"""Characterize incident factual-timeline validation."""
from __future__ import annotations

import copy
import datetime as dt
import unittest
from unittest.mock import patch

from n8n.onion_sentinel.analysis.conclusions import incident_report


class TrackingDict(dict):
    def __init__(self, *args: object, trace: list[object], label: str, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", self.label, key, default))
        return super().get(key, default)


class TrackingTimeline(list):
    def __init__(self, values: list[object], trace: list[object]) -> None:
        super().__init__(values)
        self.trace = trace

    def __getitem__(self, key: object) -> object:
        self.trace.append(("getitem", key))
        return super().__getitem__(key)

    def __iter__(self):
        raise AssertionError("original timeline must be sliced before iteration")


class Instant:
    def __init__(
        self,
        label: str,
        trace: list[object],
        less: bool,
        *,
        error: Exception | None = None,
    ) -> None:
        self.label = label
        self.trace = trace
        self.less = less
        self.error = error

    def __lt__(self, other: object) -> bool:
        self.trace.append(("lt", self.label, getattr(other, "label", other)))
        if self.error is not None:
            raise self.error
        return self.less


class IncidentTimelineValidationTests(unittest.TestCase):
    def test_non_list_and_exact_200_item_slice_are_preserved(self) -> None:
        for timeline in (None, "timeline", (), {"item": 1}):
            with self.subTest(timeline=timeline):
                self.assertEqual(
                    incident_report._timeline_validation(
                        timeline,
                        frozenset({"low"}),
                    ),
                    (0, 0, False),
                )

        trace: list[object] = []
        timeline = TrackingTimeline([None] * 201, trace)
        self.assertEqual(
            incident_report._timeline_validation(
                timeline,
                frozenset({"low"}),
            ),
            (200, 0, False),
        )
        self.assertEqual(trace, [("getitem", slice(None, 200, None))])

    def test_required_access_order_confidence_and_timestamp_counts_are_exact(self) -> None:
        trace: list[object] = []
        valid_instant = dt.datetime(2026, 8, 13, tzinfo=dt.timezone.utc)
        invalid_required = TrackingDict(
            {"timestamp": "", "event": "unreached", "source_pack": "unreached"},
            trace=trace,
            label="invalid",
        )
        low_confidence = TrackingDict(
            {
                "timestamp": "valid-time",
                "event": "event",
                "source_pack": "source",
                "confidence": "unsupported",
            },
            trace=trace,
            label="low-confidence",
        )
        unparseable = TrackingDict(
            {
                "timestamp": "invalid-time",
                "event": "event",
                "source_pack": "source",
                "confidence": "high",
            },
            trace=trace,
            label="unparseable",
        )

        def timestamp(value):
            trace.append(("timestamp", value))
            return valid_instant if value == "valid-time" else None

        with patch.object(incident_report, "timeline_timestamp", timestamp):
            result = incident_report._timeline_validation(
                [invalid_required, low_confidence, unparseable],
                frozenset({"high"}),
            )

        self.assertEqual(result, (2, 1, False))
        self.assertEqual(trace[:2], [
            ("get", "invalid", "timestamp", None),
            ("get", "invalid", "timestamp", None),
        ])
        self.assertNotIn(("get", "invalid", "event", None), trace)
        self.assertEqual(
            [item for item in trace if item[0] == "timestamp"],
            [("timestamp", "valid-time"), ("timestamp", "invalid-time")],
        )
        valid_timestamp_index = trace.index(("timestamp", "valid-time"))
        self.assertEqual(trace[valid_timestamp_index - 2:valid_timestamp_index], [
            ("get", "low-confidence", "confidence", None),
            ("get", "low-confidence", "timestamp", None),
        ])

    def test_out_of_order_comparison_is_adjacent_lazy_and_exception_exact(self) -> None:
        trace: list[object] = []
        first = Instant("first", trace, False)
        second = Instant("second", trace, False)
        third = Instant("third", trace, True)
        fourth = Instant(
            "fourth",
            trace,
            True,
            error=AssertionError("comparison continued after disorder"),
        )
        entries = [
            {"timestamp": label, "event": "event", "source_pack": "source", "confidence": "high"}
            for label in ("first", "second", "third", "fourth")
        ]
        instants = iter([first, second, third, fourth])
        with patch.object(
            incident_report,
            "timeline_timestamp",
            side_effect=lambda _value: next(instants),
        ):
            result = incident_report._timeline_validation(
                entries,
                frozenset({"high"}),
            )
        self.assertEqual(result, (0, 0, True))
        self.assertEqual(trace, [
            ("lt", "second", "first"),
            ("lt", "third", "second"),
        ])

        trace.clear()
        exploding = Instant(
            "exploding",
            trace,
            False,
            error=RuntimeError("instant comparison failed"),
        )
        instants = iter([first, exploding])
        with patch.object(
            incident_report,
            "timeline_timestamp",
            side_effect=lambda _value: next(instants),
        ):
            with self.assertRaisesRegex(RuntimeError, "instant comparison failed"):
                incident_report._timeline_validation(
                    entries[:2],
                    frozenset({"high"}),
                )

    def test_timestamp_exception_and_input_nonmutation_are_exact(self) -> None:
        timeline = [
            {
                "timestamp": "2026-08-13T00:00:00Z",
                "event": "event",
                "source_pack": "source",
                "confidence": "high",
            }
        ]
        snapshot = copy.deepcopy(timeline)
        self.assertEqual(
            incident_report._timeline_validation(
                timeline,
                frozenset({"high"}),
            ),
            (0, 0, False),
        )
        self.assertEqual(timeline, snapshot)

        with patch.object(
            incident_report,
            "timeline_timestamp",
            side_effect=LookupError("timestamp parser failed"),
        ):
            with self.assertRaisesRegex(LookupError, "timestamp parser failed"):
                incident_report._timeline_validation(
                    timeline,
                    frozenset({"high"}),
                )


if __name__ == "__main__":
    unittest.main()
