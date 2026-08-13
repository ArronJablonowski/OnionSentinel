"""Characterize exact authorization event-to-coverage matching."""
from __future__ import annotations

import copy
import datetime as dt
import unittest
from unittest.mock import patch

from n8n.onion_sentinel.analysis.conclusions import authorization_evidence


class TrackingDict(dict):
    def __init__(
        self,
        *args: object,
        trace: list[object],
        label: str,
        **kwargs: object,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace
        self.label = label

    def __getitem__(self, key: object) -> object:
        self.trace.append(("getitem", self.label, key))
        return super().__getitem__(key)


class LowerProbe:
    def __init__(self, label: str, result: bool, trace: list[object]) -> None:
        self.label = label
        self.result = result
        self.trace = trace

    def __le__(self, other: object) -> bool:
        self.trace.append(("lower_le", self.label, other))
        return self.result


class UpperProbe:
    def __init__(self, label: str) -> None:
        self.label = label


class PortProbe:
    def __init__(self, trace: list[object], upper_results: dict[str, bool]) -> None:
        self.trace = trace
        self.upper_results = upper_results

    def __le__(self, other: object) -> bool:
        label = getattr(other, "label", "unknown")
        self.trace.append(("port_le", self, other))
        return self.upper_results[label]


class PairProbe:
    def __init__(
        self,
        label: str,
        lower_result: bool,
        upper: UpperProbe,
        trace: list[object],
    ) -> None:
        self.label = label
        self.lower = LowerProbe(label, lower_result, trace)
        self.upper = upper
        self.trace = trace

    def __iter__(self):
        self.trace.append(("pair_iter", self.label, self))
        yield self.lower
        yield self.upper


class RangeCollection(list):
    def __init__(self, values: list[object], trace: list[object]) -> None:
        super().__init__(values)
        self.trace = trace

    def __iter__(self):
        self.trace.append(("ranges_iter", self))
        return super().__iter__()


class ExplodingPair:
    def __iter__(self):
        raise AssertionError("range iteration continued after a match")


class AuthorizationEventCoverageMatchTests(unittest.TestCase):
    @staticmethod
    def times() -> tuple[dt.datetime, dt.datetime, dt.datetime]:
        start = dt.datetime(2026, 8, 13, 0, 0, tzinfo=dt.timezone.utc)
        event = start + dt.timedelta(minutes=30)
        end = start + dt.timedelta(hours=1)
        return start, event, end

    def test_conversion_and_empty_optional_mapping_access_order_are_exact(self) -> None:
        trace: list[object] = []
        start, timestamp, end = self.times()
        coverage = TrackingDict(
            {
                "authorization_start": "start-raw",
                "authorization_end": "end-raw",
                "source_ips": [],
                "destination_ips": [],
                "rule_ids": ["rule-1"],
                "source_ports": [],
                "destination_ports": [443],
                "destination_port_ranges": ExplodingPair(),
                "transport_protocols": ["tcp"],
            },
            trace=trace,
            label="coverage",
        )
        event = TrackingDict(
            {
                "timestamp": timestamp,
                "source_ip": "192.0.2.1",
                "destination_ip": "198.51.100.2",
                "source_port": 49152,
                "destination_port": 443,
                "rule_id": "rule-1",
                "transport": "tcp",
            },
            trace=trace,
            label="event",
        )

        def canonical(value: object) -> dt.datetime:
            trace.append(("canonical", value))
            return start if value == "start-raw" else end

        with patch.object(authorization_evidence, "canonical_timestamp", canonical):
            result = authorization_evidence._coverage_matches_event(coverage, event)

        self.assertIs(result, True)
        self.assertEqual(trace, [
            ("getitem", "event", "destination_port"),
            ("getitem", "coverage", "authorization_start"),
            ("canonical", "start-raw"),
            ("getitem", "coverage", "authorization_end"),
            ("canonical", "end-raw"),
            ("getitem", "event", "timestamp"),
            ("getitem", "coverage", "source_ips"),
            ("getitem", "coverage", "destination_ips"),
            ("getitem", "event", "rule_id"),
            ("getitem", "coverage", "rule_ids"),
            ("getitem", "coverage", "source_ports"),
            ("getitem", "coverage", "destination_ports"),
            ("getitem", "event", "transport"),
            ("getitem", "coverage", "transport_protocols"),
        ])

    def test_nonempty_optional_fields_repeat_coverage_access_after_event_lookup(self) -> None:
        trace: list[object] = []
        start, timestamp, end = self.times()
        coverage = TrackingDict(
            {
                "authorization_start": "start",
                "authorization_end": "end",
                "source_ips": ["192.0.2.1"],
                "destination_ips": ["198.51.100.2"],
                "rule_ids": ["rule-1"],
                "source_ports": [49152],
                "destination_ports": [443],
                "destination_port_ranges": [],
                "transport_protocols": ["tcp"],
            },
            trace=trace,
            label="coverage",
        )
        event = TrackingDict(
            {
                "timestamp": timestamp,
                "source_ip": "192.0.2.1",
                "destination_ip": "198.51.100.2",
                "source_port": 49152,
                "destination_port": 443,
                "rule_id": "rule-1",
                "transport": "tcp",
            },
            trace=trace,
            label="event",
        )
        with patch.object(
            authorization_evidence,
            "canonical_timestamp",
            side_effect=[start, end],
        ):
            self.assertIs(
                authorization_evidence._coverage_matches_event(coverage, event),
                True,
            )
        self.assertEqual(trace[3:], [
            ("getitem", "event", "timestamp"),
            ("getitem", "coverage", "source_ips"),
            ("getitem", "event", "source_ip"),
            ("getitem", "coverage", "source_ips"),
            ("getitem", "coverage", "destination_ips"),
            ("getitem", "event", "destination_ip"),
            ("getitem", "coverage", "destination_ips"),
            ("getitem", "event", "rule_id"),
            ("getitem", "coverage", "rule_ids"),
            ("getitem", "coverage", "source_ports"),
            ("getitem", "event", "source_port"),
            ("getitem", "coverage", "source_ports"),
            ("getitem", "coverage", "destination_ports"),
            ("getitem", "event", "transport"),
            ("getitem", "coverage", "transport_protocols"),
        ])

    def test_destination_ranges_are_lazy_and_chained_comparisons_are_exact(self) -> None:
        trace: list[object] = []
        start, timestamp, end = self.times()
        port = PortProbe(trace, {"upper-2": False, "upper-3": True})
        upper_1 = UpperProbe("upper-1")
        upper_2 = UpperProbe("upper-2")
        upper_3 = UpperProbe("upper-3")
        first = PairProbe("range-1", False, upper_1, trace)
        second = PairProbe("range-2", True, upper_2, trace)
        third = PairProbe("range-3", True, upper_3, trace)
        ranges = RangeCollection([first, second, third, ExplodingPair()], trace)
        coverage = TrackingDict(
            {
                "authorization_start": "start",
                "authorization_end": "end",
                "source_ips": [],
                "destination_ips": [],
                "rule_ids": ["rule-1"],
                "source_ports": [],
                "destination_ports": [],
                "destination_port_ranges": ranges,
                "transport_protocols": ["tcp"],
            },
            trace=trace,
            label="coverage",
        )
        event = TrackingDict(
            {
                "timestamp": timestamp,
                "destination_port": port,
                "rule_id": "rule-1",
                "transport": "tcp",
            },
            trace=trace,
            label="event",
        )
        with patch.object(
            authorization_evidence,
            "canonical_timestamp",
            side_effect=[start, end],
        ):
            result = authorization_evidence._coverage_matches_event(coverage, event)

        self.assertIs(result, True)
        range_trace = trace[trace.index(("getitem", "coverage", "destination_port_ranges")) + 1:]
        self.assertEqual(range_trace, [
            ("ranges_iter", ranges),
            ("pair_iter", "range-1", first),
            ("lower_le", "range-1", port),
            ("pair_iter", "range-2", second),
            ("lower_le", "range-2", port),
            ("port_le", port, upper_2),
            ("pair_iter", "range-3", third),
            ("lower_le", "range-3", port),
            ("port_le", port, upper_3),
            ("getitem", "event", "transport"),
            ("getitem", "coverage", "transport_protocols"),
        ])

    def test_assertion_short_circuit_exceptions_and_nonmutation_are_exact(self) -> None:
        trace: list[object] = []
        start, timestamp, end = self.times()
        coverage = TrackingDict(
            {"authorization_start": "start", "authorization_end": "end"},
            trace=trace,
            label="coverage",
        )
        event = TrackingDict(
            {"destination_port": 443, "timestamp": timestamp},
            trace=trace,
            label="event",
        )
        with patch.object(
            authorization_evidence,
            "canonical_timestamp",
            side_effect=[None, end],
        ) as canonical:
            with self.assertRaises(AssertionError):
                authorization_evidence._coverage_matches_event(coverage, event)
            self.assertEqual(canonical.call_count, 2)
        self.assertNotIn(("getitem", "event", "timestamp"), trace)

        valid_coverage = {
            "authorization_start": "2026-08-13T00:00:00Z",
            "authorization_end": "2026-08-13T01:00:00Z",
            "source_ips": ["192.0.2.1"],
            "destination_ips": ["198.51.100.2"],
            "rule_ids": ["rule-1"],
            "source_ports": [49152],
            "destination_ports": [443],
            "destination_port_ranges": [],
            "transport_protocols": ["tcp"],
        }
        valid_event = {
            "timestamp": timestamp,
            "source_ip": "192.0.2.1",
            "destination_ip": "198.51.100.2",
            "source_port": 49152,
            "destination_port": 443,
            "rule_id": "rule-1",
            "transport": "tcp",
        }
        snapshot = copy.deepcopy((valid_coverage, valid_event))
        result = authorization_evidence._coverage_matches_event(
            valid_coverage,
            valid_event,
        )
        self.assertIs(type(result), bool)
        self.assertIs(result, True)
        self.assertEqual((valid_coverage, valid_event), snapshot)

        class ExplodingEvent(dict):
            def __getitem__(self, key: object) -> object:
                raise LookupError("event access failed")

        with self.assertRaisesRegex(LookupError, "event access failed"):
            authorization_evidence._coverage_matches_event(
                valid_coverage,
                ExplodingEvent(valid_event),
            )

        outside = dict(valid_event, timestamp=start - dt.timedelta(seconds=1))
        class LaterCoverage(dict):
            def __getitem__(self, key: object) -> object:
                if key == "source_ips":
                    raise AssertionError("window mismatch must stop later matching")
                return super().__getitem__(key)

        self.assertIs(
            authorization_evidence._coverage_matches_event(
                LaterCoverage(valid_coverage),
                outside,
            ),
            False,
        )


if __name__ == "__main__":
    unittest.main()
