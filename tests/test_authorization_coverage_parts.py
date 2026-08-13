"""Characterize canonical authorization coverage-parts admission."""
from __future__ import annotations

import copy
import datetime as dt
import unittest

from n8n.onion_sentinel.analysis.conclusions import authorization_evidence


class BoolProbe:
    def __init__(
        self,
        label: str,
        value: bool,
        trace: list[object],
        *,
        error: Exception | None = None,
    ) -> None:
        self.label = label
        self.value = value
        self.trace = trace
        self.error = error

    def __bool__(self) -> bool:
        self.trace.append(("bool", self.label, self))
        if self.error is not None:
            raise self.error
        return self.value


class EndProbe:
    def __init__(
        self,
        trace: list[object],
        result: object,
        *,
        error: Exception | None = None,
    ) -> None:
        self.trace = trace
        self.result = result
        self.error = error

    def __gt__(self, other: object) -> object:
        self.trace.append(("gt", self, other))
        if self.error is not None:
            raise self.error
        return self.result


class AuthorizationCoveragePartsTests(unittest.TestCase):
    @staticmethod
    def invoke(
        source_ips: object,
        destination_ips: object,
        rule_ids: object,
        source_ports: object,
        destination_ports: object,
        ranges: object,
        transports: object,
        start: object,
        end: object,
    ) -> bool:
        return authorization_evidence._coverage_parts_valid(
            source_ips,
            destination_ips,
            rule_ids,
            source_ports,
            destination_ports,
            ranges,
            transports,
            start,
            end,
        )

    def test_truthy_short_circuits_and_comparison_order_are_exact(self) -> None:
        trace: list[object] = []
        source_ips = BoolProbe("source", True, trace)
        destination_ips = BoolProbe("destination", True, trace)
        destination_ports = BoolProbe("destination_ports", True, trace)
        ranges = BoolProbe("ranges", True, trace)
        start = object()
        comparison = BoolProbe("comparison", True, trace)
        end = EndProbe(trace, comparison)

        result = self.invoke(
            source_ips,
            destination_ips,
            object(),
            object(),
            destination_ports,
            ranges,
            object(),
            start,
            end,
        )

        self.assertIs(result, True)
        self.assertEqual(
            trace,
            [
                ("bool", "source", source_ips),
                ("bool", "destination_ports", destination_ports),
                ("gt", end, start),
                ("bool", "comparison", comparison),
            ],
        )

    def test_false_first_choices_use_exact_fallback_truthiness(self) -> None:
        trace: list[object] = []
        source_ips = BoolProbe("source", False, trace)
        destination_ips = BoolProbe("destination", True, trace)
        destination_ports = BoolProbe("destination_ports", False, trace)
        ranges = BoolProbe("ranges", True, trace)
        start = object()
        comparison = BoolProbe("comparison", True, trace)
        end = EndProbe(trace, comparison)

        result = self.invoke(
            source_ips,
            destination_ips,
            object(),
            object(),
            destination_ports,
            ranges,
            object(),
            start,
            end,
        )

        self.assertIs(result, True)
        self.assertEqual(
            trace,
            [
                ("bool", "source", source_ips),
                ("bool", "destination", destination_ips),
                ("bool", "destination_ports", destination_ports),
                ("bool", "ranges", ranges),
                ("gt", end, start),
                ("bool", "comparison", comparison),
            ],
        )

    def test_false_admission_stops_all_later_truthiness_and_comparison(self) -> None:
        trace: list[object] = []
        source_ips = BoolProbe("source", False, trace)
        destination_ips = BoolProbe("destination", False, trace)
        later = BoolProbe(
            "unreached",
            True,
            trace,
            error=AssertionError("later truthiness must not run"),
        )
        end = EndProbe(
            trace,
            True,
            error=AssertionError("comparison must not run"),
        )
        self.assertIs(
            self.invoke(
                source_ips,
                destination_ips,
                object(),
                object(),
                later,
                later,
                object(),
                object(),
                end,
            ),
            False,
        )
        self.assertEqual(
            trace,
            [
                ("bool", "source", source_ips),
                ("bool", "destination", destination_ips),
                ("bool", "destination", destination_ips),
            ],
        )

        trace.clear()
        source_ips.value = True
        self.assertIs(
            self.invoke(
                source_ips,
                destination_ips,
                None,
                later,
                later,
                later,
                object(),
                object(),
                end,
            ),
            False,
        )
        self.assertEqual(trace, [("bool", "source", source_ips)])

        trace.clear()
        destination_ports = BoolProbe("destination_ports", False, trace)
        ranges = BoolProbe("ranges", False, trace)
        self.assertIs(
            self.invoke(
                source_ips,
                destination_ips,
                object(),
                object(),
                destination_ports,
                ranges,
                object(),
                object(),
                end,
            ),
            False,
        )
        self.assertEqual(
            trace,
            [
                ("bool", "source", source_ips),
                ("bool", "destination_ports", destination_ports),
                ("bool", "ranges", ranges),
                ("bool", "ranges", ranges),
            ],
        )

    def test_exceptions_plain_bool_result_and_input_nonmutation_are_exact(self) -> None:
        trace: list[object] = []
        exploding = BoolProbe(
            "source",
            True,
            trace,
            error=RuntimeError("source truthiness failed"),
        )
        with self.assertRaisesRegex(RuntimeError, "source truthiness failed"):
            self.invoke(
                exploding,
                [],
                [],
                [],
                [443],
                [],
                ["tcp"],
                object(),
                object(),
            )

        start = object()
        end = EndProbe(
            trace,
            True,
            error=LookupError("window comparison failed"),
        )
        with self.assertRaisesRegex(LookupError, "window comparison failed"):
            self.invoke(
                ["192.0.2.1"],
                [],
                ["rule-1"],
                [],
                [443],
                [],
                ["tcp"],
                start,
                end,
            )

        valid_parts = [
            ["192.0.2.1"],
            [],
            ["rule-1"],
            [],
            [443],
            [],
            ["tcp"],
        ]
        snapshot = copy.deepcopy(valid_parts)
        start_time = dt.datetime(2026, 8, 13, tzinfo=dt.timezone.utc)
        end_time = start_time + dt.timedelta(hours=1)
        result = self.invoke(*valid_parts, start_time, end_time)
        self.assertIs(type(result), bool)
        self.assertIs(result, True)
        self.assertEqual(valid_parts, snapshot)


if __name__ == "__main__":
    unittest.main()
