"""Characterize trusted query-result routing into observable validation."""
from __future__ import annotations

import copy
import re
import unittest
from unittest.mock import patch

from n8n.onion_sentinel.analysis.query import observables


class TrackingResult(dict):
    def __init__(self, *args: object, trace: list[object], **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.trace = trace

    def get(self, key: object, default: object = None) -> object:
        self.trace.append(("get", key, default))
        return super().get(key, default)


class QueryObservableValidationRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = observables.ValidationPolicy(
            safe_domain_pattern=re.compile(r"[a-z0-9.-]+"),
            safe_atom_pattern=re.compile(r"[A-Za-z0-9_.:@/-]+"),
            maximum_queries_per_round=4,
        )
        self.dependencies = observables.ValidationDependencies(
            text=lambda value, limit: str(value or "")[:limit],
            evidence_ref_component=lambda value, limit: str(value)[:limit],
        )

    def validate(self, results: object, *, limit: int = 20) -> list[dict[str, str]]:
        return observables.validate(
            results,
            limit=limit,
            policy=self.policy,
            dependencies=self.dependencies,
        )

    def test_non_list_and_exhausted_limit_return_without_result_access(self) -> None:
        for value in (None, {}, (), "results", 7):
            with self.subTest(value=value):
                self.assertEqual(self.validate(value), [])

        for limit in (0, -1):
            trace: list[object] = []
            result = TrackingResult(
                {"backend": "security_onion", "status": "ok"}, trace=trace
            )
            with self.subTest(limit=limit):
                self.assertEqual(self.validate([result], limit=limit), [])
                self.assertEqual(trace, [])

    def test_backend_status_routing_order_and_first_malformed_break_are_exact(self) -> None:
        trace: list[object] = []
        routed: list[object] = []
        visited: list[object] = []
        security_ok = TrackingResult(
            {"backend": "security_onion", "status": "ok", "id": "so-ok"},
            trace=trace,
        )
        security_partial = TrackingResult(
            {"backend": "security_onion", "status": "partial", "id": "so-part"},
            trace=trace,
        )
        pcap_ok = TrackingResult(
            {"backend": "pcap_zeek", "status": "ok", "id": "pcap-ok"},
            trace=trace,
        )
        skipped = [
            TrackingResult(
                {"backend": "pcap_zeek", "status": "partial"}, trace=trace
            ),
            TrackingResult({"backend": "other", "status": "ok"}, trace=trace),
            TrackingResult(
                {"backend": "security_onion", "status": "error"}, trace=trace
            ),
        ]
        after_break = TrackingResult(
            {"backend": "security_onion", "status": "ok"}, trace=trace
        )

        def security_rows(result, policy, dependencies):
            routed.append(("security_onion", result, policy, dependencies))
            return [(result["id"], f"evidence-{result['id']}")]

        def pcap_rows(result, policy, dependencies):
            routed.append(("pcap_zeek", result, policy, dependencies))
            return [(result["id"], f"evidence-{result['id']}")]

        def visit(row, evidence, discovered, seen, limit, policy, dependencies):
            visited.append(
                (row, evidence, discovered, seen, limit, policy, dependencies)
            )
            discovered.append({"kind": "row", "value": str(row)})

        snapshot = copy.deepcopy(
            [security_ok, security_partial, pcap_ok, *skipped, None, after_break]
        )
        with (
            patch.object(observables, "_security_onion_rows", security_rows),
            patch.object(observables, "_pcap_zeek_rows", pcap_rows),
            patch.object(observables, "_visit_values", visit),
        ):
            result = self.validate(
                [security_ok, security_partial, pcap_ok, *skipped, None, after_break]
            )

        self.assertEqual(
            result,
            [
                {"kind": "row", "value": "so-ok"},
                {"kind": "row", "value": "so-part"},
                {"kind": "row", "value": "pcap-ok"},
            ],
        )
        self.assertEqual(
            [(kind, item) for kind, item, _policy, _dependencies in routed],
            [
                ("security_onion", security_ok),
                ("security_onion", security_partial),
                ("pcap_zeek", pcap_ok),
            ],
        )
        self.assertTrue(all(item[2] is self.policy for item in routed))
        self.assertTrue(all(item[3] is self.dependencies for item in routed))
        self.assertEqual(
            trace,
            [("get", key, None) for _item in range(6) for key in ("backend", "status")],
        )
        self.assertEqual([item[:2] for item in visited], [
            ("so-ok", "evidence-so-ok"),
            ("so-part", "evidence-so-part"),
            ("pcap-ok", "evidence-pcap-ok"),
        ])
        self.assertTrue(all(item[2] is visited[0][2] for item in visited))
        self.assertTrue(all(item[3] is visited[0][3] for item in visited))
        self.assertEqual(
            [dict(item) if isinstance(item, dict) else item for item in
             [security_ok, security_partial, pcap_ok, *skipped, None, after_break]],
            snapshot,
        )

    def test_all_rows_are_visited_before_outer_limit_stops_next_result(self) -> None:
        first = {"backend": "security_onion", "status": "ok"}
        second = {"backend": "security_onion", "status": "ok"}
        trace: list[object] = []

        def security_rows(result, _policy, _dependencies):
            trace.append(("rows", result))
            return [("one", "evidence-1"), ("two", "evidence-2")]

        def visit(row, evidence, discovered, _seen, limit, _policy, _dependencies):
            trace.append(("visit", row, evidence, len(discovered), limit))
            if len(discovered) < limit:
                discovered.append({"kind": "row", "value": str(row)})

        with (
            patch.object(observables, "_security_onion_rows", security_rows),
            patch.object(observables, "_visit_values", visit),
        ):
            result = self.validate([first, second], limit=1)

        self.assertEqual(result, [{"kind": "row", "value": "one"}])
        self.assertEqual(trace, [
            ("rows", first),
            ("visit", "one", "evidence-1", 0, 1),
            ("visit", "two", "evidence-2", 1, 1),
        ])

    def test_mapping_and_row_owner_exceptions_propagate_before_later_results(self) -> None:
        class ExplodingResult(dict):
            def get(self, key: object, default: object = None) -> object:
                if key == "status":
                    raise RuntimeError("status access failed")
                return super().get(key, default)

        later = {"backend": "pcap_zeek", "status": "ok"}
        with patch.object(observables, "_pcap_zeek_rows") as pcap_rows:
            with self.assertRaisesRegex(RuntimeError, "status access failed"):
                self.validate([
                    ExplodingResult(backend="security_onion", status="ok"), later
                ])
            pcap_rows.assert_not_called()

        marker = RuntimeError("security row projection failed")
        with (
            patch.object(observables, "_security_onion_rows", side_effect=marker),
            patch.object(observables, "_pcap_zeek_rows") as pcap_rows,
        ):
            with self.assertRaisesRegex(RuntimeError, "security row projection failed"):
                self.validate([
                    {"backend": "security_onion", "status": "partial"}, later
                ])
            pcap_rows.assert_not_called()


if __name__ == "__main__":
    unittest.main()
