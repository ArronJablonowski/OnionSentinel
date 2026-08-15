from __future__ import annotations

import copy
import inspect
import sys
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import software_inventory_query as query


class SoftwareInventoryQueryFilterArchitectureTests(unittest.TestCase):
    def test_public_signature_defaults_types_and_key_order_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(query.parse_filters)),
            "(query: 'dict[str, list[str]] | None') -> 'dict[str, object]'",
        )
        expected = {
            "limit": 100,
            "offset": 0,
            "search": "",
            "tier": "all",
            "confidence": "all",
            "freshness": "all",
            "platform": "all",
            "window": "30d",
            "sort": "last_seen",
            "direction": "desc",
        }
        self.assertEqual(query.parse_filters(None), expected)
        self.assertEqual(query.parse_filters({}), expected)
        self.assertEqual(list(query.parse_filters(None)), list(expected))
        self.assertTrue(callable(query._one))

    def test_filter_phases_are_bounded_inside_the_existing_owner(self) -> None:
        source = (DASHBOARD / "software_inventory_query.py").read_text()
        self.assertLessEqual(len(source.splitlines()), 300)
        for symbol in (
            "_reject_unknown",
            "_integer_filters",
            "_search_filter",
            "_named_filters",
            "_validate_named",
        ):
            self.assertTrue(callable(getattr(query, symbol)))

    def test_all_valid_values_preserve_exact_normalization(self) -> None:
        result = query.parse_filters(
            {
                "limit": [" 250 "],
                "offset": ["50000"],
                "search": ["  FiRe Fox  "],
                "tier": [" INSTALLED "],
                "confidence": [" HIGH "],
                "freshness": [" CURRENT "],
                "platform": ["  MacOS  "],
                "window": [" 24H "],
                "sort": [" PRODUCT "],
                "direction": [" ASC "],
            }
        )
        self.assertEqual(
            result,
            {
                "limit": 250,
                "offset": 50000,
                "search": "FiRe Fox",
                "tier": "installed",
                "confidence": "high",
                "freshness": "current",
                "platform": "MacOS",
                "window": "24h",
                "sort": "product",
                "direction": "asc",
            },
        )

    def test_unknown_and_repeated_parameter_precedence_is_exact(self) -> None:
        cases = (
            (
                {"zeta": ["x"], "alpha": ["x"], "limit": ["bad"]},
                "unsupported query parameter: alpha",
            ),
            (
                {"limit": ["1", "2"]},
                "limit and offset must be integers",
            ),
            (
                {"offset": ["1", "2"]},
                "limit and offset must be integers",
            ),
            ({"search": ["x", "y"]}, "search must appear once"),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError, f"^{message}$"
                ) as caught:
                    query.parse_filters(value)
                if message == "limit and offset must be integers":
                    self.assertIsInstance(
                        caught.exception.__cause__,
                        query.InventoryQueryError,
                    )

    def test_integer_conversion_range_and_cause_are_exact(self) -> None:
        for value in ("bad", "1.5", ""):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError,
                    "^limit and offset must be integers$",
                ) as caught:
                    query.parse_filters({"limit": [value]})
                self.assertIsInstance(caught.exception.__cause__, ValueError)
        cases = (
            ({"limit": ["0"]}, "limit must be between 1 and 250"),
            ({"limit": ["251"]}, "limit must be between 1 and 250"),
            ({"offset": ["-1"]}, "offset must be between 0 and 50000"),
            ({"offset": ["50001"]}, "offset must be between 0 and 50000"),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError, f"^{message}$"
                ) as caught:
                    query.parse_filters(value)
                self.assertIsNone(caught.exception.__cause__)

    def test_search_and_platform_boundaries_are_exact(self) -> None:
        self.assertEqual(
            query.parse_filters({"search": ["x" * 253]})["search"],
            "x" * 253,
        )
        self.assertEqual(
            query.parse_filters({"platform": ["P" * 160]})["platform"],
            "P" * 160,
        )
        cases = (
            ({"search": ["x" * 254]}, "search is invalid"),
            ({"search": ["safe\x1funsafe"]}, "search is invalid"),
            ({"platform": [" "]}, "platform is invalid"),
            ({"platform": ["P" * 161]}, "platform is invalid"),
            ({"platform": ["safe\x00unsafe"]}, "platform is invalid"),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError, f"^{message}$"
                ):
                    query.parse_filters(value)

    def test_enum_error_order_and_messages_are_exact(self) -> None:
        cases = (
            ({"tier": ["bad"]}, "tier is unsupported"),
            ({"confidence": ["bad"]}, "confidence is unsupported"),
            ({"freshness": ["bad"]}, "freshness is unsupported"),
            ({"window": ["bad"]}, "window is unsupported"),
            ({"sort": ["bad"]}, "sort is unsupported"),
            ({"direction": ["bad"]}, "direction is unsupported"),
            (
                {"tier": ["bad"], "confidence": ["bad"]},
                "tier is unsupported",
            ),
        )
        for value, message in cases:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    query.InventoryQueryError, f"^{message}$"
                ):
                    query.parse_filters(value)

    def test_public_record_base_projection_contract_is_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(query._public_record)),
            "(record: 'dict[str, object]', observed_at: 'dt.datetime') -> 'dict[str, object]'",
        )
        observed_at = query.dt.datetime(
            2026, 8, 14, 1, 0, tzinfo=query.dt.timezone.utc
        )
        marker = object()
        record: dict[str, object] = {
            "_last_seen": observed_at,
            "tier": "installed",
            "source": "other",
            "marker": marker,
            "operating_system_observed_at": None,
            "operating_system_freshness": " existing ",
            "operating_system_association": 7,
            "operating_system_source": "",
            "operating_system_type": "",
            "operating_system_version": "",
            "last_seen": "2026-08-14T00:00:00Z",
            "product": "ignored",
            "category": "ignored",
            "version": "ignored",
            "_private": "secret",
        }
        before = copy.copy(record)
        with mock.patch.object(
            query, "_freshness", return_value="current"
        ) as freshness:
            public = query._public_record(record, observed_at)

        freshness.assert_called_once_with(record, observed_at)
        self.assertIsNot(public, record)
        self.assertEqual(record, before)
        self.assertIs(public["marker"], marker)
        self.assertNotIn("_last_seen", public)
        self.assertNotIn("_private", public)
        self.assertEqual(public["operating_system_observed_at"], "")
        self.assertEqual(
            public["operating_system_freshness"], " existing "
        )
        self.assertEqual(public["operating_system_association"], "7")
        self.assertNotIn("observed_user_agent", public)
        self.assertEqual(
            list(public),
            [key for key in record if not key.startswith("_")]
            + ["freshness"],
        )

    def test_public_record_endpoint_and_user_agent_projections_are_exact(self) -> None:
        observed_at = query.dt.datetime(
            2026, 8, 14, 1, 0, tzinfo=query.dt.timezone.utc
        )
        endpoint = {
            "_last_seen": observed_at,
            "tier": "installed",
            "source": "osquery_apps",
            "operating_system_source": "osquery_manager.result:host.os",
            "operating_system_type": "macOS",
            "operating_system_version": "26.0",
            "operating_system_observed_at": "old",
            "operating_system_freshness": "old",
            "operating_system_association": "direct",
            "last_seen": "endpoint:last-seen",
            "product": "",
            "category": "",
            "version": "",
        }
        with mock.patch.object(
            query, "_freshness", return_value="recent"
        ):
            public = query._public_record(endpoint, observed_at)
        self.assertEqual(
            public["operating_system_observed_at"], "endpoint:last-seen"
        )
        self.assertEqual(public["operating_system_freshness"], "recent")
        self.assertNotIn("observed_user_agent", public)

        http = {
            **endpoint,
            "source": "http_user_agent",
            "operating_system_source": "",
            "product": " Mozilla/5.0 ",
        }
        zeek = {
            **endpoint,
            "source": "zeek_software",
            "operating_system_source": "",
            "category": "HTTP::Browser",
            "version": "Agent/2.0",
        }
        with mock.patch.object(
            query, "_freshness", return_value="current"
        ):
            self.assertEqual(
                query._public_record(http, observed_at)[
                    "observed_user_agent"
                ],
                " Mozilla/5.0 ",
            )
            self.assertEqual(
                query._public_record(zeek, observed_at)[
                    "observed_user_agent"
                ],
                "Agent/2.0",
            )
            self.assertNotIn(
                "observed_user_agent",
                query._public_record(
                    {**zeek, "category": " HTTP::Browser "},
                    observed_at,
                ),
            )

    def test_public_record_evaluation_order_and_failures_are_exact(self) -> None:
        observed_at = query.dt.datetime(
            2026, 8, 14, 1, 0, tzinfo=query.dt.timezone.utc
        )
        events: list[tuple[object, ...]] = []

        class TracedKey(str):
            def startswith(self, prefix: str, *args: object) -> bool:
                events.append(("startswith", str(self), prefix, args))
                return super().startswith(prefix, *args)

        class TracedDict(dict):
            def items(self):
                events.append(("items",))
                return super().items()

            def get(self, key: object, default: object = None) -> object:
                events.append(("get", key, default))
                return super().get(key, default)

            def __getitem__(self, key: object) -> object:
                events.append(("getitem", key))
                return super().__getitem__(key)

        record = TracedDict(
            {
                TracedKey("source"): "http_user_agent",
                TracedKey("product"): "Agent",
                TracedKey("operating_system_observed_at"): "",
                TracedKey("operating_system_freshness"): "",
                TracedKey("operating_system_association"): "",
                TracedKey("operating_system_source"): "",
                TracedKey("operating_system_type"): "",
                TracedKey("operating_system_version"): "",
            }
        )

        def freshness(value: dict[str, object], when: object) -> str:
            events.append(("freshness", value is record, when))
            return "current"

        with mock.patch.object(query, "_freshness", side_effect=freshness):
            public = query._public_record(record, observed_at)
        self.assertEqual(public["observed_user_agent"], "Agent")
        self.assertEqual(events[0], ("freshness", True, observed_at))
        self.assertEqual(events[1], ("items",))
        self.assertEqual(
            [event[1] for event in events if event[0] == "startswith"],
            list(record),
        )
        self.assertEqual(
            [event for event in events if event[0] == "get"],
            [
                ("get", "operating_system_observed_at", None),
                ("get", "operating_system_freshness", None),
                ("get", "operating_system_association", None),
            ],
        )
        self.assertEqual(
            [event for event in events if event[0] == "getitem"],
            [
                ("getitem", "source"),
                ("getitem", "source"),
                ("getitem", "product"),
            ],
        )

        with mock.patch.object(
            query, "_freshness", side_effect=RuntimeError("freshness")
        ):
            with self.assertRaisesRegex(RuntimeError, "freshness"):
                query._public_record(record, observed_at)

    def test_empty_payload_schema_order_and_identity_are_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(query._empty_payload)),
            "(observed_at: 'dt.datetime', filters: 'dict[str, object]', *, error: 'str') -> 'dict[str, object]'",
        )
        observed_at = query.dt.datetime(
            2026, 8, 14, 1, 0, tzinfo=query.dt.timezone.utc
        )
        marker = object()
        filters: dict[str, object] = {
            "limit": 25,
            "offset": 50,
            "marker": marker,
        }
        error = "".join(("collector", " unavailable"))
        schema = object()
        observed_projection = object()
        with (
            mock.patch.object(query, "API_SCHEMA", schema),
            mock.patch.object(
                query, "_utc_iso", return_value=observed_projection
            ) as utc_iso,
        ):
            payload = query._empty_payload(
                observed_at, filters, error=error
            )

        utc_iso.assert_called_once_with(observed_at)
        self.assertEqual(
            list(payload),
            [
                "ok",
                "schema",
                "generated_at",
                "observed_at",
                "collection",
                "summary",
                "coverage",
                "filters",
                "platforms",
                "page",
                "items",
                "warnings",
                "revision",
                "error",
            ],
        )
        self.assertEqual(
            list(payload["collection"]),
            [
                "status",
                "complete",
                "window",
                "last_attempt_at",
                "last_success_at",
                "last_error",
                "source_statuses",
            ],
        )
        self.assertEqual(
            list(payload["summary"]),
            [
                "records",
                "products",
                "assets",
                "conflicting_records",
                "installed",
                "observed",
                "inferred",
                "current",
                "recent",
                "historical",
                "expired",
            ],
        )
        self.assertEqual(
            list(payload["coverage"]),
            [
                "authoritative_denominator",
                "denominator_status",
                "osquery_ready",
                "fresh_endpoint_inventories",
                "network_observed_assets",
                "coverage_gaps",
                "labeled_visible_records",
                "asset_label_inventory_complete",
                "asset_os_correlated_records",
            ],
        )
        self.assertEqual(
            list(payload["page"]),
            ["limit", "offset", "filtered_total", "has_more"],
        )
        self.assertIs(payload["schema"], schema)
        self.assertIs(payload["observed_at"], observed_projection)
        self.assertIs(payload["filters"], filters)
        self.assertIs(payload["collection"]["last_error"], error)
        self.assertIs(payload["warnings"][0], error)
        self.assertIs(payload["error"], error)
        self.assertEqual(payload["page"]["limit"], 25)
        self.assertEqual(payload["page"]["offset"], 50)
        self.assertIs(filters["marker"], marker)

    def test_empty_payload_mutable_containers_are_fresh_per_call(self) -> None:
        observed_at = query.dt.datetime(
            2026, 8, 14, 1, 0, tzinfo=query.dt.timezone.utc
        )
        filters: dict[str, object] = {"limit": 10, "offset": 3}
        with mock.patch.object(query, "_utc_iso", return_value="observed"):
            first = query._empty_payload(
                observed_at, filters, error="unavailable"
            )
            second = query._empty_payload(
                observed_at, filters, error="unavailable"
            )

        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        self.assertIs(first["filters"], filters)
        self.assertIs(second["filters"], filters)
        for key in (
            "collection",
            "summary",
            "coverage",
            "platforms",
            "page",
            "items",
            "warnings",
        ):
            self.assertIsNot(first[key], second[key], key)
        self.assertIsNot(
            first["collection"]["window"],
            second["collection"]["window"],
        )
        self.assertIsNot(
            first["collection"]["source_statuses"],
            second["collection"]["source_statuses"],
        )

    def test_empty_payload_evaluation_and_failure_order_is_exact(self) -> None:
        observed_at = query.dt.datetime(
            2026, 8, 14, 1, 0, tzinfo=query.dt.timezone.utc
        )
        events: list[tuple[object, ...]] = []

        class TracedFilters(dict):
            def __getitem__(self, key: object) -> object:
                events.append(("getitem", key))
                return super().__getitem__(key)

        filters = TracedFilters(limit=10, offset=20)

        def utc_iso(value: object) -> str:
            events.append(("utc_iso", value))
            return "observed"

        with mock.patch.object(query, "_utc_iso", side_effect=utc_iso):
            query._empty_payload(observed_at, filters, error="error")
        self.assertEqual(
            events,
            [
                ("utc_iso", observed_at),
                ("getitem", "limit"),
                ("getitem", "offset"),
            ],
        )

        events.clear()
        with mock.patch.object(
            query, "_utc_iso", side_effect=RuntimeError("utc")
        ):
            with self.assertRaisesRegex(RuntimeError, "utc"):
                query._empty_payload(observed_at, filters, error="error")
        self.assertEqual(events, [])

        class FailingFilters(TracedFilters):
            def __getitem__(self, key: object) -> object:
                value = super().__getitem__(key)
                if key == "limit":
                    raise RuntimeError(f"filter:{key}:{value}")
                return value

        events.clear()
        with mock.patch.object(query, "_utc_iso", side_effect=utc_iso):
            with self.assertRaisesRegex(RuntimeError, "filter:limit:10"):
                query._empty_payload(
                    observed_at,
                    FailingFilters(limit=10, offset=20),
                    error="error",
                )
        self.assertEqual(
            events,
            [("utc_iso", observed_at), ("getitem", "limit")],
        )


if __name__ == "__main__":
    unittest.main()
