from __future__ import annotations

import copy
import datetime as dt
import inspect
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import software_inventory_response as response
from tests.test_software_inventory_api import NOW, record, state


class SoftwareInventoryResponseArchitectureTests(unittest.TestCase):
    def write_state(self, directory: str, payload: dict) -> Path:
        path = Path(directory) / "software-inventory.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        path.chmod(0o600)
        return path

    def test_public_signature_is_exact(self) -> None:
        self.assertEqual(
            str(inspect.signature(response.build_response)),
            "(path: 'Path', query: 'dict[str, list[str]] | None' = None, *, observed_at: 'dt.datetime | None' = None, maximum_bytes: 'int' = 268435456, assets: 'object' = None, asset_inventory_complete: 'bool' = False) -> 'tuple[int, dict[str, object]]'",
        )

    def test_query_error_precedes_state_loading_and_uses_default_page(self) -> None:
        naive = dt.datetime(2026, 8, 12, 7, 15, 30)
        expected_observed_at = naive.astimezone().astimezone(dt.timezone.utc)
        with mock.patch.object(
            response,
            "load_state",
            side_effect=AssertionError("state must not load"),
        ) as load_state:
            status, payload = response.build_response(
                Path("unused"),
                {"unsupported": ["value"]},
                observed_at=naive,
                maximum_bytes=17,
            )
        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "unsupported query parameter: unsupported")
        self.assertEqual(payload["warnings"], [payload["error"]])
        self.assertEqual(payload["page"], {
            "limit": 100,
            "offset": 0,
            "filtered_total": 0,
            "has_more": False,
        })
        self.assertEqual(
            payload["observed_at"],
            expected_observed_at.isoformat().replace("+00:00", "Z"),
        )
        load_state.assert_not_called()

    def test_state_error_forwards_byte_limit_and_preserves_filters(self) -> None:
        failure = response.InventoryStateError("bounded state failed")
        with mock.patch.object(
            response,
            "load_state",
            side_effect=failure,
        ) as load_state:
            status, payload = response.build_response(
                Path("inventory.json"),
                {"limit": ["7"], "offset": ["3"]},
                observed_at=NOW,
                maximum_bytes=1234,
            )
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"], "bounded state failed")
        self.assertEqual(payload["page"]["limit"], 7)
        self.assertEqual(payload["page"]["offset"], 3)
        load_state.assert_called_once_with(
            Path("inventory.json"), maximum_bytes=1234
        )

    def test_filter_matrix_and_product_tie_break_pagination_are_exact(self) -> None:
        payload = state()
        payload["records"].extend(
            [
                record(
                    "000000000000000000000005",
                    "osquery_apps",
                    "cccccccccccccccccccccccc",
                    "fireFOX",
                    version="140.0",
                ),
                record(
                    "000000000000000000000006",
                    "osquery_apps",
                    "dddddddddddddddddddddddd",
                    "Firefox",
                    version="140.0",
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_state(directory, payload)
            status, result = response.build_response(
                path,
                {
                    "confidence": ["high"],
                    "freshness": ["current"],
                    "platform": ["MACos"],
                    "search": ["FIRE"],
                    "window": ["24h"],
                    "sort": ["product"],
                    "direction": ["desc"],
                    "limit": ["2"],
                    "offset": ["1"],
                },
                observed_at=NOW,
            )
        self.assertEqual(status, 200)
        self.assertEqual(result["page"], {
            "limit": 2,
            "offset": 1,
            "filtered_total": 3,
            "has_more": False,
        })
        self.assertEqual(
            [item["evidence_id"] for item in result["items"]],
            [
                "000000000000000000000005",
                "000000000000000000000001",
            ],
        )
        self.assertEqual(result["summary"]["products"], 1)
        self.assertEqual(result["platforms"], ["macOS"])

    def test_coverage_warning_order_and_bool_denominator_are_exact(self) -> None:
        payload = state()
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_state(directory, payload)
            normalized, revision = response.load_state(path)
        normalized["collection"]["complete"] = False
        normalized["collection"]["last_error"] = (
            "scheduled source incomplete"
        )
        normalized["collection"]["osquery_ready"] = True
        for item in normalized["records"]:
            item["_last_seen"] = NOW - dt.timedelta(days=40)
            item["_first_seen"] = NOW - dt.timedelta(days=41)
        with mock.patch.object(
            response, "load_state", return_value=(normalized, revision)
        ):
            status, result = response.build_response(
                Path("inventory.json"), observed_at=NOW
            )
        self.assertEqual(status, 200)
        self.assertEqual(result["summary"]["records"], 0)
        self.assertEqual(result["coverage"]["osquery_ready"], None)
        self.assertEqual(result["coverage"]["coverage_gaps"], None)
        self.assertEqual(result["coverage"]["fresh_endpoint_inventories"], 0)
        self.assertEqual(result["coverage"]["network_observed_assets"], 0)
        self.assertEqual(
            result["warnings"],
            [
                "LAN software coverage has no authoritative asset denominator; counts describe only observable evidence.",
                "The latest collection was incomplete; showing the last valid snapshot.",
                "Latest collection warning: scheduled source incomplete",
                "No current endpoint-reported inventory is visible; passive network evidence cannot prove software is absent.",
            ],
        )

    def test_success_mutates_loaded_records_before_public_projection(self) -> None:
        loaded = state()
        internal_records = copy.deepcopy(loaded["records"])
        events: list[str] = []

        def label(items: object, assets: object, **kwargs: object) -> int:
            events.append("labels")
            self.assertIs(items, internal_records)
            return 0

        def correlate(
            items: object,
            endpoint_evidence: object,
            **kwargs: object,
        ) -> int:
            events.append("correlation")
            self.assertIs(items, internal_records)
            self.assertIs(endpoint_evidence, internal_records)
            return 0

        normalized = copy.deepcopy(loaded)
        normalized["records"] = internal_records
        for item in internal_records:
            item["_first_seen"] = dt.datetime.fromisoformat(
                str(item["first_seen"]).replace("Z", "+00:00")
            )
            item["_last_seen"] = dt.datetime.fromisoformat(
                str(item["last_seen"]).replace("Z", "+00:00")
            )
            item["asset_label"] = ""
        normalized["collection"].pop("relay_token")
        with (
            mock.patch.object(response, "load_state", return_value=(normalized, "rev")),
            mock.patch.object(response, "apply_asset_labels", side_effect=label),
            mock.patch.object(
                response,
                "correlate_asset_operating_systems",
                side_effect=correlate,
            ),
        ):
            status, result = response.build_response(
                Path("inventory.json"), observed_at=NOW
            )
        self.assertEqual(status, 200)
        self.assertEqual(events, ["labels", "correlation"])
        self.assertEqual(result["revision"], "rev")
        self.assertEqual(len(result["items"]), 4)


if __name__ == "__main__":
    unittest.main()
