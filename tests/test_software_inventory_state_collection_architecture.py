from __future__ import annotations

import copy
import inspect
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
if str(DASHBOARD) not in sys.path:
    sys.path.insert(0, str(DASHBOARD))

import software_inventory_state as inventory_state


class SoftwareInventoryStateCollectionArchitectureTests(unittest.TestCase):
    UPDATED_AT = "2026-08-02T00:00:00Z"

    @staticmethod
    def source_statuses() -> dict[str, object]:
        return {
            "http_user_agent": {
                "status": " ok ",
                "complete": False,
                "records": -1,
                "returned": inventory_state.MAX_RECORDS + 1,
                "pages": 2,
                "freshness": "fresh",
                "latest_observation_at": "2026-08-01T03:04:05+01:00",
                "error": " bounded diagnostic ",
                "private_token": "must-not-project",
            },
            "osquery_apps": " succeeded ",
            "zeek_software": {"status": "empty"},
            "unknown_source": {
                "status": "ignored",
                "private_token": "must-not-inspect",
            },
        }

    @classmethod
    def collection(cls) -> dict[str, object]:
        return {
            "status": " succeeded ",
            "complete": True,
            "window": {
                "start": "2026-07-03T00:00:00Z",
                "end": "2026-08-02T01:00:00+01:00",
            },
            "last_attempt_at": "2026-08-02T00:30:00+00:30",
            "last_success_at": "2026-08-02T00:00:00Z",
            "last_error": " prior bounded failure ",
            "osquery_ready": 7,
            "source_statuses": cls.source_statuses(),
            "credential": "must-not-project",
        }

    def assert_state_error(
        self,
        function: object,
        value: object,
        message: str,
        *args: object,
        cause: type[BaseException] | None = None,
    ) -> None:
        with self.assertRaises(inventory_state.InventoryStateError) as caught:
            function(value, *args)  # type: ignore[operator]
        self.assertEqual(str(caught.exception), message)
        if cause is None:
            self.assertIsNone(caught.exception.__cause__)
        else:
            self.assertIsInstance(caught.exception.__cause__, cause)

    def test_private_signatures_owner_budget_and_empty_compatibility(self) -> None:
        self.assertEqual(
            str(inspect.signature(inventory_state._sanitize_source_statuses)),
            "(raw: 'object') -> 'dict[str, dict[str, object]]'",
        )
        self.assertEqual(
            str(inspect.signature(inventory_state._sanitize_collection)),
            "(raw: 'object', updated_at: 'str') -> 'dict[str, object]'",
        )
        self.assertLessEqual(
            len(
                (DASHBOARD / "software_inventory_state.py")
                .read_text()
                .splitlines()
            ),
            800,
        )
        for symbol in (
            "_source_status_counts",
            "_source_status_metadata",
            "_sanitize_source_status",
            "_collection_window",
            "_collection_projection",
            "_collection_osquery_ready",
            "_collection_times",
        ):
            self.assertTrue(callable(getattr(inventory_state, symbol)))
        self.assertEqual(inventory_state._sanitize_source_statuses(None), {})
        self.assert_state_error(
            inventory_state._sanitize_source_statuses,
            [],
            "collection.source_statuses must be an object",
        )

    def test_source_status_compatibility_projection_order_and_clamps(self) -> None:
        raw = self.source_statuses()
        before = copy.deepcopy(raw)
        result = inventory_state._sanitize_source_statuses(raw)
        self.assertEqual(raw, before)
        self.assertEqual(
            list(result),
            ["osquery_apps", "zeek_software", "http_user_agent"],
        )
        self.assertEqual(result["osquery_apps"], {"status": "succeeded"})
        self.assertEqual(result["zeek_software"], {"status": "empty"})
        self.assertEqual(
            result["http_user_agent"],
            {
                "status": "ok",
                "complete": False,
                "records": 0,
                "returned": inventory_state.MAX_RECORDS,
                "pages": 2,
                "freshness": "fresh",
                "latest_observation_at": "2026-08-01T02:04:05Z",
                "error": "bounded diagnostic",
            },
        )
        self.assertNotIn("unknown_source", result)
        self.assertNotIn("private_token", result["http_user_agent"])

    def test_source_status_type_and_counter_errors_are_exact_and_ordered(self) -> None:
        cases = (
            (
                {"osquery_apps": []},
                "collection.source_statuses.osquery_apps must be an object",
            ),
            (
                {
                    "osquery_apps": {
                        "status": "x\x00",
                        "complete": 1,
                        "records": True,
                    }
                },
                "source_statuses.osquery_apps.status is invalid",
            ),
            (
                {"osquery_apps": {"status": "ok", "complete": 1}},
                "collection.source_statuses.osquery_apps.complete must be boolean",
            ),
            (
                {
                    "osquery_apps": {
                        "status": "ok",
                        "complete": True,
                        "records": True,
                        "returned": 1.5,
                    }
                },
                "collection.source_statuses.osquery_apps.records must be an integer",
            ),
            (
                {
                    "osquery_apps": {
                        "status": "ok",
                        "records": 1,
                        "returned": 1.5,
                    }
                },
                "collection.source_statuses.osquery_apps.returned must be an integer",
            ),
        )
        for value, message in cases:
            with self.subTest(message=message):
                self.assert_state_error(
                    inventory_state._sanitize_source_statuses,
                    value,
                    message,
                )

    def test_source_status_freshness_timestamp_and_error_order_is_exact(self) -> None:
        cases = (
            (
                {
                    "osquery_apps": {
                        "status": "ok",
                        "freshness": "future",
                        "latest_observation_at": "invalid",
                    }
                },
                "collection.source_statuses.osquery_apps.freshness is invalid",
                None,
            ),
            (
                {
                    "osquery_apps": {
                        "status": "ok",
                        "freshness": "stale",
                        "latest_observation_at": "invalid",
                        "error": "x" * 301,
                    }
                },
                "source_statuses.osquery_apps.latest_observation_at is not ISO 8601",
                ValueError,
            ),
            (
                {
                    "osquery_apps": {
                        "status": "ok",
                        "freshness": "stale",
                        "latest_observation_at": "2026-08-01T00:00:00Z",
                        "error": "x" * 301,
                    }
                },
                "source_statuses.osquery_apps.error is invalid",
                None,
            ),
        )
        for value, message, cause in cases:
            with self.subTest(message=message):
                self.assert_state_error(
                    inventory_state._sanitize_source_statuses,
                    value,
                    message,
                    cause=cause,
                )

    def test_collection_projection_key_order_normalization_and_nonmutation(self) -> None:
        raw = self.collection()
        before = copy.deepcopy(raw)
        result = inventory_state._sanitize_collection(raw, self.UPDATED_AT)
        self.assertEqual(raw, before)
        self.assertEqual(
            list(result),
            [
                "status",
                "complete",
                "window",
                "last_attempt_at",
                "last_success_at",
                "last_error",
                "source_statuses",
                "osquery_ready",
            ],
        )
        self.assertEqual(result["status"], "succeeded")
        self.assertIs(result["complete"], True)
        self.assertEqual(
            result["window"],
            {
                "start": "2026-07-03T00:00:00Z",
                "end": "2026-08-02T00:00:00Z",
            },
        )
        self.assertEqual(result["last_attempt_at"], "2026-08-02T00:00:00Z")
        self.assertEqual(result["last_success_at"], self.UPDATED_AT)
        self.assertEqual(result["last_error"], "prior bounded failure")
        self.assertEqual(result["osquery_ready"], 7)
        self.assertNotIn("credential", result)

    def test_collection_fallbacks_and_optional_fields_are_exact(self) -> None:
        raw = self.collection()
        raw.pop("last_attempt_at")
        raw.pop("last_success_at")
        raw.pop("last_error")
        raw.pop("osquery_ready")
        raw.pop("source_statuses")
        complete = inventory_state._sanitize_collection(raw, "literal-fallback")
        self.assertEqual(complete["status"], "succeeded")
        self.assertEqual(complete["last_attempt_at"], "")
        self.assertEqual(complete["last_success_at"], "literal-fallback")
        self.assertEqual(complete["last_error"], "")
        self.assertEqual(complete["source_statuses"], {})
        self.assertNotIn("osquery_ready", complete)
        raw["status"] = ""
        raw["complete"] = False
        incomplete = inventory_state._sanitize_collection(raw, "unused")
        self.assertEqual(incomplete["status"], "unknown")
        self.assertEqual(incomplete["last_success_at"], "")

    def test_collection_shape_window_and_time_errors_are_exact(self) -> None:
        valid = self.collection()
        cases = (
            (None, "collection must be an object", None),
            (
                valid | {"status": "x\x00", "complete": 1},
                "collection.status is invalid",
                None,
            ),
            (
                valid | {"complete": 1},
                "collection.complete must be boolean",
                None,
            ),
            (
                valid | {"window": []},
                "collection.window must contain only start and end",
                None,
            ),
            (
                valid
                | {
                    "window": {
                        "start": "invalid",
                        "end": "also-invalid",
                    }
                },
                "collection.window.start is not ISO 8601",
                ValueError,
            ),
            (
                valid
                | {
                    "window": {
                        "start": "2026-08-02T00:00:00Z",
                        "end": "2026-08-01T00:00:00Z",
                    }
                },
                "collection.window is out of bounds",
                None,
            ),
            (
                valid
                | {
                    "window": {
                        "start": "2026-07-01T00:00:00Z",
                        "end": "2026-08-02T00:00:01Z",
                    }
                },
                "collection.window is out of bounds",
                None,
            ),
        )
        for value, message, cause in cases:
            with self.subTest(message=message):
                self.assert_state_error(
                    inventory_state._sanitize_collection,
                    value,
                    message,
                    self.UPDATED_AT,
                    cause=cause,
                )

    def test_collection_late_validation_precedence_is_exact(self) -> None:
        valid = self.collection()
        cases = (
            (
                valid
                | {
                    "last_error": "x" * 501,
                    "source_statuses": [],
                    "osquery_ready": True,
                    "last_attempt_at": "invalid",
                },
                "collection.last_error is invalid",
                None,
            ),
            (
                valid
                | {
                    "source_statuses": [],
                    "osquery_ready": True,
                    "last_attempt_at": "invalid",
                },
                "collection.source_statuses must be an object",
                None,
            ),
            (
                valid | {"osquery_ready": True, "last_attempt_at": "invalid"},
                "collection.osquery_ready is invalid",
                None,
            ),
            (
                valid
                | {
                    "osquery_ready": inventory_state.MAX_RECORDS + 1,
                    "last_attempt_at": "invalid",
                },
                "collection.osquery_ready is invalid",
                None,
            ),
            (
                valid | {"last_attempt_at": "invalid", "last_success_at": "invalid"},
                "last_attempt_at is not ISO 8601",
                ValueError,
            ),
            (
                valid | {"last_success_at": "invalid"},
                "last_success_at is not ISO 8601",
                ValueError,
            ),
        )
        for value, message, cause in cases:
            with self.subTest(message=message):
                self.assert_state_error(
                    inventory_state._sanitize_collection,
                    value,
                    message,
                    self.UPDATED_AT,
                    cause=cause,
                )


if __name__ == "__main__":
    unittest.main()
