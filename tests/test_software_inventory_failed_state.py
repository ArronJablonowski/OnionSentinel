"""Characterization for Software Inventory failed-state recovery projection."""
from __future__ import annotations

import datetime as dt
import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "software_inventory_workflow.py"


def load_module():
    dependency = str(MODULE_PATH.parent)
    if dependency not in sys.path:
        sys.path.insert(0, dependency)
    spec = importlib.util.spec_from_file_location(
        "software_inventory_failed_state_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory workflow")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryFailedStateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.now = dt.datetime(2026, 8, 13, 12, tzinfo=dt.timezone.utc)

    @staticmethod
    def previous():
        stamp = "2026-08-12T12:00:00.000Z"
        return {
            "updated_at": stamp,
            "collection": {
                "last_success_at": stamp,
                "window": {"start": "old-start", "end": "old-end"},
            },
            "records": [{"evidence_id": "a" * 24}],
        }

    def test_last_good_snapshot_preserves_exact_order_overlays_and_copies(self) -> None:
        calls = []
        previous = self.previous()
        input_state = {"raw": "previous"}
        override = {"status": "failed-source"}
        source_statuses = {
            "zeek_software": override,
            "unknown": {"status": "ignored"},
        }
        empty_values = {
            source: {"empty": source}
            for source in self.module.SOURCES
        }
        final = {"validated": True}
        validate_count = {"value": 0}

        def validate(value):
            calls.append(("validate", value))
            validate_count["value"] += 1
            return previous if validate_count["value"] == 1 else final

        def empty_status():
            source = self.module.SOURCES[
                len([call for call in calls if call[0] == "empty"])
            ]
            calls.append(("empty", source))
            return empty_values[source]

        class Error:
            def __str__(self) -> str:
                return "  synthetic\n " + "x" * 600

        with (
            mock.patch.object(
                self.module,
                "validate_state",
                side_effect=validate,
            ),
            mock.patch.object(
                self.module,
                "_empty_source_status",
                side_effect=empty_status,
            ),
            mock.patch.object(
                self.module,
                "format_timestamp",
                side_effect=lambda now: calls.append(("format", now)) or "attempt-stamp",
            ),
            mock.patch.object(
                self.module,
                "collection_window",
            ) as collection_window,
        ):
            result = self.module.failed_state(
                input_state,
                self.now,
                Error(),
                source_statuses,
            )

        self.assertIs(result, final)
        self.assertEqual(
            calls[:5],
            [
                ("validate", input_state),
                ("empty", "osquery_apps"),
                ("empty", "zeek_software"),
                ("empty", "http_user_agent"),
                ("format", self.now),
            ],
        )
        payload = calls[-1][1]
        self.assertEqual(calls[-1][0], "validate")
        self.assertEqual(payload["updated_at"], previous["updated_at"])
        self.assertEqual(
            payload["collection"]["last_success_at"],
            previous["collection"]["last_success_at"],
        )
        self.assertEqual(
            payload["collection"]["window"],
            previous["collection"]["window"],
        )
        self.assertIsNot(
            payload["collection"]["window"],
            previous["collection"]["window"],
        )
        self.assertEqual(payload["records"], previous["records"])
        self.assertIsNot(payload["records"], previous["records"])
        self.assertIs(
            payload["collection"]["source_statuses"]["zeek_software"],
            override,
        )
        self.assertIs(
            payload["collection"]["source_statuses"]["osquery_apps"],
            empty_values["osquery_apps"],
        )
        self.assertNotIn(
            "unknown",
            payload["collection"]["source_statuses"],
        )
        self.assertEqual(
            payload["collection"]["last_error"],
            ("synthetic " + "x" * 600)[:500],
        )
        collection_window.assert_not_called()

    def test_each_missing_snapshot_signal_uses_attempt_time_new_window_and_no_records(self) -> None:
        base = self.previous()
        cases = []
        missing_updated = self.previous()
        missing_updated["updated_at"] = ""
        cases.append(missing_updated)
        missing_success = self.previous()
        missing_success["collection"]["last_success_at"] = ""
        cases.append(missing_success)
        mismatched = self.previous()
        mismatched["collection"]["last_success_at"] = "different"
        cases.append(mismatched)
        missing_window = self.previous()
        missing_window["collection"]["window"] = {}
        cases.append(missing_window)

        for previous in cases:
            with self.subTest(previous=previous):
                captured = []

                def validate(value):
                    captured.append(value)
                    return previous if len(captured) == 1 else value

                with (
                    mock.patch.object(
                        self.module,
                        "validate_state",
                        side_effect=validate,
                    ),
                    mock.patch.object(
                        self.module,
                        "_empty_source_status",
                        return_value={"empty": True},
                    ),
                    mock.patch.object(
                        self.module,
                        "format_timestamp",
                        return_value="attempt-stamp",
                    ),
                    mock.patch.object(
                        self.module,
                        "collection_window",
                        return_value={"start": "new-start", "end": "new-end"},
                    ) as collection_window,
                ):
                    result = self.module.failed_state(
                        {"raw": "previous"},
                        self.now,
                        "synthetic error",
                    )
                self.assertEqual(result["updated_at"], "attempt-stamp")
                self.assertEqual(
                    result["collection"]["last_success_at"],
                    "",
                )
                self.assertEqual(
                    result["collection"]["window"],
                    {"start": "new-start", "end": "new-end"},
                )
                self.assertEqual(result["records"], [])
                collection_window.assert_called_once_with(self.now)

        self.assertTrue(base["updated_at"])

    def test_initial_validation_failure_precedes_all_projection_dependencies(self) -> None:
        original = ValueError("synthetic invalid previous state")
        with (
            mock.patch.object(
                self.module,
                "validate_state",
                side_effect=original,
            ),
            mock.patch.object(
                self.module,
                "_empty_source_status",
            ) as empty_status,
            mock.patch.object(
                self.module,
                "format_timestamp",
            ) as format_timestamp,
            mock.patch.object(
                self.module,
                "collection_window",
            ) as collection_window,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "^synthetic invalid previous state$",
            ) as raised:
                self.module.failed_state({}, self.now, "ignored")
        self.assertIs(raised.exception, original)
        empty_status.assert_not_called()
        format_timestamp.assert_not_called()
        collection_window.assert_not_called()


if __name__ == "__main__":
    unittest.main()
