from __future__ import annotations

import datetime as dt
import importlib.util
import re
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "n8n" / "bin" / "software_inventory_state_validation.py"


def load_module():
    dependency = str(MODULE_PATH.parent)
    if dependency not in sys.path:
        sys.path.insert(0, dependency)
    spec = importlib.util.spec_from_file_location(
        "software_inventory_source_status_projection_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory state validation")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventorySourceStatusProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    @staticmethod
    def status(**overrides: object) -> dict[str, object]:
        value: dict[str, object] = {
            "status": "ok",
            "complete": True,
            "pages": 2,
            "returned": 17,
            "freshness": "fresh",
            "latest_observation_at": "2026-08-12T10:11:12+00:00",
        }
        value.update(overrides)
        return value

    def test_success_projection_formats_timestamp_and_preserves_key_order(self) -> None:
        value = self.status()
        normalized = self.module.normalize_source_status(value, "osquery_apps")
        self.assertEqual(
            normalized,
            {
                "status": "ok",
                "complete": True,
                "pages": 2,
                "returned": 17,
                "freshness": "fresh",
                "latest_observation_at": "2026-08-12T10:11:12.000Z",
            },
        )
        self.assertEqual(list(normalized), list(value))
        self.assertEqual(value["latest_observation_at"], "2026-08-12T10:11:12+00:00")

    def test_normalization_dependency_call_order_and_arguments_are_exact(self) -> None:
        value = self.status()
        calls: list[tuple[object, ...]] = []
        bounded_text = self.module._bounded_text
        bounded_integer = self.module._bounded_integer
        parse_timestamp = self.module.parse_timestamp
        format_timestamp = self.module.format_timestamp

        def normalize_text(*args, **kwargs):
            calls.append(("text", args, kwargs))
            return bounded_text(*args, **kwargs)

        def normalize_integer(*args, **kwargs):
            calls.append(("integer", args, kwargs))
            return bounded_integer(*args, **kwargs)

        def parse(value: object):
            calls.append(("parse", value))
            return parse_timestamp(value)

        def format_value(value: dt.datetime):
            calls.append(("format", value))
            return format_timestamp(value)

        with (
            mock.patch.object(self.module, "_bounded_text", side_effect=normalize_text),
            mock.patch.object(self.module, "_bounded_integer", side_effect=normalize_integer),
            mock.patch.object(self.module, "parse_timestamp", side_effect=parse),
            mock.patch.object(self.module, "format_timestamp", side_effect=format_value),
        ):
            self.module.normalize_source_status(value, "osquery_apps")

        parsed = dt.datetime(2026, 8, 12, 10, 11, 12, tzinfo=dt.timezone.utc)
        self.assertEqual(
            calls,
            [
                ("text", ("ok",), {"field": "software inventory osquery_apps status", "maximum": 16, "required": True}),
                ("integer", (2,), {"field": "software inventory osquery_apps page count", "minimum": 0, "maximum": self.module.MAX_PAGES_PER_SOURCE}),
                ("integer", (17,), {"field": "software inventory osquery_apps returned count", "minimum": 0, "maximum": self.module.MAX_TOTAL_RECORDS}),
                ("text", ("fresh",), {"field": "software inventory osquery_apps freshness", "maximum": 16, "required": True}),
                ("text", ("2026-08-12T10:11:12+00:00",), {"field": "software inventory osquery_apps latest observation", "maximum": 40}),
                ("parse", "2026-08-12T10:11:12+00:00"),
                ("format", parsed),
            ],
        )

    def test_shape_status_and_completeness_error_precedence_is_exact(self) -> None:
        extra = self.status(extra=True)
        cases = [
            (None, "software inventory osquery_apps source status is invalid"),
            (extra, "software inventory osquery_apps source status is invalid"),
            (self.status(status=None), "software inventory osquery_apps status must be a string"),
            (self.status(status="partial"), "software inventory osquery_apps status is unsupported"),
            (self.status(complete=1), "software inventory osquery_apps completeness is invalid"),
        ]
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, f"^{re.escape(message)}$"):
                    self.module.normalize_source_status(value, "osquery_apps")

    def test_counter_freshness_and_timestamp_errors_are_exact_and_ordered(self) -> None:
        cases = [
            (self.status(pages=True), "software inventory osquery_apps page count must be an integer"),
            (self.status(pages=513), "software inventory osquery_apps page count must be from 0 through 512"),
            (self.status(returned=-1), "software inventory osquery_apps returned count must be from 0 through 250000"),
            (self.status(freshness=None), "software inventory osquery_apps freshness must be a string"),
            (self.status(freshness="recent"), "software inventory osquery_apps freshness is invalid"),
            (self.status(latest_observation_at=None), "software inventory osquery_apps latest observation must be a string"),
            (self.status(latest_observation_at="bad"), "Invalid isoformat string: 'bad'"),
        ]
        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, f"^{re.escape(message)}$"):
                    self.module.normalize_source_status(value, "osquery_apps")

    def test_cross_field_policy_runs_after_optional_timestamp_normalization(self) -> None:
        cases = [
            (
                self.status(complete=False),
                "software inventory osquery_apps successful status is incomplete",
            ),
            (
                self.status(status="failed", freshness="fresh"),
                "software inventory osquery_apps failed status claims freshness",
            ),
        ]
        for value, message in cases:
            with self.subTest(message=message):
                with mock.patch.object(
                    self.module,
                    "format_timestamp",
                    wraps=self.module.format_timestamp,
                ) as format_timestamp:
                    with self.assertRaisesRegex(ValueError, f"^{re.escape(message)}$"):
                        self.module.normalize_source_status(value, "osquery_apps")
                format_timestamp.assert_called_once()

    def test_empty_latest_observation_skips_timestamp_dependencies(self) -> None:
        value = self.status(latest_observation_at="", freshness="empty")
        with (
            mock.patch.object(self.module, "parse_timestamp") as parse_timestamp,
            mock.patch.object(self.module, "format_timestamp") as format_timestamp,
        ):
            normalized = self.module.normalize_source_status(value, "osquery_apps")
        self.assertEqual(normalized["latest_observation_at"], "")
        parse_timestamp.assert_not_called()
        format_timestamp.assert_not_called()


if __name__ == "__main__":
    unittest.main()
