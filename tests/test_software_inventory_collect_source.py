"""Characterization for paginated Software Inventory source collection."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
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
        "software_inventory_collect_source_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory workflow")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryCollectSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.now = dt.datetime(2026, 8, 12, 12, tzinfo=dt.timezone.utc)

    @staticmethod
    def config(**changes):
        value = {
            "max_pages_per_source": 4,
            "page_size": 2,
            "timeout_seconds": 120,
        }
        value.update(changes)
        return value

    @staticmethod
    def record(evidence: str, last_seen: str):
        return {
            "evidence_id": evidence * 24,
            "last_seen": last_seen,
        }

    def test_two_page_success_preserves_exact_call_and_admission_order(self) -> None:
        calls = []
        window = {"start": "start", "end": "end"}
        cursor = {"z": "last", "a": "first"}
        first_record = self.record("a", "2026-08-12T10:00:00.000Z")
        newer_record = self.record("b", "2026-08-12T11:00:00.000Z")
        older_record = self.record("c", "2026-08-12T09:00:00.000Z")
        raw_pages = ({"raw": 1}, {"raw": 2})
        validated_pages = (
            {
                "records": [first_record, newer_record],
                "complete": False,
                "after": cursor,
            },
            {
                "records": [older_record],
                "complete": True,
                "after": None,
            },
        )

        def fetch(config, source, requested_window, page_size, after, timeout):
            calls.append(
                (
                    "fetch",
                    config,
                    source,
                    requested_window,
                    page_size,
                    after,
                    timeout,
                )
            )
            return raw_pages[len([call for call in calls if call[0] == "fetch"]) - 1]

        def validate(value, **kwargs):
            calls.append(("validate", value, kwargs))
            return validated_pages[len([call for call in calls if call[0] == "validate"]) - 1]

        expected_status = {"status": "projected"}

        def source_status(**kwargs):
            calls.append(("status", kwargs))
            return expected_status

        config = self.config()
        with (
            mock.patch.object(
                self.module.time,
                "monotonic",
                side_effect=(100.0, 170.0),
            ),
            mock.patch.object(
                self.module,
                "validate_response",
                side_effect=validate,
            ),
            mock.patch.object(
                self.module,
                "_source_status",
                side_effect=source_status,
            ),
        ):
            records, status = self.module.collect_source(
                config,
                "zeek_software",
                window,
                self.now,
                200.0,
                page_fetcher=fetch,
            )

        self.assertEqual(records, [first_record, newer_record, older_record])
        self.assertIs(status, expected_status)
        self.assertEqual(
            calls,
            [
                (
                    "fetch",
                    config,
                    "zeek_software",
                    window,
                    2,
                    None,
                    100.0,
                ),
                (
                    "validate",
                    raw_pages[0],
                    {
                        "expected_source": "zeek_software",
                        "expected_window": window,
                        "requested_page_size": 2,
                        "previous_after": None,
                    },
                ),
                (
                    "fetch",
                    config,
                    "zeek_software",
                    window,
                    2,
                    cursor,
                    30.0,
                ),
                (
                    "validate",
                    raw_pages[1],
                    {
                        "expected_source": "zeek_software",
                        "expected_window": window,
                        "requested_page_size": 2,
                        "previous_after": cursor,
                    },
                ),
                (
                    "status",
                    {
                        "status": "ok",
                        "complete": True,
                        "pages": 2,
                        "returned": 3,
                        "latest": "2026-08-12T11:00:00.000Z",
                        "now": self.now,
                    },
                ),
            ],
        )

    def test_validation_failure_wraps_after_zero_admitted_pages(self) -> None:
        original = UnicodeError("synthetic decode")
        expected_status = {"status": "failed-projection"}
        with (
            mock.patch.object(self.module.time, "monotonic", return_value=10.0),
            mock.patch.object(
                self.module,
                "validate_response",
                side_effect=original,
            ),
            mock.patch.object(
                self.module,
                "_source_status",
                return_value=expected_status,
            ) as source_status,
        ):
            with self.assertRaisesRegex(
                self.module.SoftwareInventoryError,
                "^UnicodeError: synthetic decode$",
            ) as raised:
                self.module.collect_source(
                    self.config(),
                    "zeek_software",
                    {"start": "start", "end": "end"},
                    self.now,
                    20.0,
                    page_fetcher=lambda *args: {"raw": True},
                )
        self.assertIs(raised.exception.__cause__, original)
        self.assertEqual(
            raised.exception.source_statuses,
            {"zeek_software": expected_status},
        )
        source_status.assert_called_once_with(
            status="failed",
            complete=False,
            pages=0,
            returned=0,
            latest="",
            now=self.now,
        )

    def test_budget_failure_precedes_fetch_and_retains_exact_status(self) -> None:
        fetch = mock.Mock()
        expected_status = {"status": "failed-projection"}
        with (
            mock.patch.object(self.module.time, "monotonic", return_value=19.0),
            mock.patch.object(
                self.module,
                "_source_status",
                return_value=expected_status,
            ) as source_status,
        ):
            with self.assertRaisesRegex(
                self.module.SoftwareInventoryError,
                "^software inventory collection exceeded its wall-clock budget$",
            ) as raised:
                self.module.collect_source(
                    self.config(),
                    "zeek_software",
                    {"start": "start", "end": "end"},
                    self.now,
                    20.0,
                    page_fetcher=fetch,
                )
        fetch.assert_not_called()
        self.assertIsInstance(
            raised.exception.__cause__,
            self.module.SoftwareInventoryError,
        )
        self.assertEqual(
            raised.exception.source_statuses,
            {"zeek_software": expected_status},
        )
        source_status.assert_called_once_with(
            status="failed",
            complete=False,
            pages=0,
            returned=0,
            latest="",
            now=self.now,
        )

    def test_page_limit_retains_admitted_count_latest_and_canonical_cursor(self) -> None:
        record = self.record("a", "2026-08-12T11:00:00.000Z")
        cursor = {"z": "last", "a": "first"}
        expected_status = {"status": "failed-projection"}
        fetch = mock.Mock(return_value={"raw": True})
        with (
            mock.patch.object(self.module.time, "monotonic", return_value=10.0),
            mock.patch.object(
                self.module,
                "validate_response",
                return_value={
                    "records": [record],
                    "complete": False,
                    "after": cursor,
                },
            ),
            mock.patch.object(
                self.module.json,
                "dumps",
                wraps=json.dumps,
            ) as dumps,
            mock.patch.object(
                self.module,
                "_source_status",
                return_value=expected_status,
            ) as source_status,
        ):
            with self.assertRaisesRegex(
                self.module.SoftwareInventoryError,
                "^software inventory source exceeded its page limit$",
            ):
                self.module.collect_source(
                    self.config(max_pages_per_source=1),
                    "zeek_software",
                    {"start": "start", "end": "end"},
                    self.now,
                    20.0,
                    page_fetcher=fetch,
                )
        dumps.assert_called_once_with(
            cursor,
            separators=(",", ":"),
            sort_keys=True,
        )
        source_status.assert_called_once_with(
            status="failed",
            complete=False,
            pages=1,
            returned=1,
            latest="2026-08-12T11:00:00.000Z",
            now=self.now,
        )

    def test_duplicate_and_record_limit_failures_keep_partial_admission(self) -> None:
        first = self.record("a", "2026-08-12T10:00:00.000Z")
        duplicate = self.record("a", "2026-08-12T11:00:00.000Z")
        expected_status = {"status": "failed-projection"}
        pages = iter(
            (
                {"records": [first], "complete": False, "after": {"page": 1}},
                {"records": [duplicate], "complete": True, "after": None},
            )
        )
        with (
            mock.patch.object(self.module.time, "monotonic", return_value=10.0),
            mock.patch.object(
                self.module,
                "validate_response",
                side_effect=lambda *args, **kwargs: next(pages),
            ),
            mock.patch.object(
                self.module,
                "_source_status",
                return_value=expected_status,
            ) as source_status,
        ):
            with self.assertRaisesRegex(
                self.module.SoftwareInventoryError,
                "repeated an evidence identity",
            ):
                self.module.collect_source(
                    self.config(),
                    "zeek_software",
                    {"start": "start", "end": "end"},
                    self.now,
                    20.0,
                    page_fetcher=lambda *args: {"raw": True},
                )
        source_status.assert_called_once_with(
            status="failed",
            complete=False,
            pages=2,
            returned=1,
            latest="2026-08-12T10:00:00.000Z",
            now=self.now,
        )

        source_status.reset_mock()
        with (
            mock.patch.object(self.module.time, "monotonic", return_value=10.0),
            mock.patch.object(self.module, "MAX_TOTAL_RECORDS", 1),
            mock.patch.object(
                self.module,
                "validate_response",
                return_value={
                    "records": [first, self.record("b", "2026-08-12T11:00:00.000Z")],
                    "complete": True,
                    "after": None,
                },
            ),
            mock.patch.object(
                self.module,
                "_source_status",
                return_value=expected_status,
            ) as record_limit_status,
        ):
            with self.assertRaisesRegex(
                self.module.SoftwareInventoryError,
                "exceeded the record limit",
            ):
                self.module.collect_source(
                    self.config(),
                    "zeek_software",
                    {"start": "start", "end": "end"},
                    self.now,
                    20.0,
                    page_fetcher=lambda *args: {"raw": True},
                )
        record_limit_status.assert_called_once_with(
            status="failed",
            complete=False,
            pages=1,
            returned=2,
            latest="2026-08-12T11:00:00.000Z",
            now=self.now,
        )


if __name__ == "__main__":
    unittest.main()
