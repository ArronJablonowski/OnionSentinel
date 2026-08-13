"""Characterization for complete Software Inventory snapshot composition."""
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
        "software_inventory_collect_snapshot_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory workflow")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryCollectSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.now = dt.datetime(2026, 8, 12, 12, tzinfo=dt.timezone.utc)

    @staticmethod
    def record(source, evidence, asset, product, version):
        return {
            "source": source,
            "evidence_id": evidence * 24,
            "asset_ref": asset,
            "product": product,
            "version": version,
        }

    def test_success_preserves_source_order_deadline_sort_and_payload(self) -> None:
        calls = []
        window = {"start": "start", "end": "end"}
        records_by_source = {
            "osquery_apps": [
                self.record("osquery_apps", "c", "host-b", "Zulu", "2")
            ],
            "zeek_software": [
                self.record("zeek_software", "a", "10.0.0.2", "Alpha", "1")
            ],
            "http_user_agent": [
                self.record("http_user_agent", "b", "10.0.0.1", "Beta", "")
            ],
        }
        statuses = {
            source: {"status": source}
            for source in self.module.SOURCES
        }
        empty = {
            source: {"empty": source}
            for source in self.module.SOURCES
        }
        validated = {"validated": True}

        def empty_status():
            source = self.module.SOURCES[
                len([call for call in calls if call[0] == "empty"])
            ]
            value = empty[source]
            calls.append(("empty", source, value))
            return value

        def collect(config, source, requested_window, now, deadline, **kwargs):
            calls.append(
                (
                    "collect",
                    config,
                    source,
                    requested_window,
                    now,
                    deadline,
                    kwargs,
                )
            )
            return records_by_source[source], statuses[source]

        def format_value(now):
            calls.append(("format", now))
            return "formatted-stamp"

        def validate(payload):
            calls.append(("validate", payload))
            return validated

        config = {"max_collection_seconds": 900}
        fetcher = mock.Mock(name="page_fetcher")
        with (
            mock.patch.object(
                self.module,
                "collection_window",
                side_effect=lambda now: calls.append(("window", now)) or window,
            ),
            mock.patch.object(
                self.module.time,
                "monotonic",
                side_effect=lambda: calls.append(("time",)) or 100.0,
            ),
            mock.patch.object(
                self.module,
                "_empty_source_status",
                side_effect=empty_status,
            ),
            mock.patch.object(
                self.module,
                "collect_source",
                side_effect=collect,
            ),
            mock.patch.object(
                self.module,
                "format_timestamp",
                side_effect=format_value,
            ),
            mock.patch.object(
                self.module,
                "validate_state",
                side_effect=validate,
            ),
        ):
            result = self.module.collect_snapshot(
                config,
                {"must": "remain unread"},
                self.now,
                page_fetcher=fetcher,
            )

        self.assertIs(result, validated)
        self.assertEqual(calls[0:5], [
            ("window", self.now),
            ("time",),
            ("empty", "osquery_apps", empty["osquery_apps"]),
            ("empty", "zeek_software", empty["zeek_software"]),
            ("empty", "http_user_agent", empty["http_user_agent"]),
        ])
        self.assertEqual(
            [call[2] for call in calls if call[0] == "collect"],
            list(self.module.SOURCES),
        )
        for call in (call for call in calls if call[0] == "collect"):
            self.assertEqual(call[3:6], (window, self.now, 1000.0))
            self.assertEqual(call[6], {"page_fetcher": fetcher})
        self.assertEqual(calls[-2], ("format", self.now))
        payload = calls[-1][1]
        self.assertEqual(calls[-1][0], "validate")
        self.assertEqual(
            payload,
            {
                "schema": self.module.STATE_SCHEMA,
                "version": 1,
                "updated_at": "formatted-stamp",
                "collection": {
                    "status": "ok",
                    "last_attempt_at": "formatted-stamp",
                    "last_success_at": "formatted-stamp",
                    "last_error": "",
                    "window": window,
                    "source_statuses": statuses,
                    "complete": True,
                },
                "records": [
                    records_by_source["http_user_agent"][0],
                    records_by_source["zeek_software"][0],
                    records_by_source["osquery_apps"][0],
                ],
            },
        )

    def test_endpoint_cache_bypasses_only_osquery_and_projects_readiness(self) -> None:
        endpoint_record = self.record(
            "osquery_apps", "a", "host-a", "Endpoint", "1"
        )
        endpoint_cache = {
            "records": [endpoint_record],
            "updated_at": "2026-08-12T11:30:00.000Z",
            "targets": 7,
        }
        collected = []

        def collect(config, source, window, now, deadline, **kwargs):
            collected.append(source)
            return [], {"status": source}

        with (
            mock.patch.object(
                self.module,
                "collection_window",
                return_value={"start": "start", "end": "end"},
            ),
            mock.patch.object(self.module.time, "monotonic", return_value=100.0),
            mock.patch.object(
                self.module,
                "_empty_source_status",
                return_value={"empty": True},
            ),
            mock.patch.object(
                self.module,
                "_source_status",
                return_value={"status": "endpoint"},
            ) as source_status,
            mock.patch.object(
                self.module,
                "collect_source",
                side_effect=collect,
            ),
            mock.patch.object(
                self.module,
                "format_timestamp",
                return_value="formatted-stamp",
            ),
            mock.patch.object(
                self.module,
                "validate_state",
                side_effect=lambda value: value,
            ),
        ):
            result = self.module.collect_snapshot(
                {"max_collection_seconds": 900},
                {},
                self.now,
                page_fetcher=mock.Mock(),
                endpoint_cache=endpoint_cache,
            )

        self.assertEqual(collected, ["zeek_software", "http_user_agent"])
        source_status.assert_called_once_with(
            status="ok",
            complete=True,
            pages=1,
            returned=1,
            latest="2026-08-12T11:30:00.000Z",
            now=self.now,
        )
        self.assertEqual(result["collection"]["osquery_ready"], 7)
        self.assertIs(result["records"][0], endpoint_record)

    def test_source_failure_merges_partial_statuses_and_preserves_cause(self) -> None:
        initial = {
            source: {"empty": source}
            for source in self.module.SOURCES
        }
        count = {"value": 0}

        def empty_status():
            source = self.module.SOURCES[count["value"]]
            count["value"] += 1
            return initial[source]

        source_failure = {"osquery_apps": {"status": "failed-source"}}
        original = self.module.SoftwareInventoryError(
            "synthetic source failure",
            source_failure,
        )
        with (
            mock.patch.object(
                self.module,
                "collection_window",
                return_value={"start": "start", "end": "end"},
            ),
            mock.patch.object(self.module.time, "monotonic", return_value=100.0),
            mock.patch.object(
                self.module,
                "_empty_source_status",
                side_effect=empty_status,
            ),
            mock.patch.object(
                self.module,
                "collect_source",
                side_effect=original,
            ),
        ):
            with self.assertRaisesRegex(
                self.module.SoftwareInventoryError,
                "^synthetic source failure$",
            ) as raised:
                self.module.collect_snapshot(
                    {"max_collection_seconds": 900},
                    {},
                    self.now,
                )
        self.assertIs(raised.exception.__cause__, original)
        self.assertEqual(
            raised.exception.source_statuses,
            {
                "osquery_apps": source_failure["osquery_apps"],
                "zeek_software": initial["zeek_software"],
                "http_user_agent": initial["http_user_agent"],
            },
        )

    def test_cross_source_duplicate_and_limit_fail_after_status_assignment(self) -> None:
        duplicate = self.record(
            "zeek_software", "a", "10.0.0.1", "Example", "1"
        )
        status_calls = []

        def collect(config, source, window, now, deadline, **kwargs):
            status = {"status": source}
            status_calls.append((source, status))
            return [dict(duplicate, source=source)], status

        with (
            mock.patch.object(
                self.module,
                "collection_window",
                return_value={"start": "start", "end": "end"},
            ),
            mock.patch.object(self.module.time, "monotonic", return_value=100.0),
            mock.patch.object(
                self.module,
                "_empty_source_status",
                return_value={"empty": True},
            ),
            mock.patch.object(
                self.module,
                "collect_source",
                side_effect=collect,
            ),
        ):
            with self.assertRaisesRegex(
                self.module.SoftwareInventoryError,
                "snapshot repeated an evidence identity",
            ) as raised:
                self.module.collect_snapshot(
                    {"max_collection_seconds": 900},
                    {},
                    self.now,
                )
        self.assertIsNone(raised.exception.__cause__)
        self.assertEqual(
            raised.exception.source_statuses["osquery_apps"],
            status_calls[0][1],
        )
        self.assertEqual(
            raised.exception.source_statuses["zeek_software"],
            status_calls[1][1],
        )

        unique_records = iter(
            (
                [self.record("osquery_apps", "a", "host", "A", "1")],
                [self.record("zeek_software", "b", "10.0.0.1", "B", "1")],
            )
        )
        with (
            mock.patch.object(
                self.module,
                "collection_window",
                return_value={"start": "start", "end": "end"},
            ),
            mock.patch.object(self.module.time, "monotonic", return_value=100.0),
            mock.patch.object(self.module, "MAX_TOTAL_RECORDS", 1),
            mock.patch.object(
                self.module,
                "_empty_source_status",
                return_value={"empty": True},
            ),
            mock.patch.object(
                self.module,
                "collect_source",
                side_effect=lambda *args, **kwargs: (
                    next(unique_records),
                    {"status": args[1]},
                ),
            ),
        ):
            with self.assertRaisesRegex(
                self.module.SoftwareInventoryError,
                "snapshot exceeded the record limit",
            ) as limited:
                self.module.collect_snapshot(
                    {"max_collection_seconds": 900},
                    {},
                    self.now,
                )
        self.assertEqual(
            set(limited.exception.source_statuses),
            set(self.module.SOURCES),
        )


if __name__ == "__main__":
    unittest.main()
