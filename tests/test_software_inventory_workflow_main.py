"""Characterization for the Software Inventory workflow composition root."""
from __future__ import annotations

import contextlib
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
        "software_inventory_workflow_main_target",
        MODULE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load Software Inventory workflow")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SoftwareInventoryWorkflowMainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()
        cls.now = dt.datetime(2026, 8, 13, 12, tzinfo=dt.timezone.utc)

    def patches(self, calls, *, previous, config):
        module = self.module

        class Logger:
            def __init__(self, path, *, service):
                calls.append(("logger.init", path, service))

            def log(self, level, event, **fields):
                calls.append(("logger.log", level, event, fields))

        @contextlib.contextmanager
        def lock(path):
            calls.append(("lock.enter", path))
            try:
                yield
            finally:
                calls.append(("lock.exit", path))

        return (
            mock.patch.object(module, "SecurityJsonlLogger", Logger),
            mock.patch.object(
                module,
                "utc_now",
                side_effect=lambda: calls.append(("utc_now",)) or self.now,
            ),
            mock.patch.object(module, "collector_lock", side_effect=lock),
            mock.patch.object(
                module,
                "load_state",
                side_effect=lambda path: calls.append(("load_state", path))
                or previous,
            ),
            mock.patch.object(
                module,
                "load_config",
                side_effect=lambda path: calls.append(("load_config", path))
                or config,
            ),
        )

    @staticmethod
    def argv():
        return [
            "--config",
            "/runtime/config.json",
            "--state",
            "/runtime/state.json",
            "--log",
            "/runtime/log.jsonl",
            "--env",
            "/runtime/.env",
            "--endpoint-cache",
            "/runtime/cache.json",
            "--database-api-url",
            "http://database.invalid:9999/",
        ]

    def test_success_preserves_exact_side_effect_order_and_arguments(self) -> None:
        calls = []
        previous = {"records": [{"old": True}]}
        config = {"enabled": True}
        endpoint_cache = {"cache": True}
        updated = {
            "records": [{"one": 1}, {"two": 2}],
            "collection": {"source_statuses": {"source": {"status": "ok"}}},
        }

        def atomic_write(path, value):
            calls.append(("atomic_write_json", path, value))

        patches = self.patches(calls, previous=previous, config=config)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            mock.patch.object(
                self.module,
                "load_endpoint_cache",
                side_effect=lambda path, now: calls.append(
                    ("load_endpoint_cache", path, now)
                )
                or endpoint_cache,
            ),
            mock.patch.object(
                self.module,
                "collect_snapshot",
                side_effect=lambda cfg, old, now, *, endpoint_cache: calls.append(
                    ("collect_snapshot", cfg, old, now, endpoint_cache)
                )
                or updated,
            ),
            mock.patch.object(
                self.module,
                "database_write_token",
                side_effect=lambda path: calls.append(
                    ("database_write_token", path)
                )
                or "private-token",
            ),
            mock.patch.object(
                self.module,
                "publish_database_snapshot",
                side_effect=lambda state, *, api_url, token: calls.append(
                    ("publish_database_snapshot", state, api_url, token)
                )
                or {"snapshot_id": "snapshot-1"},
            ),
            mock.patch.object(
                self.module,
                "atomic_write_json",
                side_effect=atomic_write,
            ),
        ):
            result = self.module.main(self.argv())

        self.assertEqual(result, 0)
        self.assertEqual(
            [call[0] for call in calls],
            [
                "logger.init",
                "utc_now",
                "lock.enter",
                "load_state",
                "load_config",
                "load_endpoint_cache",
                "collect_snapshot",
                "database_write_token",
                "publish_database_snapshot",
                "atomic_write_json",
                "logger.log",
                "lock.exit",
            ],
        )
        self.assertEqual(calls[0][1:], (Path("/runtime/log.jsonl"), "software-inventory"))
        self.assertEqual(calls[5][1:], (Path("/runtime/cache.json"), self.now))
        self.assertEqual(
            calls[6][1:],
            (config, previous, self.now, endpoint_cache),
        )
        self.assertEqual(calls[7][1], Path("/runtime/.env"))
        self.assertEqual(
            calls[8][1:],
            (updated, "http://database.invalid:9999/", "private-token"),
        )
        self.assertEqual(calls[9][1:], (Path("/runtime/state.json"), updated))
        self.assertEqual(
            calls[10][1:],
            (
                "info",
                "software_inventory.completed",
                {
                    "returned": 2,
                    "storage_backend": "postgresql",
                    "snapshot_id": "snapshot-1",
                    "source_statuses": updated["collection"]["source_statuses"],
                },
            ),
        )

    def test_disabled_mode_persists_without_cache_database_or_credentials(self) -> None:
        calls = []
        previous = {"records": [{"old": True}]}
        config = {"enabled": False}
        updated = {"records": [{"retained": True}]}
        patches = self.patches(calls, previous=previous, config=config)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            mock.patch.object(
                self.module,
                "disabled_state",
                side_effect=lambda old, now: calls.append(
                    ("disabled_state", old, now)
                )
                or updated,
            ),
            mock.patch.object(
                self.module,
                "atomic_write_json",
                side_effect=lambda path, value: calls.append(
                    ("atomic_write_json", path, value)
                ),
            ),
            mock.patch.object(self.module, "load_endpoint_cache") as cache,
            mock.patch.object(self.module, "collect_snapshot") as collect,
            mock.patch.object(self.module, "database_write_token") as token,
            mock.patch.object(self.module, "publish_database_snapshot") as publish,
        ):
            result = self.module.main(self.argv())

        self.assertEqual(result, 0)
        self.assertEqual(
            [call[0] for call in calls],
            [
                "logger.init",
                "utc_now",
                "lock.enter",
                "load_state",
                "load_config",
                "disabled_state",
                "atomic_write_json",
                "logger.log",
                "lock.exit",
            ],
        )
        self.assertEqual(
            calls[7][1:],
            (
                "info",
                "software_inventory.disabled",
                {"retained": 1},
            ),
        )
        cache.assert_not_called()
        collect.assert_not_called()
        token.assert_not_called()
        publish.assert_not_called()

    def test_inventory_error_settles_after_unlock_with_source_statuses(self) -> None:
        calls = []
        previous = {"records": [{"old": 1}, {"old": 2}]}
        config = {"enabled": True}
        statuses = {"osquery_apps": {"status": "failed"}}
        error = self.module.SoftwareInventoryError(
            "  failed\n" + "x" * 600,
            statuses,
        )
        failed = {"records": [{"retained": True}]}
        patches = self.patches(calls, previous=previous, config=config)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            mock.patch.object(
                self.module,
                "load_endpoint_cache",
                side_effect=lambda path, now: calls.append(
                    ("load_endpoint_cache", path, now)
                )
                or {},
            ),
            mock.patch.object(
                self.module,
                "collect_snapshot",
                side_effect=error,
            ),
            mock.patch.object(
                self.module,
                "failed_state",
                side_effect=lambda old, now, message, source_statuses: calls.append(
                    ("failed_state", old, now, message, source_statuses)
                )
                or failed,
            ),
            mock.patch.object(
                self.module,
                "atomic_write_json",
                side_effect=lambda path, value: calls.append(
                    ("atomic_write_json", path, value)
                ),
            ),
        ):
            result = self.module.main(self.argv())

        message = " ".join(str(error).split())[:500]
        self.assertEqual(result, 1)
        self.assertEqual(
            [call[0] for call in calls],
            [
                "logger.init",
                "utc_now",
                "lock.enter",
                "load_state",
                "load_config",
                "load_endpoint_cache",
                "lock.exit",
                "failed_state",
                "atomic_write_json",
                "logger.log",
            ],
        )
        self.assertEqual(
            calls[7][1:],
            (previous, self.now, message, statuses),
        )
        self.assertEqual(
            calls[9][1:],
            (
                "error",
                "software_inventory.failed",
                {"error": message, "retained": 2},
            ),
        )

    def test_failure_before_state_load_skips_failed_state_persistence(self) -> None:
        calls = []
        config = {"enabled": True}
        patches = self.patches(calls, previous={}, config=config)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            mock.patch.object(
                self.module,
                "load_state",
                side_effect=OSError("state unavailable"),
            ),
            mock.patch.object(self.module, "failed_state") as failed_state,
            mock.patch.object(self.module, "atomic_write_json") as write,
        ):
            result = self.module.main(self.argv())

        self.assertEqual(result, 1)
        failed_state.assert_not_called()
        write.assert_not_called()
        self.assertEqual(
            calls[-1],
            (
                "logger.log",
                "error",
                "software_inventory.failed",
                {"error": "state unavailable", "retained": 0},
            ),
        )

    def test_failed_state_write_error_is_best_effort_and_original_error_wins(self) -> None:
        calls = []
        previous = {"records": [{"old": True}]}
        config = {"enabled": True}
        patches = self.patches(calls, previous=previous, config=config)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            mock.patch.object(
                self.module,
                "load_endpoint_cache",
                side_effect=RuntimeError("primary failure"),
            ),
            mock.patch.object(
                self.module,
                "failed_state",
                return_value={"records": []},
            ),
            mock.patch.object(
                self.module,
                "atomic_write_json",
                side_effect=OSError("secondary failure"),
            ),
        ):
            result = self.module.main(self.argv())

        self.assertEqual(result, 1)
        self.assertEqual(
            calls[-1],
            (
                "logger.log",
                "error",
                "software_inventory.failed",
                {"error": "primary failure", "retained": 1},
            ),
        )

    def test_unclassified_exception_propagates_without_failure_log(self) -> None:
        calls = []
        previous = {"records": []}
        config = {"enabled": True}
        patches = self.patches(calls, previous=previous, config=config)
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            mock.patch.object(
                self.module,
                "load_endpoint_cache",
                side_effect=TypeError("programming defect"),
            ),
        ):
            with self.assertRaisesRegex(TypeError, "programming defect"):
                self.module.main(self.argv())

        self.assertFalse(any(call[0] == "logger.log" for call in calls))
        self.assertEqual(calls[-1][0], "lock.exit")


if __name__ == "__main__":
    unittest.main()
