from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "n8n/bin/collect-endpoint-software-inventory.py"
BIN = ROOT / "n8n/bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))


def load_module():
    loader = importlib.machinery.SourceFileLoader(
        "endpoint_inventory_pagination_cli", str(SCRIPT)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class EndpointInventoryPaginationCliCharacterizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_module()

    def test_empty_page_returns_without_widening_query_contract(self) -> None:
        config = {"synthetic": True}
        calls: list[tuple] = []

        def query(*args):
            calls.append(args)
            return []

        with mock.patch.object(self.module, "_query", side_effect=query):
            result = self.module._paged_rows(
                config, "endpoint-a", "apps", "name,path", "case-a"
            )

        self.assertEqual(result, [])
        self.assertEqual(
            calls,
            [
                (
                    config,
                    "endpoint-a",
                    "SELECT name,path FROM apps WHERE path > '' "
                    "ORDER BY path LIMIT 50;",
                    "Scheduled read-only software inventory from apps",
                    "case-a",
                )
            ],
        )

    def test_full_then_short_page_preserves_rows_and_cursor_order(self) -> None:
        config = {"synthetic": True}
        first = [{"path": " b "}, {"path": "a"}, {"path": "c"}]
        second = [{"path": "d"}]
        original = copy.deepcopy((config, first, second))
        calls: list[tuple] = []

        def query(*args):
            calls.append(args)
            return first if len(calls) == 1 else second

        with (
            mock.patch.object(self.module, "MAX_ROWS", 3),
            mock.patch.object(self.module, "_query", side_effect=query),
        ):
            result = self.module._paged_rows(
                config, "endpoint-a", "apps", "name,path", "case-a"
            )

        self.assertEqual((config, first, second), original)
        self.assertEqual(result, first + second)
        self.assertIs(result[0], first[0])
        self.assertIs(result[-1], second[-1])
        self.assertEqual(
            [call[2] for call in calls],
            [
                "SELECT name,path FROM apps WHERE path > '' "
                "ORDER BY path LIMIT 3;",
                "SELECT name,path FROM apps WHERE path > 'c' "
                "ORDER BY path LIMIT 3;",
            ],
        )
        self.assertTrue(all(call[0] is config for call in calls))
        self.assertEqual(
            [(call[1], call[3], call[4]) for call in calls],
            [
                (
                    "endpoint-a",
                    "Scheduled read-only software inventory from apps",
                    "case-a",
                )
            ]
            * 2,
        )

    def test_missing_path_and_nonadvancing_cursor_fail_at_exact_pages(self) -> None:
        with (
            mock.patch.object(self.module, "MAX_ROWS", 2),
            mock.patch.object(
                self.module,
                "_query",
                return_value=[{"path": "a"}, {"path": ""}],
            ) as query,
            self.assertRaisesRegex(
                self.module.EndpointInventoryError,
                "^endpoint inventory row omitted its path$",
            ),
        ):
            self.module._paged_rows({}, "a", "apps", "path", "case")
        self.assertEqual(query.call_count, 1)

        pages = [
            [{"path": "b"}, {"path": "c"}],
            [{"path": "a"}, {"path": "b"}],
        ]
        with (
            mock.patch.object(self.module, "MAX_ROWS", 2),
            mock.patch.object(self.module, "_query", side_effect=pages) as query,
            self.assertRaisesRegex(
                self.module.EndpointInventoryError,
                "^endpoint inventory pagination did not advance$",
            ),
        ):
            self.module._paged_rows({}, "a", "apps", "path", "case")
        self.assertEqual(query.call_count, 2)

    def test_record_and_page_caps_fail_after_exact_query_count(self) -> None:
        pages = [
            [{"path": "a"}, {"path": "b"}],
            [{"path": "c"}],
        ]
        with (
            mock.patch.object(self.module, "MAX_ROWS", 2),
            mock.patch.object(self.module, "MAX_RECORDS", 2),
            mock.patch.object(self.module, "_query", side_effect=pages) as query,
            self.assertRaisesRegex(
                self.module.EndpointInventoryError,
                "^endpoint inventory exceeded its record limit$",
            ),
        ):
            self.module._paged_rows({}, "a", "apps", "path", "case")
        self.assertEqual(query.call_count, 2)

        with (
            mock.patch.object(self.module, "MAX_ROWS", 1),
            mock.patch.object(self.module, "MAX_PAGES", 2),
            mock.patch.object(
                self.module,
                "_query",
                side_effect=[[{"path": "a"}], [{"path": "b"}]],
            ) as query,
            self.assertRaisesRegex(
                self.module.EndpointInventoryError,
                "^endpoint inventory exceeded its page limit$",
            ),
        ):
            self.module._paged_rows({}, "a", "apps", "path", "case")
        self.assertEqual(query.call_count, 2)

    def test_main_success_preserves_lifecycle_order_and_exact_close(self) -> None:
        trace: list[list[object]] = []
        config = {"approved": True}
        previous = {"updated_at": "2026-08-12T18:00:00Z"}
        result = {"records": [{}, {}], "targets": [{}]}

        class Logger:
            def log(self, level, event, **fields):
                trace.append(["log", level, event, fields])

        def logger(path, *, service):
            trace.append(["logger", path, service])
            return Logger()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "endpoint-cache.json"
            log = root / "collector.jsonl"
            argv = [
                str(SCRIPT),
                "--config", str(root / "config.json"),
                "--cache", str(cache),
                "--log", str(log),
                "--attempts", "2",
                "--retry-delay-seconds", "7",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(self.module, "SecurityJsonlLogger", side_effect=logger),
                mock.patch.object(
                    self.module,
                    "open_collector_lock",
                    side_effect=lambda path: trace.append(["open", path]) or 91,
                ),
                mock.patch.object(
                    self.module.fcntl,
                    "flock",
                    side_effect=lambda fd, flags: trace.append(["flock", fd, flags]),
                ),
                mock.patch.object(
                    self.module,
                    "load_cache",
                    side_effect=lambda path: trace.append(["load_cache", path]) or previous,
                ),
                mock.patch.object(
                    self.module,
                    "load_live_osquery_config",
                    side_effect=lambda path: trace.append(["load_config", path]) or config,
                ),
                mock.patch.object(
                    self.module,
                    "collect_with_retries",
                    side_effect=lambda supplied, prior, **kwargs: trace.append(
                        ["collect", supplied, prior, kwargs]
                    )
                    or result,
                ),
                mock.patch.object(
                    self.module,
                    "atomic_write",
                    side_effect=lambda path, value: trace.append(["write", path, value]),
                ),
                mock.patch.object(
                    self.module.os,
                    "close",
                    side_effect=lambda fd: trace.append(["close", fd]),
                ),
            ):
                status = self.module.main()

        self.assertEqual(status, 0)
        self.assertEqual(
            trace,
            [
                ["logger", log, "endpoint-software-inventory"],
                ["open", cache.with_suffix(".json.lock")],
                ["flock", 91, self.module.fcntl.LOCK_EX | self.module.fcntl.LOCK_NB],
                ["load_cache", cache],
                ["load_config", root / "config.json"],
                [
                    "collect",
                    config,
                    previous,
                    {
                        "attempts": 2,
                        "retry_delay_seconds": 7,
                        "logger": mock.ANY,
                    },
                ],
                ["write", cache, result],
                [
                    "log",
                    "info",
                    "endpoint_software_inventory.completed",
                    {"records": 2, "targets": 1},
                ],
                ["close", 91],
            ],
        )

    def test_main_failure_projects_exact_receipt_and_closes_owned_lock(self) -> None:
        trace: list[list[object]] = []
        previous = {"updated_at": "prior"}
        failure = self.module.EndpointInventoryError(
            "synthetic timeout", reason_code="remote_timeout"
        )
        failure.attempts_completed = 2

        class Logger:
            def log(self, level, event, **fields):
                trace.append(["log", level, event, fields])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "endpoint-cache.json"
            argv = [
                str(SCRIPT),
                "--config", str(root / "config.json"),
                "--cache", str(cache),
                "--log", str(root / "collector.jsonl"),
                "--attempts", "3",
            ]
            with (
                mock.patch.object(sys, "argv", argv),
                mock.patch.object(self.module, "SecurityJsonlLogger", return_value=Logger()),
                mock.patch.object(self.module, "open_collector_lock", return_value=92),
                mock.patch.object(self.module.fcntl, "flock"),
                mock.patch.object(self.module, "load_cache", return_value=previous),
                mock.patch.object(self.module, "load_live_osquery_config", return_value={}),
                mock.patch.object(
                    self.module, "collect_with_retries", side_effect=failure
                ),
                mock.patch.object(self.module, "atomic_write") as write,
                mock.patch.object(
                    self.module,
                    "failure_code",
                    side_effect=lambda exc: trace.append(["failure_code", exc])
                    or "remote_timeout",
                ),
                mock.patch.object(
                    self.module,
                    "last_good_cache_state",
                    side_effect=lambda value: trace.append(["cache_state", value])
                    or "stale",
                ),
                mock.patch.object(
                    self.module.os,
                    "close",
                    side_effect=lambda fd: trace.append(["close", fd]),
                ),
            ):
                status = self.module.main()

        self.assertEqual(status, 1)
        write.assert_not_called()
        self.assertEqual(
            trace,
            [
                ["failure_code", failure],
                ["cache_state", previous],
                [
                    "log",
                    "error",
                    "endpoint_software_inventory.failed",
                    {
                        "failure_code": "remote_timeout",
                        "attempts": 2,
                        "attempt_limit": 3,
                        "last_good_cache_state": "stale",
                    },
                ],
                ["close", 92],
            ],
        )

    def test_invalid_cli_bounds_exit_before_logger_or_lock(self) -> None:
        for option, value in (("--attempts", "0"), ("--retry-delay-seconds", "3601")):
            with (
                self.subTest(option=option),
                mock.patch.object(sys, "argv", [str(SCRIPT), option, value]),
                mock.patch.object(self.module, "SecurityJsonlLogger") as logger,
                mock.patch.object(self.module, "open_collector_lock") as lock,
                self.assertRaises(SystemExit) as raised,
            ):
                self.module.main()
            self.assertEqual(raised.exception.code, 2)
            logger.assert_not_called()
            lock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
