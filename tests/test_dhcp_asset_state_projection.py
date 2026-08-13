from __future__ import annotations

import ast
import copy
import datetime as dt
import importlib
import inspect
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

STATE = importlib.import_module("dhcp_asset_state")


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse((BIN / "dhcp_asset_state.py").read_text(encoding="utf-8"))
    target = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    )
    complexity = 1
    for node in ast.walk(target):
        if node is target:
            continue
        if isinstance(node, (ast.If, ast.For, ast.While, ast.IfExp, ast.Assert)):
            complexity += 1
        elif isinstance(node, ast.Try):
            complexity += len(node.handlers)
        elif isinstance(node, ast.BoolOp):
            complexity += max(0, len(node.values) - 1)
        elif isinstance(node, ast.comprehension):
            complexity += 1 + len(node.ifs)
    return target.end_lineno - target.lineno + 1, complexity


class DhcpAssetStateProjectionTests(unittest.TestCase):
    def valid_config(self):
        return {
            "enabled": True,
            "host": "relay.local",
            "ssh_user": "sentinel",
            "ssh_key": "~/keys/dhcp",
            "known_hosts": "~/keys/known_hosts",
            "connect_timeout_seconds": 10,
            "timeout_seconds": 60,
            "max_response_bytes": 1024,
            "max_stderr_bytes": 1024,
            "query_window_minutes": 15,
            "query_size": 100,
            "retention_days": 30,
        }

    def test_signatures_and_decomposed_phase_bounds_are_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(STATE.load_config)),
            "(path: 'Path') -> 'dict'",
        )
        self.assertEqual(
            str(inspect.signature(STATE.merge_observations)),
            "(state: 'dict', incoming: 'list[dict]', now: 'dt.datetime', "
            "retention_days: 'int') -> 'list[dict]'",
        )
        for name in (
            "_validate_config_shape",
            "_validate_config_strings",
            "_validate_config_numbers",
            "load_config",
            "_existing_observation_records",
            "_merge_incoming_observations",
            "_retained_observations",
            "merge_observations",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_load_config_preserves_bounded_load_identity_and_path_mutations(self) -> None:
        config = self.valid_config()
        path = Path("/synthetic/dhcp.json")
        with mock.patch.object(
            STATE,
            "bounded_json",
            return_value=config,
        ) as bounded:
            result = STATE.load_config(path)
        bounded.assert_called_once_with(path, STATE.MAX_CONFIG_BYTES)
        self.assertIs(result, config)
        self.assertEqual(result["ssh_key"], str(Path("~/keys/dhcp").expanduser()))
        self.assertEqual(
            result["known_hosts"],
            str(Path("~/keys/known_hosts").expanduser()),
        )

    def test_load_config_error_precedence_and_numeric_bounds_are_exact(self) -> None:
        cases = [
            ([], "unsupported fields"),
            ({"extra": True}, "unsupported fields"),
            ({}, "boolean enabled"),
        ]
        for value, message in cases:
            with self.subTest(value=value), mock.patch.object(
                STATE,
                "bounded_json",
                return_value=value,
            ), self.assertRaisesRegex(ValueError, message):
                STATE.load_config(Path("config.json"))

        for key in ("host", "ssh_user", "ssh_key", "known_hosts"):
            config = self.valid_config()
            config[key] = " "
            with self.subTest(key=key), mock.patch.object(
                STATE,
                "bounded_json",
                return_value=config,
            ), self.assertRaisesRegex(ValueError, f"requires {key}"):
                STATE.load_config(Path("config.json"))

        limits = {
            "connect_timeout_seconds": (1, 120),
            "timeout_seconds": (5, 300),
            "max_response_bytes": (1024, 4 * 1024 * 1024),
            "max_stderr_bytes": (1024, 128 * 1024),
            "query_window_minutes": (5, 24 * 60),
            "query_size": (1, STATE.MAX_RESPONSE_OBSERVATIONS),
            "retention_days": (1, 365),
        }
        for key, (minimum, maximum) in limits.items():
            for value in (True, minimum - 1, maximum + 1, str(minimum)):
                config = self.valid_config()
                config[key] = value
                with self.subTest(key=key, value=value), mock.patch.object(
                    STATE,
                    "bounded_json",
                    return_value=config,
                ), self.assertRaisesRegex(
                    ValueError,
                    f"{key} must be from {minimum} through {maximum}",
                ):
                    STATE.load_config(Path("config.json"))

    def record(self, identity, last_seen, discovery_id, **overrides):
        value = {
            "identity_type": "mac",
            "identity_value": identity,
            "last_seen": last_seen,
            "discovery_id": discovery_id,
            "nested": {"shared": True},
        }
        value.update(overrides)
        return value

    def test_merge_preserves_existing_admission_copy_and_duplicate_overwrite(self) -> None:
        first = self.record("aa", "2026-08-04T00:00:00Z", "first")
        second = self.record("aa", "2026-08-05T00:00:00Z", "second")
        invalid = self.record("bb", "2026-08-05T00:00:00Z", "invalid")
        invalid["identity_type"] = "unsupported"
        state = {"observations": [None, first, invalid, second]}
        now = dt.datetime(2026, 8, 6, tzinfo=dt.timezone.utc)

        result = STATE.merge_observations(state, [], now, 30)

        self.assertEqual([item["discovery_id"] for item in result], ["second"])
        self.assertIsNot(result[0], second)
        self.assertIs(result[0]["nested"], second["nested"])
        self.assertEqual(state["observations"], [None, first, invalid, second])

    def test_merge_preserves_incoming_sort_merge_retention_and_final_order(self) -> None:
        state = {
            "observations": [
                self.record("new", "2026-08-05T00:00:00Z", "z"),
                self.record("old", "2026-07-01T00:00:00Z", "old"),
                self.record("bad", "not-a-time", "bad"),
                self.record("cutoff", "2026-08-01T00:00:00Z", "a"),
            ]
        }
        incoming = [
            {"observed_at": "2026-08-05T02:00:00Z", "evidence_id": "b"},
            {"observed_at": "2026-08-05T01:00:00Z", "evidence_id": "c"},
            {"observed_at": "2026-08-05T01:00:00Z", "evidence_id": "a"},
        ]
        before_state = copy.deepcopy(state)
        before_incoming = copy.deepcopy(incoming)
        calls = []

        def merge(records, item):
            calls.append((records, item))

        now = dt.datetime(2026, 8, 6, tzinfo=dt.timezone.utc)
        with mock.patch.object(STATE, "_merge_one", side_effect=merge):
            result = STATE.merge_observations(state, incoming, now, 5)

        self.assertEqual(
            [item[1]["evidence_id"] for item in calls],
            ["a", "c", "b"],
        )
        self.assertTrue(all(item[0] is calls[0][0] for item in calls))
        self.assertEqual(
            [item["discovery_id"] for item in result],
            ["z", "a"],
        )
        self.assertEqual(state, before_state)
        self.assertEqual(incoming, before_incoming)

    def test_merge_retention_is_bounded_after_descending_sort(self) -> None:
        original_max = STATE.MAX_OBSERVATIONS
        self.addCleanup(setattr, STATE, "MAX_OBSERVATIONS", original_max)
        STATE.MAX_OBSERVATIONS = 2
        state = {
            "observations": [
                self.record(
                    str(index),
                    f"2026-08-0{index + 1}T00:00:00Z",
                    str(index),
                )
                for index in range(4)
            ]
        }
        result = STATE.merge_observations(
            state,
            [],
            dt.datetime(2026, 8, 6, tzinfo=dt.timezone.utc),
            30,
        )
        self.assertEqual([item["discovery_id"] for item in result], ["3", "2"])


if __name__ == "__main__":
    unittest.main()
