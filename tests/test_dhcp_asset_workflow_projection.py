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

WORKFLOW = importlib.import_module("dhcp_asset_workflow")


def function_metrics(name: str) -> tuple[int, int]:
    tree = ast.parse((BIN / "dhcp_asset_workflow.py").read_text(encoding="utf-8"))
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


def observation(evidence_id: str, observed_at: str, marker: str) -> dict:
    return {
        "evidence_id": evidence_id,
        "observed_at": observed_at,
        "marker": marker,
    }


class DhcpAssetWorkflowProjectionTests(unittest.TestCase):
    def test_signatures_and_decomposed_phase_bounds_are_stable(self) -> None:
        self.assertEqual(
            str(inspect.signature(WORKFLOW.query_complete_window)),
            "(config: 'dict', start: 'dt.datetime', end: 'dt.datetime', "
            "size: 'int', *, max_segments: 'int' = 16, query_fn) -> 'dict'",
        )
        self.assertEqual(
            str(inspect.signature(WORKFLOW.backfill)),
            "(config: 'dict', state: 'dict', now: 'dt.datetime', days: 'int', "
            "*, query_window_fn, merge_fn) -> 'dict'",
        )
        self.assertEqual(
            str(inspect.signature(WORKFLOW.collect)),
            "(config: 'dict', state: 'dict', now: 'dt.datetime', *, "
            "collection_window_fn, query_window_fn, merge_fn) -> 'dict'",
        )
        for name in (
            "_validate_segment_budget",
            "_can_split_segment",
            "_completed_query_segments",
            "_reduced_observations",
            "_complete_window_result",
            "query_complete_window",
            "_backfill_windows",
            "_state_result",
            "_previous_backfill",
            "_backfill_status",
            "backfill",
            "_collection_status",
            "collect",
        ):
            with self.subTest(name=name):
                lines, complexity = function_metrics(name)
                self.assertLessEqual(lines, 50)
                self.assertLessEqual(complexity, 10)

    def test_segment_budget_admission_precedes_query_calls(self) -> None:
        start = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)
        query = mock.Mock(side_effect=AssertionError("query must not run"))
        for budget in (True, 0, 65, "16", None):
            with self.subTest(budget=budget), self.assertRaisesRegex(
                ValueError, "segment budget is invalid"
            ):
                WORKFLOW.query_complete_window(
                    {}, start, start + dt.timedelta(hours=1), 10,
                    max_segments=budget,
                    query_fn=query,
                )
        query.assert_not_called()

    def test_segment_split_fifo_reduction_deduplication_and_bounds_are_exact(self) -> None:
        start = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)
        end = start + dt.timedelta(minutes=4)
        calls = []
        responses = [
            {"status": "ok", "truncated": True, "hits_total": 100, "observations": []},
            {"status": "ok", "truncated": True, "hits_total": 50, "observations": []},
            {
                "status": "ok", "truncated": True, "hits_total": 3,
                "observations": [observation("a", "2026-08-01T00:00:30Z", "first")],
            },
            {
                "status": "ok", "truncated": False, "hits_total": "2",
                "observations": [observation("a", "2026-08-01T00:01:30Z", "replacement")],
            },
            {
                "status": "partial", "truncated": False, "hits_total": None,
                "observations": [observation("b", "2026-08-01T00:03:00Z", "second")],
            },
        ]

        def query(config, segment_start, segment_end, size):
            calls.append((config, segment_start, segment_end, size))
            return responses[len(calls) - 1]

        config = {"owner": "config"}
        result = WORKFLOW.query_complete_window(
            config,
            start,
            end,
            25,
            max_segments=5,
            query_fn=query,
        )

        minute = dt.timedelta(minutes=1)
        self.assertEqual(
            [(item[1], item[2]) for item in calls],
            [
                (start, end),
                (start, start + 2 * minute),
                (start, start + minute),
                (start + minute, start + 2 * minute),
                (start + 2 * minute, end),
            ],
        )
        self.assertTrue(all(item[0] is config and item[3] == 25 for item in calls))
        self.assertEqual(
            result,
            {
                "status": "partial",
                "window": {
                    "start": "2026-08-01T00:00:00.000Z",
                    "end": "2026-08-01T00:04:00.000Z",
                },
                "hits_total": 5,
                "observations": [
                    observation("a", "2026-08-01T00:01:30Z", "replacement"),
                    observation("b", "2026-08-01T00:03:00Z", "second"),
                ],
                "truncated": True,
                "query_segments": 5,
            },
        )

    def test_unsplittable_truncation_is_retained_as_one_incomplete_segment(self) -> None:
        start = dt.datetime(2026, 8, 1, tzinfo=dt.timezone.utc)
        response = {
            "status": "ok",
            "truncated": True,
            "hits_total": 7,
            "observations": [observation("x", "2026-08-01T00:00:30Z", "only")],
        }
        query = mock.Mock(return_value=response)
        result = WORKFLOW.query_complete_window(
            {}, start, start + dt.timedelta(minutes=2), 1,
            max_segments=1,
            query_fn=query,
        )
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["query_segments"], 1)
        self.assertEqual(result["hits_total"], 7)
        self.assertEqual(result["observations"], response["observations"])

    def test_backfill_success_preserves_window_progression_merge_and_projection(self) -> None:
        now = dt.datetime(2026, 8, 3, 12, tzinfo=dt.timezone.utc)
        state = {
            "schema": "old",
            "collection": {"last_success_at": "live-checkpoint"},
            "backfill": {"last_success_at": "prior-backfill"},
            "nested": {"shared": True},
            "observations": [{"existing": True}],
        }
        before = copy.deepcopy(state)
        config = {"query_size": 100, "retention_days": 45}
        query_calls = []
        merge_calls = []

        def query(cfg, start, end, size, *, max_segments):
            query_calls.append((cfg, start, end, size, max_segments))
            index = len(query_calls)
            return {
                "status": "ok",
                "truncated": False,
                "query_segments": index + 1,
                "hits_total": str(index * 10),
                "observations": [
                    observation("same", WORKFLOW.format_timestamp(start), f"day-{index}"),
                    observation(str(index), WORKFLOW.format_timestamp(end), f"unique-{index}"),
                ],
            }

        merged = [{"merged": True}]

        def merge(*args):
            merge_calls.append(args)
            return merged

        result = WORKFLOW.backfill(
            config,
            state,
            now,
            2,
            query_window_fn=query,
            merge_fn=merge,
        )

        requested = now - dt.timedelta(days=2)
        self.assertEqual(
            [(call[1], call[2], call[4]) for call in query_calls],
            [
                (requested, requested + dt.timedelta(days=1), 16),
                (requested + dt.timedelta(days=1), now, 16),
            ],
        )
        self.assertTrue(all(call[0] is config and call[3] == 100 for call in query_calls))
        self.assertEqual(len(merge_calls), 1)
        self.assertIs(merge_calls[0][0], state)
        self.assertEqual(len(merge_calls[0][1]), 4)
        self.assertEqual(merge_calls[0][2:], (now, 45))
        self.assertEqual(state, before)
        self.assertIs(result["nested"], state["nested"])
        self.assertIs(result["observations"], merged)
        self.assertEqual(
            result["backfill"],
            {
                "status": "ok",
                "last_attempt_at": "2026-08-03T12:00:00.000Z",
                "last_success_at": "2026-08-03T12:00:00.000Z",
                "last_error": "",
                "requested_start": "2026-08-01T12:00:00.000Z",
                "requested_end": "2026-08-03T12:00:00.000Z",
                "covered_through": "2026-08-03T12:00:00.000Z",
                "last_returned": 3,
                "last_hits_total": 30,
                "last_query_segments": 5,
            },
        )

    def test_backfill_global_budget_stop_retains_previous_success(self) -> None:
        now = dt.datetime(2026, 8, 3, tzinfo=dt.timezone.utc)
        state = {"backfill": {"last_success_at": "prior"}, "observations": []}
        response = {
            "status": "ok",
            "truncated": False,
            "query_segments": 64,
            "hits_total": 1,
            "observations": [],
        }
        query = mock.Mock(return_value=response)
        merge = mock.Mock(return_value=[])
        result = WORKFLOW.backfill(
            {"query_size": 10, "retention_days": 30},
            state,
            now,
            2,
            query_window_fn=query,
            merge_fn=merge,
        )
        self.assertEqual(query.call_count, 1)
        self.assertEqual(result["backfill"]["status"], "partial")
        self.assertEqual(result["backfill"]["last_success_at"], "prior")
        self.assertEqual(
            result["backfill"]["last_error"],
            "DHCP backfill stopped at its global query-segment limit",
        )
        self.assertEqual(result["backfill"]["covered_through"], "2026-08-02T00:00:00.000Z")

    def test_collect_preserves_call_order_checkpoint_and_state_projection(self) -> None:
        now = dt.datetime(2026, 8, 5, 12, tzinfo=dt.timezone.utc)
        start = now - dt.timedelta(minutes=30)
        base_state = {
            "collection": {"last_success_at": "prior"},
            "nested": {"shared": True},
            "observations": [{"old": True}],
        }
        scenarios = [
            ("ok", False, "ok", "2026-08-05T12:00:00.000Z", ""),
            ("partial", False, "partial", "prior", "DHCP query coverage was incomplete; checkpoint was not advanced"),
            ("unknown", False, "ok", "prior", "DHCP query coverage was incomplete; checkpoint was not advanced"),
            ("ok", True, "partial", "prior", "DHCP query coverage was incomplete; checkpoint was not advanced"),
        ]
        for response_status, truncated, projected_status, success, error in scenarios:
            with self.subTest(response_status=response_status, truncated=truncated):
                state = copy.deepcopy(base_state)
                before = copy.deepcopy(state)
                config = {"query_window_minutes": 30, "query_size": 100, "retention_days": 45}
                calls = []
                response = {
                    "status": response_status,
                    "truncated": truncated,
                    "window": {"start": "s", "end": "e"},
                    "hits_total": "7",
                    "query_segments": "2",
                    "observations": [observation("x", "2026-08-05T11:45:00Z", "new")],
                }
                merged = [{"merged": response_status, "truncated": truncated}]

                def window(*args):
                    calls.append(("window", args))
                    return start, now

                def query(*args):
                    calls.append(("query", args))
                    return response

                def merge(*args):
                    calls.append(("merge", args))
                    return merged

                result = WORKFLOW.collect(
                    config,
                    state,
                    now,
                    collection_window_fn=window,
                    query_window_fn=query,
                    merge_fn=merge,
                )
                self.assertEqual([item[0] for item in calls], ["window", "query", "merge"])
                self.assertEqual(calls[0][1], (state, now, 30))
                self.assertEqual(calls[1][1], (config, start, now, 100))
                self.assertEqual(calls[2][1], (state, response["observations"], now, 45))
                self.assertEqual(state, before)
                self.assertIs(result["nested"], state["nested"])
                self.assertIs(result["observations"], merged)
                self.assertEqual(result["collection"]["status"], projected_status)
                self.assertEqual(result["collection"]["last_success_at"], success)
                self.assertEqual(result["collection"]["last_error"], error)
                self.assertEqual(result["collection"]["last_returned"], 1)
                self.assertEqual(result["collection"]["last_hits_total"], 7)
                self.assertEqual(result["collection"]["last_truncated"], truncated)
                self.assertEqual(result["collection"]["last_query_segments"], 2)


if __name__ == "__main__":
    unittest.main()
