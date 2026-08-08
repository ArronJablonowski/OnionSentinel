from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DASHBOARD = ROOT / "onion-sentinel-dashboard"
sys.path.insert(0, str(DASHBOARD))

from portal_llm_history_api import (  # noqa: E402
    LlmHistoryApiSources,
    build_llm_agent_activity_snapshot,
    llm_analysis_log_limit,
    llm_analysis_log_page,
    llm_analysis_logs_response,
    read_llm_agent_activity_snapshot,
)


class RecordingCache:
    def __init__(self) -> None:
        self.value = None
        self.computes = 0

    def get_or_compute(self, key, compute):
        if self.value is None:
            self.computes += 1
            self.value = compute()
        return self.value


def sources(cache=None):
    def compose(total, loaded, primary, database_loaded, recovered, reviewers, adjudicators, limit):
        combined = [*primary, *reviewers, *adjudicators]
        return {
            "primary_logs": primary,
            "reviewer_logs": reviewers,
            "adjudication_logs": adjudicators,
            "combined": combined,
            "telemetry_total": total,
            "database_recovered_total": recovered,
            "agent_totals": {"soc-analyst": len(combined)},
            "history_truncated": total > loaded or database_loaded >= limit,
        }

    return LlmHistoryApiSources(
        telemetry_page=lambda page, limit: (3, 1, [{"log_id": "telemetry"}]),
        read_database_primary=lambda: [{"log_id": "database"}],
        reconcile_primary=lambda telemetry, database: ([*telemetry, *database], 1),
        read_reviewer=lambda primary: [{"log_id": "reviewer"}],
        read_adjudication=lambda primary: [{"log_id": "adjudicator"}],
        compose_snapshot=compose,
        read_active=lambda: [{"log_id": "active"}],
        decorate=lambda record, live: {**record, "live": live},
        cache=cache or RecordingCache(),
        history_limit=10,
    )


class LlmHistoryApiTest(unittest.TestCase):
    def test_page_and_limit_are_bounded(self) -> None:
        self.assertEqual(llm_analysis_log_page("bad"), 1)
        self.assertEqual(llm_analysis_log_page("-2"), 1)
        self.assertEqual(llm_analysis_log_limit("bad"), 25)
        self.assertEqual(llm_analysis_log_limit("0"), 1)
        self.assertEqual(llm_analysis_log_limit("500"), 50)

    def test_snapshot_composes_all_durable_roles(self) -> None:
        snapshot = build_llm_agent_activity_snapshot(sources())
        self.assertEqual(snapshot["telemetry_total"], 3)
        self.assertEqual(snapshot["database_recovered_total"], 1)
        self.assertEqual(
            [item["log_id"] for item in snapshot["combined"]],
            ["telemetry", "database", "reviewer", "adjudicator"],
        )
        self.assertTrue(snapshot["history_truncated"])

    def test_snapshot_cache_coalesces_repeated_reads(self) -> None:
        cache = RecordingCache()
        current = sources(cache)
        first = read_llm_agent_activity_snapshot(current)
        second = read_llm_agent_activity_snapshot(current)
        self.assertIs(first, second)
        self.assertEqual(cache.computes, 1)

    def test_response_paginates_and_only_shows_active_on_first_page(self) -> None:
        current = sources()
        first = llm_analysis_logs_response(current, {"page": ["1"], "limit": ["2"]})
        second = llm_analysis_logs_response(current, {"page": ["2"], "limit": ["2"]})
        self.assertEqual(first["total"], 4)
        self.assertEqual(first["total_pages"], 2)
        self.assertEqual(len(first["logs"]), 2)
        self.assertEqual(first["active_runs"], [{"log_id": "active", "live": True}])
        self.assertEqual(second["page"], 2)
        self.assertEqual(second["active_runs"], [])

    def test_out_of_range_page_clamps_to_last_page(self) -> None:
        payload = llm_analysis_logs_response(
            sources(), {"page": ["99"], "limit": ["3"]}
        )
        self.assertEqual(payload["page"], 2)
        self.assertEqual(len(payload["logs"]), 1)


if __name__ == "__main__":
    unittest.main()
