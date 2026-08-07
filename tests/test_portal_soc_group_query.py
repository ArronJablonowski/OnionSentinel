"""Direct contracts for grouped SOC alert response orchestration."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "onion-sentinel-dashboard"))

from portal_soc_group_query import (  # noqa: E402
    SocAlertQuerySnapshot,
    SocGroupQueryDependencies,
    SocGroupQueryRequest,
    SocGroupQueryRequestPolicy,
    compose_group_query_payload,
    fallback_query_plan,
    parse_group_query_request,
    summary_query_plan,
)


class SocGroupQueryTests(unittest.TestCase):
    def snapshot(self, rows: list[object]) -> SocAlertQuerySnapshot:
        return SocAlertQuerySnapshot(
            statuses={"alert-a": {"status": "open"}},
            status_counts={"open": 4, "suppressed": 1, "total": 5},
            active_total=4,
            active_severity_counts={"critical": 1, "high": 3},
            active_highest_severity="critical",
            severity_counts={"critical": 1, "high": 1},
            highest_severity="critical",
            top_endpoints={"source_ip": "192.0.2.10"},
            filtered_rows=list(rows),
            page_rows=list(rows),
            total_matching=7,
            total_pages=4,
            current_page=2,
            offset=2,
            next_cursor="2026-08-07|group-b",
        )

    def request(self, **overrides: object) -> SocGroupQueryRequest:
        values = {
            "since": "2026-08-01  00:00:00Z",
            "levels": ["critical", "high"],
            "filter_status": "accepted",
            "analyst_status": "open",
            "search": "needle",
            "cursor_seen": "2026-08-07",
            "cursor_id": "group-a",
            "limit": 25,
            "requested_page": 2,
            "sort_key": "last_seen",
            "sort_direction": "desc",
            "summary_order_sql": "last_seen DESC, group_id DESC",
            "fallback_order_sql": "last_seen DESC, group_key DESC",
        }
        values.update(overrides)
        return SocGroupQueryRequest(**values)

    def test_request_aliases_are_normalized_once_for_both_query_paths(self) -> None:
        sort_calls: list[bool] = []

        def parse_sort(_query: dict[str, list[str]], fallback: bool) -> tuple[str, str, str]:
            sort_calls.append(fallback)
            suffix = "group_key" if fallback else "group_id"
            return "severity", "asc", f"severity ASC, {suffix} ASC"

        policy = SocGroupQueryRequestPolicy(
            parse_since=lambda value: f"since:{value}",
            parse_levels=lambda value: value.lower().split(","),
            parse_cursor=lambda value: tuple(value.split("|", 1)),
            parse_limit=lambda value: int(value),
            parse_page=lambda value: int(value),
            parse_sort=parse_sort,
        )
        request = parse_group_query_request(
            {
                "levels": ["Critical,High"],
                "status": [" SUPPRESSED "],
                "search": ["  suspicious host  "],
                "analyst_status": [" OPEN "],
                "cursor": ["seen|group-a"],
                "limit": ["50"],
                "page": ["3"],
                "since": ["24h"],
            },
            policy,
        )

        self.assertEqual(sort_calls, [False, True])
        self.assertEqual(request.since, "since:24h")
        self.assertEqual(request.levels, ["critical", "high"])
        self.assertEqual(request.filter_status, "suppressed")
        self.assertEqual(request.analyst_status, "open")
        self.assertEqual(request.search, "suspicious host")
        self.assertEqual((request.cursor_seen, request.cursor_id), ("seen", "group-a"))
        self.assertEqual((request.limit, request.requested_page), (50, 3))
        self.assertEqual(request.summary_order_sql, "severity ASC, group_id ASC")
        self.assertEqual(request.fallback_order_sql, "severity ASC, group_key ASC")

    def test_summary_plan_parameterizes_filters_and_search(self) -> None:
        search = "x%' OR 1=1 --"
        plan = summary_query_plan(self.request(search=search, filter_status="duplicate"))

        self.assertNotIn(search, plan.sql)
        self.assertIn("FROM alert_group_summary", plan.sql)
        self.assertIn("representative_alert_id like ?", plan.sql)
        self.assertIn("group_key like ?", plan.sql)
        self.assertIn("filter_status, 'accepted')) = ?", plan.sql)
        self.assertEqual(plan.args[:4], [
            "2026-08-01  00:00:00Z", "critical", "high", "duplicate",
        ])
        self.assertEqual(plan.args[4:], [f"%{search}%"] * 6)

    def test_fallback_plan_uses_injected_group_expression_and_legacy_filters(self) -> None:
        search = "fallback needle"
        plan = fallback_query_plan(
            self.request(search=search, filter_status="duplicate"),
            "coalesce(stable_group_key, alert_id)",
        )

        self.assertIn("coalesce(stable_group_key, alert_id) AS group_key", plan.sql)
        self.assertIn("alert_json like ?", plan.sql)
        self.assertNotIn("representative_alert_id like ?", plan.sql)
        self.assertNotIn("filter_status, 'accepted')) = ?", plan.sql)
        self.assertNotIn(search, plan.sql)
        self.assertEqual(plan.args[:3], [
            "2026-08-01  00:00:00Z", "critical", "high",
        ])
        self.assertEqual(plan.args[3:], [f"%{search}%"] * 4)

    def test_loads_page_metadata_once_and_shares_it_across_rows(self) -> None:
        rows = [{"alert_id": "alert-a"}, {"alert_id": "alert-b"}]
        ai_reports = {"report": "value"}
        ai_artifacts = {"artifact": "value"}
        pcap_analysis = {"pcap": "value"}
        pcap_requests = {"request": "value"}
        evidence = {"evidence": "value"}
        calls: list[object] = []

        def load_evidence(page_rows: list[object], artifacts: dict,
                          pcap: dict) -> tuple[dict, dict]:
            calls.append(("evidence", page_rows, artifacts, pcap))
            return pcap_requests, evidence

        def present(*args: object) -> dict:
            calls.append(("present", args))
            return {"alert_id": args[0]["alert_id"], "threshold": args[-1]}

        dependencies = SocGroupQueryDependencies(
            db_path="/runtime/alerts.sqlite3",
            load_ai_reports=lambda: calls.append("reports") or ai_reports,
            load_ai_artifacts=lambda page: calls.append(("artifacts", page)) or ai_artifacts,
            load_analysis_min_severity=lambda: calls.append("severity") or "medium",
            load_pcap_analysis=lambda: calls.append("pcap") or pcap_analysis,
            load_page_evidence=load_evidence,
            present_alert=present,
        )

        payload = compose_group_query_payload(
            source="sqlite-summary",
            snapshot=self.snapshot(rows),
            limit=2,
            sort_key="last_seen",
            sort_direction="desc",
            dependencies=dependencies,
        )

        self.assertEqual(calls[:4], [
            "reports", ("artifacts", rows), "severity", "pcap",
        ])
        self.assertEqual(calls[4], ("evidence", rows, ai_artifacts, pcap_analysis))
        presentations = [entry[1] for entry in calls if entry[0] == "present"]
        self.assertEqual(len(presentations), 2)
        for arguments in presentations:
            self.assertIs(arguments[2], ai_reports)
            self.assertIs(arguments[3], pcap_analysis)
            self.assertIs(arguments[4], pcap_requests)
            self.assertIs(arguments[5], ai_artifacts)
            self.assertIs(arguments[6], evidence)
            self.assertEqual(arguments[7], "medium")
        self.assertEqual(payload["alerts"], [
            {"alert_id": "alert-a", "threshold": "medium"},
            {"alert_id": "alert-b", "threshold": "medium"},
        ])

    def test_response_preserves_snapshot_and_request_pagination_fields(self) -> None:
        rows = [{"alert_id": "alert-a"}]
        dependencies = SocGroupQueryDependencies(
            db_path="/runtime/alerts.sqlite3",
            load_ai_reports=dict,
            load_ai_artifacts=lambda _rows: {},
            load_analysis_min_severity=lambda: "informational",
            load_pcap_analysis=dict,
            load_page_evidence=lambda _rows, _ai, _pcap: ({}, {}),
            present_alert=lambda row, *_args: dict(row),
        )

        payload = compose_group_query_payload(
            source="sqlite",
            snapshot=self.snapshot(rows),
            limit=2,
            sort_key="severity",
            sort_direction="asc",
            dependencies=dependencies,
        )

        self.assertTrue(payload["ok"])
        self.assertEqual(payload["mode"], "grouped")
        self.assertEqual(payload["source"], "sqlite")
        self.assertEqual(payload["db_path"], "/runtime/alerts.sqlite3")
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["total_matching"], 7)
        self.assertEqual(payload["active_total"], 4)
        self.assertEqual(payload["active_highest_severity"], "critical")
        self.assertEqual(payload["page"], 2)
        self.assertEqual(payload["page_size"], 2)
        self.assertEqual(payload["total_pages"], 4)
        self.assertEqual(payload["sort"], "severity")
        self.assertEqual(payload["direction"], "asc")
        self.assertEqual(payload["next_cursor"], "2026-08-07|group-b")


if __name__ == "__main__":
    unittest.main()
