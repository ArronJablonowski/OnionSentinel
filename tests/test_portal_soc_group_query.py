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
    compose_group_query_payload,
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
