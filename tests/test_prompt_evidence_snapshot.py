#!/usr/bin/env python3
"""Direct contracts for read-only prompt evidence snapshots."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))

from prompt_evidence_snapshot import (  # noqa: E402
    CoreEvidenceSnapshotRequest,
    CoreEvidenceSnapshotSources,
    HistoricalEvidenceSnapshotRequest,
    HistoricalEvidenceSnapshotSources,
    collect_core_evidence_snapshot,
    collect_historical_evidence_snapshot,
)


def core_request() -> CoreEvidenceSnapshotRequest:
    return CoreEvidenceSnapshotRequest(
        connection="connection",
        selected={"alert_id": "alert-1"},
        rollup_dir=Path("/fixture/rollups"),
        rollup_bytes=1024,
        related_limit=8,
        include_tests=False,
        pcap_analysis_dir=Path("/fixture/pcap"),
        pcap_analysis_limit=4,
        correlation_limit=6,
        correlation_min_score=3,
    )


def history_request(**changes) -> HistoricalEvidenceSnapshotRequest:
    values = {
        "connection": "connection",
        "selected": {
            "alert_id": "alert-1",
            "rule_name": "Fixture rule",
            "source_ip": "192.0.2.10",
            "destination_ip": "198.51.100.20",
        },
        "analysis_dir": Path("/fixture/analysis"),
        "related_limit": 8,
        "include_tests": False,
        "blind_reanalysis": False,
    }
    values.update(changes)
    return HistoricalEvidenceSnapshotRequest(**values)


def ordered_result(events: list[str], name: str, result):
    return mock.Mock(side_effect=lambda *args: events.append(name) or result)


class PromptEvidenceSnapshotTests(unittest.TestCase):
    def test_collects_core_snapshot_in_existing_fail_fast_order(self):
        events: list[str] = []
        sources = CoreEvidenceSnapshotSources(
            grouped_alert_context=ordered_result(events, "group", {"group": 1}),
            pcap_evidence_context=ordered_result(events, "pcap", {"pcap": 1}),
            public_enrichment_context=ordered_result(
                events, "enrichment", {"enrichment": 1}
            ),
            authorized_activity_context=ordered_result(
                events, "authorization", {"authorization": 1}
            ),
            analyst_state_context=ordered_result(events, "analyst", {"analyst": 1}),
            correlated_alert_context=ordered_result(
                events, "correlation", {"correlation": 1}
            ),
            compact_alert=ordered_result(events, "compact", {"alert": 1}),
        )

        with tempfile.TemporaryDirectory() as directory:
            requested = core_request()
            requested = CoreEvidenceSnapshotRequest(
                **{**requested.__dict__, "rollup_dir": Path(directory)}
            )
            snapshot = collect_core_evidence_snapshot(sources, requested)

        self.assertEqual(
            events,
            [
                "group",
                "pcap",
                "enrichment",
                "authorization",
                "analyst",
                "correlation",
                "compact",
            ],
        )
        sources.grouped_alert_context.assert_called_once_with(
            "connection", {"alert_id": "alert-1"}, 8, False
        )
        sources.pcap_evidence_context.assert_called_once_with(
            "connection",
            {"alert_id": "alert-1"},
            Path("/fixture/pcap"),
            4,
        )
        sources.correlated_alert_context.assert_called_once_with(
            "connection", {"alert_id": "alert-1"}, 6, 3
        )
        self.assertEqual(snapshot.latest_daily_rollup, {"path": None, "content": ""})
        self.assertEqual(snapshot.alert, {"alert": 1})

    def test_core_failure_stops_later_collectors(self):
        events: list[str] = []
        failing_pcap = mock.Mock(side_effect=ValueError("invalid PCAP evidence"))
        later = ordered_result(events, "later", {})
        sources = CoreEvidenceSnapshotSources(
            grouped_alert_context=ordered_result(events, "group", {}),
            pcap_evidence_context=failing_pcap,
            public_enrichment_context=later,
            authorized_activity_context=later,
            analyst_state_context=later,
            correlated_alert_context=later,
            compact_alert=later,
        )

        with tempfile.TemporaryDirectory() as directory:
            requested = core_request()
            requested = CoreEvidenceSnapshotRequest(
                **{**requested.__dict__, "rollup_dir": Path(directory)}
            )
            with self.assertRaisesRegex(ValueError, "invalid PCAP evidence"):
                collect_core_evidence_snapshot(sources, requested)

        self.assertEqual(events, ["group"])
        later.assert_not_called()

    def test_latest_rollup_selects_latest_name_and_reads_bounded_bytes(self):
        sources = CoreEvidenceSnapshotSources(
            grouped_alert_context=mock.Mock(return_value={}),
            pcap_evidence_context=mock.Mock(return_value={}),
            public_enrichment_context=mock.Mock(return_value={}),
            authorized_activity_context=mock.Mock(return_value={}),
            analyst_state_context=mock.Mock(return_value={}),
            correlated_alert_context=mock.Mock(return_value={}),
            compact_alert=mock.Mock(return_value={}),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "2026-08-07-soc-daily-rollup.md").write_text(
                "older", encoding="utf-8"
            )
            latest = root / "2026-08-08-soc-daily-rollup.md"
            latest.write_text("abcdef", encoding="utf-8")
            requested = core_request()
            requested = CoreEvidenceSnapshotRequest(
                **{
                    **requested.__dict__,
                    "rollup_dir": root,
                    "rollup_bytes": 3,
                }
            )

            snapshot = collect_core_evidence_snapshot(sources, requested)

        self.assertEqual(snapshot.latest_daily_rollup["path"], str(latest))
        self.assertEqual(snapshot.latest_daily_rollup["content"], "abc")

    def test_collects_history_in_package_evaluation_order(self):
        events: list[str] = []
        sources = HistoricalEvidenceSnapshotSources(
            prior_analysis_context=ordered_result(events, "prior", {"prior": 1}),
            related_alerts=ordered_result(events, "related", [{"related": 1}]),
            query_rows=ordered_result(
                events, "notifications", [{"notification": 1}]
            ),
        )

        snapshot = collect_historical_evidence_snapshot(sources, history_request())

        self.assertEqual(events, ["prior", "related", "notifications"])
        self.assertEqual(snapshot.prior_analyses, {"prior": 1})
        self.assertEqual(snapshot.related_alerts, [{"related": 1}])
        self.assertEqual(snapshot.recent_notifications, [{"notification": 1}])
        query = sources.query_rows.call_args.args
        self.assertIn("FROM notification_log", query[1])
        self.assertEqual(
            query[2],
            ["Fixture rule", "192.0.2.10", "198.51.100.20"],
        )

    def test_blind_history_skips_prior_model_analysis_read(self):
        prior = mock.Mock(return_value={"must_not": "load"})
        sources = HistoricalEvidenceSnapshotSources(
            prior_analysis_context=prior,
            related_alerts=mock.Mock(return_value=[]),
            query_rows=mock.Mock(return_value=[]),
        )

        snapshot = collect_historical_evidence_snapshot(
            sources,
            history_request(blind_reanalysis=True),
        )

        prior.assert_not_called()
        self.assertEqual(snapshot.prior_analyses, [])


if __name__ == "__main__":
    unittest.main()
