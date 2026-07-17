"""Deterministic checks for pipeline throughput and capacity projections."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "n8n/alert_store/lib/pipeline_metrics.js"


def run_node(expression: str) -> object:
    script = f"""
const metrics = require({json.dumps(str(MODULE))});
const value = {expression};
process.stdout.write(JSON.stringify(value));
"""
    result = subprocess.run(
        ["node", "-e", script],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


class PipelineMetricsTests(unittest.TestCase):
    def test_eta_distinguishes_empty_drained_and_stalled_queues(self) -> None:
        values = run_node("[metrics.etaSeconds(0, 0), metrics.etaSeconds(10, 0), metrics.etaSeconds(10, 2)]")
        self.assertEqual(values, [0, None, 5])

    def test_window_rollups_report_rate_bytes_and_pressure(self) -> None:
        now = 1_800_000_000_000
        expression = f"""metrics.windowRollups([
          {{event_type:'enqueued', size_bytes:0, occurred_at:new Date({now} - 1000).toISOString()}},
          {{event_type:'enqueued', size_bytes:0, occurred_at:new Date({now} - 2000).toISOString()}},
          {{event_type:'completed', size_bytes:2048, occurred_at:new Date({now} - 3000).toISOString()}},
          {{event_type:'failed', size_bytes:0, occurred_at:new Date({now} - 4000).toISOString()}}
        ], {now})"""
        rollups = run_node(expression)
        self.assertEqual(rollups["15m"]["enqueued"], 2)
        self.assertEqual(rollups["15m"]["completed"], 1)
        self.assertEqual(rollups["15m"]["completed_bytes"], 2048)
        self.assertEqual(rollups["15m"]["pressure_ratio"], 2)

    def test_stage_snapshot_exposes_count_and_byte_drain_eta(self) -> None:
        now = 1_800_000_000_000
        events = ",".join(
            f"{{event_type:'completed',size_bytes:600,occurred_at:new Date({now} - {offset}).toISOString()}}"
            for offset in (1000, 2000, 3000)
        )
        expression = f"""metrics.stageSnapshot('pcap_transfer', {{
          pending:3, processing:0, failed:1, backlog_bytes_known:1800,
          backlog_bytes_unknown_items:0, oldest_pending_at:new Date({now} - 60000).toISOString()
        }}, [{events}], {now})"""
        snapshot = run_node(expression)
        self.assertEqual(snapshot["pending"], 3)
        self.assertEqual(snapshot["oldest_pending_seconds"], 60)
        self.assertEqual(snapshot["drain_eta_seconds"], 900)
        self.assertEqual(snapshot["byte_drain_eta_seconds"], 900)

    def test_disk_projection_uses_net_growth_and_known_backlog(self) -> None:
        now = 1_800_000_000_000
        expression = f"""metrics.diskProjection({{
          total_bytes:1000000, used_bytes:500000, free_bytes:500000,
          start_max_used_percent:75, hard_max_used_percent:80
        }}, [{{backlog_bytes_known:100000,backlog_bytes_unknown_items:0}}], [{{
          captured_at:new Date({now} - 3600000).toISOString(), disk_used_bytes:400000
        }}], {now})"""
        projection = run_node(expression)
        self.assertEqual(projection["start_limit_headroom_bytes"], 250000)
        self.assertEqual(projection["known_pipeline_backlog_bytes"], 100000)
        self.assertEqual(projection["projected_used_percent_with_known_backlog"], 60)
        self.assertTrue(projection["known_backlog_fits_before_start_limit"])
        self.assertGreater(projection["net_growth"]["1h"]["bytes_per_second"], 0)


if __name__ == "__main__":
    unittest.main()
