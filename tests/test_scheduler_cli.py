from __future__ import annotations

import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "n8n" / "bin"
sys.path.insert(0, str(BIN))

from scheduler_cli import (  # noqa: E402
    SchedulerCliDefaults,
    SchedulerCliPolicy,
    parse_scheduler_args,
)


class SchedulerCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.defaults = SchedulerCliDefaults(
            db=root / "alerts.db",
            harness_db=root / "harness.db",
            prompt_dir=root / "prompts",
            analysis_dir=root / "analysis",
            pcap_analysis_dir=root / "pcap",
            rollup_dir=root / "rollups",
            agent_memory_dir=root / "memory",
            shared_memory_file=root / "shared.md",
            asset_inventory_file=root / "assets.json",
            incident_evidence_dir=root / "evidence",
            incident_evidence_config=root / "evidence.json",
            investigation_pivot_dir=root / "pivots",
            live_osquery_config=root / "osquery.json",
            disagreement_adjudicator_prompt=root / "adjudicator.md",
            ai_settings=root / "settings.json",
            investigation_harness_policy=root / "harness.json",
            detection_playbooks=root / "playbooks.json",
            investigation_skills=root / "skills.json",
            lock=root / "worker.lock",
            drain=root / "drain",
            wake=root / "wake",
            levels="critical,high",
            model="",
            max_prompt_bytes=262144,
            portal_wake=root / "portal-wake",
            alert_store_url="http://127.0.0.1:8787",
        )
        self.policy = SchedulerCliPolicy(
            controlled_alert_id=re.compile(r"[A-Za-z0-9._:@=-]{1,256}"),
            controlled_dispatch_id=re.compile(r"[a-f0-9]{64}"),
            stable_group_key_valid=lambda value: bool(value) and "\0" not in str(value),
            stable_group_key_max_bytes=2048,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_defaults_preserve_runtime_paths_and_lane(self) -> None:
        args = parse_scheduler_args(self.defaults, self.policy, [])
        self.assertEqual(args.db, self.defaults.db)
        self.assertEqual(args.prior_analysis_dir, self.defaults.analysis_dir)
        self.assertEqual(args.provider_lane, "any")
        self.assertEqual(args.alert_store_url, "http://127.0.0.1:8787")

    def test_complete_controlled_identity_is_normalized(self) -> None:
        args = parse_scheduler_args(self.defaults, self.policy, [
            "--only-group-id", "ABCDEF0123456789ABCD",
            "--only-alert-id", " alert:unit ",
            "--only-stable-group-key", "v2|unit",
            "--only-dispatch-id", "a" * 64,
        ])
        self.assertEqual(args.only_group_id, "abcdef0123456789abcd")
        self.assertEqual(args.only_alert_id, "alert:unit")

    def test_partial_controlled_identity_fails_closed(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            parse_scheduler_args(
                self.defaults, self.policy,
                ["--only-group-id", "a" * 20],
            )

    def test_numeric_policy_bounds_fail_closed(self) -> None:
        for argv in (
            ["--hours", "0"],
            ["--timeout", "0"],
            ["--max-per-run", "-1"],
            ["--max-prompt-bytes", "1"],
            ["--correlation-limit", "0"],
            ["--correlation-min-score", "101"],
        ):
            with (
                self.subTest(argv=argv),
                redirect_stderr(StringIO()),
                self.assertRaises(SystemExit),
            ):
                parse_scheduler_args(self.defaults, self.policy, argv)


if __name__ == "__main__":
    unittest.main()
