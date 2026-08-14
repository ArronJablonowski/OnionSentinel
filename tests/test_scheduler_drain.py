from __future__ import annotations

import json
import sys
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_drain import (  # noqa: E402
    SchedulerDrainSources,
    SchedulerDrainState,
    select_scheduler_work,
)


class FakeConnection:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class SchedulerDrainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.messages: list[str] = []
        self.connection = FakeConnection()
        self.args = SimpleNamespace(
            max_per_run=5,
            ai_settings_file=Path("/synthetic/settings.json"),
            levels="",
            db=Path("/synthetic/alerts.sqlite3"),
            analysis_dir=Path("/synthetic/analysis"),
            pcap_analysis_dir=Path("/synthetic/pcap"),
            prompt_dir=Path("/synthetic/prompts"),
            provider_lane="any",
            dry_run=False,
        )
        self.row = {
            "alert_id": "alert-1",
            "stable_group_id": "stable-1",
            "queue_group_key": "key-1",
            "durable_job_type": "incident_response_analysis",
            "has_durable_intent": 1,
            "rule_name": "Synthetic alert",
            "triage_level": "high",
            "triage_score": 90,
            "last_seen": "2026-08-08T00:00:00Z",
            "queue_time": "2026-08-08T00:01:00Z",
        }
        self.sources = SchedulerDrainSources(
            stop_for_drain=mock.Mock(return_value=False),
            configured_levels=mock.Mock(return_value=["critical", "high"]),
            configured_incident_levels=mock.Mock(
                return_value=["critical"]
            ),
            open_readonly_database=mock.Mock(return_value=self.connection),
            select_indexed=mock.Mock(return_value=self.row),
            select_legacy=mock.Mock(return_value=self.row),
            analyzed_alert_ids=mock.Mock(return_value={"old-alert"}),
            alert_group_key=mock.Mock(return_value="derived-key"),
            alert_group_id=mock.Mock(return_value="derived-group"),
            durable_payload=mock.Mock(
                return_value={"agent_role": "incident-responder"}
            ),
            now=lambda: "NOW",
            emit=self.messages.append,
        )

    def select(
        self,
        state: SchedulerDrainState | None = None,
        *,
        indexed_mode: bool = True,
    ):
        return select_scheduler_work(
            self.sources,
            self.args,
            state or SchedulerDrainState(),
            indexed_mode=indexed_mode,
            launch_levels="critical,high,medium",
            drain_file=Path("/synthetic/drain"),
        )

    def test_indexed_selection_projects_candidate_and_updates_state(self) -> None:
        state = SchedulerDrainState()

        result = self.select(state)

        self.assertEqual(result.disposition, "selected")
        self.assertEqual(result.alert_id, "alert-1")
        self.assertEqual(result.group_id, "stable-1")
        self.assertEqual(result.job_type, "incident_response_analysis")
        self.assertTrue(result.durable_intent)
        self.assertEqual(result.allowed_analysis_levels, ("critical", "high"))
        self.assertEqual(result.allowed_incident_levels, ("critical",))
        self.assertFalse(result.automatic_execution_eligible)
        self.assertEqual(self.args.levels, "critical,high")
        self.assertEqual(state.attempted_count, 1)
        self.assertEqual(state.selected_groups, {"stable-1", "key-1"})
        self.assertTrue(self.connection.closed)
        payload = json.loads(self.messages[-1])
        self.assertEqual(payload["selected_alert_id"], "alert-1")
        self.sources.select_indexed.assert_called_once_with(
            self.connection,
            self.args,
            state.selected_groups,
        )

    def test_manual_incident_selection_is_an_explicit_policy_override(self) -> None:
        self.sources.durable_payload.return_value = {
            "agent_role": "incident-responder",
            "manual_reanalysis": True,
        }

        result = select_scheduler_work(
            self.sources,
            self.args,
            SchedulerDrainState(),
            indexed_mode=True,
            launch_levels="critical,high,medium,low,informational",
            drain_file=Path("drain"),
        )

        self.assertTrue(result.automatic_execution_eligible)
        emitted = json.loads(self.messages[-1])
        self.assertTrue(emitted["automatic_execution_eligible"])

    def test_legacy_selection_uses_artifact_exclusions_and_derived_group(self) -> None:
        self.row.pop("stable_group_id")
        self.row["queue_group_key"] = ""
        state = SchedulerDrainState()

        result = self.select(state, indexed_mode=False)

        self.assertEqual(result.group_id, "derived-group")
        self.sources.analyzed_alert_ids.assert_called_once_with(
            self.args.analysis_dir,
            self.args.pcap_analysis_dir,
            self.args.prompt_dir,
        )
        self.sources.select_legacy.assert_called_once_with(
            self.connection,
            self.args,
            {"old-alert"},
            state.selected_groups,
        )

    def test_disabled_automation_uses_fail_closed_selection_sentinel(self) -> None:
        self.sources.configured_levels.return_value = []

        result = self.select()

        self.assertEqual(result.allowed_analysis_levels, ())
        self.assertEqual(self.args.levels, "__disabled__")

    def test_maintenance_stops_before_settings_or_database_access(self) -> None:
        self.sources.stop_for_drain.return_value = True

        result = self.select()

        self.assertEqual(result.disposition, "stop")
        self.sources.configured_levels.assert_not_called()
        self.sources.configured_incident_levels.assert_not_called()
        self.sources.open_readonly_database.assert_not_called()

    def test_attempt_limit_stops_before_maintenance_check(self) -> None:
        self.args.max_per_run = 1
        state = SchedulerDrainState(attempted_count=1)

        result = self.select(state)

        self.assertEqual(result.disposition, "stop")
        self.sources.stop_for_drain.assert_not_called()

    def test_empty_queue_reports_only_when_nothing_was_analyzed(self) -> None:
        self.sources.select_indexed.return_value = None

        result = self.select(SchedulerDrainState())

        self.assertEqual(result.disposition, "stop")
        self.assertIn("no eligible unanalyzed alert found", self.messages[-1])
        self.assertTrue(self.connection.closed)

        self.messages.clear()
        self.connection = FakeConnection()
        self.sources.open_readonly_database.return_value = self.connection
        self.select(SchedulerDrainState(analyzed_count=1))
        self.assertNotIn("no eligible", "\n".join(self.messages))

    def test_dry_run_projects_and_logs_without_claiming(self) -> None:
        self.args.dry_run = True

        result = self.select()

        self.assertEqual(result.disposition, "dry_run")

    def test_state_returns_contended_attempt_and_applies_controlled_failure(self) -> None:
        state = SchedulerDrainState(attempted_count=1)
        state.release_contended_attempt()
        state.apply_outcome(
            SimpleNamespace(
                analyzed_increment=1,
                controlled_owned_job_failed=True,
                failure_detail="provider failed",
                failure_group_id="group-1",
            )
        )

        self.assertEqual(state.attempted_count, 0)
        self.assertEqual(state.analyzed_count, 1)
        self.assertTrue(state.controlled_owned_job_failed)
        self.assertEqual(state.controlled_failure_group_id, "group-1")


if __name__ == "__main__":
    unittest.main()
