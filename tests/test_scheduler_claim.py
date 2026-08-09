from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = REPO_ROOT / "n8n" / "bin"
if str(BIN_DIR) not in sys.path:
    sys.path.insert(0, str(BIN_DIR))

from scheduler_claim import (  # noqa: E402
    SchedulerClaimRequest,
    SchedulerClaimSources,
    SchedulerClaimState,
    acquire_scheduler_claim,
)
from scheduler_job_reporting import ClaimedAiLease, ControlledClaimRejected  # noqa: E402


class SchedulerClaimTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events: list[str] = []
        self.args = SimpleNamespace(
            alert_store_url="http://127.0.0.1:8787",
            db=Path("/synthetic/alerts.sqlite3"),
        )
        self.selected = {"triage_level": "high"}
        self.transition = ClaimedAiLease(
            "lease-1",
            job_payload={"agent_role": "soc-analyst"},
            job_type="ai_analysis",
            resolved_key="group-1",
            job_id=7,
        )
        self.sources = SchedulerClaimSources(
            exact_expectations=mock.Mock(return_value={"expected_job_id": 7}),
            report_status=mock.Mock(return_value=self.transition),
            load_claimed_job=mock.Mock(return_value=(
                {"agent_role": "soc-analyst"},
                "alert-1",
                "group-1",
                "high",
            )),
            require_controlled_identity=mock.Mock(),
            job_reanalysis_attempt_id=mock.Mock(return_value="attempt-1"),
            emit=self.events.append,
            now=lambda: "NOW",
        )

    def request(
        self,
        *,
        controlled: bool = False,
        indexed_mode: bool = True,
        durable_intent: bool = True,
        job_type: str = "ai_analysis",
        allowed_levels: tuple[str, ...] = ("critical", "high"),
        payload: dict[str, object] | None = None,
        state: SchedulerClaimState | None = None,
    ) -> SchedulerClaimRequest:
        return SchedulerClaimRequest(
            args=self.args,
            selected=self.selected,
            job_payload=payload or {"agent_role": "soc-analyst"},
            alert_id="alert-1",
            group_id="group-1",
            job_type=job_type,
            indexed_mode=indexed_mode,
            durable_intent=durable_intent,
            controlled=controlled,
            allowed_analysis_levels=allowed_levels,
            state=state or SchedulerClaimState(),
        )

    def test_normal_claim_uses_server_authoritative_identity(self) -> None:
        state = SchedulerClaimState()
        result = acquire_scheduler_claim(
            self.sources,
            self.request(state=state),
        )
        self.assertEqual(result.disposition, "claimed")
        self.assertEqual(result.alert_id, "alert-1")
        self.assertEqual(result.group_id, "group-1")
        self.assertEqual(result.lease_token, "lease-1")
        self.assertTrue(state.processing_recorded)
        self.sources.load_claimed_job.assert_called_once_with(
            self.transition,
            self.args.db,
            expected_job_type="ai_analysis",
            expected_group_id="group-1",
            expected_job_id=0,
        )

    def test_compare_and_set_contention_is_nonterminal(self) -> None:
        self.sources.report_status.return_value = False
        state = SchedulerClaimState()
        result = acquire_scheduler_claim(
            self.sources,
            self.request(state=state),
        )
        self.assertEqual(result.disposition, "contended")
        self.assertFalse(state.processing_recorded)
        self.sources.load_claimed_job.assert_not_called()
        self.assertIn("claim contention", self.events[-1])

    def test_controlled_claim_requires_indexed_durable_intent(self) -> None:
        with self.assertRaisesRegex(
            ControlledClaimRejected,
            "requires a durable AI job claim",
        ):
            acquire_scheduler_claim(
                self.sources,
                self.request(
                    controlled=True,
                    indexed_mode=False,
                    durable_intent=False,
                ),
            )
        self.sources.report_status.assert_not_called()

    def test_post_claim_validation_failure_retains_exact_owned_receipt(self) -> None:
        state = SchedulerClaimState()
        self.sources.require_controlled_identity.side_effect = (
            ControlledClaimRejected("dispatch drift")
        )
        with self.assertRaisesRegex(ControlledClaimRejected, "dispatch drift"):
            acquire_scheduler_claim(
                self.sources,
                self.request(controlled=True, state=state),
            )
        self.assertTrue(state.processing_recorded)
        self.assertEqual(state.lease_token, "lease-1")
        self.assertTrue(state.controlled_exact_lease_owned)

    def test_ir_attempt_identity_must_match_server_bound_lease(self) -> None:
        self.transition = ClaimedAiLease(
            "lease-ir",
            job_payload={"reanalysis_run_id": "run-1"},
            job_type="incident_response_analysis",
            resolved_key="group-1",
            job_id=7,
            reanalysis_attempt_id="different-attempt",
        )
        self.sources.report_status.return_value = self.transition
        self.sources.load_claimed_job.return_value = (
            {"reanalysis_run_id": "run-1"},
            "alert-1",
            "group-1",
            "high",
        )
        with self.assertRaisesRegex(RuntimeError, "server-bound attempt"):
            acquire_scheduler_claim(
                self.sources,
                self.request(job_type="incident_response_analysis"),
            )

    def test_automatic_job_below_floor_is_completed_without_inference(self) -> None:
        self.sources.load_claimed_job.return_value = (
            {"agent_role": "soc-analyst"},
            "alert-1",
            "group-1",
            "low",
        )
        result = acquire_scheduler_claim(
            self.sources,
            self.request(allowed_levels=("critical", "high", "medium")),
        )
        self.assertEqual(result.disposition, "retired")
        completed = self.sources.report_status.call_args_list[-1]
        self.assertEqual(completed.args[2], "completed")
        self.assertEqual(completed.kwargs["lease_token"], "lease-1")
        self.assertIn("below configured threshold", self.events[-1])


if __name__ == "__main__":
    unittest.main()
