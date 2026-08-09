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

from scheduler_drain import SchedulerDrainState, SchedulerSelection  # noqa: E402
from scheduler_worker import (  # noqa: E402
    SchedulerWorkerSources,
    process_scheduler_selection,
)


class ControlledError(RuntimeError):
    pass


class SchedulerWorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.args = SimpleNamespace(alert_store_url="http://127.0.0.1:8787")
        self.selection = SchedulerSelection(
            disposition="selected",
            allowed_analysis_levels=("critical", "high"),
            selected={"alert_id": "selected-alert"},
            alert_id="selected-alert",
            group_id="selected-group",
            job_type="ai_analysis",
            job_payload={"agent_role": "soc-analyst"},
            durable_intent=True,
        )
        self.claim = SimpleNamespace(
            disposition="claimed",
            job_payload={"agent_role": "incident-responder"},
            alert_id="claimed-alert",
            group_id="claimed-group",
            reanalysis_attempt_id="attempt-1",
        )
        self.outcome = SimpleNamespace(
            analyzed_increment=1,
            controlled_owned_job_failed=False,
            failure_detail="",
            failure_group_id="",
            stop=False,
        )
        self.sources = SchedulerWorkerSources(
            acquire_claim=mock.Mock(side_effect=self.acquire),
            claim_sources=mock.Mock(return_value="claim-sources"),
            execute_analysis=mock.Mock(
                return_value=SimpleNamespace(process="process-result")
            ),
            execution_sources=mock.Mock(return_value="execution-sources"),
            handle_process_outcome=mock.Mock(return_value=self.outcome),
            handle_claim_rejection=mock.Mock(return_value=self.outcome),
            handle_exception=mock.Mock(return_value=self.outcome),
            outcome_sources=mock.Mock(return_value="outcome-sources"),
            controlled_claim_error=ControlledError,
            execution_errors=(RuntimeError, OSError),
        )

    def acquire(self, _sources: object, request: object) -> object:
        request.state.processing_transition = SimpleNamespace(job_id=7)
        request.state.processing_recorded = True
        request.state.lease_token = "lease-1"
        return self.claim

    def process(
        self,
        state: SchedulerDrainState | None = None,
        *,
        controlled_dir: Path | None = None,
    ) -> tuple[bool, SchedulerDrainState]:
        drain_state = state or SchedulerDrainState(attempted_count=1)
        stopped = process_scheduler_selection(
            self.sources,
            self.args,
            drain_state,
            self.selection,
            indexed_mode=True,
            controlled_evaluation_dir=controlled_dir,
        )
        return stopped, drain_state

    def test_claimed_job_executes_server_authoritative_identity(self) -> None:
        stopped, state = self.process()

        self.assertFalse(stopped)
        self.assertEqual(state.analyzed_count, 1)
        claim_request = self.sources.acquire_claim.call_args.args[1]
        self.assertEqual(claim_request.alert_id, "selected-alert")
        execution_request = self.sources.execute_analysis.call_args.args[1]
        self.assertEqual(execution_request.alert_id, "claimed-alert")
        self.assertEqual(execution_request.group_id, "claimed-group")
        self.assertEqual(
            execution_request.job_payload["agent_role"],
            "incident-responder",
        )
        self.assertEqual(execution_request.lease_token, "lease-1")
        outcome_request = self.sources.handle_process_outcome.call_args.args[1]
        self.assertEqual(outcome_request.group_id, "claimed-group")
        self.assertEqual(outcome_request.lease_token, "lease-1")

    def test_contention_returns_attempt_slot_without_execution(self) -> None:
        self.claim.disposition = "contended"
        state = SchedulerDrainState(attempted_count=1)

        stopped, state = self.process(state)

        self.assertFalse(stopped)
        self.assertEqual(state.attempted_count, 0)
        self.sources.execute_analysis.assert_not_called()

    def test_retired_claim_does_not_execute_or_count_analysis(self) -> None:
        self.claim.disposition = "retired"

        stopped, state = self.process()

        self.assertFalse(stopped)
        self.assertEqual(state.analyzed_count, 0)
        self.sources.execute_analysis.assert_not_called()

    def test_controlled_rejection_preserves_exact_owned_lease_receipt(self) -> None:
        controlled_dir = Path("/synthetic/controlled")

        def reject(_sources: object, request: object) -> object:
            request.state.processing_transition = SimpleNamespace(job_id=7)
            request.state.processing_recorded = True
            request.state.lease_token = "lease-controlled"
            request.state.controlled_exact_lease_owned = True
            raise ControlledError("dispatch drift")

        self.sources.acquire_claim.side_effect = reject
        controlled_outcome = SimpleNamespace(
            analyzed_increment=0,
            controlled_owned_job_failed=True,
            failure_detail="dispatch drift",
            failure_group_id="selected-group",
            stop=True,
        )
        self.sources.handle_claim_rejection.return_value = controlled_outcome

        stopped, state = self.process(controlled_dir=controlled_dir)

        self.assertTrue(stopped)
        request = self.sources.handle_claim_rejection.call_args.args[1]
        self.assertTrue(request.processing_recorded)
        self.assertEqual(request.lease_token, "lease-controlled")
        self.assertTrue(request.controlled_exact_lease_owned)
        self.assertTrue(state.controlled_owned_job_failed)

    def test_execution_exception_uses_claimed_identity_and_receipt(self) -> None:
        self.sources.execute_analysis.side_effect = RuntimeError(
            "prompt builder failed"
        )

        stopped, state = self.process()

        self.assertFalse(stopped)
        request = self.sources.handle_exception.call_args.args[1]
        self.assertEqual(request.group_id, "claimed-group")
        self.assertEqual(request.lease_token, "lease-1")
        self.assertEqual(state.analyzed_count, 1)


if __name__ == "__main__":
    unittest.main()
