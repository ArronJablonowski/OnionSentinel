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

from scheduler_outcome import (  # noqa: E402
    SchedulerOutcomeRequest,
    SchedulerOutcomeSources,
    handle_controlled_claim_rejection,
    handle_process_outcome,
    handle_scheduler_exception,
)


class SchedulerOutcomeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.output: list[str] = []
        self.errors: list[str] = []
        self.args = SimpleNamespace(alert_store_url="http://127.0.0.1:8787")
        self.sources = SchedulerOutcomeSources(
            report_status=mock.Mock(return_value=True),
            failure_is_retryable=mock.Mock(return_value=True),
            recover_controlled_spool=mock.Mock(return_value=False),
            controlled_spool_pending=mock.Mock(return_value=False),
            now=lambda: "NOW",
            emit=self.output.append,
            emit_error=self.errors.append,
            write_stdout=self.output.append,
            write_stderr=self.errors.append,
            result_submission_indeterminate_marker=(
                "controlled_result_submission_indeterminate"
            ),
        )

    def request(self, **overrides: object) -> SchedulerOutcomeRequest:
        values: dict[str, object] = {
            "args": self.args,
            "group_id": "group-1",
            "job_type": "ai_analysis",
            "processing_recorded": True,
            "lease_token": "lease-1",
            "controlled": False,
            "controlled_evaluation_dir": None,
            "controlled_exact_lease_owned": False,
        }
        values.update(overrides)
        return SchedulerOutcomeRequest(**values)

    def test_success_reports_production_completion_and_counts_analysis(self) -> None:
        process = SimpleNamespace(returncode=0, stdout="answer\n", stderr="note\n")

        outcome = handle_process_outcome(
            self.sources,
            self.request(),
            process,
        )

        self.assertEqual(outcome.analyzed_increment, 1)
        self.assertFalse(outcome.stop)
        self.sources.report_status.assert_called_once_with(
            self.args.alert_store_url,
            "group-1",
            "completed",
            lease_token="lease-1",
            job_type="ai_analysis",
        )
        self.assertEqual(self.output, ["answer\n"])
        self.assertEqual(self.errors, ["note\n"])

    def test_controlled_success_defers_completion_to_result_submission(self) -> None:
        outcome = handle_process_outcome(
            self.sources,
            self.request(
                controlled=True,
                controlled_evaluation_dir=Path("/synthetic/controlled"),
                controlled_exact_lease_owned=True,
            ),
            SimpleNamespace(returncode=0, stdout="", stderr=""),
        )

        self.assertEqual(outcome.analyzed_increment, 1)
        self.sources.report_status.assert_not_called()

    def test_process_failure_reports_retryable_status(self) -> None:
        process = SimpleNamespace(
            returncode=7,
            stdout="",
            stderr="provider connection closed unexpectedly",
        )

        outcome = handle_process_outcome(
            self.sources,
            self.request(),
            process,
        )

        self.assertFalse(outcome.stop)
        self.sources.failure_is_retryable.assert_called_once_with(
            "provider connection closed unexpectedly"
        )
        failed = self.sources.report_status.call_args
        self.assertEqual(failed.args[2], "failed")
        self.assertEqual(failed.args[4], "lease-1")
        self.assertIs(failed.kwargs["retryable"], True)

    def test_indeterminate_controlled_result_recovers_without_failure(self) -> None:
        controlled_dir = Path("/synthetic/controlled")
        self.sources.recover_controlled_spool.return_value = True

        outcome = handle_process_outcome(
            self.sources,
            self.request(
                controlled=True,
                controlled_evaluation_dir=controlled_dir,
                controlled_exact_lease_owned=True,
            ),
            SimpleNamespace(
                returncode=9,
                stdout="",
                stderr="controlled_result_submission_indeterminate",
            ),
        )

        self.assertTrue(outcome.stop)
        self.assertEqual(outcome.analyzed_increment, 1)
        self.assertFalse(outcome.controlled_owned_job_failed)
        self.sources.recover_controlled_spool.assert_called_once_with(
            self.args,
            controlled_dir,
        )
        self.sources.report_status.assert_not_called()

    def test_owned_controlled_claim_rejection_requeues_exact_lease(self) -> None:
        outcome = handle_controlled_claim_rejection(
            self.sources,
            self.request(
                controlled=True,
                controlled_exact_lease_owned=True,
                controlled_evaluation_dir=Path("/synthetic/controlled"),
            ),
            RuntimeError("dispatch drift"),
        )

        self.assertTrue(outcome.stop)
        self.assertTrue(outcome.controlled_owned_job_failed)
        released = self.sources.report_status.call_args
        self.assertEqual(released.args[2], "failed")
        self.assertEqual(released.args[3], "dispatch drift")
        self.assertEqual(released.args[4], "lease-1")
        self.assertIs(released.kwargs["retryable"], True)

    def test_unowned_controlled_claim_rejection_never_mutates_job(self) -> None:
        outcome = handle_controlled_claim_rejection(
            self.sources,
            self.request(controlled=True),
            RuntimeError("claim lost"),
        )

        self.assertTrue(outcome.stop)
        self.assertFalse(outcome.controlled_owned_job_failed)
        self.sources.report_status.assert_not_called()

    def test_exception_recovers_pending_controlled_spool(self) -> None:
        controlled_dir = Path("/synthetic/controlled")
        self.sources.controlled_spool_pending.return_value = True
        self.sources.recover_controlled_spool.return_value = True

        outcome = handle_scheduler_exception(
            self.sources,
            self.request(
                controlled=True,
                controlled_evaluation_dir=controlled_dir,
                controlled_exact_lease_owned=True,
            ),
            RuntimeError("child disappeared"),
        )

        self.assertEqual(outcome.analyzed_increment, 1)
        self.assertFalse(outcome.stop)
        self.sources.report_status.assert_not_called()

    def test_exception_reports_failure_when_no_spool_exists(self) -> None:
        error = RuntimeError("prompt builder failed")

        outcome = handle_scheduler_exception(
            self.sources,
            self.request(),
            error,
        )

        self.assertFalse(outcome.stop)
        self.sources.failure_is_retryable.assert_called_once_with(error)
        self.assertEqual(self.sources.report_status.call_args.args[2], "failed")


if __name__ == "__main__":
    unittest.main()
