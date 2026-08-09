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

from scheduler_execution import (  # noqa: E402
    SchedulerExecutionRequest,
    SchedulerExecutionSources,
    execute_scheduler_analysis,
)


class SchedulerExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.args = SimpleNamespace(
            alert_store_url="http://127.0.0.1:8787",
            prompt_dir=Path("/synthetic/prompts"),
            pcap_analysis_dir=Path("/synthetic/pcap"),
        )
        self.process = SimpleNamespace(returncode=0, stdout="", stderr="")
        self.sources = SchedulerExecutionSources(
            report_status=mock.Mock(return_value="lease-1"),
            validate_controlled_route=mock.Mock(),
            collect_incident_evidence=mock.Mock(
                return_value=Path("/synthetic/evidence.json")
            ),
            build_prompt=mock.Mock(return_value=Path("/synthetic/prompt.md")),
            reusable_prompt=mock.Mock(return_value=None),
            run_analysis=mock.Mock(return_value=self.process),
        )

    def request(self, **overrides: object) -> SchedulerExecutionRequest:
        values: dict[str, object] = {
            "args": self.args,
            "selected": {"alert_id": "alert-1"},
            "job_payload": {},
            "alert_id": "alert-1",
            "group_id": "group-1",
            "job_type": "ai_analysis",
            "indexed_mode": True,
            "controlled": False,
            "processing_transition": SimpleNamespace(job_id=7),
            "processing_recorded": True,
            "lease_token": "lease-1",
            "reanalysis_attempt_id": "attempt-1",
        }
        values.update(overrides)
        return SchedulerExecutionRequest(**values)

    def test_indexed_soc_builds_fresh_prompt_and_dispatches_assigned_role(self) -> None:
        request = self.request(job_payload={"agent_role": "soc-analyst"})

        result = execute_scheduler_analysis(self.sources, request)

        self.assertIs(result.process, self.process)
        self.assertEqual(result.assigned_agent_role, "soc-analyst")
        self.assertIsNone(result.controlled_result_identity)
        self.sources.collect_incident_evidence.assert_not_called()
        self.sources.reusable_prompt.assert_not_called()
        self.sources.build_prompt.assert_called_once_with(
            "alert-1",
            self.args,
            request.job_payload,
            incident_evidence_path=None,
        )
        run_kwargs = self.sources.run_analysis.call_args.kwargs
        self.assertEqual(run_kwargs["agent_role"], "soc-analyst")
        self.assertIsNone(run_kwargs["controlled_result_identity"])
        self.assertTrue(callable(run_kwargs["progress_callback"]))

    def test_controlled_ir_revalidates_then_collects_and_binds_identity(self) -> None:
        events: list[str] = []
        self.sources.validate_controlled_route.side_effect = (
            lambda *_: events.append("route")
        )
        self.sources.collect_incident_evidence.side_effect = (
            lambda *_, **__: events.append("evidence")
            or Path("/synthetic/evidence.json")
        )
        payload = {
            "agent_role": "incident-responder",
            "cohort_id": "cohort-1",
            "dispatch_id": "dispatch-1",
            "stable_group_key": "stable-key",
            "release_id": "release-1",
            "expected_assigned_route": "codex:gpt-5.5:high",
            "expected_reviewer_route": "codex:gpt-5.6-sol:xhigh",
            "reviewer_required": True,
        }
        request = self.request(
            job_payload=payload,
            job_type="incident_response_analysis",
            controlled=True,
        )

        result = execute_scheduler_analysis(self.sources, request)

        self.assertEqual(events, ["route", "evidence"])
        self.sources.build_prompt.assert_called_once_with(
            "alert-1",
            self.args,
            payload,
            incident_evidence_path=Path("/synthetic/evidence.json"),
        )
        self.assertEqual(
            result.controlled_result_identity,
            {
                "job_id": 7,
                "job_type": "incident_response_analysis",
                "lease_token": "lease-1",
                "cohort_id": "cohort-1",
                "dispatch_id": "dispatch-1",
                "representative_alert_id": "alert-1",
                "stable_group_id": "group-1",
                "stable_group_key": "stable-key",
                "agent_role": "incident-responder",
                "reanalysis_attempt_id": "attempt-1",
                "release_id": "release-1",
                "expected_assigned_route": "codex:gpt-5.5:high",
                "expected_reviewer_route": "codex:gpt-5.6-sol:xhigh",
                "reviewer_required": True,
            },
        )

    def test_legacy_execution_reuses_existing_prompt(self) -> None:
        existing = Path("/synthetic/existing.md")
        self.sources.reusable_prompt.return_value = existing

        result = execute_scheduler_analysis(
            self.sources,
            self.request(indexed_mode=False, processing_recorded=False),
        )

        self.assertEqual(result.prompt_path, existing)
        self.sources.reusable_prompt.assert_called_once_with(
            self.args.prompt_dir,
            {"alert_id": "alert-1"},
            self.args.pcap_analysis_dir,
        )
        self.sources.build_prompt.assert_not_called()
        self.assertIsNone(
            self.sources.run_analysis.call_args.kwargs["progress_callback"]
        )

    def test_legacy_execution_builds_prompt_when_no_reusable_artifact(self) -> None:
        execute_scheduler_analysis(
            self.sources,
            self.request(indexed_mode=False, processing_recorded=False),
        )

        self.sources.build_prompt.assert_called_once_with("alert-1", self.args)

    def test_lease_callback_renews_exact_owned_lease(self) -> None:
        def run_with_renew(*_: object, **kwargs: object) -> object:
            kwargs["progress_callback"]()
            return self.process

        self.sources.run_analysis.side_effect = run_with_renew

        execute_scheduler_analysis(self.sources, self.request())

        self.sources.report_status.assert_called_once_with(
            self.args.alert_store_url,
            "group-1",
            "processing",
            lease_token="lease-1",
            job_type="ai_analysis",
        )

    def test_lease_callback_rejects_replacement_token(self) -> None:
        self.sources.report_status.return_value = "lease-2"

        def run_with_renew(*_: object, **kwargs: object) -> object:
            kwargs["progress_callback"]()
            return self.process

        self.sources.run_analysis.side_effect = run_with_renew
        with self.assertRaisesRegex(RuntimeError, "could not be renewed"):
            execute_scheduler_analysis(self.sources, self.request())


if __name__ == "__main__":
    unittest.main()
