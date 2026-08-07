from __future__ import annotations

from pathlib import Path
from typing import Any
import unittest

from n8n.onion_sentinel.pipeline import (
    AnalysisReviewPolicy,
    AnalysisReviewPorts,
    ORDER,
    RuntimeContext,
    RuntimePathDefaults,
    RuntimePaths,
    Stage,
    run_analysis_review,
)


class PipelineContextTests(unittest.TestCase):
    def defaults(self) -> RuntimePathDefaults:
        return RuntimePathDefaults(
            log_dir=Path("production/logs"),
            index_queue_dir=Path("production/index-pending"),
            index_quarantine_dir=Path("production/index-quarantine"),
            memory_receipt_dir=Path("production/memory-receipts"),
            memory_pending_dir=Path("production/memory-pending"),
            memory_committed_dir=Path("production/memory-committed"),
        )

    def test_full_lifecycle_is_ordered_and_auditable(self) -> None:
        context = RuntimeContext("run-1", arguments={"mode": "test"})
        for stage in ORDER[1:]:
            context.advance(stage, f"entered {stage.value}")
        self.assertEqual(context.stage, Stage.COMPLETE)
        self.assertEqual(len(context.audit()), len(ORDER) - 1)
        self.assertEqual(context.audit()[0]["previous"], "created")
        self.assertEqual(context.audit()[-1]["current"], "complete")

    def test_context_copies_mutable_inputs_at_the_boundary(self) -> None:
        package = {"alert": "a"}
        settings = {"route": "r"}
        response = {"verdict": "unknown"}
        context = RuntimeContext(
            "run-2",
            arguments=object(),
            runtime_dir=Path("runtime"),
            prompt_package=package,
            settings=settings,
            response=response,
        )
        package["alert"] = "changed"
        settings["route"] = "changed"
        response["verdict"] = "changed"
        self.assertEqual(context.prompt_package, {"alert": "a"})
        self.assertEqual(context.settings, {"route": "r"})
        self.assertEqual(context.response, {"verdict": "unknown"})

    def test_stage_skips_and_terminal_reentry_fail_closed(self) -> None:
        context = RuntimeContext("run-3", arguments=None)
        with self.assertRaisesRegex(ValueError, "invalid pipeline transition"):
            context.advance(Stage.PREPARE, "skip")
        context.fail("provider unavailable")
        with self.assertRaisesRegex(ValueError, "terminal pipeline state"):
            context.advance(Stage.LOAD, "retry")

    def test_audit_contains_only_bounded_transition_metadata(self) -> None:
        context = RuntimeContext("run-4", arguments=None)
        context.advance(Stage.LOAD, "loaded prompt contract")
        audit = context.audit()
        self.assertEqual(
            set(audit[0]),
            {"sequence", "previous", "current", "reason"},
        )
        with self.assertRaisesRegex(ValueError, "transition reason is invalid"):
            RuntimeContext("run-5", arguments=None).advance(
                Stage.LOAD,
                "x" * 257,
            )

    def test_production_paths_preserve_operator_owned_defaults(self) -> None:
        paths = RuntimePaths.resolve(None, self.defaults())
        self.assertEqual(paths.log_file, Path("production/logs/llm-analysis-log.jsonl"))
        self.assertEqual(paths.index_queue_dir, Path("production/index-pending"))
        self.assertEqual(
            paths.memory_committed_dir,
            Path("production/memory-committed"),
        )

    def test_controlled_paths_are_confined_to_evaluation_root(self) -> None:
        paths = RuntimePaths.resolve(Path("evaluation/run-1"), self.defaults())
        for value in vars(paths).values():
            self.assertTrue(Path(value).is_relative_to(Path("evaluation/run-1")))
        self.assertEqual(
            paths.index_quarantine_dir,
            Path("evaluation/run-1/analysis-index-quarantine"),
        )


class AnalysisReviewPipelineTests(unittest.TestCase):
    def context(self) -> RuntimeContext:
        context = RuntimeContext("analysis-review", arguments=None)
        for stage in (Stage.LOAD, Stage.ATTEST, Stage.PREPARE):
            context.advance(stage, f"entered {stage.value}")
        return context

    def ports(self, events: list[str]) -> AnalysisReviewPorts:
        def event(name: str, value: Any) -> Any:
            events.append(name)
            return value

        return AnalysisReviewPorts(
            load_saved_response=lambda: event("load_saved", {"primary": "saved"}),
            run_primary_analysis=lambda: event("run_primary", {"primary": "live"}),
            validate_primary=lambda response: event("validate", response),
            observe_primary=lambda _response: event("observe_primary", None),
            review_trigger=lambda _response: event("trigger", "model requested review"),
            run_configured_review=lambda response, reason: event(
                f"configured_review:{reason}", {**response, "reviewed": True}
            ),
            apply_saved_review_gate=lambda response: event(
                "saved_review", {**response, "reviewed": True}
            ),
            notify_saved_post_processing=lambda: event("notify_saved", None),
            controlled_reviewer_gate=lambda _response, trigger, frozen: event(
                f"controlled_gate:{trigger}:{frozen}", {"reviewer": "ok"}
            ),
            require_result_routes=lambda _response: event("require_routes", None),
            observe_reviewer=lambda _response: event("observe_reviewer", None),
        )

    def test_live_analysis_preserves_review_and_attestation_order(self) -> None:
        events: list[str] = []
        context = self.context()
        result = run_analysis_review(
            context,
            policy=AnalysisReviewPolicy(False, False, False),
            ports=self.ports(events),
        )
        self.assertEqual(
            events,
            [
                "run_primary", "validate", "observe_primary", "trigger",
                "configured_review:",
                "controlled_gate:model requested review:False",
                "require_routes", "observe_reviewer",
            ],
        )
        self.assertEqual(result.response["primary"], "live")
        self.assertEqual(result.trigger_reason, "model requested review")
        self.assertEqual(context.stage, Stage.ADJUDICATION)

    def test_saved_response_uses_gate_without_primary_provider(self) -> None:
        events: list[str] = []
        result = run_analysis_review(
            self.context(),
            policy=AnalysisReviewPolicy(True, True, True),
            ports=self.ports(events),
        )
        self.assertEqual(events[0], "load_saved")
        self.assertNotIn("run_primary", events)
        self.assertIn("saved_review", events)
        self.assertIn("notify_saved", events)
        self.assertEqual(result.response["primary"], "saved")

    def test_controlled_trigger_fills_only_an_empty_model_trigger(self) -> None:
        events: list[str] = []
        ports = self.ports(events)
        ports = AnalysisReviewPorts(
            **{**vars(ports), "review_trigger": lambda _response: ""}
        )
        result = run_analysis_review(
            self.context(),
            policy=AnalysisReviewPolicy(False, True, True),
            ports=ports,
        )
        self.assertEqual(
            result.trigger_reason,
            "controlled evaluation requires an independent reviewer",
        )
        self.assertIn(
            "configured_review:controlled evaluation requires an independent reviewer",
            events,
        )

    def test_unprepared_context_fails_before_any_port_call(self) -> None:
        events: list[str] = []
        with self.assertRaisesRegex(ValueError, "requires prepared context"):
            run_analysis_review(
                RuntimeContext("not-prepared", arguments=None),
                policy=AnalysisReviewPolicy(False, False, False),
                ports=self.ports(events),
            )
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
