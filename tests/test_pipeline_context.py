from __future__ import annotations

from pathlib import Path
import unittest

from n8n.onion_sentinel.pipeline import ORDER, RuntimeContext, Stage


class PipelineContextTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
